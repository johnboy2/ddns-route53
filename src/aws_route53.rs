use std::cmp::{min, Ord};
use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{anyhow, Context};
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_route53::config::Credentials;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;
use aws_types::region::Region;
use log::debug;
use tokio::time::{sleep, timeout};

use crate::addresses::{AddressRecords, Addresses};
use crate::config::Config;

pub async fn get_client(
    aws_profile: &Option<String>,
    aws_access_key_id: &Option<String>,
    aws_secret_access_key: &Option<String>,
    aws_region: &Option<String>,
) -> Client {
    let sdk_config = ::aws_config::load_from_env().await;
    let mut config_builder = ::aws_sdk_route53::config::Builder::from(&sdk_config);

    if let Some(region_name) = aws_region.as_ref() {
        let region = Region::new(region_name.to_owned());
        config_builder.set_region(Some(region));
    }

    if let Some(access_key) = aws_access_key_id {
        if let Some(secret_access_key) = aws_secret_access_key {
            let creds = Credentials::new(access_key, secret_access_key, None, None, "configfile");
            config_builder = config_builder.credentials_provider(creds);
        }
    }

    if let Some(profile) = aws_profile {
        let profile = ProfileFileCredentialsProvider::builder()
            .profile_name(profile)
            .build();
        config_builder = config_builder.credentials_provider(profile);
    }

    let config = config_builder.build();
    Client::from_conf(config)
}

fn host_is_in_domain(host_lowercase: &str, domain: &str) -> bool {
    let domain = domain.to_lowercase();

    if host_lowercase == domain {
        return true;
    }
    if host_lowercase.ends_with(domain.as_str()) {
        // While this would match "host.domain.com" in "domain.com" (which we want),
        // it would also match "mydomain.com" against "domain.com" (which we don't want).
        // So we must check that whatever precedes the domain in the host is a period.
        let host = host_lowercase.as_bytes();
        let domain = domain.as_bytes();
        let maybe_separator = host[host.len() - domain.len() - 1];
        if maybe_separator == b'.' {
            return true;
        }
    }

    false
}

pub async fn get_zone_id(client: &Client, host_name: &str) -> anyhow::Result<String> {
    let mut stream = client.list_hosted_zones().into_paginator().send();
    while let Some(page) = stream.next().await {
        let page_output = page.context("error calling Route53:ListHostedZones")?;
        for zone in page_output.hosted_zones.iter() {
            if host_is_in_domain(host_name, zone.name()) {
                return Ok(zone.id.to_owned());
            }
        }
    }

    Err(anyhow!("zone not found: \"{host_name}\""))
}

pub async fn get_resource_records(
    client: &Client,
    host_name: &String,
    route53_zone_id: &str,
) -> anyhow::Result<AddressRecords> {
    // The `set_max_items(Some(2))` below IS SAFE, because we're only interested in 'A' and 'AAAA'
    // records -- which are sorted *before* any other record types.
    let response = client
        .list_resource_record_sets()
        .set_hosted_zone_id(Some(route53_zone_id.to_owned()))
        .set_start_record_name(Some(host_name.clone()))
        .set_max_items(Some(2))
        .send()
        .await
        .context("error calling Route53:ListResourceRecordSet")?;

    let mut v4: Option<ResourceRecordSet> = None;
    let mut v6: Option<ResourceRecordSet> = None;
    for rrs in response.resource_record_sets {
        if &rrs.name != host_name {
            break;
        }
        match rrs.r#type {
            RrType::A => {
                assert!(
                    v4.is_none(),
                    "received multiple 'A' records from Route53 (this should be impossible)"
                );
                v4 = Some(rrs);
            }
            RrType::Aaaa => {
                assert!(
                    v6.is_none(),
                    "received multiple 'AAAA' records from Route53 (this should be impossible)"
                );
                v6 = Some(rrs);
            }
            _ => {
                break;
            }
        }
    }

    Ok(AddressRecords { v4, v6 })
}

fn _resource_record_set_matches_expected<IPTYPE>(
    rrs: &ResourceRecordSet,
    config: &Config,
    desired_addresses: &HashSet<IPTYPE>,
    log_prefix: &'static str,
) -> bool
where
    IPTYPE: FromStr + Ord + Hash + Clone,
    <IPTYPE as FromStr>::Err: Debug,
{
    match rrs.ttl {
        Some(ttl) => {
            if ttl != config.route53_record_ttl {
                debug!(
                    "{log_prefix}: TTL mismatch (want={}, found={ttl})",
                    config.route53_record_ttl
                );
                return false;
            }
        }
        None => {
            debug!(
                "{log_prefix}: TTL mismatch (want={}, found=None)",
                config.route53_record_ttl
            );
            return false;
        }
    };

    for pair in [
        (rrs.alias_target.is_some(), "alias_target"),
        (rrs.cidr_routing_config.is_some(), "cidr_routing_config"),
        (rrs.failover.is_some(), "failover"),
        (rrs.geo_location.is_some(), "geo_location"),
        (rrs.multi_value_answer.is_some(), "multi_value_answer"),
        (rrs.region.is_some(), "region"),
        (rrs.set_identifier.is_some(), "set_identifier"),
        (
            rrs.traffic_policy_instance_id.is_some(),
            "traffic_policy_instance_id",
        ),
    ]
    .iter()
    {
        let is_some = pair.0;
        let name = pair.1;
        if is_some {
            debug!("{log_prefix}: field is unexpectedly populated: {name}");
            return false;
        }
    }

    let rrs_ips: HashSet<IPTYPE> = rrs
        .resource_records()
        .iter()
        .map(|rr| {
            rr.value()
                .parse::<IPTYPE>()
                .expect("A/AAAA resource records should always parse as valid IP addresses")
        })
        .collect();

    if &rrs_ips != desired_addresses {
        debug!("{log_prefix}: IP mismatch");
        return false;
    }

    true
}

fn _compare_add_to_change_set<IPTYPE>(
    config: &Config,
    desired_addresses: &HashSet<IPTYPE>,
    current_address_records: &Option<ResourceRecordSet>,
    rr_type: RrType,
    changes: &mut Vec<Change>,
    log_prefix: &'static str,
) -> anyhow::Result<()>
where
    IPTYPE: FromStr + Ord + Hash + Clone + Display,
    <IPTYPE as FromStr>::Err: Debug + Display,
{
    if desired_addresses.is_empty() {
        if let Some(current) = &current_address_records {
            debug!("{log_prefix}: adding DELETE");
            let chg = Change::builder()
                .set_action(Some(ChangeAction::Delete))
                .set_resource_record_set(Some(current.clone()))
                .build()
                .context("error building Route53:Change (deletion) object")?;
            changes.push(chg);
        } else {
            debug!("{log_prefix}: no changes required");
        }
    } else if !current_address_records.as_ref().is_some_and(|rrs| {
        _resource_record_set_matches_expected(rrs, config, desired_addresses, log_prefix)
    }) {
        debug!("{log_prefix}: adding UPSERT");
        let mut v = Vec::<ResourceRecord>::with_capacity(desired_addresses.len());
        for ip in desired_addresses.iter() {
            let r = ResourceRecord::builder()
                .set_value(Some(ip.to_string()))
                .build()
                .context("error building Route53:ResourceRecord object")?;
            v.push(r);
        }
        let rrs = ResourceRecordSet::builder()
            .set_name(Some(config.host_name_normalized.to_owned()))
            .set_type(Some(rr_type))
            .set_ttl(Some(config.route53_record_ttl))
            .set_resource_records(Some(v))
            .build()
            .context("error building Route53:ResourceRecordSet object")?;
        let chg = Change::builder()
            .set_action(Some(ChangeAction::Upsert))
            .set_resource_record_set(Some(rrs))
            .build()
            .context("error building Route53:Change (upsert) object")?;
        changes.push(chg);
    } else {
        debug!("{log_prefix}: no changes required");
    }
    Ok(())
}

pub enum UpdateHostResult {
    NotRequired,
    UpdateSuccessful,
    UpdateSkipped,
}

pub async fn update_host_addresses_if_different(
    config: &Config,
    desired_addresses: &Addresses,
    current_address_records: &AddressRecords,
    do_update: bool,
) -> anyhow::Result<UpdateHostResult> {
    let changes = {
        let mut changes = Vec::<Change>::new();
        _compare_add_to_change_set(
            config,
            &desired_addresses.v4,
            &current_address_records.v4,
            RrType::A,
            &mut changes,
            "ipv4",
        )
        .context("determining ipv4-specific changes")?;
        _compare_add_to_change_set(
            config,
            &desired_addresses.v6,
            &current_address_records.v6,
            RrType::Aaaa,
            &mut changes,
            "ipv6",
        )
        .context("error determining ipv6-specific changes")?;
        changes
    };

    if changes.is_empty() {
        return Ok(UpdateHostResult::NotRequired);
    } else if !do_update {
        return Ok(UpdateHostResult::UpdateSkipped);
    }
    let start_time = Instant::now();
    let expiry_time = start_time
        .checked_add(config.update_timeout.to_owned())
        .expect("adding a duration to 'now' should always work");

    let cb = ChangeBatch::builder()
        .set_changes(Some(changes))
        .build()
        .context("error builing Route53:ChangeBatch object")?;
    let change_fut = config
        .route53_client
        .change_resource_record_sets()
        .set_change_batch(Some(cb))
        .set_hosted_zone_id(Some(config.route53_zone_id.to_owned()))
        .send();
    let timeout_fut = timeout(config.update_timeout.to_owned(), change_fut);

    let timeout_output = timeout_fut.await?;
    let change_output = timeout_output?;

    let mut ci = change_output
        .change_info
        .expect("Change-responses should include change-info");
    loop {
        if ci.status == ChangeStatus::Insync {
            return Ok(UpdateHostResult::UpdateSuccessful);
        }

        debug!("Change is not yet synchronized.");
        let now = Instant::now();
        let time_elapsed = now - start_time;
        if config.update_timeout <= time_elapsed {
            return Err(anyhow!("timed out waiting for change to synchronize"));
        }
        let time_remaining = expiry_time - now;

        sleep(min(time_remaining, config.update_poll_interval)).await;

        debug!("Re-checking whether change is synchronized...");
        let output = config
            .route53_client
            .get_change()
            .set_id(Some(ci.id))
            .send()
            .await
            .context("error calling Route53:GetChange")?;
        ci = output
            .change_info
            .expect("Change-lookups should return change-info")
    }
}
