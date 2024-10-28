use std::cmp::{min, Ord};
use std::fmt::{Debug, Display};
use std::str::FromStr;
use std::time::Instant;

use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_route53::config::Credentials;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;
use aws_types::region::Region;
use log::{debug, error};
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

pub async fn get_zone_id(client: &Client, host_name: &str) -> Result<String, String> {
    let mut stream = client.list_hosted_zones().into_paginator().send();
    while let Some(page) = stream.next().await {
        match page {
            Ok(result) => {
                for zone in result.hosted_zones.iter() {
                    if host_is_in_domain(host_name, zone.name()) {
                        return Ok(zone.id.to_owned());
                    }
                }
            }
            Err(e) => return Err(e.to_string()),
        };
    }

    Err("not found".to_owned())
}

pub async fn get_resource_records(
    client: &Client,
    host_name: &String,
    route53_zone_id: &str,
) -> Result<AddressRecords, String> {
    // The `set_max_items(Some(2))` below IS SAFE, because we're only interested in 'A' and 'AAAA'
    // records -- which are sorted *before* any other record types.
    let response = client
        .list_resource_record_sets()
        .set_hosted_zone_id(Some(route53_zone_id.to_owned()))
        .set_start_record_name(Some(host_name.clone()))
        .set_max_items(Some(2))
        .send()
        .await;

    let mut v4: Option<ResourceRecordSet> = None;
    let mut v6: Option<ResourceRecordSet> = None;
    match response {
        Ok(output) => {
            for rrs in output.resource_record_sets {
                if &rrs.name != host_name {
                    break;
                }
                match rrs.r#type {
                    RrType::A => {
                        assert!(v4.is_none(), "received multiple 'A' records from Route53 (this should be impossible)");
                        v4 = Some(rrs);
                    }
                    RrType::Aaaa => {
                        assert!(v6.is_none(), "received multiple 'AAAA' records from Route53 (this should be impossible)");
                        v6 = Some(rrs);
                    }
                    _ => {
                        break;
                    }
                }
            }
        }
        Err(e) => {
            return Err(e.to_string());
        }
    };

    Ok(AddressRecords { v4, v6 })
}

fn _resource_record_set_matches_expected<IPTYPE>(
    rrs: &ResourceRecordSet,
    config: &Config,
    desired_addresses: &Vec<IPTYPE>,
) -> bool
where
    IPTYPE: FromStr + Ord,
    <IPTYPE as FromStr>::Err: Debug,
{
    match rrs.ttl {
        Some(ttl) => {
            if ttl != config.route53_record_ttl {
                return false;
            }
        }
        None => {
            return false;
        }
    };

    if !(rrs.alias_target.is_some() || rrs.cidr_routing_config.is_some() || rrs.failover.is_some()
        || rrs.geo_location.is_some() /* || rrs.health_check_id.is_some() */
        || rrs.multi_value_answer.is_some() || rrs.region.is_some()
        || rrs.set_identifier.is_some() || rrs.traffic_policy_instance_id.is_some()
        || rrs.weight.is_some())
    {
        return false;
    }

    let rrs_ips = {
        let mut ips: Vec<IPTYPE> = rrs
            .resource_records()
            .iter()
            .map(|rr| {
                rr.value()
                    .parse::<IPTYPE>()
                    .expect("A/AAAA resource records should always parse as valid IP addresses")
            })
            .collect();
        ips.sort();
        ips
    };
    // TODO: This currently works because the two lists are always sorted; we should NOT depend on that convention
    if &rrs_ips != desired_addresses {
        return false;
    }

    true
}

fn _compare_add_to_change_set<IPTYPE>(
    config: &Config,
    desired_addresses: &Vec<IPTYPE>,
    current_address_records: &Option<ResourceRecordSet>,
    rr_type: RrType,
    changes: &mut Vec<Change>,
) -> Result<(), String>
where
    IPTYPE: FromStr + Ord + Display,
    <IPTYPE as FromStr>::Err: Debug + Display,
{
    if desired_addresses.is_empty() {
        if let Some(current) = &current_address_records {
            let chg = match Change::builder()
                .set_action(Some(ChangeAction::Delete))
                .set_resource_record_set(Some(current.clone()))
                .build()
            {
                Ok(chg) => chg,
                Err(e) => {
                    return Err(format!(
                        "error creating deletion change ({}): {e}",
                        current.r#type().as_str()
                    ));
                }
            };
            changes.push(chg);
        }
    } else if !current_address_records
        .as_ref()
        .is_some_and(|rrs| _resource_record_set_matches_expected(rrs, config, desired_addresses))
    {
        let mut v = Vec::<ResourceRecord>::with_capacity(desired_addresses.len());
        for ip in desired_addresses.iter() {
            let r = match ResourceRecord::builder()
                .set_value(Some(ip.to_string()))
                .build()
            {
                Ok(rr) => rr,
                Err(e) => {
                    return Err(format!("error creating ResourceRecord: {e}"));
                }
            };
            v.push(r);
        }
        let rrs = match ResourceRecordSet::builder()
            .set_name(Some(config.host_name_normalized.to_owned()))
            .set_type(Some(rr_type))
            .set_ttl(Some(config.route53_record_ttl))
            .set_resource_records(Some(v))
            .build()
        {
            Ok(rrs) => rrs,
            Err(e) => {
                return Err(format!("error creating ResourceRecordSet: {e}"));
            }
        };
        let chg = match Change::builder()
            .set_action(Some(ChangeAction::Upsert))
            .set_resource_record_set(Some(rrs))
            .build()
        {
            Ok(chg) => chg,
            Err(e) => {
                return Err(format!("error creating change: {e}"));
            }
        };
        changes.push(chg);
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
) -> Result<UpdateHostResult, String> {
    let changes = {
        let mut changes = Vec::<Change>::new();
        _compare_add_to_change_set(
            config,
            &desired_addresses.v4,
            &current_address_records.v4,
            RrType::A,
            &mut changes,
        )?;
        _compare_add_to_change_set(
            config,
            &desired_addresses.v6,
            &current_address_records.v6,
            RrType::Aaaa,
            &mut changes,
        )?;
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

    let cb = match ChangeBatch::builder().set_changes(Some(changes)).build() {
        Ok(cb) => cb,
        Err(e) => return Err(format!("building change batch: {e}")),
    };
    let change_fut = config
        .route53_client
        .change_resource_record_sets()
        .set_change_batch(Some(cb))
        .set_hosted_zone_id(Some(config.route53_zone_id.to_owned()))
        .send();
    let timeout_fut = timeout(config.update_timeout.to_owned(), change_fut);

    let timeout_output = match timeout_fut.await {
        Ok(output) => output,
        Err(_e) => return Err("Timed out waiting for response".to_owned()),
    };
    let change_output = match timeout_output {
        Ok(output) => output,
        Err(e) => {
            match e.raw_response() {
                Some(response) => {
                    let msg = String::from_utf8_lossy(
                        response.body().bytes().expect("non-streaming error body"),
                    );
                    error!("SDK returned error: {}", msg);
                }
                None => {
                    error!("SDK returned error with empty body");
                }
            };
            return Err(format!("change result: {e}"));
        }
    };

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
            return Err("Timed out waiting for change to synchronize".to_owned());
        }
        let time_remaining = expiry_time - now;

        sleep(min(time_remaining, config.update_poll_interval)).await;

        debug!("Re-checking whether change is synchronized...");
        let output = match config
            .route53_client
            .get_change()
            .set_id(Some(ci.id))
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => return Err(format!("get change error: {e}")),
        };
        ci = output
            .change_info
            .expect("Change-lookups should return change-info")
    }
}
