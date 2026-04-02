// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::cmp::{min, Ord};
use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{anyhow, Context};
use aws_sdk_route53::config::Credentials;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;
use aws_types::region::Region;
use log::debug;
use tokio::time::{sleep, timeout};

use crate::addresses::{Route53AddressRecords, Addresses};
use crate::config::Config;

pub async fn get_client(
    aws_profile: &Option<String>,
    aws_access_key_id: &Option<String>,
    aws_secret_access_key: &Option<String>,
    aws_region: &Option<String>,
    enable_standard_credential_search: bool
) -> Client {
    let mut loader = aws_config::from_env();

    if let Some(profile) = aws_profile {
        loader = loader.profile_name(profile);
    }
    if let Some(region) = aws_region {
        loader = loader.region(Region::new(region.to_owned()));
    }

    let mut no_credentials = !enable_standard_credential_search;
    if let Some(access_key) = aws_access_key_id {
        if let Some(secret_access_key) = aws_secret_access_key {
            // Add the provided credentials as statics.
            let creds = Credentials::new(access_key, secret_access_key, None, None, "static");
            loader = loader.credentials_provider(creds);
            no_credentials = false;
        }
    }

    if no_credentials {
        loader = loader.no_credentials();
    }

    let sdk_config = loader.load().await;
    let config_builder = aws_sdk_route53::config::Builder::from(&sdk_config);
    let config = config_builder.build();
    Client::from_conf(config)
}

fn host_is_in_domain(host_lowercase: &str, domain: &str) -> bool {
    let domain_lowercase = domain.to_lowercase();

    if host_lowercase == domain_lowercase {
        return true;
    }
    if host_lowercase.ends_with(domain_lowercase.as_str()) {
        // While this would match "host.domain.com" in "domain.com" (which we want),
        // it would also match "mydomain.com" against "domain.com" (which we don't want).
        // So we must check that a dot ('.') immediately precedes the domain portion.
        let host_lc_bytes = host_lowercase.as_bytes();
        let domain_lc_bytes = domain_lowercase.as_bytes();
        let maybe_separator = host_lc_bytes[host_lc_bytes.len() - domain_lc_bytes.len() - 1];
        if maybe_separator == b'.' {
            return true;
        }
    }

    false
}

pub async fn get_zone_id(client: &Client, host_name_lowercase: &str) -> anyhow::Result<String> {
    let mut stream = client.list_hosted_zones().into_paginator().send();
    while let Some(page) = stream.next().await {
        let page_output = page.context("error calling Route53:ListHostedZones")?;
        for zone in page_output.hosted_zones.iter() {
            if host_is_in_domain(host_name_lowercase, zone.name()) {
                return Ok(zone.id.to_owned());
            }
        }
    }

    Err(anyhow!("zone not found: \"{host_name_lowercase}\""))
}

pub async fn get_resource_records(
    client: &Client,
    host_name: &String,
    route53_zone_id: &str,
) -> anyhow::Result<Route53AddressRecords> {
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

    Ok(Route53AddressRecords { v4, v6 })
}

fn resource_record_set_matches_expected<IPTYPE>(
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

    for (is_some, name) in [
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
    ] {
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
    let mut changes_added = false;

    if desired_addresses.is_empty() {
        if let Some(current) = &current_address_records {
            debug!("{log_prefix}: adding DELETE");
            let chg = Change::builder()
                .set_action(Some(ChangeAction::Delete))
                .set_resource_record_set(Some(current.clone()))
                .build()
                .context("error building Route53:Change (deletion) object")?;
            changes.push(chg);
            changes_added = true;
        }
    } else if !current_address_records.as_ref().is_some_and(|rrs| {
        resource_record_set_matches_expected(rrs, config, desired_addresses, log_prefix)
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
        changes_added = true;
    }

    if !changes_added {
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
    current_address_records: &Route53AddressRecords,
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
        .context("error determining ipv4-specific changes")?;
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
    } else if !config.update_if_different {
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
    while ci.status != ChangeStatus::Insync {
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

    return Ok(UpdateHostResult::UpdateSuccessful);
}


#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::LazyLock;
    use std::time::Duration;
    use aws_sdk_route53::types::{AliasTarget, CidrRoutingConfig, GeoLocation, ResourceRecordSetFailover};
    use super::*;

    static TEST_CONFIG: LazyLock<Config> = LazyLock::new(|| {
        Config::build_test_config(
            "example.com",
            Duration::from_secs(1),
            Duration::from_secs(100),
            false,
            60i64
        )
    });

    #[test]
    fn test_host_in_domain() {
        let tests = [
            ("example.com", "example.com"),
            ("example.com", "com"),
            ("www.example.com", "com"),
            ("a.b.c.d.e.example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("example.com", "EXAMPLE.COM"),
            ("example.com", "COM"),
            ("www.example.com", "COM"),
            ("www.example.com", "EXAMPLE.COM"),
        ];
        for (hostname, domain) in tests {
            assert!(host_is_in_domain(hostname, domain), "host=\"{0}\", domain=\"{1}\"", hostname, domain);
        }
    }

    #[test]
    fn test_host_not_in_domain() {
        let tests = [
            ("com", "example.com"),
            ("wwwwww.example.com", "www.example.com"),
            ("myexample.com", "example.com"),
            ("www.example.com", "some_domain.org")
        ];
        for (hostname, domain) in tests {
            assert!(!host_is_in_domain(hostname, domain), "host=\"{0}\", domain=\"{1}\"", hostname, domain);
        }
    }

    #[test]
    fn test_rrset_matches_expected() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set =
            test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s)
            .unwrap())
            .collect::<HashSet::<_>>()
        ;

        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(ResourceRecord::builder().value(test_ip_strs[0]).build().unwrap())
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
            .build()
            .unwrap()
        ;

        assert!(resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));
    }

    #[test]
    fn test_rrset_mismatch_for_ttl() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set =
            test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s)
            .unwrap())
            .collect::<HashSet::<_>>()
        ;

        // First test with a "slightly wrong" TTL
        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl + 1)
            .resource_records(ResourceRecord::builder().value(test_ip_strs[0]).build().unwrap())
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
            .build()
            .unwrap()
        ;

        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Re-test with no TTL at all
        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .resource_records(ResourceRecord::builder().value(test_ip_strs[0]).build().unwrap())
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
            .build()
            .unwrap()
        ;

        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));
    }

    #[test]
    fn test_rrset_mismatch_for_special() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set =
            test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s)
            .unwrap())
            .collect::<HashSet::<_>>()
        ;

        let rrs_base = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(ResourceRecord::builder().value(test_ip_strs[0]).build().unwrap())
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
        ;

        // First the baseline test to ensure everything *else* is correct.
        let rrs = rrs_base.clone().build().unwrap();
        assert!(resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Now test for a variety of unexpected options.

        let rrs = rrs_base.clone().alias_target(AliasTarget::builder().dns_name("target").hosted_zone_id("Z-12345").build().unwrap()).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().cidr_routing_config(CidrRoutingConfig::builder().collection_id("collection").location_name("location").build().unwrap()).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().failover(ResourceRecordSetFailover::Primary).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().geo_location(GeoLocation::builder().country_code("CA").build()).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().multi_value_answer(true).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().region(aws_sdk_route53::types::ResourceRecordSetRegion::CaCentral1).build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().set_identifier("q").build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        let rrs = rrs_base.clone().traffic_policy_instance_id("i-12345").build().unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));
    }

    #[test]
    fn test_rrset_mismatch_for_mismatched_addrs() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set =
            test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s)
            .unwrap())
            .collect::<HashSet::<_>>()
        ;

        let rrs_base = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(ResourceRecord::builder().value(test_ip_strs[0]).build().unwrap())
        ;

        // Baseline test
        let rrs = rrs_base.clone()
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
            .build()
            .unwrap();
        assert!(resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Test with one address missing
        let rrs = rrs_base.clone()
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Test with an extra, unexpected address
        let rrs = rrs_base.clone()
            .resource_records(ResourceRecord::builder().value(test_ip_strs[1]).build().unwrap())
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Test with partially-overlapping addresses
        let rrs = rrs_base.clone()
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

        // Test with completely dissimilar addresses
        let rrs = rrs_base.clone()
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .resource_records(ResourceRecord::builder().value("10.0.0.2").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(&rrs, &test_config, &test_ips_set, ""));

    }
}