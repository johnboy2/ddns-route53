// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::cmp::{min, Ord};
use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{anyhow, Context};
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;
use log::{debug, error};
use tokio::time::{sleep, timeout};

use crate::addresses::{Addresses, Route53AddressRecords};
use crate::config::Config;
use crate::host_names::{host_is_in_domain, normalize_host_name};

// Helper to look up the zone ID for a given host name (i.e., if not provided by configuration or CLI arg).
pub async fn get_zone_id(client: &Client, host_name: &str) -> anyhow::Result<String> {
    let host_name_normalized = normalize_host_name(host_name)?;

    let mut best_match: Option<String> = None;

    let mut stream = client.list_hosted_zones().into_paginator().send();
    while let Some(page) = stream.next().await {
        let page_output = page.context("error calling Route53:ListHostedZones")?;
        for zone in page_output.hosted_zones.iter() {
            if host_is_in_domain(host_name_normalized.as_ref(), zone.name()) {
                // Route53 returns the zone ID as "/hostedzone/ZONEID", so we strip the prefix for further use.
                let zone_id = zone
                    .id
                    .strip_prefix("/hostedzone/")
                    .unwrap_or(zone.id.as_str());
                if best_match
                    .as_ref()
                    .is_none_or(|best_zone_id| best_zone_id.len() < zone_id.len())
                {
                    best_match = Some(zone_id.to_owned());
                }
            }
        }
    }

    if let Some(best_zone_id) = best_match {
        Ok(best_zone_id)
    } else {
        Err(anyhow!("zone not found for host: \"{host_name}\""))
    }
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

pub fn get_ip_addresses_from_resource_record_set<IPTYPE>(rrs: &ResourceRecordSet) -> HashSet<IPTYPE>
where
    IPTYPE: FromStr + Ord + Hash + Eq,
{
    rrs
        .resource_records()
        .iter()
        .filter_map(|rr| {
            match rr.value().parse::<IPTYPE>() {
                Ok(ip) => Some(ip),
                Err(_e) => {
                    error!(
                        "Route53 resource record value could not be parsed as an IP address: '{}' (ignoring)",
                        rr.value()
                    );
                    None
                }
            }
        })
        .collect::<HashSet<IPTYPE>>()
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

    macro_rules! check_unexpected_fields {
        ($rrs:expr, $log_prefix:expr, $( $field:ident ),* $(,)? ) => {
            $(
                if $rrs.$field.is_some() {
                    debug!("{}: field is unexpectedly populated: {}", $log_prefix, stringify!($field));
                    return false;
                }
            )*
        };
    }

    check_unexpected_fields!(
        rrs,
        log_prefix,
        alias_target,
        cidr_routing_config,
        failover,
        geo_location,
        multi_value_answer,
        region,
        set_identifier,
        traffic_policy_instance_id,
    );

    let rrs_ips = get_ip_addresses_from_resource_record_set(rrs);
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
            if current
                .resource_records
                .as_ref()
                .is_some_and(|rrs| !rrs.is_empty())
            {
                debug!("{log_prefix}: adding DELETE");
                let chg = Change::builder()
                    .set_action(Some(ChangeAction::Delete))
                    .set_resource_record_set(Some(current.clone()))
                    .build()
                    .context("error building Route53:Change (deletion) object")?;
                changes.push(chg);
                changes_added = true;
            }
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
    r53: &aws_sdk_route53::Client,
    config: &Config,
    desired_addresses: &Addresses,
    current_address_records: &Route53AddressRecords,
) -> anyhow::Result<UpdateHostResult> {
    // Build up the set of changes required (if any).
    let changes = {
        let mut changes = Vec::<Change>::new();

        // Handle IPv4 addresses
        _compare_add_to_change_set(
            config,
            &desired_addresses.v4,
            &current_address_records.v4,
            RrType::A,
            &mut changes,
            "ipv4",
        )
        .context("error determining ipv4-specific changes")?;

        // Handle IPv6 addresses
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

    // Early exit opportunity
    if changes.is_empty() {
        return Ok(UpdateHostResult::NotRequired);
    } else if config.no_update {
        return Ok(UpdateHostResult::UpdateSkipped);
    }

    // Submit the change request
    let start_time = Instant::now();
    let expiry_time = start_time
        .checked_add(config.update_timeout.to_owned())
        .ok_or(anyhow!(
            "Could not set timeout expiry (update_timeout is too large)"
        ))?;

    let cb = ChangeBatch::builder()
        .set_changes(Some(changes))
        .build()
        .context("error building Route53:ChangeBatch object")?;
    let change_fut = r53
        .change_resource_record_sets()
        .set_change_batch(Some(cb))
        .set_hosted_zone_id(config.route53_zone_id.to_owned())
        .send();

    // Await response to the change request
    let timeout_fut = timeout(config.update_timeout.to_owned(), change_fut);
    let response = match timeout_fut.await {
        Ok(r) => r,
        Err(_) => {
            return Err(anyhow!("timed out waiting for change submission response"));
        }
    };
    let mut ci = response?.change_info.ok_or(anyhow!(
        "ChangeResourceRecordSets response unexpectedly lacks ChangeInfo field"
    ))?;

    // Wait for the change(s) to be synchronized with Route53
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
        let output = r53
            .get_change()
            .set_id(Some(ci.id))
            .send()
            .await
            .context("error calling Route53:GetChange")?;

        ci = output.change_info.ok_or(anyhow!(
            "GetChange route53 response unexpectedly lacks ChangeInfo"
        ))?
    }
    debug!("Route53 now reports that the change has been synchronized.");

    Ok(UpdateHostResult::UpdateSuccessful)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_route53::types::{
        AliasTarget, CidrRoutingConfig, GeoLocation, ResourceRecordSetFailover,
    };
    use std::net::Ipv4Addr;
    use std::sync::LazyLock;
    use std::time::Duration;

    static TEST_CONFIG: LazyLock<Config> = LazyLock::new(|| Config {
        host_name: "example.com".into(),
        update_poll_interval: Duration::from_secs(1),
        update_timeout: Duration::from_secs(100),
        no_update: true,
        route53_record_ttl: 60,
        ..Default::default()
    });

    #[test]
    fn test_rrset_matches_expected() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set = test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s).unwrap())
            .collect::<HashSet<_>>();

        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[0])
                    .build()
                    .unwrap(),
            )
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));
    }

    #[test]
    fn test_rrset_mismatch_for_ttl() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set = test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s).unwrap())
            .collect::<HashSet<_>>();

        // First test with a "slightly wrong" TTL
        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl + 1)
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[0])
                    .build()
                    .unwrap(),
            )
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Re-test with no TTL at all
        let rrs = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[0])
                    .build()
                    .unwrap(),
            )
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));
    }

    #[test]
    fn test_rrset_mismatch_for_special() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set = test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s).unwrap())
            .collect::<HashSet<_>>();

        let rrs_base = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[0])
                    .build()
                    .unwrap(),
            )
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            );

        // First the baseline test to ensure everything *else* is correct.
        let rrs = rrs_base.clone().build().unwrap();
        assert!(resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Now test for a variety of unexpected options.

        let rrs = rrs_base
            .clone()
            .alias_target(
                AliasTarget::builder()
                    .dns_name("target")
                    .hosted_zone_id("Z-12345")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base
            .clone()
            .cidr_routing_config(
                CidrRoutingConfig::builder()
                    .collection_id("collection")
                    .location_name("location")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base
            .clone()
            .failover(ResourceRecordSetFailover::Primary)
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base
            .clone()
            .geo_location(GeoLocation::builder().country_code("CA").build())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base.clone().multi_value_answer(true).build().unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base
            .clone()
            .region(aws_sdk_route53::types::ResourceRecordSetRegion::CaCentral1)
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base.clone().set_identifier("q").build().unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        let rrs = rrs_base
            .clone()
            .traffic_policy_instance_id("i-12345")
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));
    }

    #[test]
    fn test_rrset_mismatch_for_mismatched_addrs() {
        let test_config = &*TEST_CONFIG;

        let test_ip_strs = ["192.168.0.1", "192.168.0.2"];
        let test_ips_set = test_ip_strs
            .iter()
            .map(|s| Ipv4Addr::from_str(*s).unwrap())
            .collect::<HashSet<_>>();

        let rrs_base = ResourceRecordSet::builder()
            .name(test_config.host_name.clone())
            .r#type(RrType::A)
            .ttl(test_config.route53_record_ttl)
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[0])
                    .build()
                    .unwrap(),
            );

        // Baseline test
        let rrs = rrs_base
            .clone()
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert!(resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Test with one address missing
        let rrs = rrs_base.clone().build().unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Test with an extra, unexpected address
        let rrs = rrs_base
            .clone()
            .resource_records(
                ResourceRecord::builder()
                    .value(test_ip_strs[1])
                    .build()
                    .unwrap(),
            )
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Test with partially-overlapping addresses
        let rrs = rrs_base
            .clone()
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));

        // Test with completely dissimilar addresses
        let rrs = rrs_base
            .clone()
            .resource_records(ResourceRecord::builder().value("10.0.0.1").build().unwrap())
            .resource_records(ResourceRecord::builder().value("10.0.0.2").build().unwrap())
            .build()
            .unwrap();
        assert!(!resource_record_set_matches_expected(
            &rrs,
            &test_config,
            &test_ips_set,
            ""
        ));
    }
}
