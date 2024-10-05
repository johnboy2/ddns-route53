use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_route53::config::Credentials;
use aws_sdk_route53::Client;
use aws_sdk_route53::types::{ResourceRecord, RrType};
use aws_types::region::Region;
use futures::join;
use log::{debug, error};
use tokio::time::{sleep, timeout};

use crate::addresses::Addresses;
use crate::config::Config;


pub async fn get_client(
    aws_profile: &Option<String>,
    aws_access_key_id: &Option<String>,
    aws_secret_access_key: &Option<String>,
    aws_region: &Option<String>,
) -> Client {
    let sdk_config = ::aws_config::load_from_env().await;
    let mut config_builder = ::aws_sdk_route53::config::Builder::from(&sdk_config);

    if aws_region.is_some() {
        let region = Region::new(aws_region.as_ref().unwrap().to_owned());
        config_builder.set_region(Some(region));
    }

    if aws_access_key_id.is_some() && aws_secret_access_key.is_some() {
        let creds = Credentials::new(
            aws_access_key_id.as_ref().unwrap(), 
            aws_secret_access_key.as_ref().unwrap(), 
            None,
            None,
            "configfile"
        );
        config_builder = config_builder.credentials_provider(creds);
    } else if aws_profile.is_some() {
        let profile = ProfileFileCredentialsProvider::builder()
            .profile_name(aws_profile.as_ref().unwrap())
            .build()
        ;
        config_builder = config_builder.credentials_provider(profile);
    }

    let config = config_builder.build();
    let client = Client::from_conf(config);

    client   
}


fn host_is_in_domain(host_lowercase: &str, domain: &str) -> bool {
    let domain = domain.to_lowercase();

    if host_lowercase == domain {
        return true;
    }
    if host_lowercase.ends_with(domain.as_str()) {
        let host = host_lowercase.as_bytes();
        let domain = domain.as_bytes();
        let maybe_separator = host[host.len() - domain.len() - 1];
        if maybe_separator == b'.' {
            return true;
        }
    }

    false
}


pub async fn get_zone_id(client: &Client, host_name: &String) -> Result<String, String> {
    let mut stream = client.list_hosted_zones().into_paginator().send();
    while let Some(page) = stream.next().await {
        match page {
            Ok(result) => {
                for zone in result.hosted_zones.iter() {
                    if host_is_in_domain(host_name.as_str(), zone.name()) {
                        return Ok(zone.id.to_owned())
                    }
                }
            },
            Err(e) => {
                return Err(e.to_string())
            },
        };
    }

    Err("not found".to_owned())
}


pub async fn get_host_addresses_for_single_rr_type<IPTYPE>(
        client: &Client,
        host_name: &String,
        route53_zone_id: &String,
        rrtype: RrType,
) -> Result<Vec::<IPTYPE>, String>
    where IPTYPE: std::str::FromStr,
          <IPTYPE as std::str::FromStr>::Err: std::fmt::Display
{
    let mut result = Vec::<IPTYPE>::new();

    let output = client.list_resource_record_sets()
        .set_hosted_zone_id(Some(route53_zone_id.to_owned()))
        .set_start_record_name(Some(host_name.to_owned()))
        .set_start_record_type(Some(rrtype.clone()))
        .set_max_items(Some(1))
        .send()
        .await
    ;
    match output {
        Ok(output) => {
            for rrs in output.resource_record_sets.iter() {
                if &rrs.name != host_name || rrs.r#type != rrtype {
                    break;
                }

                debug!("Got name: [{}] (type: {})", rrs.name, rrs.r#type);
                match &rrs.resource_records {
                    Some(values) => {
                        for value_struct in values.iter() {
                            match value_struct.value.parse::<IPTYPE>() {
                                Ok(ip) => { result.push(ip) },
                                Err(e) => {
                                    return Err(
                                        format!("Got bad 'A' record value back from route53: \"{}\": {}", value_struct.value, e.to_string())
                                    )
                                }
                            }
                        }
                    },
                    None => {}
                }
            }
        },
        Err(e) => { return Err(e.to_string()) }
    };

    Ok(result)
}


pub async fn get_host_addresses(
        client: &Client,
        host_name: &String,
        route53_zone_id: &Option<String>,
) -> Result<Addresses, String> {
    let zone_id = match route53_zone_id {
        Some(value) => value.to_owned(),
        None => get_zone_id(client, host_name).await?
    };

    let fut_ipv4 = get_host_addresses_for_single_rr_type::<Ipv4Addr>(
        client, host_name, &zone_id, RrType::A
    );
    let fut_ipv6 = get_host_addresses_for_single_rr_type::<Ipv6Addr>(
        client, host_name, &zone_id, RrType::Aaaa
    );

    let (result_ipv4, result_ipv6) = join!(fut_ipv4, fut_ipv6);
    let result_ipv4 = match result_ipv4 {
        Ok(rrs) => rrs,
        Err(e) => { return Err(e.to_string()) }
    };
    let result_ipv6 = match result_ipv6 {
        Ok(rrs) => rrs,
        Err(e) => { return Err(e.to_string()) }
    };

    Ok(Addresses { v4: result_ipv4, v6: result_ipv6 })
}


trait IpAny : std::fmt::Display{}
impl IpAny for Ipv4Addr {}
impl IpAny for Ipv6Addr {}


fn _build_r53_change_set(
        host_name: String,
        ttl: i64,
        addresses: &Vec::<impl IpAny + Sized>,
        rr_type: aws_sdk_route53::types::RrType,
        action: aws_sdk_route53::types::ChangeAction
) -> Result<aws_sdk_route53::types::Change, String> {
    let mut rr_vec = Vec::<ResourceRecord>::new();
    for ip in addresses.iter() {
        let rr = match
            aws_sdk_route53::types::ResourceRecord::builder()
            .set_value(Some(ip.to_string()))
            .build()
        {
            Ok(r) => r,
            Err(e) => { return Err(format!("convert ip to RR: {}", e.to_string())) }
        };
        rr_vec.push(rr);
    }

    let rrs = match
        aws_sdk_route53::types::ResourceRecordSet::builder()
        .set_name(Some(host_name))
        .set_type(Some(rr_type))
        .set_resource_records(Some(rr_vec))
        .set_ttl(Some(ttl))
        .build()
    {
        Ok(rrs) => rrs,
        Err(e) => { return Err(format!("building rrs: {}", e.to_string())) }
    };
    let chg = match
        aws_sdk_route53::types::Change::builder()
        .set_action(Some(action))
        .set_resource_record_set(Some(rrs))
        .build()
    {
        Ok(chg) => chg,
        Err(e) => { return Err(format!("building change set: {}", e.to_string())) }
    };

    Ok(chg)
}


pub async fn set_host_addresses(
        config: &Config,
        desired_addresses: &Addresses,
        current_addresses: &Addresses
) -> Result<(), String> {
    let mut changes = Vec::<aws_sdk_route53::types::Change>::new();
 
    if desired_addresses.v4 != current_addresses.v4 {
        if desired_addresses.v4.is_empty() {
            changes.push(
                _build_r53_change_set(
                    config.host_name.to_owned(),
                    config.route53_record_ttl,
                    &current_addresses.v4, 
                    aws_sdk_route53::types::RrType::A, 
                    aws_sdk_route53::types::ChangeAction::Delete
                )?
            );
        } else {
            changes.push(
                _build_r53_change_set(
                    config.host_name.to_owned(), 
                    config.route53_record_ttl,
                    &desired_addresses.v4, 
                    aws_sdk_route53::types::RrType::A, 
                    aws_sdk_route53::types::ChangeAction::Upsert
                )?
            );
        }
    }
 
    if desired_addresses.v6 != current_addresses.v6 {
        if desired_addresses.v6.is_empty() {
            changes.push(
                _build_r53_change_set(
                    config.host_name.to_owned(), 
                    config.route53_record_ttl,
                    &current_addresses.v6, 
                    aws_sdk_route53::types::RrType::Aaaa, 
                    aws_sdk_route53::types::ChangeAction::Delete
                )?
            );
        } else {
            changes.push(
                _build_r53_change_set(
                    config.host_name.to_owned(), 
                    config.route53_record_ttl,
                    &desired_addresses.v6, 
                    aws_sdk_route53::types::RrType::Aaaa,
                    aws_sdk_route53::types::ChangeAction::Upsert
                )?
            );
        }
    }
    
    if changes.is_empty() {
        return Ok(());
    }
    let start_time = Instant::now();
    let expiry_time = start_time.checked_add(config.update_timeout.to_owned()).unwrap();

    let cb = 
        match
            aws_sdk_route53::types::ChangeBatch::builder()
            .set_changes(Some(changes))
            .build()
        {
            Ok(cb) => cb,
            Err(e) => { return Err(format!("building change batch: {}", e.to_string())) }
        }
    ;
    let change_fut = 
        config.route53_client.change_resource_record_sets()
        .set_change_batch(Some(cb))
        .set_hosted_zone_id(config.route53_zone_id.to_owned())
        .send()
    ;
    let timeout_fut = timeout(config.update_timeout.to_owned(), change_fut);

    let timeout_output = match timeout_fut.await {
        Ok(output) => output,
        Err(_e) => { return Err("Timed out waiting for response".to_owned()) }
    };
    let change_output = match timeout_output {
        Ok(output) => output,
        Err(e) => {
            let rr = e.raw_response().unwrap();
            let msg = String::from_utf8_lossy(
                rr.body().bytes().unwrap()
            );
            error!("SDK returned error: {}", msg);
            return Err(format!("change result: {}", e.to_string()))
        }
    };

    let mut ci = change_output.change_info.unwrap();
    loop {
        if ci.status == aws_sdk_route53::types::ChangeStatus::Insync {
            return Ok(());
        }

        debug!("Change is not yet synchronized.");
        let now = Instant::now();
        let time_elapsed = now - start_time;
        if config.update_timeout <= time_elapsed {
            return Err("Timed out waiting for change to synchronize".to_owned());
        }
        let time_remaining = expiry_time - now;

        sleep(std::cmp::min(time_remaining, config.update_poll_interval)).await;

        debug!("Re-checking whether change is synchronized...");
        let output =
            match
                config.route53_client.get_change()
                .set_id(Some(ci.id))
                .send()
                .await
            {
                Ok(output) => output,
                Err(e) => { return Err(format!("get change error: {}", e.to_string())) }
            }
        ;
        ci = output.change_info.unwrap();
    }
}
