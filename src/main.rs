// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::process::exit;
use std::rc::Rc;
use std::time::Instant;

use log::{debug, error, info, trace, warn};
use tokio::task::{JoinHandle, LocalSet};

mod addresses;
mod aws_route53;
mod cli;
mod config;
mod ip_algorithms;

use crate::addresses::{Route53AddressRecords, Addresses};
use crate::aws_route53::{
    get_resource_records, update_host_addresses_if_different, UpdateHostResult,
};
use crate::config::Config;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let start_time = Instant::now();

    let config = match Config::load().await {
        Ok(config) => config,
        Err(e) => {
            error!("{e:?}");
            return;
        }
    };

    debug!("Using config file: {:?}", &config.config_file_path);
    trace!("Configuration: {}", serde_json::to_string(&config).unwrap());
    let arc_config = Rc::new(config);

    let local_set = LocalSet::new();

    let fut_ipv4 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move { 
            let r = arc_config.get_ipv4_addresses().await;
            trace!("Local IPv4 address determination took {:.2} seconds", start_time.elapsed().as_secs_f32());
            r
        })
    };
    let fut_ipv6 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move { 
            let r = arc_config.get_ipv6_addresses().await;
            trace!("Local IPv6 address determination took {:.2} seconds", start_time.elapsed().as_secs_f32());
            r
        })
    };

    let fut_r53_addresses: JoinHandle<anyhow::Result<Route53AddressRecords>> = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move {
            let config = arc_config.as_ref();
            let r = get_resource_records(
                &config.route53_client,
                &config.host_name_normalized,
                &config.route53_zone_id,
            )
            .await;
            trace!("Route53 address query took {:.2} seconds", start_time.elapsed().as_secs_f32());
            r
        })
    };

    local_set.await;

    let addresses_current = Addresses {
        v4: fut_ipv4.await.expect("future-join should not panic"),
        v6: fut_ipv6.await.expect("future-join should not panic"),
    };
    debug!("Got current: {:?}", addresses_current);

    let addresses_route53 = match fut_r53_addresses
        .await
        .expect("future-join should not panic")
    {
        Ok(r) => r,
        Err(e) => {
            error!("{:#}", e);
            return;
        }
    };
    debug!("Got route53: {:?}", Addresses::from(&addresses_route53));

    let update_time = Instant::now();
    match update_host_addresses_if_different(&arc_config, &addresses_current, &addresses_route53)
        .await
    {
        Ok(result) => {
            match result {
                UpdateHostResult::NotRequired => {
                    info!("Update not required");
                }
                UpdateHostResult::UpdateSuccessful => {
                    info!("Update successful");
                    trace!("Route53 update took {:.2} seconds", update_time.elapsed().as_secs_f32());
                }
                UpdateHostResult::UpdateSkipped => {
                    warn!("Update required, but skipped due to --no_update");
                    exit(78); // Code matches the BSD definition for "EX_CONFIG".
                }
            }
        }
        Err(e) => {
            error!("Update failed: {e:#}")
        }
    };
    trace!("Total time required: {:.2} seconds", start_time.elapsed().as_secs_f32());
}
