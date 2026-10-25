// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::Instant;

use log::{debug, info, trace, warn};
use tokio::task::{JoinHandle, LocalSet};

mod addresses;
mod aws_route53;
mod config;
mod host_names;
mod ip_algorithms;
mod os_helpers;

use crate::addresses::{Addresses, Route53AddressRecords};
use crate::aws_route53::{
    find_zone_id, get_resource_records, update_host_addresses_if_different, UpdateHostResult,
};
use crate::config::Config;
use crate::ip_algorithms::AlgorithmSpecification;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let start_time = Instant::now();

    let (config, aws_loader) = Config::load()?;
    debug!("Using config file: {:?}", &config.config_file_path);
    trace!(
        "Configuration:\n{}",
        toml_edit::ser::to_string(&config)
            .expect("TOML-serialization of in-memory config should always succeed")
    );

    let arc_config = Rc::new(config);

    // Install a default crypto provider. We do this here because it should happen exactly once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let local_set = LocalSet::new();

    let fut_ipv4 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move {
            let time = Instant::now();
            let algos: &[AlgorithmSpecification] = arc_config.ipv4_algorithms.as_ref();
            let r =
                AlgorithmSpecification::get_public_ip_address_for_algos::<Ipv4Addr>(algos).await;
            trace!(
                "Local IPv4 address determination took {:.2} seconds",
                time.elapsed().as_secs_f32()
            );
            r
        })
    };
    let fut_ipv6 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move {
            let time = Instant::now();
            let algos: &[AlgorithmSpecification] = arc_config.ipv6_algorithms.as_ref();
            let r =
                AlgorithmSpecification::get_public_ip_address_for_algos::<Ipv6Addr>(algos).await;
            trace!(
                "Local IPv6 address determination took {:.2} seconds",
                time.elapsed().as_secs_f32()
            );
            r
        })
    };

    let r53 = {
        let time: Instant = Instant::now();
        let sdk_config = aws_loader.load().await;
        let config_builder = aws_sdk_route53::config::Builder::from(&sdk_config);
        let config = config_builder.build();
        let r53 = aws_sdk_route53::Client::from_conf(config);
        trace!(
            "SDK configuration loading took {:.2} seconds",
            time.elapsed().as_secs_f32()
        );
        r53
    };
    let rc_r53 = Rc::new(r53);

    let zone_id = match arc_config.route53_zone_id.as_ref() {
        Some(zid) => {
            // Configuration or CLI gave us the zoneid; use the one we were given.
            zid.clone()
        }
        None => {
            // Zone ID was *NOT* provided -- so we must search for which zone to use
            let arc_config = arc_config.clone();
            let rc_r53 = rc_r53.clone();
            match local_set
                .spawn_local(async move {
                    let time: Instant = Instant::now();
                    let zone_id_lookup_result = find_zone_id(
                        rc_r53.as_ref(),
                        arc_config.host_name.as_str(),
                        arc_config.host_name_normalized.as_str(),
                    )
                    .await;
                    trace!(
                        "Dynamic zone ID lookup took {:.2} seconds",
                        time.elapsed().as_secs_f32()
                    );
                    zone_id_lookup_result
                })
                .await
            {
                Ok(Ok(zone_id)) => zone_id,
                Ok(Err(e)) => {
                    return Err(anyhow::Error::msg(format!("Failed to find zone ID: {e:?}")));
                }
                Err(e) => {
                    return Err(anyhow::Error::msg(format!("Failed to find zone ID: {e:?}")));
                }
            }
        }
    };

    let fut_r53_addresses: JoinHandle<anyhow::Result<Route53AddressRecords>> = {
        let arc_config = arc_config.clone();
        let rc_r53 = rc_r53.clone();
        let zone_id = zone_id.clone();
        local_set.spawn_local(async move {
            let config = arc_config.as_ref();
            let r53_ref = rc_r53.as_ref();
            let time: Instant = Instant::now();
            let rrs =
                get_resource_records(r53_ref, &config.host_name_normalized, zone_id.as_ref()).await;
            trace!(
                "Route53 address query took {:.2} seconds",
                time.elapsed().as_secs_f32()
            );
            rrs
        })
    };

    local_set.await;

    let addresses_current = Addresses {
        v4: fut_ipv4.await.expect("future-join should not panic")?,
        v6: fut_ipv6.await.expect("future-join should not panic")?,
    };
    debug!("Got current: {:?}", addresses_current);

    let addresses_route53 = match fut_r53_addresses
        .await
        .expect("future-join should not panic")
    {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow::Error::msg(format!(
                "Failed to determine existing Route53 addresses: {e:?}"
            )));
        }
    };
    debug!("Got route53: {:?}", Addresses::from(&addresses_route53));

    let update_time = Instant::now();
    match update_host_addresses_if_different(
        rc_r53.as_ref(),
        arc_config.as_ref(),
        zone_id.as_str(),
        &addresses_current,
        &addresses_route53,
    )
    .await
    {
        Ok(result) => match result {
            UpdateHostResult::NotRequired => {
                info!("Update not required");
            }
            UpdateHostResult::UpdateSuccessful => {
                info!("Update successful");
                trace!(
                    "Route53 update took {:.2} seconds",
                    update_time.elapsed().as_secs_f32()
                );
            }
            UpdateHostResult::UpdateSkipped => {
                warn!("Update required, but skipped due to --no_update");
            }
        },
        Err(e) => {
            return Err(anyhow::Error::msg(format!("Update failed: {e:#}")));
        }
    };
    trace!(
        "Total time required: {:.2} seconds",
        start_time.elapsed().as_secs_f32()
    );
    Ok(())
}
