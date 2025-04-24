use std::io::stdout;
use std::process::exit;
use std::rc::Rc;
use std::time::SystemTime;

use fern::Dispatch;
use humantime::format_rfc3339_seconds;
use log::{debug, error, info, trace, warn, LevelFilter};
use tokio::task::{JoinHandle, LocalSet};

mod addresses;
mod aws_route53;
mod cli;
mod config;
mod ip_algorithms;

use crate::addresses::{AddressRecords, Addresses};
use crate::aws_route53::{
    get_resource_records, update_host_addresses_if_different, UpdateHostResult,
};
use crate::cli::parse_cli_args;
use crate::config::Config;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_cli_args();

    let log_stdout = Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}: {}",
                format_rfc3339_seconds(SystemTime::now()),
                record.target(),
                record.level(),
                message
            ))
        })
        .level_for(
            env!("CARGO_CRATE_NAME"),
            match args.verbose {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            },
        )
        .level(match args.log_other {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .chain(stdout());

    let config = match Config::load(&args.config_path).await {
        Ok(config) => {
            let log_file = config.get_file_logger();
            match log_file {
                Ok(log_file) => {
                    if let Some(log_file) = log_file {
                        Dispatch::new()
                            .chain(log_stdout)
                            .chain(log_file)
                            .apply()
                            .expect("multiple loggers not allowed");
                    }
                }
                Err(e) => {
                    log_stdout.apply().expect("multiple loggers not allowed");
                    error!("{e}");
                    return;
                }
            };
            config
        }
        Err(e) => {
            log_stdout.apply().expect("multiple loggers not allowed");
            error!("{e:?}");
            return;
        }
    };

    trace!("{:?}", config);
    let arc_config = Rc::new(config);

    let local_set = LocalSet::new();

    let fut_ipv4 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move { arc_config.get_ipv4_addresses().await })
    };
    let fut_ipv6 = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move { arc_config.get_ipv6_addresses().await })
    };

    let fut_r53_addresses: JoinHandle<anyhow::Result<AddressRecords>> = {
        let arc_config = arc_config.clone();
        local_set.spawn_local(async move {
            let config = arc_config.as_ref();
            get_resource_records(
                &config.route53_client,
                &config.host_name_normalized,
                &config.route53_zone_id,
            )
            .await
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
            error!("{}", e);
            return;
        }
    };
    debug!("Got route53: {:?}", Addresses::from(&addresses_route53));

    match update_host_addresses_if_different(
        &arc_config,
        &addresses_current,
        &addresses_route53,
        !args.no_update,
    )
    .await
    {
        Ok(result) => {
            match result {
                UpdateHostResult::NotRequired => {
                    info!("Update not required");
                }
                UpdateHostResult::UpdateSuccessful => {
                    info!("Update successful");
                }
                UpdateHostResult::UpdateSkipped => {
                    warn!("Update required, but skipped due to --no_update");
                    exit(78); // Code matches the BSD definition for "EX_CONFIG".
                }
            }
        }
        Err(e) => {
            error!("Update failed: {e}")
        }
    };
}
