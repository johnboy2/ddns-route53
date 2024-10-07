use std::sync::Arc;
use std::time::SystemTime;

use log::{debug, error, info, trace, warn};

mod addresses;
mod aws_route53;
mod cli;
mod config;
mod ip_algorithms;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = crate::cli::parse_cli_args();

    let log_stdout = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}: {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.target(),
                record.level(),
                message
            ))
        })
        .level_for(
            env!("CARGO_CRATE_NAME"),
            match args.verbose {
                0 => log::LevelFilter::Warn,
                1 => log::LevelFilter::Info,
                2 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            },
        )
        .level(match args.log_other {
            0 => log::LevelFilter::Warn,
            1 => log::LevelFilter::Info,
            2 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .chain(std::io::stdout());

    let config = match crate::config::Config::load(&args.config_path).await {
        Ok(config) => {
            let log_file = config.get_file_logger();
            match log_file {
                Ok(log_file) => {
                    if let Some(log_file) = log_file {
                        fern::Dispatch::new()
                            .chain(log_stdout)
                            .chain(log_file)
                            .apply()
                            .unwrap()  // force panic if multiple loggers
                        ;
                    }
                }
                Err(e) => {
                    log_stdout.apply().unwrap();
                    error!("{e}");
                    return;
                }
            };
            config
        }
        Err(e) => {
            log_stdout.apply().unwrap();
            error!("{e}");
            return;
        }
    };

    trace!("{:?}", config);
    let arc_config = Arc::new(config);

    let set = tokio::task::LocalSet::new();

    let fut_ipv4 = {
        let arc_config = arc_config.clone();
        set.spawn_local(async move { arc_config.get_ipv4_addresses().await })
    };
    let fut_ipv6 = {
        let arc_config = arc_config.clone();
        set.spawn_local(async move { arc_config.get_ipv6_addresses().await })
    };

    let fut_r53_addresses = {
        let arc_config = arc_config.clone();
        set.spawn_local(async move {
            let config = arc_config.as_ref();
            crate::aws_route53::get_host_addresses(
                &config.route53_client,
                &config.host_name_normalized,
                &config.route53_zone_id,
            )
            .await
        })
    };

    set.await;

    let addresses_current = crate::addresses::Addresses {
        v4: fut_ipv4.await.unwrap(),
        v6: fut_ipv6.await.unwrap(),
    };
    debug!("Got current: {:?}", addresses_current);

    let addresses_route53 = match fut_r53_addresses.await.unwrap() {
        Ok(r) => r,
        Err(e) => {
            error!("{}", e);
            return ();
        }
    };
    debug!("Got route53: {:?}", addresses_route53);

    if addresses_current == addresses_route53 {
        debug!("Current addresses match route53 configuration; no update required.");
        return;
    } else if args.no_update {
        warn!("Current addresses DO NOT match configuration, but not updating due to --no_update");
        std::process::exit(78); // Code matches the BSD definition for "EX_CONFIG".
    }

    debug!("Address mismatch: attempting route53 update...");
    match crate::aws_route53::set_host_addresses(
        &*arc_config,
        &addresses_current,
        &addresses_route53,
    )
    .await
    {
        Ok(()) => {
            info!("Update successful")
        }
        Err(e) => {
            error!("Update failed: {e}")
        }
    };
}
