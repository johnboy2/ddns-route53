 #![feature(async_closure, async_fn_traits, type_alias_impl_trait)]

use std::sync::Arc;

use log::{debug, error, trace};

mod addresses;
mod aws_route53;
mod cli;
mod config;
mod ip_algorithms;


#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = crate::cli::parse_cli_args();

    simple_logger::init_with_level(
        match args.verbose {
            0 => log::Level::Warn,
            1 => log::Level::Info,
            2 => log::Level::Debug,
            _ => log::Level::Trace,
        }
    ).unwrap();
    debug!("Log-level set to {}", log::max_level());

    let config = match crate::config::Config::load(&args.config_path).await {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return;
        }
    };
    trace!("{:?}", config);
    let arc_config = Arc::new(config);

    let set = tokio::task::LocalSet::new();

    let fut_ipv4 = {
        let arc_config = arc_config.clone();
        set.spawn_local(async move {
            arc_config.get_ipv4_addresses().await
        })
    };
    let fut_ipv6 = {
        let arc_config = arc_config.clone();
        set.spawn_local(async move {
            arc_config.get_ipv6_addresses().await
        })
    };

    set.await;
    let addresses = crate::addresses::Addresses { 
        v4: fut_ipv4.await.unwrap(),
        v6: fut_ipv6.await.unwrap()
    };
    debug!("Got {:?}", addresses);

}
