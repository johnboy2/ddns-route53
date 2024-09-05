 #![feature(async_closure, async_fn_traits, type_alias_impl_trait)]

use std::sync::Arc;

use log::error;

mod addresses;
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

    let config = match crate::config::Config::load(&args.config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return;
        }
    };

    println!("{:?}", config);
    let arc_config = Arc::new(config);

    let set = tokio::task::LocalSet::new();
    let arc_config_ipv4 = arc_config.clone();
    let fut_ipv4 = set.spawn_local(async move {
        arc_config_ipv4.get_ipv4_addresses().await
    });
    let arc_config_ipv6 = arc_config.clone();
    let fut_ipv6 = set.spawn_local(async move {
        arc_config_ipv6.get_ipv6_addresses().await
    });

    set.await;
    let addresses = crate::addresses::Addresses { 
        v4: fut_ipv4.await.unwrap(),
        v6: fut_ipv6.await.unwrap()
    };

    println!("{:?}", addresses);

}
