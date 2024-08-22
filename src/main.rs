use log::error;

mod cli;
mod config;


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
}
