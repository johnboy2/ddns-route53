use clap::Parser;

static DEFAULT_CONFIG_FILE: &'static str = "ddns-route53.conf";


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Specify an alternate configuration file path
    #[arg(short, long, default_value_t = DEFAULT_CONFIG_FILE.to_string())]
    pub config_path: String,

    /// Do not update Route53, even if its current value is wrong
    #[arg(short, long)]
    pub no_update: bool,

    /// Increase logging verbosity (may be used more than once)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}


pub fn parse_cli_args() -> Args {
    Args::parse()
}