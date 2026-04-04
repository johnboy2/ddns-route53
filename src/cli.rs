// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Specify an alternate configuration file path
    #[arg(short, long)]
    pub config_path: Option<String>,

    /// Do not update Route53, even if its current value is wrong
    #[arg(short, long)]
    pub no_update: bool,

    /// Increase console logging verbosity (may be used more than once)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Increase console logging for dependent libraries (may be used more than once)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub log_other: u8,
}

pub fn parse_cli_args() -> Args {
    Args::parse()
}
