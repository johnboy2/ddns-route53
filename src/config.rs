use std::borrow::Cow;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context};
use aws_config::ConfigLoader;
use aws_sdk_route53::config::Credentials;
use aws_types::region::Region;
use clap::{ArgAction, Args, Parser, ValueHint};
use fern::Dispatch;
use humantime::format_rfc3339_seconds;
use idna::{domain_to_ascii_cow, AsciiDenyList};
use log::{debug, LevelFilter};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

use crate::ip_algorithms::AlgorithmSpecification;

const DEFAULT_UPDATE_POLL_SECS: f64 = 30.0;
const DEFAULT_UPDATE_TIMEOUT_SECS: f64 = 300.0;
const DEFAULT_ROUTE53_TLL: i32 = 3600;
const DEFAULT_LOG_FILE_LEVEL: LevelFilter = LevelFilter::Info;
const DEFAULT_LOG_FILE_LEVEL_OTHER: LevelFilter = LevelFilter::Off;
const MAX_CONFIG_FILE_SIZE_BYTES: u64 = 65536;
const MAX_UPDATE_POLL_SECONDS: f64 = 3600.0;
const MAX_UPDATE_TIMEOUT_SECONDS: f64 = 86400.0;
const MIN_UPDATE_POLL_SECONDS: f64 = 0.0;
const MIN_UPDATE_TIMEOUT_SECONDS: f64 = 0.0;
const MIN_TTL: i32 = 0;
const MAX_TTL: i32 = 2147483647;

mod serde_levelfilter {
    use std::str::FromStr;

    use log::LevelFilter;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<LevelFilter>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        match LevelFilter::from_str(s.as_str()) {
            Ok(level) => {
                // Why disallow "trace" to log files? Because it leaks AWS secrets within the Client object.
                // I briefly entertained the idea of a CLI flag to allow override this restriction, but decided against that
                // on the grounds that enabling truly dumb behavior (i.e., knowingly leaking secrets into log files) is
                // almost always unwise. (At least any console leaking that might occur is under control of the user who has
                // those secrets already.)
                if level == LevelFilter::Trace {
                    Err(D::Error::custom("This level is not allowed for the log file. Use the \"-vvv\" CLI option to get trace-level logging to the console instead."))
                } else {
                    Ok(Some(level))
                }
            }
            Err(_) => Err(D::Error::custom("Unknown log level")),
        }
    }
}

// Our CommonOptions struct has a lot of fields that are shared between the CLI and the configuration file, so we want
// to use the same logic for validating each regardless of source (i.e., CLI or config file). These functions help us
// do that, by providing a way to validate and parse each field consistently.
//
// The parse_*() functions are for the CLI arg parsing.
// The deser_*() functions are for deserializing from the configuration file (they use the corresponding parse_*()
// function internally for consistent behavior).
//
// The various traits and structs are used to provide field-details. (Serde doesn't provide a way to include field-
// specific details within the deserialization functions -- but do allow passing additional generic parameters; so
// we leverage that mechanism to pass these details.)

trait FieldNameString {
    fn name() -> &'static str;
}

struct FieldAwsProfile {}
impl FieldNameString for FieldAwsProfile {
    fn name() -> &'static str {
        "aws_profile"
    }
}

struct FieldAwsRegion {}
impl FieldNameString for FieldAwsRegion {
    fn name() -> &'static str {
        "aws_region"
    }
}

struct FieldAwsAccessKeyId {}
impl FieldNameString for FieldAwsAccessKeyId {
    fn name() -> &'static str {
        "aws_access_key_id"
    }
}

struct FieldAwsSecretAccessKey {}
impl FieldNameString for FieldAwsSecretAccessKey {
    fn name() -> &'static str {
        "aws_secret_access_key"
    }
}

fn parse_nonempty_string<FieldParams>(value: &str) -> anyhow::Result<String>
where
    FieldParams: FieldNameString,
{
    if value.is_empty() {
        Err(anyhow!(
            "value for {0} cannot be empty",
            FieldParams::name()
        ))
    } else {
        Ok(value.to_string())
    }
}

fn deser_nonempty_string<'de, D, FieldParams>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
    FieldParams: FieldNameString,
{
    if let Some(value) = Option::<String>::deserialize(deserializer)?.as_ref() {
        parse_nonempty_string::<FieldParams>(value.as_str())
            .map(Some)
            .map_err(|e| D::Error::custom(e.to_string()))
    } else {
        Ok(None)
    }
}

trait NumericFieldParameters {
    type OutputType;

    fn name() -> &'static str;
    fn type_name_singular() -> &'static str;
    fn min() -> Self::OutputType;
    fn max() -> Self::OutputType;
}

struct FieldTTL {}
impl NumericFieldParameters for FieldTTL {
    type OutputType = i32;

    fn name() -> &'static str {
        "route53_record_ttl"
    }
    fn type_name_singular() -> &'static str {
        "an integer"
    }
    fn min() -> Self::OutputType {
        MIN_TTL
    }
    fn max() -> Self::OutputType {
        MAX_TTL
    }
}

// This function ensures very large numbers are treated the same as any other "out-of-range" value, rather than
// overflowing or emitting some other, less-graceful error.
fn parse_ranged_number<FieldParams>(value: &str) -> anyhow::Result<FieldParams::OutputType>
where
    FieldParams: NumericFieldParameters,
    <FieldParams as NumericFieldParameters>::OutputType: Display + FromStr + PartialOrd,
{
    if let Ok(result) = value.parse::<FieldParams::OutputType>() {
        if FieldParams::min() <= result && result <= FieldParams::max() {
            return Ok(result);
        }
    }

    Err(anyhow!(
        "value for {0} must be {1} in the range {2}-{3}",
        FieldParams::name(),
        FieldParams::type_name_singular(),
        FieldParams::min(),
        FieldParams::max()
    ))
}

// This function ensures very large numbers are treated the same as any other "out-of-range" value, rather than
// overflowing or emitting some other, less-graceful error.
fn deser_ranged_number<'de, D, FieldParams>(
    deserializer: D,
) -> Result<Option<FieldParams::OutputType>, D::Error>
where
    D: Deserializer<'de>,
    FieldParams: NumericFieldParameters,
    <FieldParams as NumericFieldParameters>::OutputType:
        Deserialize<'de> + Display + FromStr + PartialOrd,
{
    if let Ok(value) = FieldParams::OutputType::deserialize(deserializer) {
        if FieldParams::min() <= value && value <= FieldParams::max() {
            return Ok(Some(value));
        }
    }

    Err(D::Error::custom(format!(
        "value for {0} must be {1} in the range {2}-{3}",
        FieldParams::name(),
        FieldParams::type_name_singular(),
        FieldParams::min(),
        FieldParams::max()
    )))
}

struct FieldUpdateTimeout {}
impl NumericFieldParameters for FieldUpdateTimeout {
    type OutputType = f64;

    fn name() -> &'static str {
        "route53_update_timeout"
    }
    fn type_name_singular() -> &'static str {
        "a number"
    }
    fn min() -> Self::OutputType {
        MIN_UPDATE_TIMEOUT_SECONDS
    }
    fn max() -> f64 {
        MAX_UPDATE_TIMEOUT_SECONDS
    }
}

struct FieldUpdatePollInterval {}
impl NumericFieldParameters for FieldUpdatePollInterval {
    type OutputType = f64;

    fn name() -> &'static str {
        "route53_update_poll_interval"
    }
    fn type_name_singular() -> &'static str {
        "a number"
    }
    fn min() -> Self::OutputType {
        MIN_UPDATE_POLL_SECONDS
    }
    fn max() -> Self::OutputType {
        MAX_UPDATE_POLL_SECONDS
    }
}

#[derive(Args, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CommonOptions {
    /// The fully-qualified domain name of the host to update. (This must be specified in either a configuration file
    /// or on the command-line.)
    #[arg(short = 'n', long)]
    pub host_name: Option<String>,

    /// (Optional) The Route53 zone ID within AWS to keep up to date. If not specified, the utility will attempt to
    /// resolve this dynamically
    #[arg(short = 'z', long, value_name = "ZONE_ID")]
    pub aws_route53_zone_id: Option<String>,

    /// The TTL use when updating the applicable Route53 resource record(s). Defaults to 3600 unless overridden by a
    /// configuration file
    #[arg(short='t', long, value_name = "N", value_parser = parse_ranged_number::<FieldTTL>)]
    #[serde(deserialize_with = "deser_ranged_number::<_, FieldTTL>")]
    pub aws_route53_record_ttl: Option<i32>,

    /// The timeout to use when trying to update the applicable Route53 resource record(s). Defaults to 300 unless
    /// overridden by a configuration file
    #[arg(short='w', long, value_name = "N", value_parser = parse_ranged_number::<FieldUpdateTimeout>)]
    #[serde(deserialize_with = "deser_ranged_number::<_, FieldUpdateTimeout>")]
    pub update_timeout_seconds: Option<f64>,

    /// The timeout to use when trying to update the applicable Route53 resource record(s). Defaults to 30 unless
    /// overridden by a configuration file
    #[arg(short='s', long, value_name = "N", value_parser = parse_ranged_number::<FieldUpdatePollInterval>)]
    #[serde(alias = "update_poll_seconds", deserialize_with = "deser_ranged_number::<_, FieldUpdatePollInterval>")]
    pub update_poll_interval_seconds: Option<f64>,

    /// Use a specific profile from your (AWS) credential file
    #[arg(short='p', long, value_name = "PROFILE", value_parser = parse_nonempty_string::<FieldAwsProfile>)]
    #[serde(deserialize_with = "deser_nonempty_string::<_, FieldAwsProfile>")]
    pub aws_profile: Option<String>,

    /// Use an AWS region for Route53 API calls. If omitted, this usually defaults to "us-east-1" (depends on your
    /// local Route53 SDK configuration)
    #[arg(short='r', long, value_name = "REGION", value_parser = parse_nonempty_string::<FieldAwsRegion>)]
    #[serde(deserialize_with = "deser_nonempty_string::<_, FieldAwsRegion>")]
    pub aws_region: Option<String>,

    /// (Optional) File-path at which to log events or actions related to this utility's execution. This may be used
    /// either instead of, or in addition to, console logging
    #[arg(short='f', long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    pub log_file: Option<std::path::PathBuf>,

    /// (Optional) Set the logging-level of this tool to the `log_file`. Must be one of "off", "error", "warn", "info",
    /// or "debug". (This DOES NOT affect console-output verbosity.) Defaults to "info"
    #[arg(short='l', long, value_parser = clap::value_parser!(LevelFilter), value_name = "LEVEL")]
    #[serde(with = "serde_levelfilter")]
    pub log_level: Option<LevelFilter>,

    /// (Optional) Set the logging-level of other libraries this tool uses internally to the `log_file`. Must be one of
    /// "off", "error", "warn", "info", or "debug". (This DOES NOT affect console-output verbosity.) Defaults to "off"
    #[arg(short='o', long, value_parser = clap::value_parser!(LevelFilter), value_name = "LEVEL")]
    #[serde(with = "serde_levelfilter")]
    pub log_level_other: Option<LevelFilter>,

    /// (Optional) The IPv4 algorithms to use when determining the public IPv4 address. If omitted, the utility will
    /// assume that no IPv4 addresses are present. Each entry must be a TOML-formatted inline table. See the
    /// "ddns-route53.conf" example file for per-algorithm content details and examples
    #[arg(
        short='4', long="ipv4", action=ArgAction::Append, value_name = "ALGO",
        value_parser = |arg: &str| toml::from_str::<AlgorithmSpecification>(arg)
    )]
    pub ipv4_algorithms: Option<Vec<AlgorithmSpecification>>,

    /// (Optional) The IPv6 algorithms to use when determining the public IPv6 address. If omitted, the utility will
    /// assume that no IPv6 addresses are present. Each entry must be a TOML-formatted inline table. See the
    /// "ddns-route53.conf" example file for per-algorithm content details and examples
    #[arg(
        short='6', long="ipv6", action=ArgAction::Append, value_name = "ALGO",
        value_parser = |arg: &str| toml::from_str::<AlgorithmSpecification>(arg)
    )]
    pub ipv6_algorithms: Option<Vec<AlgorithmSpecification>>,
}

#[derive(Parser)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct CliOptions {
    /// Specify a configuration file path. If omitted, it will search a default set of paths for the file to use.
    /// (Pass the special value '-' to disable use of a configuration file.)
    #[arg(short='c', long, value_hint = ValueHint::FilePath, value_name = "PATH")]
    pub config_path: Option<std::path::PathBuf>,

    /// Do not update Route53, even if its current value is wrong
    #[arg(short = 'u', long)]
    pub no_update: bool,

    /// Increase console logging verbosity (may be used more than once)
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Increase console logging for dependent libraries (may be used more than once); You generally shouldn't need this
    #[arg(long, action = clap::ArgAction::Count)]
    pub verbosity_other: u8,

    #[command(flatten)]
    pub common: CommonOptions,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileOptions {
    #[serde(flatten)]
    pub common: CommonOptions,

    #[serde(deserialize_with = "deser_nonempty_string::<_, FieldAwsAccessKeyId>")]
    pub aws_access_key_id: Option<String>,

    #[serde(deserialize_with = "deser_nonempty_string::<_, FieldAwsSecretAccessKey>")]
    pub aws_secret_access_key: Option<String>,
}

fn serialize_duration_as_secs<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64())
}

#[derive(Default, Serialize)]
pub struct Config {
    pub config_file_path: Option<PathBuf>,
    pub host_name: String,
    pub route53_zone_id: Option<String>,
    pub route53_record_ttl: i32,

    #[serde(
        rename = "update_timeout_seconds",
        serialize_with = "serialize_duration_as_secs"
    )]
    pub update_timeout: Duration,

    #[serde(
        rename = "update_poll_interval_seconds",
        serialize_with = "serialize_duration_as_secs"
    )]
    pub update_poll_interval: Duration,

    pub no_update: bool,
    pub ipv4_algorithms: Vec<AlgorithmSpecification>,
    pub ipv6_algorithms: Vec<AlgorithmSpecification>,

    #[serde(skip)]
    pub host_name_normalized: String,
}

impl Config {
    pub fn load() -> anyhow::Result<(Self, ConfigLoader)> {
        let cli_args = CliOptions::parse();
        let maybe_file_config: Option<FileOptions>;
        let mut result = Self {
            ..Default::default()
        };
        let console_log_dispatcher = create_console_log_dispatcher(&cli_args);

        match find_configuration_file(cli_args.config_path.map(Cow::Owned)) {
            Ok(maybe_file_path) => {
                if let Some(file_path) = maybe_file_path {
                    let file_path_buf = file_path.to_path_buf();
                    match load_config_file(file_path) {
                        Ok(config) => {
                            maybe_file_config = Some(config);
                            result.config_file_path = Some(file_path_buf);
                        }
                        Err(e) => {
                            // Ensure at least the console-log is setup before returning the error
                            console_log_dispatcher
                                .apply()
                                .expect("multiple loggers not allowed");
                            return Err(e);
                        }
                    }
                } else {
                    maybe_file_config = None;
                }
            }
            Err(e) => {
                // Ensure at least the console-log is setup before returning the error
                console_log_dispatcher
                    .apply()
                    .expect("multiple loggers not allowed");
                return Err(e);
            }
        };

        let cli = &cli_args.common;
        let file = maybe_file_config.as_ref().map(|args| &args.common);

        // This helper macro takes a single option name (without quotes) and checks for it first on the CLI args, then
        // in the config file (if given), and returns the first corresponding value it finds. This allows CLI args to
        // override config file values, while still allowing config files to set various baselines.
        macro_rules! take_first_defined {
            ($name:ident) => {
                cli.$name
                    .as_ref()
                    .or(file.map(|o| o.$name.as_ref()).flatten())
            };
        }

        // Finish setting up logging (console and/or file)
        if let Some(log_file_path) = take_first_defined!(log_file).map(|pb| pb.as_path()) {
            let file_log_dispatcher = match create_file_log_dispatcher(
                log_file_path,
                take_first_defined!(log_level).unwrap_or(&DEFAULT_LOG_FILE_LEVEL),
                take_first_defined!(log_level_other).unwrap_or(&DEFAULT_LOG_FILE_LEVEL_OTHER),
            ) {
                Ok(dispatcher) => dispatcher,
                Err(e) => {
                    // Ensure at least the console-log is setup before returning the error
                    console_log_dispatcher
                        .apply()
                        .expect("multiple loggers not allowed");
                    return Err(e);
                }
            };

            // Join both console and file dispatchers into a single logger.
            Dispatch::new()
                .chain(console_log_dispatcher)
                .chain(file_log_dispatcher)
                .apply()
                .expect("multiple loggers not allowed");
        } else {
            // No log-file given. Setup the console logger only.
            console_log_dispatcher
                .apply()
                .expect("multiple loggers not allowed");
        }

        result.host_name = take_first_defined!(host_name)
            .ok_or(anyhow!("Missing required option: 'host_name'"))?
            .clone();
        result.host_name_normalized = normalize_host_name(result.host_name.as_str())?.to_string();

        result.route53_record_ttl =
            *take_first_defined!(aws_route53_record_ttl).unwrap_or(&DEFAULT_ROUTE53_TLL);

        result.update_timeout = Duration::from_secs_f64(
            *take_first_defined!(update_timeout_seconds).unwrap_or(&DEFAULT_UPDATE_TIMEOUT_SECS),
        );

        result.update_poll_interval = Duration::from_secs_f64(
            *take_first_defined!(update_poll_interval_seconds).unwrap_or(&DEFAULT_UPDATE_POLL_SECS),
        );

        result.no_update = cli_args.no_update;

        if let Some(zone_id) = take_first_defined!(aws_route53_zone_id) {
            result.route53_zone_id = Some(zone_id.clone());
        }

        if let Some(ip_algos) = take_first_defined!(ipv4_algorithms) {
            // Only take them if it isn't JUST the 'None' algorithm
            let has_none_only =
                ip_algos.len() == 1 && matches!(ip_algos[0], AlgorithmSpecification::None);
            if !has_none_only {
                AlgorithmSpecification::validate_combination(ip_algos.as_slice(), false)?;
                result.ipv4_algorithms = ip_algos.clone();
            }
        }

        if let Some(ip_algos) = take_first_defined!(ipv6_algorithms) {
            // Only take them if it isn't JUST the 'None' algorithm
            let has_none_only =
                ip_algos.len() == 1 && matches!(ip_algos[0], AlgorithmSpecification::None);
            if !has_none_only {
                AlgorithmSpecification::validate_combination(ip_algos.as_slice(), true)?;
                result.ipv6_algorithms = ip_algos.clone();
            }
        }

        let mut aws_config_loader = aws_config::from_env();

        if let Some(aws_region) = take_first_defined!(aws_region) {
            aws_config_loader = aws_config_loader.region(Region::new(aws_region.clone()));
        }

        if let Some(aws_profile) = cli_args.common.aws_profile.as_ref() {
            // The CLI only allows a profile (not explicit credentials); so no conflicts are possible.
            aws_config_loader = aws_config_loader.profile_name(aws_profile.clone());
        } else if let Some(file_opts_ref) = maybe_file_config.as_ref() {
            if file_opts_ref.aws_access_key_id.is_some()
                || file_opts_ref.aws_secret_access_key.is_some()
            {
                // If the config file specifies either a key or a secret, then it must specify both (because the AWS
                // SDK will throw an error if you provide only one of them).
                let access_key = file_opts_ref.aws_access_key_id.as_ref().ok_or(anyhow!(
                    "aws_access_key_id must be provided when aws_secret_access_key is given"
                ))?;
                let secret_key = file_opts_ref.aws_secret_access_key.as_ref().ok_or(anyhow!(
                    "aws_secret_access_key must be provided when aws_access_key_id is given"
                ))?;

                if file_opts_ref.common.aws_profile.is_some() {
                    return Err(anyhow!(
                        "The configuration file cannot specify both a profile and explicit credentials."
                    ));
                }

                let creds =
                    Credentials::new(access_key.clone(), secret_key.clone(), None, None, "static");
                aws_config_loader = aws_config_loader.credentials_provider(creds);
            } else if let Some(profile_name) = file_opts_ref.common.aws_profile.as_ref() {
                aws_config_loader = aws_config_loader.profile_name(profile_name.clone());
            }
        }

        Ok((result, aws_config_loader))
    }
}

fn create_console_log_dispatcher(cli_args: &CliOptions) -> Dispatch {
    Dispatch::new()
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
            match cli_args.verbose {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            },
        )
        .level(match cli_args.verbosity_other {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .chain(std::io::stdout())
}

fn create_file_log_dispatcher(
    file_path: &Path,
    level: &LevelFilter,
    level_other: &LevelFilter,
) -> anyhow::Result<Dispatch> {
    Ok(Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}: {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.target(),
                record.level(),
                message
            ))
        })
        .level_for(env!("CARGO_CRATE_NAME"), *level)
        .level(*level_other)
        .chain(
            fern::log_file(file_path)
            .context(format!("Failed to open log file: {}", file_path.to_string_lossy()))?
        )
    )
}

fn find_configuration_file(
    cli_path: Option<Cow<'static, Path>>,
) -> anyhow::Result<Option<Cow<'static, Path>>> {
    if let Some(cli_path) = cli_path {
        if cli_path.as_os_str() == "-" {
            // Invoking user specified "no" configuraiton file
            return Ok(None);
        } else {
            // Use the caller-specified configuration file
            return Ok(Some(cli_path));
        }
    }

    // Fall back on a search

    // Check the current working directory
    let maybe_config_path = Path::new("ddns-route53.conf");
    if maybe_config_path.is_file() {
        return Ok(Some(Cow::Borrowed(maybe_config_path)));
    }

    #[cfg(unix)]
    {
        let maybe_home_dir: Option<PathBuf> = crate::os_helpers::posix::get_posix_user_home_dir()?;
        if let Some(home_dir) = maybe_home_dir {
            for candidate_rel_path in [
                ".config/ddns-route53.conf",
                ".local/share/ddns-route53.conf",
                ".ddns-route53.conf",
            ] {
                let candidate = home_dir.join(candidate_rel_path);
                if candidate.is_file() {
                    return Ok(Some(Cow::Owned(candidate)));
                }
            }
        }

        for candidate_str in [
            "/usr/local/etc/ddns-route53.conf",
            "/etc/opt/ddns-route53.conf",
            "/etc/ddns-route53.conf",
        ] {
            let candidate = Path::new(candidate_str);
            if candidate.is_file() {
                return Ok(Some(Cow::Borrowed(candidate)));
            }
        }
    }

    #[cfg(windows)]
    {
        for candidate_dir in [
            crate::os_helpers::windows::get_user_local_app_data_folder()?, // E.g., "C:\Users\John.Doe\AppData\Local"
            crate::os_helpers::windows::get_program_data_folder()?,        // E.g., "C:\ProgramData"
        ].into_iter().flatten() {
            let candidate = candidate_dir.join("ddns-route53.conf");
            if candidate.is_file() {
                return Ok(Some(Cow::Owned(candidate)));
            }
        }
    }

    debug!("No configuration file found at any of the default search paths");
    Ok(None)
}

fn get_char_representation(ch: char) -> Cow<'static, str> {
    let ch_ord = ch as i32;
    match ch_ord {
        0x27 /* '\'' */ => Cow::Borrowed("\"'\""),
        0x5C /* '\\' */ => Cow::Borrowed("'\\'"),
        0x20..0x7F => Cow::Owned(format!("'{0}'", ch)),
        0x0A /* '\n' */ => Cow::Borrowed("'\\n'"),
        0x0D /* '\r' */ => Cow::Borrowed("'\\r'"),
        0x09 /* '\t' */ => Cow::Borrowed("'\\t'"),
        0x00..0x20 | 0x7F..=0xFF => Cow::Owned(format!("'\\x{0:02X}'", ch_ord)),
        0x80..=0xFFFF => Cow::Owned(format!("'\\u+{0:04X}'", ch_ord)),
        _ => Cow::Owned(format!("'\\U+{0:08X}'", ch_ord))
    }
}

fn load_config_file<'a>(path: Cow<'a, Path>) -> anyhow::Result<FileOptions> {
    let fh = File::open(path.as_ref()).context("I/O error opening config file")?;
    let mut reader = BufReader::new(fh);
    let file_size = reader
        .seek(SeekFrom::End(0))
        .context("I/O error seeking within config file")?;
    if MAX_CONFIG_FILE_SIZE_BYTES < file_size {
        return Err(anyhow!(
            "file too large: {path:?} (size {file_size} exceeds max {MAX_CONFIG_FILE_SIZE_BYTES})"
        ));
    }
    if file_size != 0 {
        reader
            .seek(SeekFrom::Start(0))
            .expect("seek to start should always work");
    }

    let mut content = String::new();
    content.reserve(file_size as usize);
    reader
        .read_to_string(&mut content)
        .context("I/O error reading config file")?;

    let config_file =
        toml::from_str::<FileOptions>(content.as_str()).context("failed to load config file")?;

    if config_file.aws_access_key_id.is_some() {
        if config_file.aws_secret_access_key.is_none() {
            return Err(anyhow!(
                "config file: Missing 'aws_secret_access_key' (required due to 'aws_access_key_id')"
            ));
        }
        if config_file.common.aws_profile.is_some() {
            return Err(anyhow!(
                "config file: Cannot provide 'aws_profile' with 'aws_access_key_id'/'aws_secret_access_key'"
            ));
        }
    } else {
        if config_file.aws_secret_access_key.is_some() {
            return Err(anyhow!("config file: Missing 'aws_access_key_id' (required due to 'aws_secret_access_key')"));
        }
    }

    Ok(config_file)
}

fn normalize_host_name(host_name: &str) -> anyhow::Result<Cow<'_, str>> {
    let name_lower_idna = domain_to_ascii_cow(host_name.as_bytes(), AsciiDenyList::URL)?;
    validate_idna_host_name(name_lower_idna.as_ref())?;

    if name_lower_idna.ends_with(".") {
        Ok(name_lower_idna)
    } else {
        Ok(Cow::Owned(name_lower_idna.to_string() + "."))
    }
}

fn validate_idna_host_name(name: &str) -> anyhow::Result<()> {
    const MAX_DNS_FQDN_LENGTH: usize = 255;
    const MAX_DNS_LABEL_LENGTH: u32 = 64;

    if name.is_empty() {
        return Err(anyhow!("invalid host_name: cannot be empty"));
    }
    if MAX_DNS_FQDN_LENGTH < name.len() {
        return Err(
            anyhow!(
                "invalid host_name: total length cannot exceed {MAX_DNS_FQDN_LENGTH} characters (got: {0})",
                name.len()
            )
        );
    }

    let mut itr = name.chars().enumerate();
    let mut label_len: u32;
    let mut label_num = 0u32;
    let mut last_ch: char;
    let mut last_ch_idx: usize;

    loop {
        label_num += 1;
        label_len = 0;

        // Get the first/leading character of the current label
        if let Some((idx, ch)) = itr.next() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' => {}
                _ => {
                    return Err(anyhow!(
                        "invalid host_name: character at offset {0} must be one of a-z, A-Z, or 0-9 (got: {1})",
                        idx, get_char_representation(ch)
                    ));
                }
            }
            last_ch = ch;
            last_ch_idx = idx;
            label_len += 1;
        } else {
            // Since we know the host-name wasn't completely empty (since we checked at the very top), having
            // nothing (end of string) after a dot (separator) means it was a final, trailing dot. That is OK.
            return Ok(());
        }

        let mut got_label_terminator = false;
        for (idx, ch) in itr.by_ref() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {}
                '.' => {
                    last_ch_idx = idx - 1;
                    got_label_terminator = true;
                    break;
                }
                _ => {
                    return Err(anyhow!(
                        "invalid host_name: character at offset {0} must be one of a-z, A-Z, 0-9, -, or . (got: {1})",
                        idx, get_char_representation(ch)
                    ));
                }
            }
            last_ch = ch;
            last_ch_idx = idx;
            label_len += 1;
        }

        if MAX_DNS_LABEL_LENGTH <= label_len {
            return Err(anyhow!(
                "invalid host_name: label {label_num} is too long (length {label_len} exceeds maximum of {MAX_DNS_LABEL_LENGTH})"
            ));
        }
        if last_ch == '-' {
            return Err(anyhow!(
                "invalid host_name: character at offset {last_ch_idx} ('-'): hyphens are not allowed as the final character in a label"
            ));
        }

        if !got_label_terminator {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Debug, Default)]
    #[serde(default)]
    struct SerdeLevelFilter {
        #[serde(with = "serde_levelfilter")]
        level: Option<LevelFilter>,
    }

    #[test]
    fn test_level_filter() {
        let tests = [
            (Some(LevelFilter::Error), "level = \"ERROR\"", true),
            (Some(LevelFilter::Warn), "level = \"WARN\"", true),
            (Some(LevelFilter::Info), "level = \"INFO\"", true),
            (Some(LevelFilter::Debug), "level = \"DEBUG\"", true),
            (Some(LevelFilter::Trace), "level = \"TRACE\"", false),
            (Some(LevelFilter::Off), "level = \"OFF\"", true),
        ];
        for (expected, input, deser_ok) in tests {
            let maybe_struct = toml::from_str::<SerdeLevelFilter>(input);
            if deser_ok {
                assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
                let result = maybe_struct.unwrap();
                assert_eq!(result.level, expected, "{:?}", expected);
            } else {
                assert!(
                    maybe_struct.is_err(),
                    "value: {:?}, result:{:?}",
                    expected,
                    maybe_struct.unwrap()
                );
                let err = maybe_struct.unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.contains("This level is not allowed for the log file."),
                    "value={:?}, msg={:?}",
                    expected,
                    msg
                );
            }
        }
    }

    #[test]
    fn test_level_filter_empty() {
        let maybe_struct = toml::from_str::<SerdeLevelFilter>("");
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert!(result.level.is_none());
    }

    #[test]
    fn test_validate_ttl() {
        for (value, expect_ok) in [
            (0, true),
            (60, true),
            (3600, true),
            (i32::MAX, true),
            (-1, false),
            (i32::MIN, false),
        ] {
            let value_str = format!("{value}");

            let r = parse_ranged_number::<FieldTTL>(value_str.as_str());
            assert!(r.is_ok() == expect_ok, "value={value_str}, r={r:?}");
            if let Ok(r) = r {
                assert_eq!(r, value, "value={value}, r={r:?}");
            }

            let toml_str = format!("aws_route53_record_ttl = {value}");
            let maybe_struct: Result<FileOptions, toml::de::Error> =
                toml::from_str(toml_str.as_str());
            if expect_ok {
                assert!(
                    maybe_struct.is_ok(),
                    "value={value}, err={:?}",
                    maybe_struct.unwrap_err()
                );
                let struct_obj = maybe_struct.unwrap();
                assert!(
                    struct_obj.common.aws_route53_record_ttl.is_some(),
                    "expect config option is populated"
                );
                let struct_value = struct_obj.common.aws_route53_record_ttl.unwrap();
                assert_eq!(struct_value, value);
            } else {
                assert!(maybe_struct.is_err(), "value={value}");
            }
        }
    }

    #[test]
    fn test_validate_update_timeout() {
        for (value, expect_ok) in [
            (MIN_UPDATE_TIMEOUT_SECONDS, true),
            (MAX_UPDATE_TIMEOUT_SECONDS, true),
            (
                (MIN_UPDATE_TIMEOUT_SECONDS + MAX_UPDATE_TIMEOUT_SECONDS) * 0.5,
                true,
            ),
            (MIN_UPDATE_TIMEOUT_SECONDS - 1.0, false),
            (MAX_UPDATE_TIMEOUT_SECONDS + 1.0, false),
        ] {
            let value_str = format!("{value}");

            let r = parse_ranged_number::<FieldUpdateTimeout>(value_str.as_str());
            if expect_ok {
                assert!(r.is_ok(), "value={value}, err={:?}", r.unwrap_err());
                let r = r.unwrap();
                assert_eq!(r, value, "value={value}");
            } else {
                assert!(r.is_err(), "value={value}");
            }

            let toml_str = format!("update_timeout_seconds = {value}");
            let maybe_struct: Result<FileOptions, toml::de::Error> =
                toml::from_str(toml_str.as_str());
            if expect_ok {
                assert!(
                    maybe_struct.is_ok(),
                    "value={value}, err={:?}",
                    maybe_struct.unwrap_err()
                );
                let struct_obj = maybe_struct.unwrap();
                assert!(
                    struct_obj.common.update_timeout_seconds.is_some(),
                    "expect config option is populated"
                );
                let struct_value = struct_obj.common.update_timeout_seconds.unwrap();
                assert_eq!(struct_value, value);
            } else {
                assert!(maybe_struct.is_err(), "value={value}");
            }
        }
    }

    #[test]
    fn test_validate_update_poll_interval() {
        for (value, expect_ok) in [
            (MIN_UPDATE_POLL_SECONDS, true),
            (MAX_UPDATE_POLL_SECONDS, true),
            (
                (MIN_UPDATE_POLL_SECONDS + MAX_UPDATE_POLL_SECONDS) * 0.5,
                true,
            ),
            (MIN_UPDATE_POLL_SECONDS - 1.0, false),
            (MAX_UPDATE_POLL_SECONDS + 1.0, false),
        ] {
            let value_str = format!("{value}");

            let r = parse_ranged_number::<FieldUpdatePollInterval>(value_str.as_str());
            if expect_ok {
                assert!(r.is_ok(), "value={value}, err={:?}", r.unwrap_err());
                let r = r.unwrap();
                assert_eq!(r, value, "value={value}");
            } else {
                assert!(r.is_err(), "value={value}");
            }

            let toml_str = format!("update_poll_seconds = {value}");
            let maybe_struct: Result<FileOptions, toml::de::Error> =
                toml::from_str(toml_str.as_str());
            if expect_ok {
                assert!(
                    maybe_struct.is_ok(),
                    "value={value}, err={:?}",
                    maybe_struct.unwrap_err()
                );
                let struct_obj = maybe_struct.unwrap();
                assert!(
                    struct_obj.common.update_poll_interval_seconds.is_some(),
                    "expect config option is populated"
                );
                let struct_value = struct_obj.common.update_poll_interval_seconds.unwrap();
                assert_eq!(struct_value, value);
            } else {
                assert!(maybe_struct.is_err(), "value={value}");
            }
        }
    }

    #[test]
    fn test_validate_idna_host_name() {
        let tests = [
            ("localhost", true),
            ("www.google.com", true),
            ("domain.", true),
            ("xn--jxalpdlp.test", true),
            (".", false),
            ("-example", false),
            ("example-", false),
            ("example.-test", false),
            ("example.-test.", false),
            ("example.test-", false),
            ("example.test-.", false),
            ("*.wildcard.domain", false),
            ("*.wildcard.domain.", false),
            ("wildcard.*.domain", false),
            (
                "123456789012345678901234567890123456789012345678901234567890123",
                true,
            ),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                false,
            ),
        ];
        for (host_name, expect_valid) in tests {
            let result = validate_idna_host_name(host_name);
            if expect_valid {
                assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
            } else {
                assert!(result.is_err(), "host_name: {:?}", host_name);
                let err = result.unwrap_err();
                let msg = err.to_string();
                assert!(
                    msg.starts_with("invalid host_name: "),
                    "e: {:?}",
                    msg.as_str()
                );
            }
        }
    }

    #[test]
    fn test_normalize_host_name() {
        let tests = [
            ("example.com", "example.com."),
            ("EXAMPLE.COM", "example.com."),
            ("España.Example.Com", "xn--espaa-rta.example.com."),
        ];

        for (host_name, expected_normlization) in tests {
            let result = normalize_host_name(host_name).unwrap();
            assert_eq!(result, expected_normlization, "{:?}", host_name);
        }
    }
}
