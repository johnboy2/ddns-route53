use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow};
use aws_config::ConfigLoader;
use aws_sdk_route53::config::Credentials;
use aws_types::region::Region;
use clap::{Args, ArgAction, Parser, ValueHint};
use encoding_rs::Encoding;
use fern::Dispatch;
use humantime::format_rfc3339_seconds;
use idna::{AsciiDenyList, domain_to_ascii_cow};
use log::{LevelFilter, error};
use serde::{Deserialize, Serialize};
use reqwest::Url;

use crate::ip_algorithms::StringOrStringVec;


const DEFAULT_ALGO_TIMEOUT_SECS: u64 = 10;
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


fn serde_default_algo_timeout() -> Duration { Duration::from_secs(DEFAULT_ALGO_TIMEOUT_SECS) }


mod serde_duration_f64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = f64::deserialize(deserializer)?;
        if v < 0.0 {
            Err(D::Error::custom(format!("value cannot be negative: {v}")))
        } else {
            Ok(Duration::from_secs_f64(v))
        }
    }

    pub fn serialize<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(d.as_secs_f64())
    }
}

mod serde_encoding {
    use encoding_rs::Encoding;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<&'static Encoding>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if let Some(s) = Option::<String>::deserialize(deserializer)? {
            let sb = s.trim_ascii().as_bytes();

            // encoding_rs seems not to recognize some common UTF-16 aliases, so we
            // give it a hand here with a few of our own, custom translations.
            let sb: &[u8] = match sb {
                b"utf16" => b"utf-16",
                b"utf16le" | b"utf-16-le" => b"utf-16le",
                b"utf16be" | b"utf-16-be" => b"utf-16be",
                _ => sb
            };

            Encoding::for_label(sb)
            .map(|e| Some(e))
            .ok_or(D::Error::custom(format!("unknown encoding: \"{s}\"")))
        }
        else {
            Ok(None)
        }
    }

    pub fn serialize<S>(encoding: &Option<&'static Encoding>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(e) = encoding {
            serializer.serialize_str(e.name())
        }
        else {
            serializer.serialize_none()
        }
    }
}

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

mod serde_url {
    use reqwest::Url;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(|e| {
            D::Error::custom(format!("could not parse url: \"{s}\": {}", e.to_string()))
        })
    }

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(url.as_str())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum AlgorithmSpecification {
    #[serde(rename = "none")]
    None,

    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol {
        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,
    },

    #[serde(rename = "web_service")]
    WebService {
        #[serde(with = "serde_url")]
        url: Url,

        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,

        #[serde(default, with = "serde_encoding")]
        default_encoding: Option<&'static Encoding>
    },

    #[serde(rename = "plugin")]
    Plugin {
        command: StringOrStringVec,

        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "serde_default_algo_timeout"
        )]
        timeout: Duration,

        #[serde(default, with = "serde_encoding")]
        encoding: Option<&'static Encoding>
    },
}

impl Debug for AlgorithmSpecification {
    // For debugging purposes, we want a concise description of each algorithm with all the details.
    // Serializing to (compact) TOML gives us that.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        toml::to_string(&self)
            .map_err(|e| {
                error!(
                    "Failed to serialize AlgorithmSpecification: {}",
                    e.to_string()
                );
                std::fmt::Error
            })
            .and_then(|s| f.write_str(s.as_str()))
    }
}

impl Display for AlgorithmSpecification {
    // For display purposes, we want a *simple* description of each algorithm, without unnecessary details.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::None => f.write_str("none"),
            Self::DefaultPublicIp => f.write_str("default_public_ip"),
            Self::InternetGatewayProtocol {
                timeout: _
            } => write!(f, "internet_gateway_protocol"),
            Self::WebService {
                url,
                timeout: _,
                default_encoding: _
            } => write!(f, "web_service:\"{}\"", url.as_str()),
            Self::Plugin {
                command,
                timeout: _,
                encoding: _
            } => write!(f, "plugin:\"{command}\"")
        }
    }
}


#[derive(Args, Deserialize)]
struct CommonOptions {
    /// The fully-qualified domain name of the host to update. (This must be specified in either a configuration file or on the command-line.)
    #[arg(short='h', long)]
    pub host_name: Option<String>,

    /// (Optional) The Route53 zone ID within AWS to keep up to date. If not specified, the utility will attempt to resolve this dynamically.
    #[arg(short='z', long)]
    pub route53_zone_id: Option<String>,

    /// The TTL use when updating the applicable Route53 resource record(s). Defaults to 3600 unless overridden by a configuration file.
    #[arg(short='t', long)]
    pub route53_record_ttl: Option<i32>,

    /// The timeout to use when trying to update the applicable Route53 resource record(s). Defaults to 300 unless overridden by a configuration file.
    #[arg(short='w', long)]
    pub update_timeout_seconds: Option<f64>,

    /// The timeout to use when trying to update the applicable Route53 resource record(s). Defaults to 30 unless overridden by a configuration file.
    #[arg(short='s', long)]
    pub update_poll_seconds: Option<f64>,

    /// Use a specific profile from your (AWS) credential file.
    #[arg(long)]
    pub aws_profile: Option<String>,

    /// Use an AWS region for Route53 API calls. If omitted, this usually defaults to "us-east-1" (depends on your local Route53 SDK configuration).
    #[arg(long)]
    pub aws_region: Option<String>,

    /// (Optional) File-path at which to log events or actions related to this utility's execution. This may be used either instead of, or in addition to, console logging.
    #[arg(short='f', long, value_hint = ValueHint::FilePath)]
    pub log_file: Option<std::path::PathBuf>,

    /// (Optional) Set the logging-level of this tool to the `log_file`. Must be one of "off", "error", "warn", "info", or "debug". (This DOES NOT affect console-output verbosity.) Defaults to "info".
    #[arg(short='l', long, value_parser = clap::value_parser!(LevelFilter))]
    #[serde(with = "serde_levelfilter")]
    pub log_level: Option<LevelFilter>,

    /// (Optional) Set the logging-level of other libraries this tool uses internally to the `log_file`. Must be one of "off", "error", "warn", "info", or "debug". (This DOES NOT affect console-output verbosity.) Defaults to "off".
    #[arg(short='o', long, value_parser = clap::value_parser!(LevelFilter))]
    #[serde(with = "serde_levelfilter")]
    pub log_level_other: Option<LevelFilter>,

    #[arg(long="ipv4", action=ArgAction::Append, value_parser = |arg: &str| toml::from_str::<AlgorithmSpecification>(arg))]
    pub ipv4_algorithms: Option<Vec<AlgorithmSpecification>>,

    #[arg(long="ipv6", action=ArgAction::Append, value_parser = |arg: &str| toml::from_str::<AlgorithmSpecification>(arg))]
    pub ipv6_algorithms: Option<Vec<AlgorithmSpecification>>,
}


#[derive(Parser)]
struct CliOptions {
    #[command(flatten)]
    pub common: CommonOptions,

    /// Specify a configuration file path. If omitted, it will search a default set of paths for the file to use. Pass the special value '-' to disable use of a configuration file.
    #[arg(short='c', long, value_hint = ValueHint::FilePath)]
    pub config_path: Option<std::path::PathBuf>,

    /// Do not update Route53, even if its current value is wrong.
    #[arg(short='n', long)]
    pub no_update: bool,

    /// Increase console logging verbosity (may be used more than once).
    #[arg(short='v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Increase console logging for dependent libraries (may be used more than once)
    #[arg(long, action = clap::ArgAction::Count)]
    pub verbosity_other: u8,
}


#[derive(Deserialize)]
struct FileOptions {
    #[serde(flatten)]
    pub common: CommonOptions,

    pub aws_access_key_id: Option<String>,

    pub aws_secret_access_key: Option<String>,
}


#[derive(Default, Serialize)]
pub struct Config {
    pub config_file_path: Option<PathBuf>,
    pub host_name: String,
    pub route53_zone_id: Option<String>,
    pub route53_record_ttl: i32,
    pub update_timeout: Duration,
    pub update_poll_interval: Duration,
    pub no_update: bool,
    pub ipv4_algorithms: Vec<AlgorithmSpecification>,
    pub ipv6_algorithms: Vec<AlgorithmSpecification>,

    #[serde(skip)]
    pub host_name_normalized: String
}

impl Config {
    pub fn load() -> anyhow::Result<(Self, ConfigLoader)> {
        let cli_args = CliOptions::parse();
        let maybe_file_config: Option<FileOptions>;
        let mut result = Self { ..Default::default() };

        let console_log_dispatcher = create_console_log_dispatcher(&cli_args);

        match find_configuration_file(
            cli_args.config_path.map(|pb| Cow::Owned(pb))
        ) {
            Ok(maybe_file_path) => {
                if let Some(file_path) = maybe_file_path {
                    match load_config_file(&file_path) {
                        Ok(config) => {
                            maybe_file_config = Some(config);
                            result.config_file_path = Some(file_path.to_path_buf());
                        },
                        Err(e) => {
                            // Ensure at least the console-log is setup before returning the error
                            console_log_dispatcher.apply().expect("multiple loggers not allowed");
                            return Err(e);
                        }
                    }
                }
                else {
                    maybe_file_config = None;
                }
            },
            Err(e) => {
                // Ensure at least the console-log is setup before returning the error
                console_log_dispatcher.apply().expect("multiple loggers not allowed");
                return Err(e);
            }
        };

        let cli = &cli_args.common;
        let file = maybe_file_config.as_ref().map(|args| &args.common);

        // Finish setting up logging (console and/or file)

        macro_rules! take_first_defined {
            ($name:ident) => { cli.$name.as_ref().or(file.map(|o| o.$name.as_ref()).flatten()) }
        }

        if let Some(log_file_path) = take_first_defined!(log_file).map(|pb| pb.as_path())
        {
            let file_log_dispatcher = match create_file_log_dispatcher(
                log_file_path, 
                take_first_defined!(log_level).unwrap_or(&DEFAULT_LOG_FILE_LEVEL),
                take_first_defined!(log_level_other).unwrap_or(&DEFAULT_LOG_FILE_LEVEL_OTHER)
            ) {
                Ok(dispatcher) => dispatcher,
                Err(e) => {
                    // Ensure at least the console-log is setup before returning the error
                    console_log_dispatcher.apply().expect("multiple loggers not allowed");
                    return Err(e);
                }
            };

            // Join both console and file dispatchers into a single logger.
            Dispatch::new()
                .chain(console_log_dispatcher)
                .chain(file_log_dispatcher)
                .apply()
                .expect("multiple loggers not allowed");
        }
        else {
            // No log-file given. Setup the console logger only.
            console_log_dispatcher.apply().expect("multiple loggers not allowed");
        }

        result.host_name =
            take_first_defined!(host_name)
            .ok_or(anyhow!("Missing required option: 'host_name'"))?
            .clone()
        ;
        result.host_name_normalized = normalize_host_name(result.host_name.as_str())?.to_string();

        result.route53_record_ttl = *take_first_defined!(route53_record_ttl).unwrap_or(&DEFAULT_ROUTE53_TLL);
        if result.route53_record_ttl < 0 {
            return Err(anyhow!("route53_record_ttl cannot be negative: {0}", result.route53_record_ttl));
        }

        result.update_timeout = Duration::from_secs_f64(
            validate_value_in_range(
                *take_first_defined!(update_timeout_seconds).unwrap_or(&DEFAULT_UPDATE_TIMEOUT_SECS),
                MIN_UPDATE_TIMEOUT_SECONDS,
                MAX_UPDATE_TIMEOUT_SECONDS,
                "update_timeout"
            )?
        );

        result.update_poll_interval = Duration::from_secs_f64(
            validate_value_in_range(
                *take_first_defined!(update_timeout_seconds).unwrap_or(&DEFAULT_UPDATE_POLL_SECS),
                MIN_UPDATE_POLL_SECONDS,
                MAX_UPDATE_POLL_SECONDS,
                "update_poll"
            )?
        );

        result.no_update = cli_args.no_update;

        if let Some(zone_id) = take_first_defined!(route53_zone_id) {
            result.route53_zone_id = Some(zone_id.clone());
        }

        if let Some(ip_algos) = take_first_defined!(ipv4_algorithms) {
            if validate_ip_algorithm_combination(ip_algos, false)? {
                result.ipv4_algorithms = ip_algos.clone();
            }
        }

        if let Some(ip_algos) = take_first_defined!(ipv6_algorithms) {
            if validate_ip_algorithm_combination(ip_algos, true)? {
                result.ipv6_algorithms = ip_algos.clone();
            }
        }

        let maybe_aws_region = take_first_defined!(aws_region);

        let mut aws_config_loader = aws_config::from_env();
        if let Some(aws_region) = maybe_aws_region {
            aws_config_loader = aws_config_loader.region(Region::new(aws_region.clone()));
        }

        if let Some(profile_name) = take_first_defined!(aws_profile) {
            aws_config_loader = aws_config_loader.profile_name(profile_name.clone());
        }
        else if let Some(file_opts_ref) = maybe_file_config.as_ref() {
            if let Some(access_key) = file_opts_ref.aws_access_key_id.as_ref() {
                let creds = Credentials::new(
                    access_key.clone(),
                    file_opts_ref.aws_secret_access_key
                        .as_ref()
                        .expect("secret must be defined when access_key is")
                        .clone(),
                    None,
                    None,
                    "static"
                );
                aws_config_loader = aws_config_loader.credentials_provider(creds);
            }
        }

        Ok((result, aws_config_loader.into()))
    }

    #[cfg(test)]
    pub fn build_test_config(
        host_name: &str,
        update_poll_interval: Duration,
        update_timeout: Duration,
        update_if_different: bool,
        route53_record_ttl: i32
    ) -> Self {
        Self {
            config_file_path: None,
            host_name: host_name.to_string(),
            route53_zone_id: None,
            route53_record_ttl,
            update_timeout,
            update_poll_interval,
            no_update: !update_if_different,
            ipv4_algorithms: Vec::<AlgorithmSpecification>::new(),
            ipv6_algorithms: Vec::<AlgorithmSpecification>::new(),
            host_name_normalized: normalize_host_name(host_name).unwrap().to_string()
        }
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
}

fn create_file_log_dispatcher(file_path: &Path, level: &LevelFilter, level_other: &LevelFilter) -> anyhow::Result<Dispatch> {
    Ok(
        Dispatch::new()
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
        .chain(fern::log_file(file_path)?)
    )
}

fn find_configuration_file(
    cli_path: Option<Cow<'static, Path>>
) -> anyhow::Result<Option<Cow<'static, Path>>> {
    if let Some(cli_path) = cli_path {
        if cli_path.as_os_str() == "-" {
            // Invoking user specified "no" configuraiton file
            return Ok(None);
        }
        else {
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
            "/etc/ddns-route53.conf"
        ] {
            let candidate = Path::new(candidate_str);
            if candidate.is_file() {
                return Ok(Some(Cow::Borrowed(candidate)));
            }
        }
    }

    #[cfg(windows)]
    {
        for path in [
            crate::os_helpers::windows::get_user_local_app_data_folder()?, // E.g., "C:\Users\John.Doe\AppData\Local"
            crate::os_helpers::windows::get_program_data_folder()? // E.g., "C:\ProgramData"
        ] {
            if let Some(candidate_dir) = path {
                let candidate = candidate_dir.join("ddns-route53.conf");
                if candidate.is_file() {
                    return Ok(Some(Cow::Owned(candidate)));
                }
            }
        }
    }

    Err(anyhow!("Failed to find configuration file"))
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
        0x80..=0xFFFF => Cow::Owned(format!("\\u+{0:04X}'", ch_ord)),
        _ => Cow::Owned(format!("\\U+{0:08X}'", ch_ord))
    }
}

fn load_config_file<'a>(path: &Cow<'a, Path>) -> anyhow::Result<FileOptions> {
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

    let config_file = toml::from_str::<FileOptions>(content.as_str()).context("failed to load config file")?;

    if config_file.aws_access_key_id.is_some() {
        if config_file.aws_secret_access_key.is_none() {
            return Err(anyhow!("config file: Missing 'aws_secret_access_key' (required due to 'aws_access_key_id')"));
        }
        if config_file.common.aws_profile.is_some() {
            return Err(anyhow!("config file: Cannot provide 'aws_profile' with 'aws_access_key_id'/'aws_secret_access_key'"));
        }
    }
    else {
        if config_file.aws_secret_access_key.is_some() {
            return Err(anyhow!("config file: Missing 'aws_access_key_id' (required due to 'aws_secret_access_key')"));
        }
    }

    Ok(config_file)
}

fn normalize_host_name(host_name: &str) -> anyhow::Result<Cow<'_, str>> {
    let name_lower_idna = domain_to_ascii_cow(
        host_name.as_bytes(),
        AsciiDenyList::URL
    )?;
    validate_idna_host_name(name_lower_idna.as_ref())?;

    if name_lower_idna.ends_with(".") {
        Ok(name_lower_idna)
    }
    else {
        Ok(Cow::Owned(name_lower_idna.to_string() + "."))
    }
}

fn validate_value_in_range<T>(value: T, min: T, max: T, field_name: &str) -> anyhow::Result<T> 
where T: Display + PartialOrd{
    if min <= value && value <= max {
        Ok(value)
    }
    else {
        Err(anyhow!("{field_name} must be in range {min}-{max} (got {value})"))
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

    loop {
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
                    'a'..='z' | 'A'..='Z' | '0'..='9' => {},
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
            }
            else {
                // Since we know the host-name wasn't completely empty (since we checked at the very top), having
                // nothing (end of string) after a dot (separator) means it was a final, trailing dot. That is OK.
                return Ok(());
            }

            let mut got_label_terminator = false;
            while let Some((idx, ch)) = itr.next() {
                match ch {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {},
                    '.' => {
                        last_ch_idx = idx - 1;
                        got_label_terminator = true;
                        break;
                    },
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
}

fn validate_ip_algorithm_combination(algos: &Vec::<AlgorithmSpecification>, is_v6: bool) -> anyhow::Result<bool> {
    let mut unique_algos = HashSet::<String>::new();
    for algo in algos {
        let name = format!("{algo}");
        let err = anyhow!("algorithm '{name}' cannot be specified more than once");
        if !unique_algos.insert(name) {
            return Err(err);
        }
    }

    if is_v6 {
        let igd_name = format!("{}", AlgorithmSpecification::InternetGatewayProtocol { timeout: serde_default_algo_timeout() });
        if unique_algos.contains(igd_name.as_str()) {
            return Err(anyhow!("algorithm '{igd_name}' cannot be used with IPv6"));
        }
    }    

    let none_name = format!("{}", AlgorithmSpecification::None);
    if unique_algos.contains(none_name.as_str()) {
        if algos.len() == 1 {
            Ok(false)
        }
        else {
            Err(anyhow!("algorithm '{none_name}' cannot be included with others"))
        }
    }
    else {
        Ok(algos.len() != 0)
    }
}
