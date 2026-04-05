// SPDX-License-Identifier: [MIT] OR [Apache-2.0]

use core::str;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::io::{stdout, BufReader, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use std::vec::Vec;

use anyhow::{anyhow, Context};
use fern::Dispatch;
use humantime::format_rfc3339_seconds;
use encoding_rs::Encoding;
use idna::{domain_to_ascii_cow, AsciiDenyList};
use log::{debug, error, warn, LevelFilter};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};

use crate::cli::{parse_cli_args, Args};
use crate::ip_algorithms::StringOrStringVec;

fn default_algo_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_update_poll_seconds() -> Duration {
    Duration::from_secs(30)
}
fn default_update_timeout_seconds() -> Duration {
    Duration::from_secs(300)
}
fn default_route53_ttl() -> i64 {
    3600
}
fn default_log_level() -> LevelFilter {
    LevelFilter::Info
}
fn default_log_level_other() -> LevelFilter {
    LevelFilter::Warn
}
const MAX_CONFIG_FILE_SIZE: u64 = 65536;
const TTL_MIN: i64 = 0;
const TTL_MAX: i64 = 2147483647;

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

mod serde_levelfilter {
    use std::str::FromStr;

    use log::LevelFilter;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
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
                    Ok(level)
                }
            }
            Err(_) => Err(D::Error::custom("Unknown log level")),
        }
    }

    pub fn serialize<S>(level: &LevelFilter, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        serializer.serialize_str(level.as_str())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
enum AlgorithmSpecification {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol {
        #[serde(
            rename = "timeout_seconds",
            with = "serde_duration_f64",
            default = "default_algo_timeout"
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
            default = "default_algo_timeout"
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
            default = "default_algo_timeout"
        )]
        timeout: Duration,

        #[serde(default, with = "serde_encoding")]
        encoding: Option<&'static Encoding>
    },
}

impl Debug for AlgorithmSpecification {
    // For debugging purposes, we want a concise description of each algorithm with all the details.
    // Serializing to (compact) JSON gives us that.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        serde_json::to_string(&self)
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
            Self::DefaultPublicIp => f.write_str("default_public_ip"),
            Self::InternetGatewayProtocol { timeout: _ } => write!(f, "internet_gateway_protocol"),
            Self::WebService { url, timeout: _, default_encoding: _ } => write!(f, "web_service:\"{}\"", url.as_str()),
            Self::Plugin {
                command,
                timeout: _,
                encoding: _
            } => {
                const MAX_STR_LEN: usize = 32;
                match command {
                    StringOrStringVec::String(s) => {
                        if s.len() <= MAX_STR_LEN {
                            write!(f, "plugin:\"{s}\"")
                        } else {
                            let substr: String = s.chars().take(MAX_STR_LEN - 1).collect();
                            write!(f, "plugin:\"{substr}…\"")
                        }
                    }
                    StringOrStringVec::Vec(v) => {
                        if v.is_empty() {
                            write!(f, "plugin:")
                        } else if v[0].len() <= MAX_STR_LEN {
                            write!(f, "plugin:\"{} …\"", v[0])
                        } else {
                            let substr: String = v[0].chars().take(MAX_STR_LEN - 1).collect();
                            write!(f, "plugin:\"{substr}…\"")
                        }
                    }
                }
            }
        }
    }
}

// Overrides the default in that a `Some("")` becomes `None`.
fn deserialize_option_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?;
    Ok(s.filter(|s| !s.is_empty()))
}

// Ensures TTLs are in a valid range
fn deserialize_dns_ttl<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let i = i64::deserialize(deserializer)?;
    if TTL_MIN <= i && i <= TTL_MAX {
        Ok(i)
    } else {
        use serde::de::Error;
        Err(D::Error::custom(format!(
            "DNS TTL value must be in range {TTL_MIN}-{TTL_MAX}: {i}"
        )))
    }
}

#[derive(Deserialize)]
struct FileConfig {
    host_name: String,

    #[serde(
        rename = "update_poll_seconds",
        with = "serde_duration_f64",
        default = "default_update_poll_seconds"
    )]
    update_poll_interval: Duration,

    #[serde(
        rename = "update_timeout_seconds",
        with = "serde_duration_f64",
        default = "default_update_timeout_seconds"
    )]
    update_timeout: Duration,

    ipv4_algorithms: Vec<AlgorithmSpecification>,

    ipv6_algorithms: Vec<AlgorithmSpecification>,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    aws_profile: Option<String>,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    aws_access_key_id: Option<String>,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    aws_secret_access_key: Option<String>,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    aws_region: Option<String>,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    aws_route53_zone_id: Option<String>,

    #[serde(
        deserialize_with = "deserialize_dns_ttl",
        default = "default_route53_ttl"
    )]
    aws_route53_record_ttl: i64,

    #[serde(deserialize_with = "deserialize_option_string", default)]
    log_file: Option<String>,

    #[serde(
        with = "serde_levelfilter",
        default = "default_log_level"
    )]
    log_level: LevelFilter,

    #[serde(
        with = "serde_levelfilter",
        default = "default_log_level_other"
    )]
    log_level_other: LevelFilter,
}

impl FileConfig {
    pub fn load(path: &Path) -> anyhow::Result<FileConfig> {
        let f = File::open(path).context("I/O error opening config file")?;

        let mut reader = BufReader::new(f);

        let file_size = reader
            .seek(SeekFrom::End(0))
            .context("I/O error seeking within config file")?;
        if MAX_CONFIG_FILE_SIZE < file_size {
            return Err(anyhow!(
                "file too large: {path:?} (size {file_size} exceeds max {MAX_CONFIG_FILE_SIZE})"
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

        let file_config = toml::from_str(content.as_str()).context("failed to load config file")?;
        Ok(file_config)
    }
}

#[derive(Serialize)]
pub struct Config {
    pub config_file_path: PathBuf,
    pub host_name: String,
    pub host_name_normalized: String,
    pub update_poll_interval: Duration,
    pub update_timeout: Duration,
    pub update_if_different: bool,

    ipv4_algorithms: Vec<AlgorithmSpecification>,
    ipv6_algorithms: Vec<AlgorithmSpecification>,

    #[serde(skip_serializing)]
    pub route53_client: ::aws_sdk_route53::Client,

    pub route53_zone_id: String,
    pub route53_record_ttl: i64,
    log_file: Option<String>,

    #[serde(with = "serde_levelfilter")]
    log_level: LevelFilter,
    #[serde(with = "serde_levelfilter")]
    log_level_other: LevelFilter,
}


fn normalize_host_name(host_name: &str) -> anyhow::Result<String> {
    let mut name_lower_idna =
        domain_to_ascii_cow(host_name.as_bytes(), AsciiDenyList::URL)
            .map(|s| s.into_owned())
            .context("invalid hostname")?;

    Config::validate_idna_host_name(name_lower_idna.as_str())
        .context("invalid hostname")?;
    if !name_lower_idna.ends_with(".") {
        name_lower_idna += ".";
    }
    Ok(name_lower_idna)
}

fn find_config_file_path() -> anyhow::Result<PathBuf> {
    let path = PathBuf::from("ddns-route53.conf");
    if path.is_file() {
        return Ok(path);
    }

    if cfg!(windows) {
        let env_vars = [
            "USERPROFILE",
            "ProgramData"
        ];
        for env_var in env_vars {
            if let Some(env_value) = std::env::var_os(env_var) {
                let mut pb = PathBuf::from(env_value);
                pb.push("ddns-route53.conf");
                if pb.is_file() {
                    return Ok(pb);
                }
            }
        }
    }

    if cfg!(unix) {
        if let Some(home_dir_path) = std::env::home_dir().as_ref() {
            // ~/.config/ddns-route53.conf
            let mut pb = PathBuf::from(home_dir_path);
            pb.push(".config");
            pb.push("ddns-route53.conf");
            if pb.is_file() {
                return Ok(pb);
            }

            // ~/.ddns-route53.conf
            let mut pb = PathBuf::from(home_dir_path);
            pb.push(".ddns-route53.conf");
            if pb.is_file() {
                return Ok(pb);
            }
        }

        let static_paths = [
            "/usr/local/etc",
            "/etc/opt",
            "/etc"
        ];
        for static_path in static_paths {
            let mut pb = PathBuf::from(static_path);
            pb.push("ddns-route53.conf");

            if pb.is_file() {
                return Ok(pb);
            }
        }
    }

    Err(anyhow!("Failed to locate configuration file"))
}

impl Config {
    async fn _apply_config_file(cli_args: &Args) -> anyhow::Result<Self> {
        let config_file_path = if let Some(config_file_path_str) = cli_args.config_path.as_ref() {
            PathBuf::from(config_file_path_str)
        }
        else {
            find_config_file_path()?
        };
        let config_file = FileConfig::load(config_file_path.as_path())?;

        let host_name_normalized = normalize_host_name(config_file.host_name.as_ref())?;

        for ipv6_algo in &config_file.ipv6_algorithms {
            match ipv6_algo {
                AlgorithmSpecification::InternetGatewayProtocol { timeout: _ } => {
                    return Err(anyhow!("internet_gateway_protocol can only be used with ipv4_algorithms (not ipv6)"));
                }
                _ => {}
            }
        }

        if config_file.aws_access_key_id.is_some() != config_file.aws_secret_access_key.is_some() {
            return Err(anyhow!("config 'aws_access_key_id' and 'aws_secret_access_key' must both be either present or absent"));
        }
        if config_file.aws_access_key_id.is_some() && config_file.aws_profile.is_some() {
            return Err(anyhow!(
                "config cannot use 'aws_profile' with 'aws_access_key_id'"
            ));
        }

        let client = crate::aws_route53::get_client(
            &config_file.aws_profile,
            &config_file.aws_access_key_id,
            &config_file.aws_secret_access_key,
            &config_file.aws_region,
            true
        )
        .await;

        let zone_id = match config_file.aws_route53_zone_id {
            Some(zone) => zone,
            None => crate::aws_route53::get_zone_id(&client, host_name_normalized.as_ref()).await?,
        };

        Ok(Self {
            config_file_path,
            host_name: config_file.host_name,
            host_name_normalized,
            update_poll_interval: config_file.update_poll_interval,
            update_timeout: config_file.update_timeout,
            update_if_different: !cli_args.no_update,
            ipv4_algorithms: config_file.ipv4_algorithms,
            ipv6_algorithms: config_file.ipv6_algorithms,
            route53_client: client,
            route53_zone_id: zone_id,
            route53_record_ttl: config_file.aws_route53_record_ttl,
            log_file: config_file.log_file,
            log_level: config_file.log_level,
            log_level_other: config_file.log_level_other,
        })
    }

    pub async fn load() -> anyhow::Result<Self> {
        let cli_args = parse_cli_args();

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
                match cli_args.verbose {
                    0 => LevelFilter::Warn,
                    1 => LevelFilter::Info,
                    2 => LevelFilter::Debug,
                    _ => LevelFilter::Trace,
                },
            )
            .level(match cli_args.log_other {
                0 => LevelFilter::Warn,
                1 => LevelFilter::Info,
                2 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            })
            .chain(stdout());

        let config = match Self::_apply_config_file(&cli_args).await {
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
                        // Fall back on the stdout logger
                        log_stdout.apply().expect("multiple loggers not allowed");

                        return Err(anyhow!(e));
                    }
                };
                config
            }
            Err(e) => {
                // Fall back on the stdout logger
                log_stdout.apply().expect("multiple loggers not allowed");

                return Err(e);
            }
        };

        Ok(config)
    }

    fn validate_idna_host_name(name: &str) -> anyhow::Result<()> {
        'outer: loop {
            if name.is_empty() || 255 < name.len() { break; }

            let mut itr = name.chars();
            let mut label_len = 0;
            let mut last_ch;

            loop {
                if let Some(ch) = itr.next() {
                    match ch {
                        'a'..='z' | 'A'..='Z' | '0'..='9' => {},
                        _ => { break 'outer; }
                    }
                    last_ch = ch;
                    label_len += 1;
                }
                else {
                    // Since we know the host-name wasn't completely empty, having
                    // nothing after a dot (separator) means it was a trailing dot.
                    // That is OK.
                    return Ok(());
                }

                loop {
                    if let Some(ch) = itr.next() {
                        match ch {
                            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {},
                            '.' if last_ch != '-' => { break; },
                            _ => { break 'outer; }
                        }
                        last_ch = ch;
                        label_len += 1;
                        if 64 <= label_len { break 'outer; }
                    }
                    else if last_ch == '-' {
                        break 'outer;
                    }
                    else {
                        return Ok(());
                    }
                }
            }
        }

        Err(anyhow!("invalid host name: \"{name}\""))
    }

    pub fn get_file_logger(&self) -> Result<Option<fern::Dispatch>, String> {
        if let Some(log_file) = &self.log_file {
            let log = fern::Dispatch::new()
                .format(|out, message, record| {
                    out.finish(format_args!(
                        "{} [{}] {}: {}",
                        humantime::format_rfc3339_seconds(SystemTime::now()),
                        record.target(),
                        record.level(),
                        message
                    ))
                })
                .level_for(env!("CARGO_CRATE_NAME"), self.log_level)
                .level(self.log_level_other)
                .chain(match fern::log_file(log_file) {
                    Ok(log) => log,
                    Err(e) => {
                        return Err(format!("{e}"));
                    }
                });
            Ok(Some(log))
        } else {
            Ok(None)
        }
    }

    pub async fn get_ipv4_addresses(&self) -> HashSet<Ipv4Addr> {
        let algos = &self.ipv4_algorithms;
        let ip_version = '4';

        for (idx, algo) in algos.iter().enumerate() {
            debug!("ipv{ip_version}_algorithms[{idx}]: Trying algorithm: {algo:?}");

            let algo_result = match algo {
                AlgorithmSpecification::DefaultPublicIp => {
                    crate::ip_algorithms::get_default_public_ipv4().await
                }
                AlgorithmSpecification::InternetGatewayProtocol { timeout } => {
                    crate::ip_algorithms::get_igd_ipv4(timeout).await
                }
                AlgorithmSpecification::WebService { url, timeout, default_encoding } => {
                    crate::ip_algorithms::get_web_service_ip::<Ipv4Addr>(url, timeout, *default_encoding).await
                }
                AlgorithmSpecification::Plugin { command, timeout, encoding } => {
                    crate::ip_algorithms::get_plugin_ip::<Ipv4Addr>(command, timeout, *encoding).await
                }
            };

            match algo_result {
                Ok(ips) => {
                    debug!(
                        "ipv{ip_version}_algorithms[{idx}]: got addresses: {:?}",
                        &ips
                    );
                    if ips.is_empty() {
                        debug!("ipv{ip_version}_algorithms[{idx}]: skipping empty result");
                    } else {
                        return ips.iter().copied().collect();
                    }
                }
                Err(msg) => {
                    warn!("ipv{ip_version}_algorithms[{idx}] ({algo}): returned error: {msg}");
                }
            };
        }

        if algos.len() != 0 {
            warn!("ipv{ip_version}_algorithms: none of the configured algorithms found any results; returning empty-set.");
        }

        HashSet::<Ipv4Addr>::new()
    }

    pub async fn get_ipv6_addresses(&self) -> HashSet<Ipv6Addr> {
        let algos = &self.ipv6_algorithms;
        let ip_version = '6';

        for (idx, algo) in algos.iter().enumerate() {
            debug!("ipv{ip_version}_algorithms[{idx}]: Trying algorithm: {algo:?}");

            let algo_result = match algo {
                AlgorithmSpecification::DefaultPublicIp => {
                    crate::ip_algorithms::get_default_public_ipv6().await
                }
                AlgorithmSpecification::InternetGatewayProtocol { timeout: _ } => {
                    Err::<Vec<Ipv6Addr>, anyhow::Error>(anyhow!(
                        "internet_gateway_device algorithm is not implemented for IPv6"
                    ))
                }
                AlgorithmSpecification::WebService { url, timeout, default_encoding } => {
                    crate::ip_algorithms::get_web_service_ip::<Ipv6Addr>(url, timeout, *default_encoding).await
                }
                AlgorithmSpecification::Plugin { command, timeout, encoding } => {
                    crate::ip_algorithms::get_plugin_ip::<Ipv6Addr>(command, timeout, *encoding).await
                }
            };

            match algo_result {
                Ok(ips) => {
                    debug!(
                        "ipv{ip_version}_algorithms[{idx}]: got addresses: {:?}",
                        &ips
                    );
                    if ips.is_empty() {
                        debug!("ipv{ip_version}_algorithms[{idx}]: skipping empty result");
                    } else {
                        return ips.iter().copied().collect();
                    }
                }
                Err(msg) => {
                    warn!("ipv{ip_version}_algorithms[{idx}] ({algo}): returned error: {msg}");
                }
            };
        }

        if algos.len() != 0 {
            warn!("ipv{ip_version}_algorithms: none of the configured algorithms found any results; returning empty-set.");
        }

        HashSet::<Ipv6Addr>::new()
    }

    #[cfg(test)]
    pub fn build_test_config(
        host_name: &str,
        update_poll_interval: Duration,
        update_timeout: Duration,
        update_if_different: bool,
        route53_record_ttl: i64
    ) -> Self {
        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
        ;
        let r53client = async_runtime.block_on(
            crate::aws_route53::get_client(
                &None,
                &None,
                &None,
                &Some("us-east-1".to_owned()),
                false
            )
        );

        Self {
            config_file_path: PathBuf::new(),
            host_name: host_name.to_owned(),
            host_name_normalized: normalize_host_name(host_name).unwrap(),
            update_poll_interval,
            update_timeout,
            update_if_different,
            ipv4_algorithms: vec!(),
            ipv6_algorithms: vec!(),
            route53_client: r53client,
            route53_zone_id: "Z-NOT-A-ZONE-ID".to_owned(),
            route53_record_ttl,
            log_file: None,
            log_level: LevelFilter::Off,
            log_level_other: LevelFilter::Off
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeDuration {
        #[serde(with = "serde_duration_f64")]
        timeout: Duration
    }

    #[test]
    fn test_serialize_duration_to_json() {
        let test_struct = SerdeDuration {timeout: Duration::from_secs_f64(1.5)};
        let maybe_json = serde_json::to_string(&test_struct);
        assert!(maybe_json.is_ok(), "err: {:?}", maybe_json.unwrap_err());
        let json = maybe_json.unwrap();
        assert_eq!(json.as_str(), "{\"timeout\":1.5}");
    }


    #[test]
    fn test_parse_negative_duration_from_json() {
        let json: &str = "{\"timeout\": -1}";
        let maybe_struct = serde_json::from_str::<SerdeDuration>(json);
        assert!(maybe_struct.is_err(), "struct: {:?}", maybe_struct.unwrap());
        let err = maybe_struct.unwrap_err();
        let msg = err.to_string();
        assert!(msg.starts_with("value cannot be negative: "), "{:?}", msg);
    }


    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeEncoding {
        #[serde(with = "serde_encoding")]
        encoding: Option<&'static Encoding>
    }

    #[test]
    fn test_serialize_encoding_utf8() {
        let test_struct = SerdeEncoding { encoding: Some(encoding_rs::UTF_8) };
        let maybe_json = serde_json::to_string(&test_struct);
        assert!(maybe_json.is_ok(), "err: {:?}", maybe_json.unwrap_err());
        let json = maybe_json.unwrap();
        assert_eq!(json.as_str(), "{\"encoding\":\"UTF-8\"}");
    }

    #[test]
    fn test_serialize_encoding_none() {
        let test_struct = SerdeEncoding { encoding: None };
        let maybe_json = serde_json::to_string(&test_struct);
        assert!(maybe_json.is_ok(), "err: {:?}", maybe_json.unwrap_err());
        let json = maybe_json.unwrap();
        assert_eq!(json.as_str(), "{\"encoding\":null}");
    }

    #[test]
    fn test_deserialize_encoding_utf8() {
        let json: &str = "{\"encoding\": \"utf-8\"}";
        let maybe_struct = serde_json::from_str::<SerdeEncoding>(json);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(result.encoding, Some(encoding_rs::UTF_8), "{:?}", json);

        let json: &str = "{\"encoding\": \"UTF-8\"}";
        let maybe_struct = serde_json::from_str::<SerdeEncoding>(json);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(result.encoding, Some(encoding_rs::UTF_8), "{:?}", json);

        let json: &str = "{\"encoding\": \"utf8\"}";
        let maybe_struct = serde_json::from_str::<SerdeEncoding>(json);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(result.encoding, Some(encoding_rs::UTF_8), "{:?}", json);
    }

    #[test]
    fn test_deserialize_encoding_none() {
        let json: &str = "{\"encoding\": null}";
        let maybe_struct = serde_json::from_str::<SerdeEncoding>(json);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(result.encoding, None, "{:?}", json);
    }


    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeUrl {
        #[serde(with = "serde_url")]
        url: Url
    }

    #[test]
    fn test_serialize_url() {
        let test_struct = SerdeUrl { url: Url::parse("https://www.google.com/").unwrap() };
        let maybe_json = serde_json::to_string(&test_struct);
        assert!(maybe_json.is_ok(), "err: {:?}", maybe_json.unwrap_err());
        let json = maybe_json.unwrap();
        assert_eq!(json.as_str(), "{\"url\":\"https://www.google.com/\"}");
    }

    #[test]
    fn test_deserialize_url() {
        let json: &str = "{\"url\": \"http://localhost/\"}";
        let maybe_struct = serde_json::from_str::<SerdeUrl>(json);
        assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
        let result = maybe_struct.unwrap();
        assert_eq!(result.url, Url::parse("http://localhost/").unwrap(), "{:?}", json);
    }


    #[derive(Deserialize, Serialize, Debug)]
    struct SerdeLevelFilter {
        #[serde(with = "serde_levelfilter")]
        level: LevelFilter
    }

    #[test]
    fn test_level_filter() {
        let tests = [
            (LevelFilter::Error, "{\"level\":\"ERROR\"}", true),
            (LevelFilter::Warn, "{\"level\":\"WARN\"}", true),
            (LevelFilter::Info, "{\"level\":\"INFO\"}", true),
            (LevelFilter::Debug, "{\"level\":\"DEBUG\"}", true),
            (LevelFilter::Trace, "{\"level\":\"TRACE\"}", false),
        ];
        for (input, expected, deser_ok) in tests {
            let test_struct = SerdeLevelFilter { level: input };
            let maybe_json = serde_json::to_string(&test_struct);
            assert!(maybe_json.is_ok(), "err: {:?}", maybe_json.unwrap_err());
            let json = maybe_json.unwrap();
            assert_eq!(json.as_str(), expected);

            let maybe_struct = serde_json::from_str::<SerdeLevelFilter>(expected);
            if deser_ok {
                assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
                let result = maybe_struct.unwrap();
                assert_eq!(result.level, input, "{:?}", expected);
            }
            else {
                assert!(maybe_struct.is_err(), "value: {:?}", expected);
                let err = maybe_struct.unwrap_err();
                let msg = err.to_string();
                assert!(msg.starts_with("This level is not allowed for the log file."), "value={:?}, msg={:?}", expected, msg);
            }
        }
    }


    #[derive(Deserialize, Debug)]
    struct SerdeOptionString {
        #[serde(deserialize_with = "deserialize_option_string", default)]
        value: Option<String>
    }

    #[test]
    fn test_deserialize_option_string() {
        let tests = &[
            ("{\"value\":null}", None),
            ("{\"value\":\"\"}", None),
            ("{\"value\":\"str\"}", Some(String::from("str"))),
        ];
        for (json, expected) in tests {
            let maybe_struct = serde_json::from_str::<SerdeOptionString>(*json);
            assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
            let result = maybe_struct.unwrap();
            assert_eq!(result.value, *expected, "{:?}", *expected);
        }
    }


    #[derive(Deserialize, Debug)]
    struct SerdeTtl {
        #[serde(deserialize_with = "deserialize_dns_ttl", default)]
        value: i64
    }

    #[test]
    fn test_deserialize_dns_ttl() {
        let tests = &[
            (format!("{{\"value\":{0}}}", TTL_MIN), Some(TTL_MIN)),
            (format!("{{\"value\":{0}}}", TTL_MAX), Some(TTL_MAX)),
            (format!("{{\"value\":{0}}}", TTL_MIN - 1), None),
            (format!("{{\"value\":{0}}}", TTL_MAX + 1), None),
        ];
        for (json, expected) in tests {
            let maybe_struct = serde_json::from_str::<SerdeTtl>((*json).as_str());
            if let Some(expected) = *expected {
                assert!(maybe_struct.is_ok(), "err: {:?}", maybe_struct.unwrap_err());
                let result = maybe_struct.unwrap();
                assert_eq!(result.value, expected, "{:?}", expected);
            }
            else {
                assert!(maybe_struct.is_err(), "value: {:?}", maybe_struct.unwrap());
                let err = maybe_struct.unwrap_err();
                let msg = err.to_string();
                assert!(msg.starts_with("DNS TTL value must be in range "), "json={:?}, msg={:?}", (*json).as_str(), msg.as_str());
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
            ("123456789012345678901234567890123456789012345678901234567890123", true),
            ("1234567890123456789012345678901234567890123456789012345678901234", false)
        ];
        for (host_name, expect_valid) in tests {
            let result= Config::validate_idna_host_name(host_name);
            if expect_valid {
                assert!(result.is_ok(), "err: {:?}", result.unwrap_err());
            }
            else {
                assert!(result.is_err(), "host_name: {:?}", host_name);
                let err = result.unwrap_err();
                let msg = err.to_string();
                assert!(msg.starts_with("invalid host name: "));
            }
        }
    }


    #[test]
    fn test_normalize_host_name() {
        let tests = [
            ("example.com", "example.com."),
            ("EXAMPLE.COM", "example.com."),
            ("España.Example.Com", "xn--espaa-rta.example.com.")
        ];

        for (host_name, expected_normlization) in tests {
            let result = normalize_host_name(host_name).unwrap();
            assert_eq!(result, expected_normlization, "{:?}", host_name);
        }
    }
}