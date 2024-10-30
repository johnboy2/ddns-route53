use core::str;
use std::collections::HashSet;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Fn;
use std::pin::Pin;
use std::time::{Duration, SystemTime};
use std::vec::Vec;

use anyhow::anyhow;
use derivative::Derivative;
use idna::{domain_to_ascii_cow, AsciiDenyList};
use lazy_format::lazy_format;
use log::{debug, warn, LevelFilter};
use regex::Regex;
use reqwest::Url;
use serde::Deserialize;

static DEFAULT_ALGO_TIMEOUT_SECONDS: f64 = 10.0;
fn default_update_poll_seconds() -> f64 {
    30.0
}
fn default_update_timeout_seconds() -> f64 {
    300.0
}
static MAX_CONFIG_FILE_SIZE: u64 = 65536;
static MAX_UPDATE_POLL_SECONDS: f64 = 3600.0;
static MAX_UPDATE_TIMEOUT_SECONDS: f64 = 3600.0;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AlgorithmSpecificationV4 {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol { timeout_seconds: Option<f64> },

    #[serde(rename = "web_service")]
    WebService {
        url: String,
        timeout_seconds: Option<f64>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AlgorithmSpecificationV6 {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "web_service")]
    WebService {
        url: String,
        timeout_seconds: Option<f64>,
    },
}

#[derive(Deserialize)]
struct FileConfig {
    host_name: String,

    #[serde(default = "default_update_poll_seconds")]
    update_poll_seconds: f64,

    #[serde(default = "default_update_timeout_seconds")]
    update_timeout_seconds: f64,

    ipv4_algorithms: Vec<AlgorithmSpecificationV4>,
    ipv6_algorithms: Vec<AlgorithmSpecificationV6>,
    aws_profile: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    aws_route53_zone_id: Option<String>,
    aws_route53_record_ttl: i64,
    log_file: Option<String>,
    log_level: Option<String>,
    log_level_other: Option<String>,
}

fn check_timeout(value: f64, maximum: Option<f64>) -> anyhow::Result<Duration> {
    if value < 0.0 {
        return Err(anyhow!("timeout cannot be negative: value={value}"));
    } else if let Some(max) = maximum {
        if max < value {
            return Err(anyhow!("timeout cannot exceed {max}: value={value}"));
        }
    }
    Ok(Duration::from_secs_f64(value))
}

fn check_bounded_integer(
    value: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> anyhow::Result<i64> {
    if let Some(min) = minimum {
        if let Some(max) = maximum {
            if value < min || max < value {
                return Err(anyhow!("value must be in range {min}-{max}: {value}"));
            }
        } else if value < min {
            return Err(anyhow!("value cannot be less than {min}: {value}"));
        }
    } else if let Some(max) = maximum {
        if max < value {
            return Err(anyhow!("value cannot be greater than {max}: {value}"));
        }
    } else {
        panic!("check_bounded_integer must be called with at least one of minimum or maximum");
    }

    Ok(value)
}

fn read_config_file(config_path: &String) -> anyhow::Result<FileConfig> {
    let f = File::open(config_path)?;

    let mut reader = BufReader::new(f);

    let file_size = reader.seek(SeekFrom::End(0))?;
    if MAX_CONFIG_FILE_SIZE < file_size {
        return Err(anyhow!(
            "file too large: {config_path} (size {file_size} exceeds max {MAX_CONFIG_FILE_SIZE})"
        ));
    }
    if file_size != 0 {
        reader
            .seek(SeekFrom::Start(0))
            .expect("seek to start should always work");
    }

    let mut content = String::new();
    reader.read_to_string(&mut content)?;

    let file_config = toml::from_str(content.as_str())?;
    Ok(file_config)
}

type V4AlgoFn =
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<Ipv4Addr>>> + Send>> + Sync;
type V6AlgoFn =
    dyn Fn() -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<Ipv6Addr>>> + Send>> + Sync;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Config {
    pub host_name: String,
    pub host_name_normalized: String,
    pub update_poll_interval: Duration,
    pub update_timeout: Duration,

    #[derivative(Debug = "ignore")]
    ipv4_algo_fns: Vec<Box<V4AlgoFn>>,
    ipv4_algorithms: Vec<String>,

    #[derivative(Debug = "ignore")]
    ipv6_algo_fns: Vec<Box<V6AlgoFn>>,
    ipv6_algorithms: Vec<String>,

    pub route53_client: ::aws_sdk_route53::Client,
    pub route53_zone_id: String,
    pub route53_record_ttl: i64,
    log_file: Option<String>,
    log_level: LevelFilter,
    log_level_other: LevelFilter,
}

struct V4AlgoResult {
    descriptions: Vec<String>,
    functions: Vec<Box<V4AlgoFn>>,
}

fn build_v4_algos(specs: &[AlgorithmSpecificationV4]) -> anyhow::Result<V4AlgoResult> {
    let mut have_default = false;
    let mut have_igd = false;
    let mut have_web_service_url = HashSet::<&str>::with_capacity(specs.len());
    let mut descriptions = Vec::<String>::with_capacity(specs.len());
    let mut functions = Vec::<Box<V4AlgoFn>>::new();
    for spec in specs.iter() {
        match spec {
            AlgorithmSpecificationV4::DefaultPublicIp => {
                let name = "default_public_ip";
                if have_default {
                    return Err(anyhow!("ipv4:{name} can only be given once"));
                }
                have_default = true;
                descriptions.push(format!("{{type=\"{name}\"}}"));
                functions.push(Box::new(|| {
                    Box::pin(crate::ip_algorithms::get_default_public_ip_v4())
                }));
            }
            AlgorithmSpecificationV4::InternetGatewayProtocol { timeout_seconds } => {
                let name = "internet_gateway_protocol";
                if have_igd {
                    return Err(anyhow!("ipv4:{name} can only be given once"));
                }
                have_igd = true;
                let mut description = format!("{{type=\"{name}\"");
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        check_timeout(*timeout_secs, None)?
                    }
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(Box::new(move || {
                    Box::pin(crate::ip_algorithms::get_igd_ip_v4(timeout))
                }));
            }
            AlgorithmSpecificationV4::WebService {
                url,
                timeout_seconds,
            } => {
                let name = lazy_format!("web_service:[{url}]");
                if !have_web_service_url.insert(url.as_str()) {
                    return Err(anyhow!("ipv4:{name} can only be given once"));
                }
                let mut description = format!("{{type=\"web_service\", url=\"{url}\"");
                let url_parsed = Url::parse(url)?;
                let url_owned = url.to_owned();
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        check_timeout(*timeout_secs, None)?
                    }
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(Box::new(move || {
                    Box::pin(crate::ip_algorithms::get_web_service_ip_v4(
                        url_parsed.to_owned(),
                        url_owned.to_owned(),
                        timeout,
                    ))
                }))
            }
        };
    }

    Ok(V4AlgoResult {
        descriptions,
        functions,
    })
}

struct V6AlgoResult {
    descriptions: Vec<String>,
    functions: Vec<Box<V6AlgoFn>>,
}

fn build_v6_algos(specs: &[AlgorithmSpecificationV6]) -> anyhow::Result<V6AlgoResult> {
    let mut have_default = false;
    let mut have_web_service_url = HashSet::<&str>::with_capacity(specs.len());
    let mut descriptions = Vec::<String>::with_capacity(specs.len());
    let mut functions = Vec::<Box<V6AlgoFn>>::new();
    for spec in specs.iter() {
        match spec {
            AlgorithmSpecificationV6::DefaultPublicIp => {
                let name = "default_public_ip";
                if have_default {
                    return Err(anyhow!("ipv6:{name} can only be given once"));
                }
                have_default = true;
                descriptions.push(format!("{{type=\"{name}\"}}"));
                functions.push(Box::new(|| {
                    Box::pin(crate::ip_algorithms::get_default_public_ip_v6())
                }));
            }
            AlgorithmSpecificationV6::WebService {
                url,
                timeout_seconds,
            } => {
                let name = lazy_format!("web_service:[{url}]");
                if !have_web_service_url.insert(url.as_str()) {
                    return Err(anyhow!("ipv6:{name} can only be given once"));
                }
                let mut description = format!("{{type=\"web_service\", url=\"{url}\"");
                let url_parsed = Url::parse(url)?;
                let url_owned = url.to_owned();
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        check_timeout(*timeout_secs, None)?
                    }
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(Box::new(move || {
                    Box::pin(crate::ip_algorithms::get_web_service_ip_v6(
                        url_parsed.to_owned(),
                        url_owned.to_owned(),
                        timeout,
                    ))
                }))
            }
        };
    }

    Ok(V6AlgoResult {
        descriptions,
        functions,
    })
}

fn parse_log_level(name: &Option<String>, default: LevelFilter) -> anyhow::Result<LevelFilter> {
    match name {
        Some(name) => match name.as_str() {
            "off" => Ok(LevelFilter::Off),
            "error" => Ok(LevelFilter::Error),
            "warn" => Ok(LevelFilter::Warn),
            "info" => Ok(LevelFilter::Info),
            "debug" => Ok(LevelFilter::Debug),
            "trace" => Ok(LevelFilter::Trace),
            _ => Err(anyhow!("unknown log level: \"{name}\"")),
        },
        None => Ok(default),
    }
}

fn validate_host_name(name: &str) -> anyhow::Result<()> {
    let ptn = Regex::new("^[a-zA-Z0-9]|[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9](\\.[a-zA-Z0-9]|[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])*\\.?$")
        .expect("hard-coded regex should always be valid")
    ;
    if ptn.is_match(name) {
        Ok(())
    } else {
        Err(anyhow!("invalid host name: \"{name}\""))
    }
}

impl Config {
    pub async fn load(config_path: &String) -> anyhow::Result<Self> {
        let config_file = read_config_file(config_path)?;

        let host_name_normalized = {
            let mut name_lower_idna =
                domain_to_ascii_cow(config_file.host_name.as_bytes(), AsciiDenyList::URL)?
                    .into_owned();
            validate_host_name(name_lower_idna.as_str())?;
            if !name_lower_idna.ends_with(".") {
                name_lower_idna += ".";
            }
            name_lower_idna
        };

        let v4_algos = build_v4_algos(&config_file.ipv4_algorithms)?;
        let v6_algos = build_v6_algos(&config_file.ipv6_algorithms)?;

        let client = crate::aws_route53::get_client(
            &config_file.aws_profile,
            &config_file.aws_access_key_id,
            &config_file.aws_secret_access_key,
            &config_file.aws_region,
        )
        .await;

        let zone_id = match config_file.aws_route53_zone_id {
            Some(zone) => zone,
            None => crate::aws_route53::get_zone_id(&client, host_name_normalized.as_ref()).await?,
        };

        Ok(Self {
            host_name: config_file.host_name,
            host_name_normalized,
            update_poll_interval: check_timeout(
                config_file.update_poll_seconds,
                Some(MAX_UPDATE_POLL_SECONDS),
            )?,
            update_timeout: check_timeout(
                config_file.update_timeout_seconds,
                Some(MAX_UPDATE_TIMEOUT_SECONDS),
            )?,
            ipv4_algorithms: v4_algos.descriptions,
            ipv4_algo_fns: v4_algos.functions,
            ipv6_algorithms: v6_algos.descriptions,
            ipv6_algo_fns: v6_algos.functions,
            route53_client: client,
            route53_zone_id: zone_id,
            route53_record_ttl: check_bounded_integer(
                config_file.aws_route53_record_ttl,
                Some(0i64),
                Some(2147483647i64),
            )?,
            log_file: config_file.log_file,
            log_level: parse_log_level(&config_file.log_level, LevelFilter::Info)?,
            log_level_other: parse_log_level(&config_file.log_level_other, LevelFilter::Warn)?,
        })
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

    pub async fn get_ipv4_addresses(&self) -> Vec<Ipv4Addr> {
        for (name, algo_fn) in self.ipv4_algorithms.iter().zip(self.ipv4_algo_fns.iter()) {
            debug!("ipv4: Trying algorithm: {}", name);
            let algo_result = algo_fn().await;
            match algo_result {
                Ok(mut ips) => {
                    debug!("ipv4: got addresses: {:?}", &ips);
                    if ips.is_empty() {
                        debug!("ipv4: skipping empty result for algorithm: {}", name);
                    } else {
                        ips.sort();
                        debug!("ipv4: return {} found address(es)", ips.len());
                        return ips;
                    }
                }
                Err(msg) => {
                    warn!("ipv4: algorithm {} returned error: {}", name, msg);
                }
            };
        }

        warn!("ipv4: none of the configured algorithms found any results; returning empty-set.");
        Vec::<Ipv4Addr>::new()
    }

    pub async fn get_ipv6_addresses(&self) -> Vec<Ipv6Addr> {
        for (name, algo_fn) in self.ipv6_algorithms.iter().zip(self.ipv6_algo_fns.iter()) {
            debug!("ipv6: Trying algorithm: {}", name);
            let algo_result = algo_fn().await;
            match algo_result {
                Ok(mut ips) => {
                    debug!("ipv6: got addresses: {:?}", &ips);
                    if ips.is_empty() {
                        debug!("ipv6: skipping empty result for algorithm: {}", name);
                    } else {
                        ips.sort();
                        debug!("ipv6: return {} found address(es)", ips.len());
                        return ips;
                    }
                }
                Err(msg) => {
                    warn!("ipv6: algorithm {} returned error: {}", name, msg);
                }
            };
        }

        warn!("ipv6: none of the configured algorithms found any results; returning empty-set.");
        Vec::<Ipv6Addr>::new()
    }
}
