use core::str;
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Fn;
use std::pin::Pin;
use std::time::Duration;
use std::vec::Vec;

use derivative::Derivative;
use log::{debug, warn};
use regex::Regex;
use serde::Deserialize;


static DEFAULT_ALGO_TIMEOUT_SECONDS: f64 = 10.0;
fn default_update_poll_seconds() -> f64 { return 30.0; }
fn default_update_timeout_seconds() -> f64 { return 300.0; }
static MAX_CONFIG_FILE_SIZE: u64 = 65536;
static MAX_UPDATE_POLL_SECONDS: f64 = 3600.0;
static MAX_UPDATE_TIMEOUT_SECONDS: f64 = 3600.0;


#[derive(Deserialize)]
#[serde(tag = "type")]
enum AlgorithmSpecification {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol {timeout_seconds: Option::<f64>},

    #[serde(rename = "web_service")]
    WebService {url: String, timeout_seconds: Option::<f64>}
}


#[derive(Deserialize)]
struct FileConfig {
    host_name: String,

    #[serde(default = "default_update_poll_seconds")]
    update_poll_seconds: f64,

    #[serde(default = "default_update_timeout_seconds")]
    update_timeout_seconds: f64,

    ipv4_algorithms: Vec::<AlgorithmSpecification>,
    ipv6_algorithms: Vec::<AlgorithmSpecification>,
    aws_profile: Option<String>,
    aws_access_key_id: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    aws_route53_zone_id: Option<String>,
    aws_route53_record_ttl: i64,
}


fn process_timeout(value: f64, maximum: Option<f64>) -> Result<Duration, String> {
    if value < 0.0 {
        return Err(format!("cannot be negative: {}", value));
    } else if maximum.is_some() {
        let maximum = maximum.unwrap();
        if maximum < value {
            return Err(format!("cannot exceed {}: {}", maximum, value));
        }
    }
    Ok(Duration::from_secs_f64(value))
}


fn process_bounded_integer(value: i64, minimum: Option<i64>, maximum: Option<i64>) -> Result<i64, String> {
    loop {
        if minimum.is_some_and(|min| value < min) {
            // Lower than minimum
            break;
        }

        if maximum.is_some_and(|max| max < value) {
            // Larger than maximum
            break;
        }

        return Ok(value);
    }
    
    Err(
        if minimum.is_some() {
            if maximum.is_some() {
                format!("value {} is outside of required range {}-{}", value, minimum.unwrap(), maximum.unwrap())
            } else {
                format!("value {} cannot be less than {}", value, minimum.unwrap())
            }
        } else {
            format!("value {} cannot be greater than {}", value, maximum.unwrap())
        }
    )
}


fn validate_host_name(name: &str) -> Result<(), String> {
    let ptn = Regex::new("^[a-zA-Z0-9]|[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9](\\.[a-zA-Z0-9]|[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])*\\.?$").unwrap();
    if ptn.is_match(name) {
        return Ok(());
    } else {
        return Err("Invalid host name".to_owned());
    }
}


fn read_config_file(config_path: &String) -> Result<FileConfig, String> {
    let f = match File::open(config_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(format!(
                "Failed to open file [{config_path}]: {}", e.to_string()
            ));
        }
    };

    let mut reader = BufReader::new(f);
    
    let file_size = match reader.seek(std::io::SeekFrom::End(0)) {
        Ok(size) => size,
        Err(e) => {
            return Err(format!(
                "I/O error with file [{config_path}]: {}", 
                e.to_string()
            ));
        }
    };
    if MAX_CONFIG_FILE_SIZE < file_size {
        return Err(format!(
            "File too large [{config_path}]: maximum allowed size is {}",
            MAX_CONFIG_FILE_SIZE
        ));
    }
    if file_size != 0 {
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
    }
    
    let mut content = String::new();
    match reader.read_to_string(&mut content) {
        Ok(_size) => {},
        Err(e) => {
            return Err(format!(
                "Error reading file [{config_path}]: {}", e.to_string()
            ));
        }
    };

    let file_config: FileConfig = match toml::from_str(content.as_str()) {
        Ok(value) => value,
        Err(e) => {
            return Err(format!(
                "Config file [{config_path}] invalid: {}", e.to_string()
            ))
        }
    };

    Ok(file_config)
}


type V4AlgoFn = dyn Fn() -> Pin<Box<dyn Future<Output = Result::<Vec::<Ipv4Addr>, String>> + Send>> + Sync;
type V6AlgoFn = dyn Fn() -> Pin<Box<dyn Future<Output = Result::<Vec::<Ipv6Addr>, String>> + Send>> + Sync;


#[derive(Derivative)]
#[derivative(Debug)]
pub struct Config {
    pub host_name: String,
    pub host_name_normalized: String,
    pub update_poll_interval: Duration,
    pub update_timeout: Duration,

    #[derivative(Debug="ignore")]
    ipv4_algo_fns: Vec::<Box<V4AlgoFn>>,
    ipv4_algorithms: Vec::<String>,

    #[derivative(Debug="ignore")]
    ipv6_algo_fns: Vec::<Box<V6AlgoFn>>,
    ipv6_algorithms: Vec::<String>,

    pub route53_client: ::aws_sdk_route53::Client,
    pub route53_zone_id: Option::<String>,
    pub route53_record_ttl: i64,
}


struct V4AlgoResult {
    descriptions: Vec::<String>,
    functions: Vec::<Box<V4AlgoFn>>,
}


fn build_v4_algos(specs: &Vec::<AlgorithmSpecification>) -> Result<V4AlgoResult, String> {
    let mut have_default = false;
    let mut have_igd = false;
    let mut have_web_service_url = std::collections::HashSet::<&str>::with_capacity(specs.len());
    let mut descriptions = Vec::<String>::with_capacity(specs.len());
    let mut functions = Vec::<Box<V4AlgoFn>>::new();
    for spec in specs.iter() {
        match spec {
            AlgorithmSpecification::DefaultPublicIp => {
                if have_default {
                    return Err("config:ipv4_algorithms can only have up to one default_public_ip".to_owned());
                }
                have_default = true;
                descriptions.push(String::from("{type=\"default_public_ip\"}"));
                functions.push(
                    Box::new(
                        || Box::pin(crate::ip_algorithms::get_default_public_ip_v4())
                    )
                );
            },
            AlgorithmSpecification::InternetGatewayProtocol { timeout_seconds } => {
                if have_igd {
                    return Err("config:ipv4_algorithms can only have up to one internet_gateway_protocol".to_owned());
                }
                have_igd = true;
                let mut description = String::from("{type=\"internet_gateway_protocol\"");
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        process_timeout(*timeout_secs, None)?
                    },
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(
                    Box::new(
                        move || Box::pin(crate::ip_algorithms::get_igd_ip_v4(timeout))
                    )
                );
            },
            AlgorithmSpecification::WebService { url, timeout_seconds } => {
                if !have_web_service_url.insert(url.as_str()) {
                    return Err(format!("config:ipv4_algorithms can only have up to one web_service:[{}]", url));
                }
                let mut description = format!("{{type=\"web_service\", url=\"{url}\"");
                let url_parsed = match reqwest::Url::parse(url) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        return Err(format!("Failed to parse URL [{}]: {}", url, e.to_string()))
                    }
                };
                let url_owned = url.to_owned();
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        process_timeout(*timeout_secs, None)?
                    },
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(
                    Box::new(
                        move || Box::pin(crate::ip_algorithms::get_web_service_ip_v4(
                            url_parsed.to_owned(), url_owned.to_owned(), timeout
                        ))
                    )
                )
            },
        };
    }

    Ok(V4AlgoResult {descriptions, functions})
}


struct V6AlgoResult {
    descriptions: Vec::<String>,
    functions: Vec::<Box<V6AlgoFn>>,
}


fn build_v6_algos(specs: &Vec::<AlgorithmSpecification>) -> Result<V6AlgoResult, String> {
    let mut have_default = false;
    let mut have_web_service_url = std::collections::HashSet::<&str>::with_capacity(specs.len());
    let mut descriptions = Vec::<String>::with_capacity(specs.len());
    let mut functions = Vec::<Box<V6AlgoFn>>::new();
    for spec in specs.iter() {
        match spec {
            AlgorithmSpecification::DefaultPublicIp => {
                if have_default {
                    return Err("config:ipv6_algorithms can only have up to one default_public_ip".to_owned());
                }
                have_default = true;
                descriptions.push(String::from("{type=\"default_public_ip\"}"));
                functions.push(
                    Box::new(
                        || Box::pin(crate::ip_algorithms::get_default_public_ip_v6())
                    )
                );
            },
            AlgorithmSpecification::InternetGatewayProtocol { timeout_seconds: _ } => {
                // TODO: consider making this error the same as any other unknown/invalid "type"
                return Err("config:ipv6_algorithms cannot have internet_gateway_protocol".to_owned());
            },
            AlgorithmSpecification::WebService { url, timeout_seconds } => {
                if !have_web_service_url.insert(url.as_str()) {
                    return Err(format!("config:ipv6_algorithms can only have up to one web_service:[{}]", url));
                }
                let mut description = format!("{{type=\"web_service\", url=\"{url}\"");
                let url_parsed = match reqwest::Url::parse(url) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        return Err(format!("Failed to parse URL [{}]: {}", url, e.to_string()))
                    }
                };
                let url_owned = url.to_owned();
                let timeout = match timeout_seconds {
                    Some(timeout_secs) => {
                        description += format!(", timeout_seconds={timeout_secs}").as_str();
                        process_timeout(*timeout_secs, None)?
                    },
                    None => Duration::from_secs_f64(DEFAULT_ALGO_TIMEOUT_SECONDS),
                };
                description += "}";
                descriptions.push(description);
                functions.push(
                    Box::new(
                        move || Box::pin(crate::ip_algorithms::get_web_service_ip_v6(
                            url_parsed.to_owned(), url_owned.to_owned(), timeout
                        ))
                    )
                )
            },
        };
    }

    Ok(V6AlgoResult {descriptions, functions})
}


impl Config {
    pub async fn load(config_path: &String) -> Result<Self, String> {
        let config_file = read_config_file(config_path)?;

        let host_name_normalized = {
            let name_lower = config_file.host_name.to_lowercase();
            let mut name_lower_idna = match
                idna::domain_to_ascii_cow(
                    name_lower.as_bytes(), idna::AsciiDenyList::URL
                )
                {
                    Ok(r) => r,
                    Err(e) => { return Err(format!("Failed to convert hostname to IDNA: {}", e.to_string())); }
                }.into_owned()
            ;
            validate_host_name(name_lower_idna.as_str())?;
            if !name_lower_idna.ends_with(".") {
                name_lower_idna += ".";
            }
            name_lower_idna
        };

        let poll_interval = process_timeout(
            config_file.update_poll_seconds, 
            Some(MAX_UPDATE_POLL_SECONDS)
        )?;
        let timeout = process_timeout(
            config_file.update_timeout_seconds, 
            Some(MAX_UPDATE_TIMEOUT_SECONDS)
        )?;
        let ttl = process_bounded_integer(config_file.aws_route53_record_ttl, Some(0i64), Some(2147483647i64))?;
        let v4_algos = build_v4_algos(&config_file.ipv4_algorithms)?;
        let v6_algos = build_v6_algos(&config_file.ipv6_algorithms)?;

        let client = crate::aws_route53::get_client(
            &config_file.aws_profile,
            &config_file.aws_access_key_id,
            &config_file.aws_secret_access_key,
            &config_file.aws_region
        ).await;

        Ok(Self {
            host_name: config_file.host_name,
            host_name_normalized,
            update_poll_interval: poll_interval,
            update_timeout: timeout,
            ipv4_algorithms: v4_algos.descriptions,
            ipv4_algo_fns: v4_algos.functions,
            ipv6_algorithms: v6_algos.descriptions,
            ipv6_algo_fns: v6_algos.functions,
            route53_client: client,
            route53_zone_id: config_file.aws_route53_zone_id,
            route53_record_ttl: ttl,
        })
    }

    pub async fn get_ipv4_addresses(&self) -> Vec::<Ipv4Addr> {
        for (name, algo_fn) in self.ipv4_algorithms.iter().zip(self.ipv4_algo_fns.iter()) {
            debug!("ipv4: Trying algorithm: {}", name);
            let algo_result = algo_fn().await;
            match algo_result {
                Ok(ips) => {
                    debug!("ipv4: got addresses: {:?}", &ips);
                    if ips.is_empty() {
                        debug!("ipv4: skipping empty result for algorithm: {}", name);
                    } else {
                        debug!("ipv4: return {} found address(es)", ips.len());
                        return ips;
                    }
                },
                Err(msg) => {
                    warn!("ipv4: algorithm {} returned error: {}", name, msg);
                }
            };
        }

        warn!("ipv4: none of the configured algorithms found any results; returning empty-set.");
        Vec::<Ipv4Addr>::new()
    }

    pub async fn get_ipv6_addresses(&self) -> Vec::<Ipv6Addr> {
        for (name, algo_fn) in self.ipv6_algorithms.iter().zip(self.ipv6_algo_fns.iter()) {
            debug!("ipv6: Trying algorithm: {}", name);
            let algo_result = algo_fn().await;
            match algo_result {
                Ok(ips) => {
                    debug!("ipv6: got addresses: {:?}", &ips);
                    if ips.is_empty() {
                        debug!("ipv6: skipping empty result for algorithm: {}", name);
                    } else {
                        debug!("ipv6: return {} found address(es)", ips.len());
                        return ips;
                    }
                },
                Err(msg) => {
                    warn!("ipv6: algorithm {} returned error: {}", name, msg);
                }
            };
        }

        warn!("ipv6: none of the configured algorithms found any results; returning empty-set.");
        Vec::<Ipv6Addr>::new()
    }
}
 