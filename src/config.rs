use core::str;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::time::Duration;
use std::vec::Vec;

use serde::Deserialize;


static DEFAULT_ALGO_TIMEOUT: f64 = 10.0;
fn default_update_poll_seconds() -> f64 { return 30.0; }
fn default_update_timeout_seconds() -> f64 { return 300.0; }
static MAX_CONFIG_FILE_SIZE: u64 = 65536;
static MAX_UPDATE_POLL_SECONDS: f64 = 3600.0;
static MAX_UPDATE_TIMEOUT_SECONDS: f64 = 3600.0;


#[derive(Deserialize)]
#[serde(tag = "type")]
enum V4algo {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

    #[serde(rename = "internet_gateway_protocol")]
    InternetGatewayProtocol {timeout_seconds: Option::<f64>},

    #[serde(rename = "web_service")]
    WebService {url: String, timeout_seconds: Option::<f64>}
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum V6algo {
    #[serde(rename = "default_public_ip")]
    DefaultPublicIp,

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

    ipv4_algorithms: Vec::<V4algo>,
    ipv6_algorithms: Vec::<V6algo>,
    aws_profile: Option<String>,
    aws_secret_key: Option<String>,
    aws_secret_access_key: Option<String>,
    aws_region: Option<String>,
    aws_route53_zone_id: Option<String>,
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


#[derive(Debug)]
pub struct Config {
    host_name: String,
    update_poll_interval: Duration,
    update_timeout: Duration,

    route53_zone_id: Option::<String>,
}

impl Config {
    pub fn load(config_path: &String) -> Result<Self, String> {
        let config_file = read_config_file(config_path)?;

        let poll_interval = process_timeout(
            config_file.update_poll_seconds, 
            Some(MAX_UPDATE_POLL_SECONDS)
        )?;
        let timeout = process_timeout(
            config_file.update_timeout_seconds, 
            Some(MAX_UPDATE_TIMEOUT_SECONDS)
        )?;

        Ok(Self {
            host_name: config_file.host_name,
            update_poll_interval: poll_interval,
            update_timeout: timeout,
            route53_zone_id: config_file.aws_route53_zone_id,
        })
    }
}