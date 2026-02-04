use std::{
    fmt::Display, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path, path::PathBuf,
    time::Duration,
};

use serde::Deserialize;
use tracing::{info, warn};

use crate::tracing_config::LogLevel;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Observability configuration
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// DNS zone configuration
    pub zone: ZoneConfig,

    /// DNS server configuration
    pub server: DnsServerConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ZoneConfig {
    pub zone_name: String,
    pub dns_server_name: String,
    pub responsible_name: String,
    pub private_key_path: PathBuf,
    #[serde(default = "default_sign_duration")]
    pub sign_duration: Duration,
    pub servers_list_path: PathBuf,
}

/// Default signing duration for the DNS zone
fn default_sign_duration() -> Duration {
    Duration::from_secs(120)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsServerConfig {
    #[serde(rename = "listen")]
    pub listen_addr: SocketAddr,
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout: Duration,
}

/// Default TCP timeout duration
fn default_tcp_timeout() -> Duration {
    Duration::from_secs(5)
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub log_level: Option<LogLevel>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error while reading config: {e}"),
            Self::Toml(e) => write!(f, "config toml parsing error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let meta = std::fs::metadata(&file)?;
        let perm = meta.permissions();

        const S_IWOTH: u32 = 2;
        if perm.mode() & S_IWOTH != 0 {
            warn!("Unrestricted config file permissions: Others can write.");
        }

        let contents = tokio::fs::read_to_string(file).await?;
        Ok(toml::de::from_str(&contents)?)
    }

    pub async fn from_args(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let path = file.as_ref();
        info!(?path, "using config file");

        let config = Config::from_file(path).await?;

        Ok(config)
    }
}
