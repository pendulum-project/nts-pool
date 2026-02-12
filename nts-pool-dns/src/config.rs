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
    #[serde(
        rename = "sign-duration-seconds",
        default = "default_sign_duration",
        deserialize_with = "duration_seconds"
    )]
    pub sign_duration: Duration,
    pub servers_list_path: PathBuf,
}

/// Default signing duration for the DNS zone
fn default_sign_duration() -> Duration {
    Duration::from_secs(120)
}

fn duration_seconds<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsServerConfig {
    #[serde(rename = "listen")]
    pub listen_addr: SocketAddr,
    #[serde(
        rename = "tcp-timeout-ms",
        default = "default_tcp_timeout",
        deserialize_with = "duration_millis"
    )]
    pub tcp_timeout: Duration,
}

/// Default TCP timeout duration
fn default_tcp_timeout() -> Duration {
    Duration::from_secs(5)
}

fn duration_millis<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let millis = u64::deserialize(deserializer)?;
    Ok(Duration::from_millis(millis))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deserialize_zone_config() {
        let config_content = r#"
            zone-name = "example.com."
            dns-server-name = "ns1.example.com."
            responsible-name = "admin.example.com."
            private-key-path = "/path/to/key.pem"
            sign-duration-seconds = 120
            servers-list-path = "/path/to/servers.txt"
        "#;
        let zone_config: ZoneConfig =
            toml::from_str(config_content).expect("Failed to deserialize ZoneConfig");
        assert_eq!(zone_config.zone_name, "example.com.");
        assert_eq!(zone_config.dns_server_name, "ns1.example.com.");
        assert_eq!(zone_config.responsible_name, "admin.example.com.");
        assert_eq!(
            zone_config.private_key_path,
            PathBuf::from("/path/to/key.pem")
        );
        assert_eq!(zone_config.sign_duration, Duration::from_secs(120));
        assert_eq!(
            zone_config.servers_list_path,
            PathBuf::from("/path/to/servers.txt")
        );
    }

    #[test]
    fn test_deserialize_dns_server_config() {
        let config_content = r#"
            listen = "127.0.0.1:53"
            tcp-timeout-ms = 10000
        "#;
        let dns_server_config: DnsServerConfig =
            toml::from_str(config_content).expect("Failed to deserialize DnsServerConfig");
        assert_eq!(
            dns_server_config.listen_addr,
            "127.0.0.1:53".parse().unwrap()
        );
        assert_eq!(dns_server_config.tcp_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_deserialize_observability_config() {
        let config_content = r#"
            log-level = "debug"
        "#;
        let observability_config: ObservabilityConfig =
            toml::from_str(config_content).expect("Failed to deserialize ObservabilityConfig");
        assert_eq!(observability_config.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_deserialize_config() {
        let config_content = r#"
            [observability]
            log-level = "info"

            [zone]
            zone-name = "example.com."
            dns-server-name = "ns1.example.com."
            responsible-name = "admin.example.com."
            private-key-path = "/path/to/key.pem"
            servers-list-path = "/path/to/servers.txt"

            [server]
            listen = "[::1]:53"
        "#;
        let config: Config = toml::from_str(config_content).expect("Failed to deserialize Config");
        assert_eq!(config.observability.log_level, Some(LogLevel::Info));
        assert_eq!(config.zone.zone_name, "example.com.");
        assert_eq!(config.zone.dns_server_name, "ns1.example.com.");
        assert_eq!(config.zone.responsible_name, "admin.example.com.");
        assert_eq!(
            config.zone.private_key_path,
            PathBuf::from("/path/to/key.pem")
        );
        assert_eq!(config.zone.sign_duration, Duration::from_secs(120));
        assert_eq!(
            config.zone.servers_list_path,
            PathBuf::from("/path/to/servers.txt")
        );
        assert_eq!(config.server.listen_addr, "[::1]:53".parse().unwrap());
        assert_eq!(config.server.tcp_timeout, Duration::from_secs(5));
    }
}
