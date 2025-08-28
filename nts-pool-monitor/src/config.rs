use std::{
    fmt::Display,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::pki_types::pem::PemObject;
use serde::Deserialize;
use tracing::{info, warn};

use crate::tls_utils::Certificate;

fn load_certificates(
    path: impl AsRef<std::path::Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    rustls::pki_types::CertificateDer::pem_file_iter(path)?.collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub monitoring: ProbeControlConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
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
    pub fn check(&self) -> bool {
        true
    }

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

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub log_level: Option<super::daemon_tracing::LogLevel>,
}

#[derive(Debug, Clone)]
pub struct ProbeControlConfig {
    pub management_interface: String,
    pub authorization_key: String,
    pub certificates: Arc<[Certificate]>,
}

impl<'de> Deserialize<'de> for ProbeControlConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        struct BareProbeControlConfig {
            pub management_interface: String,
            pub authorization_key: String,
            pub certificates: Option<PathBuf>,
        }

        let bare = BareProbeControlConfig::deserialize(deserializer)?;

        let certificates = bare
            .certificates
            .map(|path| {
                load_certificates(&path).map_err(|e| {
                    serde::de::Error::custom(format!(
                        "error reading additional upstream ca certificates from `{path:?}`: {e:?}"
                    ))
                })
            })
            .transpose()?;

        Ok({
            ProbeControlConfig {
                management_interface: bare.management_interface,
                authorization_key: bare.authorization_key,
                certificates: certificates.unwrap_or_default().into(),
            }
        })
    }
}
