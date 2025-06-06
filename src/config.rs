use std::{
    fmt::Display,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{
    pki_types::{pem::PemObject, ServerName},
    version::TLS13,
};
use rustls_platform_verifier::Verifier;
use serde::Deserialize;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub server: NtsPoolKeConfig,
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

#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct BareNtsPoolKeConfig {
    /// Additional CAs used to validate the certificates of upstream servers
    #[serde(default)]
    upstream_cas: Option<PathBuf>,
    /// Certificate chain for the key used by the server to identify itself during tls sessions
    certificate_chain: PathBuf,
    /// Private key used by the server to identify itself during tls sessions
    private_key: PathBuf,
    #[serde(default = "default_nts_ke_timeout")]
    /// Timeout
    key_exchange_timeout: u64,
    /// Address for the server to listen on.
    listen: SocketAddr,
    /// Which upstream servers to use.
    key_exchange_servers: Box<[KeyExchangeServer]>,
}

fn default_nts_ke_timeout() -> u64 {
    1000
}

#[derive(Clone)]
pub struct NtsPoolKeConfig {
    pub server_tls: TlsAcceptor,
    pub upstream_tls: TlsConnector,
    pub listen: SocketAddr,
    pub key_exchange_servers: Box<[KeyExchangeServer]>,
    pub key_exchange_timeout: Duration,
}

fn load_certificates(
    path: impl AsRef<std::path::Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    rustls::pki_types::CertificateDer::pem_file_iter(path)?.collect()
}

impl<'de> Deserialize<'de> for NtsPoolKeConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bare = BareNtsPoolKeConfig::deserialize(deserializer)?;

        let upstream_cas = bare
            .upstream_cas
            .map(|path| {
                load_certificates(&path).map_err(|e| {
                    serde::de::Error::custom(format!(
                        "error reading additional upstream ca certificates from `{:?}`: {:?}",
                        path, e
                    ))
                })
            })
            .transpose()?;

        let certificate_chain = load_certificates(&bare.certificate_chain).map_err(|e| {
            serde::de::Error::custom(format!(
                "error reading server's certificate chain from `{:?}`: {:?}",
                bare.certificate_chain, e
            ))
        })?;

        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(&bare.private_key)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "error reading server's private key from `{:?}`: {:?}",
                    bare.private_key, e
                ))
            })?;

        let mut server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain.clone(), private_key.clone_key())
            .map_err(serde::de::Error::custom)?;
        server_config.alpn_protocols.clear();
        server_config.alpn_protocols.push(b"ntske/1".to_vec());

        let server_tls = TlsAcceptor::from(Arc::new(server_config));

        let upstream_config_builder =
            rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13]);
        let provider = upstream_config_builder.crypto_provider().clone();
        let verifier = match upstream_cas {
            Some(upstream_cas) => Verifier::new_with_extra_roots(upstream_cas.iter().cloned())
                .map_err(serde::de::Error::custom)?
                .with_provider(provider),
            None => Verifier::new(),
        };

        let upstream_config = upstream_config_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(serde::de::Error::custom)?;
        let upstream_tls = TlsConnector::from(Arc::new(upstream_config));

        Ok(NtsPoolKeConfig {
            server_tls,
            upstream_tls,
            listen: bare.listen,
            key_exchange_servers: bare.key_exchange_servers,
            key_exchange_timeout: std::time::Duration::from_millis(bare.key_exchange_timeout),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyExchangeServer {
    pub domain: String,
    pub server_name: ServerName<'static>,
    pub port: u16,
}

impl<'de> Deserialize<'de> for KeyExchangeServer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct BareKeyExchangeServer {
            domain: String,
            port: u16,
        }

        let bare = BareKeyExchangeServer::deserialize(deserializer)?;

        let Ok(server_name) = ServerName::try_from(bare.domain.clone()) else {
            return Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&bare.domain),
                &"Domain name",
            ));
        };

        Ok(KeyExchangeServer {
            domain: bare.domain.to_string(),
            server_name,
            port: bare.port,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use super::*;

    #[test]
    fn test_deserialize_bare_config() {
        let test: BareNtsPoolKeConfig = toml::from_str(
            r#"
            listen = "0.0.0.0:4460"
            upstream-cas = "/foo/bar/ca.pem"
            certificate-chain = "/foo/bar/baz.pem"
            private-key = "spam.der"
            key-exchange-servers = [
                { domain = "foo.bar", port = 1234 },
                { domain = "bar.foo", port = 4321 },
            ]
            "#,
        )
        .unwrap();

        let ca = PathBuf::from("/foo/bar/ca.pem");
        assert_eq!(test.upstream_cas, Some(ca));

        let chain = PathBuf::from("/foo/bar/baz.pem");
        assert_eq!(test.certificate_chain, chain);

        let private_key = PathBuf::from("spam.der");
        assert_eq!(test.private_key, private_key);

        assert_eq!(test.key_exchange_timeout, 1000,);
        assert_eq!(test.listen, "0.0.0.0:4460".parse().unwrap(),);

        assert_eq!(
            test.key_exchange_servers.deref(),
            [
                KeyExchangeServer {
                    domain: String::from("foo.bar"),
                    server_name: ServerName::try_from("foo.bar").unwrap(),
                    port: 1234
                },
                KeyExchangeServer {
                    domain: String::from("bar.foo"),
                    server_name: ServerName::try_from("bar.foo").unwrap(),
                    port: 4321
                },
            ]
            .as_slice()
        );
    }

    #[test]
    fn test_deserialize_config() {
        let test: Config = toml::from_str(
            r#"
            [server]
            listen = "0.0.0.0:4460"
            key-exchange-timeout = 500
            upstream-cas = "testdata/testca.pem"
            certificate-chain = "testdata/end.fullchain.pem"
            private-key = "testdata/end.key"
            key-exchange-servers = [
                { domain = "foo.bar", port = 1234 },
                { domain = "bar.foo", port = 4321 },
            ]
            "#,
        )
        .unwrap();

        assert_eq!(test.server.key_exchange_timeout, Duration::from_millis(500));
        assert_eq!(test.server.listen, "0.0.0.0:4460".parse().unwrap(),);

        assert_eq!(
            test.server.key_exchange_servers.deref(),
            [
                KeyExchangeServer {
                    domain: String::from("foo.bar"),
                    server_name: ServerName::try_from("foo.bar").unwrap(),
                    port: 1234
                },
                KeyExchangeServer {
                    domain: String::from("bar.foo"),
                    server_name: ServerName::try_from("bar.foo").unwrap(),
                    port: 4321
                },
            ]
            .as_slice()
        );
    }
}
