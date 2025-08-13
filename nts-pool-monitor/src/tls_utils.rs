#[allow(unused)]
mod rustls_shim {
    pub use rustls::ClientConfig;
    pub use rustls::ClientConnection;
    pub use rustls::ConnectionCommon;
    pub use rustls::Error;
    pub use rustls::RootCertStore;
    pub use rustls::ServerConfig;
    pub use rustls::ServerConnection;
    pub use rustls::pki_types::InvalidDnsNameError;
    pub use rustls::pki_types::ServerName;
    pub use rustls::server::NoClientAuth;
    pub use rustls::version::TLS13;

    pub type Certificate = rustls::pki_types::CertificateDer<'static>;
    pub type PrivateKey = rustls::pki_types::PrivateKeyDer<'static>;

    pub use rustls_platform_verifier::Verifier as PlatformVerifier;

    pub mod pemfile {
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject,
        };

        pub fn certs(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<CertificateDer<'static>, std::io::Error>> + '_ {
            CertificateDer::pem_reader_iter(rd).map(|item| {
                item.map_err(|err| match err {
                    rustls::pki_types::pem::Error::Io(error) => error,
                    _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                })
            })
        }

        pub fn private_key(
            rd: &mut dyn std::io::BufRead,
        ) -> Result<PrivateKeyDer<'static>, std::io::Error> {
            PrivateKeyDer::from_pem_reader(rd).map_err(|err| match err {
                rustls::pki_types::pem::Error::Io(error) => error,
                _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            })
        }

        pub fn pkcs8_private_keys(
            rd: &mut dyn std::io::BufRead,
        ) -> impl Iterator<Item = Result<PrivatePkcs8KeyDer<'static>, std::io::Error>> + '_
        {
            PrivatePkcs8KeyDer::pem_reader_iter(rd).map(|item| {
                item.map_err(|err| match err {
                    rustls::pki_types::pem::Error::Io(error) => error,
                    _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                })
            })
        }
    }

    pub trait CloneKeyShim {}

    pub fn client_config_builder()
    -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
        ClientConfig::builder()
    }

    pub fn client_config_builder_with_protocol_versions(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier> {
        ClientConfig::builder_with_protocol_versions(versions)
    }

    pub fn server_config_builder()
    -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
        ServerConfig::builder()
    }

    pub fn server_config_builder_with_protocol_versions(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier> {
        ServerConfig::builder_with_protocol_versions(versions)
    }
}

pub use rustls_shim::*;
