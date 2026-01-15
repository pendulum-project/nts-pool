use std::{borrow::Cow, sync::Arc};

use pool_nts::{
    AlgorithmId, BufferBorrowingReader, ClientRequest, ErrorCode, KeyExchangeResponse, ProtocolId,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::{
    NtpVersion,
    packet::{AesSivCmac256, AesSivCmac512, Cipher},
    tls_utils::{self, Certificate, ServerName, TLS13},
};

const NTP_DEFAULT_PORT: u16 = 123;

/// From https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum AeadAlgorithm {
    AeadAesSivCmac256,
    AeadAesSivCmac512,
    Unknown(u16),
}

impl From<u16> for AeadAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            15 => Self::AeadAesSivCmac256,
            17 => Self::AeadAesSivCmac512,
            v => Self::Unknown(v),
        }
    }
}

impl From<AeadAlgorithm> for u16 {
    fn from(value: AeadAlgorithm) -> Self {
        match value {
            AeadAlgorithm::AeadAesSivCmac256 => 15,
            AeadAlgorithm::AeadAesSivCmac512 => 17,
            AeadAlgorithm::Unknown(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum NextProtocol {
    NTPv4,
    DraftNTPv5,
    Unknown(u16),
}

impl From<u16> for NextProtocol {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::NTPv4,
            0x8001 => Self::DraftNTPv5,
            v => Self::Unknown(v),
        }
    }
}

impl From<NextProtocol> for u16 {
    fn from(value: NextProtocol) -> Self {
        match value {
            NextProtocol::NTPv4 => 0,
            NextProtocol::DraftNTPv5 => 0x8001,
            NextProtocol::Unknown(v) => v,
        }
    }
}

fn extract_key_bytes<T: Default + AsMut<[u8]>, ConnectionData>(
    tls_connection: &tls_utils::ConnectionCommon<ConnectionData>,
    context: &[u8],
) -> Result<T, tls_utils::Error> {
    let mut key = T::default();
    tls_connection.export_keying_material(
        &mut key,
        b"EXPORTER-network-time-security",
        Some(context),
    )?;

    Ok(key)
}

struct NtsKeys {
    c2s: Box<dyn Cipher>,
    s2c: Box<dyn Cipher>,
}

impl NtsKeys {
    fn extract_from_connection<T>(
        tls_connection: &tls_utils::ConnectionCommon<T>,
        protocol: NextProtocol,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, NtsError> {
        let protocol_id: u16 = protocol.into();
        let algorithm_id: u16 = algorithm.into();

        let c2s_context = &[
            (protocol_id >> 8) as u8,
            protocol_id as u8,
            (algorithm_id >> 8) as u8,
            algorithm_id as u8,
            0,
        ];
        let s2c_context = &[
            (protocol_id >> 8) as u8,
            protocol_id as u8,
            (algorithm_id >> 8) as u8,
            algorithm_id as u8,
            1,
        ];

        match algorithm {
            AeadAlgorithm::AeadAesSivCmac256 => Ok(NtsKeys {
                c2s: Box::new(AesSivCmac256::new(extract_key_bytes(
                    tls_connection,
                    c2s_context,
                )?)),
                s2c: Box::new(AesSivCmac256::new(extract_key_bytes(
                    tls_connection,
                    s2c_context,
                )?)),
            }),
            AeadAlgorithm::AeadAesSivCmac512 => Ok(NtsKeys {
                c2s: Box::new(AesSivCmac512::new(extract_key_bytes(
                    tls_connection,
                    c2s_context,
                )?)),
                s2c: Box::new(AesSivCmac512::new(extract_key_bytes(
                    tls_connection,
                    s2c_context,
                )?)),
            }),
            AeadAlgorithm::Unknown(_) => Err(NtsError::Invalid),
        }
    }
}

/// Error generated during the parsing of NTS messages.
#[derive(Debug)]
pub enum NtsError {
    IO(std::io::Error),
    Tls(tls_utils::Error),
    Dns(tls_utils::InvalidDnsNameError),
    UnrecognizedCriticalRecord,
    Invalid,
    UnknownWarning(u16),
    Error(ErrorCode),
}

impl From<std::io::Error> for NtsError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<tls_utils::Error> for NtsError {
    fn from(value: tls_utils::Error) -> Self {
        Self::Tls(value)
    }
}

impl From<tls_utils::InvalidDnsNameError> for NtsError {
    fn from(value: tls_utils::InvalidDnsNameError) -> Self {
        Self::Dns(value)
    }
}

impl From<pool_nts::NtsError> for NtsError {
    fn from(value: pool_nts::NtsError) -> Self {
        match value {
            pool_nts::NtsError::IO(error) => NtsError::IO(error),
            pool_nts::NtsError::UnrecognizedCriticalRecord => NtsError::UnrecognizedCriticalRecord,
            pool_nts::NtsError::Invalid => NtsError::Invalid,
            pool_nts::NtsError::UnknownWarning(v) => NtsError::UnknownWarning(v),
            pool_nts::NtsError::Error(error_code) => NtsError::Error(error_code),
        }
    }
}

impl std::fmt::Display for NtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtsError::IO(error) => error.fmt(f),
            NtsError::Tls(error) => error.fmt(f),
            NtsError::Dns(error) => error.fmt(f),
            NtsError::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            NtsError::Invalid => f.write_str("Invalid request or response"),
            NtsError::UnknownWarning(code) => {
                write!(f, "Received unknown warning from remote: {code}")
            }
            NtsError::Error(error) => write!(f, "Received error from remote: {error}"),
        }
    }
}

impl std::error::Error for NtsError {}

pub struct KeyExchangeResult {
    pub remote: String,
    pub port: u16,
    pub cookies: Vec<Vec<u8>>,
    pub c2s: Box<dyn Cipher>,
    pub s2c: Box<dyn Cipher>,
    #[allow(unused)]
    pub protocol_version: NtpVersion,
}

#[derive(Debug, Clone)]
pub struct NtsClientConfig {
    pub certificates: Arc<[Certificate]>,
    pub protocol_version: NtpVersion,
    pub authorization_key: String,
}

impl Default for NtsClientConfig {
    fn default() -> Self {
        Self {
            certificates: Default::default(),
            protocol_version: NtpVersion::V4,
            authorization_key: "".into(),
        }
    }
}

pub struct KeyExchangeClient {
    connector: TlsConnector,
    protocols: Box<[NextProtocol]>,
    algorithms: Box<[AeadAlgorithm]>,
    authorization_key: String,
}

impl KeyExchangeClient {
    pub fn new(config: NtsClientConfig) -> Result<Self, NtsError> {
        let builder = tls_utils::client_config_builder_with_protocol_versions(&[&TLS13]);
        let verifier = tls_utils::PlatformVerifier::new_with_extra_roots(
            config.certificates.iter().cloned(),
            builder.crypto_provider().clone(),
        )?;
        let mut tls_config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"ntske/1".to_vec()];

        Ok(KeyExchangeClient {
            connector: TlsConnector::from(Arc::new(tls_config)),
            protocols: match config.protocol_version {
                NtpVersion::V4 => [NextProtocol::NTPv4].into(),
                NtpVersion::V5 => [NextProtocol::DraftNTPv5].into(),
                _ => [NextProtocol::DraftNTPv5, NextProtocol::NTPv4].into(),
            },
            algorithms: [
                AeadAlgorithm::AeadAesSivCmac512,
                AeadAlgorithm::AeadAesSivCmac256,
            ]
            .into(),
            authorization_key: config.authorization_key,
        })
    }

    pub async fn exchange_keys(
        &self,
        io: impl AsyncRead + AsyncWrite + Unpin,
        server_name: String,
        uuid: Option<impl AsRef<str>>,
    ) -> Result<KeyExchangeResult, NtsError> {
        let request = if let Some(ref uuid) = uuid {
            ClientRequest::Uuid {
                algorithms: self
                    .algorithms
                    .iter()
                    .copied()
                    .map(|v| v.into())
                    .collect::<Vec<AlgorithmId>>()
                    .into(),
                protocols: self
                    .protocols
                    .iter()
                    .copied()
                    .map(|v| v.into())
                    .collect::<Vec<ProtocolId>>()
                    .into(),
                key: self.authorization_key.as_str().into(),
                uuid: uuid.as_ref().into(),
            }
        } else {
            ClientRequest::Ordinary {
                algorithms: self
                    .algorithms
                    .iter()
                    .copied()
                    .map(|v| v.into())
                    .collect::<Vec<AlgorithmId>>()
                    .into(),
                protocols: self
                    .protocols
                    .iter()
                    .copied()
                    .map(|v| v.into())
                    .collect::<Vec<ProtocolId>>()
                    .into(),
                denied_servers: vec![],
            }
        };

        let mut io = self
            .connector
            .connect(ServerName::try_from(server_name.clone())?, io)
            .await?;

        // Serialize request first to a buffer to ensure it is most likely to be sent as a
        // single packet, which ntpsec needs.
        let mut req_buf = vec![];
        request.serialize(&mut req_buf).await?;
        io.write_all(req_buf.as_slice()).await?;

        io.flush().await?;

        let mut buffer = [0u8; 4096];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut io, &mut buffer))
                .await?;

        let keys = NtsKeys::extract_from_connection(
            io.get_ref().1,
            response.protocol.into(),
            response.algorithm.into(),
        )?;

        Ok(KeyExchangeResult {
            remote: response
                .server
                .unwrap_or(Cow::Owned(server_name))
                .into_owned(),
            port: response.port.unwrap_or(NTP_DEFAULT_PORT),
            cookies: response
                .cookies
                .iter()
                .map(|v| v.clone().into_owned())
                .collect(),
            c2s: keys.c2s,
            s2c: keys.s2c,
            protocol_version: match response.protocol.into() {
                NextProtocol::NTPv4 => NtpVersion::V4,
                NextProtocol::DraftNTPv5 => NtpVersion::V5,
                NextProtocol::Unknown(_) => return Err(NtsError::Invalid),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_algorithm_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(AeadAlgorithm::from(i)));
        }
    }

    #[test]
    fn test_next_protocol_encoding() {
        for i in 0..=u16::MAX {
            assert_eq!(i, u16::from(NextProtocol::from(i)));
        }
    }
}
