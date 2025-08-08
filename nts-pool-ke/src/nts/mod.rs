use std::{borrow::Cow, fmt::Display, io::Error, slice};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod record;

#[cfg(feature = "fuzz")]
pub use record::NtsRecord;
#[cfg(not(feature = "fuzz"))]
use record::NtsRecord;

pub type ProtocolId = u16;
pub type AlgorithmId = u16;

const MAX_MESSAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgorithmDescription {
    pub id: AlgorithmId,
    pub keysize: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    UnrecognizedCriticalRecord,
    BadRequest,
    InternalServerError,
    NoSuchServer,
    Unknown(u16),
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            ErrorCode::BadRequest => f.write_str("Bad request"),
            ErrorCode::InternalServerError => f.write_str("Internal server error"),
            ErrorCode::NoSuchServer => f.write_str("Requested server doesn't exist"),
            ErrorCode::Unknown(id) => write!(f, "Unknown({id})"),
        }
    }
}

impl ErrorCode {
    pub async fn parse(mut reader: impl AsyncRead + Unpin) -> Result<Self, Error> {
        let code = reader.read_u16().await?;
        Ok(match code {
            0 => Self::UnrecognizedCriticalRecord,
            1 => Self::BadRequest,
            2 => Self::InternalServerError,
            0xF000 => Self::NoSuchServer,
            _ => Self::Unknown(code),
        })
    }

    pub async fn serialize(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        match *self {
            ErrorCode::UnrecognizedCriticalRecord => writer.write_u16(0).await,
            ErrorCode::BadRequest => writer.write_u16(1).await,
            ErrorCode::InternalServerError => writer.write_u16(2).await,
            ErrorCode::NoSuchServer => writer.write_u16(0xF000).await,
            ErrorCode::Unknown(code) => writer.write_u16(code).await,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WarningCode {
    Unknown(u16),
}

impl WarningCode {
    pub async fn parse(mut reader: impl AsyncRead + Unpin) -> Result<Self, Error> {
        let code = reader.read_u16().await?;

        Ok(Self::Unknown(code))
    }

    pub async fn serialize(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        match *self {
            Self::Unknown(code) => writer.write_u16(code).await,
        }
    }
}

#[derive(Debug)]
pub enum NtsError {
    IO(Error),
    UnrecognizedCriticalRecord,
    Invalid,
    UnknownWarning(u16),
    Error(ErrorCode),
}

impl From<Error> for NtsError {
    fn from(value: Error) -> Self {
        Self::IO(value)
    }
}

impl Display for NtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtsError::IO(error) => error.fmt(f),
            NtsError::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            NtsError::Invalid => f.write_str("Invalid request or response"),
            NtsError::UnknownWarning(code) => {
                write!(f, "Received unknown warning from remote: {code}")
            }
            NtsError::Error(error) => write!(f, "Received error from remote: {error}"),
        }
    }
}

impl core::error::Error for NtsError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientRequest<'a> {
    Ordinary {
        algorithms: Cow<'a, [AlgorithmId]>,
        protocols: Cow<'a, [ProtocolId]>,
        denied_servers: Vec<Cow<'a, str>>,
    },
    Uuid {
        algorithms: Cow<'a, [AlgorithmId]>,
        protocols: Cow<'a, [ProtocolId]>,
        key: Cow<'a, str>,
        uuid: Cow<'a, str>,
    },
}

impl ClientRequest<'_> {
    pub fn algorithms(&self) -> &[AlgorithmId] {
        match self {
            ClientRequest::Ordinary { algorithms, .. } | ClientRequest::Uuid { algorithms, .. } => {
                algorithms
            }
        }
    }

    pub fn protocols(&self) -> &[ProtocolId] {
        match self {
            ClientRequest::Ordinary { protocols, .. } | ClientRequest::Uuid { protocols, .. } => {
                protocols
            }
        }
    }

    pub async fn parse(reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut reader = reader.take(MAX_MESSAGE_SIZE);

        let mut algorithms = None;
        let mut protocols = None;
        let mut denied_servers = vec![];
        let mut authentication_key = None;
        let mut given_uuid = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocols.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    protocols = Some(protocol_ids)
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithms.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    algorithms = Some(algorithm_ids)
                }
                NtsRecord::NtpServerDeny { denied } => denied_servers.push(denied),
                NtsRecord::Authentication { key } => {
                    if authentication_key.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    authentication_key = Some(key)
                }
                NtsRecord::UUIDRequest { uuid } if authentication_key.is_some() => {
                    if given_uuid.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    given_uuid = Some(uuid)
                }
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::Unknown { .. }
                | NtsRecord::KeepAlive
                | NtsRecord::Port { .. }
                | NtsRecord::Server { .. } => {}
                // Not allowed
                NtsRecord::Error { .. }
                | NtsRecord::Warning { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::NewCookie { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::SupportedNextProtocolList { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(algorithms), Some(protocols)) = (algorithms, protocols) {
            if let (Some(key), Some(uuid)) = (authentication_key, given_uuid) {
                if !denied_servers.is_empty() {
                    return Err(NtsError::Invalid);
                }
                Ok(ClientRequest::Uuid {
                    algorithms,
                    protocols,
                    key,
                    uuid,
                })
            } else {
                Ok(ClientRequest::Ordinary {
                    algorithms,
                    protocols,
                    denied_servers,
                })
            }
        } else {
            Err(NtsError::Invalid)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerInformationRequest;

impl ServerInformationRequest {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        NtsRecord::SupportedAlgorithmList {
            supported_algorithms: [].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::SupportedNextProtocolList {
            supported_protocols: [].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerInformationResponse<'a> {
    pub supported_algorithms: Cow<'a, [AlgorithmDescription]>,
    pub supported_protocols: Cow<'a, [ProtocolId]>,
}

impl ServerInformationResponse<'_> {
    pub async fn parse(reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut reader = reader.take(MAX_MESSAGE_SIZE);

        let mut supported_algorithms = None;
        let mut supported_protocols = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::SupportedNextProtocolList {
                    supported_protocols: protocols,
                } => {
                    if supported_protocols.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    supported_protocols = Some(protocols);
                }
                NtsRecord::SupportedAlgorithmList {
                    supported_algorithms: algorithms,
                } => {
                    if supported_algorithms.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    supported_algorithms = Some(algorithms)
                }
                // Error
                NtsRecord::Error { errorcode } => return Err(NtsError::Error(errorcode)),
                // Warning
                NtsRecord::Warning { warningcode } => match warningcode {
                    WarningCode::Unknown(code) => return Err(NtsError::UnknownWarning(code)),
                },
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::KeepAlive
                | NtsRecord::Unknown { .. }
                | NtsRecord::Server { .. }
                | NtsRecord::Port { .. }
                | NtsRecord::Authentication { .. } => {}
                // Not allowed
                NtsRecord::NewCookie { .. }
                | NtsRecord::NextProtocol { .. }
                | NtsRecord::AeadAlgorithm { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::NtpServerDeny { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(supported_algorithms), Some(supported_protocols)) =
            (supported_algorithms, supported_protocols)
        {
            Ok(ServerInformationResponse {
                supported_algorithms,
                supported_protocols,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }
}

pub struct FixedKeyRequest<'a> {
    pub c2s: Cow<'a, [u8]>,
    pub s2c: Cow<'a, [u8]>,
    pub protocol: ProtocolId,
    pub algorithm: AlgorithmId,
}

impl FixedKeyRequest<'_> {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        NtsRecord::FixedKeyRequest {
            c2s: self.c2s,
            s2c: self.s2c,
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::NextProtocol {
            protocol_ids: slice::from_ref(&self.protocol).into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::AeadAlgorithm {
            algorithm_ids: slice::from_ref(&self.algorithm).into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn parse(reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut reader = reader.take(MAX_MESSAGE_SIZE);

        let mut c2s = None;
        let mut s2c = None;
        let mut algorithm = None;
        let mut protocol = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::FixedKeyRequest {
                    c2s: c2s_rem,
                    s2c: s2c_rem,
                } => {
                    if c2s.is_some() || s2c.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    c2s = Some(c2s_rem);
                    s2c = Some(s2c_rem);
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithm.is_some() || algorithm_ids.len() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    algorithm = Some(algorithm_ids[0]);
                }
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocol.is_some() || protocol_ids.len() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    protocol = Some(protocol_ids[0]);
                }
                // Error
                NtsRecord::Error { errorcode } => return Err(NtsError::Error(errorcode)),
                // Warning
                NtsRecord::Warning { warningcode } => match warningcode {
                    WarningCode::Unknown(code) => return Err(NtsError::UnknownWarning(code)),
                },
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::KeepAlive
                | NtsRecord::Unknown { .. }
                | NtsRecord::Server { .. }
                | NtsRecord::Port { .. }
                | NtsRecord::Authentication { .. } => {}
                // Not allowed
                NtsRecord::NewCookie { .. }
                | NtsRecord::SupportedNextProtocolList { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::NtpServerDeny { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(algorithm), Some(protocol), Some(c2s), Some(s2c)) =
            (algorithm, protocol, c2s, s2c)
        {
            Ok(Self {
                c2s,
                s2c,
                protocol,
                algorithm,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }
}

pub struct KeyExchangeResponse<'a> {
    pub protocol: ProtocolId,
    pub algorithm: AlgorithmId,
    pub cookies: Vec<Cow<'a, [u8]>>,
    pub server: Option<Cow<'a, str>>,
    pub port: Option<u16>,
}

impl KeyExchangeResponse<'_> {
    pub async fn parse(reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut reader = reader.take(MAX_MESSAGE_SIZE);

        let mut protocol = None;
        let mut algorithm = None;
        let mut cookies = vec![];
        let mut server = None;
        let mut port = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocol.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    match protocol_ids.split_first() {
                        Some((&id, [])) => protocol = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithm.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    match algorithm_ids.split_first() {
                        Some((&id, [])) => algorithm = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::NewCookie { cookie_data } => cookies.push(cookie_data),
                NtsRecord::Server { name } => {
                    if server.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    server = Some(name)
                }
                NtsRecord::Port {
                    port: received_port,
                } => {
                    if port.is_some() {
                        return Err(NtsError::Invalid);
                    }
                    port = Some(received_port);
                }
                // Error
                NtsRecord::Error { errorcode } => return Err(NtsError::Error(errorcode)),
                // Warning
                NtsRecord::Warning { warningcode } => match warningcode {
                    WarningCode::Unknown(code) => return Err(NtsError::UnknownWarning(code)),
                },
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::Unknown { .. }
                | NtsRecord::KeepAlive
                | NtsRecord::Authentication { .. } => {}
                // Not allowed
                NtsRecord::NtpServerDeny { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::SupportedNextProtocolList { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(protocol), Some(algorithm)) = (protocol, algorithm) {
            Ok(KeyExchangeResponse {
                protocol,
                algorithm,
                cookies,
                server,
                port,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }

    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        NtsRecord::NextProtocol {
            protocol_ids: slice::from_ref(&self.protocol).into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::AeadAlgorithm {
            algorithm_ids: slice::from_ref(&self.algorithm).into(),
        }
        .serialize(&mut writer)
        .await?;
        for cookie_data in self.cookies {
            NtsRecord::NewCookie { cookie_data }
                .serialize(&mut writer)
                .await?;
        }
        if let Some(name) = self.server {
            NtsRecord::Server { name }.serialize(&mut writer).await?;
        }
        if let Some(port) = self.port {
            NtsRecord::Port { port }.serialize(&mut writer).await?;
        }
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

pub struct NoAgreementResponse;

impl NoAgreementResponse {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        NtsRecord::NextProtocol {
            protocol_ids: [].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

pub struct ErrorResponse {
    pub errorcode: ErrorCode,
}

impl ErrorResponse {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        NtsRecord::Error {
            errorcode: self.errorcode,
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        future::Future,
        io::Error,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use super::{
        AlgorithmDescription, ClientRequest, ErrorCode, ErrorResponse, FixedKeyRequest,
        KeyExchangeResponse, NoAgreementResponse, NtsError, ServerInformationRequest,
        ServerInformationResponse,
    };

    // wrapper for dealing with the fact that serialize functions are async in tests.
    fn swrap<'a, F, T, U>(f: F, t: T, buf: &'a mut Vec<u8>) -> Result<(), Error>
    where
        F: FnOnce(T, &'a mut Vec<u8>) -> U,
        U: Future<Output = Result<(), Error>>,
    {
        let Poll::Ready(result) = pin!(f(t, buf)).poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("Future stalled unexpectedly.");
        };

        result
    }

    // wrapper for dealing with the fact that serialize functions are async in tests.
    fn pwrap<'a, F, T, U>(f: F, buf: &'a [u8]) -> Result<T, NtsError>
    where
        F: FnOnce(&'a [u8]) -> U,
        U: Future<Output = Result<T, NtsError>>,
    {
        let Poll::Ready(result) = pin!(f(buf)).poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("Future stalled unexpectedly");
        };

        result
    }

    #[test]
    fn test_error_response() {
        let mut buf = vec![];
        assert!(matches!(
            swrap(
                ErrorResponse::serialize,
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 2, 0x80, 0, 0, 0]);
    }

    #[test]
    fn test_client_request_basic() {
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);

        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x40, 3, 0, 5, b'h', b'e', b'l', b'l',
                b'o', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [4].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, ["hello"]);
    }

    #[test]
    fn test_client_request_rejects_incomplete() {
        assert!(
            pwrap(
                ClientRequest::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4]
            )
            .is_err()
        );
        assert!(pwrap(ClientRequest::parse, &[0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0]).is_err());
        assert!(pwrap(ClientRequest::parse, &[0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0]).is_err());
    }

    #[test]
    fn test_client_request_rejects_unknown_critical() {
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 50, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_client_request_ignores_unneccessary() {
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 50, 0, 0, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);

        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);

        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);

        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);

        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(denied_servers, [] as [String; 0]);
    }

    #[test]
    fn test_client_request_rejects_problematic() {
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 2, 0, 4, 1, 2, 3, 4, 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'h', b'i', 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_client_request_uuid_basic() {
        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
                b'c', b'd', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");
    }

    #[test]
    fn test_client_request_uuid_requires_authentication() {
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'c', b'd', 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'c', b'd', 0x4F, 0,
                    0, 2, b'a', b'b'
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_client_request_uuid_ignores_non_problematic() {
        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
                b'c', b'd', 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");

        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap(
            ClientRequest::parse,
            &[
                0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
                b'c', b'd', 0x80, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
            ],
        )
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms, [0].as_slice());
        assert_eq!(protocols, [0].as_slice());
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");
    }

    #[test]
    fn test_client_request_uuid_reject_problematic() {
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x80, 1, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x80, 2, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x80, 3, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x80, 4, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x80, 5, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0xC0, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0xC0, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0xC0, 5, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0x4F, 0, 0, 2, 5, 6, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ClientRequest::parse,
                &[
                    0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x4F, 0, 2, b'a', b'b', 0xCF, 1, 0,
                    2, b'c', b'd', 0xCF, 0, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_server_information_request() {
        let mut buf = vec![];
        assert!(
            swrap(
                ServerInformationRequest::serialize,
                ServerInformationRequest,
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0]);
    }

    #[test]
    fn test_server_information_response_basic() {
        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());
    }

    #[test]
    fn test_server_information_request_rejects_incomplete() {
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[0xC0, 1, 0, 4, 0, 0, 0, 16, 0x80, 0, 0, 0]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
    }

    #[test]
    fn test_server_information_request_rejects_unknown_critical() {
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 40, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_server_information_request_rejects_problematic() {
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0xC0, 2, 0, 2, 1, 2, 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x40, 3, 0, 2, b'h', b'i',
                    0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 5, 0, 2, 1, 2, 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 4, 0, 2, 0, 1, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 1, 0, 2, 0, 0, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                ServerInformationResponse::parse,
                &[
                    0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x4F, 1, 0, 2, 1, 2, 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_server_information_request_handles_error_response() {
        assert!(matches!(
            pwrap(
                ServerInformationResponse::parse,
                &[0x80, 2, 0, 2, 0, 2, 0x80, 0, 0, 0]
            ),
            Err(NtsError::Error(ErrorCode::InternalServerError))
        ));
        assert!(matches!(
            dbg!(pwrap(
                ServerInformationResponse::parse,
                &[
                    0x80, 3, 0, 2, 0, 0, 0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 0,
                    0, 0
                ]
            )),
            Err(NtsError::UnknownWarning(0))
        ));
    }

    #[test]
    fn test_server_information_request_ignores_irrelevant() {
        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());

        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 6, 0, 2, b'h', b'i', 0x80, 0,
                0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());

        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());

        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 50, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());

        let Ok(response) = pwrap(
            ServerInformationResponse::parse,
            &[
                0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x4f, 0, 0, 2, 1, 2, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms,
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols, [0].as_slice());
    }

    #[test]
    fn test_fixed_key_request() {
        let mut buf = vec![];
        assert!(
            swrap(
                FixedKeyRequest::serialize,
                FixedKeyRequest {
                    c2s: [1, 2].as_slice().into(),
                    s2c: [3, 4].as_slice().into(),
                    protocol: 1,
                    algorithm: 2
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0xC0, 2, 0, 4, 1, 2, 3, 4, 0x80, 1, 0, 2, 0, 1, 0x80, 4, 0, 2, 0, 2, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_key_exchange_response_parse_basic() {
        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3, 4,
                0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(
            response.cookies.as_slice(),
            [Cow::Borrowed([1, 2].as_slice()), [3, 4].as_slice().into()]
        );
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, Some("hi".into()));

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3, 4,
                0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(
            response.cookies,
            [Cow::Borrowed([1, 2].as_slice()), [3, 4].as_slice().into()]
        );
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, Some("hi".into()));
    }

    #[test]
    fn test_key_exchange_response_reject_incomplete() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_multiple() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 4, 0, 0, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 15, 0, 17, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_repeated() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_problematic() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 3, 0, 2, b'h', b'i', 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x4F, 1, 0, 2, b'h', b'i', 0x80, 0,
                    0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_reject_unknown_critical() {
        assert!(
            pwrap(
                KeyExchangeResponse::parse,
                &[
                    0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 50, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_key_exchange_response_ignore() {
        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 50, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 0, 0, 0, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x4f, 0, 0, 2, 1, 2, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);
    }

    #[test]
    fn test_key_exchange_response_parse_error_warning() {
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0]
            ),
            Err(NtsError::Error(ErrorCode::UnrecognizedCriticalRecord))
        ));
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 3, 0, 2, 0, 1, 0x80, 0, 0, 0]
            ),
            Err(NtsError::UnknownWarning(1))
        ));
    }

    #[test]
    fn test_key_exchange_response_serialize() {
        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: 0,
                    algorithm: 4,
                    cookies: vec![],
                    server: None,
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: 0,
                    algorithm: 4,
                    cookies: vec![[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()],
                    server: None,
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 5, 0, 3, 1, 2, 3, 0, 5, 0, 2, 4, 5,
                0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: 0,
                    algorithm: 4,
                    cookies: vec![],
                    server: Some("hi".into()),
                    port: None
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: 0,
                    algorithm: 4,
                    cookies: vec![],
                    server: None,
                    port: Some(15)
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 7, 0, 2, 0, 15, 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: 0,
                    algorithm: 4,
                    cookies: vec![[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()],
                    server: Some("hi".into()),
                    port: Some(15)
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 5, 0, 3, 1, 2, 3, 0, 5, 0, 2, 4, 5,
                0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 15, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_no_agreement_response() {
        let mut buf = vec![];
        assert!(
            swrap(
                NoAgreementResponse::serialize,
                NoAgreementResponse,
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(buf, [0x80, 1, 0, 0, 0x80, 0, 0, 0]);
    }
}
