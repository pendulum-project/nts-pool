use std::{borrow::Cow, fmt::Display, io::Error, slice};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod record;
mod util;

#[cfg(feature = "fuzz")]
pub use record::NtsRecord;
#[cfg(not(feature = "fuzz"))]
use record::NtsRecord;

use crate::record::{AlgorithmDescriptionList, AlgorithmList, ProtocolList};

pub use util::BufferBorrowingReader;

pub type ProtocolId = u16;
pub type AlgorithmId = u16;

pub const MAX_MESSAGE_SIZE: u64 = 4096;

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
    CouldNotConnectDownstream,
    CouldNotGetDownstreamCapabilities,
    CouldNotGetDownstreamCookies,
    Unknown(u16),
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::UnrecognizedCriticalRecord => f.write_str("Unrecognized critical record"),
            ErrorCode::BadRequest => f.write_str("Bad request"),
            ErrorCode::InternalServerError => f.write_str("Internal server error"),
            ErrorCode::NoSuchServer => f.write_str("Requested server doesn't exist"),
            ErrorCode::CouldNotConnectDownstream => {
                f.write_str("Could not connect to downstream time source")
            }
            ErrorCode::CouldNotGetDownstreamCapabilities => f.write_str(
                "Could not get downstream time source supported protocols and algorithms",
            ),
            ErrorCode::CouldNotGetDownstreamCookies => {
                f.write_str("Could not get cookies from downstream time source")
            }
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
            0xF001 => Self::CouldNotConnectDownstream,
            0xF002 => Self::CouldNotGetDownstreamCapabilities,
            0xF003 => Self::CouldNotGetDownstreamCookies,
            _ => Self::Unknown(code),
        })
    }

    pub async fn serialize(&self, mut writer: impl AsyncWrite + Unpin) -> Result<(), Error> {
        match *self {
            ErrorCode::UnrecognizedCriticalRecord => writer.write_u16(0).await,
            ErrorCode::BadRequest => writer.write_u16(1).await,
            ErrorCode::InternalServerError => writer.write_u16(2).await,
            ErrorCode::NoSuchServer => writer.write_u16(0xF000).await,
            ErrorCode::CouldNotConnectDownstream => writer.write_u16(0xF001).await,
            ErrorCode::CouldNotGetDownstreamCapabilities => writer.write_u16(0xF002).await,
            ErrorCode::CouldNotGetDownstreamCookies => writer.write_u16(0xF003).await,
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

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ClientRequest<'a> {
    Ordinary {
        algorithms: AlgorithmList<'a>,
        protocols: ProtocolList<'a>,
        denied_servers: Vec<Cow<'a, str>>,
    },
    Uuid {
        algorithms: AlgorithmList<'a>,
        protocols: ProtocolList<'a>,
        key: Cow<'a, str>,
        uuid: Cow<'a, str>,
    },
}

impl std::fmt::Debug for ClientRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordinary {
                algorithms,
                protocols,
                denied_servers,
            } => f
                .debug_struct("Ordinary")
                .field("algorithms", algorithms)
                .field("protocols", protocols)
                .field("denied_servers", denied_servers)
                .finish(),
            Self::Uuid {
                algorithms,
                protocols,
                key: _key,
                uuid,
            } => f
                .debug_struct("Uuid")
                .field("algorithms", algorithms)
                .field("protocols", protocols)
                .field("key", &"<HIDDEN>")
                .field("uuid", uuid)
                .finish(),
        }
    }
}

impl ClientRequest<'_> {
    pub fn algorithms<'a>(&'a self) -> &'a AlgorithmList<'a> {
        match self {
            ClientRequest::Ordinary { algorithms, .. } | ClientRequest::Uuid { algorithms, .. } => {
                algorithms
            }
        }
    }

    pub fn protocols<'a>(&'a self) -> &'a ProtocolList<'a> {
        match self {
            ClientRequest::Ordinary { protocols, .. } | ClientRequest::Uuid { protocols, .. } => {
                protocols
            }
        }
    }
}

impl<'a> ClientRequest<'a> {
    pub async fn parse(
        reader: &mut BufferBorrowingReader<'a, impl AsyncRead + Unpin>,
    ) -> Result<Self, NtsError> {
        tracing::trace!("Parsing client request");
        let mut algorithms = None;
        let mut protocols = None;
        let mut denied_servers = vec![];
        let mut authentication_key = None;
        let mut given_uuid = None;

        loop {
            let record = NtsRecord::parse(reader).await?;
            tracing::trace!("Received record {:?}", record);

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
                NtsRecord::AuthenticationToken { key } => {
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

        tracing::trace!("Finished receiving records");

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

    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        match self {
            ClientRequest::Ordinary {
                algorithms,
                protocols,
                denied_servers,
            } => {
                NtsRecord::NextProtocol {
                    protocol_ids: protocols,
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::AeadAlgorithm {
                    algorithm_ids: algorithms,
                }
                .serialize(&mut writer)
                .await?;
                for denied in denied_servers {
                    NtsRecord::NtpServerDeny { denied }
                        .serialize(&mut writer)
                        .await?;
                }
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;

                Ok(())
            }
            ClientRequest::Uuid {
                algorithms,
                protocols,
                key,
                uuid,
            } => {
                NtsRecord::AuthenticationToken { key }
                    .serialize(&mut writer)
                    .await?;
                NtsRecord::UUIDRequest { uuid }
                    .serialize(&mut writer)
                    .await?;
                NtsRecord::NextProtocol {
                    protocol_ids: protocols,
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::AeadAlgorithm {
                    algorithm_ids: algorithms,
                }
                .serialize(&mut writer)
                .await?;
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;

                Ok(())
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServerInformationRequest<'a> {
    pub key: Cow<'a, str>,
}

impl std::fmt::Debug for ServerInformationRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerInformationRequest")
            .field("key", &"<HIDDEN>")
            .finish()
    }
}

impl ServerInformationRequest<'_> {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        NtsRecord::AuthenticationToken { key: self.key }
            .serialize(&mut writer)
            .await?;
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
    pub supported_algorithms: AlgorithmDescriptionList<'a>,
    pub supported_protocols: ProtocolList<'a>,
}

impl<'a> ServerInformationResponse<'a> {
    pub async fn parse(
        reader: &mut BufferBorrowingReader<'a, impl AsyncRead + Unpin>,
    ) -> Result<Self, NtsError> {
        tracing::trace!("Parsing ServerInformationResponse");
        let mut supported_algorithms = None;
        let mut supported_protocols = None;

        loop {
            let record = NtsRecord::parse(reader).await?;
            tracing::trace!("Received record {:?}", record);

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
                | NtsRecord::AuthenticationToken { .. } => {}
                // Not allowed
                NtsRecord::NewCookie { .. }
                | NtsRecord::NextProtocol { .. }
                | NtsRecord::AeadAlgorithm { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::NtpServerDeny { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }
        tracing::trace!("Finished receiving records");

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
    pub key: Cow<'a, str>,
    pub c2s: Cow<'a, [u8]>,
    pub s2c: Cow<'a, [u8]>,
    pub protocol: ProtocolId,
    pub algorithm: AlgorithmId,
}

impl std::fmt::Debug for FixedKeyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedKeyRequest")
            .field("key", &"<HIDDEN>")
            .field("c2s", &"<HIDDEN>")
            .field("s2c", &"<HIDDEN>")
            .field("protocol", &self.protocol)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl<'a> FixedKeyRequest<'a> {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        NtsRecord::AuthenticationToken { key: self.key }
            .serialize(&mut writer)
            .await?;
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

    pub async fn parse(
        reader: &mut BufferBorrowingReader<'a, impl AsyncRead + Unpin>,
    ) -> Result<Self, NtsError> {
        tracing::trace!("Parsing FixedKeyRequest");
        let mut authentication_key = None;
        let mut c2s = None;
        let mut s2c = None;
        let mut algorithm = None;
        let mut protocol = None;

        loop {
            let record = NtsRecord::parse(reader).await?;
            tracing::trace!("Received record {:?}", record);

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
                    if algorithm.is_some() || algorithm_ids.iter().count() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    algorithm = Some(algorithm_ids.iter().next().unwrap());
                }
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocol.is_some() || protocol_ids.iter().count() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    protocol = Some(protocol_ids.iter().next().unwrap());
                }
                NtsRecord::AuthenticationToken { key } => {
                    if authentication_key.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    authentication_key = Some(key)
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
                | NtsRecord::Port { .. } => {}
                // Not allowed
                NtsRecord::NewCookie { .. }
                | NtsRecord::SupportedNextProtocolList { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::NtpServerDeny { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }
        tracing::trace!("Finished receiving records");

        if let (Some(algorithm), Some(protocol), Some(c2s), Some(s2c), Some(key)) =
            (algorithm, protocol, c2s, s2c, authentication_key)
        {
            Ok(Self {
                key,
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

#[derive(Debug)]
pub struct KeyExchangeResponse<'a> {
    pub protocol: ProtocolId,
    pub algorithm: AlgorithmId,
    pub cookies: Vec<Cow<'a, [u8]>>,
    pub server: Option<Cow<'a, str>>,
    pub port: Option<u16>,
}

impl<'a> KeyExchangeResponse<'a> {
    pub async fn parse(
        reader: &mut BufferBorrowingReader<'a, impl AsyncRead + Unpin>,
    ) -> Result<Self, NtsError> {
        tracing::trace!("Parsing KeyExchangeResponse");
        let mut protocol = None;
        let mut algorithm = None;
        let mut cookies = vec![];
        let mut server = None;
        let mut port = None;

        loop {
            let record = NtsRecord::parse(reader).await?;
            tracing::trace!("Received record {:?}", record);

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocol.is_some() || protocol_ids.iter().count() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    protocol = Some(protocol_ids.iter().next().unwrap());
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithm.is_some() || algorithm_ids.iter().count() != 1 {
                        return Err(NtsError::Invalid);
                    }

                    algorithm = Some(algorithm_ids.iter().next().unwrap());
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
                | NtsRecord::AuthenticationToken { .. } => {}
                // Not allowed
                NtsRecord::NtpServerDeny { .. }
                | NtsRecord::FixedKeyRequest { .. }
                | NtsRecord::SupportedAlgorithmList { .. }
                | NtsRecord::SupportedNextProtocolList { .. }
                | NtsRecord::UUIDRequest { .. } => return Err(NtsError::Invalid),
            }
        }
        tracing::trace!("Finished receiving records");

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

    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
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

#[derive(Debug)]
pub struct NoAgreementResponse;

impl NoAgreementResponse {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        NtsRecord::NextProtocol {
            protocol_ids: [].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::EndOfMessage.serialize(&mut writer).await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ErrorResponse {
    pub errorcode: ErrorCode,
}

impl ErrorResponse {
    pub async fn serialize(self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
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

    use crate::record::{AlgorithmList, ProtocolList};

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
    macro_rules! pwrap {
        ($f:expr, $buf:expr) => {{
            let Poll::Ready(result) =
                pin!($f(&mut $buf.as_mut().into())).poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("Future stalled unexpectedly");
            };

            result
        }};
    }

    #[test]
    fn test_error_codes() {
        for error_code in [
            ErrorCode::BadRequest,
            ErrorCode::InternalServerError,
            ErrorCode::UnrecognizedCriticalRecord,
            ErrorCode::NoSuchServer,
            ErrorCode::CouldNotConnectDownstream,
            ErrorCode::CouldNotGetDownstreamCapabilities,
            ErrorCode::CouldNotGetDownstreamCookies,
        ] {
            let mut buf = vec![];
            assert!(swrap(ErrorCode::serialize, &error_code, &mut buf).is_ok());

            let Poll::Ready(result) = pin!(ErrorCode::parse(buf.as_slice()))
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("Future stalled unexpectedly");
            };

            assert_eq!(error_code, result.unwrap());
        }

        for i in 0..=u16::MAX {
            let Poll::Ready(result) = pin!(ErrorCode::parse(i.to_le_bytes().as_slice()))
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("Future stalled unexpectedly");
            };
            let e = result.unwrap();
            let mut buf = vec![];
            assert!(swrap(ErrorCode::serialize, &e, &mut buf).is_ok());
            assert_eq!(i, u16::from_le_bytes(buf.try_into().unwrap()));
            let Poll::Ready(result) = pin!(ErrorCode::parse(i.to_le_bytes().as_slice()))
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("Future stalled unexpectedly");
            };
            let e2 = result.unwrap();
            assert_eq!(e, e2);
        }
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
    fn test_client_request_serialize_basic() {
        let mut buf = vec![];
        assert!(
            swrap(
                ClientRequest::serialize,
                ClientRequest::Ordinary {
                    algorithms: AlgorithmList::from([0, 1].as_slice()),
                    protocols: ProtocolList::from([0, 1].as_slice()),
                    denied_servers: vec![]
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 4, 0, 0, 0, 1, 0x80, 4, 0, 4, 0, 0, 0, 1, 0x80, 0, 0, 0
            ]
        );

        let mut buf = vec![];
        assert!(
            swrap(
                ClientRequest::serialize,
                ClientRequest::Ordinary {
                    algorithms: AlgorithmList::from([0, 1].as_slice()),
                    protocols: ProtocolList::from([0, 1].as_slice()),
                    denied_servers: vec!["test".into()]
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 4, 0, 0, 0, 1, 0x80, 4, 0, 4, 0, 0, 0, 1, 0x40, 3, 0, 4, b't', b'e',
                b's', b't', 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_client_request_serialize_uuid() {
        let mut buf = vec![];
        assert!(
            swrap(
                ClientRequest::serialize,
                ClientRequest::Uuid {
                    algorithms: AlgorithmList::from([0, 1].as_slice()),
                    protocols: ProtocolList::from([0, 1].as_slice()),
                    key: "key".into(),
                    uuid: "uuid".into(),
                },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x40, 5, 0, 3, b'k', b'e', b'y', 0xCF, 1, 0, 4, b'u', b'u', b'i', b'd', 0x80, 1, 0,
                4, 0, 0, 0, 1, 0x80, 4, 0, 4, 0, 0, 0, 1, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_client_request_basic() {
        let mut arr1 = [0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr1)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);

        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x40, 3, 0, 5, b'h', b'e', b'l', b'l', b'o',
            0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr2)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [4]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, ["hello"]);
    }

    #[test]
    fn test_client_request_rejects_incomplete() {
        let rec = &mut [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4];
        assert!(pwrap!(ClientRequest::parse, rec).is_err());
        let rec = &mut [0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0];
        assert!(pwrap!(ClientRequest::parse, rec).is_err());
        let rec = &mut [0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0];
        assert!(pwrap!(ClientRequest::parse, rec).is_err());
    }

    #[test]
    fn test_client_request_rejects_unknown_critical() {
        let mut arr = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 50, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr).is_err());
    }

    #[test]
    fn test_client_request_ignores_unneccessary() {
        let mut arr1 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 50, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr1)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);

        let mut arr2 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr2)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);

        let mut arr3 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr3)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);

        let mut arr4 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr4)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);

        let mut arr5 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Ordinary {
            algorithms,
            protocols,
            denied_servers,
        }) = pwrap!(ClientRequest::parse, &mut arr5)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(denied_servers, [] as [String; 0]);
    }

    #[test]
    fn test_client_request_rejects_problematic() {
        let mut arr1 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr2).is_err());
        let mut arr3 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 4, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr3).is_err());
        let mut arr4 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 1, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr4).is_err());
        let mut arr5 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 2, 0, 4, 1, 2, 3, 4, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr5).is_err());
        let mut arr6 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr6).is_err());
        let mut arr7 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr7).is_err());
    }

    #[test]
    fn test_client_request_uuid_basic() {
        let mut arr = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
            b'c', b'd', 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap!(ClientRequest::parse, &mut arr)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");
    }

    #[test]
    fn test_client_request_uuid_requires_authentication() {
        let mut arr1 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'c', b'd', 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0xCF, 1, 0, 2, b'c', b'd', 0x40, 5, 0, 2,
            b'a', b'b',
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr2).is_err());
    }

    #[test]
    fn test_client_request_uuid_ignores_non_problematic() {
        let mut arr1 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
            b'c', b'd', 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap!(ClientRequest::parse, &mut arr1)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");

        let mut arr2 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 0, 2, b'a', b'b', 0xCF, 1, 0, 2,
            b'c', b'd', 0x80, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
        ];
        let Ok(ClientRequest::Uuid {
            algorithms,
            protocols,
            key,
            uuid,
        }) = pwrap!(ClientRequest::parse, &mut arr2)
        else {
            panic!("Expected parse");
        };
        assert_eq!(algorithms.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(protocols.iter().collect::<Vec<_>>(), [0]);
        assert_eq!(key, "ab");
        assert_eq!(uuid, "cd");
    }

    #[test]
    fn test_client_request_uuid_reject_problematic() {
        let mut arr1 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x80, 1, 0, 2, 0, 1, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x80, 2, 0, 2, 0, 1, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr2).is_err());
        let mut arr3 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x80, 3, 0, 2, 0, 1, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr3).is_err());
        let mut arr4 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x80, 4, 0, 2, 0, 1, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr4).is_err());
        let mut arr5 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x80, 5, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr5).is_err());
        let mut arr6 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0xC0, 4, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr6).is_err());
        let mut arr7 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0xC0, 1, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr7).is_err());
        let mut arr8 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0xC0, 5, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr8).is_err());
        let mut arr9 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr9).is_err());
        let mut arr10 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr10).is_err());
        let mut arr11 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0x40, 5, 0, 2, 5, 6, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr11).is_err());
        let mut arr12 = [
            0x80, 4, 0, 2, 0, 0, 0x80, 1, 0, 2, 0, 0, 0x40, 5, 2, b'a', b'b', 0xCF, 1, 0, 2, b'c',
            b'd', 0xCF, 0, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ClientRequest::parse, &mut arr12).is_err());
    }

    #[test]
    fn test_server_information_request() {
        let mut buf = vec![];
        assert!(
            swrap(
                ServerInformationRequest::serialize,
                ServerInformationRequest { key: "abcd".into() },
                &mut buf
            )
            .is_ok()
        );
        assert_eq!(
            buf,
            [
                0x40, 5, 0, 4, b'a', b'b', b'c', b'd', 0xC0, 1, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_server_information_response_basic() {
        let mut rec = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut rec) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(
            response.supported_protocols.iter().collect::<Vec<_>>(),
            [0].as_slice()
        );
    }

    #[test]
    fn test_server_information_request_rejects_incomplete() {
        let mut arr1 = [0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr1).is_err());
        let mut arr2 = [0xC0, 1, 0, 4, 0, 0, 0, 16, 0x80, 0, 0, 0];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr2).is_err());
        let mut arr3 = [0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr3).is_err());
    }

    #[test]
    fn test_server_information_request_rejects_unknown_critical() {
        let mut arr = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 40, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr).is_err());
    }

    #[test]
    fn test_server_information_request_rejects_problematic() {
        let mut arr1 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr1).is_err());
        let mut arr2 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0,
            0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr2).is_err());
        let mut arr3 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 5, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr3).is_err());
        let mut arr4 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 4, 0, 2, 0, 1, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr4).is_err());
        let mut arr5 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 1, 0, 2, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr5).is_err());
        let mut arr6 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x4F, 1, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(ServerInformationResponse::parse, &mut arr6).is_err());
    }

    #[test]
    fn test_server_information_request_handles_error_response() {
        let mut arr1 = [0x80, 2, 0, 2, 0, 2, 0x80, 0, 0, 0];
        assert!(matches!(
            pwrap!(ServerInformationResponse::parse, &mut arr1),
            Err(NtsError::Error(ErrorCode::InternalServerError))
        ));
        let mut arr2 = [
            0x80, 3, 0, 2, 0, 0, 0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(matches!(
            dbg!(pwrap!(ServerInformationResponse::parse, &mut arr2)),
            Err(NtsError::UnknownWarning(0))
        ));
    }

    #[test]
    fn test_server_information_request_ignores_irrelevant() {
        let mut arr1 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x40, 0, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut arr1) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(
            response.supported_protocols.iter().collect::<Vec<_>>(),
            [0].as_slice()
        );

        let mut arr2 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut arr2) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(
            response.supported_protocols.iter().collect::<Vec<_>>(),
            [0].as_slice()
        );

        let mut arr3 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 7, 0, 2, 0, 123, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut arr3) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(
            response.supported_protocols.iter().collect::<Vec<_>>(),
            [0].as_slice()
        );

        let mut arr4 = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0, 50, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut arr4) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }].as_slice()
        );
        assert_eq!(response.supported_protocols.iter().collect::<Vec<_>>(), [0]);

        let mut arr = [
            0xC0, 1, 0, 4, 0, 0, 0, 16, 0xC0, 4, 0, 2, 0, 0, 0x4f, 0, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(ServerInformationResponse::parse, &mut arr) else {
            panic!("Expected succesfull parse");
        };
        assert_eq!(
            response.supported_algorithms.iter().collect::<Vec<_>>(),
            [AlgorithmDescription { id: 0, keysize: 16 }]
        );
        assert_eq!(response.supported_protocols.iter().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn test_fixed_key_request() {
        let mut buf = vec![];
        assert!(
            swrap(
                FixedKeyRequest::serialize,
                FixedKeyRequest {
                    key: "abcd".into(),
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
                0x40, 5, 0, 4, b'a', b'b', b'c', b'd', 0xC0, 2, 0, 4, 1, 2, 3, 4, 0x80, 1, 0, 2, 0,
                1, 0x80, 4, 0, 2, 0, 2, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_key_exchange_response_parse_basic() {
        let mut arr1 = [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr1) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3, 4,
            0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr2) else {
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

        let mut arr3 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr3) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, Some("hi".into()));

        let mut arr4 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr4) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, None);

        let mut arr = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3, 4,
            0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr) else {
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
        let mut arr1 = [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr1).is_err());
        let mut arr2 = [0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr2).is_err());
        let mut arr3 = [0x80, 4, 0, 2, 0, 4, 0x80, 0, 0, 0];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr3).is_err());
    }

    #[test]
    fn test_key_exchange_response_reject_multiple() {
        let mut arr1 = [
            0x80, 1, 0, 4, 0, 0, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 15, 0, 17, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr2).is_err());
    }

    #[test]
    fn test_key_exchange_response_reject_repeated() {
        let mut arr1 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0x80, 1, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr2).is_err());
    }

    #[test]
    fn test_key_exchange_response_reject_problematic() {
        let mut arr1 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 4, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr1).is_err());
        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 1, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr2).is_err());
        let mut arr3 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 2, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr3).is_err());
        let mut arr4 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr4).is_err());
        let mut arr5 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x4F, 1, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr5).is_err());
    }

    #[test]
    fn test_key_exchange_response_reject_unknown_critical() {
        let mut arr = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x80, 50, 0, 0, 0x80, 0, 0, 0,
        ];
        assert!(pwrap!(KeyExchangeResponse::parse, &mut arr).is_err());
    }

    #[test]
    fn test_key_exchange_response_ignore() {
        let mut arr1 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0, 50, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr1) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let mut arr2 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0xC0, 0, 0, 0, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr2) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, 0);
        assert_eq!(response.algorithm, 4);
        assert_eq!(response.cookies, [] as [Vec<u8>; 0]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let mut arr3 = [
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 4, 0x4f, 0, 0, 2, 1, 2, 0x80, 0, 0, 0,
        ];
        let Ok(response) = pwrap!(KeyExchangeResponse::parse, &mut arr3) else {
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
        let mut arr1 = [0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0];
        assert!(matches!(
            pwrap!(KeyExchangeResponse::parse, &mut arr1),
            Err(NtsError::Error(ErrorCode::UnrecognizedCriticalRecord))
        ));
        let mut arr2 = [0x80, 3, 0, 2, 0, 1, 0x80, 0, 0, 0];
        assert!(matches!(
            pwrap!(KeyExchangeResponse::parse, &mut arr2),
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
