use std::{
    borrow::Cow,
    io::{Error, ErrorKind},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::BufferBorrowingReader;

use super::{AlgorithmDescription, AlgorithmId, ErrorCode, ProtocolId, WarningCode};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ListInner<'a, T> {
    BorrowedData(&'a [u8]),
    BorrowedList(&'a [T]),
    Owned(Vec<T>),
}

trait Serializable: Sync + Send {
    fn serialize<'a: 'b, 'b, C: AsyncWrite + Unpin + Send + 'b>(
        &'a self,
        writer: C,
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'b;
}

impl Serializable for u16 {
    async fn serialize<'a: 'b, 'b, C: AsyncWrite + Unpin + Send + 'b>(
        &'a self,
        mut writer: C,
    ) -> std::io::Result<()> {
        writer.write_u16(*self).await
    }
}

impl Serializable for AlgorithmDescription {
    async fn serialize<'a: 'b, 'b, C: AsyncWrite + Unpin + Send + 'b>(
        &'a self,
        mut writer: C,
    ) -> std::io::Result<()> {
        writer.write_u16(self.id).await?;
        writer.write_u16(self.keysize).await
    }
}

impl<'a, T: Copy> ListInner<'a, T> {
    fn iter_from_fn<const N: usize>(&self, f: impl Fn([u8; N]) -> T) -> impl Iterator<Item = T> {
        enum Either<X, Y, Z> {
            A(X),
            B(Y),
            C(Z),
        }

        impl<I, X: Iterator<Item = I>, Y: Iterator<Item = I>, Z: Iterator<Item = I>> Iterator
            for Either<X, Y, Z>
        {
            type Item = I;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Either::A(a) => a.next(),
                    Either::B(b) => b.next(),
                    Either::C(c) => c.next(),
                }
            }
        }

        match self {
            ListInner::BorrowedData(items) => Either::A(items.as_chunks().0.iter().copied().map(f)),
            ListInner::BorrowedList(items) => Either::B(items.iter().copied()),
            ListInner::Owned(items) => Either::C(items.iter().copied()),
        }
    }
}

impl<'a, T: Serializable> ListInner<'a, T> {
    fn serialize<'b, C: AsyncWrite + Send + Unpin + 'b>(
        &'b self,
        mut writer: C,
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'b
    where
        'a: 'b,
    {
        fn fut_workaround<'c, F: Future<Output = std::io::Result<()>> + Send + 'c>(
            f: F,
        ) -> impl Future<Output = std::io::Result<()>> + Send + 'c {
            f
        }

        async move {
            match self {
                ListInner::BorrowedData(items) => writer.write_all(items).await,
                ListInner::BorrowedList(items) => {
                    for item in *items {
                        fut_workaround(item.serialize(&mut writer)).await?;
                    }
                    Ok(())
                }
                ListInner::Owned(items) => {
                    for item in items {
                        fut_workaround(item.serialize(&mut writer)).await?;
                    }
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolList<'a> {
    inner: ListInner<'a, ProtocolId>,
}

impl<'a> ProtocolList<'a> {
    pub fn from_buffer(data: &'a [u8]) -> Result<Self, Error> {
        if !data.len().is_multiple_of(2) {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(Self {
            inner: ListInner::BorrowedData(data),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = ProtocolId> {
        self.inner.iter_from_fn(u16::from_be_bytes)
    }

    pub async fn serialize(&self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        self.inner.serialize(writer).await
    }
}

impl<'a> From<&'a [ProtocolId]> for ProtocolList<'a> {
    fn from(value: &'a [ProtocolId]) -> Self {
        Self {
            inner: ListInner::BorrowedList(value),
        }
    }
}

impl<'a> From<Vec<ProtocolId>> for ProtocolList<'a> {
    fn from(value: Vec<ProtocolId>) -> Self {
        Self {
            inner: ListInner::Owned(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlgorithmList<'a> {
    inner: ListInner<'a, AlgorithmId>,
}

impl<'a> AlgorithmList<'a> {
    pub fn from_buffer(data: &'a [u8]) -> Result<Self, Error> {
        if !data.len().is_multiple_of(2) {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(Self {
            inner: ListInner::BorrowedData(data),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = AlgorithmId> {
        self.inner.iter_from_fn(u16::from_be_bytes)
    }

    pub async fn serialize(&self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        self.inner.serialize(writer).await
    }
}

impl<'a> From<&'a [AlgorithmId]> for AlgorithmList<'a> {
    fn from(value: &'a [AlgorithmId]) -> Self {
        Self {
            inner: ListInner::BorrowedList(value),
        }
    }
}

impl<'a> From<Vec<AlgorithmId>> for AlgorithmList<'a> {
    fn from(value: Vec<AlgorithmId>) -> Self {
        Self {
            inner: ListInner::Owned(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlgorithmDescriptionList<'a> {
    inner: ListInner<'a, AlgorithmDescription>,
}

impl<'a> AlgorithmDescriptionList<'a> {
    pub fn from_buffer(data: &'a [u8]) -> Result<Self, Error> {
        if !data.len().is_multiple_of(4) {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(Self {
            inner: ListInner::BorrowedData(data),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = AlgorithmDescription> {
        self.inner.iter_from_fn(|v: [u8; 4]| AlgorithmDescription {
            id: u16::from_be_bytes(v.as_chunks().0[0]),
            keysize: u16::from_be_bytes(v.as_chunks().0[1]),
        })
    }

    pub async fn serialize(&self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        self.inner.serialize(writer).await
    }
}

impl<'a> From<&'a [AlgorithmDescription]> for AlgorithmDescriptionList<'a> {
    fn from(value: &'a [AlgorithmDescription]) -> Self {
        Self {
            inner: ListInner::BorrowedList(value),
        }
    }
}

impl<'a> From<Vec<AlgorithmDescription>> for AlgorithmDescriptionList<'a> {
    fn from(value: Vec<AlgorithmDescription>) -> Self {
        Self {
            inner: ListInner::Owned(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NtsRecord<'a> {
    /// Standard NTS records
    EndOfMessage,
    NextProtocol {
        protocol_ids: ProtocolList<'a>,
    },
    Error {
        errorcode: ErrorCode,
    },
    Warning {
        warningcode: WarningCode,
    },
    AeadAlgorithm {
        algorithm_ids: AlgorithmList<'a>,
    },
    NewCookie {
        cookie_data: Cow<'a, [u8]>,
    },
    Server {
        name: Cow<'a, str>,
    },
    Port {
        port: u16,
    },
    Unknown {
        record_type: u16,
        critical: bool,
        data: Cow<'a, [u8]>,
    },

    /// NTS pool draft
    KeepAlive,
    SupportedNextProtocolList {
        supported_protocols: ProtocolList<'a>,
    },
    SupportedAlgorithmList {
        supported_algorithms: AlgorithmDescriptionList<'a>,
    },
    FixedKeyRequest {
        c2s: Cow<'a, [u8]>,
        s2c: Cow<'a, [u8]>,
    },
    NtpServerDeny {
        denied: Cow<'a, str>,
    },

    /// Internal pool NTS records
    Authentication {
        key: Cow<'a, str>,
    },
    UUIDRequest {
        uuid: Cow<'a, str>,
    },
}

impl<'a> NtsRecord<'a> {
    pub async fn parse(
        reader: &mut BufferBorrowingReader<'a, impl AsyncRead + Unpin>,
    ) -> Result<Self, Error> {
        let record_type = reader.read_u16().await?;
        let size = reader.read_u16().await?;

        let critical = (record_type & 0x8000) != 0;
        let record_type = record_type & 0x7FFF;
        let mut body = reader.read_bufref(size.into()).await?;

        match record_type {
            0 => Self::parse_end_of_message(body),
            1 => Self::parse_next_protocol(body),
            2 => Self::parse_error(body).await,
            3 => Self::parse_warning(body).await,
            4 => Self::parse_aead_algorithm(body).await,
            5 => Self::parse_new_cookie(body),
            6 => Self::parse_server(body),
            7 => Self::parse_port(body).await,
            0x4000 => Self::parse_keep_alive(body),
            0x4004 => Self::parse_supported_next_protocol_list(body),
            0x4001 => Self::parse_supported_algorithm_list(body),
            0x4002 => Self::parse_fixed_key_request(body),
            0x4003 => Self::parse_ntp_server_deny(body),
            0x4F00 => Self::parse_authentication(body).await,
            0x4F01 => Self::parse_uuid_request(body).await,
            _ => {
                let mut data = vec![0; size.into()];
                body.read_exact(&mut data).await?;
                Ok(Self::Unknown {
                    record_type,
                    critical,
                    data: data.into(),
                })
            }
        }
    }

    fn parse_end_of_message(_body: &'a [u8]) -> Result<Self, Error> {
        Ok(NtsRecord::EndOfMessage)
    }

    fn parse_next_protocol(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::NextProtocol {
            protocol_ids: ProtocolList::from_buffer(body)?,
        })
    }

    async fn parse_error(mut body: &'a [u8]) -> Result<Self, Error> {
        let errorcode = ErrorCode::parse(&mut body).await?;
        if !body.is_empty() {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Error { errorcode })
        }
    }

    async fn parse_warning(mut body: &'a [u8]) -> Result<Self, Error> {
        let warningcode = WarningCode::parse(&mut body).await?;
        if !body.is_empty() {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Warning { warningcode })
        }
    }

    async fn parse_aead_algorithm(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::AeadAlgorithm {
            algorithm_ids: AlgorithmList::from_buffer(body)?,
        })
    }

    fn parse_new_cookie(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::NewCookie {
            cookie_data: body.into(),
        })
    }

    fn parse_server(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::Server {
            name: str::from_utf8(body)
                .map_err(|_| Error::from(ErrorKind::InvalidData))?
                .into(),
        })
    }

    async fn parse_port(mut body: &'a [u8]) -> Result<Self, Error> {
        let port = body.read_u16().await?;
        if !body.is_empty() {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(Self::Port { port })
        }
    }

    fn parse_keep_alive(_body: &'a [u8]) -> Result<Self, Error> {
        Ok(NtsRecord::KeepAlive)
    }

    fn parse_supported_next_protocol_list(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::SupportedNextProtocolList {
            supported_protocols: ProtocolList::from_buffer(body)?,
        })
    }

    fn parse_supported_algorithm_list(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::SupportedAlgorithmList {
            supported_algorithms: AlgorithmDescriptionList::from_buffer(body)?,
        })
    }

    fn parse_fixed_key_request(body: &'a [u8]) -> Result<Self, Error> {
        if !body.len().is_multiple_of(2) {
            return Err(ErrorKind::InvalidData.into());
        }

        let (c2s, s2c) = body.split_at(body.len() / 2);
        Ok(Self::FixedKeyRequest {
            c2s: c2s.into(),
            s2c: s2c.into(),
        })
    }

    fn parse_ntp_server_deny(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::NtpServerDeny {
            denied: str::from_utf8(body)
                .map_err(|_| Error::from(ErrorKind::InvalidData))?
                .into(),
        })
    }

    async fn parse_authentication(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::Authentication {
            key: str::from_utf8(body)
                .map_err(|_| Error::from(ErrorKind::InvalidData))?
                .into(),
        })
    }

    async fn parse_uuid_request(body: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::UUIDRequest {
            uuid: str::from_utf8(body)
                .map_err(|_| Error::from(ErrorKind::InvalidData))?
                .into(),
        })
    }

    pub async fn serialize(&self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), Error> {
        writer.write_u16(self.record_type()).await?;
        let size: u16 = self
            .body_size()
            .try_into()
            .map_err(|_| ErrorKind::InvalidInput)?;
        writer.write_u16(size).await?;
        match self {
            NtsRecord::EndOfMessage => {}
            NtsRecord::NextProtocol { protocol_ids } => {
                protocol_ids.serialize(&mut writer).await?;
            }
            NtsRecord::Error { errorcode } => errorcode.serialize(writer).await?,
            NtsRecord::Warning { warningcode } => warningcode.serialize(writer).await?,
            NtsRecord::AeadAlgorithm { algorithm_ids } => {
                algorithm_ids.serialize(&mut writer).await?;
            }
            NtsRecord::NewCookie { cookie_data } => writer.write_all(cookie_data).await?,
            NtsRecord::Server { name } => writer.write_all(name.as_bytes()).await?,
            NtsRecord::Port { port } => writer.write_u16(*port).await?,
            NtsRecord::Unknown { data, .. } => writer.write_all(data).await?,
            NtsRecord::KeepAlive => {}
            NtsRecord::SupportedNextProtocolList {
                supported_protocols,
            } => {
                supported_protocols.serialize(&mut writer).await?;
            }
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            } => {
                supported_algorithms.serialize(&mut writer).await?;
            }
            NtsRecord::FixedKeyRequest { c2s, s2c } => {
                writer.write_all(c2s).await?;
                writer.write_all(s2c).await?
            }
            NtsRecord::NtpServerDeny { denied } => writer.write_all(denied.as_bytes()).await?,
            NtsRecord::Authentication { key } => writer.write_all(key.as_bytes()).await?,
            NtsRecord::UUIDRequest { uuid } => writer.write_all(uuid.as_bytes()).await?,
        }
        Ok(())
    }

    fn record_type(&self) -> u16 {
        const CRITICAL_BIT: u16 = 0x8000;
        match self {
            #[allow(clippy::identity_op)]
            NtsRecord::EndOfMessage => 0 | CRITICAL_BIT,
            NtsRecord::NextProtocol { .. } => 1 | CRITICAL_BIT,
            NtsRecord::Error { .. } => 2 | CRITICAL_BIT,
            NtsRecord::Warning { .. } => 3 | CRITICAL_BIT,
            NtsRecord::AeadAlgorithm { .. } => 4 | CRITICAL_BIT,
            NtsRecord::NewCookie { .. } => 5,
            NtsRecord::Server { .. } => 6 | CRITICAL_BIT,
            NtsRecord::Port { .. } => 7 | CRITICAL_BIT,
            NtsRecord::Unknown {
                record_type,
                critical,
                ..
            } => record_type | if *critical { CRITICAL_BIT } else { 0 },
            NtsRecord::KeepAlive => 0x4000,
            NtsRecord::SupportedNextProtocolList { .. } => 0x4004 | CRITICAL_BIT,
            NtsRecord::SupportedAlgorithmList { .. } => 0x4001 | CRITICAL_BIT,
            NtsRecord::FixedKeyRequest { .. } => 0x4002 | CRITICAL_BIT,
            NtsRecord::NtpServerDeny { .. } => 0x4003,
            NtsRecord::Authentication { .. } => 0x4F00,
            NtsRecord::UUIDRequest { .. } => 0x4F01 | CRITICAL_BIT,
        }
    }

    fn body_size(&self) -> usize {
        match self {
            NtsRecord::EndOfMessage => 0,
            NtsRecord::NextProtocol { protocol_ids } => {
                protocol_ids.iter().count() * size_of::<u16>()
            }
            NtsRecord::Error { .. } => size_of::<u16>(),
            NtsRecord::Warning { .. } => size_of::<u16>(),
            NtsRecord::AeadAlgorithm { algorithm_ids } => {
                algorithm_ids.iter().count() * size_of::<u16>()
            }
            NtsRecord::NewCookie { cookie_data } => cookie_data.len(),
            NtsRecord::Server { name } => name.len(),
            NtsRecord::Port { .. } => size_of::<u16>(),
            NtsRecord::Unknown { data, .. } => data.len(),
            NtsRecord::KeepAlive => 0,
            NtsRecord::SupportedNextProtocolList {
                supported_protocols,
            } => supported_protocols.iter().count() * size_of::<u16>(),
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms,
            } => supported_algorithms.iter().count() * 2 * size_of::<u16>(),
            NtsRecord::FixedKeyRequest { c2s, s2c } => c2s.len() + s2c.len(),
            NtsRecord::NtpServerDeny { denied } => denied.len(),
            NtsRecord::Authentication { key } => key.len(),
            NtsRecord::UUIDRequest { uuid } => uuid.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::Error,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use crate::{AlgorithmDescription, ErrorCode, WarningCode};

    use super::NtsRecord;

    fn parse(buf: &mut [u8]) -> Result<NtsRecord<'_>, Error> {
        let Poll::Ready(result) =
            pin!(NtsRecord::parse(&mut buf.into())).poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("Unexpected sleep in future");
        };

        result
    }

    fn serialize(record: NtsRecord, buf: &mut Vec<u8>) {
        assert!(matches!(
            pin!(record.serialize(buf)).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }

    #[test]
    fn test_end_of_message() {
        assert!(matches!(
            parse(&mut [0, 0, 0, 0]),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse(&mut [0x80, 0, 0, 0]),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0x80, 0, 0, 0, 0, 0].as_mut()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0, 0, 0, 3, 1, 2, 3].as_mut()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(matches!(
            parse([0x80, 0, 0, 3, 1, 2, 3].as_mut()),
            Ok(NtsRecord::EndOfMessage)
        ));
        assert!(parse([0x80, 0, 0, 3].as_mut()).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::EndOfMessage, &mut buf);
        assert_eq!(buf, [0x80, 0, 0, 0]);
    }

    #[test]
    fn test_next_protocol() {
        let rec = &mut [0, 1, 0, 2, 0, 0];
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(rec) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids.iter().collect::<Vec<_>>(), [0].as_slice());

        let rec = &mut [0, 1, 0, 2, 0, 0, 0, 0];
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(rec) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids.iter().collect::<Vec<_>>(), [0].as_slice());

        let rec = &mut [0x80, 1, 0, 2, 0, 0];
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(rec) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids.iter().collect::<Vec<_>>(), [0].as_slice());

        let rec = &mut [0x80, 1, 0, 0];
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(rec) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(
            protocol_ids.iter().collect::<Vec<_>>(),
            [].as_slice() as &[u16]
        );

        let rec = &mut [0x80, 1, 0, 4, 0, 0, 0, 4];
        let Ok(NtsRecord::NextProtocol { protocol_ids }) = parse(rec) else {
            panic!("Expected successfull parse");
        };
        assert_eq!(protocol_ids.iter().collect::<Vec<_>>(), [0, 4].as_slice());

        assert!(parse([0x80, 1, 0, 1, 0].as_mut()).is_err());
        assert!(parse([0x80, 1, 0, 2, 0].as_mut()).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NextProtocol {
                protocol_ids: [0, 1].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 1, 0, 4, 0, 0, 0, 1]);
    }

    #[test]
    fn test_error() {
        assert!(matches!(
            parse(&mut [0x80, 2, 0, 2, 0, 0]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord
            })
        ));
        assert!(matches!(
            parse(&mut [0, 2, 0, 2, 0, 0]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord
            })
        ));
        assert!(matches!(
            parse(&mut [0x80, 2, 0, 2, 0, 1]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::BadRequest
            })
        ));
        assert!(matches!(
            parse(&mut [0x80, 2, 0, 2, 0, 2]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::InternalServerError
            })
        ));
        assert!(matches!(
            parse(&mut [0x80, 2, 0, 2, 0, 3]),
            Ok(NtsRecord::Error {
                errorcode: ErrorCode::Unknown(3)
            })
        ));
        assert!(parse(&mut [0x80, 2, 0, 4, 0, 3, 0, 0]).is_err());
        assert!(parse(&mut [0x80, 2, 0, 1, 0]).is_err());
        assert!(parse(&mut [0x80, 2, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::UnrecognizedCriticalRecord,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 0]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::BadRequest,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 1]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::InternalServerError,
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 2]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Error {
                errorcode: ErrorCode::Unknown(3),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 2, 0, 2, 0, 3]);
    }

    #[test]
    fn test_warning() {
        assert!(matches!(
            parse(&mut [0x80, 3, 0, 2, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(matches!(
            parse(&mut [0, 3, 0, 2, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(matches!(
            parse(&mut [0x80, 3, 0, 2, 0, 0, 0, 0]),
            Ok(NtsRecord::Warning {
                warningcode: WarningCode::Unknown(0)
            })
        ));
        assert!(parse(&mut [0x80, 3, 0, 2, 0]).is_err());
        assert!(parse(&mut [0x80, 3, 0, 1, 0]).is_err());
        assert!(parse(&mut [0x80, 3, 0, 3, 0, 0, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Warning {
                warningcode: WarningCode::Unknown(3),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 3, 0, 2, 0, 3]);
    }

    #[test]
    fn test_aead() {
        let rec = &mut [0x80, 4, 0, 2, 0, 0];
        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(algorithm_ids.iter().collect::<Vec<_>>(), [0].as_slice());

        let rec = &mut [0, 4, 0, 4, 0, 2, 0, 3];
        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(algorithm_ids.iter().collect::<Vec<_>>(), [2, 3].as_slice());

        let rec = &mut [0, 4, 0, 2, 0, 0, 1, 2];
        let Ok(NtsRecord::AeadAlgorithm { algorithm_ids }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(algorithm_ids.iter().collect::<Vec<_>>(), [0].as_slice());

        assert!(parse(&mut [0, 4, 0, 2, 0]).is_err());
        assert!(parse(&mut [0, 4, 0, 3, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::AeadAlgorithm {
                algorithm_ids: [2, 3].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 4, 0, 4, 0, 2, 0, 3]);
    }

    #[test]
    fn test_new_cookie() {
        let rec = &mut [0x80, 5, 0, 2, 16, 17];
        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [16, 17].as_slice());

        let rec = &mut [0, 5, 0, 0];
        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [].as_slice() as &[u8]);

        let rec = &mut [0, 5, 0, 0, 16, 17];
        let Ok(NtsRecord::NewCookie { cookie_data }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(cookie_data, [].as_slice() as &[u8]);

        assert!(parse(&mut [0x80, 5, 0, 3, 1, 2]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NewCookie {
                cookie_data: [1, 2, 3].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0, 5, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_server() {
        let rec = &mut [0x80, 6, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let Ok(NtsRecord::Server { name }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(name, "hello");

        let rec = &mut [0x80, 6, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'];
        let Ok(NtsRecord::Server { name }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(name, "hello");

        let rec = &mut [0x80, 6, 0, 5, b'h', b'e', b'l'];
        assert!(parse(rec).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::Server { name: "hi".into() }, &mut buf);
        assert_eq!(buf, &[0x80, 6, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_port() {
        assert!(matches!(
            parse(&mut [0x80, 7, 0, 2, 0, 123]),
            Ok(NtsRecord::Port { port: 123 })
        ));
        assert!(matches!(
            parse(&mut [0, 7, 0, 2, 0, 123, 5, 6, 7]),
            Ok(NtsRecord::Port { port: 123 })
        ));
        assert!(parse(&mut [0, 7, 0, 3, 0, 123, 5]).is_err());
        assert!(parse(&mut [0, 7, 0, 1, 0, 123]).is_err());
        assert!(parse(&mut [0, 7, 0, 2, 0]).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::Port { port: 123 }, &mut buf);
        assert_eq!(buf, [0x80, 7, 0, 2, 0, 123]);
    }

    #[test]
    fn test_keep_alive() {
        assert!(matches!(
            parse(&mut [0x40, 0, 0, 0]),
            Ok(NtsRecord::KeepAlive)
        ));
        assert!(matches!(
            parse(&mut [0xC0, 0, 0, 2, 0, 3]),
            Ok(NtsRecord::KeepAlive)
        ));
        assert!(matches!(
            parse(&mut [0x40, 0, 0, 0, 0, 3]),
            Ok(NtsRecord::KeepAlive)
        ));
        assert!(parse(&mut [0x40, 0, 0, 2]).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::KeepAlive, &mut buf);
        assert_eq!(buf, [0x40, 0, 0, 0]);
    }

    #[test]
    fn test_supported_next_protocol_list() {
        let rec = &mut [0xC0, 4, 0, 0];
        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_protocols.iter().collect::<Vec<_>>(),
            [].as_slice() as &[u16]
        );

        let rec = &mut [0xC0, 4, 0, 4, 0, 0, 0, 1];
        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_protocols.iter().collect::<Vec<_>>(),
            [0, 1].as_slice()
        );

        let rec = &mut [0x40, 4, 0, 4, 0, 0, 0, 1, 2, 3, 4, 5];
        let Ok(NtsRecord::SupportedNextProtocolList {
            supported_protocols,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_protocols.iter().collect::<Vec<_>>(),
            [0, 1].as_slice()
        );

        assert!(parse(&mut [0xC0, 4, 0, 4, 0, 0]).is_err());
        assert!(parse(&mut [0xC0, 4, 0, 3, 0, 0, 1]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedNextProtocolList {
                supported_protocols: [1, 2].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xC0, 4, 0, 4, 0, 1, 0, 2]);

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedNextProtocolList {
                supported_protocols: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xC0, 4, 0, 0]);
    }

    #[test]
    fn test_supported_algorithm_list() {
        let rec = &mut [0xC0, 1, 0, 0];
        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_algorithms.iter().collect::<Vec<_>>(),
            [].as_slice()
        );

        let rec = &mut [0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32];
        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_algorithms.iter().collect::<Vec<_>>(),
            [
                AlgorithmDescription { id: 0, keysize: 16 },
                AlgorithmDescription { id: 1, keysize: 32 }
            ]
            .as_slice()
        );

        let rec = &mut [0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32];
        let Ok(NtsRecord::SupportedAlgorithmList {
            supported_algorithms,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(
            supported_algorithms.iter().collect::<Vec<_>>(),
            [
                AlgorithmDescription { id: 0, keysize: 16 },
                AlgorithmDescription { id: 1, keysize: 32 }
            ]
            .as_slice()
        );

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 1, 0, 0]);

        let mut buf = vec![];
        serialize(
            NtsRecord::SupportedAlgorithmList {
                supported_algorithms: [AlgorithmDescription { id: 0, keysize: 32 }]
                    .as_slice()
                    .into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 1, 0, 4, 0, 0, 0, 32]);
    }

    #[test]
    fn test_fixed_key_request() {
        let rec = &mut [0xC0, 2, 0, 0];
        let Ok(NtsRecord::FixedKeyRequest { c2s, s2c }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(c2s, [].as_slice() as &[u8]);
        assert_eq!(s2c, [].as_slice() as &[u8]);

        let rec = &mut [0x40, 2, 0, 4, 1, 2, 3, 4];
        let Ok(NtsRecord::FixedKeyRequest { c2s, s2c }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(c2s, [1, 2].as_slice());
        assert_eq!(s2c, [3, 4].as_slice());

        assert!(parse(&mut [0xC0, 2, 0, 3, 1, 2, 3]).is_err());
        assert!(parse(&mut [0xC0, 2, 0, 4, 1, 2, 3]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::FixedKeyRequest {
                c2s: [5, 6].as_slice().into(),
                s2c: [7, 8].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0xc0, 2, 0, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_server_deny() {
        let rec = &mut [0x40, 3, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let Ok(NtsRecord::NtpServerDeny { denied }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(denied, "hello");

        let rec = &mut [0xC0, 3, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'];
        let Ok(NtsRecord::NtpServerDeny { denied }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(denied, "hello");

        assert!(parse(&mut [0x40, 3, 0, 5, b'h', b'e', b'l']).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::NtpServerDeny {
                denied: "hi".into(),
            },
            &mut buf,
        );
        assert_eq!(buf, &[0x40, 3, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_authentication() {
        let rec = &mut [0x4F, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let Ok(NtsRecord::Authentication { key }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(key, "hello");

        let rec = &mut [0xCF, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'];
        let Ok(NtsRecord::Authentication { key }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(key, "hello");

        assert!(parse(&mut [0x4F, 0, 0, 5, b'h', b'e', b'l']).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::Authentication { key: "hi".into() }, &mut buf);
        assert_eq!(buf, &[0x4F, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_uuid_request() {
        let rec = &mut [0x4F, 1, 0, 5, b'h', b'e', b'l', b'l', b'o'];
        let Ok(NtsRecord::UUIDRequest { uuid }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(uuid, "hello");

        let rec = &mut [0xCF, 1, 0, 5, b'h', b'e', b'l', b'l', b'o', b' ', b'w'];
        let Ok(NtsRecord::UUIDRequest { uuid }) = parse(rec) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(uuid, "hello");

        assert!(parse(&mut [0xCF, 1, 0, 5, b'h', b'e', b'l']).is_err());

        let mut buf = vec![];
        serialize(NtsRecord::UUIDRequest { uuid: "hi".into() }, &mut buf);
        assert_eq!(buf, &[0xCF, 1, 0, 2, b'h', b'i']);
    }

    #[test]
    fn test_unknown() {
        let rec = &mut [0, 20, 0, 3, 1, 2, 3];
        let Ok(NtsRecord::Unknown {
            record_type,
            critical,
            data,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(record_type, 20);
        assert!(!critical);
        assert_eq!(data, [1, 2, 3].as_slice());

        let rec = &mut [0x80, 21, 0, 2, 5, 6, 7, 8];
        let Ok(NtsRecord::Unknown {
            record_type,
            critical,
            data,
        }) = parse(rec)
        else {
            panic!("Expected succesful parse");
        };
        assert_eq!(record_type, 21);
        assert!(critical);
        assert_eq!(data, [5, 6].as_slice());

        assert!(parse(&mut [0x80, 23, 0, 5, 1, 2]).is_err());

        let mut buf = vec![];
        serialize(
            NtsRecord::Unknown {
                record_type: 50,
                critical: false,
                data: [9, 10].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0, 50, 0, 2, 9, 10]);

        let mut buf = vec![];
        serialize(
            NtsRecord::Unknown {
                record_type: 51,
                critical: true,
                data: [].as_slice().into(),
            },
            &mut buf,
        );
        assert_eq!(buf, [0x80, 51, 0, 0]);
    }
}
