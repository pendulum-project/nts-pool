use std::borrow::Cow;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::nts::DEFAULT_NUMBER_OF_COOKIES;

use super::record::NtsRecord;
use super::{AeadAlgorithm, NextProtocol, NtsError, WarningCode};

// Defense-in-depth against oversized requests/responses
const MAX_MESSAGE_SIZE: u64 = 4096;

pub enum Request<'a> {
    KeyExchange {
        algorithms: Cow<'a, [AeadAlgorithm]>,
        #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
        protocols: Cow<'a, [NextProtocol]>,
    },
}

impl Request<'_> {
    #[cfg(test)]
    pub async fn parse(reader: impl AsyncRead + Unpin) -> Result<Self, NtsError> {
        let mut reader = reader.take(MAX_MESSAGE_SIZE);

        let mut protocols = None;
        let mut algorithms = None;

        loop {
            let record = NtsRecord::parse(&mut reader).await?;

            match record {
                NtsRecord::EndOfMessage => break,
                NtsRecord::NextProtocol { protocol_ids } => {
                    if protocols.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    protocols = Some(protocol_ids);
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithms.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    algorithms = Some(algorithm_ids);
                }
                // Unknown critical
                NtsRecord::Unknown { critical: true, .. } => {
                    return Err(NtsError::UnrecognizedCriticalRecord);
                }
                // Ignored
                NtsRecord::Unknown { .. } | NtsRecord::Server { .. } | NtsRecord::Port { .. } => {}
                // not allowed
                NtsRecord::Error { .. }
                | NtsRecord::Warning { .. }
                | NtsRecord::NewCookie { .. } => return Err(NtsError::Invalid),
            }
        }

        if let (Some(protocols), Some(algorithms)) = (protocols, algorithms) {
            Ok(Request::KeyExchange {
                algorithms,
                protocols,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }

    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        match self {
            Request::KeyExchange {
                algorithms,
                protocols,
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
                NtsRecord::EndOfMessage.serialize(&mut writer).await?;
            }
        }

        Ok(())
    }
}

pub struct KeyExchangeResponse<'a> {
    #[cfg_attr(feature = "__internal-fuzz", allow(private_interfaces))]
    pub protocol: NextProtocol,
    pub algorithm: AeadAlgorithm,
    pub cookies: Cow<'a, [Cow<'a, [u8]>]>,
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
                        None => return Err(NtsError::NoOverlappingProtocol),
                        Some((&id, [])) => protocol = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::AeadAlgorithm { algorithm_ids } => {
                    if algorithm.is_some() {
                        return Err(NtsError::Invalid);
                    }

                    match algorithm_ids.split_first() {
                        None => return Err(NtsError::NoOverlappingAlgorithm),
                        Some((&id, [])) => algorithm = Some(id),
                        _ => return Err(NtsError::Invalid),
                    }
                }
                NtsRecord::NewCookie { cookie_data } => {
                    if cookies.len() < DEFAULT_NUMBER_OF_COOKIES {
                        cookies.push(cookie_data)
                    }
                }
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
                NtsRecord::Unknown { .. } => {}
            }
        }

        if let (Some(protocol), Some(algorithm)) = (protocol, algorithm) {
            Ok(KeyExchangeResponse {
                protocol,
                algorithm,
                cookies: cookies.into(),
                server,
                port,
            })
        } else {
            Err(NtsError::Invalid)
        }
    }

    #[cfg(test)]
    pub async fn serialize(
        self,
        mut writer: impl AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        NtsRecord::NextProtocol {
            protocol_ids: [self.protocol].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        NtsRecord::AeadAlgorithm {
            algorithm_ids: [self.algorithm].as_slice().into(),
        }
        .serialize(&mut writer)
        .await?;
        for cookie_data in self.cookies.iter() {
            NtsRecord::NewCookie {
                cookie_data: Cow::Borrowed(cookie_data),
            }
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

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        io::Error,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use crate::nts::ErrorCode;

    use super::*;

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
    fn test_request_basic() {
        let Ok(request) = pwrap(
            Request::parse,
            &[0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 1, 0, 4, 0x80, 1, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac512].as_slice());
                assert_eq!(
                    protocols,
                    [NextProtocol::DraftNTPv5, NextProtocol::NTPv4].as_slice()
                );
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }
    }

    #[test]
    fn test_request_basic_reject_incomplete() {
        assert!(pwrap(Request::parse, &[0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0]).is_err());
        assert!(pwrap(Request::parse, &[0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0]).is_err());
        assert!(pwrap(Request::parse, &[0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0]).is_err());
    }

    #[test]
    fn test_request_basic_reject_multiple() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 4, 0, 2, 0, 17, 0x80, 1, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 1, 0, 2, 0x80, 1, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_reject_problematic() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0xC0, 1, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0xC0, 4, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 2, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 3, 0, 2, 0, 0, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );

        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0, 5, 0, 4, 1, 2, 3, 4, 0x80, 0, 0,
                    0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_reject_unknown_critical() {
        assert!(
            pwrap(
                Request::parse,
                &[
                    0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 50, 0, 2, 0, 1, 0x80, 0, 0, 0
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn test_request_basic_ignore() {
        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0, 50, 0, 2, 1, 2, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x80, 7, 0, 2, 0, 124, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }

        let Ok(request) = pwrap(
            Request::parse,
            &[
                0x80, 4, 0, 2, 0, 15, 0x80, 1, 0, 2, 0, 0, 0x40, 3, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected parse");
        };
        match request {
            Request::KeyExchange {
                algorithms,
                protocols,
                ..
            } => {
                assert_eq!(algorithms, [AeadAlgorithm::AeadAesSivCmac256].as_slice());
                assert_eq!(protocols, [NextProtocol::NTPv4].as_slice());
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Unexpected misparse of message"),
        }
    }

    #[test]
    fn test_request_basic_serialize() {
        let mut buf = vec![];
        assert!(matches!(
            swrap(
                Request::serialize,
                Request::KeyExchange {
                    algorithms: [
                        AeadAlgorithm::AeadAesSivCmac512,
                        AeadAlgorithm::AeadAesSivCmac256
                    ]
                    .as_slice()
                    .into(),
                    protocols: [NextProtocol::NTPv4].as_slice().into(),
                },
                &mut buf
            ),
            Ok(())
        ));
        assert_eq!(
            buf,
            [
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 4, 0, 17, 0, 15, 0x80, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_key_exchange_response_parse_basic() {
        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 0, 0, 0],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3,
                4, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(
            response.cookies,
            [[1u8, 2].as_slice().into(), [3u8, 4].as_slice().into()].as_slice()
                as &[Cow<'static, [u8]>]
        );
        assert_eq!(response.port, None);
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 6, 0, 2, b'h', b'i', 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, None);
        assert_eq!(response.server, Some("hi".into()));

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
        assert_eq!(response.port, Some(5));
        assert_eq!(response.server, None);

        let Ok(response) = pwrap(
            KeyExchangeResponse::parse,
            &[
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 17, 0x80, 5, 0, 2, 1, 2, 0x80, 5, 0, 2, 3,
                4, 0x80, 6, 0, 2, b'h', b'i', 0x80, 7, 0, 2, 0, 5, 0x80, 0, 0, 0,
            ],
        ) else {
            panic!("Expected succesful parse");
        };
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::AeadAesSivCmac512);
        assert_eq!(
            response.cookies,
            [[1u8, 2].as_slice().into(), [3u8, 4].as_slice().into()].as_slice()
                as &[Cow<'static, [u8]>]
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
        assert_eq!(response.protocol, NextProtocol::NTPv4);
        assert_eq!(response.algorithm, AeadAlgorithm::Unknown(4));
        assert_eq!(response.cookies, [].as_slice() as &[Cow<'static, [u8]>]);
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
    fn test_key_exchange_response_no_overlap() {
        assert!(matches!(
            pwrap(KeyExchangeResponse::parse, &[0x80, 1, 0, 0, 0x80, 0, 0, 0]),
            Err(NtsError::NoOverlappingProtocol)
        ));
        assert!(matches!(
            pwrap(
                KeyExchangeResponse::parse,
                &[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 0, 0x80, 0, 0, 0]
            ),
            Err(NtsError::NoOverlappingAlgorithm)
        ));
    }

    #[test]
    fn test_key_exchange_response_serialize() {
        let mut buf = vec![];
        assert!(
            swrap(
                KeyExchangeResponse::serialize,
                KeyExchangeResponse {
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
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
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()]
                        .as_slice()
                        .into(),
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
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
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
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [].as_slice().into(),
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
                    protocol: NextProtocol::NTPv4,
                    algorithm: AeadAlgorithm::Unknown(4),
                    cookies: [[1, 2, 3].as_slice().into(), [4, 5].as_slice().into()]
                        .as_slice()
                        .into(),
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
}
