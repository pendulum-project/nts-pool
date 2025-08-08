use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::PoolError;

const HAPROXY_V2_SIGNATURE: [u8; 12] = *b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

async fn skip_bytes(
    mut connection: impl AsyncRead + Unpin,
    mut count: usize,
) -> Result<(), std::io::Error> {
    const BUF_LEN: usize = 256;
    let mut buf = [0; BUF_LEN];

    while count > 0 {
        let read = connection.read(&mut buf[..count.min(BUF_LEN)]).await?;
        count -= read;
    }

    Ok(())
}

/// parse and process an haproxy header
pub async fn parse_haproxy_header(
    mut connection: impl AsyncRead + Unpin,
) -> Result<Option<SocketAddr>, PoolError> {
    let mut sig = [0; 12];
    connection.read_exact(&mut sig).await?;
    if sig != HAPROXY_V2_SIGNATURE {
        return Err(PoolError::NoProxy);
    }
    let commandversion = connection.read_u8().await?;
    let family = connection.read_u8().await?;
    let len = connection.read_u16().await?;
    match commandversion {
        0x20 => {
            skip_bytes(connection, len.into()).await?;
            Ok(None)
        }
        0x21 => match family {
            0x11 if len >= 12 => {
                let mut source_addr = [0; 4];
                connection.read_exact(&mut source_addr).await?;
                skip_bytes(&mut connection, 4).await?;
                let source_port = connection.read_u16().await?;
                skip_bytes(&mut connection, usize::from(len) - (2 * 4 + 2)).await?;

                Ok(Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        source_addr[0],
                        source_addr[1],
                        source_addr[2],
                        source_addr[3],
                    )),
                    source_port,
                )))
            }
            0x21 if len >= 36 => {
                let mut source_addr = [0; 16];
                connection.read_exact(&mut source_addr).await?;
                skip_bytes(&mut connection, 16).await?;
                let source_port = connection.read_u16().await?;
                skip_bytes(&mut connection, usize::from(len) - (2 * 16 + 2)).await?;

                Ok(Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(source_addr)),
                    source_port,
                )))
            }
            _ => Err(PoolError::NoProxy),
        },
        _ => Err(PoolError::NoProxy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_local() {
        let mut reader =
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x20\x00\x00\x00hello".as_slice();
        assert!(matches!(parse_haproxy_header(&mut reader).await, Ok(None)));
        assert_eq!(reader, b"hello");

        let mut reader =
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x20\x15\x00\x02hello".as_slice();
        assert!(matches!(parse_haproxy_header(&mut reader).await, Ok(None)));
        assert_eq!(reader, b"llo");
    }

    #[tokio::test]
    async fn test_proxy_ipv4() {
        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert_eq!(
            parse_haproxy_header(&mut reader).await.unwrap().unwrap(),
            "1.2.3.4:10".parse().unwrap()
        );
        assert_eq!(reader, b"hello");

        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0F\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert_eq!(
            parse_haproxy_header(&mut reader).await.unwrap().unwrap(),
            "1.2.3.4:10".parse().unwrap()
        );
        assert_eq!(reader, b"lo");

        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0b\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn test_proxy_ipv6() {
        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x21\x00\x24\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x04hello".as_slice();
        assert_eq!(
            parse_haproxy_header(&mut reader).await.unwrap().unwrap(),
            "[::1]:3".parse().unwrap()
        );
        assert_eq!(reader, b"hello");

        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x21\x00\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x04hello".as_slice();
        assert_eq!(
            parse_haproxy_header(&mut reader).await.unwrap().unwrap(),
            "[::1]:3".parse().unwrap()
        );
        assert_eq!(reader, b"ello");

        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x21\x00\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x04hello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn test_proxy_invalid() {
        let mut reader = b"\x0E\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0F\x21\x11\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x12\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
        let mut reader = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x22\x11\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x0a\x00\x0bhello".as_slice();
        assert!(parse_haproxy_header(&mut reader).await.is_err());
    }
}
