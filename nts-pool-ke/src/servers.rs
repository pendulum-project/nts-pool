use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{
    error::PoolError,
    nts::{
        AlgorithmDescription, AlgorithmId, ProtocolId, ServerInformationRequest,
        ServerInformationResponse,
    },
};

mod geo;
pub use geo::GeographicServerManager;
mod roundrobin;
pub use roundrobin::RoundRobinServerManager;

pub trait ServerManager: Sync + Send {
    type Server<'a>: Server + 'a
    where
        Self: 'a;

    /// Select a server for a client at the given address, taking into acount
    /// any denied servers.
    ///
    /// Denied servers need not be respected if no other options are available
    fn assign_server(&self, address: SocketAddr, denied_servers: &[String]) -> Self::Server<'_>;
}

pub trait Server: Sync + Send {
    type Connection<'a>: ServerConnection + 'a
    where
        Self: 'a;

    /// Name of the server, to be passed in the server record if the server
    /// itself doesn't provide one.
    fn name(&self) -> &str;

    /// Fetch which protocols and algorithms a server supports.
    fn support(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                HashSet<ProtocolId>,
                HashMap<AlgorithmId, AlgorithmDescription>,
            ),
            PoolError,
        >,
    > + Send;

    /// Open a connection to the server.
    fn connect<'a>(
        &'a self,
    ) -> impl Future<Output = Result<Self::Connection<'a>, PoolError>> + Send;
}

pub trait ServerConnection: AsyncRead + AsyncWrite + Unpin + Send {
    /// Return the connection to be reused later.
    #[allow(unused)]
    fn reuse(self) -> impl Future<Output = ()> + Send;
}

impl ServerConnection for TlsStream<TcpStream> {
    async fn reuse(mut self) {
        // no reuse, just shutdown the connection
        let _ = self.shutdown().await;
    }
}

async fn fetch_support_data(
    mut connection: impl ServerConnection,
    allowed_protocols: &HashSet<ProtocolId>,
    timeout: Duration,
) -> Result<
    (
        HashSet<ProtocolId>,
        HashMap<AlgorithmId, AlgorithmDescription>,
    ),
    PoolError,
> {
    match tokio::time::timeout(timeout, async {
        ServerInformationRequest.serialize(&mut connection).await?;
        let support_info = ServerInformationResponse::parse(&mut connection).await?;
        connection.shutdown().await?;
        let supported_protocols: HashSet<ProtocolId> = support_info
            .supported_protocols
            .into_iter()
            .filter(|v| allowed_protocols.contains(v))
            .collect();
        let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
            .supported_algorithms
            .into_iter()
            .map(|v| (v.id, v))
            .collect();
        Ok((supported_protocols, supported_algorithms))
    })
    .await
    {
        Ok(v) => v,
        Err(_) => Err(PoolError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct TestConnection<'a> {
        written: &'a Mutex<Vec<u8>>,
        read_data: &'a [u8],
    }

    impl AsyncRead for TestConnection<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let to_write = self.read_data.len().min(buf.remaining());

            let (now, fut) = self.read_data.split_at(to_write);
            self.read_data = fut;
            buf.put_slice(now);

            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestConnection<'_> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            let mut written = self.written.lock().unwrap();
            written.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            //noop
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            //noop
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl ServerConnection for TestConnection<'_> {
        async fn reuse(self) { /* noop */
        }
    }

    #[tokio::test]
    async fn test_query_supporting_servers() {
        let mut received = Mutex::new(vec![]);
        let connection = TestConnection {
            written: &received,
            read_data: &[
                0xC0, 4, 0, 6, 0, 0, 0, 1, 0, 2, 0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32, 0x80, 0,
                0, 0,
            ],
        };

        let (protocols, algorithms) =
            fetch_support_data(connection, &HashSet::from([0, 1]), Duration::from_secs(1))
                .await
                .unwrap();
        assert!(protocols.contains(&0));
        assert!(protocols.contains(&1));
        assert_eq!(protocols.len(), 2);

        assert_eq!(
            algorithms.get(&0),
            Some(&AlgorithmDescription { id: 0, keysize: 16 })
        );
        assert_eq!(
            algorithms.get(&1),
            Some(&AlgorithmDescription { id: 1, keysize: 32 })
        );

        let req = ServerInformationResponse::parse(received.get_mut().unwrap().as_slice())
            .await
            .unwrap();
        assert_eq!(req.supported_algorithms.len(), 0);
        assert_eq!(req.supported_protocols.len(), 0);
    }
}
