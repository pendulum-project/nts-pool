use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use notify::{RecursiveMode, Watcher};
use pool_nts::{
    AlgorithmDescription, AlgorithmId, BufferBorrowingReader, MAX_MESSAGE_SIZE, ProtocolId,
    ServerInformationRequest, ServerInformationResponse,
};
use rustls::{pki_types::pem::PemObject, version::TLS13};
use rustls_platform_verifier::Verifier;
use sha3::Digest;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{config::BackendConfig, error::PoolError, util::load_certificates};

mod geo;
pub use geo::GeographicServerManager;
mod roundrobin;
pub use roundrobin::RoundRobinServerManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConnectionType {
    IpV4,
    IpV6,
    #[default]
    Either,
}

impl From<SocketAddr> for ConnectionType {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(_) => ConnectionType::IpV4,
            SocketAddr::V6(_) => ConnectionType::IpV6,
        }
    }
}

impl ConnectionType {
    #[must_use]
    fn is_of_type(&self, a: SocketAddr) -> bool {
        match (self, a) {
            (ConnectionType::IpV4, SocketAddr::V4(_))
            | (ConnectionType::IpV6, SocketAddr::V6(_))
            | (ConnectionType::Either, SocketAddr::V4(_))
            | (ConnectionType::Either, SocketAddr::V6(_)) => true,
            (ConnectionType::IpV4, SocketAddr::V6(_))
            | (ConnectionType::IpV6, SocketAddr::V4(_)) => false,
        }
    }
}

pub trait ServerManager: Sync + Send {
    type Server<'a>: Server + 'a
    where
        Self: 'a;

    /// Select a server for a client at the given address, taking into acount
    /// any denied servers.
    ///
    /// Denied servers need not be respected if no other options are available
    fn assign_server(
        &self,
        address: SocketAddr,
        denied_servers: &[Cow<'_, str>],
    ) -> Option<Self::Server<'_>>;

    /// Select a server with given UUID. This is used for making KE connections
    /// in the monitoring.
    fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>>;
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
        connection_type: ConnectionType,
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
        connection_type: ConnectionType,
    ) -> impl Future<Output = Result<Self::Connection<'a>, PoolError>> + Send;

    fn auth_key(&self) -> String;
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

async fn resolve_with_type<T: tokio::net::ToSocketAddrs>(
    addr: T,
    connection_type: ConnectionType,
) -> std::io::Result<SocketAddr> {
    let resolved = tokio::net::lookup_host(addr).await?;

    for candidate in resolved {
        if connection_type.is_of_type(candidate) {
            return Ok(candidate);
        }
    }

    Err(std::io::ErrorKind::NotFound.into())
}

#[expect(deprecated)]
fn calculate_auth_key(
    base_shared_secret: &[u8],
    server_uuid: &[u8],
    server_randomizer: &[u8],
) -> String {
    struct HashOutput<'a>(&'a [u8]);
    impl<'a> std::fmt::Display for HashOutput<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for el in self.0 {
                write!(f, "{:02x}", el)?;
            }
            Ok(())
        }
    }

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(base_shared_secret);
    hasher.update(server_uuid);
    hasher.update(server_randomizer);
    let hash = hasher.finalize();
    format!("{}", HashOutput(hash.as_slice()))
}

async fn fetch_support_data(
    mut connection: impl ServerConnection,
    key: String,
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
        ServerInformationRequest {
            key: key.into(),
            keep_alive: true,
        }
        .serialize(&mut connection)
        .await?;
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let support_info = ServerInformationResponse::parse(&mut BufferBorrowingReader::new(
            &mut connection,
            &mut buf,
        ))
        .await?;
        if support_info.keep_alive {
            connection.reuse().await;
        } else {
            connection.shutdown().await?;
        }
        let supported_protocols: HashSet<ProtocolId> = support_info
            .supported_protocols
            .iter()
            .filter(|v| allowed_protocols.contains(v))
            .collect();
        let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
            .supported_algorithms
            .iter()
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

async fn tls_config_updater(
    upstream_tls: Arc<RwLock<TlsConnector>>,
    config: Arc<BackendConfig>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let (change_sender, mut change_receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
    // Use a poll watcher here as INotify can be unreliable in many ways and I don't want to deal with that.
    let mut watcher = notify::poll::PollWatcher::new(
        move |event: notify::Result<notify::Event>| {
            if event.is_ok() {
                let _ = change_sender.send(());
            }
        },
        notify::Config::default()
            .with_poll_interval(std::time::Duration::from_secs(60))
            .with_compare_contents(true),
    )
    .map_err(std::io::Error::other)?;

    watcher
        .watch(&config.certificate_chain, RecursiveMode::NonRecursive)
        .map_err(std::io::Error::other)?;
    watcher
        .watch(&config.private_key, RecursiveMode::NonRecursive)
        .map_err(std::io::Error::other)?;
    config
        .upstream_cas
        .as_ref()
        .map(|upstream_cas| {
            watcher
                .watch(upstream_cas, RecursiveMode::NonRecursive)
                .map_err(std::io::Error::other)
        })
        .transpose()?;

    Ok(tokio::task::spawn(async move {
        // keep the watcher alive
        let _w = watcher;
        loop {
            change_receiver.recv().await;
            match load_upstream_tls(&config).await {
                Ok(tls) => {
                    *upstream_tls.write().unwrap() = tls;
                }
                Err(e) => {
                    tracing::error!("Could not reload tls configuration: {}", e);
                }
            }
        }
    }))
}

async fn load_upstream_tls(config: &BackendConfig) -> std::io::Result<TlsConnector> {
    // Unfortunately, we need to clone here as there is no way to use references with tokio's spawn_blocking
    let upstream_cas = config.upstream_cas.clone();
    let certificate_chain = config.certificate_chain.clone();
    let private_key = config.private_key.clone();

    tokio::task::spawn_blocking(|| {
        let upstream_cas = upstream_cas
            .map(|path| load_certificates(path).map_err(std::io::Error::other))
            .transpose()?;

        let certificate_chain =
            load_certificates(certificate_chain).map_err(std::io::Error::other)?;

        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(private_key)
            .map_err(std::io::Error::other)?;

        let upstream_config_builder =
            rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13]);
        let provider = upstream_config_builder.crypto_provider().clone();
        let verifier = match upstream_cas {
            Some(upstream_cas) => {
                Verifier::new_with_extra_roots(upstream_cas.iter().cloned(), provider)
                    .map_err(std::io::Error::other)?
            }
            None => Verifier::new(provider).map_err(std::io::Error::other)?,
        };

        let mut upstream_config = upstream_config_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(certificate_chain, private_key)
            .map_err(std::io::Error::other)?;
        upstream_config.alpn_protocols = vec![b"ntske/1".to_vec()];
        let upstream_tls = TlsConnector::from(Arc::new(upstream_config));

        Ok(upstream_tls)
    })
    .await
    .unwrap()
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, atomic::AtomicUsize};

    use super::*;

    struct TestConnection<'a> {
        written: &'a Mutex<Vec<u8>>,
        reuse_call_count: &'a AtomicUsize,
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
        async fn reuse(self) {
            self.reuse_call_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn test_query_supporting_servers() {
        let mut received = Mutex::new(vec![]);
        let reuse_count = AtomicUsize::new(0);
        let connection = TestConnection {
            written: &received,
            reuse_call_count: &reuse_count,
            read_data: &[
                0xC0, 4, 0, 6, 0, 0, 0, 1, 0, 2, 0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32, 0x40, 0,
                0, 0, 0x80, 0, 0, 0,
            ],
        };

        let (protocols, algorithms) = fetch_support_data(
            connection,
            "abcd".into(),
            &HashSet::from([0, 1]),
            Duration::from_secs(1),
        )
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

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let req = ServerInformationResponse::parse(&mut BufferBorrowingReader::new(
            received.get_mut().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();
        assert!(req.supported_algorithms.iter().next().is_none());
        assert!(req.supported_protocols.iter().next().is_none());
        assert_eq!(reuse_count.into_inner(), 1);
    }

    #[tokio::test]
    async fn test_query_supporting_servers_keepalive_disallowed() {
        let mut received = Mutex::new(vec![]);
        let reuse_count = AtomicUsize::new(0);
        let connection = TestConnection {
            written: &received,
            reuse_call_count: &reuse_count,
            read_data: &[
                0xC0, 4, 0, 6, 0, 0, 0, 1, 0, 2, 0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32, 0x80, 0,
                0, 0,
            ],
        };

        let (protocols, algorithms) = fetch_support_data(
            connection,
            "abcd".into(),
            &HashSet::from([0, 1]),
            Duration::from_secs(1),
        )
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

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let req = ServerInformationResponse::parse(&mut BufferBorrowingReader::new(
            received.get_mut().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();
        assert!(req.supported_algorithms.iter().next().is_none());
        assert!(req.supported_protocols.iter().next().is_none());
        assert_eq!(reuse_count.into_inner(), 0);
    }
}
