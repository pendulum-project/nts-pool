use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use notify::{RecursiveMode, Watcher};
use opentelemetry::{KeyValue, metrics::Counter};
use pool_nts::{
    AlgorithmDescription, BufferBorrowingReader, ClientRequest, ErrorCode, ErrorResponse,
    FixedKeyRequest, KeyExchangeResponse, MAX_MESSAGE_SIZE, NoAgreementResponse, NtsError,
    ProtocolId,
};
use rustls::{pki_types::pem::PemObject, version::TLS13};
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::TcpListener,
    select,
    signal::unix::{SignalKind, signal},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;
use tracing::{debug, info};

use crate::{
    config::NtsPoolKeConfig,
    error::PoolError,
    haproxy::parse_haproxy_header,
    servers::{ConnectionType, Server, ServerConnection, ServerManager},
    util::load_certificates,
};

pub async fn run_nts_pool_ke(
    nts_pool_ke_config: NtsPoolKeConfig,
    server_manager: impl ServerManager + 'static,
) -> std::io::Result<()> {
    let pool_ke = NtsPoolKe::new(nts_pool_ke_config, server_manager).await?;

    Arc::new(pool_ke).serve().await
}

struct NtsPoolKe<S> {
    config: NtsPoolKeConfig,
    server_tls: RwLock<TlsAcceptor>,
    monitoring_keys: RwLock<Arc<HashSet<String>>>,
    session_counter: Counter<u64>,
    server_manager: S,
}

impl<S: ServerManager + 'static> NtsPoolKe<S> {
    async fn new(config: NtsPoolKeConfig, server_manager: S) -> std::io::Result<Self> {
        let server_config = load_tls_config(&config).await?;

        let server_tls = RwLock::new(server_config);

        let monitoring_keys = RwLock::new(Arc::new(load_monitoring_keys(&config).await?));

        let session_counter = opentelemetry::global::meter("PoolKe")
            .u64_counter("sessions")
            .with_description("number of ke sessions with clients")
            .build();

        Ok(NtsPoolKe {
            config,
            server_tls,
            monitoring_keys,
            session_counter,
            server_manager,
        })
    }

    async fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;
        self.serve_inner(listener).await
    }

    async fn serve_inner(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let connectionpermits = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));
        let mut shutdown =
            signal(SignalKind::terminate()).expect("Unable to configure termination signal");
        let tracker = TaskTracker::new();

        info!("listening on '{:?}'", listener.local_addr());

        let tls_updater = self.clone().tls_config_updater().await?;
        let monitoring_keys_updater = self.clone().monitoring_keys_updater().await?;

        loop {
            let permit = connectionpermits
                .clone()
                .acquire_owned()
                .await
                .expect("Semaphore shouldn't be closed");
            let (client_stream, source_address) = select! {
                biased;
                _ = shutdown.recv() => { break; }
                accept_result = listener.accept() => { accept_result? }
            };
            let self_clone = self.clone();

            tracker.spawn(async move {
                let mut is_monitor = false;
                match tokio::time::timeout(
                    self_clone.config.key_exchange_timeout,
                    self_clone.handle_client(client_stream, source_address, &mut is_monitor),
                )
                .await
                {
                    Err(_) => {
                        ::tracing::debug!(?source_address, "NTS Pool KE timed out");
                        self_clone.session_counter.add(
                            1,
                            &[
                                KeyValue::new("outcome", "timeout"),
                                KeyValue::new("is_monitor", is_monitor),
                            ],
                        );
                    }
                    Ok(Err(err)) => {
                        ::tracing::debug!(?err, ?source_address, "NTS Pool KE failed");
                        self_clone.session_counter.add(
                            1,
                            &[
                                KeyValue::new("outcome", "error"),
                                KeyValue::new("is_monitor", is_monitor),
                            ],
                        );
                    }
                    Ok(Ok(())) => {
                        ::tracing::debug!(?source_address, "NTS Pool KE completed");
                        self_clone.session_counter.add(
                            1,
                            &[
                                KeyValue::new("outcome", "success"),
                                KeyValue::new("is_monitor", is_monitor),
                            ],
                        );
                    }
                }
                drop(permit);
            });
        }

        info!("Shutting down...");

        tracker.close();
        tls_updater.abort();
        monitoring_keys_updater.abort();
        tracker.wait().await;

        info!("Finished all connections");

        Ok(())
    }

    async fn monitoring_keys_updater(
        self: Arc<Self>,
    ) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
        let Some(monitoring_keys_path) = self.config.monitoring_keys.clone() else {
            return Ok(tokio::task::spawn(async {}));
        };

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
            .watch(&monitoring_keys_path, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;

        Ok(tokio::spawn(async move {
            // keep the watcher alive
            let _w = watcher;
            loop {
                change_receiver.recv().await;
                match load_monitoring_keys(&self.config).await {
                    Ok(monitoring_keys) => {
                        *self.monitoring_keys.write().unwrap() = Arc::new(monitoring_keys);
                    }
                    Err(e) => {
                        tracing::error!("Could not reload tls configuration: {}", e);
                    }
                }
            }
        }))
    }

    async fn tls_config_updater(
        self: Arc<Self>,
    ) -> Result<tokio::task::JoinHandle<()>, std::io::Error> {
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
            .watch(&self.config.certificate_chain, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;
        watcher
            .watch(&self.config.private_key, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;

        Ok(tokio::spawn(async move {
            // keep the watcher alive
            let _w = watcher;
            loop {
                change_receiver.recv().await;
                match load_tls_config(&self.config).await {
                    Ok(server_tls) => {
                        *self.server_tls.write().unwrap() = server_tls;
                    }
                    Err(e) => {
                        tracing::error!("Could not reload tls configuration: {}", e);
                    }
                }
            }
        }))
    }

    async fn handle_client(
        &self,
        mut client_stream: tokio::net::TcpStream,
        mut source_address: SocketAddr,
        is_monitor: &mut bool,
    ) -> Result<(), PoolError> {
        // Handle the proxy message if needed
        if self.config.use_proxy_protocol
            && let Some(addr) = parse_haproxy_header(&mut client_stream).await?
        {
            info!("Proxy protocol used, change address from {source_address:?} to {addr:?}");
            source_address = addr;
        }

        debug!("Handling client with source address {}", source_address);

        // handle the initial client to pool
        let server_tls = self.server_tls.read().unwrap().clone();
        let mut client_stream = BufStream::new(server_tls.accept(client_stream).await?);

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let client_request = match ClientRequest::parse(&mut BufferBorrowingReader::new(
            &mut client_stream,
            &mut buf,
        ))
        .await
        {
            Ok(client_request) => client_request,
            Err(e @ NtsError::Invalid) => {
                ErrorResponse {
                    errorcode: ErrorCode::BadRequest,
                }
                .serialize(&mut client_stream)
                .await?;
                client_stream.shutdown().await?;
                return Err(e.into());
            }
            // Nothing we can do for the other errors as the connection is the main culprit.
            Err(e) => return Err(e.into()),
        };

        debug!("Recevied request from client: {:?}", client_request);

        let monitoring_keys = self.monitoring_keys.read().unwrap().clone();

        let pick = match &client_request {
            ClientRequest::Ordinary { denied_servers, .. } => match self
                .server_manager
                .assign_server(source_address, denied_servers)
            {
                Some(server) => server,
                None => {
                    ErrorResponse {
                        errorcode: ErrorCode::InternalServerError,
                    }
                    .serialize(&mut client_stream)
                    .await?;
                    client_stream.shutdown().await?;
                    return Err(PoolError::NoSuchServer);
                }
            },
            ClientRequest::Uuid { key, uuid, .. } if monitoring_keys.contains(key.as_ref()) => {
                *is_monitor = true;
                if let Some(server) = self.server_manager.get_server_by_uuid(uuid) {
                    server
                } else {
                    ErrorResponse {
                        errorcode: ErrorCode::NoSuchServer,
                    }
                    .serialize(&mut client_stream)
                    .await?;
                    client_stream.shutdown().await?;
                    return Err(PoolError::NoSuchServer);
                }
            }
            ClientRequest::Uuid { .. } => {
                ErrorResponse {
                    errorcode: ErrorCode::BadRequest,
                }
                .serialize(&mut client_stream)
                .await?;
                client_stream.shutdown().await?;
                return Err(PoolError::FailedAuthentication);
            }
        };

        let (protocol, algorithm) = match self
            .select_protocol_algorithm(source_address.into(), &client_request, &pick)
            .await
        {
            Ok(Some(result)) => result,
            Ok(None) => {
                NoAgreementResponse.serialize(&mut client_stream).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
            Err(e) => {
                ErrorResponse {
                    errorcode: match e {
                        PoolError::IO(_) | PoolError::Rustls(_) => {
                            ErrorCode::CouldNotConnectDownstream
                        }
                        _ if matches!(&client_request, ClientRequest::Uuid { .. }) => {
                            ErrorCode::CouldNotGetDownstreamCapabilities
                        }
                        _ => ErrorCode::InternalServerError,
                    },
                }
                .serialize(&mut client_stream)
                .await?;
                client_stream.shutdown().await?;
                return Err(e);
            }
        };
        let (c2s, s2c) =
            match self.extract_keys(client_stream.get_ref().get_ref().1, protocol, algorithm) {
                Ok(result) => result,
                Err(e) => {
                    ErrorResponse {
                        errorcode: ErrorCode::InternalServerError,
                    }
                    .serialize(&mut client_stream)
                    .await?;
                    client_stream.shutdown().await?;
                    return Err(e);
                }
            };

        debug!("fetching cookies from the NTS KE server");

        let mut upstream_buffer = [0u8; MAX_MESSAGE_SIZE as _];
        let result = match self
            .perform_upstream_key_exchange(
                &mut upstream_buffer,
                FixedKeyRequest {
                    key: pick.auth_key().into(),
                    c2s: c2s.into(),
                    s2c: s2c.into(),
                    protocol,
                    algorithm: algorithm.id,
                    keep_alive: true,
                },
                &pick,
                source_address.into(),
            )
            .await
        {
            // These errors indicate the pool did something weird or the time source is misconfigured
            Err(e @ PoolError::NtsError(NtsError::Error(ErrorCode::BadRequest)))
            | Err(
                e @ PoolError::NtsError(NtsError::Error(ErrorCode::UnrecognizedCriticalRecord)),
            ) => {
                ErrorResponse {
                    errorcode: if matches!(client_request, ClientRequest::Uuid { .. }) {
                        ErrorCode::CouldNotGetDownstreamCookies
                    } else {
                        ErrorCode::InternalServerError
                    },
                }
                .serialize(&mut client_stream)
                .await?;
                Err(e)
            }
            // Pass other errors from the server on unchanged
            Err(e @ PoolError::NtsError(NtsError::Error(errorcode))) => {
                ErrorResponse { errorcode }
                    .serialize(&mut client_stream)
                    .await?;
                Err(e)
            }
            // All other errors indicate we are doing something strange or cant connect to the time source
            Err(e) => {
                ErrorResponse {
                    errorcode: match e {
                        PoolError::IO(_) | PoolError::Rustls(_) => {
                            ErrorCode::CouldNotConnectDownstream
                        }
                        _ => ErrorCode::InternalServerError,
                    },
                }
                .serialize(&mut client_stream)
                .await?;
                Err(e)
            }
            Ok(mut response) => {
                if response.server.is_none() {
                    response.server = Some(pick.name().into());
                }
                response.serialize(&mut client_stream).await?;
                Ok(())
            }
        };

        client_stream.shutdown().await?;
        result
    }

    fn extract_keys(
        &self,
        tls_connection: &rustls::ServerConnection,
        protocol: u16,
        algorithm: AlgorithmDescription,
    ) -> Result<(Vec<u8>, Vec<u8>), PoolError> {
        let mut c2s = vec![0; algorithm.keysize.into()];
        let mut s2c = vec![0; algorithm.keysize.into()];
        tls_connection.export_keying_material(
            &mut c2s,
            b"EXPORTER-network-time-security",
            Some(&[
                (protocol >> 8) as u8,
                protocol as u8,
                (algorithm.id >> 8) as u8,
                algorithm.id as u8,
                0,
            ]),
        )?;
        tls_connection.export_keying_material(
            &mut s2c,
            b"EXPORTER-network-time-security",
            Some(&[
                (protocol >> 8) as u8,
                protocol as u8,
                (algorithm.id >> 8) as u8,
                algorithm.id as u8,
                1,
            ]),
        )?;
        Ok((c2s, s2c))
    }

    async fn select_protocol_algorithm(
        &self,
        connection_type: ConnectionType,
        client_request: &ClientRequest<'_>,
        server: &S::Server<'_>,
    ) -> Result<Option<(ProtocolId, AlgorithmDescription)>, PoolError> {
        let (supported_protocols, supported_algorithms) =
            server.support(connection_type).await.map_err(|e| {
                debug!("Error querying protocol support: {e}");
                e
            })?;
        let mut protocol = None;
        for candidate_protocol in client_request.protocols().iter() {
            if supported_protocols.contains(&candidate_protocol) {
                protocol = Some(candidate_protocol);
                break;
            }
        }
        let mut algorithm = None;
        for candidate_algorithm in client_request.algorithms().iter() {
            if let Some(algdesc) = supported_algorithms.get(&candidate_algorithm) {
                algorithm = Some(*algdesc);
                break;
            }
        }
        Ok(match (protocol, algorithm) {
            (Some(protocol), Some(algorithm)) => Some((protocol, algorithm)),
            _ => None,
        })
    }

    async fn perform_upstream_key_exchange<'c>(
        &self,
        buffer: &'c mut [u8],
        request: FixedKeyRequest<'_>,
        server: &S::Server<'_>,
        connection_type: ConnectionType,
    ) -> Result<KeyExchangeResponse<'c>, PoolError> {
        // This function is needed to teach rust that the lifetimes actually do work.
        #[allow(clippy::manual_async_fn)]
        fn workaround_lifetime_bug<'d: 'b, 'b, C: ServerConnection + 'b>(
            buffer: &'d mut [u8],
            request: FixedKeyRequest<'b>,
            mut server_stream: C,
        ) -> impl Future<Output = Result<KeyExchangeResponse<'d>, PoolError>> + Send + 'b {
            async move {
                request.serialize(&mut server_stream).await?;
                server_stream.flush().await?;
                let response = KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(
                    &mut server_stream,
                    buffer,
                ))
                .await?;
                if response.keep_alive {
                    server_stream.reuse().await;
                } else {
                    let _ = server_stream.shutdown().await;
                }
                Ok(response)
            }
        }

        // TODO: Implement connection reuse
        match tokio::time::timeout(self.config.timesource_timeout, async {
            let server_stream = server.connect(connection_type).await?;
            workaround_lifetime_bug(buffer, request, server_stream).await
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Err(PoolError::Timeout),
        }
    }
}

async fn load_tls_config(config: &NtsPoolKeConfig) -> Result<TlsAcceptor, std::io::Error> {
    let certificate_chain = config.certificate_chain.clone();
    let private_key = config.private_key.clone();

    tokio::task::spawn_blocking(|| {
        let certificate_chain =
            load_certificates(certificate_chain).map_err(std::io::Error::other)?;
        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(private_key)
            .map_err(std::io::Error::other)?;
        let mut server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain.clone(), private_key.clone_key())
            .map_err(std::io::Error::other)?;
        server_config.alpn_protocols = vec!["ntske/1".into()];
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    })
    .await
    .unwrap()
}

async fn load_monitoring_keys(config: &NtsPoolKeConfig) -> Result<HashSet<String>, std::io::Error> {
    let Some(monitoring_keys) = config.monitoring_keys.clone() else {
        return Ok(HashSet::new());
    };

    tokio::task::spawn_blocking(|| {
        serde_json::from_reader(std::fs::File::open(monitoring_keys)?)
            .map_err(std::io::Error::other)
    })
    .await
    .unwrap()
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use std::{
        borrow::Cow,
        net::SocketAddr,
        path::PathBuf,
        sync::{Arc, Mutex, atomic::AtomicUsize},
        time::Duration,
    };

    use pool_nts::{
        AlgorithmDescription, AlgorithmId, BufferBorrowingReader, ErrorCode, FixedKeyRequest,
        KeyExchangeResponse, MAX_MESSAGE_SIZE, NtsError, ProtocolId,
    };
    use rustls::{
        RootCertStore,
        pki_types::{ServerName, pem::PemObject},
        version::TLS13,
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsConnector;

    use crate::{
        config::NtsPoolKeConfig,
        pool_ke::NtsPoolKe,
        servers::{ConnectionType, Server, ServerConnection, ServerManager},
    };

    fn upstream_tls_config() -> TlsConnector {
        let upstream_cas = rustls::pki_types::CertificateDer::pem_file_iter(format!(
            "{}/testdata/testca.pem",
            env!("CARGO_MANIFEST_DIR"),
        ))
        .unwrap()
        .collect::<Result<Vec<rustls::pki_types::CertificateDer>, _>>()
        .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(upstream_cas);
        let upstream_config = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(upstream_config))
    }

    struct TestManagerInner {
        name: String,
        supports: (
            std::collections::HashSet<ProtocolId>,
            std::collections::HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        written: Mutex<Vec<u8>>,
        reuse_count: AtomicUsize,
        uuid_exists: bool,
        response: Vec<u8>,
        received_denied_servers: Mutex<Vec<String>>,
        received_addr: Mutex<Option<SocketAddr>>,
        received_uuid: Mutex<Option<String>>,
    }

    #[derive(Clone)]
    struct TestManager {
        inner: Arc<TestManagerInner>,
    }

    impl TestManager {
        fn new(
            name: String,
            response: Vec<u8>,
            protocols: &[ProtocolId],
            algorithms: &[AlgorithmDescription],
            uuid_exists: bool,
        ) -> Self {
            Self {
                inner: Arc::new(TestManagerInner {
                    name,
                    supports: (
                        protocols.iter().copied().collect(),
                        algorithms.iter().copied().map(|v| (v.id, v)).collect(),
                    ),
                    written: Mutex::new(vec![]),
                    reuse_count: AtomicUsize::new(0),
                    response,
                    uuid_exists,
                    received_denied_servers: Mutex::new(vec![]),
                    received_addr: Mutex::new(None),
                    received_uuid: Mutex::new(None),
                }),
            }
        }
    }

    impl ServerManager for TestManager {
        type Server<'a>
            = TestServer<'a>
        where
            Self: 'a;

        fn assign_server(
            &self,
            address: std::net::SocketAddr,
            denied_servers: &[Cow<'_, str>],
        ) -> Option<Self::Server<'_>> {
            *self.inner.received_denied_servers.lock().unwrap() = denied_servers
                .iter()
                .map(|v| v.clone().into_owned())
                .collect();
            *self.inner.received_addr.lock().unwrap() = Some(address);
            Some(TestServer {
                name: &self.inner.name,
                supports: self.inner.supports.clone(),
                written: &self.inner.written,
                reuse_count: &self.inner.reuse_count,
                read_data: &self.inner.response,
            })
        }

        fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
            *self.inner.received_uuid.lock().unwrap() = Some(uuid.as_ref().into());
            if self.inner.uuid_exists {
                Some(TestServer {
                    name: &self.inner.name,
                    supports: self.inner.supports.clone(),
                    written: &self.inner.written,
                    reuse_count: &self.inner.reuse_count,
                    read_data: &self.inner.response,
                })
            } else {
                None
            }
        }
    }

    struct TestServer<'a> {
        name: &'a str,
        supports: (
            std::collections::HashSet<ProtocolId>,
            std::collections::HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        written: &'a Mutex<Vec<u8>>,
        reuse_count: &'a AtomicUsize,
        read_data: &'a [u8],
    }

    impl Server for TestServer<'_> {
        type Connection<'a>
            = TestConnection<'a>
        where
            Self: 'a;

        fn name(&self) -> &str {
            self.name
        }

        async fn support(
            &self,
            _connection_type: ConnectionType,
        ) -> Result<
            (
                std::collections::HashSet<ProtocolId>,
                std::collections::HashMap<AlgorithmId, AlgorithmDescription>,
            ),
            crate::error::PoolError,
        > {
            Ok(self.supports.clone())
        }

        async fn connect<'a>(
            &'a self,
            _connection_type: ConnectionType,
        ) -> Result<Self::Connection<'a>, crate::error::PoolError> {
            Ok(TestConnection {
                written: self.written,
                reuse_count: self.reuse_count,
                read_data: self.read_data,
            })
        }

        fn auth_key(&self) -> String {
            "abcdefghi".into()
        }
    }

    struct TestConnection<'a> {
        written: &'a Mutex<Vec<u8>>,
        reuse_count: &'a AtomicUsize,
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
            self.reuse_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn test_keyexchange_basic() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: None,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x80, 0, 0, 0])
            .await
            .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let timesource_request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(timesource_request.algorithm, 0);
        assert_eq!(timesource_request.protocol, 0);
        assert_eq!(timesource_request.c2s.len(), 16);
        assert_eq!(timesource_request.s2c.len(), 16);
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_keepalive() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x40,
                0, 0, 0, 0x80, 0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: None,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x80, 0, 0, 0])
            .await
            .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let timesource_request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(timesource_request.algorithm, 0);
        assert_eq!(timesource_request.protocol, 0);
        assert_eq!(timesource_request.c2s.len(), 16);
        assert_eq!(timesource_request.s2c.len(), 16);
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_1() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[1, 0],
            &[
                AlgorithmDescription { id: 1, keysize: 32 },
                AlgorithmDescription { id: 0, keysize: 16 },
            ],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: None,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 4, 0, 0, 0, 1, 0x80, 4, 0, 4, 0, 0, 0, 1, 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(request.algorithm, 0);
        assert_eq!(request.protocol, 0);
        assert_eq!(request.c2s.len(), 16);
        assert_eq!(request.s2c.len(), 16);
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_2() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 1, 0x80, 4, 0, 2, 0, 1, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[1, 0],
            &[
                AlgorithmDescription { id: 1, keysize: 32 },
                AlgorithmDescription { id: 0, keysize: 16 },
            ],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: None,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 4, 0, 1, 0, 0, 0x80, 4, 0, 4, 0, 1, 0, 0, 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.algorithm, 1);
        assert_eq!(response.protocol, 1);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(request.algorithm, 1);
        assert_eq!(request.protocol, 1);
        assert_eq!(request.c2s.len(), 32);
        assert_eq!(request.s2c.len(), 32);
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_keyexchange_proxy() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: true,
                monitoring_keys: None,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let mut conn = TcpStream::connect(pool_addr).await.unwrap();
        conn.write_all(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\x01\x02\x03\x04\x05\x06\x07\x08\x00\x09\x00\x0A").await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x80, 0, 0, 0])
            .await
            .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let timesource_request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(timesource_request.algorithm, 0);
        assert_eq!(timesource_request.protocol, 0);
        assert_eq!(timesource_request.c2s.len(), 16);
        assert_eq!(timesource_request.s2c.len(), 16);
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));
        assert_eq!(
            manager.inner.received_addr.lock().unwrap().unwrap(),
            "1.2.3.4:9".parse().unwrap()
        );
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_get_uuid() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            true,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: Some(
                    format!(
                        "{}/testdata/monitoring_keys.json",
                        env!("CARGO_MANIFEST_DIR")
                    )
                    .into(),
                ),
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x40, 5, 0, 4, b't', b'e', b's', b't', 0xCF,
            1, 0, 4, b'u', b'u', b'i', b'd', 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf))
                .await
                .unwrap();
        conn.shutdown().await.unwrap();

        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let timesource_request = FixedKeyRequest::parse(&mut BufferBorrowingReader::new(
            manager.inner.written.lock().unwrap().as_slice(),
            &mut buf,
        ))
        .await
        .unwrap();

        assert_eq!(timesource_request.algorithm, 0);
        assert_eq!(timesource_request.protocol, 0);
        assert_eq!(timesource_request.c2s.len(), 16);
        assert_eq!(timesource_request.s2c.len(), 16);
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));
        assert_eq!(
            manager.inner.received_uuid.lock().unwrap().take().unwrap(),
            "uuid"
        );
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_get_uuid_non_existing() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            false,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: Some(
                    format!(
                        "{}/testdata/monitoring_keys.json",
                        env!("CARGO_MANIFEST_DIR")
                    )
                    .into(),
                ),
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x40, 5, 0, 4, b't', b'e', b's', b't', 0xCF,
            1, 0, 4, b'u', b'u', b'i', b'd', 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf)).await;
        conn.shutdown().await.unwrap();

        assert!(manager.inner.written.lock().unwrap().is_empty());

        assert!(matches!(
            response,
            Err(NtsError::Error(ErrorCode::NoSuchServer))
        ));
        assert_eq!(
            manager.inner.received_uuid.lock().unwrap().take().unwrap(),
            "uuid"
        );
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_get_uuid_authfail() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            true,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: Some(
                    format!(
                        "{}/testdata/monitoring_keys.json",
                        env!("CARGO_MANIFEST_DIR")
                    )
                    .into(),
                ),
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x40, 5, 0, 4, b'n', b'o', b'n', b'e', 0xCF,
            1, 0, 4, b'u', b'u', b'i', b'd', 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf)).await;
        conn.shutdown().await.unwrap();

        assert!(manager.inner.written.lock().unwrap().is_empty());

        assert!(matches!(
            response,
            Err(NtsError::Error(ErrorCode::BadRequest))
        ));
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_get_uuid_missing_auth() {
        crate::test_init();
        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let manager = TestManager::new(
            "a.test".into(),
            vec![
                0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0, 5, 0, 2, 1, 2, 0, 5, 0, 2, 3, 4, 0x80,
                0, 0, 0,
            ],
            &[0],
            &[AlgorithmDescription { id: 0, keysize: 16 }],
            true,
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                certificate_chain: PathBuf::from(format!(
                    "{}/testdata/pool.test.fullchain.pem",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                private_key: PathBuf::from(format!(
                    "{}/testdata/pool.test.key",
                    env!("CARGO_MANIFEST_DIR"),
                )),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
                monitoring_keys: Some(
                    format!(
                        "{}/testdata/monitoring_keys.json",
                        env!("CARGO_MANIFEST_DIR")
                    )
                    .into(),
                ),
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).await.unwrap());
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0xCF, 1, 0, 4, b'u', b'u', b'i', b'd', 0x80,
            0, 0, 0,
        ])
        .await
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_SIZE as _];
        let response =
            KeyExchangeResponse::parse(&mut BufferBorrowingReader::new(&mut conn, &mut buf)).await;
        conn.shutdown().await.unwrap();

        assert!(manager.inner.written.lock().unwrap().is_empty());

        assert!(matches!(
            response,
            Err(NtsError::Error(ErrorCode::BadRequest))
        ));
        assert_eq!(
            manager
                .inner
                .reuse_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        pool_handle.abort();
    }
}
