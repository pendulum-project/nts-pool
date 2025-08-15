use std::{net::SocketAddr, sync::Arc};

use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing::{debug, info};

use crate::{
    config::NtsPoolKeConfig,
    error::PoolError,
    haproxy::parse_haproxy_header,
    nts::{
        AlgorithmDescription, ClientRequest, ErrorCode, ErrorResponse, FixedKeyRequest,
        KeyExchangeResponse, NoAgreementResponse, NtsError, ProtocolId,
    },
    servers::{Server, ServerConnection, ServerManager},
};

pub async fn run_nts_pool_ke(
    nts_pool_ke_config: NtsPoolKeConfig,
    server_manager: impl ServerManager + 'static,
) -> std::io::Result<()> {
    let pool_ke = NtsPoolKe::new(nts_pool_ke_config, server_manager)?;

    Arc::new(pool_ke).serve().await
}

struct NtsPoolKe<S> {
    config: NtsPoolKeConfig,
    server_manager: S,
}

impl<S: ServerManager + 'static> NtsPoolKe<S> {
    fn new(config: NtsPoolKeConfig, server_manager: S) -> std::io::Result<Self> {
        Ok(NtsPoolKe {
            config,
            server_manager,
        })
    }

    async fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;
        self.serve_inner(listener).await
    }

    async fn serve_inner(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let connectionpermits = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));

        info!("listening on '{:?}'", listener.local_addr());

        loop {
            let permit = connectionpermits
                .clone()
                .acquire_owned()
                .await
                .expect("Semaphore shouldn't be closed");
            let (client_stream, source_address) = listener.accept().await?;
            let self_clone = self.clone();

            tokio::spawn(async move {
                match tokio::time::timeout(
                    self_clone.config.key_exchange_timeout,
                    self_clone.handle_client(client_stream, source_address),
                )
                .await
                {
                    Err(_) => ::tracing::debug!(?source_address, "NTS Pool KE timed out"),
                    Ok(Err(err)) => ::tracing::debug!(?err, ?source_address, "NTS Pool KE failed"),
                    Ok(Ok(())) => ::tracing::debug!(?source_address, "NTS Pool KE completed"),
                }
                drop(permit);
            });
        }
    }

    async fn handle_client(
        &self,
        mut client_stream: tokio::net::TcpStream,
        mut source_address: SocketAddr,
    ) -> Result<(), PoolError> {
        // Handle the proxy message if needed
        if self.config.use_proxy_protocol {
            if let Some(addr) = parse_haproxy_header(&mut client_stream).await? {
                source_address = addr;
            }
        }

        // handle the initial client to pool
        let mut client_stream = self.config.server_tls.accept(client_stream).await?;

        let client_request = match ClientRequest::parse(&mut client_stream).await {
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

        debug!("Recevied request from client");

        let pick = self
            .server_manager
            .assign_server(source_address, &client_request.denied_servers);

        let (protocol, algorithm) =
            match self.select_protocol_algorithm(&client_request, &pick).await {
                Ok(Some(result)) => result,
                Ok(None) => {
                    NoAgreementResponse.serialize(&mut client_stream).await?;
                    client_stream.shutdown().await?;
                    return Ok(());
                }
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
        let (c2s, s2c) = match self.extract_keys(client_stream.get_ref().1, protocol, algorithm) {
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

        let result = match self
            .perform_upstream_key_exchange(
                FixedKeyRequest {
                    c2s,
                    s2c,
                    protocol,
                    algorithm: algorithm.id,
                },
                &pick,
            )
            .await
        {
            // These errors indicate the pool did something weird
            Err(e @ PoolError::NtsError(NtsError::Error(ErrorCode::BadRequest)))
            | Err(
                e @ PoolError::NtsError(NtsError::Error(ErrorCode::UnrecognizedCriticalRecord)),
            ) => {
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
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
            // All other errors indicate we are doing something strange
            Err(e) => {
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
                }
                .serialize(&mut client_stream)
                .await?;
                Err(e)
            }
            Ok(mut response) => {
                if response.server.is_none() {
                    response.server = Some(pick.name().to_owned());
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
        client_request: &ClientRequest,
        server: &S::Server<'_>,
    ) -> Result<Option<(ProtocolId, AlgorithmDescription)>, PoolError> {
        let (supported_protocols, supported_algorithms) = server.support().await?;
        let mut protocol = None;
        for candidate_protocol in client_request.protocols.iter() {
            if supported_protocols.contains(candidate_protocol) {
                protocol = Some(*candidate_protocol);
                break;
            }
        }
        let mut algorithm = None;
        for candidate_algorithm in client_request.algorithms.iter() {
            if let Some(algdesc) = supported_algorithms.get(candidate_algorithm) {
                algorithm = Some(*algdesc);
                break;
            }
        }
        Ok(match (protocol, algorithm) {
            (Some(protocol), Some(algorithm)) => Some((protocol, algorithm)),
            _ => None,
        })
    }

    async fn perform_upstream_key_exchange(
        &self,
        request: FixedKeyRequest,
        server: &S::Server<'_>,
    ) -> Result<KeyExchangeResponse, PoolError> {
        // This function is needed to teach rust that the lifetimes actually do work.
        #[allow(clippy::manual_async_fn)]
        fn workaround_lifetime_bug<'b, C: ServerConnection + 'b>(
            request: FixedKeyRequest,
            mut server_stream: C,
        ) -> impl Future<Output = Result<KeyExchangeResponse, PoolError>> + Send + 'b {
            async move {
                request.serialize(&mut server_stream).await?;
                Ok(KeyExchangeResponse::parse(&mut server_stream).await?)
            }
        }

        // TODO: Implement connection reuse
        match tokio::time::timeout(self.config.timesource_timeout, async {
            let server_stream = server.connect().await?;
            workaround_lifetime_bug(request, server_stream).await
        })
        .await
        {
            Ok(v) => v,
            Err(_) => Err(PoolError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
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
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::{
        config::NtsPoolKeConfig,
        nts::{AlgorithmDescription, FixedKeyRequest, KeyExchangeResponse, ProtocolId},
        pool_ke::NtsPoolKe,
        servers::{Server, ServerConnection, ServerManager},
    };

    fn listen_tls_config(name: &str) -> TlsAcceptor {
        let certificate_chain = rustls::pki_types::CertificateDer::pem_file_iter(format!(
            "{}/testdata/{}.fullchain.pem",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap()
        .collect::<Result<Vec<rustls::pki_types::CertificateDer>, _>>()
        .unwrap();

        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(format!(
            "{}/testdata/{}.key",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap();

        let mut server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(certificate_chain.clone(), private_key.clone_key())
            .unwrap();
        server_config.alpn_protocols.clear();
        server_config.alpn_protocols.push(b"ntske/1".to_vec());

        TlsAcceptor::from(Arc::new(server_config))
    }

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
            std::collections::HashSet<crate::nts::ProtocolId>,
            std::collections::HashMap<crate::nts::AlgorithmId, crate::nts::AlgorithmDescription>,
        ),
        written: Mutex<Vec<u8>>,
        response: Vec<u8>,
        received_denied_servers: Mutex<Vec<String>>,
        received_addr: Mutex<Option<SocketAddr>>,
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
        ) -> Self {
            Self {
                inner: Arc::new(TestManagerInner {
                    name,
                    supports: (
                        protocols.iter().copied().collect(),
                        algorithms.iter().copied().map(|v| (v.id, v)).collect(),
                    ),
                    written: Mutex::new(vec![]),
                    response,
                    received_denied_servers: Mutex::new(vec![]),
                    received_addr: Mutex::new(None),
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
            denied_servers: &[String],
        ) -> Self::Server<'_> {
            *self.inner.received_denied_servers.lock().unwrap() = denied_servers.to_vec();
            *self.inner.received_addr.lock().unwrap() = Some(address);
            TestServer {
                name: &self.inner.name,
                supports: self.inner.supports.clone(),
                written: &self.inner.written,
                read_data: &self.inner.response,
            }
        }

        fn get_server_by_uuid(&self, _uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
            unimplemented!()
        }
    }

    struct TestServer<'a> {
        name: &'a str,
        supports: (
            std::collections::HashSet<crate::nts::ProtocolId>,
            std::collections::HashMap<crate::nts::AlgorithmId, crate::nts::AlgorithmDescription>,
        ),
        written: &'a Mutex<Vec<u8>>,
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
        ) -> Result<
            (
                std::collections::HashSet<crate::nts::ProtocolId>,
                std::collections::HashMap<
                    crate::nts::AlgorithmId,
                    crate::nts::AlgorithmDescription,
                >,
            ),
            crate::error::PoolError,
        > {
            Ok(self.supports.clone())
        }

        async fn connect<'a>(&'a self) -> Result<Self::Connection<'a>, crate::error::PoolError> {
            Ok(TestConnection {
                written: self.written,
                read_data: self.read_data,
            })
        }
    }

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
    async fn test_keyexchange_basic() {
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
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).unwrap());
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
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();

        #[allow(clippy::await_holding_lock)]
        let timesource_request =
            FixedKeyRequest::parse(manager.inner.written.lock().unwrap().as_slice())
                .await
                .unwrap();

        assert_eq!(timesource_request.algorithm, 0);
        assert_eq!(timesource_request.protocol, 0);
        assert_eq!(timesource_request.c2s.len(), 16);
        assert_eq!(timesource_request.s2c.len(), 16);
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_1() {
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
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).unwrap());
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
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        #[allow(clippy::await_holding_lock)]
        let request = FixedKeyRequest::parse(manager.inner.written.lock().unwrap().as_slice())
            .await
            .unwrap();

        assert_eq!(request.algorithm, 0);
        assert_eq!(request.protocol, 0);
        assert_eq!(request.c2s.len(), 16);
        assert_eq!(request.s2c.len(), 16);
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_2() {
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
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: false,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).unwrap());
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
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.algorithm, 1);
        assert_eq!(response.protocol, 1);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        #[allow(clippy::await_holding_lock)]
        let request = FixedKeyRequest::parse(manager.inner.written.lock().unwrap().as_slice())
            .await
            .unwrap();

        assert_eq!(request.algorithm, 1);
        assert_eq!(request.protocol, 1);
        assert_eq!(request.c2s.len(), 32);
        assert_eq!(request.s2c.len(), 32);
    }

    #[tokio::test]
    async fn test_keyexchange_proxy() {
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
        );
        let pool_manager = manager.clone();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                timesource_timeout: Duration::from_millis(500),
                max_connections: 1,
                use_proxy_protocol: true,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config, pool_manager).unwrap());
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
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();

        #[allow(clippy::await_holding_lock)]
        let timesource_request =
            FixedKeyRequest::parse(manager.inner.written.lock().unwrap().as_slice())
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

        pool_handle.abort();
    }
}
