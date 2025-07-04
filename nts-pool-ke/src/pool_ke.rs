use std::{net::SocketAddr, sync::Arc};

use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing::{debug, info};

use crate::{
    config::NtsPoolKeConfig,
    error::PoolError,
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
        client_stream: tokio::net::TcpStream,
        source_address: SocketAddr,
    ) -> Result<(), PoolError> {
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
                Err(e.into())
            }
            // Pass other errors from the server on unchanged
            Err(e @ PoolError::NtsError(NtsError::Error(errorcode))) => {
                ErrorResponse { errorcode }
                    .serialize(&mut client_stream)
                    .await?;
                Err(e.into())
            }
            // All other errors indicate we are doing something strange
            Err(e) => {
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
                }
                .serialize(&mut client_stream)
                .await?;
                Err(e.into())
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
        let server_stream = server.connect().await?;
        workaround_lifetime_bug(request, server_stream).await
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use rustls::{
        RootCertStore,
        pki_types::{ServerName, pem::PemObject},
        version::TLS13,
    };
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::{
        config::{BackendConfig, KeyExchangeServer, NtsPoolKeConfig},
        nts::{FixedKeyRequest, KeyExchangeResponse, ServerInformationResponse},
        pool_ke::NtsPoolKe,
        servers::RoundRobinServerManager,
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

    async fn basic_upstream_server(name: &str, listener: TcpListener) -> (Vec<u8>, Vec<u8>) {
        let acceptor = listen_tls_config(name);

        let conn = listener.accept().await.unwrap().0;
        let mut conn = acceptor.accept(conn).await.unwrap();

        let _ = ServerInformationResponse::parse(&mut conn).await.unwrap();
        conn.write_all(&[
            0xC0, 0x04, 0, 4, 0, 0, 0, 1, 0xC0, 0x01, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32, 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();

        conn.shutdown().await.unwrap();

        let conn = listener.accept().await.unwrap().0;
        let mut conn = acceptor.accept(conn).await.unwrap();

        let request = FixedKeyRequest::parse(&mut conn).await.unwrap();

        let response = KeyExchangeResponse {
            protocol: request.protocol,
            algorithm: request.algorithm,
            cookies: vec![vec![1, 2, 3, 4]],
            server: None,
            port: None,
        };

        response.serialize(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();

        (request.c2s, request.s2c)
    }

    #[tokio::test]
    async fn test_keyexchange_basic() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let upstream_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_listener).await });

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };
            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
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
        assert_eq!(response.algorithm, 0);
        assert_eq!(response.protocol, 0);
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        let (c2s, s2c) = upstream_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_1() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let upstream_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_listener).await });

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };
            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
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

        let (c2s, s2c) = upstream_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);
    }

    #[tokio::test]
    async fn test_keyexchange_respects_client_prioritization_2() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let upstream_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_listener).await });

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };
            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
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

        let (c2s, s2c) = upstream_handle.await.unwrap();

        assert_eq!(c2s.len(), 32);
        assert_eq!(s2c.len(), 32);
    }

    #[tokio::test]
    async fn test_keyexchange_distributes_load() {
        let upstream_a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_a_addr = upstream_a_listener.local_addr().unwrap();

        let upstream_a_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_a_listener).await });

        let upstream_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_b_addr = upstream_b_listener.local_addr().unwrap();

        let upstream_b_handle =
            tokio::spawn(async move { basic_upstream_server("b.test", upstream_b_listener).await });

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };
            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![
                    KeyExchangeServer {
                        domain: "a.test".to_string(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("127.0.0.1".to_string(), upstream_a_addr.port()),
                    },
                    KeyExchangeServer {
                        domain: "b.test".to_string(),
                        server_name: ServerName::try_from("b.test").unwrap(),
                        connection_address: ("127.0.0.1".to_string(), upstream_b_addr.port()),
                    },
                ]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
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
        let response_1 = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert!(response_1.server.is_some());

        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();
        conn.write_all(&[0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x80, 0, 0, 0])
            .await
            .unwrap();
        let response_2 = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert!(response_2.server.is_some());

        assert_ne!(response_1.server, response_2.server);

        pool_handle.abort();

        let (c2s, s2c) = upstream_a_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);

        let (c2s, s2c) = upstream_b_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);
    }

    #[tokio::test]
    async fn test_keyexchange_respects_deny_if_possible() {
        let upstream_a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_a_addr = upstream_a_listener.local_addr().unwrap();

        let upstream_a_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_a_listener).await });

        let upstream_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_b_addr = upstream_b_listener.local_addr().unwrap();

        let upstream_b_handle =
            tokio::spawn(async move { basic_upstream_server("b.test", upstream_b_listener).await });

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };
            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![
                    KeyExchangeServer {
                        domain: "a.test".to_string(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("127.0.0.1".to_string(), upstream_a_addr.port()),
                    },
                    KeyExchangeServer {
                        domain: "b.test".to_string(),
                        server_name: ServerName::try_from("b.test").unwrap(),
                        connection_address: ("127.0.0.1".to_string(), upstream_b_addr.port()),
                    },
                ]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();

        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();
        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x40, 3, 0, 6, b'a', b'.', b't', b'e', b's',
            b't', 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.server.as_deref(), Some("b.test"));

        pool_handle.abort();
        upstream_a_handle.abort();

        let (c2s, s2c) = upstream_b_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);
    }

    #[tokio::test]
    async fn test_keyexchange_ignores_deny_if_no_other_server() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let pool_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pool_addr = pool_listener.local_addr().unwrap();

        let upstream_handle =
            tokio::spawn(async move { basic_upstream_server("a.test", upstream_listener).await });

        let pool_handle = tokio::spawn(async move {
            let pool_config = NtsPoolKeConfig {
                server_tls: listen_tls_config("pool.test"),
                listen: pool_addr,
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let backend_config = BackendConfig {
                upstream_tls: upstream_tls_config(),
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
            };

            let pool = Arc::new(
                NtsPoolKe::new(pool_config, RoundRobinServerManager::new(backend_config)).unwrap(),
            );
            pool.serve_inner(pool_listener).await
        });

        let pool_connector = upstream_tls_config();
        let conn = TcpStream::connect(pool_addr).await.unwrap();
        let mut conn = pool_connector
            .connect(ServerName::try_from("pool.test").unwrap(), conn)
            .await
            .unwrap();

        conn.write_all(&[
            0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 0, 0x40, 3, 0, 6, b'a', b'.', b't', b'e', b's',
            b't', 0x80, 0, 0, 0,
        ])
        .await
        .unwrap();
        let response = KeyExchangeResponse::parse(&mut conn).await.unwrap();
        conn.shutdown().await.unwrap();
        assert_eq!(response.server.as_deref(), Some("a.test"));

        pool_handle.abort();

        let (c2s, s2c) = upstream_handle.await.unwrap();

        assert_eq!(c2s.len(), 16);
        assert_eq!(s2c.len(), 16);
    }
}
