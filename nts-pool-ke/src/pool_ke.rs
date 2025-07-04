use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, atomic::AtomicUsize},
};

use rustls::ServerConnection;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing::{debug, info};

use crate::{
    config::{self, KeyExchangeServer, NtsPoolKeConfig},
    error::PoolError,
    nts::{
        AlgorithmDescription, AlgorithmId, ClientRequest, ErrorCode, ErrorResponse,
        FixedKeyRequest, KeyExchangeResponse, NoAgreementResponse, NtsError, ProtocolId,
        ServerInformationRequest, ServerInformationResponse,
    },
};

pub async fn run_nts_pool_ke(nts_pool_ke_config: NtsPoolKeConfig) -> std::io::Result<()> {
    let pool_ke = NtsPoolKe::new(nts_pool_ke_config)?;

    Arc::new(pool_ke).serve().await
}

struct NtsPoolKe {
    config: NtsPoolKeConfig,
    next_start: AtomicUsize,
}

impl NtsPoolKe {
    fn new(config: NtsPoolKeConfig) -> std::io::Result<Self> {
        Ok(NtsPoolKe {
            config,
            next_start: AtomicUsize::new(0),
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
                    self_clone.handle_client(client_stream),
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

    async fn handle_client(&self, client_stream: tokio::net::TcpStream) -> Result<(), PoolError> {
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

        let pick = self.pick_nts_ke_servers(&client_request.denied_servers);

        let (protocol, algorithm) =
            match self.select_protocol_algorithm(&client_request, pick).await {
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
                pick,
            )
            .await
        {
            // These errors indicate the pool did something weird
            Err(e @ NtsError::Error(ErrorCode::BadRequest))
            | Err(e @ NtsError::Error(ErrorCode::UnrecognizedCriticalRecord)) => {
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
                }
                .serialize(&mut client_stream)
                .await?;
                Err(e.into())
            }
            // Pass other errors from the server on unchanged
            Err(e @ NtsError::Error(errorcode)) => {
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
                    response.server = Some(pick.domain.clone());
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
        tls_connection: &ServerConnection,
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
        server: &KeyExchangeServer,
    ) -> Result<Option<(ProtocolId, AlgorithmDescription)>, PoolError> {
        let server_stream = tokio::net::TcpStream::connect(&server.connection_address).await?;
        let mut server_stream = self
            .config
            .upstream_tls
            .connect(server.server_name.clone(), server_stream)
            .await?;
        ServerInformationRequest
            .serialize(&mut server_stream)
            .await?;
        let support_info = ServerInformationResponse::parse(&mut server_stream).await?;
        server_stream.shutdown().await?;
        let supported_protocols: HashSet<ProtocolId> =
            support_info.supported_protocols.into_iter().collect();
        let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
            .supported_algorithms
            .into_iter()
            .map(|v| (v.id, v))
            .collect();
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
        server: &config::KeyExchangeServer,
    ) -> Result<KeyExchangeResponse, NtsError> {
        // TODO: Implement connection reuse
        let server_stream = tokio::net::TcpStream::connect(&server.connection_address).await?;
        let mut server_stream = self
            .config
            .upstream_tls
            .connect(server.server_name.clone(), server_stream)
            .await?;

        request.serialize(&mut server_stream).await?;
        KeyExchangeResponse::parse(&mut server_stream).await
    }

    fn pick_nts_ke_servers<'a>(
        &'a self,
        denied_servers: &[String],
    ) -> &'a config::KeyExchangeServer {
        use std::sync::atomic::Ordering;
        let start_index = self.next_start.fetch_add(1, Ordering::Relaxed);

        // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
        // permanently cripple the pool
        let servers = &self.config.key_exchange_servers;
        let (left, right) = servers.split_at(start_index % servers.len());
        let rotated_servers = right.iter().chain(left.iter());

        for server in rotated_servers {
            if denied_servers.contains(&server.domain) {
                continue;
            }

            return server;
        }

        debug!("All servers denied. Falling back to denied server");

        &servers[start_index % servers.len()]
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
        config::{KeyExchangeServer, NtsPoolKeConfig},
        nts::{FixedKeyRequest, KeyExchangeResponse, ServerInformationResponse},
        pool_ke::NtsPoolKe,
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
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
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
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
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
                upstream_tls: upstream_tls_config(),
                listen: pool_addr,
                key_exchange_servers: vec![KeyExchangeServer {
                    domain: "a.test".to_string(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("127.0.0.1".to_string(), upstream_addr.port()),
                }]
                .into(),
                key_exchange_timeout: Duration::from_millis(1000),
                max_connections: 1,
            };

            let pool = Arc::new(NtsPoolKe::new(pool_config).unwrap());
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
