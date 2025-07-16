use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::atomic::AtomicUsize,
};

use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    error::PoolError,
    nts::{
        AlgorithmDescription, AlgorithmId, ProtocolId, ServerInformationRequest,
        ServerInformationResponse,
    },
    servers::{Server, ServerManager},
};

pub struct RoundRobinServerManager {
    servers: Box<[KeyExchangeServer]>,
    allowed_protocols: HashSet<ProtocolId>,
    upstream_tls: TlsConnector,
    next_start: AtomicUsize,
}

impl RoundRobinServerManager {
    pub fn new(config: BackendConfig) -> std::io::Result<Self> {
        let server_file = std::fs::File::open(config.key_exchange_servers)?;
        let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

        Ok(Self {
            servers,
            allowed_protocols: config.allowed_protocols,
            upstream_tls: config.upstream_tls,
            next_start: AtomicUsize::new(0),
        })
    }
}

impl ServerManager for RoundRobinServerManager {
    type Server<'a>
        = RoundRobinServer<'a>
    where
        Self: 'a;

    fn assign_server(&self, _address: SocketAddr, denied_servers: &[String]) -> Self::Server<'_> {
        use std::sync::atomic::Ordering;
        let start_index = self.next_start.fetch_add(1, Ordering::Relaxed);

        // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
        // permanently cripple the pool
        let (left, right) = self.servers.split_at(start_index % self.servers.len());
        let rotated_servers = right.iter().chain(left.iter());

        for server in rotated_servers {
            if denied_servers.contains(&server.domain) {
                continue;
            }

            return RoundRobinServer {
                server,
                owner: self,
            };
        }

        debug!("All servers denied. Falling back to denied server");

        RoundRobinServer {
            server: &self.servers[start_index % self.servers.len()],
            owner: self,
        }
    }
}

pub struct RoundRobinServer<'a> {
    server: &'a KeyExchangeServer,
    owner: &'a RoundRobinServerManager,
}

impl Server for RoundRobinServer<'_> {
    type Connection<'a>
        = TlsStream<TcpStream>
    where
        Self: 'a;

    fn name(&self) -> &str {
        &self.server.domain
    }

    async fn support(
        &self,
    ) -> Result<
        (
            HashSet<ProtocolId>,
            HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        PoolError,
    > {
        let mut connection = self.connect().await?;

        ServerInformationRequest.serialize(&mut connection).await?;
        let support_info = ServerInformationResponse::parse(&mut connection).await?;
        connection.shutdown().await?;
        let supported_protocols: HashSet<ProtocolId> = support_info
            .supported_protocols
            .into_iter()
            .filter(|v| self.owner.allowed_protocols.contains(v))
            .collect();
        let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
            .supported_algorithms
            .into_iter()
            .map(|v| (v.id, v))
            .collect();
        Ok((supported_protocols, supported_algorithms))
    }

    async fn connect(&self) -> Result<Self::Connection<'_>, PoolError> {
        let io = TcpStream::connect(self.server.connection_address.clone()).await?;
        Ok(self
            .owner
            .upstream_tls
            .connect(self.server.server_name.clone(), io)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use rustls::{
        RootCertStore,
        pki_types::{ServerName, pem::PemObject},
        version::TLS13,
    };
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::{
        config::KeyExchangeServer,
        nts::{AlgorithmDescription, ServerInformationResponse},
        servers::{RoundRobinServerManager, Server, ServerManager},
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

    #[test]
    fn test_load_is_distributed() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
        };

        let first_server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
        let second_server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
        assert_ne!(first_server.name(), second_server.name());
    }

    #[test]
    fn test_respect_denied_if_possible() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
        };

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");
    }

    #[test]
    fn test_ignore_denied_if_impossible() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
        };

        let first = manager.assign_server(
            "127.0.0.1:4460".parse().unwrap(),
            &["a.test".into(), "b.test".into()],
        );
        let second = manager.assign_server(
            "127.0.0.1:4460".parse().unwrap(),
            &["a.test".into(), "b.test".into()],
        );
        assert_ne!(first.name(), second.name());
    }

    async fn basic_upstream_server(
        name: &str,
        listener: TcpListener,
        response: &[u8],
    ) -> ServerInformationResponse {
        let acceptor = listen_tls_config(name);

        let conn = listener.accept().await.unwrap().0;
        let mut conn = acceptor.accept(conn).await.unwrap();

        let result = ServerInformationResponse::parse(&mut conn).await.unwrap();
        conn.write_all(response).await.unwrap();

        result
    }

    #[tokio::test]
    async fn test_query_supporting_servers() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let upstream_handler = tokio::spawn(basic_upstream_server(
            "a.test",
            upstream_listener,
            &[
                0xC0, 4, 0, 6, 0, 0, 0, 1, 0, 2, 0xC0, 1, 0, 8, 0, 0, 0, 16, 0, 1, 0, 32, 0x80, 0,
                0, 0,
            ],
        ));

        let mut allowed_protocols = HashSet::new();
        allowed_protocols.insert(0);
        allowed_protocols.insert(1);

        let manager = RoundRobinServerManager {
            servers: [KeyExchangeServer {
                domain: "a.test".into(),
                server_name: "a.test".try_into().unwrap(),
                connection_address: ("127.0.0.1".into(), upstream_addr.port()),
                regions: vec![],
            }]
            .into(),
            upstream_tls: upstream_tls_config(),
            allowed_protocols,
            next_start: 0.into(),
        };

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);

        assert_eq!(server.name(), "a.test");

        let (protocols, algorithms) = server.support().await.unwrap();
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

        let req = upstream_handler.await.unwrap();
        assert_eq!(req.supported_algorithms.len(), 0);
        assert_eq!(req.supported_protocols.len(), 0);
    }
}
