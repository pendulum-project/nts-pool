use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::atomic::AtomicUsize,
    time::Duration,
};

use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    error::PoolError,
    nts::{AlgorithmDescription, AlgorithmId, ProtocolId},
    servers::{Server, ServerManager, fetch_support_data},
};

pub struct RoundRobinServerManager {
    servers: Box<[KeyExchangeServer]>,
    uuid_lookup: HashMap<String, usize>,
    allowed_protocols: HashSet<ProtocolId>,
    upstream_tls: TlsConnector,
    next_start: AtomicUsize,
    timeout: Duration,
}

impl RoundRobinServerManager {
    pub fn new(config: BackendConfig) -> std::io::Result<Self> {
        let server_file = std::fs::File::open(config.key_exchange_servers)?;
        let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

        let mut uuid_lookup = HashMap::new();
        for (index, server) in servers.iter().enumerate() {
            uuid_lookup.insert(server.uuid.clone(), index);
        }

        Ok(Self {
            servers,
            uuid_lookup,
            allowed_protocols: config.allowed_protocols,
            upstream_tls: config.upstream_tls,
            next_start: AtomicUsize::new(0),
            timeout: config.timesource_timeout,
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

    fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
        self.uuid_lookup
            .get(uuid.as_ref())
            .map(|&index| RoundRobinServer {
                server: &self.servers[index],
                owner: self,
            })
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
        fetch_support_data(
            self.connect().await?,
            &self.owner.allowed_protocols,
            self.owner.timeout,
        )
        .await
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
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
        time::Duration,
    };

    use rustls::{
        RootCertStore,
        pki_types::{ServerName, pem::PemObject},
        version::TLS13,
    };
    use tokio_rustls::TlsConnector;

    use crate::{
        config::KeyExchangeServer,
        servers::{RoundRobinServerManager, Server, ServerManager},
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

    #[test]
    fn test_load_is_distributed() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let first_server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
        let second_server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
        assert_ne!(first_server.name(), second_server.name());
    }

    #[test]
    fn test_lookup_by_uuid() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let server = manager.get_server_by_uuid("UUID-a").unwrap();
        assert_eq!(server.name(), "a.test");

        let server = manager.get_server_by_uuid("UUID-b").unwrap();
        assert_eq!(server.name(), "b.test");
    }

    #[test]
    fn test_respect_denied_if_possible() {
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
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
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    regions: vec![],
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    regions: vec![],
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
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
}
