use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use pool_nts::{AlgorithmDescription, AlgorithmId, ProtocolId};
use tokio::{io::BufStream, net::TcpStream};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    error::PoolError,
    servers::{
        ConnectionType, Server, ServerManager, fetch_support_data, load_upstream_tls,
        resolve_with_type,
    },
};

pub struct RoundRobinServerManager {
    servers: Box<[KeyExchangeServer]>,
    uuid_lookup: HashMap<Arc<str>, usize>,
    allowed_protocols: HashSet<ProtocolId>,
    upstream_tls: TlsConnector,
    base_server_secret: Vec<String>,
    next_start: AtomicUsize,
    timeout: Duration,
}

impl RoundRobinServerManager {
    pub async fn new(config: BackendConfig) -> std::io::Result<Self> {
        let upstream_tls = load_upstream_tls(&config).await?;

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
            upstream_tls,
            base_server_secret: config.base_shared_secret,
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

    fn assign_server(
        &self,
        _address: SocketAddr,
        denied_servers: &[Cow<'_, str>],
    ) -> Option<Self::Server<'_>> {
        if self.servers.is_empty() {
            return None;
        }

        use std::sync::atomic::Ordering;
        let start_index = self.next_start.fetch_add(1, Ordering::Relaxed);

        // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
        // permanently cripple the pool
        let (left, right) = self.servers.split_at(start_index % self.servers.len());
        let rotated_servers = right.iter().chain(left.iter());

        for server in rotated_servers {
            if denied_servers.iter().any(|v| *v == *server.domain) {
                continue;
            }

            return Some(RoundRobinServer {
                server,
                owner: self,
            });
        }

        debug!("All servers denied. Falling back to denied server");

        Some(RoundRobinServer {
            server: &self.servers[start_index % self.servers.len()],
            owner: self,
        })
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
        = BufStream<TlsStream<TcpStream>>
    where
        Self: 'a;

    fn uuid(&self) -> &Arc<str> {
        &self.server.uuid
    }

    fn name(&self) -> &Arc<str> {
        &self.server.domain
    }

    async fn support(
        &self,
        connection_type: ConnectionType,
    ) -> Result<
        (
            HashSet<ProtocolId>,
            HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        PoolError,
    > {
        fetch_support_data(
            self.connect(connection_type).await?,
            self.auth_key(),
            &self.owner.allowed_protocols,
            self.owner.timeout,
        )
        .await
    }

    async fn connect(
        &self,
        connection_type: ConnectionType,
    ) -> Result<Self::Connection<'_>, PoolError> {
        let addr = resolve_with_type(&self.server.connection_address, connection_type).await?;
        let io = TcpStream::connect(addr).await?;
        Ok(BufStream::new(
            self.owner
                .upstream_tls
                .connect(self.server.server_name.clone(), io)
                .await?,
        ))
    }

    fn auth_key(&self) -> String {
        super::calculate_auth_key(
            self.owner
                .base_server_secret
                .get(self.server.base_key_index)
                .map_or(&[], |v| v.as_bytes()),
            self.server.uuid.as_bytes(),
            self.server.randomizer.as_bytes(),
        )
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
        crate::test_init();
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            base_server_secret: vec![],
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let first_server = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
            .unwrap();
        let second_server = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
            .unwrap();
        assert_ne!(first_server.name(), second_server.name());
    }

    #[test]
    fn test_lookup_by_uuid() {
        crate::test_init();
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            base_server_secret: vec![],
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let server = manager.get_server_by_uuid("UUID-a").unwrap();
        assert_eq!(server.name().as_ref(), "a.test");

        let server = manager.get_server_by_uuid("UUID-b").unwrap();
        assert_eq!(server.name().as_ref(), "b.test");
    }

    #[test]
    fn test_respect_denied_if_possible() {
        crate::test_init();
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            base_server_secret: vec![],
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let server = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()])
            .unwrap();
        assert_ne!(server.name().as_ref(), "a.test");

        let server = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()])
            .unwrap();
        assert_ne!(server.name().as_ref(), "a.test");
    }

    #[test]
    fn test_ignore_denied_if_impossible() {
        crate::test_init();
        let manager = RoundRobinServerManager {
            servers: [
                KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "a.test".into(),
                    server_name: ServerName::try_from("a.test").unwrap(),
                    connection_address: ("a.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
                KeyExchangeServer {
                    uuid: "UUID-b".into(),
                    domain: "b.test".into(),
                    server_name: ServerName::try_from("b.test").unwrap(),
                    connection_address: ("b.test".into(), 4460),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                },
            ]
            .into(),
            uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            upstream_tls: upstream_tls_config(),
            base_server_secret: vec![],
            allowed_protocols: HashSet::new(),
            next_start: 0.into(),
            timeout: Duration::from_secs(1),
        };

        let first = manager
            .assign_server(
                "127.0.0.1:4460".parse().unwrap(),
                &["a.test".into(), "b.test".into()],
            )
            .unwrap();
        let second = manager
            .assign_server(
                "127.0.0.1:4460".parse().unwrap(),
                &["a.test".into(), "b.test".into()],
            )
            .unwrap();
        assert_ne!(first.name(), second.name());
    }
}
