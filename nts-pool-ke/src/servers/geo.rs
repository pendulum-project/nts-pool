use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use maxminddb::geoip2;
use phf::phf_map;
use rand::Rng;
use tokio::{net::TcpStream, task::spawn_blocking};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    nts::ProtocolId,
    servers::{
        ConnectionType, Server, ServerManager, fetch_support_data, load_upstream_tls,
        resolve_with_type,
    },
};

static CONTINENTS: phf::Map<&'static str, &'static str> = phf_map! {
    "AF" => "AFRICA",
    "AN" => "ANTARCTICA",
    "AS" => "ASIA",
    "EU" => "EUROPE",
    "NA" => "NORTH-AMERICA",
    "OC" => "OCEANIA",
    "SA" => "SOUTH_AMERICA",
};

const GLOBAL: &str = "@";

#[derive(Clone)]
pub struct GeographicServerManager {
    inner: Arc<RwLock<Arc<GeographicServerManagerInner>>>,
    upstream_tls: TlsConnector,
    allowed_protocols: Arc<HashSet<ProtocolId>>,
    timeout: Duration,
}

struct GeographicServerManagerInner {
    servers: Box<[KeyExchangeServer]>,
    regions_ipv4: HashMap<String, Vec<usize>>,
    regions_ipv6: HashMap<String, Vec<usize>>,
    geodb: maxminddb::Reader<Vec<u8>>,
    uuid_lookup: HashMap<String, usize>,
}

impl GeographicServerManager {
    pub async fn new(config: BackendConfig) -> std::io::Result<Self> {
        let upstream_tls = load_upstream_tls(&config).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(Arc::new(
                Self::load(
                    config.key_exchange_servers,
                    config
                        .geolocation_db
                        .ok_or(std::io::Error::other("Missing geolocation db"))?,
                )
                .await?,
            ))),
            upstream_tls,
            allowed_protocols: Arc::new(config.allowed_protocols),
            timeout: config.timesource_timeout,
        })
    }

    async fn load(
        servers: PathBuf,
        geodb: PathBuf,
    ) -> std::io::Result<GeographicServerManagerInner> {
        spawn_blocking(|| {
            let server_file = std::fs::File::open(servers)?;
            let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

            let mut regions_ipv4: HashMap<String, Vec<usize>> = HashMap::new();
            let mut regions_ipv6: HashMap<String, Vec<usize>> = HashMap::new();
            let mut uuid_lookup = HashMap::new();
            for (index, server) in servers.iter().enumerate() {
                uuid_lookup.insert(server.uuid.clone(), index);
                if server.ipv4_capable {
                    for region in &server.regions {
                        if let Some(region_list) = regions_ipv4.get_mut(region) {
                            region_list.push(index)
                        } else {
                            regions_ipv4.insert(region.clone(), vec![index]);
                        }
                    }
                }
                if server.ipv6_capable {
                    for region in &server.regions {
                        if let Some(region_list) = regions_ipv6.get_mut(region) {
                            region_list.push(index)
                        } else {
                            regions_ipv6.insert(region.clone(), vec![index]);
                        }
                    }
                }
            }
            regions_ipv4.insert(
                GLOBAL.into(),
                servers
                    .iter()
                    .enumerate()
                    .filter(|(_, server)| server.ipv4_capable)
                    .map(|(index, _)| index)
                    .collect(),
            );
            regions_ipv6.insert(
                GLOBAL.into(),
                servers
                    .iter()
                    .enumerate()
                    .filter(|(_, server)| server.ipv6_capable)
                    .map(|(index, _)| index)
                    .collect(),
            );

            let geodb = maxminddb::Reader::open_readfile(geodb).map_err(std::io::Error::other)?;

            Ok(GeographicServerManagerInner {
                servers,
                regions_ipv4,
                regions_ipv6,
                geodb,
                uuid_lookup,
            })
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

impl ServerManager for GeographicServerManager {
    type Server<'a>
        = GeographicServer
    where
        Self: 'a;

    fn assign_server(
        &self,
        address: std::net::SocketAddr,
        denied_servers: &[Cow<'_, str>],
    ) -> Self::Server<'_> {
        let inner = self.inner.read().unwrap().clone();
        let regions = if address.is_ipv4() {
            &inner.regions_ipv4
        } else {
            &inner.regions_ipv6
        };
        let region =
            if let Ok(Some(location)) = inner.geodb.lookup::<geoip2::Country>(address.ip()) {
                location
                    .country
                    .and_then(|v| v.iso_code)
                    .and_then(|v| regions.get(v))
                    .or_else(|| {
                        location
                            .continent
                            .and_then(|v| v.code)
                            .and_then(|v| CONTINENTS.get(v))
                            .and_then(|v| regions.get(*v))
                    })
            } else {
                None
            }
            .unwrap_or_else(|| regions.get(GLOBAL).unwrap());

        let start_index = (rand::rng().random::<u64>() as usize) % region.len();

        let (left, right) = region.split_at(start_index);
        let rotated_servers = right.iter().chain(left.iter()).copied();

        for index in rotated_servers {
            if denied_servers
                .iter()
                .any(|v| *v == inner.servers[index].domain)
            {
                continue;
            }

            return GeographicServer {
                inner,
                upstream_tls: self.upstream_tls.clone(),
                index,
                allowed_protocols: self.allowed_protocols.clone(),
                timeout: self.timeout,
            };
        }

        debug!("All servers denied. Falling back to denied server");

        GeographicServer {
            upstream_tls: self.upstream_tls.clone(),
            index: region[start_index],
            inner,
            allowed_protocols: self.allowed_protocols.clone(),
            timeout: self.timeout,
        }
    }

    fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
        let inner = self.inner.read().unwrap().clone();

        let index = inner.uuid_lookup.get(uuid.as_ref()).copied();
        index.map(move |index| GeographicServer {
            inner,
            upstream_tls: self.upstream_tls.clone(),
            allowed_protocols: self.allowed_protocols.clone(),
            timeout: self.timeout,
            index,
        })
    }
}

pub struct GeographicServer {
    inner: Arc<GeographicServerManagerInner>,
    upstream_tls: TlsConnector,
    allowed_protocols: Arc<HashSet<ProtocolId>>,
    timeout: Duration,
    index: usize,
}

impl Server for GeographicServer {
    type Connection<'a>
        = TlsStream<TcpStream>
    where
        Self: 'a;

    fn name(&self) -> &str {
        &self.inner.servers[self.index].domain
    }

    async fn support(
        &self,
    ) -> Result<
        (
            std::collections::HashSet<crate::nts::ProtocolId>,
            HashMap<crate::nts::AlgorithmId, crate::nts::AlgorithmDescription>,
        ),
        crate::error::PoolError,
    > {
        fetch_support_data(
            self.connect(ConnectionType::Either).await?,
            &self.allowed_protocols,
            self.timeout,
        )
        .await
    }

    async fn connect<'a>(
        &'a self,
        connection_type: ConnectionType,
    ) -> Result<Self::Connection<'a>, crate::error::PoolError> {
        let addr = resolve_with_type(
            &self.inner.servers[self.index].connection_address,
            connection_type,
        )
        .await?;
        let io = TcpStream::connect(addr).await?;
        Ok(self
            .upstream_tls
            .connect(self.inner.servers[self.index].server_name.clone(), io)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use maxminddb::Reader;
    use rustls::{
        RootCertStore,
        pki_types::{ServerName, pem::PemObject},
        version::TLS13,
    };

    use super::*;

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
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-a".into(),
                        domain: "a.test".into(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("a.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-b".into(),
                        domain: "b.test".into(),
                        server_name: ServerName::try_from("b.test").unwrap(),
                        connection_address: ("b.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([("@".into(), vec![0, 1])]),
                regions_ipv6: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: Arc::new(HashSet::new()),
            timeout: Duration::from_secs(1),
        };

        let first = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);

        let mut ok = false;
        // Assignment is probabilistic, but getting the same server 128 times in a row is exceedingly unlikely.
        for _ in 0..128 {
            let second = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
            if second.name() != first.name() {
                ok = true;
                break;
            }
        }
        assert!(ok);
    }

    #[test]
    fn test_respect_denied_if_possible() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-a".into(),
                        domain: "a.test".into(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("a.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-b".into(),
                        domain: "b.test".into(),
                        server_name: ServerName::try_from("b.test").unwrap(),
                        connection_address: ("b.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([("@".into(), vec![0, 1])]),
                regions_ipv6: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: Arc::new(HashSet::new()),
            timeout: Duration::from_secs(1),
        };

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");
    }

    #[test]
    fn test_ignore_denied_if_impossible() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-a".into(),
                        domain: "a.test".into(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("a.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-b".into(),
                        domain: "b.test".into(),
                        server_name: ServerName::try_from("b.test").unwrap(),
                        connection_address: ("b.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([("@".into(), vec![0, 1])]),
                regions_ipv6: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: Arc::new(HashSet::new()),
            timeout: Duration::from_secs(1),
        };

        let first = manager.assign_server(
            "127.0.0.1:4460".parse().unwrap(),
            &["a.test".into(), "b.test".into()],
        );
        assert!(first.name() == "a.test" || first.name() == "b.test");
    }

    #[test]
    fn test_region_handling() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-global".into(),
                        domain: "global.test".into(),
                        server_name: ServerName::try_from("global.test").unwrap(),
                        connection_address: ("global.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-eu".into(),
                        domain: "eu.test".into(),
                        server_name: ServerName::try_from("eu.test").unwrap(),
                        connection_address: ("eu.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-gb".into(),
                        domain: "gb.test".into(),
                        server_name: ServerName::try_from("gb.test").unwrap(),
                        connection_address: ("gb.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([
                    ("@".into(), vec![0]),
                    ("EUROPE".into(), vec![1]),
                    ("GB".into(), vec![2]),
                ]),
                regions_ipv6: HashMap::from([
                    ("@".into(), vec![0]),
                    ("EUROPE".into(), vec![1]),
                    ("GB".into(), vec![2]),
                ]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([
                    ("UUID-global".into(), 0),
                    ("UUID-eu".into(), 1),
                    ("UUID-gb".into(), 2),
                ]),
            }))),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: Arc::new(HashSet::new()),
            timeout: Duration::from_secs(1),
        };

        // GB
        let server = manager.assign_server("81.2.69.193:4460".parse().unwrap(), &[]);
        assert_eq!(server.name(), "gb.test");
        // SE
        let server = manager.assign_server("89.160.20.113:4460".parse().unwrap(), &[]);
        assert_eq!(server.name(), "eu.test");
        // US
        let server = manager.assign_server("50.114.0.1:4460".parse().unwrap(), &[]);
        assert_eq!(server.name(), "global.test");
    }

    #[test]
    fn test_v4_v6_handling() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-both".into(),
                        domain: "both.test".into(),
                        server_name: ServerName::try_from("both.test").unwrap(),
                        connection_address: ("both.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-ipv4".into(),
                        domain: "ipv4.test".into(),
                        server_name: ServerName::try_from("ipv4.test").unwrap(),
                        connection_address: ("ipv4.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: false,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-ipv6".into(),
                        domain: "ipv6.test".into(),
                        server_name: ServerName::try_from("ipv6.test").unwrap(),
                        connection_address: ("ipv6.test".into(), 4460),
                        regions: vec![],
                        ipv4_capable: false,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([("@".into(), vec![0, 1])]),
                regions_ipv6: HashMap::from([("@".into(), vec![0, 2])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([
                    ("UUID-both".into(), 0),
                    ("UUID-ipv4".into(), 1),
                    ("UUID-ipv6".into(), 2),
                ]),
            }))),
            upstream_tls: upstream_tls_config(),
            allowed_protocols: Arc::new(HashSet::new()),
            timeout: Duration::from_secs(1),
        };

        let ipv4 = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &[]);
        assert!(ipv4.inner.servers[ipv4.index].ipv4_capable);

        let ipv6 = manager.assign_server("[::]:4460".parse().unwrap(), &[]);
        assert!(ipv6.inner.servers[ipv6.index].ipv6_capable);
    }

    #[tokio::test]
    async fn test_server_list_parsing() {
        crate::test_init();
        let manager = GeographicServerManager::new(BackendConfig {
            upstream_cas: Some(
                format!("{}/testdata/testca.pem", env!("CARGO_MANIFEST_DIR")).into(),
            ),
            private_key: format!("{}/testdata/pool.test.key", env!("CARGO_MANIFEST_DIR")).into(),
            certificate_chain: format!(
                "{}/testdata/pool.test.fullchain.pem",
                env!("CARGO_MANIFEST_DIR")
            )
            .into(),
            key_exchange_servers: "testdata/testservers.json".into(),
            geolocation_db: Some("testdata/GeoLite2-Country-Test.mmdb".into()),
            allowed_protocols: HashSet::new(),
            timesource_timeout: Duration::from_secs(1),
        })
        .await
        .unwrap();

        let inner = manager.inner.read().unwrap();
        for (i, server) in inner.servers.iter().enumerate() {
            assert_eq!(
                inner.regions_ipv4.get(GLOBAL).unwrap().contains(&i),
                server.ipv4_capable
            );
            assert_eq!(
                inner.regions_ipv6.get(GLOBAL).unwrap().contains(&i),
                server.ipv6_capable
            );
            for region in server.regions.iter() {
                assert_eq!(
                    inner.regions_ipv4.get(region).unwrap().contains(&i),
                    server.ipv4_capable
                );
                assert_eq!(
                    inner.regions_ipv6.get(region).unwrap().contains(&i),
                    server.ipv6_capable
                );
            }
        }
    }
}
