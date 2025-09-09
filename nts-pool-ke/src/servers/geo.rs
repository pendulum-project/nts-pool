use std::{
    borrow::Cow,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use maxminddb::geoip2;
use phf::phf_map;
use rand::Rng;
use tokio::{net::TcpStream, task::spawn_blocking};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    servers::{Server, ServerManager, fetch_support_data, load_upstream_tls, tls_config_updater},
    util::AbortingJoinHandle,
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
    config: Arc<BackendConfig>,
    upstream_tls: Arc<RwLock<TlsConnector>>,
    // Kept around for its effect on drop.
    #[allow(unused)]
    tls_updater: Arc<AbortingJoinHandle<()>>,
}

struct GeographicServerManagerInner {
    servers: Box<[KeyExchangeServer]>,
    regions: HashMap<String, Vec<usize>>,
    geodb: maxminddb::Reader<Vec<u8>>,
    uuid_lookup: HashMap<String, usize>,
}

impl GeographicServerManager {
    pub async fn new(config: BackendConfig) -> std::io::Result<Self> {
        let upstream_tls = Arc::new(RwLock::new(load_upstream_tls(&config).await?));
        let config = Arc::new(config);
        let tls_updater = Arc::new(
            tls_config_updater(upstream_tls.clone(), config.clone())
                .await?
                .into(),
        );

        let result = Self {
            inner: Arc::new(RwLock::new(Arc::new(
                Self::load(
                    config.key_exchange_servers.clone(),
                    config
                        .geolocation_db
                        .clone()
                        .ok_or(std::io::Error::other("Missing geolocation db"))?,
                )
                .await?,
            ))),
            upstream_tls,
            config,
            tls_updater,
        };

        Ok(result)
    }

    async fn load(
        servers: PathBuf,
        geodb: PathBuf,
    ) -> std::io::Result<GeographicServerManagerInner> {
        spawn_blocking(|| {
            let server_file = std::fs::File::open(servers)?;
            let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

            let mut regions: HashMap<String, Vec<usize>> = HashMap::new();
            let mut uuid_lookup = HashMap::new();
            for (index, server) in servers.iter().enumerate() {
                uuid_lookup.insert(server.uuid.clone(), index);
                for region in &server.regions {
                    if let Some(region_list) = regions.get_mut(region) {
                        region_list.push(index)
                    } else {
                        regions.insert(region.clone(), vec![index]);
                    }
                }
            }
            regions.insert(GLOBAL.into(), (0..servers.len()).collect());

            let geodb = maxminddb::Reader::open_readfile(geodb).map_err(std::io::Error::other)?;

            Ok(GeographicServerManagerInner {
                servers,
                regions,
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
        let region =
            if let Ok(Some(location)) = inner.geodb.lookup::<geoip2::Country>(address.ip()) {
                location
                    .country
                    .and_then(|v| v.iso_code)
                    .and_then(|v| inner.regions.get(v))
                    .or_else(|| {
                        location
                            .continent
                            .and_then(|v| v.code)
                            .and_then(|v| CONTINENTS.get(v))
                            .and_then(|v| inner.regions.get(*v))
                    })
            } else {
                None
            }
            .unwrap_or_else(|| inner.regions.get(GLOBAL).unwrap());

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
                config: self.config.clone(),
            };
        }

        debug!("All servers denied. Falling back to denied server");

        GeographicServer {
            upstream_tls: self.upstream_tls.clone(),
            index: region[start_index],
            inner,
            config: self.config.clone(),
        }
    }

    fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
        let inner = self.inner.read().unwrap().clone();

        let index = inner.uuid_lookup.get(uuid.as_ref()).copied();
        index.map(move |index| GeographicServer {
            inner,
            upstream_tls: self.upstream_tls.clone(),
            config: self.config.clone(),
            index,
        })
    }
}

pub struct GeographicServer {
    inner: Arc<GeographicServerManagerInner>,
    upstream_tls: Arc<RwLock<TlsConnector>>,
    config: Arc<BackendConfig>,
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
            self.connect().await?,
            &self.config.allowed_protocols,
            self.config.timesource_timeout,
        )
        .await
    }

    async fn connect<'a>(&'a self) -> Result<Self::Connection<'a>, crate::error::PoolError> {
        let io =
            TcpStream::connect(self.inner.servers[self.index].connection_address.clone()).await?;
        let upstream_tls = self.upstream_tls.read().unwrap().clone();
        Ok(upstream_tls
            .connect(self.inner.servers[self.index].server_name.clone(), io)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

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

    #[tokio::test]
    async fn test_load_is_distributed() {
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
                regions: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
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

    #[tokio::test]
    async fn test_respect_denied_if_possible() {
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
                regions: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
        };

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");

        let server = manager.assign_server("127.0.0.1:4460".parse().unwrap(), &["a.test".into()]);
        assert_ne!(server.name(), "a.test");
    }

    #[tokio::test]
    async fn test_ignore_denied_if_impossible() {
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
                regions: HashMap::from([("@".into(), vec![0, 1])]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
        };

        let first = manager.assign_server(
            "127.0.0.1:4460".parse().unwrap(),
            &["a.test".into(), "b.test".into()],
        );
        assert!(first.name() == "a.test" || first.name() == "b.test");
    }

    #[tokio::test]
    async fn test_region_handling() {
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
                    },
                    KeyExchangeServer {
                        uuid: "UUID-eu".into(),
                        domain: "eu.test".into(),
                        server_name: ServerName::try_from("eu.test").unwrap(),
                        connection_address: ("eu.test".into(), 4460),
                        regions: vec![],
                    },
                    KeyExchangeServer {
                        uuid: "UUID-gb".into(),
                        domain: "gb.test".into(),
                        server_name: ServerName::try_from("gb.test").unwrap(),
                        connection_address: ("gb.test".into(), 4460),
                        regions: vec![],
                    },
                ]
                .into(),
                regions: HashMap::from([
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
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
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
            assert!(inner.regions.get(GLOBAL).unwrap().contains(&i));
            for region in server.regions.iter() {
                assert!(inner.regions.get(region).unwrap().contains(&i));
            }
        }
    }
}
