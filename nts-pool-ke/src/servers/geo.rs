use std::{
    collections::{HashMap, HashSet},
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
    nts::ProtocolId,
    servers::{Server, ServerManager, fetch_support_data},
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
}

struct GeographicServerManagerInner {
    servers: Box<[KeyExchangeServer]>,
    regions: HashMap<String, Vec<usize>>,
    geodb: maxminddb::Reader<Vec<u8>>,
}

impl GeographicServerManager {
    pub async fn new(config: BackendConfig) -> std::io::Result<Self> {
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
            upstream_tls: config.upstream_tls,
            allowed_protocols: Arc::new(config.allowed_protocols),
        })
    }

    async fn load(
        servers: PathBuf,
        geodb: PathBuf,
    ) -> std::io::Result<GeographicServerManagerInner> {
        spawn_blocking(|| {
            let server_file = std::fs::File::open(servers)?;
            let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

            let mut regions: HashMap<String, Vec<usize>> = HashMap::new();
            for (index, server) in servers.iter().enumerate() {
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
        denied_servers: &[String],
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
            if denied_servers.contains(&inner.servers[index].domain) {
                continue;
            }

            return GeographicServer {
                inner,
                upstream_tls: self.upstream_tls.clone(),
                index,
                allowed_protocols: self.allowed_protocols.clone(),
            };
        }

        debug!("All servers denied. Falling back to denied server");

        GeographicServer {
            upstream_tls: self.upstream_tls.clone(),
            index: region[start_index],
            inner,
            allowed_protocols: self.allowed_protocols.clone(),
        }
    }
}

pub struct GeographicServer {
    inner: Arc<GeographicServerManagerInner>,
    upstream_tls: TlsConnector,
    allowed_protocols: Arc<HashSet<ProtocolId>>,
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
        fetch_support_data(self.connect().await?, &self.allowed_protocols).await
    }

    async fn connect<'a>(&'a self) -> Result<Self::Connection<'a>, crate::error::PoolError> {
        let io =
            TcpStream::connect(self.inner.servers[self.index].connection_address.clone()).await?;
        Ok(self
            .upstream_tls
            .connect(self.inner.servers[self.index].server_name.clone(), io)
            .await?)
    }
}
