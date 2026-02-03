use std::{
    borrow::Cow,
    collections::HashMap,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, OnceLock, RwLock},
};

use maxminddb::geoip2;
use notify::{RecursiveMode, Watcher};
use opentelemetry::{KeyValue, metrics::Counter};
use phf::phf_map;
use pool_nts::{AlgorithmDescription, AlgorithmId, ProtocolId};
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufStream, ReadBuf},
    net::TcpStream,
    task::spawn_blocking,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::{debug, error};

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    servers::{
        ConnectionType, Server, ServerConnection, ServerManager, fetch_support_data,
        load_upstream_tls, resolve_with_type, tls_config_updater,
    },
    util::{AbortingJoinHandle, ArrayDeque},
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

struct ServerLookup {
    total_weight_including: usize,
    index: usize,
}

struct ServerSupportCacheEntry {
    age: tokio::time::Instant,
    data: (
        std::collections::HashSet<ProtocolId>,
        HashMap<AlgorithmId, AlgorithmDescription>,
    ),
}

const MAX_CACHED_PER_SERVER: usize = 5;

struct ServerConnectionCacheEntry {
    len_age: [tokio::time::Instant; MAX_CACHED_PER_SERVER],
    connections:
        ArrayDeque<MAX_CACHED_PER_SERVER, (tokio::time::Instant, BufStream<TlsStream<TcpStream>>)>,
}

impl Default for ServerConnectionCacheEntry {
    fn default() -> Self {
        Self {
            len_age: std::array::from_fn(|_| tokio::time::Instant::now()),
            connections: ArrayDeque::new(),
        }
    }
}

#[derive(Clone)]
pub struct GeographicServerManager {
    inner: Arc<RwLock<Arc<GeographicServerManagerInner>>>,
    server_support_cache: Arc<scc::HashMap<(ConnectionType, Arc<str>), ServerSupportCacheEntry>>,
    server_connection_cache:
        Arc<scc::HashMap<(ConnectionType, Arc<str>), ServerConnectionCacheEntry>>,
    config: Arc<BackendConfig>,
    upstream_tls: Arc<RwLock<TlsConnector>>,
    // Kept around for their effect on drop.
    #[allow(unused)]
    tls_updater: Arc<AbortingJoinHandle<()>>,
    #[allow(unused)]
    server_list_updater: Arc<AbortingJoinHandle<()>>,
    #[allow(unused)]
    cache_invalidator: Arc<AbortingJoinHandle<()>>,
}

struct GeographicServerManagerInner {
    servers: Box<[KeyExchangeServer]>,
    regions_ipv4: HashMap<String, Vec<ServerLookup>>,
    regions_ipv6: HashMap<String, Vec<ServerLookup>>,
    geodb: maxminddb::Reader<Vec<u8>>,
    uuid_lookup: HashMap<Arc<str>, usize>,
}

impl GeographicServerManager {
    pub async fn new(config: BackendConfig) -> std::io::Result<Self> {
        let upstream_tls = Arc::new(RwLock::new(load_upstream_tls(&config).await?));
        let config = Arc::new(config);
        let server_support_cache = Arc::new(scc::HashMap::new());
        let server_connection_cache = Arc::new(scc::HashMap::new());
        let tls_updater = Arc::new(
            tls_config_updater(upstream_tls.clone(), config.clone())
                .await?
                .into(),
        );
        let inner = Arc::new(RwLock::new(Arc::new(
            Self::load(
                config.key_exchange_servers.clone(),
                config
                    .geolocation_db
                    .clone()
                    .ok_or(std::io::Error::other("Missing geolocation db"))?,
            )
            .await?,
        )));
        let server_list_updater = Arc::new(
            Self::server_list_updater(inner.clone(), config.clone())
                .await?
                .into(),
        );
        let cache_invalidator = Arc::new(
            Self::cache_invalidator(
                inner.clone(),
                server_support_cache.clone(),
                server_connection_cache.clone(),
                config.clone(),
            )
            .into(),
        );

        let server_connection_cache_clone = server_connection_cache.clone();
        opentelemetry::global::meter("PoolKe")
            .u64_observable_gauge("cached_connections")
            .with_description("Number of currently cached connections.")
            .with_callback(move |observer| {
                server_connection_cache_clone.iter_sync(|key, value| {
                    observer.observe(
                        value.connections.size() as u64,
                        &[
                            KeyValue::new(
                                "ip-type",
                                match key.0 {
                                    ConnectionType::IpV4 => "ipv4",
                                    ConnectionType::IpV6 => "ipv6",
                                    ConnectionType::Either => "either",
                                },
                            ),
                            KeyValue::new("uuid", key.1.clone()),
                        ],
                    );
                    true
                });
            });

        let result = Self {
            inner,
            server_support_cache,
            server_connection_cache,
            upstream_tls,
            config,
            tls_updater,
            server_list_updater,
            cache_invalidator,
        };

        Ok(result)
    }

    fn cache_invalidator(
        serverdata: Arc<RwLock<Arc<GeographicServerManagerInner>>>,
        server_support_cache: Arc<
            scc::HashMap<(ConnectionType, Arc<str>), ServerSupportCacheEntry>,
        >,
        server_connection_cache: Arc<
            scc::HashMap<(ConnectionType, Arc<str>), ServerConnectionCacheEntry>,
        >,
        config: Arc<BackendConfig>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let serverdata = serverdata.read().unwrap().clone();
                server_support_cache
                    .iter_mut_async(|entry| {
                        if !serverdata.uuid_lookup.contains_key(&entry.0.1)
                            || entry.1.age + config.server_support_cache_validity
                                < tokio::time::Instant::now()
                        {
                            // delete old entry
                            let _ = entry.consume();
                        }
                        true
                    })
                    .await;
                let mut connections_to_dispose = Vec::new();
                server_connection_cache
                    .iter_mut_async(|entry| {
                        if !serverdata.uuid_lookup.contains_key(&entry.0.1) {
                            let mut consumed = entry.consume();
                            while let Some((_, connection)) = consumed.1.connections.pop() {
                                connections_to_dispose.push(connection);
                            }
                        }
                        true
                    })
                    .await;
                drop(serverdata);

                let next_timer = tokio::time::sleep(config.server_support_cache_validity);

                for mut connection in connections_to_dispose.into_iter() {
                    let _ = connection.shutdown().await;
                }

                next_timer.await;
            }
        })
    }

    async fn server_list_updater(
        inner: Arc<RwLock<Arc<GeographicServerManagerInner>>>,
        config: Arc<BackendConfig>,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
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
            .watch(
                config.geolocation_db.as_ref().unwrap(),
                RecursiveMode::NonRecursive,
            )
            .map_err(std::io::Error::other)?;
        watcher
            .watch(&config.key_exchange_servers, RecursiveMode::NonRecursive)
            .map_err(std::io::Error::other)?;

        Ok(tokio::spawn(async move {
            // keep the watcher alive
            let _w = watcher;
            loop {
                change_receiver.recv().await;
                match Self::load(
                    config.key_exchange_servers.clone(),
                    config.geolocation_db.clone().unwrap(),
                )
                .await
                {
                    Ok(new_inner) => {
                        *inner.write().unwrap() = Arc::new(new_inner);
                    }
                    Err(e) => {
                        tracing::error!("Could not reload tls configuration: {}", e);
                    }
                }
            }
        }))
    }

    async fn load(
        servers: PathBuf,
        geodb: PathBuf,
    ) -> std::io::Result<GeographicServerManagerInner> {
        spawn_blocking(|| {
            let server_file = std::fs::File::open(servers)?;
            let servers: Box<[KeyExchangeServer]> = serde_json::from_reader(server_file)?;

            let mut regions_ipv4: HashMap<String, Vec<ServerLookup>> = HashMap::new();
            let mut regions_ipv6: HashMap<String, Vec<ServerLookup>> = HashMap::new();
            let mut uuid_lookup = HashMap::new();
            for (index, server) in servers.iter().enumerate() {
                if uuid_lookup.insert(server.uuid.clone(), index).is_some() {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                if server.ipv4_capable {
                    for region in &server.regions {
                        if let Some(region_list) = regions_ipv4.get_mut(region) {
                            region_list.push(ServerLookup {
                                index,
                                total_weight_including: server.weight
                                    + region_list
                                        .last()
                                        .map(|v| v.total_weight_including)
                                        .unwrap_or(0),
                            })
                        } else {
                            regions_ipv4.insert(
                                region.clone(),
                                vec![ServerLookup {
                                    index,
                                    total_weight_including: server.weight,
                                }],
                            );
                        }
                    }
                }
                if server.ipv6_capable {
                    for region in &server.regions {
                        if let Some(region_list) = regions_ipv6.get_mut(region) {
                            region_list.push(ServerLookup {
                                index,
                                total_weight_including: server.weight
                                    + region_list
                                        .last()
                                        .map(|v| v.total_weight_including)
                                        .unwrap_or(0),
                            })
                        } else {
                            regions_ipv6.insert(
                                region.clone(),
                                vec![ServerLookup {
                                    index,
                                    total_weight_including: server.weight,
                                }],
                            );
                        }
                    }
                }
            }
            let mut ipv4weight = 0;
            regions_ipv4.insert(
                GLOBAL.into(),
                servers
                    .iter()
                    .enumerate()
                    .filter(|(_, server)| server.ipv4_capable)
                    .map(|(index, server)| {
                        ipv4weight += server.weight;
                        ServerLookup {
                            total_weight_including: ipv4weight,
                            index,
                        }
                    })
                    .collect(),
            );
            let mut ipv6weight = 0;
            regions_ipv6.insert(
                GLOBAL.into(),
                servers
                    .iter()
                    .enumerate()
                    .filter(|(_, server)| server.ipv6_capable)
                    .map(|(index, server)| {
                        ipv6weight += server.weight;
                        ServerLookup {
                            total_weight_including: ipv6weight,
                            index,
                        }
                    })
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

const MAX_SKIPS: usize = 3;

impl ServerManager for GeographicServerManager {
    type Server<'a>
        = GeographicServer
    where
        Self: 'a;

    fn assign_server(
        &self,
        address: std::net::SocketAddr,
        denied_servers: &[Cow<'_, str>],
    ) -> Option<Self::Server<'_>> {
        debug!("Assigning server through geolocation");
        let inner = self.inner.read().unwrap().clone();
        let regions = if address.is_ipv4() {
            &inner.regions_ipv4
        } else {
            &inner.regions_ipv6
        };
        let region = if let Ok(Some(location)) = inner
            .geodb
            .lookup(address.ip())
            .and_then(|r| r.decode::<geoip2::Country>())
        {
            debug!("Geolocation lookup for {:?}", location);
            location
                .country
                .iso_code
                .and_then(|v| regions.get(v))
                .or_else(|| {
                    debug!("Falling back to continent, country zone does not exist");
                    location
                        .continent
                        .code
                        .and_then(|v| CONTINENTS.get(v))
                        .and_then(|v| regions.get(*v))
                })
        } else {
            None
        }
        .unwrap_or_else(|| {
            debug!("Falling back to global, continent and country zone does not exist");
            regions.get(GLOBAL).unwrap()
        });

        if region.is_empty() {
            debug!("Selected region is empty");
            return None;
        }

        let total_weight = region.last().map(|v| v.total_weight_including).unwrap();
        struct Skip {
            weight: usize,
            above: usize,
        }
        let mut skips: Vec<Skip> = Vec::with_capacity(MAX_SKIPS);

        loop {
            // Make a choice by weight, removing the weights of the skipped servers
            let mut choice = rand::rng()
                .random_range(0..(total_weight - skips.iter().map(|v| v.weight).sum::<usize>()));
            // Compensate for the skipped servers
            for skip in &skips {
                if choice >= skip.above {
                    choice += skip.weight
                }
            }

            // Binary search always returns an error since we never return equal.
            // This provides the "boundary" between less returning elements and
            // greater returning elements, which is exactly the index of the
            // element we are looking for.
            //
            // Note that since choice < total_weight, pick is guaranteed to be
            // smaller than region.len()
            let pick = region
                .binary_search_by(|probe| {
                    if probe.total_weight_including <= choice {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                })
                .unwrap_err();

            if skips.len() + 1 < region.len()
                && skips.len() < MAX_SKIPS
                && denied_servers
                    .iter()
                    .any(|v| *v == *inner.servers[region[pick].index].domain)
            {
                let weight = inner.servers[region[pick].index].weight;
                skips.push(Skip {
                    above: region[pick].total_weight_including - weight,
                    weight,
                });
                skips.sort_by(|a, b| a.above.cmp(&b.above))
            } else {
                return Some(GeographicServer {
                    server_support_cache: self.server_support_cache.clone(),
                    server_connection_cache: self.server_connection_cache.clone(),
                    upstream_tls: self.upstream_tls.clone(),
                    index: region[pick].index,
                    inner,
                    config: self.config.clone(),
                });
            }
        }
    }

    fn get_server_by_uuid(&self, uuid: impl AsRef<str>) -> Option<Self::Server<'_>> {
        debug!("Getting server {} by uuid", uuid.as_ref());
        let inner = self.inner.read().unwrap().clone();

        let index = inner.uuid_lookup.get(uuid.as_ref()).copied();
        index.map(move |index| GeographicServer {
            inner,
            server_support_cache: self.server_support_cache.clone(),
            server_connection_cache: self.server_connection_cache.clone(),
            upstream_tls: self.upstream_tls.clone(),
            config: self.config.clone(),
            index,
        })
    }
}

pub struct GeographicServer {
    inner: Arc<GeographicServerManagerInner>,
    server_support_cache: Arc<scc::HashMap<(ConnectionType, Arc<str>), ServerSupportCacheEntry>>,
    server_connection_cache:
        Arc<scc::HashMap<(ConnectionType, Arc<str>), ServerConnectionCacheEntry>>,
    upstream_tls: Arc<RwLock<TlsConnector>>,
    config: Arc<BackendConfig>,
    index: usize,
}

impl Server for GeographicServer {
    type Connection<'a>
        = GeoCachedTlsStream
    where
        Self: 'a;

    fn uuid(&self) -> &Arc<str> {
        &self.inner.servers[self.index].uuid
    }

    fn name(&self) -> &Arc<str> {
        &self.inner.servers[self.index].domain
    }

    async fn support(
        &self,
        connection_type: ConnectionType,
    ) -> Result<
        (
            std::collections::HashSet<ProtocolId>,
            HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        crate::error::PoolError,
    > {
        let entry = self
            .server_support_cache
            .entry_async((connection_type, self.inner.servers[self.index].uuid.clone()))
            .await;
        match entry {
            scc::hash_map::Entry::Occupied(occupied_entry)
                if occupied_entry.age + self.config.server_support_cache_validity
                    > tokio::time::Instant::now() =>
            {
                Ok(occupied_entry.data.clone())
            }
            _ => {
                let data = fetch_support_data(
                    self.connect(connection_type).await?,
                    self.uuid().clone(),
                    self.auth_key(),
                    &self.config.allowed_protocols,
                    self.config.timesource_timeout,
                )
                .await?;
                Ok(entry
                    .insert_entry(ServerSupportCacheEntry {
                        age: tokio::time::Instant::now(),
                        data,
                    })
                    .data
                    .clone())
            }
        }
    }

    async fn connect<'a>(
        &'a self,
        connection_type: ConnectionType,
    ) -> Result<Self::Connection<'a>, crate::error::PoolError> {
        static CONNECTION_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();

        let connection_counter = CONNECTION_COUNTER.get_or_init(|| {
            opentelemetry::global::meter("PoolKe")
                .u64_counter("upstream_connections")
                .with_description(
                    "Number of connections made to upstream time sources for various requests.",
                )
                .build()
        });

        // First try the cache
        if let Some(mut entry) = self
            .server_connection_cache
            .get_async(&(connection_type, self.inner.servers[self.index].uuid.clone()))
            .await
        {
            while let Some((age, mut connection)) = entry.connections.pop() {
                let mut buf = [0u8; 4];
                let mut buf = ReadBuf::new(&mut buf);
                // There are two criteria used here for wether the connection is usable.
                //  1). we discard any connection that has been idle for more than self.config.server_connection_cache_duration
                //  2). we discard any connection that returns anything on trying to read it.
                //
                // We discard on anything when trying to read since all possible outcomes indicate a problematic connection, since
                //  - Errors are self-evidently problematic
                //  - Any data means that the state of the connection is not well understood
                //  - No data means and no error means the remote closed the connection.
                if age + self.config.server_connection_cache_duration > tokio::time::Instant::now()
                    && std::future::poll_fn(|cx| {
                        std::task::Poll::Ready(
                            Pin::new(&mut connection)
                                .poll_read(cx, &mut buf)
                                .is_pending(),
                        )
                    })
                    .await
                {
                    connection_counter.add(
                        1,
                        &[
                            KeyValue::new("uuid", self.uuid().clone()),
                            KeyValue::new("reused", true),
                        ],
                    );
                    return Ok(GeoCachedTlsStream {
                        inner: connection,
                        key: (connection_type, self.inner.servers[self.index].uuid.clone()),
                        config: self.config.clone(),
                        cache: self.server_connection_cache.clone(),
                    });
                }

                let _ = connection.shutdown().await;
            }
        }

        debug!(
            "Looking up name {:?}",
            self.inner.servers[self.index].connection_address
        );
        let addr = resolve_with_type(
            &self.inner.servers[self.index].connection_address,
            connection_type,
        )
        .await?;
        debug!("Connecting to {addr:?}");
        let io = TcpStream::connect(addr).await?;
        let upstream_tls = self.upstream_tls.read().unwrap().clone();
        let inner = BufStream::new(
            upstream_tls
                .connect(self.inner.servers[self.index].server_name.clone(), io)
                .await?,
        );
        connection_counter.add(
            1,
            &[
                KeyValue::new("uuid", self.uuid().clone()),
                KeyValue::new("reused", false),
            ],
        );
        Ok(GeoCachedTlsStream {
            inner,
            key: (connection_type, self.inner.servers[self.index].uuid.clone()),
            config: self.config.clone(),
            cache: self.server_connection_cache.clone(),
        })
    }

    fn auth_key(&self) -> String {
        super::calculate_auth_key(
            self.config
                .base_shared_secret
                .get(self.inner.servers[self.index].base_key_index)
                .map_or(&[], |v| v.as_bytes()),
            self.inner.servers[self.index].uuid.as_bytes(),
            self.inner.servers[self.index].randomizer.as_bytes(),
        )
    }
}

pub struct GeoCachedTlsStream {
    inner: BufStream<TlsStream<TcpStream>>,
    key: (ConnectionType, Arc<str>),
    config: Arc<BackendConfig>,
    cache: Arc<scc::HashMap<(ConnectionType, Arc<str>), ServerConnectionCacheEntry>>,
}

impl AsyncWrite for GeoCachedTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for GeoCachedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl ServerConnection for GeoCachedTlsStream {
    #[allow(unused)]
    async fn reuse(self) {
        let mut entry = self.cache.entry_async(self.key).await.or_default();
        // Don't add new connection if we had current amount of connections for at least 2 times the individual connection cache duration.
        if (entry.connections.is_empty()
            || entry.len_age[entry.connections.size() - 1]
                + self.config.server_connection_cache_duration
                + self.config.server_connection_cache_duration
                > tokio::time::Instant::now())
            && !entry.connections.is_full()
        {
            if let Some((_, mut conn)) = entry
                .connections
                .try_push((tokio::time::Instant::now(), self.inner))
            {
                error!("Could not add connection to cache even though it is not full");
                let _ = conn.shutdown().await;
                return;
            }
            let idx = entry.connections.size() - 1;
            entry.len_age[idx] = tokio::time::Instant::now();
        } else {
            // Replace the oldest entry
            if let Some((_, mut conn)) = entry.connections.pop() {
                let _ = conn.shutdown().await;
            } else {
                error!("Could not get connection from cache even though there should be one");
            }
            if let Some((_, mut conn)) = entry
                .connections
                .try_push((tokio::time::Instant::now(), self.inner))
            {
                error!("Could not add connection to cache even though it is not full");
                let _ = conn.shutdown().await;
            }
        }
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
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

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

    fn server_tls_config() -> TlsAcceptor {
        let cert_chain = rustls::pki_types::CertificateDer::pem_file_iter(format!(
            "{}/testdata/end.fullchain.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
        .collect::<Result<Vec<rustls::pki_types::CertificateDer>, _>>()
        .unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::from_pem_file(format!(
            "{}/testdata/end.key",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();

        let config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
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
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        let first = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
            .unwrap();

        let mut ok = false;
        // Assignment is probabilistic, but getting the same server 128 times in a row is exceedingly unlikely.
        for _ in 0..128 {
            let second = manager
                .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
                .unwrap();
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
                        randomizer: "".into(),
                        base_key_index: 0,
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
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
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
                        base_key_index: 0,
                        connection_address: ("b.test".into(), 4460),
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        let first = manager
            .assign_server(
                "127.0.0.1:4460".parse().unwrap(),
                &["a.test".into(), "b.test".into()],
            )
            .unwrap();
        assert!(first.name().as_ref() == "a.test" || first.name().as_ref() == "b.test");
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
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-eu".into(),
                        domain: "eu.test".into(),
                        server_name: ServerName::try_from("eu.test").unwrap(),
                        connection_address: ("eu.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-gb".into(),
                        domain: "gb.test".into(),
                        server_name: ServerName::try_from("gb.test").unwrap(),
                        connection_address: ("gb.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([
                    (
                        "@".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        }],
                    ),
                    (
                        "EUROPE".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 1,
                        }],
                    ),
                    (
                        "GB".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 2,
                        }],
                    ),
                ]),
                regions_ipv6: HashMap::from([
                    (
                        "@".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        }],
                    ),
                    (
                        "EUROPE".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 1,
                        }],
                    ),
                    (
                        "GB".into(),
                        vec![ServerLookup {
                            total_weight_including: 1,
                            index: 2,
                        }],
                    ),
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
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        // GB
        let server = manager
            .assign_server("81.2.69.193:4460".parse().unwrap(), &[])
            .unwrap();
        assert_eq!(server.name().as_ref(), "gb.test");
        // SE
        let server = manager
            .assign_server("89.160.20.113:4460".parse().unwrap(), &[])
            .unwrap();
        assert_eq!(server.name().as_ref(), "eu.test");
        // US
        let server = manager
            .assign_server("50.114.0.1:4460".parse().unwrap(), &[])
            .unwrap();
        assert_eq!(server.name().as_ref(), "global.test");
    }

    #[tokio::test]
    async fn test_v4_v6_handling() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-both".into(),
                        domain: "both.test".into(),
                        server_name: ServerName::try_from("both.test").unwrap(),
                        connection_address: ("both.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-ipv4".into(),
                        domain: "ipv4.test".into(),
                        server_name: ServerName::try_from("ipv4.test").unwrap(),
                        connection_address: ("ipv4.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: false,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-ipv6".into(),
                        domain: "ipv6.test".into(),
                        server_name: ServerName::try_from("ipv6.test").unwrap(),
                        connection_address: ("ipv6.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: false,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 2,
                        },
                    ],
                )]),
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
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        let ipv4 = manager
            .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
            .unwrap();
        assert!(ipv4.inner.servers[ipv4.index].ipv4_capable);

        let ipv6 = manager
            .assign_server("[::]:4460".parse().unwrap(), &[])
            .unwrap();
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
            base_shared_secret: vec![],
            certificate_chain: format!(
                "{}/testdata/pool.test.fullchain.pem",
                env!("CARGO_MANIFEST_DIR")
            )
            .into(),
            key_exchange_servers: "testdata/testservers.json".into(),
            geolocation_db: Some("testdata/GeoLite2-Country-Test.mmdb".into()),
            allowed_protocols: HashSet::new(),
            timesource_timeout: Duration::from_secs(1),
            server_support_cache_validity: Duration::from_secs(300),
            server_connection_cache_duration: Duration::from_secs(300),
        })
        .await
        .unwrap();

        let inner = manager.inner.read().unwrap();
        for (i, server) in inner.servers.iter().enumerate() {
            assert_eq!(
                inner
                    .regions_ipv4
                    .get(GLOBAL)
                    .unwrap()
                    .iter()
                    .any(|v| v.index == i),
                server.ipv4_capable
            );
            assert_eq!(
                inner
                    .regions_ipv6
                    .get(GLOBAL)
                    .unwrap()
                    .iter()
                    .any(|v| v.index == i),
                server.ipv6_capable
            );
            for region in server.regions.iter() {
                assert_eq!(
                    inner
                        .regions_ipv4
                        .get(region)
                        .unwrap()
                        .iter()
                        .any(|v| v.index == i),
                    server.ipv4_capable
                );
                assert_eq!(
                    inner
                        .regions_ipv6
                        .get(region)
                        .unwrap()
                        .iter()
                        .any(|v| v.index == i),
                    server.ipv6_capable
                );
            }
        }
    }

    #[tokio::test]
    async fn test_server_weighting_no_exclusion() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
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
                        weight: 2,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 3,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 3,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        // 500 trials, about 166 should be server with UUID-a as id
        let mut count_0 = 0;
        for _ in 0..500 {
            let server = manager
                .assign_server("127.0.0.1:4460".parse().unwrap(), &[])
                .unwrap();
            if server.index == 0 {
                count_0 += 1;
            }
        }
        // Failure bounds chosen such that only 1 in 10^10 executions will result in
        // failure by chance.
        assert!(count_0 >= 102);
        assert!(count_0 <= 235);
    }

    #[tokio::test]
    async fn test_server_weighting_with_exclusion() {
        crate::test_init();
        let manager = GeographicServerManager {
            inner: Arc::new(RwLock::new(Arc::new(GeographicServerManagerInner {
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
                        weight: 2,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                    KeyExchangeServer {
                        uuid: "UUID-c".into(),
                        domain: "c.test".into(),
                        server_name: ServerName::try_from("c.test").unwrap(),
                        connection_address: ("c.test".into(), 4460),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 4,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 3,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 3,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }))),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            tls_updater: Arc::new(tokio::spawn(async {}).into()),
            server_list_updater: Arc::new(tokio::spawn(async {}).into()),
            cache_invalidator: Arc::new(tokio::spawn(async {}).into()),
        };

        // 500 trials, about 166 should be server with UUID-a as id
        let mut count_0 = 0;
        for _ in 0..500 {
            let server = manager
                .assign_server("127.0.0.1:4460".parse().unwrap(), &["c.test".into()])
                .unwrap();
            if server.index == 0 {
                count_0 += 1;
            }
        }
        // Failure bounds chosen such that only 1 in 10^10 executions will result in
        // failure by chance.
        assert!(count_0 >= 102);
        assert!(count_0 <= 235);
    }

    #[tokio::test(start_paused = true)]
    async fn test_support_caching() {
        let server_support_cache = scc::HashMap::new();
        assert!(
            server_support_cache
                .insert_async(
                    (ConnectionType::IpV4, "UUID-a".into()),
                    ServerSupportCacheEntry {
                        age: tokio::time::Instant::now(),
                        data: (HashSet::new(), HashMap::new())
                    }
                )
                .await
                .is_ok()
        );

        let server = GeographicServer {
            inner: Arc::new(GeographicServerManagerInner {
                servers: [
                    KeyExchangeServer {
                        uuid: "UUID-a".into(),
                        domain: "a.test".into(),
                        server_name: ServerName::try_from("a.test").unwrap(),
                        connection_address: ("127.0.0.1".into(), 0),
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
                        connection_address: ("127.0.0.1".into(), 0),
                        base_key_index: 0,
                        randomizer: "".into(),
                        weight: 1,
                        regions: vec![],
                        ipv4_capable: true,
                        ipv6_capable: true,
                    },
                ]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![
                        ServerLookup {
                            total_weight_including: 1,
                            index: 0,
                        },
                        ServerLookup {
                            total_weight_including: 2,
                            index: 1,
                        },
                    ],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0), ("UUID-b".into(), 1)]),
            }),
            server_support_cache: Arc::new(server_support_cache),
            server_connection_cache: Arc::new(scc::HashMap::new()),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            index: 0,
        };

        assert!(server.support(ConnectionType::IpV4).await.is_ok());
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert!(server.support(ConnectionType::IpV4).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn test_connection_caching() {
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let client_connector = upstream_tls_config();

        let servertask = tokio::spawn(async move {
            let acceptor = server_tls_config();
            let mut connections = vec![];
            loop {
                let (conn, _) = server_listener.accept().await.unwrap();
                connections.push(acceptor.accept(conn).await.unwrap());
            }
        });

        let conn = client_connector
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(server_addr).await.unwrap(),
            )
            .await
            .unwrap();

        let cached_port = conn.get_ref().0.local_addr().unwrap().port();

        let server_connection_cache = scc::HashMap::new();
        let mut server_connection_entry = ServerConnectionCacheEntry::default();
        assert!(
            server_connection_entry
                .connections
                .try_push((tokio::time::Instant::now(), BufStream::new(conn)))
                .is_none()
        );

        assert!(
            server_connection_cache
                .insert_async(
                    (ConnectionType::IpV4, "UUID-a".into()),
                    server_connection_entry
                )
                .await
                .is_ok()
        );

        let server = GeographicServer {
            inner: Arc::new(GeographicServerManagerInner {
                servers: [KeyExchangeServer {
                    uuid: "UUID-a".into(),
                    domain: "localhost".into(),
                    server_name: ServerName::try_from("localhost").unwrap(),
                    connection_address: ("127.0.0.1".into(), server_addr.port()),
                    base_key_index: 0,
                    randomizer: "".into(),
                    weight: 1,
                    regions: vec![],
                    ipv4_capable: true,
                    ipv6_capable: true,
                }]
                .into(),
                regions_ipv4: HashMap::from([(
                    "@".into(),
                    vec![ServerLookup {
                        total_weight_including: 1,
                        index: 0,
                    }],
                )]),
                regions_ipv6: HashMap::from([(
                    "@".into(),
                    vec![ServerLookup {
                        total_weight_including: 1,
                        index: 0,
                    }],
                )]),
                geodb: Reader::from_source(
                    include_bytes!("../../testdata/GeoLite2-Country-Test.mmdb").to_vec(),
                )
                .unwrap(),
                uuid_lookup: HashMap::from([("UUID-a".into(), 0)]),
            }),
            server_support_cache: Arc::new(scc::HashMap::new()),
            server_connection_cache: Arc::new(server_connection_cache),
            upstream_tls: Arc::new(RwLock::new(upstream_tls_config())),
            config: Arc::new(BackendConfig {
                upstream_cas: None,
                certificate_chain: "/".into(),
                private_key: "/".into(),
                base_shared_secret: vec![],
                key_exchange_servers: "/".into(),
                allowed_protocols: HashSet::new(),
                geolocation_db: None,
                timesource_timeout: Duration::from_secs(1),
                server_support_cache_validity: Duration::from_secs(300),
                server_connection_cache_duration: Duration::from_secs(300),
            }),
            index: 0,
        };

        let conn = server.connect(ConnectionType::IpV4).await.unwrap();
        assert_eq!(
            conn.inner
                .get_ref()
                .get_ref()
                .0
                .local_addr()
                .unwrap()
                .port(),
            cached_port
        );
        conn.reuse().await;

        let conn = server.connect(ConnectionType::IpV4).await.unwrap();
        assert_eq!(
            conn.inner
                .get_ref()
                .get_ref()
                .0
                .local_addr()
                .unwrap()
                .port(),
            cached_port
        );
        conn.reuse().await;

        tokio::time::sleep(Duration::from_secs(600)).await;

        let conn = server.connect(ConnectionType::IpV4).await.unwrap();
        assert_ne!(
            conn.inner
                .get_ref()
                .get_ref()
                .0
                .local_addr()
                .unwrap()
                .port(),
            cached_port
        );
        conn.reuse().await;

        servertask.abort();
    }
}
