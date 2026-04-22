use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use eyre::Context as _;
use hickory_server::{
    authority::Catalog,
    proto::{
        dnssec::{Algorithm, SigSigner, SigningKey, crypto::signing_key_from_der, rdata::DNSKEY},
        rr::{
            Name, RData, Record, RecordSet, RecordType, RrKey,
            rdata::{NS, SOA, SRV},
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use maxminddb::geoip2;
use nts_pool_shared::KeyExchangeServer;
use phf::phf_map;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, pem::PemObject as _};

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

async fn load_key(
    path: impl AsRef<Path>,
    algorithm: Algorithm,
) -> Result<SharedSigningKey, eyre::Report> {
    let key_pem = tokio::fs::read(path)
        .await
        .wrap_err("Could not read PEM file")?;
    let private_key =
        PrivateKeyDer::from_pem_reader(&key_pem[..]).wrap_err("Could not parse PEM file")?;
    let signing_key = signing_key_from_der(&private_key, algorithm)
        .wrap_err("Could not create signing key from DER")?;

    Ok(signing_key.into())
}

#[derive(Clone)]
pub struct SharedSigningKey(Arc<dyn SigningKey>);

impl From<Box<dyn SigningKey>> for SharedSigningKey {
    fn from(value: Box<dyn SigningKey>) -> Self {
        Self(value.into())
    }
}

impl SigningKey for SharedSigningKey {
    fn sign(
        &self,
        tbs: &hickory_server::proto::dnssec::TBS,
    ) -> hickory_server::proto::dnssec::DnsSecResult<Vec<u8>> {
        self.0.sign(tbs)
    }

    fn to_public_key(
        &self,
    ) -> hickory_server::proto::dnssec::DnsSecResult<hickory_server::proto::dnssec::PublicKeyBuf>
    {
        self.0.to_public_key()
    }

    fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }
}

#[derive(Debug, Clone)]
pub struct GeoHandlerConfig {
    pub zone_name: Name,
    pub dns_server_name: Name,
    pub responsible_name: Name,
    pub key_path: PathBuf,
    pub servers_list_path: PathBuf,
    pub geolocation_db_path: PathBuf,
    pub algorithm: Algorithm,
    pub sign_duration: Duration,
    pub ttl: Duration,
}

impl GeoHandlerConfig {
    pub async fn load_key(&self) -> eyre::Result<SharedSigningKey> {
        load_key(&self.key_path, self.algorithm).await
    }
}

pub struct GeoHandlerInner {
    geodb: maxminddb::Reader<Vec<u8>>,
    regions: HashMap<String, Catalog>,
}

impl GeoHandlerInner {
    pub async fn load(config: &GeoHandlerConfig) -> eyre::Result<Self> {
        // Determine serial to use
        let create_time = tokio::fs::metadata(config.servers_list_path.as_path())
            .await
            .wrap_err("Could not get update time of servers list")?
            .modified()
            .wrap_err("Could not get update time of server list")?
            .duration_since(SystemTime::UNIX_EPOCH)
            .wrap_err("Could not get update time of server list")?
            .as_secs();

        let data = tokio::fs::read(config.servers_list_path.as_path())
            .await
            .wrap_err("Could not read servers list file")?;

        let create_time_check = tokio::fs::metadata(config.servers_list_path.as_path())
            .await
            .wrap_err("Could not get update time of servers list")?
            .modified()
            .wrap_err("Could not get update time of server list")?
            .duration_since(SystemTime::UNIX_EPOCH)
            .wrap_err("Could not get update time of server list")?
            .as_secs();

        // Deal with the potential race condition between statting the file and reading it.
        if create_time != create_time_check {
            return Err(eyre::eyre!("Race between read and update of server list."));
        }

        // Derive a serial for all the records. The truncation here is deliberate.
        let serial = create_time as u32;

        let servers: Vec<KeyExchangeServer> =
            serde_json::from_slice(&data).wrap_err("Could not parse servers list file")?;

        let mut regions = HashMap::new();

        for server in &servers {
            Self::add_to_region(&mut regions, GLOBAL, server, serial, config)?;
            for region in &server.regions {
                Self::add_to_region(&mut regions, region, server, serial, config)?;
            }
        }

        // Convert the records to catalogs and sign them
        let signing_key = config.load_key().await?;

        let regions = regions
            .into_iter()
            .map(|(k, v)| {
                let public_key = signing_key
                    .to_public_key()
                    .wrap_err("Failed to get public key")?;
                let signer = SigSigner::dnssec(
                    DNSKEY::from_key(&public_key),
                    Box::new(signing_key.clone()),
                    config.zone_name.clone(),
                    config.sign_duration,
                );

                let mut authority = InMemoryAuthority::empty(
                    config.zone_name.clone(),
                    hickory_server::authority::ZoneType::Primary,
                    false,
                    None,
                );

                let ttl_secs = config
                    .ttl
                    .as_secs()
                    .try_into()
                    .wrap_err("TTL value too large")?;

                let soa = RData::SOA(SOA::new(
                    config.dns_server_name.clone(),
                    config.responsible_name.clone(),
                    serial,
                    3600,
                    600,
                    86400,
                    ttl_secs,
                ));
                let soa_record = Record::from_rdata(config.zone_name.clone(), ttl_secs, soa);
                authority.upsert_mut(soa_record, serial);
                let ns = RData::NS(NS(config.dns_server_name.clone()));
                let ns_record = Record::from_rdata(config.zone_name.clone(), ttl_secs, ns);
                authority.upsert_mut(ns_record, serial);
                authority.records_get_mut().insert(
                    RrKey::new(config.zone_name.clone().into(), RecordType::SRV),
                    Arc::new(v),
                );

                authority
                    .add_zone_signing_key_mut(signer)
                    .wrap_err("Failed to add zone signing key")?;
                authority
                    .secure_zone_mut()
                    .wrap_err("Failed to sign zone")?;

                let mut catalog = Catalog::new();
                catalog.upsert(config.zone_name.clone().into(), vec![Arc::new(authority)]);
                Ok((k, catalog))
            })
            .collect::<eyre::Result<HashMap<_, _>>>()?;

        let geodb = maxminddb::Reader::from_source(
            tokio::fs::read(config.geolocation_db_path.as_path())
                .await
                .wrap_err("Could not load Geolocation DB")?,
        )
        .wrap_err("Could not load Geolocation DB")?;

        Ok(Self { geodb, regions })
    }

    fn add_to_region(
        regions: &mut HashMap<String, RecordSet>,
        regionname: &str,
        server: &KeyExchangeServer,
        serial: u32,
        config: &GeoHandlerConfig,
    ) -> eyre::Result<()> {
        let region_lookup = regions
            .entry(regionname.to_owned())
            .or_insert_with(|| RecordSet::new(config.zone_name.clone(), RecordType::SRV, serial));
        let record = SRV::new(
            0,
            0,
            server.port,
            server.domain.parse().wrap_err("Invalid domain name")?,
        );
        region_lookup.add_rdata(RData::SRV(record));
        Ok(())
    }
}

impl GeoHandlerInner {
    fn lookup_region(&self, client_addr: IpAddr) -> &Catalog {
        if let Ok(Some(location)) = self
            .geodb
            .lookup(client_addr)
            .and_then(|r| r.decode::<geoip2::Country>())
        {
            location
                .country
                .iso_code
                .and_then(|v| self.regions.get(v))
                .or_else(|| {
                    location
                        .continent
                        .code
                        .and_then(|v| CONTINENTS.get(v))
                        .and_then(|v| self.regions.get(*v))
                })
        } else {
            None
        }
        .unwrap_or_else(|| self.regions.get(GLOBAL).unwrap())
    }
}

pub struct GeoHandler {
    config: GeoHandlerConfig,
    inner: Arc<Mutex<Arc<GeoHandlerInner>>>,
}

impl GeoHandler {
    pub async fn new(config: GeoHandlerConfig) -> eyre::Result<Self> {
        let inner = Arc::new(Mutex::new(Arc::new(GeoHandlerInner::load(&config).await?)));

        Ok(Self { config, inner })
    }

    pub async fn reload(&self) -> eyre::Result<()> {
        let new_inner = Arc::new(GeoHandlerInner::load(&self.config).await?);

        *self.inner.lock().unwrap() = new_inner;

        Ok(())
    }
}

/// Helper wrapper to allow us to implement RequestHandler for `Arc<GeoHandler>`
pub struct GeoHandlerArc(pub Arc<GeoHandler>);

#[async_trait::async_trait]
impl RequestHandler for GeoHandlerArc {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        let inner = self.0.inner.lock().unwrap().clone();
        let region = inner.lookup_region(request.src().ip());
        region.handle_request(request, response).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use hickory_server::{authority::LookupOptions, proto::rr::LowerName};

    use super::*;

    #[tokio::test]
    async fn load_test_key() {
        load_key("testdata/pool.test.key", Algorithm::RSASHA256)
            .await
            .expect("Failed to load test key");
    }

    async fn test_lookup(
        catalog: &Catalog,
        name: &LowerName,
        rtype: RecordType,
    ) -> impl Iterator<Item = Record> {
        let mut lookup_objs = vec![];
        for authority in catalog.find(name).iter().flat_map(|v| v.iter()) {
            lookup_objs.push(
                authority
                    .lookup(name, rtype, LookupOptions::default())
                    .await
                    .map_result()
                    .transpose()
                    .unwrap(),
            );
        }

        lookup_objs
            .into_iter()
            .flatten()
            .flat_map(|v| v.iter().cloned().collect::<Vec<_>>().into_iter())
    }

    #[tokio::test]
    async fn create_test_handler() {
        let config = GeoHandlerConfig {
            zone_name: "pool.test.".parse().unwrap(),
            dns_server_name: "ns1.pool.test.".parse().unwrap(),
            responsible_name: "admin.pool.test.".parse().unwrap(),
            key_path: "testdata/pool.test.key".into(),
            servers_list_path: "testdata/testservers.json".into(),
            geolocation_db_path: "testdata/GeoLite2-Country-Test.mmdb".into(),
            algorithm: Algorithm::RSASHA256,
            sign_duration: Duration::from_secs(120),
            ttl: Duration::from_secs(300),
        };

        let authority = GeoHandler::new(config)
            .await
            .expect("Failed to create test handler");
        let inner = authority.inner.lock().unwrap().clone();

        for (_, region) in inner.regions.iter() {
            assert!(region.contains(&Name::from_ascii("pool.test.").unwrap().into()));

            for record in test_lookup(
                region,
                &Name::from_ascii("pool.test.").unwrap().into(),
                RecordType::ANY,
            )
            .await
            {
                assert_eq!(record.name(), &Name::from_ascii("pool.test.").unwrap());
            }
        }

        // Check the NL Zone is correct
        let region = inner.regions.get("NL").unwrap();
        let domains: HashSet<String> = test_lookup(
            region,
            &Name::from_ascii("pool.test.").unwrap().into(),
            RecordType::SRV,
        )
        .await
        .filter_map(|v| Record::<SRV>::try_from(v).ok())
        .map(|v| v.data().target().to_string())
        .collect();
        assert_eq!(domains, HashSet::from(["a.test".into(), "c.test".into()]));

        // Lookup from GB should give the EUROPE zone
        let region = inner.lookup_region("81.2.69.193".parse().unwrap());
        let domains: HashSet<String> = test_lookup(
            region,
            &Name::from_ascii("pool.test.").unwrap().into(),
            RecordType::SRV,
        )
        .await
        .filter_map(|v| Record::<SRV>::try_from(v).ok())
        .map(|v| v.data().target().to_string())
        .collect();
        assert_eq!(domains, HashSet::from(["a.test".into()]));
    }
}
