use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use eyre::Context as _;
use hickory_server::{
    authority::{Catalog, DnssecAuthority},
    proto::{
        dnssec::{Algorithm, SigSigner, SigningKey, crypto::signing_key_from_der, rdata::DNSKEY},
        rr::{
            Name, RData, Record, RecordSet, RecordType, RrKey,
            rdata::{SOA, SRV},
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use nts_pool_shared::KeyExchangeServer;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, pem::PemObject as _};

async fn load_key(
    path: impl AsRef<Path>,
    algorithm: Algorithm,
) -> Result<Box<dyn SigningKey>, eyre::Report> {
    let key_pem = tokio::fs::read(path)
        .await
        .wrap_err("Could not read PEM file")?;
    let private_key =
        PrivateKeyDer::from_pem_reader(&key_pem[..]).wrap_err("Could not parse PEM file")?;
    let signing_key = signing_key_from_der(&private_key, algorithm)
        .wrap_err("Could not create signing key from DER")?;

    Ok(signing_key)
}

pub struct GeoHandler {
    config: GeoHandlerConfig,
    catalog: Catalog,
    authority: Arc<InMemoryAuthority>,
}

#[derive(Debug, Clone)]
pub struct GeoHandlerConfig {
    pub zone_name: Name,
    pub dns_server_name: Name,
    pub responsible_name: Name,
    pub key_path: PathBuf,
    pub servers_list_path: PathBuf,
    pub algorithm: Algorithm,
    pub sign_duration: Duration,
    pub ttl: Duration,
}

impl GeoHandlerConfig {
    pub async fn load_key(&self) -> eyre::Result<Box<dyn SigningKey>> {
        load_key(&self.key_path, self.algorithm).await
    }
}

impl GeoHandler {
    pub async fn new(config: GeoHandlerConfig) -> eyre::Result<Self> {
        let mut catalog = Catalog::new();

        let authority = Self::create_authority(&config)
            .await
            .wrap_err("Failed to create authority")?;

        catalog.upsert(config.zone_name.clone().into(), vec![authority.clone()]);

        let handler = GeoHandler {
            config,
            catalog,
            authority,
        };
        handler
            .load_servers_list()
            .await
            .wrap_err("Failed to load servers list")?;

        Ok(handler)
    }

    async fn create_authority(config: &GeoHandlerConfig) -> eyre::Result<Arc<InMemoryAuthority>> {
        let key = config.load_key().await?;
        let public_key = key.to_public_key().wrap_err("Failed to get public key")?;
        let signer = SigSigner::dnssec(
            DNSKEY::from_key(&public_key),
            key,
            config.zone_name.clone(),
            config.sign_duration,
        );

        let mut authority = InMemoryAuthority::empty(
            config.zone_name.clone(),
            hickory_server::authority::ZoneType::Primary,
            false,
            None,
        );

        let current_ts_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .wrap_err("Failed to get current unix timestamp")?
            .as_secs();
        let serial = current_ts_unix as u32; // intentional truncating behavior for serial number

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

        authority
            .add_zone_signing_key_mut(signer)
            .wrap_err("Failed to add zone signing key")?;
        authority
            .secure_zone_mut()
            .wrap_err("Failed to sign zone")?;

        Ok(Arc::new(authority))
    }

    /// Loads the servers list from the configured path and updates the SRV records accordingly.
    pub async fn load_servers_list(&self) -> eyre::Result<()> {
        let data = tokio::fs::read(self.config.servers_list_path.as_path())
            .await
            .wrap_err("Could not read servers list file")?;
        let servers: Vec<KeyExchangeServer> =
            serde_json::from_slice(&data).wrap_err("Could not parse servers list file")?;

        let current_ts_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .wrap_err("Failed to get current unix timestamp")?
            .as_secs();
        let serial = current_ts_unix as u32; // intentional truncating behavior for serial number

        // Create SRV record set
        let mut rrset = RecordSet::new(self.config.zone_name.clone(), RecordType::SRV, serial);
        for server in servers {
            let record = SRV::new(
                0,
                0,
                server.port,
                server.domain.parse().wrap_err("Invalid domain name")?,
            );
            rrset.add_rdata(RData::SRV(record));
        }

        // Key under which the SRV record set is stored
        let rrkey = RrKey::new(self.config.zone_name.clone().into(), RecordType::SRV);

        // Update SRV record set
        self.authority
            .records_mut()
            .await
            .insert(rrkey, Arc::new(rrset));

        // Re-sign zone
        self.sign_zone().await.wrap_err("Failed to sign zone")?;
        Ok(())
    }

    pub async fn sign_zone(&self) -> eyre::Result<()> {
        self.authority
            .secure_zone()
            .await
            .wrap_err("Failed to sign zone")?;
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
        // let client_addr = request.src().ip();
        self.0.catalog.handle_request(request, response).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_test_key() {
        load_key("testdata/pool.test.key", Algorithm::RSASHA256)
            .await
            .expect("Failed to load test key");
    }

    #[tokio::test]
    async fn create_test_handler() {
        let config = GeoHandlerConfig {
            zone_name: "pool.test.".parse().unwrap(),
            dns_server_name: "ns1.pool.test.".parse().unwrap(),
            responsible_name: "admin.pool.test.".parse().unwrap(),
            key_path: "testdata/pool.test.key".into(),
            servers_list_path: "testdata/testservers.json".into(),
            algorithm: Algorithm::RSASHA256,
            sign_duration: Duration::from_secs(120),
            ttl: Duration::from_secs(300),
        };

        let authority = GeoHandler::new(config)
            .await
            .expect("Failed to create test handler");
        authority
            .authority
            .records()
            .await
            .iter()
            .for_each(|(key, _record)| {
                assert_eq!(key.name(), &Name::from_ascii("pool.test.").unwrap().into());
            });
        assert!(
            authority
                .catalog
                .contains(&Name::from_ascii("pool.test.").unwrap().into())
        );
    }
}
