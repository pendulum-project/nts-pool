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
        rr::{Name, RData, Record, rdata::SOA},
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

    pub async fn load_servers_list(&self) -> eyre::Result<()> {
        let data = tokio::fs::read(self.config.servers_list_path.as_path())
            .await
            .wrap_err("Could not read servers list file")?;
        let _servers: Vec<KeyExchangeServer> =
            serde_json::from_slice(&data).wrap_err("Could not parse servers list file")?;

        // Re-sign zone
        self.sign_zone().await?;
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
