use std::{net::IpAddr, sync::Arc};

use eyre::{Context as _, Report};
use phf::phf_map;

use crate::error::AppError;

pub static CONTINENTS: phf::Map<&'static str, &'static str> = phf_map! {
    "AF" => "AFRICA",
    "AN" => "ANTARCTICA",
    "AS" => "ASIA",
    "EU" => "EUROPE",
    "NA" => "NORTH-AMERICA",
    "OC" => "OCEANIA",
    "SA" => "SOUTH_AMERICA",
};

pub async fn load_geodb(
    geodb_path: &std::path::Path,
) -> Result<Arc<maxminddb::Reader<Vec<u8>>>, AppError> {
    let geodb_raw = tokio::fs::read(geodb_path)
        .await
        .wrap_err("Could not load geolocation database from disk")?;

    Ok(Arc::new(
        maxminddb::Reader::from_source(geodb_raw).wrap_err("Invalid geolocation database")?,
    ))
}

pub trait GeoLookupSource {
    fn lookup(&self, ip: IpAddr) -> Result<GeoLookupResult, Report>;
}

impl<T> GeoLookupSource for maxminddb::Reader<T>
where
    T: AsRef<[u8]>,
{
    fn lookup(&self, ip: IpAddr) -> Result<GeoLookupResult, Report> {
        let lookup = self
            .lookup(ip)
            .and_then(|r| r.decode::<maxminddb::geoip2::Country>())?;

        let (continent, country) = if let Some(lookup) = &lookup {
            let continent = lookup
                .continent
                .code
                .and_then(|c| CONTINENTS.get(c))
                .map(|continent| continent.to_string());
            let country = lookup.country.iso_code.map(|country| country.to_string());

            (continent, country)
        } else {
            (None, None)
        };

        Ok(GeoLookupResult {
            country_iso_code: country,
            continent_code: continent,
        })
    }
}

pub struct GeoLookupResult {
    pub country_iso_code: Option<String>,
    pub continent_code: Option<String>,
}

impl GeoLookupResult {
    pub fn new(country_iso_code: Option<String>, continent_code: Option<String>) -> Self {
        Self {
            country_iso_code,
            continent_code,
        }
    }
}
