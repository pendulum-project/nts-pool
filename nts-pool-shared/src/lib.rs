use serde::{Deserialize, Serialize};

mod monitoring;
pub use monitoring::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct KeyExchangeServer {
    pub uuid: String,
    pub domain: String,
    pub port: u16,
    #[serde(default)]
    pub weight: Option<usize>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub ipv4_capable: Option<bool>,
    #[serde(default)]
    pub ipv6_capable: Option<bool>,
}
