use std::{collections::HashSet, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "ip_protocol"))]
#[cfg_attr(feature = "sqlx", sqlx(rename_all = "kebab-case"))]
pub enum IpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Serialize, Deserialize)]
pub struct ProbeControlCommand {
    pub timesources: HashSet<(IpVersion, String)>,
    pub poolke: String,
    pub result_endpoint: String,
    pub result_batchsize: usize,
    pub result_max_waittime: Duration,
    pub update_interval: Duration,
    pub probe_interval: Duration,
    pub nts_timeout: Duration,
    pub ntp_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub keyexchange: KeyExchangeProbeResult,
    pub ntp_with_ke_cookie: SecuredNtpProbeResult,
    pub ntp_with_ntp_cookie: SecuredNtpProbeResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyExchangeStatus {
    Success,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeyExchangeProbeResult {
    pub status: KeyExchangeStatus,
    pub exchange_start: u64,
    pub exchange_duration: f64,
    pub num_cookies: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SecuredNtpProbeStatus {
    Success,
    DnsLookupFailed,
    NtsNak,
    Deny,
    Timeout,
    #[default]
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct SecuredNtpProbeResult {
    pub status: SecuredNtpProbeStatus,
    pub request_sent: u64,
    pub roundtrip_duration: Option<f64>,
    pub remote_residence_time: Option<f64>,
    pub offset: Option<f64>,
    pub stratum: Option<u8>,
    pub leap_indicates_synchronized: bool,
    pub requested_cookies: usize,
    pub received_cookies: usize,
}
