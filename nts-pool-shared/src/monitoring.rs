use std::{collections::HashSet, time::Duration};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(feature = "sqlx", sqlx(type_name = "ip_protocol"))]
#[cfg_attr(feature = "sqlx", sqlx(rename_all = "kebab-case"))]
pub enum IpVersion {
    Ipv4,
    Ipv6,
    Srvv4,
    Srvv6,
}

impl IpVersion {
    pub fn is_srv(self) -> bool {
        matches!(self, IpVersion::Srvv4 | IpVersion::Srvv6)
    }

    pub fn other_ip_protocol(self) -> Self {
        match self {
            IpVersion::Ipv4 => IpVersion::Ipv6,
            IpVersion::Ipv6 => IpVersion::Ipv4,
            IpVersion::Srvv4 => IpVersion::Srvv6,
            IpVersion::Srvv6 => IpVersion::Srvv4,
        }
    }
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::Ipv4 => write!(f, "IPv4"),
            IpVersion::Ipv6 => write!(f, "IPv6"),
            IpVersion::Srvv4 => write!(f, "SRVv4"),
            IpVersion::Srvv6 => write!(f, "SRVv6"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ProbeTimesourceInfo {
    pub uuid: String,
    pub domain: Option<String>,
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct ProbeControlCommand {
    pub timesources: HashSet<(IpVersion, ProbeTimesourceInfo)>,
    pub poolke: String,
    pub result_endpoint: String,
    pub result_batchsize: usize,
    pub result_max_waittime: Duration,
    pub update_interval: Duration,
    pub probe_interval: Duration,
    pub nts_timeout: Duration,
    pub ntp_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub keyexchange: KeyExchangeProbeResult,
    pub ntp_with_ke_cookie: SecuredNtpProbeResult,
    pub ntp_with_ntp_cookie: SecuredNtpProbeResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyExchangeStatus {
    Success,
    SrvIpv4Only,
    SrvIpv6Only,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyExchangeProbeResult {
    pub status: KeyExchangeStatus,
    pub description: String,
    pub exchange_start: u64,
    pub exchange_duration: f64,
    pub num_cookies: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SecuredNtpProbeStatus {
    Success,
    DnsLookupFailed,
    CouldNotConnect,
    CouldNotSend,
    CouldNotReceive,
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
