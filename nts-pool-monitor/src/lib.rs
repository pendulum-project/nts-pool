use std::fmt::Display;

use crate::{cookiestash::CookieStash, packet::Cipher};

mod cookiestash;
mod identifiers;
mod io;
mod nts;
mod packet;
mod time_types;
mod tls_utils;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum NtpVersion {
    V3,
    V4,
    V5,
}

impl NtpVersion {
    pub fn as_u8(self) -> u8 {
        self.into()
    }
}

#[derive(Debug)]
pub struct InvalidNtpVersion(u8);

impl Display for InvalidNtpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid NTP version: {}", self.0)
    }
}

impl std::error::Error for InvalidNtpVersion {}

impl TryFrom<u8> for NtpVersion {
    type Error = InvalidNtpVersion;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(NtpVersion::V3),
            4 => Ok(NtpVersion::V4),
            5 => Ok(NtpVersion::V5),
            e => Err(InvalidNtpVersion(e)),
        }
    }
}

impl From<NtpVersion> for u8 {
    fn from(value: NtpVersion) -> Self {
        match value {
            NtpVersion::V3 => 3,
            NtpVersion::V4 => 4,
            NtpVersion::V5 => 5,
        }
    }
}

pub struct SourceNtsData {
    pub cookies: CookieStash,
    // Note: we use Box<dyn Cipher> to support the use
    // of multiple different ciphers, that might differ
    // in the key information they need to keep.
    pub c2s: Box<dyn Cipher>,
    pub s2c: Box<dyn Cipher>,
}

impl std::fmt::Debug for SourceNtsData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceNtsData")
            .field("cookies", &self.cookies)
            .finish()
    }
}

pub use nts::{KeyExchangeClient, NtsClientConfig};
pub use packet::NtpPacket;
pub use time_types::PollInterval;
pub use tls_utils::pemfile::certs;