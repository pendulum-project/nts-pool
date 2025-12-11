#![forbid(unsafe_code)]

use std::{fmt::Display, net::SocketAddr, path::PathBuf};

use nts_pool_shared::IpVersion;
use tracing_subscriber::util::SubscriberInitExt;

use crate::{cli::MonitorOptions, config::Config, control::run_probing, tracing::LogLevel};

mod cli;
mod config;
mod control;
mod identifiers;
mod io;
mod nts;
mod packet;
mod probe;
mod time_types;
mod tls_utils;
mod tracing;

use self::tracing as daemon_tracing;

async fn resolve_as_version<T: tokio::net::ToSocketAddrs>(
    addr: T,
    ipprot: IpVersion,
) -> std::io::Result<SocketAddr> {
    let resolved = tokio::net::lookup_host(addr).await?;

    for candidate in resolved {
        match (ipprot, candidate) {
            (IpVersion::Ipv4 | IpVersion::Srvv4, SocketAddr::V4(_))
            | (IpVersion::Ipv6 | IpVersion::Srvv6, SocketAddr::V6(_)) => {
                return Ok(candidate);
            }
            _ => {}
        }
    }

    Err(std::io::ErrorKind::NotFound.into())
}

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

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn monitor_main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to init default crypto provider");

    let options = MonitorOptions::try_parse_from(std::env::args())?;

    match options.action {
        cli::MonitorAction::Help => {
            eprintln!("pool-monitoring {VERSION}");
        }
        cli::MonitorAction::Version => {
            println!("{}", cli::long_help_message());
        }
        cli::MonitorAction::Run => run(options).await,
    }

    Ok(())
}

// initializes the logger so that logs during config parsing are reported. Then it overrides the
// log level based on the config if required.
async fn initialize_logging_parse_config(
    initial_log_level: Option<LogLevel>,
    config_path: Option<PathBuf>,
) -> Config {
    let mut log_level = initial_log_level.unwrap_or_default();

    let config_tracing = daemon_tracing::tracing_init(log_level);
    let config = ::tracing::subscriber::with_default(config_tracing, || {
        async {
            match config_path {
                None => {
                    eprintln!("no configuration path specified");
                    std::process::exit(exitcode::CONFIG);
                }
                Some(config_path) => {
                    match Config::from_args(config_path).await {
                        Ok(c) => c,
                        Err(e) => {
                            // print to stderr because tracing is not yet setup
                            eprintln!("There was an error loading the config: {e}");
                            std::process::exit(exitcode::CONFIG);
                        }
                    }
                }
            }
        }
    })
    .await;

    if let Some(config_log_level) = config.observability.log_level
        && initial_log_level.is_none()
    {
        log_level = config_log_level;
    }

    // set a default global subscriber from now on
    let tracing_inst = daemon_tracing::tracing_init(log_level);
    tracing_inst.init();

    config
}

async fn run(options: MonitorOptions) {
    let config = initialize_logging_parse_config(options.log_level, options.config).await;

    config.check();

    run_probing(config.monitoring).await
}

#[cfg(test)]
pub fn test_init() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
