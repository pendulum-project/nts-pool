#![forbid(unsafe_code)]
#![cfg_attr(feature = "fuzz", allow(private_interfaces))]

mod cli;
mod config;
mod error;
mod haproxy;
mod pool_ke;
mod servers;
mod tracing;
mod util;

use std::path::PathBuf;

use cli::NtsPoolKeOptions;
use config::Config;

use crate::{
    pool_ke::run_nts_pool_ke,
    servers::{GeographicServerManager, RoundRobinServerManager},
};

use self::tracing as daemon_tracing;
use daemon_tracing::LogLevel;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(feature = "fuzz")]
pub use util::BufferBorrowingReader;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn nts_pool_ke_main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to init default crypto provider");

    let options = NtsPoolKeOptions::try_parse_from(std::env::args())?;

    match options.action {
        cli::NtsPoolKeAction::Help => {
            println!("{}", cli::long_help_message());
        }
        cli::NtsPoolKeAction::Version => {
            eprintln!("nts-pool-ke {VERSION}");
        }
        cli::NtsPoolKeAction::Run => run(options).await?,
    }

    Ok(())
}

// initializes the logger so that logs during config parsing are reported. Then it overrides the
// log level based on the config if required.
pub(crate) async fn initialize_logging_parse_config(
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

async fn run(options: NtsPoolKeOptions) -> Result<(), Box<dyn std::error::Error>> {
    let config = initialize_logging_parse_config(options.log_level, options.config).await;

    // give the user a warning that we use the command line option
    if config.observability.log_level.is_some() && options.log_level.is_some() {
        ::tracing::info!("Log level override from command line arguments is active");
    }

    // Warn/error if the config is unreasonable. We do this after finishing
    // tracing setup to ensure logging is fully configured.
    config.check();

    let result = if config.backend.geolocation_db.is_some() {
        let backend = GeographicServerManager::new(config.backend).await?;
        run_nts_pool_ke(config.server, backend).await
    } else {
        let backend = RoundRobinServerManager::new(config.backend).await?;
        run_nts_pool_ke(config.server, backend).await
    };

    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            ::tracing::error!("Abnormal termination of NTS KE server: {e}");
            std::process::exit(exitcode::SOFTWARE)
        }
    }
}

#[cfg(test)]
pub fn test_init() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
