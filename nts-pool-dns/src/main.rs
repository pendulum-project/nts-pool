use std::{path::PathBuf, sync::Arc};

use eyre::Context as _;
use hickory_server::proto::{dnssec::Algorithm, rr::Name};
use notify::{RecursiveMode, Watcher as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::rustls;
use tracing::{error, info};
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::{
    cli::NtsPoolDnsOptions,
    config::Config,
    geo_handler::{GeoHandler, GeoHandlerArc, GeoHandlerConfig},
    tracing_config::LogLevel,
    util::AbortingJoinHandle,
};

mod cli;
mod config;
mod geo_handler;
mod tracing_config;
mod util;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to init default crypto provider");

    let options = NtsPoolDnsOptions::try_parse_from(std::env::args())?;

    match options.action {
        cli::NtsPoolDnsAction::Help => {
            println!("{}", cli::long_help_message());
        }
        cli::NtsPoolDnsAction::Version => {
            eprintln!("nts-pool-dns {VERSION}");
        }
        cli::NtsPoolDnsAction::Run => main_run(options).await?,
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

    let config_tracing = tracing_config::tracing_init(log_level);
    let config = tracing::subscriber::with_default(config_tracing, || {
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
    let tracing_inst = tracing_config::tracing_init(log_level);
    tracing_inst.init();

    config
}

async fn main_run(options: NtsPoolDnsOptions) -> eyre::Result<()> {
    let config = initialize_logging_parse_config(options.log_level, options.config).await;

    // give the user a warning that we use the command line option
    if config.observability.log_level.is_some() && options.log_level.is_some() {
        info!("Log level override from command line arguments is active");
    }

    let result = run_nts_pool_dns(config).await;

    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            ::tracing::error!("Abnormal termination of NTS Pool DNS server: {e:?}");
            std::process::exit(exitcode::SOFTWARE)
        }
    }
}

async fn server_list_updater(
    handler: Arc<GeoHandler>,
    servers_list_path: PathBuf,
) -> eyre::Result<tokio::task::JoinHandle<()>> {
    info!(
        "Listening for changes to server list file at {:?}",
        servers_list_path
    );
    let (change_sender, mut change_receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
    // Use a poll watcher here as INotify can be unreliable in many ways and I don't want to deal with that.
    let mut watcher = notify::poll::PollWatcher::new(
        move |event: notify::Result<notify::Event>| {
            if event.is_ok() {
                let _ = change_sender.send(());
            }
        },
        notify::Config::default()
            .with_poll_interval(std::time::Duration::from_secs(60))
            .with_compare_contents(true),
    )
    .wrap_err("Could not create file watcher")?;

    watcher
        .watch(servers_list_path.as_path(), RecursiveMode::NonRecursive)
        .wrap_err("Could not watch servers list path")?;

    Ok(tokio::spawn(async move {
        // keep the watcher alive
        let _w = watcher;
        loop {
            change_receiver.recv().await;
            match handler.load_servers_list().await {
                Ok(_) => {
                    info!("Successfully reloaded server list");
                }
                Err(e) => {
                    error!("Could not reload server list: {}", e);
                }
            }
        }
    }))
}

async fn run_nts_pool_dns(config: Config) -> eyre::Result<()> {
    let zone_name = Name::from_utf8(config.zone.zone_name).wrap_err("Invalid zone name")?;
    let dns_server_name =
        Name::from_utf8(config.zone.dns_server_name).wrap_err("Invalid DNS server name")?;
    let responsible_name =
        Name::from_utf8(config.zone.responsible_name).wrap_err("Invalid responsible name")?;

    let geo_config = GeoHandlerConfig {
        zone_name: zone_name.clone(),
        dns_server_name: dns_server_name.clone(),
        responsible_name: responsible_name.clone(),
        key_path: config.zone.private_key_path.clone(),
        servers_list_path: config.zone.servers_list_path.clone(),
        algorithm: Algorithm::RSASHA256,
        sign_duration: config.zone.sign_duration,
        ttl: config.zone.sign_duration,
    };
    let geo_handler = Arc::new(
        GeoHandler::new(geo_config)
            .await
            .wrap_err("Failed to create GeoHandler")?,
    );

    let mut server = hickory_server::server::ServerFuture::new(GeoHandlerArc(geo_handler.clone()));
    let udp_socket = UdpSocket::bind(config.server.listen_addr)
        .await
        .wrap_err("Failed to bind UDP socket")?;
    let tcp_socket = TcpListener::bind(config.server.listen_addr)
        .await
        .wrap_err("Failed to bind TCP socket")?;

    tracing::info!(
        "Starting NTS Pool DNS server on UDP/TCP {}",
        config.server.listen_addr,
    );

    let _updater_handle: Arc<AbortingJoinHandle<_>> = Arc::new(
        server_list_updater(geo_handler.clone(), config.zone.servers_list_path.clone())
            .await?
            .into(),
    );

    server.register_socket(udp_socket);
    server.register_listener(tcp_socket, config.server.tcp_timeout);
    server.block_until_done().await.wrap_err("Server error")?;

    Ok(())
}
