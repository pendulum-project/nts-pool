extern crate rustls23 as rustls;

mod cli;
mod config;

mod nts;
mod tracing;

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use ::tracing::{debug, info};
use cli::NtsPoolKeOptions;
use config::{Config, NtsPoolKeConfig};
use rustls::{pki_types::CertificateDer, version::TLS13, ServerConnection};
use rustls23::pki_types::pem::PemObject;
use rustls_platform_verifier::Verifier;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, ToSocketAddrs},
};
use tokio_rustls::TlsConnector;

use crate::{
    config::KeyExchangeServer,
    nts::{
        AlgorithmDescription, AlgorithmId, ClientRequest, ErrorCode, ErrorResponse,
        FixedKeyRequest, KeyExchangeResponse, NoAgreementResponse, NtsError, ProtocolId,
        ServerInformationRequest, ServerInformationResponse,
    },
};

use self::tracing as daemon_tracing;
use daemon_tracing::LogLevel;
use tracing_subscriber::util::SubscriberInitExt;

pub(crate) mod exitcode {
    /// An internal software error has been detected.  This
    /// should be limited to non-operating system related
    /// errors as possible.
    pub const SOFTWARE: i32 = 70;

    /// Something was found in an unconfigured or misconfigured state.
    pub const CONFIG: i32 = 78;
}

#[derive(Debug)]
enum PoolError {
    NtsError(NtsError),
    IO(std::io::Error),
    Rustls(rustls::Error),
}

impl From<NtsError> for PoolError {
    fn from(value: NtsError) -> Self {
        PoolError::NtsError(value)
    }
}

impl From<std::io::Error> for PoolError {
    fn from(value: std::io::Error) -> Self {
        PoolError::IO(value)
    }
}

impl From<rustls::Error> for PoolError {
    fn from(value: rustls::Error) -> Self {
        PoolError::Rustls(value)
    }
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtsError(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            Self::Rustls(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PoolError {}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn nts_pool_ke_main() -> Result<(), Box<dyn std::error::Error>> {
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

    if let Some(config_log_level) = config.observability.log_level {
        if initial_log_level.is_none() {
            log_level = config_log_level;
        }
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

    let result = run_nts_pool_ke(config.nts_pool_ke_server).await;

    match result {
        Ok(v) => Ok(v),
        Err(e) => {
            ::tracing::error!("Abnormal termination of NTS KE server: {e}");
            std::process::exit(exitcode::SOFTWARE)
        }
    }
}

async fn run_nts_pool_ke(nts_pool_ke_config: NtsPoolKeConfig) -> std::io::Result<()> {
    let certificate_authority_file =
        std::fs::File::open(&nts_pool_ke_config.certificate_authority_path).map_err(|e| {
            io_error(&format!(
                "error reading certificate_authority_path at `{:?}`: {:?}",
                nts_pool_ke_config.certificate_authority_path, e
            ))
        })?;

    let certificate_chain_file = std::fs::File::open(&nts_pool_ke_config.certificate_chain_path)
        .map_err(|e| {
            io_error(&format!(
                "error reading certificate_chain_path at `{:?}`: {:?}",
                nts_pool_ke_config.certificate_chain_path, e
            ))
        })?;

    let private_key_file =
        std::fs::File::open(&nts_pool_ke_config.private_key_path).map_err(|e| {
            io_error(&format!(
                "error reading key_der_path at `{:?}`: {:?}",
                nts_pool_ke_config.private_key_path, e
            ))
        })?;

    let certificate_authority: Arc<[rustls::pki_types::CertificateDer]> =
        rustls::pki_types::CertificateDer::pem_reader_iter(&mut std::io::BufReader::new(
            certificate_authority_file,
        ))
        .map(|item| {
            item.map_err(|err| match err {
                rustls::pki_types::pem::Error::Io(error) => error,
                _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            })
        })
        .collect::<std::io::Result<Arc<[rustls::pki_types::CertificateDer]>>>()?;

    let certificate_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls::pki_types::CertificateDer::pem_reader_iter(&mut std::io::BufReader::new(
            certificate_chain_file,
        ))
        .map(|item| {
            item.map_err(|err| match err {
                rustls::pki_types::pem::Error::Io(error) => error,
                _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            })
        })
        .collect::<std::io::Result<Vec<rustls::pki_types::CertificateDer>>>()?;

    let private_key = rustls::pki_types::PrivateKeyDer::from_pem_reader(
        &mut std::io::BufReader::new(private_key_file),
    )
    .map_err(|err| match err {
        rustls::pki_types::pem::Error::Io(error) => error,
        _ => std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
    })?;

    pool_key_exchange_server(
        nts_pool_ke_config.listen,
        certificate_authority,
        certificate_chain,
        private_key,
        nts_pool_ke_config.key_exchange_servers,
        nts_pool_ke_config.key_exchange_timeout_ms,
    )
    .await
}

fn io_error(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

async fn pool_key_exchange_server(
    address: impl ToSocketAddrs,
    certificate_authority: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    servers: Vec<config::KeyExchangeServer>,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;

    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_no_client_auth()
        .with_single_cert(certificate_chain.clone(), private_key.clone_key())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    config.alpn_protocols.clear();
    config.alpn_protocols.push(b"ntske/1".to_vec());

    let config = Arc::new(config);
    let servers: Arc<[_]> = servers.into();

    info!("listening on '{:?}'", listener.local_addr());

    loop {
        let (client_stream, source_address) = listener.accept().await?;
        let client_to_pool_config = config.clone();
        let servers = servers.clone();
        let certificate_chain = certificate_chain.clone();
        let private_key = private_key.clone_key();

        let certificate_authority = certificate_authority.clone();
        let fut = handle_client(
            client_stream,
            client_to_pool_config,
            certificate_authority,
            certificate_chain,
            private_key,
            servers,
        );

        tokio::spawn(async move {
            let timeout = std::time::Duration::from_millis(timeout_ms);
            match tokio::time::timeout(timeout, fut).await {
                Err(_) => ::tracing::debug!(?source_address, "NTS Pool KE timed out"),
                Ok(Err(err)) => ::tracing::debug!(?err, ?source_address, "NTS Pool KE failed"),
                Ok(Ok(())) => ::tracing::debug!(?source_address, "NTS Pool KE completed"),
            }
        });
    }
}

fn pick_nts_ke_servers<'a>(
    servers: &'a [config::KeyExchangeServer],
    denied_servers: &[String],
) -> &'a KeyExchangeServer {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static START_INDEX: AtomicUsize = AtomicUsize::new(0);
    let start_index = START_INDEX.fetch_add(1, Ordering::Relaxed);

    // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
    // permanently cripple the pool
    let (left, right) = servers.split_at(start_index % servers.len());
    let rotated_servers = right.iter().chain(left.iter());

    for server in rotated_servers {
        if denied_servers.contains(&server.domain) {
            continue;
        }

        return server;
    }

    debug!("All servers denied. Falling back to denied server");

    &servers[start_index % servers.len()]
}

async fn handle_client(
    client_stream: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    certificate_authority: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
    servers: Arc<[config::KeyExchangeServer]>,
) -> Result<(), PoolError> {
    // handle the initial client to pool
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let mut client_stream = acceptor.accept(client_stream).await?;

    let client_request = match ClientRequest::parse(&mut client_stream).await {
        Ok(client_request) => client_request,
        Err(e @ NtsError::Invalid) => {
            ErrorResponse {
                errorcode: ErrorCode::BadRequest,
            }
            .serialize(&mut client_stream)
            .await?;
            client_stream.shutdown().await?;
            return Err(e.into());
        }
        // Nothing we can do for the other errors as the connection is the main culprit.
        Err(e) => return Err(e.into()),
    };

    debug!("Recevied request from client");

    let pick = pick_nts_ke_servers(&servers, &client_request.denied_servers);

    let connector =
        match pool_to_server_connector(&certificate_authority, certificate_chain, private_key) {
            Ok(connector) => connector,
            Err(e) => {
                // Report the internal server error to the client
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
                }
                .serialize(&mut client_stream)
                .await?;
                client_stream.shutdown().await?;
                return Err(e);
            }
        };

    let (protocol, algorithm) =
        match select_protocol_algorithm(&client_request, &connector, pick).await {
            Ok(Some(result)) => result,
            Ok(None) => {
                NoAgreementResponse.serialize(&mut client_stream).await?;
                client_stream.shutdown().await?;
                return Ok(());
            }
            Err(e) => {
                ErrorResponse {
                    errorcode: ErrorCode::InternalServerError,
                }
                .serialize(&mut client_stream)
                .await?;
                client_stream.shutdown().await?;
                return Err(e);
            }
        };
    let (c2s, s2c) = match extract_keys(client_stream.get_ref().1, protocol, algorithm) {
        Ok(result) => result,
        Err(e) => {
            ErrorResponse {
                errorcode: ErrorCode::InternalServerError,
            }
            .serialize(&mut client_stream)
            .await?;
            client_stream.shutdown().await?;
            return Err(e);
        }
    };

    debug!("fetching cookies from the NTS KE server");

    let result = match perform_upstream_key_exchange(
        FixedKeyRequest {
            c2s,
            s2c,
            protocol,
            algorithm: algorithm.id,
        },
        &connector,
        pick,
    )
    .await
    {
        // These errors indicate the pool did something weird
        Err(e @ NtsError::Error(ErrorCode::BadRequest))
        | Err(e @ NtsError::Error(ErrorCode::UnrecognizedCriticalRecord)) => {
            ErrorResponse {
                errorcode: ErrorCode::InternalServerError,
            }
            .serialize(&mut client_stream)
            .await?;
            Err(e.into())
        }
        // Pass other errors from the server on unchanged
        Err(e @ NtsError::Error(errorcode)) => {
            ErrorResponse { errorcode }
                .serialize(&mut client_stream)
                .await?;
            Err(e.into())
        }
        // All other errors indicate we are doing something strange
        Err(e) => {
            ErrorResponse {
                errorcode: ErrorCode::InternalServerError,
            }
            .serialize(&mut client_stream)
            .await?;
            Err(e.into())
        }
        Ok(mut response) => {
            if response.server.is_none() {
                response.server = Some(pick.domain.clone());
            }
            response.serialize(&mut client_stream).await?;
            Ok(())
        }
    };
    client_stream.shutdown().await?;
    result
}

fn extract_keys(
    tls_connection: &ServerConnection,
    protocol: u16,
    algorithm: AlgorithmDescription,
) -> Result<(Vec<u8>, Vec<u8>), PoolError> {
    let mut c2s = vec![0; algorithm.keysize.into()];
    let mut s2c = vec![0; algorithm.keysize.into()];
    tls_connection.export_keying_material(
        &mut c2s,
        b"EXPORTER-network-time-security",
        Some(&[
            (protocol >> 8) as u8,
            protocol as u8,
            (algorithm.id >> 8) as u8,
            algorithm.id as u8,
            0,
        ]),
    )?;
    tls_connection.export_keying_material(
        &mut s2c,
        b"EXPORTER-network-time-security",
        Some(&[
            (protocol >> 8) as u8,
            protocol as u8,
            (algorithm.id >> 8) as u8,
            algorithm.id as u8,
            1,
        ]),
    )?;
    Ok((c2s, s2c))
}

async fn select_protocol_algorithm(
    client_request: &ClientRequest,
    connector: &TlsConnector,
    server: &KeyExchangeServer,
) -> Result<Option<(ProtocolId, AlgorithmDescription)>, PoolError> {
    let server_stream =
        tokio::net::TcpStream::connect((server.domain.as_str(), server.port)).await?;
    let mut server_stream = connector
        .connect(server.server_name.clone(), server_stream)
        .await?;
    ServerInformationRequest
        .serialize(&mut server_stream)
        .await?;
    let support_info = ServerInformationResponse::parse(&mut server_stream).await?;
    server_stream.shutdown().await?;
    let supported_protocols: HashSet<ProtocolId> =
        support_info.supported_protocols.into_iter().collect();
    let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
        .supported_algorithms
        .into_iter()
        .map(|v| (v.id, v))
        .collect();
    let mut protocol = None;
    for candidate_protocol in client_request.protocols.iter() {
        if supported_protocols.contains(candidate_protocol) {
            protocol = Some(*candidate_protocol);
            break;
        }
    }
    let mut algorithm = None;
    for candidate_algorithm in client_request.algorithms.iter() {
        if let Some(algdesc) = supported_algorithms.get(candidate_algorithm) {
            algorithm = Some(*algdesc);
        }
    }
    Ok(match (protocol, algorithm) {
        (Some(protocol), Some(algorithm)) => Some((protocol, algorithm)),
        _ => None,
    })
}

async fn perform_upstream_key_exchange(
    request: FixedKeyRequest,
    connector: &TlsConnector,
    server: &KeyExchangeServer,
) -> Result<KeyExchangeResponse, NtsError> {
    // TODO: Implement connection reuse
    let server_stream =
        tokio::net::TcpStream::connect((server.domain.as_str(), server.port)).await?;
    let mut server_stream = connector
        .connect(server.server_name.clone(), server_stream)
        .await?;

    request.serialize(&mut server_stream).await?;
    KeyExchangeResponse::parse(&mut server_stream).await
}

fn pool_to_server_connector(
    extra_certificates: &[CertificateDer<'static>],
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<tokio_rustls::TlsConnector, PoolError> {
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&TLS13]);
    let provider = builder.crypto_provider().clone();
    let verifier =
        Verifier::new_with_extra_roots(extra_certificates.iter().cloned())?.with_provider(provider);

    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certificate_chain, private_key)
        .unwrap();

    // already has the FixedKeyRequest record
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}
