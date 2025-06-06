use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use rustls::ServerConnection;
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing::{debug, info};

use crate::{
    config::{self, KeyExchangeServer, NtsPoolKeConfig},
    nts::{
        AlgorithmDescription, AlgorithmId, ClientRequest, ErrorCode, ErrorResponse,
        FixedKeyRequest, KeyExchangeResponse, NoAgreementResponse, NtsError, ProtocolId,
        ServerInformationRequest, ServerInformationResponse,
    },
};

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

pub async fn run_nts_pool_ke(nts_pool_ke_config: NtsPoolKeConfig) -> std::io::Result<()> {
    let pool_ke = NtsPoolKe::new(nts_pool_ke_config)?;

    Arc::new(pool_ke).serve().await
}

struct NtsPoolKe {
    config: NtsPoolKeConfig,
}

impl NtsPoolKe {
    fn new(config: NtsPoolKeConfig) -> std::io::Result<Self> {
        Ok(NtsPoolKe { config })
    }

    async fn serve(self: Arc<Self>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen).await?;

        info!("listening on '{:?}'", listener.local_addr());

        loop {
            let (client_stream, source_address) = listener.accept().await?;
            let self_clone = self.clone();

            tokio::spawn(async move {
                match tokio::time::timeout(
                    self_clone.config.key_exchange_timeout,
                    self_clone.handle_client(client_stream),
                )
                .await
                {
                    Err(_) => ::tracing::debug!(?source_address, "NTS Pool KE timed out"),
                    Ok(Err(err)) => ::tracing::debug!(?err, ?source_address, "NTS Pool KE failed"),
                    Ok(Ok(())) => ::tracing::debug!(?source_address, "NTS Pool KE completed"),
                }
            });
        }
    }

    async fn handle_client(&self, client_stream: tokio::net::TcpStream) -> Result<(), PoolError> {
        // handle the initial client to pool
        let mut client_stream = self.config.server_tls.accept(client_stream).await?;

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

        let pick = self.pick_nts_ke_servers(&client_request.denied_servers);

        let (protocol, algorithm) =
            match self.select_protocol_algorithm(&client_request, pick).await {
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
        let (c2s, s2c) = match self.extract_keys(client_stream.get_ref().1, protocol, algorithm) {
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

        let result = match self
            .perform_upstream_key_exchange(
                FixedKeyRequest {
                    c2s,
                    s2c,
                    protocol,
                    algorithm: algorithm.id,
                },
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
        &self,
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
        &self,
        client_request: &ClientRequest,
        server: &KeyExchangeServer,
    ) -> Result<Option<(ProtocolId, AlgorithmDescription)>, PoolError> {
        let server_stream =
            tokio::net::TcpStream::connect((server.domain.as_str(), server.port)).await?;
        let mut server_stream = self
            .config
            .upstream_tls
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
        &self,
        request: FixedKeyRequest,
        server: &config::KeyExchangeServer,
    ) -> Result<KeyExchangeResponse, NtsError> {
        // TODO: Implement connection reuse
        let server_stream =
            tokio::net::TcpStream::connect((server.domain.as_str(), server.port)).await?;
        let mut server_stream = self
            .config
            .upstream_tls
            .connect(server.server_name.clone(), server_stream)
            .await?;

        request.serialize(&mut server_stream).await?;
        KeyExchangeResponse::parse(&mut server_stream).await
    }

    fn pick_nts_ke_servers<'a>(
        &'a self,
        denied_servers: &[String],
    ) -> &'a config::KeyExchangeServer {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static START_INDEX: AtomicUsize = AtomicUsize::new(0);
        let start_index = START_INDEX.fetch_add(1, Ordering::Relaxed);

        // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
        // permanently cripple the pool
        let servers = &self.config.key_exchange_servers;
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
}
