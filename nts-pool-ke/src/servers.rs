use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::atomic::AtomicUsize,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tracing::debug;

use crate::{
    config::{BackendConfig, KeyExchangeServer},
    error::PoolError,
    nts::{
        AlgorithmDescription, AlgorithmId, ProtocolId, ServerInformationRequest,
        ServerInformationResponse,
    },
};

pub trait ServerManager: Sync + Send {
    type Server<'a>: Server + 'a
    where
        Self: 'a;

    /// Select a server for a client at the given address, taking into acount
    /// any denied servers.
    ///
    /// Denied servers need not be respected if no other options are available
    fn assign_server(&self, address: SocketAddr, denied_servers: &[String]) -> Self::Server<'_>;
}

pub trait Server: Sync + Send {
    type Connection<'a>: ServerConnection + 'a
    where
        Self: 'a;

    /// Name of the server, to be passed in the server record if the server
    /// itself doesn't provide one.
    fn name(&self) -> &str;

    /// Fetch which protocols and algorithms a server supports.
    fn support(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                HashSet<ProtocolId>,
                HashMap<AlgorithmId, AlgorithmDescription>,
            ),
            PoolError,
        >,
    > + Send;

    /// Open a connection to the server.
    fn connect<'a>(
        &'a self,
    ) -> impl Future<Output = Result<Self::Connection<'a>, PoolError>> + Send;
}

pub trait ServerConnection: AsyncRead + AsyncWrite + Unpin + Send {
    /// Return the connection to be reused later.
    #[allow(unused)]
    fn reuse(self) -> impl Future<Output = ()> + Send;
}

pub struct RoundRobinServerManager {
    servers: Box<[KeyExchangeServer]>,
    upstream_tls: TlsConnector,
    next_start: AtomicUsize,
}

impl RoundRobinServerManager {
    pub fn new(config: BackendConfig) -> Self {
        Self {
            servers: config.key_exchange_servers,
            upstream_tls: config.upstream_tls,
            next_start: AtomicUsize::new(0),
        }
    }
}

impl ServerManager for RoundRobinServerManager {
    type Server<'a>
        = RoundRobinServer<'a>
    where
        Self: 'a;

    fn assign_server(&self, _address: SocketAddr, denied_servers: &[String]) -> Self::Server<'_> {
        use std::sync::atomic::Ordering;
        let start_index = self.next_start.fetch_add(1, Ordering::Relaxed);

        // rotate the serverlist so that an error caused by a single NTS-KE server doesn't
        // permanently cripple the pool
        let (left, right) = self.servers.split_at(start_index % self.servers.len());
        let rotated_servers = right.iter().chain(left.iter());

        for server in rotated_servers {
            if denied_servers.contains(&server.domain) {
                continue;
            }

            return RoundRobinServer {
                server,
                owner: self,
            };
        }

        debug!("All servers denied. Falling back to denied server");

        RoundRobinServer {
            server: &self.servers[start_index % self.servers.len()],
            owner: self,
        }
    }
}

pub struct RoundRobinServer<'a> {
    server: &'a KeyExchangeServer,
    owner: &'a RoundRobinServerManager,
}

impl Server for RoundRobinServer<'_> {
    type Connection<'a>
        = TlsStream<TcpStream>
    where
        Self: 'a;

    fn name(&self) -> &str {
        &self.server.domain
    }

    async fn support(
        &self,
    ) -> Result<
        (
            HashSet<ProtocolId>,
            HashMap<AlgorithmId, AlgorithmDescription>,
        ),
        PoolError,
    > {
        let mut connection = self.connect().await?;

        ServerInformationRequest.serialize(&mut connection).await?;
        let support_info = ServerInformationResponse::parse(&mut connection).await?;
        connection.shutdown().await?;
        let supported_protocols: HashSet<ProtocolId> =
            support_info.supported_protocols.into_iter().collect();
        let supported_algorithms: HashMap<AlgorithmId, AlgorithmDescription> = support_info
            .supported_algorithms
            .into_iter()
            .map(|v| (v.id, v))
            .collect();
        Ok((supported_protocols, supported_algorithms))
    }

    async fn connect(&self) -> Result<Self::Connection<'_>, PoolError> {
        let io = TcpStream::connect(self.server.connection_address.clone()).await?;
        Ok(self
            .owner
            .upstream_tls
            .connect(self.server.server_name.clone(), io)
            .await?)
    }
}

impl ServerConnection for TlsStream<TcpStream> {
    async fn reuse(mut self) {
        // no reuse, just shutdown the connection
        let _ = self.shutdown().await;
    }
}
