use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{
    error::PoolError,
    nts::{AlgorithmDescription, AlgorithmId, ProtocolId},
};

mod roundrobin;
pub use roundrobin::RoundRobinServerManager;

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

impl ServerConnection for TlsStream<TcpStream> {
    async fn reuse(mut self) {
        // no reuse, just shutdown the connection
        let _ = self.shutdown().await;
    }
}
