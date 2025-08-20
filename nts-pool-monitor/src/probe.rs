use std::{io::Cursor, time::Duration};

use tokio::net::TcpStream;

use crate::{
    NtsClientConfig,
    nts::{KeyExchangeClient, NtsError},
    packet::NtpPacket,
    time_types::PollInterval,
};

pub struct ProbeConfig {
    pub poolke: String,
    pub nts_config: NtsClientConfig,
    pub nts_timeout: Duration,
    pub ntp_timeout: Duration,
}

pub struct Probe {
    poolke: String,
    ntske: KeyExchangeClient,
    nts_timeout: Duration,
    ntp_timeout: Duration,
}

impl Probe {
    pub fn new(config: ProbeConfig) -> Result<Self, NtsError> {
        Ok(Probe {
            ntske: KeyExchangeClient::new(config.nts_config)?,
            nts_timeout: config.nts_timeout,
            ntp_timeout: config.ntp_timeout,
            poolke: config.poolke,
        })
    }

    pub async fn probe(&self, uuid: impl AsRef<str>) {
        let io = TcpStream::connect("localhost:4460").await.unwrap();

        let result = self
            .ntske
            .exchange_keys(io, "localhost".into(), "UUID-A")
            .await
            .unwrap();

        let cookie = result.cookies.first().unwrap();

        let request = NtpPacket::nts_poll_message(cookie, 0, PollInterval::NEVER);

        let mut buf = [0; 1024];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        request
            .0
            .serialize(&mut cursor, result.c2s.as_ref(), None)
            .unwrap();
        let size = cursor.position() as usize;
        let msg = &buf[..size];

        let addr = tokio::net::lookup_host((result.remote, result.port))
            .await
            .unwrap()
            .next()
            .unwrap();
        let mut socket = timestamped_socket::socket::connect_address(
            addr,
            timestamped_socket::socket::GeneralTimestampMode::SoftwareAll,
        )
        .unwrap();

        let send = socket.send(msg).await.unwrap().unwrap();

        let received = socket.recv(&mut buf).await.unwrap();

        assert_eq!(received.remote_addr, addr);
        let recv = received.timestamp.unwrap();

        let incoming =
            NtpPacket::deserialize(&buf[..received.bytes_read], result.s2c.as_ref()).unwrap();

        assert!(incoming.valid_server_response(request.1, true));

        println!(
            "{:?} {:?} {:?} {:?}",
            send,
            incoming.receive_timestamp(),
            incoming.transmit_timestamp(),
            recv
        );
    }
}
