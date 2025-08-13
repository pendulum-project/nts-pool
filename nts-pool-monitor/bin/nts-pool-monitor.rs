use std::io::Cursor;

use nts_pool_monitor::{KeyExchangeClient, NtpPacket, NtpVersion, NtsClientConfig, PollInterval};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let io = TcpStream::connect("time.tweede.golf:4460").await.unwrap();

    let client = KeyExchangeClient::new(NtsClientConfig {
        certificates: [].into(),
        protocol_version: NtpVersion::V4,
    })
    .unwrap();

    let result = client
        .exchange_keys(io, "time.tweede.golf".into())
        .await
        .unwrap();

    let mut nts = result.nts;

    let cookie = nts.cookies.get().unwrap();

    let request = NtpPacket::nts_poll_message(&cookie, 0, PollInterval::NEVER);

    let mut buf = [0; 1024];
    let mut cursor = Cursor::new(buf.as_mut_slice());
    request
        .0
        .serialize(&mut cursor, nts.c2s.as_ref(), None)
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

    let incoming = NtpPacket::deserialize(&buf[..received.bytes_read], nts.s2c.as_ref()).unwrap();

    assert!(incoming.valid_server_response(request.1, true));

    println!(
        "{:?} {:?} {:?} {:?}",
        send,
        incoming.receive_timestamp(),
        incoming.transmit_timestamp(),
        recv
    );
}
