use std::{
    io::Cursor,
    pin::pin,
    time::{Duration, SystemTime},
};

use nts_pool_shared::{
    KeyExchangeProbeResult, KeyExchangeStatus, ProbeResult, SecuredNtpProbeResult,
    SecuredNtpProbeStatus,
};
use rand::{Rng, rng};
use tokio::{
    net::TcpStream,
    select,
    time::{Instant, timeout},
};

use crate::{
    IpVersion,
    nts::{KeyExchangeClient, NtsClientConfig, NtsError},
    packet::{Cipher, NtpLeapIndicator, NtpPacket},
    resolve_as_version,
    time_types::{NtpTimestamp, PollInterval},
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

struct NtpInputs {
    ipprot: IpVersion,
    host: String,
    port: u16,
    cookie: Vec<u8>,
    pub c2s: Box<dyn Cipher>,
    pub s2c: Box<dyn Cipher>,
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

    pub async fn probe(
        &self,
        uuid: impl AsRef<str>,
        domain: impl AsRef<str>,
        port: u16,
        ipprot: IpVersion,
    ) -> Result<ProbeResult, eyre::Error> {
        let uuid = uuid.as_ref();
        tracing::debug!("Probing {}", uuid);
        let (keyexchange, next) = self.probe_keyexchange(uuid, domain, port, ipprot).await?;
        tracing::debug!("Keyexchange result: {:?}", keyexchange);

        let (ntp_with_ke_cookie, next) = match next {
            None => (Default::default(), None),
            Some(inputs) => self.probe_ntp(inputs).await?,
        };
        tracing::debug!("First ntp result: {:?}", ntp_with_ke_cookie);

        let ntp_with_ntp_cookie = match next {
            None => Default::default(),
            Some(inputs) => self.probe_ntp(inputs).await?.0,
        };
        tracing::debug!("Second ntp result: {:?}", ntp_with_ke_cookie);

        tracing::debug!("Finished probe of {}", uuid);

        Ok(ProbeResult {
            keyexchange,
            ntp_with_ke_cookie,
            ntp_with_ntp_cookie,
        })
    }

    async fn probe_keyexchange(
        &self,
        uuid: impl AsRef<str>,
        domain: impl AsRef<str>,
        port: u16,
        ipprot: IpVersion,
    ) -> Result<(KeyExchangeProbeResult, Option<NtpInputs>), eyre::Error> {
        let (domain, addr) = if ipprot.is_srv() {
            match resolve_as_version((domain.as_ref(), port), ipprot).await {
                Ok(addr) => (domain.as_ref().to_owned(), addr),
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error().is_none() =>
                {
                    let (status, description);
                    if resolve_as_version((domain.as_ref(), port), ipprot.other_ip_protocol())
                        .await
                        .is_ok()
                    {
                        status = match ipprot {
                            IpVersion::Ipv4 => KeyExchangeStatus::Failed,
                            IpVersion::Ipv6 => KeyExchangeStatus::Failed,
                            IpVersion::Srvv4 => KeyExchangeStatus::SrvIpv6Only,
                            IpVersion::Srvv6 => KeyExchangeStatus::SrvIpv4Only,
                        };
                        description = "Only resolvable over other IP version".into();
                    } else {
                        status = KeyExchangeStatus::Failed;
                        description = "Domain name not resolvable".into();
                    }

                    return Ok((
                        KeyExchangeProbeResult {
                            status,
                            description,
                            exchange_start: SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),

                            exchange_duration: 0.0,
                            num_cookies: 0,
                        },
                        None,
                    ));
                }

                Err(e) => return Err(e.into()),
            }
        } else {
            (
                self.poolke.clone(),
                resolve_as_version((self.poolke.as_str(), 4460), ipprot).await?,
            )
        };

        let exchange_start = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start_time = Instant::now();
        match timeout(self.nts_timeout, async {
            let io = match TcpStream::connect(addr).await {
                Ok(io) => io,
                Err(_) if ipprot.is_srv() => {
                    let end_time = Instant::now();
                    return Ok((
                        KeyExchangeProbeResult {
                            status: KeyExchangeStatus::Failed,
                            description: "Time source NTS key exchange server was not reachable."
                                .into(),
                            exchange_start,
                            exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                            num_cookies: 0,
                        },
                        None,
                    ));
                }
                Err(e) => return Err(e.into()),
            };
            match self
                .ntske
                .exchange_keys(io, domain, if ipprot.is_srv() { None } else { Some(uuid) })
                .await
            {
                Ok(ke_result) => {
                    let end_time = Instant::now();
                    Ok((
                        KeyExchangeProbeResult {
                            status: KeyExchangeStatus::Success,
                            description: String::new(),
                            exchange_start,
                            exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                            num_cookies: ke_result.cookies.len(),
                        },
                        Some(NtpInputs {
                            ipprot,
                            host: ke_result.remote,
                            port: ke_result.port,
                            cookie: ke_result.cookies.into_iter().next().unwrap(),
                            c2s: ke_result.c2s,
                            s2c: ke_result.s2c,
                        }),
                    ))
                }
                Err(NtsError::Error(pool_nts::ErrorCode::NoSuchServer)) if !ipprot.is_srv() => {
                    Err(eyre::eyre!("Server not known (yet)"))
                }
                Err(e) => {
                    let end_time = Instant::now();
                    Ok((
                        KeyExchangeProbeResult {
                            status: KeyExchangeStatus::Failed,
                            description: match e {
                                NtsError::Invalid => {
                                    "Time source's response was invalid but well-structured".into()
                                }
                                NtsError::Error(e) => e.to_string(),
                                e => {
                                    format!("Unexpected error during key exchange: {e}")
                                }
                            },
                            exchange_start,
                            exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                            num_cookies: 0,
                        },
                        None,
                    ))
                }
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let end_time = Instant::now();
                Ok((
                    KeyExchangeProbeResult {
                        status: KeyExchangeStatus::Timeout,
                        description: String::new(),
                        exchange_start,
                        exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                        num_cookies: 0,
                    },
                    None,
                ))
            }
        }
    }

    async fn probe_ntp(
        &self,
        inputs: NtpInputs,
    ) -> Result<(SecuredNtpProbeResult, Option<NtpInputs>), std::io::Error> {
        let cookies_requested = rng().random_range(1..=3);

        let (request, request_id) =
            NtpPacket::nts_poll_message(&inputs.cookie, cookies_requested, PollInterval::NEVER);

        let mut buf = [0; 1024];
        let mut cursor = Cursor::new(buf.as_mut_slice());
        request.serialize(&mut cursor, inputs.c2s.as_ref())?;
        let size = cursor.position() as usize;
        let msg = &buf[..size];

        let addr =
            match resolve_as_version((inputs.host.as_str(), inputs.port), inputs.ipprot).await {
                Ok(addr) => addr,
                Err(e) if e.raw_os_error().is_none() => {
                    return Ok((
                        SecuredNtpProbeResult {
                            status: SecuredNtpProbeStatus::DnsLookupFailed,
                            request_sent: SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            requested_cookies: 0,
                            received_cookies: 0,
                            roundtrip_duration: None,
                            remote_residence_time: None,
                            offset: None,
                            stratum: None,
                            leap_indicates_synchronized: false,
                        },
                        None,
                    ));
                }
                Err(e) => return Err(e),
            };
        let mut socket = match timestamped_socket::socket::connect_address(
            addr,
            timestamped_socket::socket::GeneralTimestampMode::SoftwareAll,
        ) {
            Ok(socket) => socket,
            Err(e) => {
                tracing::debug!("Unexpected error during connect: {e}");
                return Ok((
                    SecuredNtpProbeResult {
                        status: SecuredNtpProbeStatus::CouldNotConnect,
                        request_sent: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        requested_cookies: 0,
                        received_cookies: 0,
                        roundtrip_duration: None,
                        remote_residence_time: None,
                        offset: None,
                        stratum: None,
                        leap_indicates_synchronized: false,
                    },
                    None,
                ));
            }
        };

        let send = match socket.send(msg).await {
            // Timestamp not present errors are purely internal problems, don't blame remote for those.
            Ok(timestamp) => timestamp.ok_or(std::io::ErrorKind::Other)?,
            Err(e) => {
                tracing::debug!("Unexpected error during send: {e}");
                return Ok((
                    SecuredNtpProbeResult {
                        status: SecuredNtpProbeStatus::CouldNotSend,
                        request_sent: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        requested_cookies: 0,
                        received_cookies: 0,
                        roundtrip_duration: None,
                        remote_residence_time: None,
                        offset: None,
                        stratum: None,
                        leap_indicates_synchronized: false,
                    },
                    None,
                ));
            }
        };
        let t1 = NtpTimestamp::from_net_timestamp(send);

        let mut have_deny = false;
        let mut have_ntsn = false;
        let mut timeout = pin!(tokio::time::sleep(self.ntp_timeout));

        let (t4, msg) = loop {
            let received = select! {
                biased;
                r = socket.recv(&mut buf) => match r {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!("Unexpected error during recv: {e}");
                        return Ok((
                            SecuredNtpProbeResult {
                                status: SecuredNtpProbeStatus::CouldNotReceive,
                                request_sent: SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                requested_cookies: 0,
                                received_cookies: 0,
                                roundtrip_duration: None,
                                remote_residence_time: None,
                                offset: None,
                                stratum: None,
                                leap_indicates_synchronized: false,
                            },
                            None,
                        ));
                    }
                },
                _ = &mut timeout => {
                    return Ok((
                        SecuredNtpProbeResult {
                            status: if have_ntsn {
                                SecuredNtpProbeStatus::NtsNak
                            } else if have_deny {
                                SecuredNtpProbeStatus::Deny
                            } else {
                                SecuredNtpProbeStatus::Timeout
                            },
                            requested_cookies: cookies_requested.into(),
                            received_cookies: 0,
                            request_sent: send.seconds as u64,
                            roundtrip_duration: None,
                            remote_residence_time: None,
                            offset: None,
                            stratum: None,
                            leap_indicates_synchronized: false,
                        },
                        None,
                    ));
                }
            };

            if received.remote_addr != addr {
                continue;
            }

            let Ok(incoming) =
                NtpPacket::deserialize(&buf[..received.bytes_read], inputs.s2c.as_ref())
            else {
                continue;
            };

            if incoming.is_kiss() && incoming.valid_server_response(request_id, false) {
                tracing::debug!("Received kiss response: {:?}", incoming);
                if incoming.is_kiss_deny() || incoming.is_kiss_rstr() {
                    have_deny = true;
                    if incoming.valid_server_response(request_id, true) {
                        return Ok((
                            SecuredNtpProbeResult {
                                status: SecuredNtpProbeStatus::Deny,
                                requested_cookies: cookies_requested.into(),
                                received_cookies: 0,
                                request_sent: send.seconds as u64,
                                roundtrip_duration: None,
                                remote_residence_time: None,
                                offset: None,
                                stratum: None,
                                leap_indicates_synchronized: false,
                            },
                            None,
                        ));
                    }
                }

                if incoming.is_kiss_ntsn() {
                    have_ntsn = true;
                }

                continue;
            }

            if !incoming.valid_server_response(request_id, true) {
                tracing::debug!(
                    "Received response not corresponding to request: {:?}",
                    incoming
                );
                continue;
            }

            break (
                NtpTimestamp::from_net_timestamp(
                    // Timestamps should be present, problems with that are a bug on our side.
                    received.timestamp.ok_or(std::io::ErrorKind::Other)?,
                ),
                incoming,
            );
        };

        let t2 = msg.receive_timestamp();
        let t3 = msg.transmit_timestamp();

        let received_cookies = msg.new_cookies().count();

        Ok((
            SecuredNtpProbeResult {
                status: SecuredNtpProbeStatus::Success,
                requested_cookies: cookies_requested.into(),
                received_cookies,
                request_sent: send.seconds as _,
                roundtrip_duration: Some((t4 - t1).to_seconds()),
                remote_residence_time: Some((t3 - t2).to_seconds()),
                offset: Some((((t2 - t1) + (t3 - t4)) / 2i32).to_seconds()),
                stratum: Some(msg.stratum()),
                leap_indicates_synchronized: !matches!(msg.leap(), NtpLeapIndicator::Unknown),
            },
            msg.new_cookies().next().map(|cookie| NtpInputs {
                ipprot: inputs.ipprot,
                host: inputs.host,
                port: inputs.port,
                cookie,
                c2s: inputs.c2s,
                s2c: inputs.s2c,
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use crate::{packet::IdentityCipher, test_init};

    use super::*;

    #[tokio::test]
    async fn test_nts_keyexchange_dns() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let findings = probe
            .probe_keyexchange("UUID", "doesnotexist", 4460, IpVersion::Srvv4)
            .await
            .unwrap();
        assert_eq!(findings.0.status, KeyExchangeStatus::Failed);

        let findings = probe
            .probe_keyexchange("UUID", "127.0.0.1", 4460, IpVersion::Srvv6)
            .await
            .unwrap();
        assert_eq!(std::dbg!(findings.0).status, KeyExchangeStatus::SrvIpv4Only);
    }

    #[tokio::test]
    async fn test_ntp_dns_failed() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let findings = probe
            .probe_ntp(NtpInputs {
                ipprot: IpVersion::Ipv4,
                host: "doesnotexist".into(),
                port: 123,
                cookie: b"1234".into(),
                c2s: Box::new(IdentityCipher::new(16)),
                s2c: Box::new(IdentityCipher::new(16)),
            })
            .await
            .unwrap();
        assert!(findings.1.is_none());
        assert_eq!(findings.0.status, SecuredNtpProbeStatus::DnsLookupFailed);
    }

    #[tokio::test]
    async fn test_ntp_noresponse() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            server.recv(&mut packet).await.unwrap();
        });

        let finding = probe
            .probe_ntp(NtpInputs {
                ipprot: if server_addr.is_ipv4() {
                    IpVersion::Ipv4
                } else {
                    IpVersion::Ipv6
                },
                host: server_addr.ip().to_string(),
                port: server_addr.port(),
                cookie: b"1234".into(),
                c2s: Box::new(IdentityCipher::new(16)),
                s2c: Box::new(IdentityCipher::new(16)),
            })
            .await
            .unwrap();

        assert!(finding.1.is_none());
        assert_eq!(finding.0.status, SecuredNtpProbeStatus::Timeout);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_ntp_deny_response() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            let (l, a) = server.recv_from(&mut packet).await.unwrap();
            let req = NtpPacket::deserialize(&packet[..l], &IdentityCipher::new(16)).unwrap();
            let response = NtpPacket::nts_deny_response(req);
            let out = response.serialize_vec(&IdentityCipher::new(16)).unwrap();
            server.send_to(&out, a).await.unwrap();
        });

        let finding = probe
            .probe_ntp(NtpInputs {
                ipprot: if server_addr.is_ipv4() {
                    IpVersion::Ipv4
                } else {
                    IpVersion::Ipv6
                },
                host: server_addr.ip().to_string(),
                port: server_addr.port(),
                cookie: b"1234".into(),
                c2s: Box::new(IdentityCipher::new(16)),
                s2c: Box::new(IdentityCipher::new(16)),
            })
            .await
            .unwrap();

        assert!(finding.1.is_none());
        assert_eq!(finding.0.status, SecuredNtpProbeStatus::Deny);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_ntp_ntsn_response() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            let (l, a) = server.recv_from(&mut packet).await.unwrap();
            let req = NtpPacket::deserialize(&packet[..l], &IdentityCipher::new(16)).unwrap();
            let response = NtpPacket::nts_nak_response(req);
            let out = response.serialize_without_encryption_vec().unwrap();
            server.send_to(&out, a).await.unwrap();
        });

        let finding = probe
            .probe_ntp(NtpInputs {
                ipprot: if server_addr.is_ipv4() {
                    IpVersion::Ipv4
                } else {
                    IpVersion::Ipv6
                },
                host: server_addr.ip().to_string(),
                port: server_addr.port(),
                cookie: b"1234".into(),
                c2s: Box::new(IdentityCipher::new(16)),
                s2c: Box::new(IdentityCipher::new(16)),
            })
            .await
            .unwrap();

        assert!(finding.1.is_none());
        assert_eq!(finding.0.status, SecuredNtpProbeStatus::NtsNak);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_ntp_timestamp_response_valid() {
        test_init();
        let probe = Probe::new(ProbeConfig {
            poolke: "".into(),
            nts_config: NtsClientConfig {
                certificates: [].into(),
                protocol_version: crate::NtpVersion::V4,
                authorization_key: "".into(),
            },
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })
        .unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            let (l, a) = server.recv_from(&mut packet).await.unwrap();
            let req = NtpPacket::deserialize(&packet[..l], &IdentityCipher::new(16)).unwrap();
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let ts = NtpTimestamp::from_seconds_nanos_since_ntp_era(
                ((70 * 365 + 17) * 86400 + now.as_secs()) as u32,
                now.subsec_nanos(),
            );
            let response = NtpPacket::nts_timestamp_response(req, ts, ts, 1);
            let out = response.serialize_vec(&IdentityCipher::new(16)).unwrap();
            server.send_to(&out, a).await.unwrap();
        });

        let finding = probe
            .probe_ntp(NtpInputs {
                ipprot: if server_addr.is_ipv4() {
                    IpVersion::Ipv4
                } else {
                    IpVersion::Ipv6
                },
                host: server_addr.ip().to_string(),
                port: server_addr.port(),
                cookie: b"1234".into(),
                c2s: Box::new(IdentityCipher::new(16)),
                s2c: Box::new(IdentityCipher::new(16)),
            })
            .await
            .unwrap();

        assert!(finding.1.is_some());
        assert_eq!(finding.0.status, SecuredNtpProbeStatus::Success);
        assert!(finding.0.offset.is_some());
        assert_eq!(finding.0.received_cookies, finding.0.requested_cookies);
        assert!(finding.0.remote_residence_time.is_some());
        assert!(finding.0.roundtrip_duration.is_some());

        server_task.await.unwrap();
    }
}
