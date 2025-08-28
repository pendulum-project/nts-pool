use std::{
    io::Cursor,
    pin::pin,
    time::{Duration, SystemTime},
};

use rand::{Rng, rng};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, select, time::{timeout, Instant}};

use crate::{
    nts::{KeyExchangeClient, NtsClientConfig, NtsError},
    packet::{Cipher, NtpPacket},
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    keyexchange: KeyExchangeProbeResult,
    ntp_with_ke_cookie: SecuredNtpProbeResult,
    ntp_with_ntp_cookie: SecuredNtpProbeResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyExchangeStatus {
    Success,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeyExchangeProbeResult {
    pub status: KeyExchangeStatus,
    pub exchange_start: u64,
    pub exchange_duration: f64,
    pub num_cookies: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SecuredNtpProbeStatus {
    Success,
    DnsLookupFailed,
    NtsNak,
    Deny,
    Timeout,
    #[default]
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct SecuredNtpProbeResult {
    pub status: SecuredNtpProbeStatus,
    pub request_sent: u64,
    pub roundtrip_duration: Option<f64>,
    pub remote_residence_time: Option<f64>,
    pub offset: Option<f64>,
    pub requested_cookies: usize,
    pub received_cookies: usize,
}

struct NtpInputs {
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

    pub async fn probe(&self, uuid: impl AsRef<str>) -> Result<ProbeResult, std::io::Error> {
        let (keyexchange, next) = self.probe_keyexchange(uuid).await?;

        let (ntp_with_ke_cookie, next) = match next {
            None => (Default::default(), None),
            Some(inputs) => self.probe_ntp(inputs).await?,
        };

        let ntp_with_ntp_cookie = match next {
            None => Default::default(),
            Some(inputs) => self.probe_ntp(inputs).await?.0,
        };

        Ok(ProbeResult {
            keyexchange,
            ntp_with_ke_cookie,
            ntp_with_ntp_cookie,
        })
    }

    async fn probe_keyexchange(
        &self,
        uuid: impl AsRef<str>,
    ) -> Result<(KeyExchangeProbeResult, Option<NtpInputs>), std::io::Error> {
        let io = TcpStream::connect((self.poolke.as_str(), 4460)).await?;

        let exchange_start = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start_time = Instant::now();
        let ke_result = match timeout(
            self.nts_timeout,
            self.ntske.exchange_keys(io, self.poolke.clone(), uuid),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(NtsError::IO(e))) => return Err(e),
            Ok(Err(NtsError::Tls(e))) => return Err(std::io::Error::other(e)),
            Ok(Err(NtsError::Dns(e))) => return Err(std::io::Error::other(e)),
            Ok(Err(NtsError::UnrecognizedCriticalRecord))
            | Ok(Err(NtsError::UnknownWarning(_))) => {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            Ok(Err(_)) => {
                let end_time = Instant::now();
                return Ok((
                    KeyExchangeProbeResult {
                        status: KeyExchangeStatus::Failed,
                        exchange_start,
                        exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                        num_cookies: 0,
                    },
                    None,
                ));
            }
            Err(_) => {
                let end_time = Instant::now();
                return Ok((
                    KeyExchangeProbeResult {
                        status: KeyExchangeStatus::Timeout,
                        exchange_start,
                        exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                        num_cookies: 0,
                    },
                    None,
                ));
            }
        };
        let end_time = Instant::now();

        Ok((
            KeyExchangeProbeResult {
                status: KeyExchangeStatus::Success,
                exchange_start,
                exchange_duration: end_time.duration_since(start_time).as_secs_f64(),
                num_cookies: ke_result.cookies.len(),
            },
            Some(NtpInputs {
                host: ke_result.remote,
                port: ke_result.port,
                cookie: ke_result.cookies.into_iter().next().unwrap(),
                c2s: ke_result.c2s,
                s2c: ke_result.s2c,
            }),
        ))
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

        let Some(addr) = tokio::net::lookup_host((inputs.host.as_str(), inputs.port))
            .await?
            .next()
        else {
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
                },
                None,
            ));
        };
        let mut socket = timestamped_socket::socket::connect_address(
            addr,
            timestamped_socket::socket::GeneralTimestampMode::SoftwareAll,
        )?;

        let send = socket.send(msg).await?.ok_or(std::io::ErrorKind::Other)?;
        let t1 = NtpTimestamp::from_net_timestamp(send);

        let mut have_deny = false;
        let mut have_ntsn = false;
        let mut timeout = pin!(tokio::time::sleep(self.ntp_timeout));

        let (t4, msg) = loop {
            let received = select! {
                biased;
                r = socket.recv(&mut buf) => r?,
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
                if incoming.is_kiss_deny() || incoming.is_kiss_rstr() {
                    have_deny = true;
                }

                if incoming.is_kiss_ntsn() {
                    have_ntsn = true;
                }

                continue;
            }

            if !incoming.valid_server_response(request_id, true) {
                continue;
            }

            break (
                NtpTimestamp::from_net_timestamp(
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
            },
            msg.new_cookies().next().map(|cookie| NtpInputs {
                host: inputs.host,
                port: inputs.port,
                cookie,
                c2s: inputs.c2s,
                s2c: inputs.s2c,
            }),
        ))
    }
}
