use std::{fs::File, io::BufReader, sync::Arc, time::Duration};

use nts_pool_monitor::{NtpVersion, NtsClientConfig, Probe, ProbeConfig, certs};

#[tokio::main]
async fn main() {
    let config = ProbeConfig {
        poolke: "localhost".into(),
        nts_config: NtsClientConfig {
            certificates: certs(&mut BufReader::new(
                File::open("./nts-pool-ke/testdata/testca.pem").unwrap(),
            ))
            .collect::<Result<Arc<_>, _>>()
            .unwrap(),
            protocol_version: NtpVersion::V4,
            authorization_key: "testmonitor".into(),
        },
        nts_timeout: Duration::from_secs(1),
        ntp_timeout: Duration::from_secs(1),
    };

    let probe = Probe::new(config).unwrap();

    probe.probe("UUID-B").await;
}
