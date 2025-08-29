// This file contains the main run loops for the monitor, controlling the
// probing and sending of probe results.
//
// The running of the probing is divided into two parts, the
// `run_probing_inner` function handles the fetching of work and starting the
// probe. The results of these probes are then collected in the
// `run_result_reporter` function, where they are aggregated and periodically
// sent out. Communication to the reporting function is done through an mpsc
// channel, and it automatically terminates once all senders are gone.
//
// To manage the work to be done, the `run_probing_inner` functions maintains
// two queues. One is local to the task and is contains the work that has been
// going on for longer. The other is a channel filled with new work by the
// update task. This allows us to efficiently merge in new work without having
// to stop the world.
//
// Information on the current instructions on the work from the pool are
// shared between the tasks in an `Arc<Rwlock<Arc<>>>`, which allows us to keep
// locking time short at the cost of using somewhat older information in still
// running actions.
//
// The probe starting time is spread out for servers added at the same time.
// To ensure servers received from updates are also spread out among the
// existing list, it is advisable to have an update interval that is not an
// integer multiple of the probing interval.
use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, RwLock},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    select,
    time::{Instant, sleep_until},
};
use tracing::{error, warn};

use crate::{
    NtpVersion,
    config::ProbeControlConfig,
    nts::NtsClientConfig,
    probe::{Probe, ProbeConfig, ProbeResult},
};

#[derive(Serialize, Deserialize)]
struct ProbeControlCommand {
    timesources: HashSet<String>,
    poolke: String,
    result_endpoint: String,
    result_batchsize: usize,
    result_max_waittime: Duration,
    update_interval: Duration,
    probe_interval: Duration,
    nts_timeout: Duration,
    ntp_timeout: Duration,
}

const MAX_PARALLEL_PROBES: usize = 250;
const MAX_RESULT_QUEUE_SIZE: usize = 100;

// Trait to allow easier testing by injecting the prober.
trait ProbeExecutor {
    type Output: std::fmt::Debug + Send;

    fn from_command(config: &ProbeControlConfig, command: &ProbeControlCommand) -> Self;

    fn run_probe(
        self: Arc<Self>,
        timesource: String,
    ) -> impl Future<Output = Result<Self::Output, std::io::Error>> + Send;
}

impl ProbeExecutor for Probe {
    type Output = ProbeResult;

    fn from_command(config: &ProbeControlConfig, command: &ProbeControlCommand) -> Self {
        Probe::new(ProbeConfig {
            poolke: command.poolke.clone(),
            nts_config: NtsClientConfig {
                certificates: config.certificates.clone(),
                protocol_version: NtpVersion::V4,
                authorization_key: config.authorization_key.clone(),
            },
            nts_timeout: command.nts_timeout,
            ntp_timeout: command.ntp_timeout,
        })
        .expect("Unable to create new probe")
    }

    async fn run_probe(
        self: Arc<Self>,
        timesource: String,
    ) -> Result<Self::Output, std::io::Error> {
        self.probe(timesource).await
    }
}

// Trait to allow easier testing through mocking the requests to the management interface
trait ManagementRequestor {
    fn get_command(
        config: &ProbeControlConfig,
    ) -> impl Future<Output = Result<ProbeControlCommand, std::io::Error>> + Send;
}

async fn run_probing_inner<
    T: ProbeExecutor + Send + Sync + 'static,
    S: Future + Unpin + Send + 'static,
    M: ManagementRequestor,
>(
    config: ProbeControlConfig,
    mut stop: S,
) -> (
    tokio::sync::mpsc::Receiver<(String, T::Output)>,
    Arc<RwLock<Arc<ProbeControlCommand>>>,
) {
    let command = match M::get_command(&config).await {
        Ok(command) => command,
        Err(e) => {
            error!("Could not fetch initial command: {}", e);
            std::process::exit(crate::exitcode::SOFTWARE);
        }
    };
    let probe = Arc::new(RwLock::new(Arc::new(T::from_command(&config, &command))));

    // Generate the initial work order, spread out over the work interval.
    let startup_increment =
        command.probe_interval / (command.timesources.len().try_into().unwrap_or(u32::MAX));
    let start_time = Instant::now();
    let mut work: VecDeque<_> = command
        .timesources
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, uuid)| {
            (
                start_time + startup_increment * (index.try_into().unwrap_or(u32::MAX)),
                uuid,
            )
        })
        .collect();
    let mut update_deadline = start_time + command.update_interval;

    let command = Arc::new(RwLock::new(Arc::new(command)));
    let command_extern = command.clone();
    let config = Arc::new(config);

    let (new_work_sender, mut new_work) =
        tokio::sync::mpsc::unbounded_channel::<(Instant, String)>();
    let (result_sender, result_receiver) =
        tokio::sync::mpsc::channel::<(String, T::Output)>(MAX_RESULT_QUEUE_SIZE);
    let permitter = Arc::new(tokio::sync::Semaphore::new(MAX_PARALLEL_PROBES));

    let mut last_new_work = None;

    tokio::spawn(async move {
        loop {
            enum Task {
                Probe,
                Update,
            }

            let cur = work.front().unwrap().0;
            let probe_deadline = if let Some((new, _)) = &last_new_work
                && *new < cur
            {
                *new
            } else {
                cur
            };
            let task = select! {
                _ = sleep_until(probe_deadline) => Task::Probe,
                _ = sleep_until(update_deadline) => Task::Update,
                next_new_work = new_work.recv(), if last_new_work.is_none() => {
                    last_new_work = next_new_work;
                    continue;
                }
                _ = &mut stop => { break; }
            };

            match task {
                Task::Probe => {
                    let work_item = if let Some((new_ts, _)) = &last_new_work
                        && *new_ts < cur
                    {
                        last_new_work.take().unwrap()
                    } else {
                        work.pop_front().unwrap()
                    };
                    let command = command.read().unwrap().clone();
                    if command.timesources.contains(&work_item.1) {
                        if let Ok(permit) = permitter.clone().try_acquire_owned() {
                            let local_probe = probe.read().unwrap().clone();
                            let uuid = work_item.1.clone();
                            let result_sender = result_sender.clone();
                            tokio::spawn(async move {
                                match local_probe.run_probe(uuid.clone()).await {
                                    Ok(result) => {
                                        let _ = result_sender.send((uuid, result)).await;
                                    }
                                    Err(e) => {
                                        warn!("Probe failed: {}", e)
                                    }
                                }
                                drop(permit);
                            });
                        } else {
                            // Just skip the probe to reduce load
                            warn!("Overloaded, skipping probe");
                        }
                        work.push_back((Instant::now() + command.probe_interval, work_item.1));
                    }
                }
                Task::Update => {
                    let command = command.clone();
                    let config = config.clone();
                    let new_work_sender = new_work_sender.clone();
                    update_deadline = Instant::now() + command.read().unwrap().update_interval;
                    tokio::spawn(async move {
                        let Ok(new_command) = M::get_command(&config).await else {
                            return;
                        };
                        let new_command = Arc::new(new_command);

                        // Make sure the compiler doesn't think the lock guard lives beyond this block.
                        let old_command = {
                            let mut command_place = command.write().unwrap();
                            let old_command = command_place.clone();
                            *command_place = new_command.clone();
                            drop(command_place);
                            old_command
                        };

                        let new_server_count = new_command
                            .timesources
                            .difference(&old_command.timesources)
                            .count();
                        if new_server_count == 0 {
                            return;
                        }

                        let start_interval = new_command.probe_interval
                            / (new_server_count.try_into().unwrap_or(u32::MAX));
                        let start_time = Instant::now();
                        for (index, ts) in new_command
                            .timesources
                            .difference(&old_command.timesources)
                            .enumerate()
                        {
                            // Don't care if receiver no longer exists.
                            let _ = new_work_sender.send((
                                start_time
                                    + start_interval * (index.try_into().unwrap_or(u32::MAX)),
                                ts.clone(),
                            ));
                        }
                    });
                }
            }
        }
    });

    (result_receiver, command_extern)
}

async fn run_result_reporter<T: Send + Serialize + 'static>(
    mut results: tokio::sync::mpsc::Receiver<(String, T)>,
    settings: Arc<RwLock<Arc<ProbeControlCommand>>>,
    config: ProbeControlConfig,
) {
    let mut cache = vec![];
    let mut send_timeout = std::pin::pin!(tokio::time::sleep_until(Instant::now()));

    loop {
        enum Task<T> {
            Recv { result: (String, T) },
            Stop,
            Send,
            Continue,
        }
        let mut task = tokio::select! {
            result = results.recv() => { if let Some(result) = result { Task::Recv { result } } else { Task::Stop } }
            _ = &mut send_timeout => { if cache.is_empty() { Task::Continue } else { Task::Send } }
        };

        if let Task::Recv { result } = task {
            if cache.is_empty() {
                send_timeout
                    .as_mut()
                    .reset(Instant::now() + settings.read().unwrap().result_max_waittime)
            }
            cache.push(result);
            if cache.len() >= settings.read().unwrap().result_batchsize {
                task = Task::Send
            } else {
                task = Task::Continue;
            }
        }

        if matches!(task, Task::Stop | Task::Send) {
            let send_target = settings.read().unwrap().result_endpoint.clone();
            match reqwest::Client::new()
                .post(send_target)
                .bearer_auth(&config.authorization_key)
                .json(&cache)
                .send()
                .await
                .and_then(|response| response.error_for_status())
            {
                Ok(_) => { /* nothing to do on success */ }
                Err(e) => {
                    warn!("Failed to submit monitoring results: {}", e);
                }
            }
            cache.clear();
        }

        if matches!(task, Task::Stop) {
            break;
        }
    }
}

struct ReqwestManagementRequestor;

impl ManagementRequestor for ReqwestManagementRequestor {
    async fn get_command(
        config: &ProbeControlConfig,
    ) -> Result<ProbeControlCommand, std::io::Error> {
        let result = reqwest::Client::new()
            .get(&config.management_interface)
            .bearer_auth(&config.authorization_key)
            .send()
            .await
            .map_err(std::io::Error::other)?;
        result.json().await.map_err(std::io::Error::other)
    }
}

pub async fn run_probing(config: ProbeControlConfig) {
    let (receiver, command) = run_probing_inner::<Probe, _, ReqwestManagementRequestor>(
        config.clone(),
        Box::pin(async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .unwrap()
                .recv()
                .await
        }),
    )
    .await;
    run_result_reporter(receiver, command, config).await;
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, RwLock, atomic::AtomicUsize},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use crate::{
        config::ProbeControlConfig,
        control::{
            ManagementRequestor, ProbeControlCommand, ProbeExecutor, ReqwestManagementRequestor,
            run_probing_inner, run_result_reporter,
        },
    };

    struct NoopProbe;

    impl ProbeExecutor for NoopProbe {
        type Output = String;

        fn from_command(_config: &ProbeControlConfig, _command: &ProbeControlCommand) -> Self {
            NoopProbe
        }

        async fn run_probe(
            self: Arc<Self>,
            timesource: String,
        ) -> Result<Self::Output, std::io::Error> {
            Ok(timesource)
        }
    }

    #[tokio::test]
    async fn test_reqwest_command_fetcher() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut conn, _) = server.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = conn.read(&mut req).await.unwrap();
            conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 329\r\n\r\n{\"timesources\":[\"UUID-A\",\"UUID-B\"],\"poolke\":\"localhost\",\"result_endpoint\":\"http://localhost:3000/monitoring/submit\",\"result_batchsize\":4,\"result_max_waittime\":{\"secs\":60,\"nanos\":0},\"update_interval\":{\"secs\":60,\"nanos\":0},\"probe_interval\":{\"secs\":4,\"nanos\":0},\"nts_timeout\":{\"secs\":1,\"nanos\":0},\"ntp_timeout\":{\"secs\":1,\"nanos\":0}}").await.unwrap();
            conn.shutdown().await.unwrap();
        });

        let command = ReqwestManagementRequestor::get_command(&ProbeControlConfig {
            management_interface: format!("http://{}/", server_addr),
            authorization_key: "".into(),
            certificates: [].into(),
        })
        .await
        .unwrap();

        assert_eq!(command.poolke, "localhost");
        assert_eq!(command.ntp_timeout, Duration::from_secs(1));

        server_task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_response_sender() {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let (server_incoming_send, mut server_incoming_recv) = tokio::sync::mpsc::channel(1);

        let server_task = tokio::spawn(async move {
            loop {
                let (mut conn, _) = server.accept().await.unwrap();
                let mut req = [0u8; 4096];
                let n = conn.read(&mut req).await.unwrap();
                server_incoming_send.send(req[..n].to_vec()).await.unwrap();
                conn.write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
                conn.shutdown().await.unwrap();
            }
        });

        let (channel_send, channel_recv) = tokio::sync::mpsc::channel::<(String, String)>(100);
        let command = Arc::new(RwLock::new(Arc::new(ProbeControlCommand {
            timesources: [].into(),
            poolke: "".into(),
            result_endpoint: format!("http://{}/", server_addr),
            result_batchsize: 2,
            result_max_waittime: Duration::from_secs(1),
            update_interval: Duration::from_secs(1),
            probe_interval: Duration::from_secs(1),
            nts_timeout: Duration::from_secs(1),
            ntp_timeout: Duration::from_secs(1),
        })));

        let response_task = tokio::spawn(run_result_reporter(
            channel_recv,
            command,
            ProbeControlConfig {
                management_interface: "".into(),
                authorization_key: "".into(),
                certificates: [].into(),
            },
        ));

        channel_send.send(("a".into(), "b".into())).await.unwrap();
        assert!(
            server_incoming_recv
                .recv()
                .await
                .unwrap()
                .ends_with(br#"[["a","b"]]"#)
        );

        channel_send.send(("c".into(), "d".into())).await.unwrap();
        channel_send.send(("e".into(), "f".into())).await.unwrap();
        channel_send.send(("g".into(), "h".into())).await.unwrap();
        assert!(
            server_incoming_recv
                .recv()
                .await
                .unwrap()
                .ends_with(br#"[["c","d"],["e","f"]]"#)
        );
        assert!(
            server_incoming_recv
                .recv()
                .await
                .unwrap()
                .ends_with(br#"[["g","h"]]"#)
        );

        drop(channel_send);

        response_task.await.unwrap();
        server_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_probe_runner_basic() {
        struct BasicCommandRequestor;
        impl ManagementRequestor for BasicCommandRequestor {
            async fn get_command(
                _config: &ProbeControlConfig,
            ) -> Result<ProbeControlCommand, std::io::Error> {
                Ok(ProbeControlCommand {
                    timesources: ["A".to_string(), "B".to_string()].into(),
                    poolke: "".into(),
                    result_endpoint: "".into(),
                    result_batchsize: 1,
                    result_max_waittime: Duration::from_secs(1),
                    update_interval: Duration::from_secs(39),
                    probe_interval: Duration::from_secs(40),
                    nts_timeout: Duration::from_secs(1),
                    ntp_timeout: Duration::from_secs(1),
                })
            }
        }

        let (mut recv, _) = run_probing_inner::<NoopProbe, _, BasicCommandRequestor>(
            ProbeControlConfig {
                management_interface: "".into(),
                authorization_key: "".into(),
                certificates: [].into(),
            },
            Box::pin(tokio::time::sleep(Duration::from_secs(119))),
        )
        .await;

        let a = recv.recv().await.unwrap();
        let b = recv.recv().await.unwrap();
        assert_ne!(a, b);
        assert!(a == ("A".into(), "A".into()) || b == ("A".into(), "A".into()));
        assert!(a == ("B".into(), "B".into()) || b == ("B".into(), "B".into()));

        let a = recv.recv().await.unwrap();
        let b = recv.recv().await.unwrap();
        assert_ne!(a, b);
        assert!(a == ("A".into(), "A".into()) || b == ("A".into(), "A".into()));
        assert!(a == ("B".into(), "B".into()) || b == ("B".into(), "B".into()));

        let a = recv.recv().await.unwrap();
        let b = recv.recv().await.unwrap();
        assert_ne!(a, b);
        assert!(a == ("A".into(), "A".into()) || b == ("A".into(), "A".into()));
        assert!(a == ("B".into(), "B".into()) || b == ("B".into(), "B".into()));

        assert!(recv.recv().await.is_none())
    }

    #[tokio::test(start_paused = true)]
    async fn test_probe_runner_changing_servers() {
        struct SequencedCommandRequestor;
        impl ManagementRequestor for SequencedCommandRequestor {
            async fn get_command(
                _config: &ProbeControlConfig,
            ) -> Result<ProbeControlCommand, std::io::Error> {
                static INDEX: AtomicUsize = AtomicUsize::new(0);
                Ok(match INDEX.load(std::sync::atomic::Ordering::SeqCst) {
                    0 => {
                        INDEX.store(1, std::sync::atomic::Ordering::SeqCst);
                        ProbeControlCommand {
                            timesources: ["A".to_string(), "B".to_string()].into(),
                            poolke: "".into(),
                            result_endpoint: "".into(),
                            result_batchsize: 1,
                            result_max_waittime: Duration::from_secs(1),
                            update_interval: Duration::from_secs(39),
                            probe_interval: Duration::from_secs(40),
                            nts_timeout: Duration::from_secs(1),
                            ntp_timeout: Duration::from_secs(1),
                        }
                    }
                    1 => {
                        INDEX.store(2, std::sync::atomic::Ordering::SeqCst);
                        ProbeControlCommand {
                            timesources: ["B".to_string()].into(),
                            poolke: "".into(),
                            result_endpoint: "".into(),
                            result_batchsize: 1,
                            result_max_waittime: Duration::from_secs(1),
                            update_interval: Duration::from_secs(39),
                            probe_interval: Duration::from_secs(40),
                            nts_timeout: Duration::from_secs(1),
                            ntp_timeout: Duration::from_secs(1),
                        }
                    }
                    _ => ProbeControlCommand {
                        timesources: ["B".to_string(), "C".to_string()].into(),
                        poolke: "".into(),
                        result_endpoint: "".into(),
                        result_batchsize: 1,
                        result_max_waittime: Duration::from_secs(1),
                        update_interval: Duration::from_secs(39),
                        probe_interval: Duration::from_secs(40),
                        nts_timeout: Duration::from_secs(1),
                        ntp_timeout: Duration::from_secs(1),
                    },
                })
            }
        }

        let (mut recv, _) = run_probing_inner::<NoopProbe, _, SequencedCommandRequestor>(
            ProbeControlConfig {
                management_interface: "".into(),
                authorization_key: "".into(),
                certificates: [].into(),
            },
            Box::pin(tokio::time::sleep(Duration::from_secs(119))),
        )
        .await;

        let a = recv.recv().await.unwrap();
        let b = recv.recv().await.unwrap();
        assert_ne!(a, b);
        assert!(a == ("A".into(), "A".into()) || b == ("A".into(), "A".into()));
        assert!(a == ("B".into(), "B".into()) || b == ("B".into(), "B".into()));

        assert_eq!(recv.recv().await.unwrap(), ("B".into(), "B".into()));
        assert_eq!(recv.recv().await.unwrap(), ("C".into(), "C".into()));
        assert_eq!(recv.recv().await.unwrap(), ("B".into(), "B".into()));
        assert_eq!(recv.recv().await.unwrap(), ("C".into(), "C".into()));
        assert!(recv.recv().await.is_none())
    }
}
