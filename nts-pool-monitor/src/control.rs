use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{select, time::sleep_until};

use crate::{
    NtpVersion,
    nts::NtsClientConfig,
    probe::{Probe, ProbeConfig, ProbeResult},
    tls_utils::Certificate,
};

#[derive(Debug, Clone)]
pub struct ProbeControlConfig {
    pub management_interface: String,
    pub authorization_key: String,
    pub certificates: Arc<[Certificate]>,
}

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
    let command = M::get_command(&config)
        .await
        .expect("Could not get initial command");
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
                _ = sleep_until(probe_deadline.into()) => Task::Probe,
                _ = sleep_until(update_deadline.into()) => Task::Update,
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
                                    Err(_) => { /* log error once we have logging here */ }
                                }
                                drop(permit);
                            });
                        } else {
                            // Just skip the probe to reduce load
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
    let mut send_timeout = std::pin::pin!(tokio::time::sleep_until(Instant::now().into()));

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
                    .reset((Instant::now() + settings.read().unwrap().result_max_waittime).into())
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
            let _ = reqwest::Client::new()
                .post(send_target)
                .bearer_auth(&config.authorization_key)
                .json(&cache)
                .send()
                .await;
            // TODO: Report error once we have tracing
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
