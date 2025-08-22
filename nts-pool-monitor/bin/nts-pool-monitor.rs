use nts_pool_monitor::monitor_main;

#[tokio::main]
async fn main() {
    monitor_main().await;
}
