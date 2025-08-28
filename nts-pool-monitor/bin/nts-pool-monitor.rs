use nts_pool_monitor::monitor_main;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    monitor_main().await
}
