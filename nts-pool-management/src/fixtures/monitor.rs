use sqlx::PgConnection;

use crate::{
    fixtures::{FixtureContext, FixtureError},
    models::{
        monitor::{self, MonitorId, NewMonitor},
        user::UserId,
    },
};

pub async fn monitor_fixture(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let monitor = monitor::create(
        &mut *conn,
        NewMonitor {
            name: context.get_clone("monitor-name")?,
            authentication_key: context.get_clone("monitor-authentication-key")?,
        },
    )
    .await?;

    Ok(context.with("monitor", monitor.id))
}

pub async fn fixture(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let context = monitor_fixture(
        conn,
        context
            .with("monitor-name", "testmonitor".to_string())
            .with("monitor-authentication-key", "testmonitor".to_string()),
    )
    .await?;
    let monitor_id: MonitorId = context.get_copy("monitor")?;

    Ok(context.with("test-monitor", monitor_id))
}
