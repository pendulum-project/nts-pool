use eyre::Context;
use sqlx::PgConnection;

use crate::{
    fixtures::{FixtureContext, FixtureError},
    geo::{GeoLookupResult, GeoLookupSource},
    models::{
        time_source::{self, NewTimeSource, TimeSourceId},
        user::UserId,
        util::port::Port,
    },
};

pub async fn time_source_fixture(
    conn: &mut PgConnection,
    mut context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let owner = context.get_copy("time-source-user")?;

    struct TestGeoSource;

    impl GeoLookupSource for TestGeoSource {
        fn lookup(&self, _ip: std::net::IpAddr) -> Result<GeoLookupResult, eyre::Error> {
            return Ok(GeoLookupResult::new(
                Some("NL".into()),
                Some("EUROPE".into()),
            ));
        }
    }

    let ts = time_source::create(
        &mut *conn,
        owner,
        NewTimeSource {
            hostname: context.get_clone("time-source-hostname")?,
            port: context.get_copy("time-source-port")?,
        },
        1,
        &TestGeoSource,
    )
    .await?;
    context.set("time-source", ts);

    Ok(context)
}

pub async fn fixture(
    conn: &mut PgConnection,
    context: FixtureContext,
) -> Result<FixtureContext, FixtureError> {
    let admin: UserId = context.get_copy("admin")?;

    // Create the first time source
    let context = time_source_fixture(
        conn,
        context
            .with("time-source-user", admin)
            .with("time-source-hostname", "test-time-local1".to_string())
            .with(
                "time-source-port",
                Port::new(4460).wrap_err("Invalid port")?,
            ),
    )
    .await?;
    let ts1: TimeSourceId = context.get_copy("time-source")?;

    // create the second time source
    let context = time_source_fixture(
        conn,
        context
            .with("time-source-user", admin)
            .with("time-source-hostname", "test-time-local2".to_string())
            .with(
                "time-source-port",
                Port::new(4460).wrap_err("Invalid port")?,
            ),
    )
    .await?;
    let ts2: TimeSourceId = context.get_copy("time-source")?;

    Ok(context
        .with("time-source-1", ts1)
        .with("time-source-2", ts2))
}
