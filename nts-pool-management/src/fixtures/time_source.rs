use eyre::Context;
use sqlx::PgConnection;
use uuid::Uuid;

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
            id: context.get_copy("time-source-id").ok(),
        },
        1,
        &TestGeoSource,
    )
    .await?;

    time_source::update_auth_token_randomizer(
        &mut *conn,
        owner,
        ts,
        context.get_clone("time-source-auth-token-randomizer")?,
        0,
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
    let ts1_uuid: TimeSourceId = Uuid::parse_str("1532f796-7a16-40bd-8d5a-4d09fc90e061")
        .wrap_err("Invalid UUID for time source 1")?
        .into();
    let context = time_source_fixture(
        conn,
        context
            .with("time-source-id", ts1_uuid)
            .with("time-source-user", admin)
            .with("time-source-hostname", "time-a".to_string())
            .with(
                "time-source-auth-token-randomizer",
                "4a4A8wEJ2ZKte6DJ3VxK6e".to_string(),
            )
            .with(
                "time-source-port",
                Port::new(4460).wrap_err("Invalid port")?,
            ),
    )
    .await?;
    let ts1: TimeSourceId = context.get_copy("time-source")?;

    // create the second time source
    let ts2_uuid: TimeSourceId = Uuid::parse_str("de9b1a09-691a-431e-908a-2625e3c34a84")
        .wrap_err("Invalid UUID for time source 2")?
        .into();
    let context = time_source_fixture(
        conn,
        context
            .with("time-source-id", ts2_uuid)
            .with("time-source-user", admin)
            .with("time-source-hostname", "time-b".to_string())
            .with(
                "time-source-auth-token-randomizer",
                "rehrJnlBAKWNJyQE0V2MVv".to_string(),
            )
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
