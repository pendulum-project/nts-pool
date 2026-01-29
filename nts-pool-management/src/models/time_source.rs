use std::collections::HashSet;

use chrono::{DateTime, Utc};
use eyre::Context;
use nts_pool_shared::IpVersion;
use phf::phf_map;
use serde::Deserialize;
use sha3::Digest;

use crate::{
    DbConnLike,
    context::AppContext,
    error::AppError,
    models::{
        monitor::MonitorId,
        user::UserId,
        util::{port::Port, uuid},
    },
};

static CONTINENTS: phf::Map<&'static str, &'static str> = phf_map! {
    "AF" => "AFRICA",
    "AN" => "ANTARCTICA",
    "AS" => "ASIA",
    "EU" => "EUROPE",
    "NA" => "NORTH-AMERICA",
    "OC" => "OCEANIA",
    "SA" => "SOUTH_AMERICA",
};

uuid!(TimeSourceId);

#[derive(Debug, Clone, Deserialize, sqlx::FromRow, sqlx::Type)]
pub struct TimeSource {
    pub id: TimeSourceId,
    pub owner: UserId,
    pub hostname: String,
    pub port: Option<Port>,
    pub countries: Vec<String>,
    pub auth_token_randomizer: String,
    pub base_secret_index: i32,
    pub weight: i32,
    pub ipv4_score: f64,
    pub ipv6_score: f64,
    pub srv4_score: f64,
    pub srv6_score: f64,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct NewTimeSource {
    pub hostname: String,
    pub port: Port,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NewTimeSourceForm {
    pub hostname: String,
    pub port: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpdateTimeSourceForm {
    pub weight: i32,
}

const DEFAULT_NTSKE_PORT: u16 = 4460;

impl NewTimeSourceForm {
    pub fn into_new_source(self, context: &AppContext) -> Result<NewTimeSource, AppError> {
        let port = if self.port.is_empty() {
            DEFAULT_NTSKE_PORT
                .try_into()
                .wrap_err("Internal app error, 4460 not a valid port")?
        } else {
            self.port
                .parse::<u16>()
                .wrap_err("Could not parse into port number")?
                .try_into()
                .wrap_err("Could not parse into port number")?
        };

        check_hostname_reasonable(&self.hostname, context)?;

        Ok(NewTimeSource {
            hostname: self.hostname,
            port,
        })
    }
}

fn check_hostname_reasonable(hostname: &str, context: &AppContext) -> Result<(), AppError> {
    if hostname.is_empty()
        || !hostname
            .chars()
            .all(|c| matches!(c, '0'..='9' | '.' | '-' | 'a'..='z' | 'A'..='Z'))
        || hostname.ends_with(".local")
        || hostname.ends_with(".")
        || hostname.ends_with("localhost")
        || hostname.ends_with(&context.ke_domain)
    {
        return Err(eyre::eyre!("Invalid domain name").into());
    }

    Ok(())
}

pub async fn infer_regions(
    hostname: impl AsRef<str>,
    geodb: &maxminddb::Reader<impl AsRef<[u8]>>,
) -> Vec<String> {
    // Note: port doesn't matter but is needed for the lookup_host interface
    let addresses = match tokio::net::lookup_host((hostname.as_ref(), 4460)).await {
        Ok(addresses) => addresses,
        Err(e) => {
            if e.raw_os_error().is_some() {
                // Definitely an issue
                tracing::error!("Could not resolve hostname of time source: {e}");
            }
            return vec![];
        }
    };

    let mut result = HashSet::new();
    for addr in addresses {
        let Some(lookup) = (match geodb
            .lookup(addr.ip())
            .and_then(|r| r.decode::<maxminddb::geoip2::Country>())
        {
            Ok(lookup) => lookup,
            Err(e) => {
                tracing::error!("Failure during geoip lookup: {e}");
                None
            }
        }) else {
            continue;
        };

        if let Some(continent) = lookup.continent.code.and_then(|c| CONTINENTS.get(c)) {
            result.insert((*continent).to_owned());
        }
        if let Some(country) = lookup.country.iso_code {
            result.insert(country.to_owned());
        }
    }

    result.into_iter().collect()
}

pub fn calculate_auth_key(
    base_shared_secret: &[u8],
    timesource_id: TimeSourceId,
    auth_token_randomizer: impl AsRef<str>,
) -> String {
    struct HashOutput<'a>(&'a [u8]);
    impl<'a> std::fmt::Display for HashOutput<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for el in self.0 {
                write!(f, "{:02x}", el)?;
            }
            Ok(())
        }
    }

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(base_shared_secret);
    hasher.update(timesource_id.to_string().as_bytes());
    hasher.update(auth_token_randomizer.as_ref().as_bytes());
    let hash = hasher.finalize();
    format!("{}", HashOutput(hash.as_slice()))
}

pub async fn create(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    new_time_source: NewTimeSource,
    base_secret_index: i32,
    geodb: &maxminddb::Reader<impl AsRef<[u8]>>,
) -> Result<TimeSourceId, sqlx::Error> {
    let regions = infer_regions(&new_time_source.hostname, geodb).await;

    sqlx::query!(
        r#"
            INSERT INTO time_sources (owner, hostname, port, countries, base_secret_index)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        "#,
        owner as _,
        new_time_source.hostname,
        new_time_source.port as _,
        regions.as_slice(),
        base_secret_index,
    )
    .fetch_one(conn)
    .await
    .map(|v| v.id.into())
}

pub async fn update(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
    time_source: UpdateTimeSourceForm,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE time_sources
            SET weight = $3
            WHERE id = $1 AND owner = $2
        "#,
        time_source_id as _,
        owner as _,
        time_source.weight
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn update_auth_token_randomizer(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
    auth_token_randomizer: String,
    base_secret_index: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            UPDATE time_sources
            SET auth_token_randomizer = $3, base_secret_index = $4
            WHERE id = $2 AND owner = $1
        "#,
        owner as _,
        time_source_id as _,
        auth_token_randomizer,
        base_secret_index,
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delete(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
             UPDATE time_sources
             SET deleted = true
             WHERE id = $1 AND owner = $2;
        "#,
        time_source_id as _,
        owner as _,
    )
    .execute(conn)
    .await?;

    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LogRow {
    pub score: f64,
    pub protocol: IpVersion,
    pub monitor: MonitorId,
    pub sample: sqlx::types::JsonValue,
    pub received_at: DateTime<Utc>,
}

impl std::fmt::Display for LogRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sample = serde_json::to_string(&self.sample)
            .unwrap_or_else(|_| format!("Formatting error on {:?}", self.sample));
        write!(
            f,
            "Sample from {} for {} giving new score {:.1}: {}",
            self.monitor, self.protocol, self.score, sample
        )
    }
}

pub async fn logs(
    conn: impl DbConnLike<'_>,
    time_source_id: TimeSourceId,
    monitor_id: MonitorId,
    protocol: IpVersion,
    offset: i64,
    limit: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as!(
        LogRow,
        r#"
            SELECT score, protocol as "protocol: IpVersion", monitor_id as monitor, raw_sample AS sample, received_at
            FROM monitor_samples
            WHERE time_source_id = $1 AND protocol = $2 AND monitor_id = $3
            ORDER BY monitor_samples.received_at DESC
            OFFSET $4
            LIMIT $5
        "#,
        time_source_id as _,
        protocol as _,
        monitor_id as _,
        offset,
        limit,
    )
    .fetch_all(conn)
    .await
}

pub async fn log_count(
    conn: impl DbConnLike<'_>,
    time_source_id: TimeSourceId,
    monitor_id: MonitorId,
    protocol: IpVersion,
) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM monitor_samples
        WHERE time_source_id = $1 AND protocol = $2 AND monitor_id = $3
        "#,
        time_source_id as _,
        protocol as _,
        monitor_id as _,
    )
    .fetch_one(conn)
    .await?
    .count)
}

pub async fn source_name(
    conn: impl DbConnLike<'_>,
    owner: UserId,
    time_source_id: TimeSourceId,
) -> Result<String, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
            SELECT hostname FROM time_sources
            WHERE owner = $1 AND id = $2
        "#,
        owner as _,
        time_source_id as _,
    )
    .fetch_one(conn)
    .await?
    .hostname)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScoreListEntry {
    pub id: MonitorId,
    pub protocol: IpVersion,
    pub score: f64,
}

pub async fn scores(
    conn: impl DbConnLike<'_>,
    id: TimeSourceId,
) -> Result<Vec<ScoreListEntry>, sqlx::Error> {
    sqlx::query_as!(
        ScoreListEntry,
        r#"
            SELECT ms2.monitor_id AS "id!: _", ms2.protocol AS "protocol!: _", ms2.score AS "score!: _" FROM (
                SELECT time_source_id, protocol, monitor_id, MAX(received_at) AS target_received_at
                FROM monitor_samples
                WHERE time_source_id = $1
                GROUP BY time_source_id, protocol, monitor_id
            ) AS ms1
            LEFT JOIN monitor_samples AS ms2 ON
                ms1.time_source_id = ms2.time_source_id AND
                ms1.protocol = ms2.protocol AND
                ms1.monitor_id = ms2.monitor_id AND
                ms1.target_received_at = ms2.received_at
        "#,
        id as _
    )
    .fetch_all(conn)
    .await
}

pub async fn details(
    conn: impl DbConnLike<'_>,
    id: TimeSourceId,
) -> Result<TimeSource, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT
                id AS "id!",
                owner AS "owner!",
                hostname AS "hostname!",
                port AS "port: _",
                countries AS "countries!",
                auth_token_randomizer AS "auth_token_randomizer!",
                base_secret_index AS "base_secret_index!",
                weight AS "weight!",
                ipv4_score AS "ipv4_score!: _",
                ipv6_score AS "ipv6_score!: _",
                srv4_score AS "srv4_score!: _",
                srv6_score AS "srv6_score!: _"
            FROM time_source_scores
            WHERE id = $1 AND deleted = false;
        "#,
        id as _,
    )
    .fetch_one(conn)
    .await
}

pub async fn by_user(
    conn: impl DbConnLike<'_>,
    owner: UserId,
) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT
                id AS "id!",
                owner AS "owner!",
                hostname AS "hostname!",
                port AS "port: _",
                countries AS "countries!",
                auth_token_randomizer AS "auth_token_randomizer!",
                base_secret_index AS "base_secret_index!",
                weight AS "weight!",
                ipv4_score AS "ipv4_score!: _",
                ipv6_score AS "ipv6_score!: _",
                srv4_score AS "srv4_score!: _",
                srv6_score AS "srv6_score!: _"
            FROM time_source_scores
            WHERE owner = $1 AND deleted = false;
        "#,
        owner as _,
    )
    .fetch_all(conn)
    .await
}

pub async fn list(conn: impl DbConnLike<'_>) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT
                id AS "id!",
                owner AS "owner!",
                hostname AS "hostname!",
                port AS "port: _",
                countries AS "countries!",
                auth_token_randomizer AS "auth_token_randomizer!",
                base_secret_index AS "base_secret_index!",
                weight AS "weight!",
                ipv4_score AS "ipv4_score!: _",
                ipv6_score AS "ipv6_score!: _",
                srv4_score AS "srv4_score!: _",
                srv6_score AS "srv6_score!: _"
            FROM time_source_scores
            WHERE deleted = false;
        "#,
    )
    .fetch_all(conn)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TimeSourceWithOwner {
    pub time_source: TimeSource,
    pub user_email: String,
}

pub async fn list_with_owner_names(
    conn: impl DbConnLike<'_>,
) -> Result<Vec<TimeSourceWithOwner>, sqlx::Error> {
    sqlx::query_as!(
        TimeSourceWithOwner,
        r#"
            SELECT
                (
                    ts.id,
                    ts.owner,
                    ts.hostname,
                    ts.port,
                    ts.countries,
                    ts.auth_token_randomizer,
                    ts.base_secret_index,
                    ts.weight,
                    ts.ipv4_score,
                    ts.ipv6_score,
                    ts.srv4_score,
                    ts.srv6_score
                ) AS "time_source!: TimeSource",
                u.email AS "user_email!"
            FROM time_source_scores AS ts
            LEFT JOIN users AS u ON ts.owner = u.id
            WHERE ts.deleted = false;
        "#,
    )
    .fetch_all(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_source_form_valid_without_port_1() {
        assert_eq!(
            NewTimeSourceForm {
                hostname: "test".into(),
                port: "".into()
            }
            .into_new_source(&AppContext::default())
            .unwrap(),
            NewTimeSource {
                hostname: "test".into(),
                port: 4460.try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_time_source_form_valid_without_port_2() {
        assert_eq!(
            NewTimeSourceForm {
                hostname: "ExAmPlE.com".into(),
                port: "".into()
            }
            .into_new_source(&AppContext::default())
            .unwrap(),
            NewTimeSource {
                hostname: "ExAmPlE.com".into(),
                port: 4460.try_into().unwrap(),
            }
        );
    }

    #[test]
    fn test_time_source_form_valid_with_port() {
        assert_eq!(
            NewTimeSourceForm {
                hostname: "test".into(),
                port: "456".into()
            }
            .into_new_source(&AppContext::default())
            .unwrap(),
            NewTimeSource {
                hostname: "test".into(),
                port: 456.try_into().unwrap()
            }
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_1() {
        assert!(
            NewTimeSourceForm {
                hostname: "js(.com".into(),
                port: "".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_2() {
        assert!(
            NewTimeSourceForm {
                hostname: "jsê.com".into(),
                port: "".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_3() {
        assert!(
            NewTimeSourceForm {
                hostname: "js@.com".into(),
                port: "".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_0() {
        assert!(
            NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "0".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_100000() {
        assert!(
            NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "100000".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_non_numeric_port() {
        assert!(
            NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "fe".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_with_trailing_garbage() {
        assert!(
            NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "123 abc".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_require_hostname() {
        assert!(
            NewTimeSourceForm {
                hostname: "".into(),
                port: "".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_local() {
        assert!(
            NewTimeSourceForm {
                hostname: "example.local".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );

        assert!(
            NewTimeSourceForm {
                hostname: "localhost".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );

        assert!(
            NewTimeSourceForm {
                hostname: "example.local.".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );

        assert!(
            NewTimeSourceForm {
                hostname: "example.localhost".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext::default())
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_ke_domain() {
        assert!(
            NewTimeSourceForm {
                hostname: "ke.example.org".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext {
                ke_domain: "ke.example.org".into(),
                ..AppContext::default()
            })
            .is_err()
        );

        assert!(
            NewTimeSourceForm {
                hostname: "bla.ke.example.org".into(),
                port: "123".into(),
            }
            .into_new_source(&AppContext {
                ke_domain: "ke.example.org".into(),
                ..AppContext::default()
            })
            .is_err()
        );
    }
}
