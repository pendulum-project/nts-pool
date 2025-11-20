use std::collections::HashSet;

use chrono::{DateTime, Utc};
use eyre::Context;
use nts_pool_shared::IpVersion;
use phf::phf_map;
use serde::Deserialize;
use sha3::Digest;

use crate::{
    DbConnLike,
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

#[derive(Debug, Clone, Deserialize, sqlx::FromRow)]
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
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct NewTimeSource {
    pub hostname: String,
    pub port: Option<Port>,
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

impl TryFrom<NewTimeSourceForm> for NewTimeSource {
    type Error = AppError;

    fn try_from(form: NewTimeSourceForm) -> Result<Self, Self::Error> {
        let port = if form.port.is_empty() {
            None
        } else {
            Some(
                form.port
                    .parse::<u16>()
                    .wrap_err("Could not parse into port number")?
                    .try_into()
                    .wrap_err("Could not parse into port number")?,
            )
        };

        // Check domain name is reasonable (cf. RFC 1035)
        if form.hostname.is_empty()
            || !form
                .hostname
                .chars()
                .all(|c| matches!(c, '0'..='9' | '.' | '-' | 'a'..='z' | 'A'..='Z'))
        {
            return Err(eyre::eyre!("Invalid domain name").into());
        }

        Ok(Self {
            hostname: form.hostname,
            port,
        })
    }
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
        let Some(lookup) = (match geodb.lookup::<maxminddb::geoip2::Country>(addr.ip()) {
            Ok(lookup) => lookup,
            Err(e) => {
                tracing::error!("Failure during geoip lookup: {e}");
                None
            }
        }) else {
            continue;
        };

        if let Some(continent) = lookup
            .continent
            .and_then(|v| v.code)
            .and_then(|c| CONTINENTS.get(c))
        {
            result.insert((*continent).to_owned());
        }
        if let Some(country) = lookup.country.and_then(|v| v.iso_code) {
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
    owner: UserId,
    time_source_id: TimeSourceId,
    offset: i64,
    limit: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as!(
        LogRow,
        r#"
            SELECT score, protocol as "protocol: IpVersion", monitor_id as monitor, raw_sample AS sample, received_at
            FROM monitor_samples
            JOIN time_sources ON monitor_samples.time_source_id = time_sources.id
            WHERE time_sources.owner = $1 AND time_sources.id = $2
            ORDER BY monitor_samples.received_at DESC
            OFFSET $3
            LIMIT $4
        "#,
        owner as _,
        time_source_id as _,
        offset,
        limit,
    )
    .fetch_all(conn)
    .await
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

pub async fn by_user(
    conn: impl DbConnLike<'_>,
    owner: UserId,
) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT id, owner, hostname, port AS "port: _", countries, auth_token_randomizer, base_secret_index, weight, COALESCE(ipv4_score, 0) AS "ipv4_score!: _", COALESCE(ipv6_score, 0) AS "ipv6_score!: _" FROM time_sources
            LEFT JOIN (
                SELECT ms2.time_source_id, MAX(ms2.score) AS ipv4_score FROM (
                    SELECT time_source_id, protocol, monitor_id, MAX(received_at) AS target_received_at
                    FROM monitor_samples
                    WHERE protocol = 'ipv4'
                    GROUP BY time_source_id, protocol, monitor_id
                ) AS ms1
                LEFT JOIN monitor_samples AS ms2 ON
                    ms1.time_source_id = ms2.time_source_id AND
                    ms1.protocol = ms2.protocol AND
                    ms1.monitor_id = ms2.monitor_id AND
                    ms1.target_received_at = ms2.received_at
                GROUP BY
                    ms2.time_source_id
            ) AS s4 ON id = s4.time_source_id
            LEFT JOIN (
                SELECT ms2.time_source_id, MAX(ms2.score) AS ipv6_score FROM (
                    SELECT time_source_id, protocol, monitor_id, MAX(received_at) AS target_received_at
                    FROM monitor_samples
                    WHERE protocol = 'ipv6'
                    GROUP BY time_source_id, protocol, monitor_id
                ) AS ms1
                LEFT JOIN monitor_samples AS ms2 ON
                    ms1.time_source_id = ms2.time_source_id AND
                    ms1.protocol = ms2.protocol AND
                    ms1.monitor_id = ms2.monitor_id AND
                    ms1.target_received_at = ms2.received_at
                GROUP BY
                    ms2.time_source_id
            ) AS s6 ON id = s6.time_source_id
            WHERE owner = $1 AND deleted = false;
        "#,
        owner as _,
    )
    .fetch_all(conn)
    .await
}

pub async fn not_deleted(conn: impl DbConnLike<'_>) -> Result<Vec<TimeSource>, sqlx::Error> {
    sqlx::query_as!(
        TimeSource,
        r#"
            SELECT id, owner, hostname, port AS "port: _", countries, auth_token_randomizer, base_secret_index, weight, COALESCE(ipv4_score, 0) AS "ipv4_score!: _", COALESCE(ipv6_score, 0) AS "ipv6_score!: _" FROM time_sources
            LEFT JOIN (
                SELECT ms2.time_source_id, MAX(ms2.score) AS ipv4_score FROM (
                    SELECT time_source_id, protocol, monitor_id, MAX(received_at) AS target_received_at
                    FROM monitor_samples
                    WHERE protocol = 'ipv4'
                    GROUP BY time_source_id, protocol, monitor_id
                ) AS ms1
                LEFT JOIN monitor_samples AS ms2 ON
                    ms1.time_source_id = ms2.time_source_id AND
                    ms1.protocol = ms2.protocol AND
                    ms1.monitor_id = ms2.monitor_id AND
                    ms1.target_received_at = ms2.received_at
                GROUP BY
                    ms2.time_source_id
            ) AS s4 ON id = s4.time_source_id
            LEFT JOIN (
                SELECT ms2.time_source_id, MAX(ms2.score) AS ipv6_score FROM (
                    SELECT time_source_id, protocol, monitor_id, MAX(received_at) AS target_received_at
                    FROM monitor_samples
                    WHERE protocol = 'ipv6'
                    GROUP BY time_source_id, protocol, monitor_id
                ) AS ms1
                LEFT JOIN monitor_samples AS ms2 ON
                    ms1.time_source_id = ms2.time_source_id AND
                    ms1.protocol = ms2.protocol AND
                    ms1.monitor_id = ms2.monitor_id AND
                    ms1.target_received_at = ms2.received_at
                GROUP BY
                    ms2.time_source_id
            ) AS s6 ON id = s6.time_source_id
            WHERE deleted = false;
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
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "test".into(),
                port: "".into()
            })
            .unwrap(),
            NewTimeSource {
                hostname: "test".into(),
                port: None
            }
        );
    }

    #[test]
    fn test_time_source_form_valid_without_port_2() {
        assert_eq!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "ExAmPlE.com".into(),
                port: "".into()
            })
            .unwrap(),
            NewTimeSource {
                hostname: "ExAmPlE.com".into(),
                port: None
            }
        );
    }

    #[test]
    fn test_time_source_form_valid_with_port() {
        assert_eq!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "test".into(),
                port: "456".into()
            })
            .unwrap(),
            NewTimeSource {
                hostname: "test".into(),
                port: Some(456.try_into().unwrap())
            }
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_1() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "js(.com".into(),
                port: "".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_2() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "jsê.com".into(),
                port: "".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_weird_characters_3() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "js@.com".into(),
                port: "".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_0() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "0".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_100000() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "100000".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_non_numeric_port() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "fe".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_reject_port_with_trailing_garbage() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "example.com".into(),
                port: "123 abc".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn test_time_source_form_require_hostname() {
        assert!(
            NewTimeSource::try_from(NewTimeSourceForm {
                hostname: "".into(),
                port: "".into(),
            })
            .is_err()
        );
    }
}
