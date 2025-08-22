use std::borrow::Cow;

use sqlx::PgPool;
use testcontainers::{
    ContainerAsync, Image,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};

pub struct PostgresContainer;

impl PostgresContainer {
    pub async fn connection_string(node: &ContainerAsync<PostgresContainer>) -> String {
        format!(
            "postgres://nts-pool:nts-pool@{}:{}/nts-pool",
            node.get_host()
                .await
                .expect("Failed to get PostgreSQL host"),
            node.get_host_port_ipv4(5432)
                .await
                .expect("Failed to get PostgreSQL port")
        )
    }

    pub async fn init() -> (ContainerAsync<PostgresContainer>, PgPool) {
        let node = PostgresContainer
            .start()
            .await
            .expect("Failed to start PostgreSQL container");
        let conn_str = PostgresContainer::connection_string(&node).await;
        let pool = crate::pool_conn(&conn_str, 1, std::time::Duration::from_secs(1), true)
            .await
            .expect("Failed to connect to PostgreSQL container");
        (node, pool)
    }
}

impl Image for PostgresContainer {
    fn name(&self) -> &str {
        "ghcr.io/tweedegolf/postgres"
    }

    fn tag(&self) -> &str {
        "17"
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![
            WaitFor::message_on_stderr("database system is ready to accept connections"),
            WaitFor::message_on_stdout("database system is ready to accept connections"),
        ]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        vec![
            ("POSTGRES_USER", "nts-pool"),
            ("POSTGRES_DB", "nts-pool"),
            ("TZ", "Europe/Amsterdam"),
            ("POSTGRES_HOST_AUTH_METHOD", "trust"),
        ]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[ContainerPort::Tcp(5432)]
    }
}
