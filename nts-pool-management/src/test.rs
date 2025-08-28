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

pub trait IntoHtml {
    fn into_html(self) -> impl Future<Output = HtmlDocument> + Send;
}

impl IntoHtml for axum::response::Response {
    async fn into_html(self) -> HtmlDocument {
        let body = self.into_body();
        body.into_html().await
    }
}

impl IntoHtml for axum::body::Body {
    async fn into_html(self) -> HtmlDocument {
        let bytes = axum::body::to_bytes(self, 10_000_000)
            .await
            .expect("Failed to read response body");
        let body_str = std::str::from_utf8(&bytes).expect("Response body is not valid UTF-8");
        HtmlDocument(scraper::Html::parse_document(body_str))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct HtmlDocument(scraper::Html);

impl HtmlDocument {
    /// Get the matching element, or error if not exactly one is found.
    pub fn element(&self, selector: &str) -> SelectedElements<'_> {
        let elements = self.elements(selector);
        assert!(
            elements.len() == 1,
            "Expected exactly one element for selector '{selector}', found {}",
            elements.len()
        );
        SelectedElements(vec![elements[0]])
    }

    /// Get the first element matching the selector, or error if none are found.
    pub fn first_element(&self, selector: &str) -> SelectedElements<'_> {
        let elements = self.elements(selector);
        assert!(
            !elements.is_empty(),
            "Expected at least one element for selector '{selector}', found none"
        );
        SelectedElements(vec![elements[0]])
    }

    /// Get all elements matching the selector.
    pub fn elements(&self, selector: &str) -> SelectedElements<'_> {
        let sel = scraper::Selector::parse(selector)
            .unwrap_or_else(|_| panic!("Failed to parse selector: {selector}"));
        let elements = self.select(&sel).collect::<Vec<_>>();
        SelectedElements(elements)
    }

    pub fn body(&self) -> SelectedElements<'_> {
        self.element("body")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Deref)]
pub struct SelectedElements<'a>(Vec<scraper::ElementRef<'a>>);

impl<'a> SelectedElements<'a> {
    pub fn contains_text(&self, text: &str) {
        assert!(
            self.iter().any(|el| el.text().any(|t| t.contains(text))),
            "None of the selected elements contains the text '{text}'"
        );
    }

    pub fn exists(&self) {
        assert!(!self.is_empty(), "No elements found");
    }
}
