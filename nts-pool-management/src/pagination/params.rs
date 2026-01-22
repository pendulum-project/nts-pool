use axum::{
    extract::{FromRequestParts, Query, rejection::QueryRejection},
    http::request::Parts,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{PaginationInfo, info};

#[derive(Debug, Copy, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

impl SortDirection {
    /// Reverse the current sort direction.
    pub fn reverse(&self) -> SortDirection {
        match self {
            SortDirection::Asc => SortDirection::Desc,
            SortDirection::Desc => SortDirection::Asc,
        }
    }
}

/// Raw pagination query parameters the client can supply.
#[derive(Debug, Deserialize, Serialize)]
pub struct Pagination<S: Default + PartialEq> {
    /// Requested page number (1-indexed). Defaults to `1`.
    #[serde(default = "default_page")]
    #[serde(skip_serializing_if = "is_default_page")]
    pub page: u32,
    /// Requested page size. Defaults to [`Pagination::default_per_page`].
    #[serde(default = "default_per_page")]
    #[serde(skip_serializing_if = "is_default_per_page")]
    pub per_page: u32,
    /// Optional field to sort by.
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub sort: S,
    /// Optional sort order.
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub order: SortDirection,
}

/// Default page when the user omits or zeroes the parameter.
const fn default_page() -> u32 {
    1
}

fn is_default_page(page: &u32) -> bool {
    *page == default_page()
}

/// Default page size when unspecified.
const fn default_per_page() -> u32 {
    500
}

fn is_default_per_page(per_page: &u32) -> bool {
    *per_page == default_per_page()
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

impl<S> Default for Pagination<S>
where
    S: Default + PartialEq,
{
    fn default() -> Self {
        Self {
            page: default_page(),
            per_page: default_per_page(),
            sort: S::default(),
            order: SortDirection::default(),
        }
    }
}

impl<S, SO> FromRequestParts<S> for Pagination<SO>
where
    S: Send + Sync,
    SO: DeserializeOwned + Serialize + Default + PartialEq,
    Pagination<SO>: DeserializeOwned,
{
    type Rejection = QueryRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(pagination) = Query::<Pagination<SO>>::from_request_parts(parts, state).await?;

        Ok(pagination)
    }
}

impl<S> Pagination<S>
where
    S: Serialize + Copy + PartialEq + Default,
{
    /// Combine the current request with the number of available items to compute final pagination
    /// values. This clamps the current page within valid bounds and prepares the metadata we need
    /// for database queries and template rendering.
    pub fn set_total(self, total_items: u64) -> PaginationInfo<S> {
        info::to_info(self, total_items)
    }

    pub fn as_query(&self) -> String {
        match serde_urlencoded::to_string(self) {
            Ok(query) if !query.is_empty() => format!("?{}", query),
            _ => String::from("?"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Copy, Clone, Deserialize, Serialize, Default, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum DummySort {
        #[default]
        Name,
        Age,
    }

    #[test]
    fn reverses_sort_direction() {
        assert_eq!(SortDirection::Asc.reverse(), SortDirection::Desc);
        assert_eq!(SortDirection::Desc.reverse(), SortDirection::Asc);
    }

    #[test]
    fn omits_defaults_in_query_string() {
        let pagination: Pagination<DummySort> = Pagination::default();
        assert_eq!(pagination.as_query(), "?");
    }

    #[test]
    fn serializes_all_fields_in_query_string() {
        let pagination = Pagination {
            page: 2,
            per_page: 15,
            sort: DummySort::Age,
            order: SortDirection::Desc,
        };

        assert_eq!(
            pagination.as_query(),
            "?page=2&per_page=15&sort=age&order=desc"
        );
    }
}
