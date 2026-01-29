use serde::Serialize;

use super::{MAX_PER_PAGE, PageLink, Pagination, SortDirection, links::build_links};

/// Pagination metadata consumed by templates and components.
#[derive(Clone, Debug, Serialize)]
pub struct PaginationInfo<S> {
    /// Current 1-indexed page.
    pub page: u32,
    /// Items per page after clamping.
    pub per_page: u32,
    pub has_prev: bool,
    pub has_next: bool,
    pub total_pages: u32,
    pub total_items: u64,
    /// Pre-computed markup-friendly page links (numbers and ellipses).
    pub links: Vec<PageLink>,

    pub sort: S,
    pub order: SortDirection,
}

impl<S> PaginationInfo<S>
where
    S: Serialize + Copy + PartialEq + Default,
{
    /// Translate the pagination configuration into a SQL `LIMIT`.
    pub fn limit(&self) -> i64 {
        self.per_page as i64
    }

    /// Translate the pagination configuration into a SQL `OFFSET`.
    pub fn offset(&self) -> i64 {
        ((self.page - 1) as i64) * self.per_page as i64
    }

    pub fn total_items(&self) -> u64 {
        self.total_items
    }

    /// Generate a URL query string for the given page and per-page values.
    pub fn url(&self, page: u32, per_page: u32) -> String {
        Pagination {
            page,
            per_page,
            sort: self.sort,
            order: self.order,
        }
        .as_query()
    }

    pub fn sort(&self) -> &S {
        &self.sort
    }

    pub fn direction(&self) -> &SortDirection {
        &self.order
    }

    pub fn next(&self) -> String {
        self.url(self.page + 1, self.per_page)
    }

    pub fn prev(&self) -> String {
        self.url(self.page.saturating_sub(1), self.per_page)
    }

    pub fn goto(&self, page: &u32) -> String {
        self.url(*page, self.per_page)
    }

    pub fn sort_link(&self, sort: S) -> String {
        Pagination {
            page: 1,
            per_page: self.per_page,
            sort,
            order: if sort == self.sort {
                self.order.reverse()
            } else {
                self.order
            },
        }
        .as_query()
    }

    pub fn dir_icon(&self, sort: S) -> &'static str {
        if sort == self.sort {
            match self.order {
                SortDirection::Asc => "▲",
                SortDirection::Desc => "▼",
            }
        } else {
            ""
        }
    }
}

pub fn to_info<S>(pagination: Pagination<S>, total_items: u64) -> PaginationInfo<S>
where
    S: Serialize + Copy + PartialEq + Default,
{
    let per_page = pagination.per_page.clamp(1, MAX_PER_PAGE);

    let total_pages = if total_items == 0 {
        1
    } else {
        ((total_items - 1) / per_page as u64) as u32 + 1
    };

    let page: u32 = pagination.page.min(total_pages).max(1);
    let has_prev = page > 1;
    let has_next = page < total_pages;

    PaginationInfo {
        page,
        per_page,
        has_prev,
        has_next,
        total_pages,
        total_items,
        links: build_links(page, total_pages),
        sort: pagination.sort,
        order: pagination.order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Copy, Clone, PartialEq, Default)]
    #[serde(rename_all = "snake_case")]
    enum DummySort {
        #[default]
        Name,
        Age,
    }

    #[test]
    fn clamps_page_and_page_size_and_builds_meta() {
        let pagination = Pagination {
            page: 5,
            per_page: 1_000,
            sort: DummySort::Name,
            order: SortDirection::Desc,
        };

        let info = pagination.set_total(1_200);

        assert_eq!(info.page, 3);
        assert_eq!(info.per_page, MAX_PER_PAGE);
        assert_eq!(info.total_pages, 3);
        assert!(info.has_prev);
        assert!(!info.has_next);
        assert_eq!(info.limit(), 500);
        assert_eq!(info.offset(), 1_000);
        assert!(info.links.iter().any(|l| l.current && l.number == Some(3)));
    }

    #[test]
    fn builds_urls_and_sort_links() {
        let pagination = Pagination {
            page: 2,
            per_page: 10,
            sort: DummySort::Name,
            order: SortDirection::Desc,
        };
        let info = pagination.set_total(50);

        assert_eq!(info.url(3, 5), "?page=3&per_page=5&order=desc");
        assert_eq!(info.next(), "?page=3&per_page=10&order=desc");
        assert_eq!(info.prev(), "?per_page=10&order=desc");
        assert_eq!(info.goto(&5), "?page=5&per_page=10&order=desc");

        assert_eq!(info.sort_link(DummySort::Name), "?per_page=10");
        assert_eq!(
            info.sort_link(DummySort::Age),
            "?per_page=10&sort=age&order=desc"
        );

        assert_eq!(info.dir_icon(DummySort::Name), "▼");
        assert_eq!(info.dir_icon(DummySort::Age), "");
    }
}
