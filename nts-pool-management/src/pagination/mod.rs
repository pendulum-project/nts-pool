mod info;
mod links;
mod params;

/// Maximum permitted page size to avoid expensive queries.
const MAX_PER_PAGE: u32 = 500;

pub use info::PaginationInfo;
pub use links::PageLink;
pub use params::{Pagination, SortDirection};
