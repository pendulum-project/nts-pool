use std::collections::BTreeSet;

#[derive(Clone, Debug, serde::Serialize)]
pub struct PageLink {
    /// Concrete page number, or `None` to represent an ellipsis.
    pub number: Option<u32>,
    /// Marks the current page.
    pub current: bool,
}

/// Build a condensed list of pagination links.
///
/// Always includes the first and last page, the current page, and up to two neighbours on each
/// side. Large gaps are represented as `None`, allowing templates to render ellipses.
pub(super) fn build_links(page: u32, total_pages: u32) -> Vec<PageLink> {
    if total_pages == 0 {
        return Vec::new();
    }

    let mut page_numbers = BTreeSet::new();
    page_numbers.insert(1);
    page_numbers.insert(total_pages);

    for offset in 0..=2 {
        if page > offset {
            page_numbers.insert(page - offset);
        }
        let next = page + offset;
        if next <= total_pages {
            page_numbers.insert(next);
        }
    }

    let mut links = Vec::new();
    let mut previous = None;

    for number in page_numbers {
        if let Some(prev) = previous
            && number > prev + 1
        {
            links.push(PageLink {
                number: None,
                current: false,
            });
        }

        links.push(PageLink {
            number: Some(number),
            current: number == page,
        });
        previous = Some(number);
    }

    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_when_total_pages_is_zero() {
        let links = build_links(1, 0);
        assert!(links.is_empty());
    }

    #[test]
    fn builds_compact_sequence_without_gaps() {
        let links = build_links(2, 3);
        let numbers: Vec<Option<u32>> = links.iter().map(|l| l.number).collect();
        assert_eq!(numbers, vec![Some(1), Some(2), Some(3)]);
        assert_eq!(links.iter().filter(|l| l.current).count(), 1);
        assert!(links.iter().any(|l| l.current && l.number == Some(2)));
    }

    #[test]
    fn inserts_ellipses_when_gap_exists() {
        let links = build_links(5, 10);
        let numbers: Vec<Option<u32>> = links.iter().map(|l| l.number).collect();

        assert_eq!(
            numbers,
            vec![
                Some(1),
                None,
                Some(3),
                Some(4),
                Some(5),
                Some(6),
                Some(7),
                None,
                Some(10)
            ]
        );
        assert!(links.iter().any(|l| l.current && l.number == Some(5)));
    }
}
