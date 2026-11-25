//! Release names as versions: `v` and a semantic version (`v1.2.3`, `v1.3.0-rc.1`), ordered
//! as Semantic Versioning 2.0.0 orders them. A hand-over goes only to a newer one.

use std::cmp::Ordering;

use crate::{Error, Result};

/// One identifier of a pre-release.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ident {
    Number(u64),
    Text(String),
}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Ident::Number(a), Ident::Number(b)) => a.cmp(b),
            (Ident::Number(_), Ident::Text(_)) => Ordering::Less,
            (Ident::Text(_), Ident::Number(_)) => Ordering::Greater,
            (Ident::Text(a), Ident::Text(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A release version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    core: (u64, u64, u64),
    pre: Vec<Ident>,
}

fn number(text: &str) -> Option<u64> {
    let leading_zero = text.len() > 1 && text.starts_with('0');
    if text.is_empty() || leading_zero || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl Version {
    /// Reads a release name: `v`, MAJOR.MINOR.PATCH, and an optional `-` pre-release of
    /// dot-separated identifiers. Build metadata (`+...`) is refused: it would not order.
    pub fn parse(name: &str) -> Result<Self> {
        let bad = || Error::ReleaseInvalid(name.chars().take(64).collect());
        let rest = name.strip_prefix('v').ok_or_else(bad)?;
        if rest.contains('+') {
            return Err(bad());
        }
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let mut parts = core.split('.');
        let core = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (
                number(a).ok_or_else(bad)?,
                number(b).ok_or_else(bad)?,
                number(c).ok_or_else(bad)?,
            ),
            _ => return Err(bad()),
        };
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|ident| {
                    if ident.is_empty()
                        || !ident
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        Err(bad())
                    } else if ident.bytes().all(|b| b.is_ascii_digit()) {
                        number(ident).map(Ident::Number).ok_or_else(bad)
                    } else {
                        Ok(Ident::Text(ident.to_string()))
                    }
                })
                .collect::<Result<Vec<_>>>()?,
        };
        Ok(Self { core, pre })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A pre-release comes before its release.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Whether release `to` is newer than release `from`; a name that is not a version is never
/// newer.
pub fn is_newer(from: &str, to: &str) -> bool {
    matches!((Version::parse(from), Version::parse(to)), (Ok(a), Ok(b)) if b > a)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn semver_order() {
        let ordered = [
            "v0.9.9",
            "v1.0.0-alpha",
            "v1.0.0-alpha.1",
            "v1.0.0-alpha.beta",
            "v1.0.0-beta",
            "v1.0.0-beta.2",
            "v1.0.0-beta.11",
            "v1.0.0-rc.1",
            "v1.0.0",
            "v1.0.1",
            "v1.10.0",
            "v2.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(is_newer(pair[0], pair[1]), "{pair:?}");
            assert!(!is_newer(pair[1], pair[0]), "{pair:?}");
        }
        assert!(!is_newer("v1.0.0", "v1.0.0"));
    }

    #[test]
    fn names_that_are_not_versions() {
        for bad in [
            "1.0.0",
            "v1.0",
            "v1.0.0.0",
            "v01.0.0",
            "dev",
            "v1.0.0+build",
            "v1.0.0-",
            "v1.0.0-a..b",
            "v1.0.0-01",
            "v-1.0.0",
            "",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad}");
            assert!(!is_newer("v0.0.1", bad));
            assert!(!is_newer(bad, "v9.9.9"));
        }
    }
}
