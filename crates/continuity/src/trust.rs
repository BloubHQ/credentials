//! The pinned Sigstore trust root: the Fulcio certificate authorities and the Rekor log keys,
//! in the `trusted_root.json` format of Sigstore (`dev.sigstore.trustedroot.v0.1`), the
//! file the Sigstore root of trust (TUF, `sigstore/root-signing`) distributes.
//!
//! The production root is compiled in from `trust/trusted_root.json`, so it is part of the
//! measured enclave image and of the client library.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The trusted root compiled into this build (`crates/continuity/trust/trusted_root.json`).
pub const PRODUCTION_TRUSTED_ROOT: &[u8] = include_bytes!("../trust/trusted_root.json");

/// A Fulcio certificate authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// The trust anchor: the last certificate of the chain (DER).
    pub root: Vec<u8>,
    /// The certificates between a signing certificate and the root (DER).
    pub intermediates: Vec<Vec<u8>>,
    /// When it began to issue, Unix milliseconds.
    pub valid_from_ms: u64,
    /// When it stopped, if it did.
    pub valid_until_ms: Option<u64>,
}

/// A Rekor transparency log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    /// Its public key (SubjectPublicKeyInfo, DER); ECDSA P-256.
    pub key: Vec<u8>,
    /// SHA-256 of the key: the log id entries name.
    pub key_id: [u8; 32],
    /// When the key began to sign, Unix milliseconds.
    pub valid_from_ms: u64,
    /// When it stopped, if it did.
    pub valid_until_ms: Option<u64>,
}

/// The authorities and logs a successor statement may be signed and logged by.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustRoot {
    /// Fulcio certificate authorities.
    pub authorities: Vec<Authority>,
    /// Rekor logs.
    pub logs: Vec<Log>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File {
    #[serde(default)]
    tlogs: Vec<TlogJson>,
    #[serde(default)]
    certificate_authorities: Vec<AuthorityJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TlogJson {
    public_key: KeyJson,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyJson {
    raw_bytes: String,
    #[serde(default)]
    key_details: Option<String>,
    valid_for: Option<ValidFor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityJson {
    cert_chain: ChainJson,
    valid_for: Option<ValidFor>,
}

#[derive(Deserialize)]
struct ChainJson {
    certificates: Vec<RawBytes>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBytes {
    raw_bytes: String,
}

#[derive(Deserialize)]
struct ValidFor {
    start: Option<String>,
    end: Option<String>,
}

fn bytes(text: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|_| Error::TrustRootInvalid("a value is not base64"))
}

fn window(valid: Option<&ValidFor>) -> Result<(u64, Option<u64>)> {
    let Some(valid) = valid else {
        return Ok((0, None));
    };
    let start = valid
        .start
        .as_deref()
        .map(rfc3339_ms)
        .transpose()?
        .unwrap_or(0);
    let end = valid.end.as_deref().map(rfc3339_ms).transpose()?;
    Ok((start, end))
}

impl TrustRoot {
    /// Reads a `trusted_root.json`.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let file: File = serde_json::from_slice(json)
            .map_err(|_| Error::TrustRootInvalid("not a trusted root"))?;
        let mut root = TrustRoot::default();
        for log in file.tlogs {
            if log
                .public_key
                .key_details
                .as_deref()
                .is_some_and(|d| d != "PKIX_ECDSA_P256_SHA_256")
            {
                // Only ECDSA P-256 logs (the Rekor v1 of the public instance) are read.
                continue;
            }
            let key = bytes(&log.public_key.raw_bytes)?;
            let (valid_from_ms, valid_until_ms) = window(log.public_key.valid_for.as_ref())?;
            root.logs.push(Log {
                key_id: Sha256::digest(&key).into(),
                key,
                valid_from_ms,
                valid_until_ms,
            });
        }
        for authority in file.certificate_authorities {
            let mut chain = authority
                .cert_chain
                .certificates
                .iter()
                .map(|c| bytes(&c.raw_bytes))
                .collect::<Result<Vec<_>>>()?;
            let root_cert = chain
                .pop()
                .ok_or(Error::TrustRootInvalid("an authority has no certificate"))?;
            let (valid_from_ms, valid_until_ms) = window(authority.valid_for.as_ref())?;
            root.authorities.push(Authority {
                root: root_cert,
                intermediates: chain,
                valid_from_ms,
                valid_until_ms,
            });
        }
        Ok(root)
    }

    /// The trusted root compiled into this build.
    pub fn production() -> Result<Self> {
        Self::from_json(PRODUCTION_TRUSTED_ROOT)
    }

    /// True when it trusts no authority or no log: every statement is refused.
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty() || self.logs.is_empty()
    }
}

/// Whether `at` falls within `[from, until)`.
pub(crate) fn within(at: u64, from: u64, until: Option<u64>) -> bool {
    at >= from && until.is_none_or(|end| at < end)
}

fn digits(text: &str) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::TrustRootInvalid("a time is not RFC 3339"));
    }
    text.parse()
        .map_err(|_| Error::TrustRootInvalid("a time is not RFC 3339"))
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = i64::try_from(year).ok()? - i64::from(month <= 2);
    let month = i64::try_from(month).ok()?;
    let day = i64::try_from(day).ok()?;
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` as Unix milliseconds.
pub(crate) fn rfc3339_ms(text: &str) -> Result<u64> {
    let bad = || Error::TrustRootInvalid("a time is not RFC 3339");
    let text = text.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = text.split_once('T').ok_or_else(bad)?;
    let mut date = date.split('-');
    let (year, month, day) = match (date.next(), date.next(), date.next(), date.next()) {
        (Some(y), Some(m), Some(d), None) if y.len() == 4 && m.len() == 2 && d.len() == 2 => {
            (digits(y)?, digits(m)?, digits(d)?)
        }
        _ => return Err(bad()),
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    let mut clock = clock.split(':');
    let (hour, minute, second) = match (clock.next(), clock.next(), clock.next(), clock.next()) {
        (Some(h), Some(m), Some(s), None) if h.len() == 2 && m.len() == 2 && s.len() == 2 => {
            (digits(h)?, digits(m)?, digits(s)?)
        }
        _ => return Err(bad()),
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(bad());
    }
    let millis = match fraction {
        None => 0,
        Some(f) => {
            digits(f)?;
            let mut padded: String = f.chars().take(3).collect();
            while padded.len() < 3 {
                padded.push('0');
            }
            digits(&padded)?
        }
    };
    let days = days_from_civil(year, month, day).ok_or_else(bad)?;
    let secs = days
        .checked_mul(86_400)
        .and_then(|s| s.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(bad)?;
    secs.checked_mul(1_000)
        .and_then(|ms| ms.checked_add(millis))
        .ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn times() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            rfc3339_ms("2023-11-14T22:13:20.123Z").unwrap(),
            1_700_000_000_123
        );
        assert_eq!(
            rfc3339_ms("2000-02-29T00:00:00.5Z").unwrap(),
            951_782_400_500
        );
        for bad in [
            "2023-11-14 22:13:20Z",
            "2023-11-14T22:13:20",
            "2023-13-14T22:13:20Z",
            "2023-11-14T22:13:20.x1Z",
            "+023-11-14T22:13:20Z",
            "",
        ] {
            assert!(rfc3339_ms(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_compiled_root_parses() {
        let root = TrustRoot::production().unwrap();
        // The public instance: Rekor v1 (one ECDSA P-256 log; the Ed25519 Rekor v2 log is not
        // read) and its two Fulcio roots (the one of 2021-2022 and the current one).
        assert!(!root.is_empty());
        assert_eq!(root.logs.len(), 1);
        assert_eq!(root.authorities.len(), 2);
        assert!(root.authorities.iter().any(|a| a.valid_until_ms.is_none()));
    }
}
