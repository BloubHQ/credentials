//! What a response may carry back: captured secrets are redacted, and a response that still
//! holds a secret is dropped.
//!
//! - A captured secret (a token the server just issued) of [`MIN_NEEDLE`] bytes or more is
//!   replaced with [`REDACTED`] wherever it appears raw, JSON-escaped (also with `\/`), or
//!   inside a JSON string written with any other escapes (`a`); a JSON string that holds
//!   it is replaced whole.
//! - A response that then still holds any captured secret (one shorter than
//!   [`MIN_NEEDLE`] counts wherever it appears), a secret field raw (from [`MIN_NEEDLE`]
//!   bytes), a secret field in a known encoding (from [`MIN_ENCODED`] bytes: base64 in both
//!   alphabets, percent encoding, JSON escaping, hex), or a rendered value that holds a secret
//!   in reversible form, fails with [`Error::Reflection`]. JSON strings are searched decoded as
//!   well.
//!
//! A server that echoes a value in another form (split, compressed in the body, encrypted) is
//! not caught; see the README.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

use crate::fields::Fields;
use crate::policy::Policy;
use crate::primitives::{hex, json_escape, pct};
use crate::response::find;
use crate::{Error, Result};

pub use crate::response::REDACTED;

/// Shortest secret searched raw.
pub const MIN_NEEDLE: usize = 4;
/// Shortest secret searched in its encoded forms.
pub const MIN_ENCODED: usize = 8;
/// Longest secret searched in percent, JSON and hex forms.
const ENCODED_LIMIT: usize = 1024 * 1024;

type Bytes = Zeroizing<Vec<u8>>;

/// The secrets of one operation.
pub(crate) struct Secrets<'a> {
    pub policy: &'a Policy,
    pub fields: &'a Fields,
    /// Values captured into secret fields or secret temporary values.
    pub captured: &'a [Bytes],
    /// Rendered values that hold a secret in reversible form.
    pub rendered: &'a [Bytes],
}

fn b64_with<E: Engine>(engine: &E, bytes: &[u8]) -> Result<Bytes> {
    let len = base64::encoded_len(bytes.len(), false).ok_or(Error::Encoding)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let written = engine
        .encode_slice(bytes, out.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    out.truncate(written);
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

/// `secret` JSON-escaped with every `/` written `\/`.
fn slashed(escaped: &[u8]) -> Bytes {
    let slashes = escaped.iter().filter(|b| **b == b'/').count();
    let mut out = Zeroizing::new(Vec::with_capacity(escaped.len() + slashes));
    for &b in escaped {
        if b == b'/' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

fn replace_all(bytes: &mut Vec<u8>, needle: &[u8], with: &[u8]) {
    let count = memchr::memmem::find_iter(bytes.as_slice(), needle).count();
    if needle.is_empty() || count == 0 {
        return;
    }
    let len = bytes.len() - count * needle.len() + count * with.len();
    let mut out = Vec::with_capacity(len);
    let mut rest = bytes.as_slice();
    while let Some(at) = find(rest, needle) {
        out.extend_from_slice(rest.get(..at).unwrap_or_default());
        out.extend_from_slice(with);
        rest = rest.get(at + needle.len()..).unwrap_or_default();
    }
    out.extend_from_slice(rest);
    bytes.zeroize();
    *bytes = out;
}

/// The spans (with quotes) of the JSON strings in `bytes` that hold a backslash, with their
/// decoded text. Bytes that are not JSON yield what parses as a JSON string.
fn escaped_strings(bytes: &[u8]) -> Vec<(usize, usize, Bytes)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(start) = memchr::memchr(b'"', bytes.get(i..).unwrap_or_default()).map(|p| p + i)
    {
        let mut j = start + 1;
        let mut escaped = false;
        let mut has_escape = false;
        let mut end = None;
        while let Some(&b) = bytes.get(j) {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
                has_escape = true;
            } else if b == b'"' {
                end = Some(j + 1);
                break;
            }
            j += 1;
        }
        let Some(end) = end else {
            break;
        };
        let token = bytes.get(start..end).unwrap_or_default();
        if has_escape && let Ok(mut text) = serde_json::from_slice::<String>(token) {
            out.push((start, end, Zeroizing::new(text.as_bytes().to_vec())));
            text.zeroize();
        }
        i = end;
    }
    out
}

/// Replaces the captured secrets in `bytes` with [`REDACTED`].
pub(crate) fn redact(bytes: &mut Vec<u8>, captured: &[Bytes]) {
    let mut any = false;
    for secret in captured.iter().filter(|s| s.len() >= MIN_NEEDLE) {
        any = true;
        replace_all(bytes, secret, REDACTED);
        let escaped = json_escape(secret);
        replace_all(bytes, &escaped, REDACTED);
        if secret.contains(&b'/') {
            replace_all(bytes, &slashed(&escaped), REDACTED);
        }
    }
    if !any {
        return;
    }
    let spans: Vec<(usize, usize)> = escaped_strings(bytes)
        .into_iter()
        .filter(|(_, _, text)| {
            captured
                .iter()
                .filter(|s| s.len() >= MIN_NEEDLE)
                .any(|s| contains(text, s))
        })
        .map(|(start, end, _)| (start, end))
        .collect();
    if spans.is_empty() {
        return;
    }
    let mut out = Vec::with_capacity(bytes.len() + spans.len() * (REDACTED.len() + 2));
    let mut at = 0;
    for (start, end) in spans {
        out.extend_from_slice(bytes.get(at..start).unwrap_or_default());
        out.push(b'"');
        out.extend_from_slice(REDACTED);
        out.push(b'"');
        at = end;
    }
    out.extend_from_slice(bytes.get(at..).unwrap_or_default());
    bytes.zeroize();
    *bytes = out;
}

/// The needles of the reflection check.
fn needles(s: &Secrets<'_>) -> Result<Vec<Bytes>> {
    let mut out: Vec<Bytes> = Vec::new();
    for value in s.captured {
        if !value.is_empty() {
            out.push(value.clone());
        }
    }
    for value in s.rendered.iter().filter(|r| r.len() >= MIN_NEEDLE) {
        out.push(value.clone());
    }
    for (name, value) in s.fields.values() {
        if !s.policy.is_secret(name) || value.len() < MIN_NEEDLE {
            continue;
        }
        out.push(Zeroizing::new(value.to_vec()));
        if value.len() < MIN_ENCODED {
            continue;
        }
        out.push(b64_with(&STANDARD_NO_PAD, value)?);
        out.push(b64_with(&URL_SAFE_NO_PAD, value)?);
        if value.len() <= ENCODED_LIMIT {
            let escaped = json_escape(value);
            if escaped.as_slice() != value {
                out.push(escaped);
            }
            let encoded = pct(value);
            if encoded.as_slice() != value {
                out.push(encoded);
            }
            let lower = hex(value);
            out.push(Zeroizing::new(lower.to_ascii_uppercase()));
            out.push(lower);
        }
    }
    Ok(out)
}

/// Fails with [`Error::Reflection`] when `bytes` holds a secret in a known form.
pub(crate) fn check(bytes: &[u8], s: &Secrets<'_>) -> Result<()> {
    let needles = needles(s)?;
    if needles.iter().any(|n| contains(bytes, n)) {
        return Err(Error::Reflection);
    }
    for (_, _, text) in escaped_strings(bytes) {
        if needles.iter().any(|n| contains(&text, n)) {
            return Err(Error::Reflection);
        }
    }
    Ok(())
}

/// Redacts and checks `bytes`; zeroizes them when the check fails.
pub(crate) fn release(mut bytes: Vec<u8>, s: &Secrets<'_>) -> Result<Vec<u8>> {
    redact(&mut bytes, s.captured);
    if let Err(error) = check(&bytes, s) {
        bytes.zeroize();
        return Err(error);
    }
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn redacts_every_written_form() {
        let secret = Zeroizing::new(b"abc/defghij".to_vec());
        // `a` as a JSON encoder may write it: backslash, u, 0061.
        let unicode_a = format!("{}u0061", char::from(0x5c));
        let mut bytes = format!(
            r#"{{"t":"abc/defghij","u":"abc\/defghij","v":"{unicode_a}bc/defghij","w":"x"}}"#
        )
        .into_bytes();
        redact(&mut bytes, &[secret]);
        assert_eq!(
            bytes,
            br#"{"t":"[redacted]","u":"[redacted]","v":"[redacted]","w":"x"}"#
        );
    }

    #[test]
    fn escaped_strings_are_decoded() {
        let text = format!(r#"a "b\"c" "plain" "{}u0041""#, char::from(0x5c));
        let found = escaped_strings(text.as_bytes());
        let texts: Vec<&[u8]> = found.iter().map(|(_, _, t)| t.as_slice()).collect();
        assert_eq!(texts, [&b"b\"c"[..], b"A"]);
    }
}
