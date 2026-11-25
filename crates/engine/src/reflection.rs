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

/// The longest raw run one decoded byte of a JSON escape comes from (`A` is six bytes
/// for one).
const ESCAPE_RATIO: usize = 6;
/// The longest JSON escape: a surrogate pair, `😀`.
const LONGEST_ESCAPE: usize = 12;

/// The bytes of `window` with every JSON escape decoded (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`,
/// `\r`, `\t`, `\uXXXX` and surrogate pairs), wherever it stands, and the offsets in
/// `window` where each token (a byte or an escape) starts. A backslash that starts no valid
/// escape is a byte of its own.
fn unescape(window: &[u8]) -> (Bytes, Vec<usize>) {
    let mut out = Zeroizing::new(Vec::with_capacity(window.len()));
    let mut starts = Vec::with_capacity(window.len() + 1);
    let mut i = 0;
    let hex4 = |at: usize| -> Option<u32> {
        let digits = window.get(at..at + 4)?;
        let text = core::str::from_utf8(digits).ok()?;
        u32::from_str_radix(text, 16).ok()
    };
    while let Some(&byte) = window.get(i) {
        starts.push(i);
        let next = window.get(i + 1).copied();
        let simple = match (byte, next) {
            (b'\\', Some(b'"')) => Some(b'"'),
            (b'\\', Some(b'\\')) => Some(b'\\'),
            (b'\\', Some(b'/')) => Some(b'/'),
            (b'\\', Some(b'b')) => Some(0x08),
            (b'\\', Some(b'f')) => Some(0x0c),
            (b'\\', Some(b'n')) => Some(b'\n'),
            (b'\\', Some(b'r')) => Some(b'\r'),
            (b'\\', Some(b't')) => Some(b'\t'),
            _ => None,
        };
        if let Some(decoded) = simple {
            out.push(decoded);
            i += 2;
            continue;
        }
        if byte == b'\\'
            && next == Some(b'u')
            && let Some(high) = hex4(i + 2)
        {
            let pair = (0xd800..0xdc00).contains(&high)
                && window.get(i + 6) == Some(&b'\\')
                && window.get(i + 7) == Some(&b'u');
            let low = if pair { hex4(i + 8) } else { None };
            let (code, len) = match low {
                Some(low) if (0xdc00..0xe000).contains(&low) => {
                    (0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00), 12)
                }
                _ => (high, 6),
            };
            if let Some(c) = char::from_u32(code) {
                let mut utf8 = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
                i += len;
                continue;
            }
        }
        out.push(byte);
        i += 1;
    }
    starts.push(window.len());
    (out, starts)
}

/// The reflection search over a response that arrives in parts (a streamed body, the
/// messages of a WebSocket): each part is searched together with the last `n - 1` bytes
/// before it, where `n` is the longest form of any secret the search knows (its encodings,
/// and its JSON-escaped form at six bytes per byte), and those bytes are held back until the
/// next part or the end. A secret split across parts is therefore found before any byte of
/// it is released.
///
/// The search finds every needle of the whole-response check (secret fields raw and in
/// base64, percent, JSON and hex forms; rendered values; captured secrets) in the bytes as
/// they are and with JSON escapes decoded. Captured secrets are not redacted in a stream:
/// one stops it.
pub struct Scrubber {
    needles: Vec<Bytes>,
    hold: usize,
    tail: Bytes,
}

impl Scrubber {
    pub(crate) fn new(secrets: &Secrets<'_>) -> Result<Self> {
        Ok(Self::with_needles(needles(secrets)?))
    }

    /// A scrubber that searches for these byte strings.
    pub fn with_needles(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        let needles: Vec<Bytes> = needles.into_iter().filter(|n| !n.is_empty()).collect();
        let longest = needles.iter().map(|n| n.len()).max().unwrap_or(0);
        let hold = if longest == 0 {
            0
        } else {
            longest
                .saturating_mul(ESCAPE_RATIO)
                .max(LONGEST_ESCAPE)
                .saturating_sub(1)
        };
        Self {
            needles,
            hold,
            tail: Zeroizing::new(Vec::new()),
        }
    }

    /// How many bytes are held back at most (`n - 1`), less one escape.
    pub fn hold(&self) -> usize {
        self.hold
    }

    /// Searches `chunk` with the bytes held back before it, and releases what can no longer
    /// be part of a secret. Fails with [`Error::Reflection`] when a secret is found; nothing
    /// of the window is released then.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut window = Zeroizing::new(Vec::with_capacity(self.tail.len() + chunk.len()));
        window.extend_from_slice(&self.tail);
        window.extend_from_slice(chunk);
        self.tail.zeroize();
        if self.needles.is_empty() {
            return Ok(window);
        }
        let (decoded, starts) = unescape(&window);
        let found = self
            .needles
            .iter()
            .any(|n| contains(&window, n) || contains(&decoded, n));
        drop(decoded);
        if found {
            window.zeroize();
            return Err(Error::Reflection);
        }
        let target = window.len().saturating_sub(self.hold);
        // The cut is at the start of a token, so the bytes held back start where the decoding
        // of the next window is in step with this one.
        let cut = starts
            .iter()
            .rev()
            .find(|s| **s <= target)
            .copied()
            .unwrap_or(0);
        let released = Zeroizing::new(window.get(..cut).unwrap_or_default().to_vec());
        self.tail = Zeroizing::new(window.get(cut..).unwrap_or_default().to_vec());
        Ok(released)
    }

    /// The bytes still held back, at the end of the response (they were searched).
    pub fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        core::mem::take(&mut self.tail)
    }

    /// Searches one whole message (a WebSocket message goes back whole or not at all) with
    /// the end of the messages before it, and keeps its end for the next one. A secret split
    /// across two messages is found when the second arrives; the first was released, but it
    /// held only part of the secret.
    pub fn message(&mut self, data: &[u8]) -> Result<()> {
        self.push(data).map(drop)
    }

    /// Searches for one more value from now on (a frame template rendered a secret).
    pub(crate) fn add(&mut self, needle: Zeroizing<Vec<u8>>) {
        if needle.is_empty() || self.needles.contains(&needle) {
            return;
        }
        let hold = needle
            .len()
            .saturating_mul(ESCAPE_RATIO)
            .max(LONGEST_ESCAPE)
            .saturating_sub(1);
        self.hold = self.hold.max(hold);
        self.needles.push(needle);
    }
}

/// Every form of `secret` the stream search knows, as [`Scrubber`] builds them for a secret
/// field (for tests and the fuzz target).
pub fn forms(secret: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut out = vec![Zeroizing::new(secret.to_vec())];
    if secret.len() >= MIN_ENCODED {
        out.push(b64_with(&STANDARD_NO_PAD, secret)?);
        out.push(b64_with(&URL_SAFE_NO_PAD, secret)?);
        let escaped = json_escape(secret);
        if escaped.as_slice() != secret {
            out.push(escaped);
        }
        let encoded = pct(secret);
        if encoded.as_slice() != secret {
            out.push(encoded);
        }
        let lower = hex(secret);
        out.push(Zeroizing::new(lower.to_ascii_uppercase()));
        out.push(lower);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// `secret` with every byte written as a `\u00XX` JSON escape.
    fn u_escaped(secret: &[u8]) -> Vec<u8> {
        secret
            .iter()
            .flat_map(|b| format!("\\u{:04x}", b).into_bytes())
            .collect()
    }

    #[test]
    fn a_secret_split_at_every_offset_in_every_form_is_caught() {
        let secret = b"s3cr3t-T0KEN/+=\"value";
        let mut written = forms(secret).unwrap();
        assert_eq!(written.len(), 7);
        written.push(Zeroizing::new(u_escaped(secret)));
        // In the middle of an SSE stream: before and after it, other bytes.
        for form in &written {
            let mut stream = b"data: {\"a\":\"".to_vec();
            let start = stream.len();
            stream.extend_from_slice(form);
            stream.extend_from_slice(b"\"}\n\n");
            for split in 1..form.len() {
                let mut s = Scrubber::with_needles(forms(secret).unwrap());
                let first = s.push(&stream[..start + split]).unwrap();
                // Nothing of the secret's form left with the first part.
                assert!(first.len() <= start, "released into the secret");
                assert_eq!(
                    s.push(&stream[start + split..]),
                    Err(Error::Reflection),
                    "split not caught"
                );
            }
        }
    }

    #[test]
    fn clean_streams_pass_whole_and_in_order() {
        let secret = b"0123456789abcdef";
        let mut s = Scrubber::with_needles(forms(secret).unwrap());
        let text: Vec<u8> = (0..5000u32)
            .flat_map(|i| format!("data: {i} \\u0041 \\\\ x\n").into_bytes())
            .collect();
        let mut out = Vec::new();
        for chunk in text.chunks(37) {
            out.extend_from_slice(&s.push(chunk).unwrap());
        }
        out.extend_from_slice(&s.finish());
        assert_eq!(out, text);
        assert_eq!(s.hold(), 6 * 32 - 1);
    }

    #[test]
    fn escapes_cut_at_the_hold_stay_in_step() {
        // An escaped backslash just before an escape of the secret's first byte: a decoding
        // that started between the two backslashes would miss it.
        let secret = b"ZZZZZZZZ";
        let mut stream = vec![b'x'; 200];
        stream.extend_from_slice(b"\\\\");
        stream.extend_from_slice(&u_escaped(secret));
        for split in 1..stream.len() {
            let mut s = Scrubber::with_needles(forms(secret).unwrap());
            let found = s
                .push(&stream[..split])
                .and_then(|_| s.push(&stream[split..]));
            assert_eq!(found, Err(Error::Reflection));
        }
    }

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
