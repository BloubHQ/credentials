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

mod delimit;

pub use crate::response::REDACTED;
pub(crate) use delimit::Delimited;

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

/// The base64 characters of `secret` in a longer value, where it starts `offset` bytes (0 to
/// 2) into a group of three: only the characters that the secret's bits alone decide, so the
/// first and last ones, which take bits of the bytes around it, are left out.
fn b64_aligned<E: Engine>(engine: &E, secret: &[u8], offset: usize) -> Result<Bytes> {
    let mut grouped = Zeroizing::new(Vec::with_capacity(offset + secret.len()));
    grouped.resize(offset, 0);
    grouped.extend_from_slice(secret);
    let all = b64_with(engine, &grouped)?;
    // Character k carries bits 6k to 6k + 6 of the value; the secret holds bits
    // 8 * offset to 8 * (offset + len).
    let first = (8 * offset).div_ceil(6);
    let last = (8 * (offset + secret.len())) / 6;
    Ok(Zeroizing::new(
        all.get(first..last).unwrap_or_default().to_vec(),
    ))
}

/// The needles of a search, by the view of the bytes each is searched in.
#[derive(Default)]
pub(crate) struct Search {
    /// Searched in the bytes as they are and with JSON escapes decoded.
    exact: Vec<Bytes>,
    /// Secrets searched in the bytes with percent encoding decoded: `%XX` in either case,
    /// `+` read once as a space and once as itself, any other byte as itself.
    decoded: Vec<Bytes>,
    /// Lowercase hex, searched in the bytes with ASCII letters lowercased.
    folded: Vec<Bytes>,
}

fn push_new(list: &mut Vec<Bytes>, needle: Bytes) {
    if !needle.is_empty() && !list.contains(&needle) {
        list.push(needle);
    }
}

/// How many bytes before the end of a window a secret's form could still start: the longest
/// needle read as JSON escapes (six bytes for one), less one.
fn hold_for(longest: usize) -> usize {
    if longest == 0 {
        0
    } else {
        longest
            .saturating_mul(ESCAPE_RATIO)
            .max(LONGEST_ESCAPE)
            .saturating_sub(1)
    }
}

impl Search {
    /// Searches for a secret field: raw from [`MIN_NEEDLE`] bytes; from [`MIN_ENCODED`]
    /// bytes in base64 (both alphabets, at the three alignments, inside a longer value too),
    /// and up to 1 MiB JSON-escaped, percent-encoded and in hex.
    pub(crate) fn add_field(&mut self, value: &[u8]) -> Result<()> {
        if value.len() < MIN_NEEDLE {
            return Ok(());
        }
        push_new(&mut self.exact, Zeroizing::new(value.to_vec()));
        if value.len() < MIN_ENCODED {
            return Ok(());
        }
        for offset in 0..3 {
            push_new(
                &mut self.exact,
                b64_aligned(&STANDARD_NO_PAD, value, offset)?,
            );
            push_new(
                &mut self.exact,
                b64_aligned(&URL_SAFE_NO_PAD, value, offset)?,
            );
        }
        if value.len() <= ENCODED_LIMIT {
            let escaped = json_escape(value);
            if escaped.as_slice() != value {
                push_new(&mut self.exact, escaped);
            }
            push_new(&mut self.decoded, Zeroizing::new(value.to_vec()));
            push_new(&mut self.folded, hex(value));
        }
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.decoded.is_empty() && self.folded.is_empty()
    }

    fn longest(&self) -> usize {
        self.exact
            .iter()
            .chain(&self.decoded)
            .chain(&self.folded)
            .map(|n| n.len())
            .max()
            .unwrap_or(0)
    }

    /// See [`Scrubber::hold`].
    pub(crate) fn hold(&self) -> usize {
        hold_for(self.longest())
    }

    fn found_exact(&self, bytes: &[u8]) -> bool {
        self.exact.iter().any(|n| contains(bytes, n))
    }

    /// Whether `bytes` hold a secret percent-encoded or in hex of any case.
    fn found_encoded(&self, bytes: &[u8]) -> bool {
        if !self.decoded.is_empty() && bytes.iter().any(|b| *b == b'%' || *b == b'+') {
            for plus in [true, false] {
                let view = percent(bytes, plus, None);
                if self.decoded.iter().any(|n| contains(&view, n)) {
                    return true;
                }
            }
        }
        if !self.folded.is_empty() {
            let lower = Zeroizing::new(bytes.to_ascii_lowercase());
            if self.folded.iter().any(|n| contains(&lower, n)) {
                return true;
            }
        }
        false
    }

    /// The search of a stream window: the bytes as they are, with every JSON escape
    /// decoded, percent-decoded and lowercased.
    pub(crate) fn found_stream(&self, bytes: &[u8]) -> bool {
        if self.found_exact(bytes) {
            return true;
        }
        let unescaped = unescape(bytes);
        self.found_exact(&unescaped.bytes) || self.found_encoded(bytes)
    }

    /// The views of `window` with the needles searched in each.
    fn views(&self, window: &[u8]) -> Vec<(View, &[Bytes])> {
        let mut out = Vec::new();
        if !self.exact.is_empty() {
            out.push((
                View::identity(Zeroizing::new(window.to_vec())),
                &self.exact[..],
            ));
            out.push((unescape(window), &self.exact[..]));
        }
        if !self.decoded.is_empty() && window.iter().any(|b| *b == b'%' || *b == b'+') {
            out.push((View::percent(window, true), &self.decoded[..]));
            if window.contains(&b'+') {
                out.push((View::percent(window, false), &self.decoded[..]));
            }
        }
        if !self.folded.is_empty() {
            out.push((
                View::identity(Zeroizing::new(window.to_ascii_lowercase())),
                &self.folded[..],
            ));
        }
        out
    }

    /// Whether an occurrence of a secret in `window`, in any view, covers a byte of
    /// `start..end`.
    pub(crate) fn overlaps(&self, window: &[u8], start: usize, end: usize) -> bool {
        for (view, needles) in self.views(window) {
            for needle in needles {
                let mut at = 0;
                while let Some(i) = view.bytes.get(at..).and_then(|rest| find(rest, needle)) {
                    let q = at + i;
                    let (from, to) = view.raw_span(q, needle.len());
                    if from < end && to > start {
                        return true;
                    }
                    at = q + 1;
                }
            }
        }
        false
    }

    /// Whether bytes after `window` could complete an occurrence of a secret that starts
    /// before `end`: the end of some view, from a byte before `end`, is the start of a needle,
    /// or a token that more bytes could change starts before `end`.
    pub(crate) fn open(&self, window: &[u8], end: usize) -> bool {
        for (view, needles) in self.views(window) {
            let text = view.bytes.get(..view.settled).unwrap_or_default();
            for needle in needles {
                let k = border(needle, text);
                if view.raw_at(view.settled - k) < end {
                    return true;
                }
            }
        }
        false
    }
}

/// The length of the longest proper prefix of `needle` that ends `text`.
fn border(needle: &[u8], text: &[u8]) -> usize {
    let m = needle.len();
    if m < 2 {
        return 0;
    }
    // A proper prefix is shorter than the needle: only the end of the text matters.
    let text = text
        .get(text.len().saturating_sub(m - 1)..)
        .unwrap_or_default();
    let mut fail: Zeroizing<Vec<usize>> = Zeroizing::new(vec![0; m]);
    let mut k = 0;
    for i in 1..m {
        let c = needle.get(i);
        while k > 0 && needle.get(k) != c {
            k = fail.get(k - 1).copied().unwrap_or(0);
        }
        if needle.get(k) == c {
            k += 1;
        }
        if let Some(slot) = fail.get_mut(i) {
            *slot = k;
        }
    }
    let mut k = 0;
    for c in text {
        while k > 0 && needle.get(k) != Some(c) {
            k = fail.get(k - 1).copied().unwrap_or(0);
        }
        if needle.get(k) == Some(c) {
            k += 1;
        }
        if k == m {
            k = fail.get(m - 1).copied().unwrap_or(0);
        }
    }
    k
}

/// The needles of the reflection check.
fn needles(s: &Secrets<'_>) -> Result<Search> {
    let mut out = Search::default();
    for value in s.captured {
        push_new(&mut out.exact, value.clone());
    }
    for value in s.rendered.iter().filter(|r| r.len() >= MIN_NEEDLE) {
        push_new(&mut out.exact, value.clone());
    }
    for (name, value) in s.fields.values() {
        if s.policy.is_secret(name) {
            out.add_field(value)?;
        }
    }
    Ok(out)
}

/// Fails with [`Error::Reflection`] when `bytes` holds a secret in a known form.
pub(crate) fn check(bytes: &[u8], s: &Secrets<'_>) -> Result<()> {
    let search = needles(s)?;
    if search.found_exact(bytes) || search.found_encoded(bytes) {
        return Err(Error::Reflection);
    }
    for (_, _, text) in escaped_strings(bytes) {
        if search.found_exact(&text) {
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

/// Bytes as one decoding reads them, with where each came from in the raw window.
struct View {
    bytes: Bytes,
    /// The raw offset of each token, then the length of the window; empty when each byte is
    /// a token of its own.
    starts: Vec<usize>,
    /// The token each byte of `bytes` comes from; empty when byte `j` is token `j`.
    owner: Vec<usize>,
    /// How many bytes of `bytes` come from tokens that more bytes cannot change.
    settled: usize,
    /// The raw offset of the first token that more bytes could change (the window length
    /// when there is none).
    settled_raw: usize,
    raw_len: usize,
}

impl View {
    /// One token per byte (the bytes as they are, or lowercased).
    fn identity(bytes: Bytes) -> Self {
        let len = bytes.len();
        Self {
            bytes,
            starts: Vec::new(),
            owner: Vec::new(),
            settled: len,
            settled_raw: len,
            raw_len: len,
        }
    }

    /// The window percent-decoded. A `%` or `%X` at the very end could still become an
    /// escape.
    fn percent(window: &[u8], plus: bool) -> Self {
        let mut starts = Vec::with_capacity(window.len() + 1);
        let bytes = percent(window, plus, Some(&mut starts));
        let len = window.len();
        let tail = match window {
            [.., b'%'] => len - 1,
            [.., b'%', x] if x.is_ascii_hexdigit() => len - 2,
            _ => len,
        };
        let settled = starts.partition_point(|s| *s < tail).min(bytes.len());
        starts.push(len);
        Self {
            bytes,
            starts,
            owner: Vec::new(),
            settled,
            settled_raw: tail,
            raw_len: len,
        }
    }

    fn token_start(&self, token: usize) -> usize {
        if self.starts.is_empty() {
            token.min(self.raw_len)
        } else {
            self.starts.get(token).copied().unwrap_or(self.raw_len)
        }
    }

    fn token_of(&self, byte: usize) -> usize {
        if self.owner.is_empty() {
            byte
        } else {
            self.owner.get(byte).copied().unwrap_or(usize::MAX)
        }
    }

    /// The raw bytes `len` bytes of the view from `q` come from.
    fn raw_span(&self, q: usize, len: usize) -> (usize, usize) {
        let first = self.token_of(q);
        let last = self.token_of(q + len.saturating_sub(1));
        (
            self.token_start(first),
            self.token_start(last.saturating_add(1)),
        )
    }

    /// The raw offset byte `q` of the view comes from; at or past the settled bytes, where
    /// the unsettled tokens start.
    fn raw_at(&self, q: usize) -> usize {
        if q >= self.settled {
            self.settled_raw
        } else {
            self.token_start(self.token_of(q))
        }
    }
}

/// `window` percent-decoded: `%XX` (either case) is the byte, `+` a space when `plus`, any
/// other byte itself. Pushes the raw offset of each token to `starts`, when given.
fn percent(window: &[u8], plus: bool, mut starts: Option<&mut Vec<usize>>) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(window.len()));
    let mut i = 0;
    let digit = |b: Option<&u8>| -> Option<u8> {
        let c = char::from(*b?);
        c.to_digit(16).and_then(|d| u8::try_from(d).ok())
    };
    while let Some(&byte) = window.get(i) {
        if let Some(starts) = starts.as_deref_mut() {
            starts.push(i);
        }
        if byte == b'%'
            && let (Some(hi), Some(lo)) = (digit(window.get(i + 1)), digit(window.get(i + 2)))
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        out.push(if plus && byte == b'+' { b' ' } else { byte });
        i += 1;
    }
    out
}

/// The bytes of `window` with every JSON escape decoded (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`,
/// `\r`, `\t`, `\uXXXX` and surrogate pairs), wherever it stands, with the offsets in
/// `window` where each token (a byte or an escape) starts. A backslash that starts no valid
/// escape is a byte of its own. A backslash in the last bytes, where an escape could still be
/// cut, starts the unsettled tokens.
fn unescape(window: &[u8]) -> View {
    let mut out = Zeroizing::new(Vec::with_capacity(window.len()));
    let mut starts = Vec::with_capacity(window.len() + 1);
    let mut owner = Vec::with_capacity(window.len());
    let mut i = 0;
    let hex4 = |at: usize| -> Option<u32> {
        let digits = window.get(at..at + 4)?;
        let text = core::str::from_utf8(digits).ok()?;
        u32::from_str_radix(text, 16).ok()
    };
    let unicode = |at: usize| -> Option<(char, usize)> {
        let high = hex4(at + 2)?;
        let pair = (0xd800..0xdc00).contains(&high)
            && window.get(at + 6) == Some(&b'\\')
            && window.get(at + 7) == Some(&b'u');
        let low = if pair { hex4(at + 8) } else { None };
        let (code, used) = match low {
            Some(low) if (0xdc00..0xe000).contains(&low) => {
                (0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00), 12)
            }
            _ => (high, 6),
        };
        char::from_u32(code).map(|c| (c, used))
    };
    let cut_from = window.len().saturating_sub(LONGEST_ESCAPE - 1);
    let mut tail = window.len();
    let mut settled = None;
    while let Some(&byte) = window.get(i) {
        let token = starts.len();
        starts.push(i);
        if byte == b'\\' && i >= cut_from && settled.is_none() {
            tail = i;
            settled = Some(out.len());
        }
        let before = out.len();
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
        let mut len = 1;
        if let Some(decoded) = simple {
            out.push(decoded);
            len = 2;
        } else if byte == b'\\'
            && next == Some(b'u')
            && let Some((c, used)) = unicode(i)
        {
            let mut utf8 = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            len = used;
        } else {
            out.push(byte);
        }
        owner.resize(owner.len() + (out.len() - before), token);
        i += len;
    }
    starts.push(window.len());
    let settled = settled.unwrap_or(out.len());
    View {
        bytes: out,
        starts,
        owner,
        settled,
        settled_raw: tail,
        raw_len: window.len(),
    }
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
/// they are, with JSON escapes decoded, percent-decoded and (hex) in any case. Captured
/// secrets are not redacted in a stream: one stops it.
pub struct Scrubber {
    search: Search,
    hold: usize,
    tail: Bytes,
}

impl Scrubber {
    pub(crate) fn new(secrets: &Secrets<'_>) -> Result<Self> {
        Ok(Self::with_search(needles(secrets)?))
    }

    fn with_search(search: Search) -> Self {
        let hold = search.hold();
        Self {
            search,
            hold,
            tail: Zeroizing::new(Vec::new()),
        }
    }

    /// A scrubber that searches for these byte strings (as they are and with JSON escapes
    /// decoded).
    pub fn with_needles(needles: Vec<Zeroizing<Vec<u8>>>) -> Self {
        let mut search = Search::default();
        for needle in needles {
            push_new(&mut search.exact, needle);
        }
        Self::with_search(search)
    }

    /// A scrubber that searches for `secret` as for a secret field of a record: raw and in
    /// every encoded form the search knows.
    pub fn for_secret(secret: &[u8]) -> Result<Self> {
        let mut search = Search::default();
        search.add_field(secret)?;
        Ok(Self::with_search(search))
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
        if self.search.is_empty() {
            return Ok(window);
        }
        let decoded = unescape(&window);
        let found = self.search.found_exact(&window)
            || self.search.found_exact(&decoded.bytes)
            || self.search.found_encoded(&window);
        if found {
            window.zeroize();
            return Err(Error::Reflection);
        }
        let target = window.len().saturating_sub(self.hold);
        // The cut is at the start of a token, so the bytes held back start where the decoding
        // of the next window is in step with this one. (A percent escape cut there only ever
        // precedes a form that starts after the cut, which the next window reads whole.)
        let cut = decoded
            .starts
            .iter()
            .rev()
            .find(|s| **s <= target)
            .copied()
            .unwrap_or(0);
        drop(decoded);
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
        if needle.is_empty() || self.search.exact.contains(&needle) {
            return;
        }
        self.hold = self.hold.max(hold_for(needle.len()));
        self.search.exact.push(needle);
    }
}

/// Written forms of `secret` a server may echo, as common encoders write it alone (for tests
/// and the fuzz target): raw; from [`MIN_ENCODED`] bytes base64 in both alphabets, JSON
/// escaping, percent encoding in upper and lower case, and hex in lower, upper and mixed
/// case. [`Scrubber::for_secret`] finds each, inside a longer value too.
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
            // The escapes in lower case, the rest as it is.
            let mut lower = Zeroizing::new(encoded.to_vec());
            let mut after = 0;
            for b in lower.iter_mut() {
                if *b == b'%' {
                    after = 2;
                } else if after > 0 {
                    after -= 1;
                    b.make_ascii_lowercase();
                }
            }
            out.push(encoded);
            push_new(&mut out, lower);
        }
        let lower = hex(secret);
        // Every other letter in upper case.
        let mut letters = 0usize;
        let mixed: Bytes = Zeroizing::new(
            lower
                .iter()
                .map(|c| {
                    if c.is_ascii_alphabetic() {
                        letters += 1;
                        if letters.is_multiple_of(2) {
                            return c.to_ascii_uppercase();
                        }
                    }
                    *c
                })
                .collect(),
        );
        out.push(Zeroizing::new(lower.to_ascii_uppercase()));
        out.push(lower);
        push_new(&mut out, mixed);
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
        assert_eq!(written.len(), 9);
        written.push(Zeroizing::new(u_escaped(secret)));
        // In the middle of an SSE stream: before and after it, other bytes.
        for (f, form) in written.iter().enumerate() {
            let mut stream = b"data: {\"a\":\"".to_vec();
            let start = stream.len();
            stream.extend_from_slice(form);
            stream.extend_from_slice(b"\"}\n\n");
            for split in 1..form.len() {
                let mut s = Scrubber::for_secret(secret).unwrap();
                let first = s.push(&stream[..start + split]).unwrap();
                // Nothing of the secret's form left with the first part.
                assert!(first.len() <= start, "released into the secret");
                assert_eq!(
                    s.push(&stream[start + split..]),
                    Err(Error::Reflection),
                    "form {f} split at {split} not caught"
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

    /// A secret field of 31 bytes (not a multiple of three) with reserved characters and
    /// spaces.
    const FIELD: &[u8] = b"p@ss/w0rd+key=1&x horse staple!";

    fn field_policy() -> (Policy, Fields) {
        let policy = Policy {
            item: None,
            fields: vec![crate::policy::FieldSpec::secret("key")],
            callers: vec![],
            operations: vec![],
        };
        let mut fields = Fields::new();
        fields.insert("key", FIELD.to_vec()).unwrap();
        (policy, fields)
    }

    fn found(bytes: &[u8]) -> bool {
        let (policy, fields) = field_policy();
        let secrets = Secrets {
            policy: &policy,
            fields: &fields,
            captured: &[],
            rendered: &[],
        };
        check(bytes, &secrets) == Err(Error::Reflection)
    }

    /// The written forms a server may echo the field in that are not the field alone, in
    /// one encoder's exact output: base64 inside a longer value at every alignment, percent
    /// encoding in lowercase, with `+` for spaces, or leaving reserved characters raw, and
    /// hex in mixed case.
    fn embedded_forms() -> Vec<(String, Vec<u8>)> {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE};
        let mut out = Vec::new();
        for (alphabet, engine) in [("standard", &STANDARD), ("url-safe", &URL_SAFE)] {
            for offset in 0..3usize {
                // Bytes before the field (so it starts `offset` bytes into a group of three)
                // and after it.
                let mut value = b"\xfb\xff"[..offset].to_vec();
                value.extend_from_slice(FIELD);
                value.extend_from_slice(b"\xff\xfe\xfd");
                let mut written = b"blob=".to_vec();
                written.extend_from_slice(engine.encode(&value).as_bytes());
                out.push((format!("{alphabet} base64 at offset {offset}"), written));
            }
        }
        let lower: Vec<u8> = pct(FIELD).to_ascii_lowercase();
        out.push(("lowercase percent".into(), lower));
        let mut plus = Vec::new();
        for &b in FIELD {
            match b {
                b' ' => plus.push(b'+'),
                b if b.is_ascii_alphanumeric() => plus.push(b),
                b => plus.extend_from_slice(format!("%{b:02X}").as_bytes()),
            }
        }
        out.push(("percent with + for spaces".into(), plus));
        let mut partial = Vec::new();
        for &b in FIELD {
            match b {
                b'@' | b' ' | b'&' => partial.extend_from_slice(format!("%{b:02x}").as_bytes()),
                b => partial.push(b),
            }
        }
        out.push(("percent leaving reserved characters raw".into(), partial));
        let mixed: Vec<u8> = hex(FIELD)
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i % 3 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    *c
                }
            })
            .collect();
        out.push(("mixed-case hex".into(), mixed));
        out
    }

    #[test]
    fn a_field_inside_a_longer_encoded_value_is_found() {
        let mut missed = Vec::new();
        for (name, written) in embedded_forms() {
            let mut response = b"HTTP/1.1 200 OK\r\n\r\n{\"v\":\"".to_vec();
            response.extend_from_slice(&written);
            response.extend_from_slice(b"\"}");
            if !found(&response) {
                missed.push(name);
            }
        }
        assert!(missed.is_empty(), "not found: {missed:?}");
    }

    #[test]
    fn the_stream_search_finds_the_new_forms_split_at_every_offset() {
        let (policy, fields) = field_policy();
        let secrets = Secrets {
            policy: &policy,
            fields: &fields,
            captured: &[],
            rendered: &[],
        };
        let mut missed = Vec::new();
        for (name, written) in embedded_forms() {
            let mut stream = b"data: ".to_vec();
            let start = stream.len();
            stream.extend_from_slice(&written);
            stream.extend_from_slice(b"\n\n");
            for split in 1..written.len() {
                let mut s = Scrubber::new(&secrets).unwrap();
                let first = s.push(&stream[..start + split]);
                let caught = match first {
                    Err(_) => true,
                    Ok(released) => {
                        assert!(released.len() <= start, "{name}: released into the form");
                        s.push(&stream[start + split..]).is_err()
                    }
                };
                if !caught {
                    missed.push(format!("{name} split at {split}"));
                    break;
                }
            }
        }
        assert!(missed.is_empty(), "not found: {missed:?}");
    }

    #[test]
    fn encoded_text_without_the_field_passes() {
        use base64::engine::general_purpose::STANDARD;
        let mut response = b"q=a%2Fb+c%40d&h=DEADbeef00112233aabbCCdd&b=".to_vec();
        let other: Vec<u8> = (0u8..=255).collect();
        response.extend_from_slice(STANDARD.encode(&other).as_bytes());
        response.extend_from_slice(b"&p=%25%2B%2b+%zz%4");
        assert!(!found(&response));
        // The field's first bytes alone, in each form, are not the field.
        let short = &FIELD[..MIN_ENCODED - 1];
        let mut partial = pct(short).to_ascii_lowercase();
        partial.extend_from_slice(&hex(short));
        assert!(!found(&partial));
    }

    #[test]
    fn escaped_strings_are_decoded() {
        let text = format!(r#"a "b\"c" "plain" "{}u0041""#, char::from(0x5c));
        let found = escaped_strings(text.as_bytes());
        let texts: Vec<&[u8]> = found.iter().map(|(_, _, t)| t.as_slice()).collect();
        assert_eq!(texts, [&b"b\"c"[..], b"A"]);
    }
}
