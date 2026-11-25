//! Reading responses: the parts a capture names, and the response handed back.
//!
//! A response is parsed into status, headers and a decoded body before anything is captured or
//! handed back, so a secret cannot hide in the framing: interim `1xx` responses are skipped, a
//! chunked body is joined, and a body the engine cannot read as plain bytes (`Content-Encoding`
//! other than `identity`, a partial `Content-Range`, a transfer coding other than `chunked`) is
//! refused. The caller gets the parsed response ([`Response`]), never the bytes of the wire.

use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use crate::policy::{BodyProjection, Projection, Source};
use crate::{Error, Result};

/// Longest response the engine reads, in bytes.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// Longest status line and headers of one response, in bytes.
pub const MAX_HEAD: usize = 64 * 1024;
/// Most headers of one response.
pub const MAX_RESPONSE_HEADERS: usize = 128;
/// Longest captured value, in bytes.
pub const MAX_CAPTURE: usize = 64 * 1024;
/// What replaces a captured secret in a response handed back.
pub const REDACTED: &[u8] = b"[redacted]";

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// The response of an operation, as the caller gets it: after redaction and the reflection
/// check. The body is decoded (no chunked framing); `Content-Length` and `Transfer-Encoding`
/// are not among the headers.
///
/// In JSON, header values and the body are base64url.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub(crate) status: u16,
    #[serde(with = "crate::encoding::b64_pairs")]
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    #[serde(with = "crate::encoding::b64_vec")]
    pub(crate) body: Vec<u8>,
    pub(crate) log_seqs: Vec<u64>,
}

impl Response {
    /// The status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The value of the first header with this name (case does not matter).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// All headers, in order.
    pub fn headers(&self) -> &[(String, Vec<u8>)] {
        &self.headers
    }

    /// The body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The sequence numbers of the log entries of the requests of the operation.
    pub fn log_seqs(&self) -> &[u64] {
        &self.log_seqs
    }

    /// The response as HTTP/1.1 bytes with a `Content-Length`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = 32
            + self
                .headers
                .iter()
                .map(|(n, v)| n.len() + v.len() + 4)
                .sum::<usize>()
            + self.body.len();
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(format!("HTTP/1.1 {}\r\n", self.status).as_bytes());
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    fn wipe(&mut self) {
        self.body.zeroize();
        for (_, value) in &mut self.headers {
            value.zeroize();
        }
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// An HTTP/1.1 response, parsed.
pub(crate) struct Http {
    pub status: u16,
    pub headers: Vec<(String, Zeroizing<Vec<u8>>)>,
    pub body: Zeroizing<Vec<u8>>,
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    memchr::memmem::find(haystack, needle)
}

fn dechunk(mut rest: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(rest.len()));
    loop {
        let line_end = find(rest, b"\r\n").ok_or(invalid("chunk size line"))?;
        let (line, tail) = rest.split_at(line_end);
        let size_text = line.split(|b| *b == b';').next().unwrap_or_default();
        let size_text = core::str::from_utf8(size_text).map_err(|_| invalid("chunk size"))?;
        let size =
            usize::from_str_radix(size_text.trim(), 16).map_err(|_| invalid("chunk size"))?;
        let tail = tail.get(2..).ok_or(invalid("chunk size line"))?;
        if size == 0 {
            return Ok(out);
        }
        let chunk = tail
            .get(..size)
            .ok_or(invalid("chunk shorter than its size"))?;
        if tail.get(size..size + 2) != Some(b"\r\n") {
            return Err(invalid("chunk not followed by CRLF"));
        }
        out.extend_from_slice(chunk);
        rest = tail.get(size + 2..).ok_or(invalid("chunk framing"))?;
    }
}

fn is_header_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

impl Http {
    /// Parses a response.
    pub fn parse(mut bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RESPONSE {
            return Err(Error::transport(
                crate::error::TransportKind::TooLarge,
                true,
            ));
        }
        loop {
            let window = bytes.get(..bytes.len().min(MAX_HEAD + 4)).unwrap_or(bytes);
            let split = find(window, b"\r\n\r\n").ok_or(invalid("head missing or too long"))?;
            let (head, rest) = bytes.split_at(split);
            let rest = rest.get(4..).unwrap_or_default();
            let mut lines = head
                .split(|b| *b == b'\n')
                .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
            let status_line = lines.next().ok_or(invalid("status line"))?;
            let status = parse_status(status_line)?;
            if (100..200).contains(&status) {
                if status == 101 {
                    return Err(invalid("protocol switch"));
                }
                bytes = rest;
                continue;
            }
            let mut headers = Vec::new();
            for line in lines {
                if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                    return Err(invalid("folded header"));
                }
                let colon = line
                    .iter()
                    .position(|b| *b == b':')
                    .ok_or(invalid("header line"))?;
                let (name, value) = line.split_at(colon);
                if !is_header_name(name) {
                    return Err(invalid("header name"));
                }
                let name = String::from_utf8(name.to_vec()).map_err(|_| invalid("header name"))?;
                let value = value.get(1..).unwrap_or_default().trim_ascii();
                headers.push((name, Zeroizing::new(value.to_vec())));
                if headers.len() > MAX_RESPONSE_HEADERS {
                    return Err(invalid("too many headers"));
                }
            }
            return Self::framed(status, headers, rest);
        }
    }

    fn framed(
        status: u16,
        mut headers: Vec<(String, Zeroizing<Vec<u8>>)>,
        raw_body: &[u8],
    ) -> Result<Self> {
        let named = |headers: &[(String, Zeroizing<Vec<u8>>)], name: &str| {
            headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.to_vec())
                .collect::<Vec<_>>()
        };
        let encodings = named(&headers, "content-encoding");
        if encodings
            .iter()
            .any(|v| !v.trim_ascii().eq_ignore_ascii_case(b"identity"))
        {
            return Err(invalid("encoded body"));
        }
        if status == 206 || !named(&headers, "content-range").is_empty() {
            return Err(invalid("partial body"));
        }
        let codings = named(&headers, "transfer-encoding");
        let lengths = named(&headers, "content-length");
        let body = match codings.as_slice() {
            [] => match lengths.as_slice() {
                [] => Zeroizing::new(raw_body.to_vec()),
                [one] => {
                    let length = core::str::from_utf8(one)
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .ok_or(invalid("content length"))?;
                    Zeroizing::new(
                        raw_body
                            .get(..length)
                            .ok_or(invalid("body shorter than its length"))?
                            .to_vec(),
                    )
                }
                _ => return Err(invalid("several content lengths")),
            },
            [one] if one.trim_ascii().eq_ignore_ascii_case(b"chunked") => dechunk(raw_body)?,
            _ => return Err(invalid("transfer coding other than chunked")),
        };
        headers.retain(|(n, _)| {
            !n.eq_ignore_ascii_case("transfer-encoding")
                && !n.eq_ignore_ascii_case("content-length")
        });
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    fn headers_named<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s [u8]> + 's {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// The value a source names, if the response has it.
    pub fn capture(&self, source: &Source) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let value = match source {
            Source::Status => Some(Zeroizing::new(self.status.to_string().into_bytes())),
            Source::Header { name } => self
                .headers_named(name)
                .next()
                .map(|v| Zeroizing::new(v.to_vec())),
            Source::HeaderParam {
                name,
                param,
                scheme,
            } => self
                .headers_named(name)
                .find_map(|v| header_param(v, param, scheme.as_deref())),
            Source::Cookie { name } => self
                .headers_named("set-cookie")
                .find_map(|v| set_cookie(v, name)),
            Source::Json { pointer } => json_pointer(&self.body, pointer)?,
            Source::Between { start, end } => between(&self.body, start, end),
            Source::Html {
                selector,
                attribute,
            } => crate::extract::html(&self.body, selector, attribute.as_deref())?,
            Source::Regex { pattern, group } => crate::extract::regex(&self.body, pattern, *group)?,
            Source::All => Some(self.body.clone()),
        };
        limit(value)
    }

    /// The parts of the response `projection` lets back to the caller: the status, the
    /// headers it names and the body as it says (nothing without a projection or a body
    /// rule).
    pub fn project(
        mut self,
        projection: Option<&Projection>,
        log_seqs: Vec<u64>,
    ) -> Result<Response> {
        let headers = projection.map_or(&[][..], |p| p.headers.as_slice());
        self.headers
            .retain(|(n, _)| headers.iter().any(|h| h.eq_ignore_ascii_case(n)));
        let body = match projection.and_then(|p| p.body.as_ref()) {
            None => Zeroizing::new(Vec::new()),
            Some(BodyProjection::All) => core::mem::take(&mut self.body),
            Some(BodyProjection::Json(pointers)) => project_json(&self.body, pointers)?,
        };
        self.body = body;
        Ok(self.into_response(log_seqs))
    }

    /// The parsed response, for the caller.
    pub fn into_response(mut self, log_seqs: Vec<u64>) -> Response {
        Response {
            status: self.status,
            headers: core::mem::take(&mut self.headers)
                .into_iter()
                .map(|(n, v)| (n, v.to_vec()))
                .collect(),
            body: self.body.to_vec(),
            log_seqs,
        }
    }
}

fn parse_status(line: &[u8]) -> Result<u16> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with(b"HTTP/1.") || code.len() != 3 {
        return Err(invalid("status line"));
    }
    core::str::from_utf8(code)
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|c| (100..600).contains(c))
        .ok_or(invalid("status line"))
}

fn limit(value: Option<Zeroizing<Vec<u8>>>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match value {
        Some(v) if v.len() > MAX_CAPTURE => Err(invalid("captured value too large")),
        other => Ok(other),
    }
}

/// The value a stream source (`between`, `regex` or `all`) names in bytes read from a stream.
pub(crate) fn capture_bytes(bytes: &[u8], source: &Source) -> Result<Option<Zeroizing<Vec<u8>>>> {
    limit(match source {
        Source::Between { start, end } => between(bytes, start, end),
        Source::Regex { pattern, group } => crate::extract::regex(bytes, pattern, *group)?,
        Source::All => Some(Zeroizing::new(bytes.to_vec())),
        _ => return Err(invalid("source not available on a stream")),
    })
}

fn between(bytes: &[u8], start: &str, end: &str) -> Option<Zeroizing<Vec<u8>>> {
    let from = find(bytes, start.as_bytes())? + start.len();
    let rest = bytes.get(from..)?;
    let to = find(rest, end.as_bytes())?;
    Some(Zeroizing::new(rest.get(..to)?.to_vec()))
}

/// Splits a header value on commas outside double quotes.
fn split_params(value: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, b) in value.iter().enumerate() {
        match b {
            _ if escaped => escaped = false,
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.extend(value.get(start..i));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.extend(value.get(start..));
    out
}

fn unquote(raw: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    Some(
        match raw.strip_prefix(b"\"").and_then(|r| r.strip_suffix(b"\"")) {
            Some(inner) => {
                let mut out = Zeroizing::new(Vec::with_capacity(inner.len()));
                let mut iter = inner.iter();
                while let Some(&b) = iter.next() {
                    out.push(if b == b'\\' { *iter.next()? } else { b });
                }
                out
            }
            None => Zeroizing::new(raw.to_vec()),
        },
    )
}

/// A parameter of the challenges in a header value. A part that starts with a scheme
/// (`Digest realm="x"`) opens a challenge; with `scheme`, only its challenges are read.
fn header_param(value: &[u8], param: &str, scheme: Option<&str>) -> Option<Zeroizing<Vec<u8>>> {
    let mut current: Option<&[u8]> = None;
    for part in split_params(value) {
        let part = part.trim_ascii();
        let Some(eq) = part.iter().position(|b| *b == b'=') else {
            // A scheme without parameters (`Negotiate`) opens a challenge too.
            if !part.is_empty() && !part.contains(&b' ') {
                current = Some(part);
            }
            continue;
        };
        let (key, rest) = part.split_at(eq);
        let key = match key.iter().position(|b| *b == b' ') {
            Some(space) => {
                current = key.get(..space);
                key.get(space + 1..).unwrap_or_default().trim_ascii()
            }
            None => key.trim_ascii(),
        };
        let scheme_ok =
            scheme.is_none_or(|s| current.is_some_and(|c| c.eq_ignore_ascii_case(s.as_bytes())));
        if scheme_ok && key.eq_ignore_ascii_case(param.as_bytes()) {
            return unquote(rest.get(1..)?.trim_ascii());
        }
    }
    None
}

fn set_cookie(value: &[u8], name: &str) -> Option<Zeroizing<Vec<u8>>> {
    let pair = value.split(|b| *b == b';').next()?;
    let eq = pair.iter().position(|b| *b == b'=')?;
    let (key, rest) = pair.split_at(eq);
    if key.trim_ascii() != name.as_bytes() {
        return None;
    }
    Some(Zeroizing::new(rest.get(1..)?.trim_ascii().to_vec()))
}

/// One step of a JSON pointer: the member or element `token` of an object or array, borrowed
/// from the document. The other members and elements are skipped, not collected, so a large
/// document costs no more memory than its bytes.
struct Pick<'t>(&'t str);

impl<'de> serde::de::Visitor<'de> for Pick<'_> {
    type Value = Option<&'de RawValue>;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a JSON object or array")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> core::result::Result<Self::Value, A::Error> {
        let mut found = None;
        while let Some(mut key) = map.next_key::<String>()? {
            if found.is_none() && key == self.0 {
                found = Some(map.next_value::<&'de RawValue>()?);
            } else {
                map.next_value::<serde::de::IgnoredAny>()?;
            }
            key.zeroize();
        }
        Ok(found)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> core::result::Result<Self::Value, A::Error> {
        let index = self
            .0
            .parse::<usize>()
            .ok()
            .filter(|_| self.0 == "0" || !self.0.starts_with('0'));
        let mut found = None;
        let mut i = 0usize;
        loop {
            if Some(i) == index {
                match seq.next_element::<&'de RawValue>()? {
                    Some(value) => found = Some(value),
                    None => break,
                }
            } else if seq.next_element::<serde::de::IgnoredAny>()?.is_none() {
                break;
            }
            i = i.saturating_add(1);
        }
        Ok(found)
    }
}

/// The JSON text of the value at `tokens`, or of every value a `*` token reaches (as an
/// array), or `None` when nothing is there.
fn resolve(raw: &RawValue, tokens: &[String]) -> Result<Option<Zeroizing<String>>> {
    use serde::Deserializer as _;
    let bad = || invalid("body is not JSON");
    let Some((token, rest)) = tokens.split_first() else {
        return Ok(Some(Zeroizing::new(raw.get().trim().to_string())));
    };
    let text = raw.get().trim_start();
    if token == "*" {
        if !text.starts_with('[') {
            return Ok(None);
        }
        let items: Vec<&RawValue> = serde_json::from_str(text).map_err(|_| bad())?;
        let mut out = Zeroizing::new(String::from("["));
        let mut first = true;
        for item in items {
            if let Some(value) = resolve(item, rest)? {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&value);
                if out.len() > MAX_RESPONSE {
                    return Err(invalid("projected body too large"));
                }
            }
        }
        out.push(']');
        return Ok(Some(out));
    }
    if !text.starts_with('{') && !text.starts_with('[') {
        return Ok(None);
    }
    let mut de = serde_json::Deserializer::from_str(text);
    match de.deserialize_any(Pick(token)).map_err(|_| bad())? {
        Some(next) => resolve(next, rest),
        None => Ok(None),
    }
}

/// A JSON object from each pointer to the value it reaches; pointers that reach nothing are
/// left out.
fn project_json(body: &[u8], pointers: &[String]) -> Result<Zeroizing<Vec<u8>>> {
    let root: &RawValue = serde_json::from_slice(body).map_err(|_| invalid("body is not JSON"))?;
    let mut out = Zeroizing::new(String::from("{"));
    let mut first = true;
    for pointer in pointers {
        let tokens: Vec<String> = pointer
            .split('/')
            .skip(1)
            .map(|t| t.replace("~1", "/").replace("~0", "~"))
            .collect();
        if let Some(value) = resolve(root, &tokens)? {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&serde_json::to_string(pointer).map_err(|_| Error::Encoding)?);
            out.push(':');
            out.push_str(&value);
            if out.len() > MAX_RESPONSE {
                return Err(invalid("projected body too large"));
            }
        }
    }
    out.push('}');
    Ok(Zeroizing::new(out.as_bytes().to_vec()))
}

/// Follows a JSON pointer one level at a time over borrowed raw values. Strings come back
/// unescaped, other scalars as written.
fn json_pointer(body: &[u8], pointer: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use serde::Deserializer as _;
    let bad = || invalid("body is not JSON");
    let mut current: &RawValue = serde_json::from_slice(body).map_err(|_| bad())?;
    if !pointer.is_empty() {
        for token in pointer.split('/').skip(1) {
            let token = token.replace("~1", "/").replace("~0", "~");
            let text = current.get().trim_start();
            if !text.starts_with('{') && !text.starts_with('[') {
                return Ok(None);
            }
            let mut de = serde_json::Deserializer::from_str(text);
            match de.deserialize_any(Pick(&token)).map_err(|_| bad())? {
                Some(next) => current = next,
                None => return Ok(None),
            }
        }
    }
    let text = current.get().trim();
    Ok(match text.as_bytes().first() {
        Some(b'"') => {
            let mut s: String = serde_json::from_str(text).map_err(|_| bad())?;
            let out = Zeroizing::new(s.as_bytes().to_vec());
            s.zeroize();
            Some(out)
        }
        Some(b'{' | b'[') | None => None,
        Some(_) if text == "null" => None,
        Some(_) => Some(Zeroizing::new(text.as_bytes().to_vec())),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n\
HTTP/1.1 401 Unauthorized\r\n\
WWW-Authenticate: Bearer realm=\"api\", error=\"invalid_token\"\r\n\
WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b\", opaque=\"5ccc\"\r\n\
Set-Cookie: theme=dark; Path=/\r\n\
Set-Cookie: sid=abc123def456; HttpOnly\r\n\
Transfer-Encoding: chunked\r\n\r\n\
7\r\n{\"a\":{\"\r\ne\r\nb\":\"x/y\",\"n\":1\r\nb\r\n.50,\"l\":[7]\r\n2\r\n}}\r\n0\r\n\r\n";

    fn get(source: Source) -> Option<Vec<u8>> {
        Http::parse(RESPONSE)
            .unwrap()
            .capture(&source)
            .unwrap()
            .map(|v| v.to_vec())
    }

    #[test]
    fn captures_each_source() {
        assert_eq!(get(Source::Status).unwrap(), b"401");
        let param = |p: &str, s: Option<&str>| Source::HeaderParam {
            name: "www-authenticate".into(),
            param: p.into(),
            scheme: s.map(Into::into),
        };
        assert_eq!(get(param("realm", None)).unwrap(), b"api");
        assert_eq!(
            get(param("realm", Some("digest"))).unwrap(),
            b"testrealm@host.com"
        );
        assert_eq!(get(param("qop", Some("Digest"))).unwrap(), b"auth,auth-int");
        assert_eq!(get(param("opaque", Some("Digest"))).unwrap(), b"5ccc");
        assert_eq!(get(param("error", Some("Digest"))), None);
        assert_eq!(
            get(Source::Cookie { name: "sid".into() }).unwrap(),
            b"abc123def456"
        );
        let json = |p: &str| Source::Json { pointer: p.into() };
        assert_eq!(get(json("/a/b")).unwrap(), b"x/y");
        assert_eq!(get(json("/a/n")).unwrap(), b"1.50");
        assert_eq!(get(json("/a/l/0")).unwrap(), b"7");
        assert_eq!(get(json("/a/l/01")), None);
        assert_eq!(get(json("/a")), None);
        assert_eq!(
            get(Source::Cookie {
                name: "none".into()
            }),
            None
        );
    }

    #[test]
    fn refuses_hidden_bodies() {
        for (bytes, rule) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nxx"[..],
                "encoded body",
            ),
            (
                b"HTTP/1.1 206 Partial\r\nContent-Range: bytes 0-1/9\r\n\r\nxx",
                "partial body",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
                "transfer coding other than chunked",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx",
                "several content lengths",
            ),
            (b"HTTP/1.1 101 Switching\r\n\r\n", "protocol switch"),
            (b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n", "folded header"),
        ] {
            assert_eq!(
                Http::parse(bytes).map(|_| ()),
                Err(Error::ResponseInvalid { rule }),
                "{rule}"
            );
        }
    }

    #[test]
    fn hands_back_the_decoded_response() {
        let response = Http::parse(RESPONSE).unwrap().into_response(vec![3]);
        assert_eq!(response.status(), 401);
        assert_eq!(response.body(), br#"{"a":{"b":"x/y","n":1.50,"l":[7]}}"#);
        assert!(response.header("transfer-encoding").is_none());
        assert!(
            response.to_bytes().ends_with(
                b"Content-Length: 34\r\n\r\n{\"a\":{\"b\":\"x/y\",\"n\":1.50,\"l\":[7]}}"
            )
        );
    }
}
