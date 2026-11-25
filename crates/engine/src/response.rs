//! Reading responses: the parts a capture names, and the redaction of captured secrets.

use zeroize::Zeroizing;

use crate::policy::Source;
use crate::template::json_escape;
use crate::{Error, Result};

/// Longest response the engine reads, in bytes.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// What replaces a captured secret in a response handed back.
pub const REDACTED: &[u8] = b"[redacted]";

/// An HTTP/1.1 response, split.
pub(crate) struct Http<'a> {
    pub status: u16,
    pub headers: Vec<(&'a str, &'a [u8])>,
    pub body: Zeroizing<Vec<u8>>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dechunk(mut rest: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(rest.len()));
    loop {
        let line_end = find(rest, b"\r\n").ok_or(Error::ResponseInvalid)?;
        let (line, tail) = rest.split_at(line_end);
        let size_text = line.split(|b| *b == b';').next().unwrap_or_default();
        let size_text = core::str::from_utf8(size_text).map_err(|_| Error::ResponseInvalid)?;
        let size =
            usize::from_str_radix(size_text.trim(), 16).map_err(|_| Error::ResponseInvalid)?;
        let tail = tail.get(2..).ok_or(Error::ResponseInvalid)?;
        if size == 0 {
            return Ok(out);
        }
        let chunk = tail.get(..size).ok_or(Error::ResponseInvalid)?;
        out.extend_from_slice(chunk);
        rest = tail.get(size + 2..).ok_or(Error::ResponseInvalid)?;
    }
}

impl<'a> Http<'a> {
    /// Splits a response. A chunked body is joined; a body longer than its `Content-Length`
    /// is cut.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_RESPONSE {
            return Err(Error::ResponseInvalid);
        }
        let split = find(bytes, b"\r\n\r\n").ok_or(Error::ResponseInvalid)?;
        let (head, rest) = bytes.split_at(split);
        let raw_body = rest.get(4..).unwrap_or_default();
        let head = core::str::from_utf8(head).map_err(|_| Error::ResponseInvalid)?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or(Error::ResponseInvalid)?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let status: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::ResponseInvalid)?;
        if !version.starts_with("HTTP/") {
            return Err(Error::ResponseInvalid);
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or(Error::ResponseInvalid)?;
            headers.push((name.trim(), value.trim().as_bytes()));
        }
        let mut http = Self {
            status,
            headers,
            body: Zeroizing::new(Vec::new()),
        };
        let chunked = http
            .header("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case(b"chunked"));
        let length = http
            .header("content-length")
            .and_then(|v| core::str::from_utf8(v).ok())
            .and_then(|v| v.parse::<usize>().ok());
        http.body = if chunked {
            dechunk(raw_body)?
        } else {
            let end = length.map_or(raw_body.len(), |l| l.min(raw_body.len()));
            Zeroizing::new(raw_body.get(..end).unwrap_or_default().to_vec())
        };
        Ok(http)
    }

    fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    fn headers_named(&self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    /// The value a source names, if the response has it.
    pub fn capture(&self, source: &Source) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(match source {
            Source::Status => Some(Zeroizing::new(self.status.to_string().into_bytes())),
            Source::Header { name } => self.header(name).map(|v| Zeroizing::new(v.to_vec())),
            Source::HeaderParam { name, param } => self
                .headers_named(name)
                .find_map(|v| header_param(v, param)),
            Source::Cookie { name } => self
                .headers_named("set-cookie")
                .find_map(|v| set_cookie(v, name)),
            Source::Json { pointer } => json_pointer(&self.body, pointer)?,
            Source::Between { start, end } => between(&self.body, start, end),
            Source::All => Some(self.body.clone()),
        })
    }
}

/// The value a stream source (`between` or `all`) names in bytes read from a stream.
pub(crate) fn capture_bytes(bytes: &[u8], source: &Source) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match source {
        Source::Between { start, end } => Ok(between(bytes, start, end)),
        Source::All => Ok(Some(Zeroizing::new(bytes.to_vec()))),
        _ => Err(Error::PolicyInvalid),
    }
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

fn header_param(value: &[u8], param: &str) -> Option<Zeroizing<Vec<u8>>> {
    for part in split_params(value) {
        let Some(eq) = part.iter().position(|b| *b == b'=') else {
            continue;
        };
        let (key, rest) = part.split_at(eq);
        // The first parameter follows the scheme: `Digest realm="x"`.
        let key = key
            .trim_ascii()
            .rsplit(|b| *b == b' ')
            .next()
            .unwrap_or_default();
        if !key.eq_ignore_ascii_case(param.as_bytes()) {
            continue;
        }
        let raw = rest.get(1..)?.trim_ascii();
        return Some(
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
        );
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

fn json_pointer(body: &[u8], pointer: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Err(Error::ResponseInvalid);
    };
    Ok(value.pointer(pointer).and_then(|v| match v {
        serde_json::Value::String(s) => Some(Zeroizing::new(s.as_bytes().to_vec())),
        serde_json::Value::Number(n) => Some(Zeroizing::new(n.to_string().into_bytes())),
        serde_json::Value::Bool(b) => Some(Zeroizing::new(b.to_string().into_bytes())),
        _ => None,
    }))
}

fn replace_all(bytes: &mut Vec<u8>, needle: &[u8]) {
    if needle.len() < crate::reflection::MIN_NEEDLE {
        return;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut rest = bytes.as_slice();
    while let Some(at) = find(rest, needle) {
        out.extend_from_slice(rest.get(..at).unwrap_or_default());
        out.extend_from_slice(REDACTED);
        rest = rest.get(at + needle.len()..).unwrap_or_default();
    }
    out.extend_from_slice(rest);
    zeroize::Zeroize::zeroize(bytes);
    bytes.clear();
    bytes.extend_from_slice(&out);
}

/// Replaces every captured secret in `bytes`, raw and JSON-escaped, with [`REDACTED`].
pub(crate) fn redact(bytes: &mut Vec<u8>, secrets: &[Zeroizing<Vec<u8>>]) {
    for secret in secrets {
        replace_all(bytes, secret);
        let escaped = json_escape(secret);
        replace_all(bytes, &escaped);
        // JSON may escape `/` as `\/`.
        if secret.contains(&b'/') {
            let mut slashed = Zeroizing::new(Vec::with_capacity(escaped.len() + 8));
            for &b in escaped.iter() {
                if b == b'/' {
                    slashed.push(b'\\');
                }
                slashed.push(b);
            }
            replace_all(bytes, &slashed);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const RESPONSE: &[u8] = b"HTTP/1.1 401 Unauthorized\r\n\
WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b\", opaque=\"5ccc\"\r\n\
Set-Cookie: theme=dark; Path=/\r\n\
Set-Cookie: sid=abc123def456; HttpOnly\r\n\
Transfer-Encoding: chunked\r\n\r\n\
7\r\n{\"a\":{\"\r\na\r\nb\":\"x/y\"}}\r\n0\r\n\r\n";

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
        let param = |p: &str| Source::HeaderParam {
            name: "www-authenticate".into(),
            param: p.into(),
        };
        assert_eq!(get(param("realm")).unwrap(), b"testrealm@host.com");
        assert_eq!(get(param("qop")).unwrap(), b"auth,auth-int");
        assert_eq!(get(param("opaque")).unwrap(), b"5ccc");
        assert_eq!(
            get(Source::Cookie { name: "sid".into() }).unwrap(),
            b"abc123def456"
        );
        assert_eq!(
            get(Source::Json {
                pointer: "/a/b".into()
            })
            .unwrap(),
            b"x/y"
        );
        assert_eq!(
            get(Source::Cookie {
                name: "none".into()
            }),
            None
        );
    }

    #[test]
    fn redacts_raw_and_escaped() {
        let mut bytes = br#"{"t":"abc/defghij","u":"abc\/defghij"}"#.to_vec();
        redact(&mut bytes, &[Zeroizing::new(b"abc/defghij".to_vec())]);
        assert_eq!(bytes, br#"{"t":"[redacted]","u":"[redacted]"}"#);
    }
}
