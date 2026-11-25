//! A minimal HTTP/1.1 client for the node server: plain `http://` only, one request per
//! connection. TLS in front of a node is the deployer's job.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::files::{Failure, Res, exit};

/// Largest response read.
const MAX_REPLY: u64 = 64 * 1024 * 1024;

/// A response of the server.
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

impl Reply {
    /// True for a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// `Ok` for a 2xx status, else the failure with the exit code of the status: refused
    /// (400, 403, 404), rate limited (429), transport or log failure of the node (502, 503).
    pub fn check(&self, url: &str) -> Res<()> {
        if self.is_success() {
            return Ok(());
        }
        let status = self.status;
        let error = serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));
        let detail = error.map(|e| format!(": {e}")).unwrap_or_default();
        let (code, what) = match status {
            400 | 403 | 404 => (exit::REFUSED, "refused by the node"),
            429 => (exit::RATE_LIMITED, "rate limited by the node"),
            502 | 503 => (exit::IO, "the node failed (transport or log)"),
            _ => (exit::OTHER, "the node answered with an error"),
        };
        Err(Failure::new(
            code,
            format!("{what} (HTTP {status} from {url}){detail}"),
        ))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn connect(authority: &str) -> Res<TcpStream> {
    let addrs: Vec<SocketAddr> = authority
        .to_socket_addrs()
        .map_err(|e| Failure::io(format!("cannot resolve {authority}: {e}")))?
        .collect();
    let mut last = format!("{authority} resolves to no address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = format!("cannot connect to {addr}: {e}"),
        }
    }
    Err(Failure::io(last))
}

/// Sends `method path` with an optional JSON body to the server at `base`
/// (`http://host:port`, optionally with a path prefix).
pub fn request(base: &str, method: &str, path: &str, body: Option<&[u8]>) -> Res<Reply> {
    let rest = base.strip_prefix("http://").ok_or_else(|| {
        Failure::usage(format!(
            "{base}: only http:// URLs are supported (put TLS in front of the node yourself)"
        ))
    })?;
    let (authority, prefix) = match rest.split_once('/') {
        Some((authority, prefix)) => (authority, format!("/{}", prefix.trim_end_matches('/'))),
        None => (rest, String::new()),
    };
    let prefix = if prefix == "/" { String::new() } else { prefix };
    let mut stream = connect(authority)?;
    let io = |e: std::io::Error| Failure::io(format!("{base}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(io)?;
    let mut head = format!(
        "{method} {prefix}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(io)?;
    if let Some(body) = body {
        stream.write_all(body).map_err(io)?;
    }
    stream.flush().map_err(io)?;
    let mut raw = Vec::new();
    stream.take(MAX_REPLY).read_to_end(&mut raw).map_err(io)?;
    parse(&raw).ok_or_else(|| Failure::io(format!("{base}: malformed HTTP response")))
}

fn parse(raw: &[u8]) -> Option<Reply> {
    let end = find(raw, b"\r\n\r\n")?;
    let (head, rest) = raw.split_at(end);
    let body = rest.get(4..)?;
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Some(Reply { status, body })
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(data, b"\r\n")?;
        let (line, rest) = data.split_at(line_end);
        let size = std::str::from_utf8(line).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        let rest = rest.get(2..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        data = rest.get(size.checked_add(2)?..)?;
    }
}
