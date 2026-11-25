//! The server side of HTTP/1.1 for the node: one request per connection, read under a
//! deadline with a bounded head and body, answered with `Connection: close`.
//!
//! A slow client holds only its own connection thread (the number of them is capped by the
//! server), never a worker that runs acts, and loses the connection when its deadline passes.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

/// Largest request line and headers.
pub const MAX_HEAD: usize = 16 * 1024;

/// How long a single read or write may block.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a client has to send its whole request (head and body).
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// A request the server read in full.
pub struct Request {
    /// The method, such as `GET`.
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The body (empty without `Content-Length`).
    pub body: Vec<u8>,
}

/// Why no request was read.
pub enum ReadError {
    /// Answer with this status and message, then close.
    Reply(u16, String),
    /// The client went away or broke the connection: close without an answer.
    Gone,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads more bytes into `buf` before `deadline`. `Ok(false)` when the client closed.
fn read_more(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    deadline: Instant,
) -> Result<bool, ReadError> {
    let timeout = || ReadError::Reply(408, "the request was not received in time".into());
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(timeout());
    }
    stream
        .set_read_timeout(Some(remaining.min(IO_TIMEOUT)))
        .map_err(|_| ReadError::Gone)?;
    let mut chunk = [0u8; 8192];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(false),
        Ok(n) => {
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Err(timeout()),
        Err(e) if e.kind() == ErrorKind::Interrupted => Ok(true),
        Err(_) => Err(ReadError::Gone),
    }
}

/// What the head says about the body.
struct Head {
    method: String,
    path: String,
    content_length: Option<usize>,
}

fn parse_head(head: &[u8]) -> Result<Head, ReadError> {
    let bad = |m: &str| ReadError::Reply(400, m.to_string());
    let head = std::str::from_utf8(head).map_err(|_| bad("the request head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("malformed request line"));
    };
    if !version.starts_with("HTTP/1.") || method.is_empty() || !target.starts_with('/') {
        return Err(bad("malformed request line"));
    }
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("malformed header"));
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ReadError::Reply(
                501,
                "Transfer-Encoding is not supported; send Content-Length".into(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n: usize = value
                .trim()
                .parse()
                .map_err(|_| bad("Content-Length is not a number"))?;
            if content_length.is_some_and(|old| old != n) {
                return Err(bad("conflicting Content-Length headers"));
            }
            content_length = Some(n);
        }
    }
    let path = target.split('?').next().unwrap_or_default().to_string();
    Ok(Head {
        method: method.to_string(),
        path,
        content_length,
    })
}

/// Reads one request: the head (at most [`MAX_HEAD`] bytes), then a body of at most
/// `max_body` bytes announced by `Content-Length`, all within [`REQUEST_DEADLINE`]. A body
/// too large is refused before it is read.
pub fn read_request(stream: &mut TcpStream, max_body: usize) -> Result<Request, ReadError> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::new();
    let end = loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReadError::Reply(431, "request head too large".into()));
        }
        if !read_more(stream, &mut buf, deadline)? {
            return Err(ReadError::Gone);
        }
    };
    if end > MAX_HEAD {
        return Err(ReadError::Reply(431, "request head too large".into()));
    }
    let head = parse_head(buf.get(..end).unwrap_or(&[]))?;
    let length = match head.content_length {
        Some(n) => n,
        None if head.method == "POST" => {
            return Err(ReadError::Reply(411, "a POST needs Content-Length".into()));
        }
        None => 0,
    };
    if length > max_body {
        return Err(ReadError::Reply(
            413,
            format!("body larger than {max_body} bytes"),
        ));
    }
    let mut body = buf.split_off(end.saturating_add(4).min(buf.len()));
    while body.len() < length {
        if !read_more(stream, &mut body, deadline)? {
            return Err(ReadError::Reply(400, "the body ended early".into()));
        }
    }
    body.truncate(length);
    Ok(Request {
        method: head.method,
        path: head.path,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Writes a JSON response and closes the connection. What the client still sends is read
/// and dropped for a moment first, so the close does not reset the connection before the
/// client read the answer.
pub fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    let written = stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.write_all(head.as_bytes()))
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
    if let Err(e) = written {
        eprintln!("error: cannot send the response: {e}");
        return;
    }
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = std::io::copy(&mut stream.take(256 * 1024), &mut std::io::sink());
}
