//! Streaming calls (`POST /stream`): a WebSocket operation, or an HTTPS operation whose
//! `return` streams the body.
//!
//! The request body is the [`SignedCall`] as JSON, as for `/call`. A call refused before
//! anything reached the server gets the JSON reply of `/call`. Otherwise the answer is
//! `200` with `Content-Type: application/vnd.credentials.stream`, and both ways the
//! connection then carries frames: one type byte, the payload length (four bytes, big
//! endian), the payload.
//!
//! From the node:
//! - `H`: the response head as JSON ([`engine::node::Response`]: status, headers, no body);
//!   for a WebSocket, `101` once its steps ran;
//! - `D`: body bytes of a streamed response, after the stream search;
//! - `T`, `B`: a text or binary message of the server (WebSocket);
//! - `E`: the end, as JSON: `{"ok": {"kind": "closed", ...}, "record": ...}` or
//!   `{"error": ..., "status": ..., "record": ...}`. The connection closes after it.
//!
//! From the caller, once it read `H`:
//! - `T`, `B`: a frame for the server: its number (eight bytes, big endian, from 0), its
//!   signature ([`CallerKey::sign_frame`], 64 bytes), then its bytes;
//! - `C`: the caller closes.
//!
//! Everything is synchronous: one thread per connection, as every call. The node waits on
//! the server a few milliseconds at a time, then on the caller.

use std::io::{self, Read, Write};
use std::time::Duration;

use engine::Error;
use engine::call::SignedCall;
use engine::error::TransportKind;
use engine::keys::CallerKey;
use engine::node::{CallerFrame, FromCaller, Part, Relay};
use engine::policy::FrameKind;

use crate::http::Connection;

/// The content type of a streaming answer.
pub const CONTENT_TYPE: &str = "application/vnd.credentials.stream";
/// The response head (JSON).
pub const HEAD: u8 = b'H';
/// Body bytes.
pub const DATA: u8 = b'D';
/// A text message.
pub const TEXT: u8 = b'T';
/// A binary message.
pub const BINARY: u8 = b'B';
/// The end (JSON).
pub const END: u8 = b'E';
/// The caller closes.
pub const CLOSE: u8 = b'C';
/// Longest frame payload the node reads from a caller: a 1 MiB frame, its number and
/// signature.
pub const MAX_CALLER_FRAME: usize = 1024 * 1024 + 8 + 64;
/// Longest frame payload a caller should accept from the node.
pub const MAX_NODE_FRAME: usize = 32 * 1024 * 1024;

/// Writes one frame.
pub fn write_frame<W: Write>(out: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let [a, b, c, d] = len.to_be_bytes();
    out.write_all(&[kind, a, b, c, d])?;
    out.write_all(payload)?;
    out.flush()
}

/// Reads one frame of at most `max` bytes; `None` at the end of the connection.
pub fn read_frame<R: Read>(input: &mut R, max: usize) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match input.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let [kind, a, b, c, d] = head;
    let len = u32::from_be_bytes([a, b, c, d]) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    Ok(Some((kind, payload)))
}

/// The payload of a caller's frame `seq` of `kind` on the call `call`, signed by `key`.
pub fn caller_frame(
    key: &CallerKey,
    call: &SignedCall,
    seq: u64,
    kind: FrameKind,
    data: &[u8],
) -> (u8, Vec<u8>) {
    let binary = kind == FrameKind::Binary;
    let signature = key.sign_frame(&call.auth, seq, binary, data);
    let mut payload = Vec::with_capacity(72 + data.len());
    payload.extend_from_slice(&seq.to_be_bytes());
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(data);
    (if binary { BINARY } else { TEXT }, payload)
}

/// Reads a caller's frame back.
pub fn parse_caller(kind: u8, payload: &[u8]) -> Result<FromCaller, Error> {
    let refused = |rule| Error::FrameRefused { rule };
    let kind = match kind {
        CLOSE => return Ok(FromCaller::Close),
        TEXT => FrameKind::Text,
        BINARY => FrameKind::Binary,
        _ => return Err(refused("unknown frame type")),
    };
    let (Some(seq), Some(signature), Some(data)) = (
        payload
            .get(..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes),
        payload
            .get(8..72)
            .and_then(|b| <[u8; 64]>::try_from(b).ok()),
        payload.get(72..),
    ) else {
        return Err(refused("frame shorter than its number and signature"));
    };
    Ok(FromCaller::Frame(CallerFrame {
        seq,
        kind,
        data: data.to_vec(),
        signature,
    }))
}

fn gone() -> Error {
    Error::transport(TransportKind::Closed, false)
}

/// The caller's side of a streaming call, on its connection.
pub(crate) struct ConnectionRelay<'c, C: Connection> {
    conn: &'c mut C,
    /// True once the answer's head (`200`) was written.
    pub started: bool,
    input: Vec<u8>,
    closed: bool,
}

impl<'c, C: Connection> ConnectionRelay<'c, C> {
    pub(crate) fn new(conn: &'c mut C) -> Self {
        Self {
            conn,
            started: false,
            input: Vec::new(),
            closed: false,
        }
    }

    fn start(&mut self) -> io::Result<()> {
        if self.started {
            return Ok(());
        }
        self.started = true;
        let _ = self.conn.set_write_timeout(Some(crate::http::IO_TIMEOUT));
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {CONTENT_TYPE}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        );
        self.conn.write_all(head.as_bytes())?;
        self.conn.flush()
    }

    /// Writes the end frame and closes the sending side.
    pub(crate) fn finish(&mut self, end: &[u8]) {
        let written = self
            .start()
            .and_then(|()| write_frame(&mut *self.conn, END, end));
        if let Err(e) = written {
            eprintln!("error: cannot send the end of a stream: {e}");
        }
        let _ = self.conn.shutdown_write();
    }

    /// A whole frame of the caller in what was read, if any.
    fn take(&mut self) -> Result<Option<FromCaller>, Error> {
        let Some(head) = self.input.get(..5) else {
            return Ok(None);
        };
        let (kind, len) = match head {
            [kind, a, b, c, d] => (*kind, u32::from_be_bytes([*a, *b, *c, *d]) as usize),
            _ => return Ok(None),
        };
        if len > MAX_CALLER_FRAME {
            return Err(Error::FrameRefused {
                rule: "caller frame too large",
            });
        }
        let Some(payload) = self.input.get(5..5 + len) else {
            return Ok(None);
        };
        let frame = parse_caller(kind, payload)?;
        self.input.drain(..5 + len);
        Ok(Some(frame))
    }
}

impl<C: Connection> Relay for ConnectionRelay<'_, C> {
    fn deliver(&mut self, part: Part) -> Result<(), Error> {
        let (kind, payload) = match part {
            Part::Head(response) => (
                HEAD,
                serde_json::to_vec(&response).map_err(|_| Error::Encoding)?,
            ),
            Part::Body(bytes) => (DATA, bytes.to_vec()),
            Part::Text(bytes) => (TEXT, bytes.to_vec()),
            Part::Binary(bytes) => (BINARY, bytes.to_vec()),
        };
        self.start()
            .and_then(|()| write_frame(&mut *self.conn, kind, &payload))
            .map_err(|_| gone())
    }

    fn next(&mut self, wait: Duration) -> Result<Option<FromCaller>, Error> {
        if self.closed {
            return Ok(Some(FromCaller::Close));
        }
        if let Some(frame) = self.take()? {
            return Ok(Some(frame));
        }
        let wait = wait.max(Duration::from_millis(1));
        if self.conn.set_read_timeout(Some(wait)).is_err() {
            return Err(gone());
        }
        let mut buf = [0u8; 16 * 1024];
        match self.conn.read(&mut buf) {
            Ok(0) => {
                self.closed = true;
                Ok(Some(FromCaller::Close))
            }
            Ok(n) => {
                self.input
                    .extend_from_slice(buf.get(..n).unwrap_or_default());
                if self.input.len() > MAX_CALLER_FRAME + 5 {
                    // Room for exactly one frame: a caller cannot fill the node's memory.
                    if let Some(frame) = self.take()? {
                        return Ok(Some(frame));
                    }
                    return Err(Error::FrameRefused {
                        rule: "caller frame too large",
                    });
                }
                self.take()
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(_) => {
                self.closed = true;
                Ok(Some(FromCaller::Close))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut wire = Vec::new();
        write_frame(&mut wire, TEXT, b"hello").unwrap();
        write_frame(&mut wire, CLOSE, b"").unwrap();
        let mut input = wire.as_slice();
        assert_eq!(
            read_frame(&mut input, 64).unwrap(),
            Some((TEXT, b"hello".to_vec()))
        );
        assert_eq!(
            read_frame(&mut input, 64).unwrap(),
            Some((CLOSE, Vec::new()))
        );
        assert_eq!(read_frame(&mut input, 64).unwrap(), None);
        let mut big = Vec::new();
        write_frame(&mut big, DATA, &[0; 65]).unwrap();
        assert!(read_frame(&mut big.as_slice(), 64).is_err());
        assert!(matches!(
            parse_caller(TEXT, &[0; 71]),
            Err(Error::FrameRefused { .. })
        ));
        assert!(matches!(
            parse_caller(b'X', &[0; 80]),
            Err(Error::FrameRefused { .. })
        ));
    }
}
