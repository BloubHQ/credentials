//! A synchronous HTTP/2 client (RFC 9113) for one request per connection.
//!
//! The engine builds every request in HTTP/1.1 form and reads every response in that form, so
//! its contracts, injections, projection and reflection search apply the same over both
//! versions. This module translates: the request the engine built becomes a `HEADERS` frame
//! (and `DATA`), and the response becomes HTTP/1.1 bytes with a chunked body and its trailers.
//!
//! Nothing a server sends reaches those bytes unchecked: header names must be lowercase
//! tokens, values may hold no control character but tab (no CR, LF or NUL that would start a
//! line of their own), pseudo-headers come first and only `:status` in a response head,
//! connection-specific fields are refused, `Content-Length` must equal the body, and frame
//! sizes, header blocks, windows and settings are bounded. Server push is turned off
//! (`SETTINGS_ENABLE_PUSH = 0`) and a `PUSH_PROMISE` is a protocol error.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use engine::readbuf::ReadBuf;
use zeroize::Zeroize;

use crate::hpack::{self, Decoder};

/// The connection preface of a client.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Largest frame payload the node accepts (`SETTINGS_MAX_FRAME_SIZE`, the default).
pub const MAX_FRAME: usize = 16_384;
/// Largest header list the node accepts (`SETTINGS_MAX_HEADER_LIST_SIZE`).
pub const MAX_HEADER_LIST: usize = 64 * 1024;
/// Largest compressed header block (a `HEADERS` frame and its `CONTINUATION`s).
pub const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// The receive window of the stream and of the connection.
const WINDOW: u32 = 1 << 20;
/// The largest flow-control window (RFC 9113, 6.9.1).
const MAX_WINDOW: i64 = (1 << 31) - 1;
/// The stream of the one request.
const STREAM: u32 = 1;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// Why an HTTP/2 exchange failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum H2Error {
    /// The server broke the protocol: `0` says how.
    #[error("HTTP/2 protocol error: {0}")]
    Protocol(&'static str),
    /// A header block did not decode.
    #[error("HPACK: {0}")]
    Hpack(hpack::HpackError),
    /// The connection ended before the response did.
    #[error("connection closed before the response ended")]
    Closed,
    /// The server reset the stream or refused it.
    #[error("the server reset the stream")]
    Reset,
    /// Reading or writing failed.
    #[error("I/O: {0:?}")]
    Io(io::ErrorKind),
    /// The deadline passed.
    #[error("deadline passed")]
    Timeout,
    /// The response is larger than the limit.
    #[error("response too large")]
    TooLarge,
}

impl From<hpack::HpackError> for H2Error {
    fn from(e: hpack::HpackError) -> Self {
        H2Error::Hpack(e)
    }
}

fn protocol(rule: &'static str) -> H2Error {
    H2Error::Protocol(rule)
}

/// A byte stream an HTTP/2 connection runs over, with a wait for reads.
pub trait Io: Read + Write {
    /// Sets how long one read or write may block.
    fn set_wait(&mut self, wait: Duration) -> io::Result<()>;
}

fn io_error(e: &io::Error) -> H2Error {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => H2Error::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => H2Error::Closed,
        kind => H2Error::Io(kind),
    }
}

/// One frame.
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

fn frame_bytes(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(len.get(1..).unwrap_or_default());
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Splits the frames out of what was read, keeping a partial frame for the next read.
#[derive(Default)]
struct Reader {
    /// Wiped as frames are taken and when dropped.
    buf: ReadBuf,
}

impl Reader {
    fn next(&mut self) -> Result<Option<Frame>, H2Error> {
        let pending = self.buf.pending();
        let Some([l0, l1, l2, kind, flags, s0, s1, s2, s3]) = pending
            .get(..9)
            .and_then(|head| <[u8; 9]>::try_from(head).ok())
        else {
            return Ok(None);
        };
        let len = usize::from(l0) << 16 | usize::from(l1) << 8 | usize::from(l2);
        if len > MAX_FRAME {
            return Err(protocol("frame larger than SETTINGS_MAX_FRAME_SIZE"));
        }
        let stream = u32::from_be_bytes([s0, s1, s2, s3]) & 0x7fff_ffff;
        if pending.len() < 9 + len {
            return Ok(None);
        }
        self.buf.skip(9);
        // The frame takes the bytes out; the buffer they were taken from is erased.
        let payload = std::mem::take(&mut *self.buf.take(len));
        Ok(Some(Frame {
            kind,
            flags,
            stream,
            payload,
        }))
    }
}

/// The parts of the request the engine built.
struct Request<'w> {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    body: &'w [u8],
}

/// Fields of HTTP/1.1 that have no meaning in HTTP/2 (RFC 9113, 8.2.2).
const CONNECTION_FIELDS: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads the HTTP/1.1 request the engine built into the fields and body of an HTTP/2 one.
fn request(wire: &[u8]) -> Result<Request<'_>, H2Error> {
    let bad = || protocol("the request is not one the engine builds");
    let split = find(wire, b"\r\n\r\n").ok_or_else(bad)?;
    let head = wire.get(..split).ok_or_else(bad)?;
    let body = wire.get(split + 4..).ok_or_else(bad)?;
    let mut lines = head
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = lines.next().ok_or_else(bad)?;
    let mut parts = line.splitn(3, |b| *b == b' ');
    let (Some(method), Some(target), Some(b"HTTP/1.1")) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let mut authority = None;
    let mut regular = Vec::new();
    let mut length = None;
    for line in lines {
        let colon = line.iter().position(|b| *b == b':').ok_or_else(bad)?;
        let name = line.get(..colon).ok_or_else(bad)?.to_ascii_lowercase();
        let value = line.get(colon + 1..).ok_or_else(bad)?.trim_ascii();
        if name == b"host" {
            authority = Some(value.to_vec());
            continue;
        }
        if name == b"content-length" {
            length = engine::encoding::digits::<usize>(value);
        }
        if CONNECTION_FIELDS.contains(&name.as_slice()) || (name == b"te" && value != b"trailers") {
            continue;
        }
        regular.push((name, value.to_vec()));
    }
    if length != Some(body.len()) {
        return Err(bad());
    }
    let mut fields = vec![
        (b":method".to_vec(), method.to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), authority.ok_or_else(bad)?),
        (b":path".to_vec(), target.to_vec()),
    ];
    fields.extend(regular);
    Ok(Request { fields, body })
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The fields of a response head (`trailers == false`) or of its trailers, checked
/// (RFC 9113, 8.2 and 8.3), with the status and the declared content length.
#[derive(Debug, PartialEq, Eq)]
pub struct Checked {
    /// The `:status` of a head.
    pub status: Option<u16>,
    /// The regular fields, in order, without `content-length`.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
    /// The `content-length`, when given.
    pub length: Option<u64>,
}

/// Checks decoded fields before any reaches HTTP/1.1 form.
pub fn check_fields(fields: Vec<hpack::Field>, trailers: bool) -> Result<Checked, H2Error> {
    let mut status = None;
    let mut regular = false;
    let mut length: Option<u64> = None;
    let mut out = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        if let Some(pseudo) = name.strip_prefix(b":") {
            if trailers || regular || pseudo != b"status" || status.is_some() {
                return Err(protocol("pseudo-header not allowed here"));
            }
            let text = core::str::from_utf8(&value).map_err(|_| protocol(":status"))?;
            if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
                return Err(protocol(":status"));
            }
            status = Some(text.parse::<u16>().map_err(|_| protocol(":status"))?);
            continue;
        }
        regular = true;
        if name.is_empty() || !name.iter().all(|b| is_name_byte(*b)) {
            return Err(protocol("header name not a lowercase token"));
        }
        if CONNECTION_FIELDS.contains(&name.as_slice()) || name == b"te" {
            return Err(protocol("connection-specific header"));
        }
        let controls = value
            .iter()
            .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f);
        let padded = value.first().is_some_and(|b| *b == b' ' || *b == b'\t')
            || value.last().is_some_and(|b| *b == b' ' || *b == b'\t');
        if controls || padded {
            return Err(protocol(
                "header value holds a control character or padding",
            ));
        }
        if name == b"content-length" {
            let n = engine::encoding::digits::<u64>(&value)
                .ok_or_else(|| protocol("content-length"))?;
            if length.is_some_and(|l| l != n) {
                return Err(protocol("content-length given twice"));
            }
            length = Some(n);
            continue;
        }
        out.push((name, value));
    }
    if !trailers && status.is_none() {
        return Err(protocol("response without :status"));
    }
    Ok(Checked {
        status,
        fields: out,
        length,
    })
}

fn lines(out: &mut Vec<u8>, fields: &[(Vec<u8>, Vec<u8>)]) {
    for (name, value) in fields {
        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
}

/// The state of the response.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the head.
    Head,
    /// Reading the body.
    Body,
    /// The response ended.
    Done,
}

/// One HTTP/2 connection carrying one request.
pub struct Conn<S: Io> {
    io: S,
    reader: Reader,
    decoder: Decoder,
    /// What the server lets the node send: the connection and the stream.
    send_conn: i64,
    send_stream: i64,
    peer_initial: i64,
    peer_frame: usize,
    /// A header block in pieces (`HEADERS` without `END_HEADERS`), and whether its stream
    /// ends with it.
    block: Option<(Vec<u8>, bool)>,
    phase: Phase,
    data_len: u64,
    length: Option<u64>,
    /// The request is a `HEAD`: its response has no body.
    head_request: bool,
    /// HTTP/1.1 bytes of the response not yet handed out.
    out: Vec<u8>,
    io_timeout: Duration,
    deadline: Instant,
}

impl<S: Io> Drop for Conn<S> {
    fn drop(&mut self) {
        self.out.zeroize();
    }
}

impl<S: Io> Conn<S> {
    fn wait(&mut self, wait: Duration) -> Result<(), H2Error> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(H2Error::Timeout);
        }
        self.io
            .set_wait(
                wait.min(self.io_timeout)
                    .min(left)
                    .max(Duration::from_millis(1)),
            )
            .map_err(|e| io_error(&e))
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), H2Error> {
        self.wait(self.io_timeout)?;
        self.io
            .write_all(bytes)
            .and_then(|()| self.io.flush())
            .map_err(|e| io_error(&e))
    }

    fn write_frame(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> Result<(), H2Error> {
        let mut bytes = frame_bytes(kind, flags, stream, payload);
        let written = self.write(&bytes);
        bytes.zeroize();
        written
    }

    /// Opens the connection and sends the request `wire` (HTTP/1.1, as the engine built it).
    pub fn start(
        io: S,
        wire: &[u8],
        io_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, H2Error> {
        let mut conn = Conn {
            io,
            reader: Reader::default(),
            decoder: Decoder::default(),
            send_conn: 65_535,
            send_stream: 65_535,
            peer_initial: 65_535,
            peer_frame: MAX_FRAME,
            block: None,
            phase: Phase::Head,
            data_len: 0,
            length: None,
            head_request: engine::response::is_head_request(wire),
            out: Vec::new(),
            io_timeout,
            deadline,
        };
        let request = request(wire)?;
        let mut settings = Vec::with_capacity(18);
        for (id, value) in [
            (0x2u16, 0u32),
            (0x4, WINDOW),
            (0x6, u32::try_from(MAX_HEADER_LIST).unwrap_or(u32::MAX)),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&value.to_be_bytes());
        }
        let mut opening = PREFACE.to_vec();
        opening.extend(frame_bytes(SETTINGS, 0, 0, &settings));
        opening.extend(frame_bytes(
            WINDOW_UPDATE,
            0,
            0,
            &(WINDOW - 65_535).to_be_bytes(),
        ));
        conn.write(&opening)?;

        let fields: Vec<(&[u8], &[u8])> = request
            .fields
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        let mut block = hpack::encode(&fields);
        let end = if request.body.is_empty() {
            END_STREAM
        } else {
            0
        };
        let mut first = true;
        let mut rest: &[u8] = &block;
        loop {
            let take = rest.len().min(conn.peer_frame);
            let (part, tail) = rest.split_at(take);
            let last = tail.is_empty();
            let flags = if last { END_HEADERS } else { 0 };
            if first {
                conn.write_frame(HEADERS, flags | end, STREAM, part)?;
                first = false;
            } else {
                conn.write_frame(CONTINUATION, flags, STREAM, part)?;
            }
            rest = tail;
            if last {
                break;
            }
        }
        block.zeroize();
        let mut body = request.body;
        while !body.is_empty() {
            let room = conn.send_conn.min(conn.send_stream);
            if room <= 0 {
                // Wait for the server to open its window.
                if conn.phase == Phase::Done {
                    break;
                }
                conn.step(conn.io_timeout)?;
                continue;
            }
            let room = usize::try_from(room).unwrap_or(0);
            let take = body.len().min(room).min(conn.peer_frame);
            let (part, tail) = body.split_at(take);
            let flags = if tail.is_empty() { END_STREAM } else { 0 };
            conn.write_frame(DATA, flags, STREAM, part)?;
            let sent = i64::try_from(take).unwrap_or(i64::MAX);
            conn.send_conn -= sent;
            conn.send_stream -= sent;
            body = tail;
        }
        Ok(conn)
    }

    /// Reads one read's worth of bytes and handles the frames they complete. False when
    /// nothing came within `wait`.
    fn step(&mut self, wait: Duration) -> Result<bool, H2Error> {
        if let Some(frame) = self.reader.next()? {
            self.handle(frame)?;
            return Ok(true);
        }
        self.wait(wait)?;
        let mut chunk = [0u8; 16 * 1024];
        let n = match self.io.read(&mut chunk) {
            Ok(0) => return Err(H2Error::Closed),
            Ok(n) => n,
            Err(e) => {
                return match io_error(&e) {
                    H2Error::Timeout => Ok(false),
                    other => Err(other),
                };
            }
        };
        self.reader.buf.push(chunk.get(..n).unwrap_or_default());
        chunk.zeroize();
        while let Some(frame) = self.reader.next()? {
            self.handle(frame)?;
        }
        Ok(true)
    }

    fn handle(&mut self, frame: Frame) -> Result<(), H2Error> {
        if self.block.is_some() && (frame.kind != CONTINUATION || frame.stream != STREAM) {
            return Err(protocol("a header block was interrupted"));
        }
        match frame.kind {
            DATA => self.data(frame),
            HEADERS => {
                self.ours(&frame)?;
                let mut payload = unpad(&frame)?;
                if frame.flags & PRIORITY_FLAG != 0 {
                    payload = payload.get(5..).ok_or(protocol("HEADERS priority"))?;
                }
                let block = payload.to_vec();
                let end_stream = frame.flags & END_STREAM != 0;
                if frame.flags & END_HEADERS != 0 {
                    self.headers(block, end_stream)
                } else {
                    self.block = Some((block, end_stream));
                    Ok(())
                }
            }
            CONTINUATION => {
                self.ours(&frame)?;
                let Some((mut block, end_stream)) = self.block.take() else {
                    return Err(protocol("CONTINUATION without HEADERS"));
                };
                block.extend_from_slice(&frame.payload);
                if block.len() > MAX_HEADER_BLOCK {
                    return Err(protocol("header block too large"));
                }
                if frame.flags & END_HEADERS != 0 {
                    self.headers(block, end_stream)
                } else {
                    self.block = Some((block, end_stream));
                    Ok(())
                }
            }
            PRIORITY => {
                if frame.stream == 0 || frame.payload.len() != 5 {
                    return Err(protocol("PRIORITY"));
                }
                Ok(())
            }
            RST_STREAM => {
                if frame.stream == 0 || frame.payload.len() != 4 {
                    return Err(protocol("RST_STREAM"));
                }
                self.ours(&frame)?;
                Err(H2Error::Reset)
            }
            SETTINGS => self.settings(&frame),
            PUSH_PROMISE => Err(protocol("PUSH_PROMISE with push disabled")),
            PING => {
                if frame.stream != 0 || frame.payload.len() != 8 {
                    return Err(protocol("PING"));
                }
                if frame.flags & ACK == 0 {
                    self.write_frame(PING, ACK, 0, &frame.payload)?;
                }
                Ok(())
            }
            GOAWAY => {
                if frame.stream != 0 || frame.payload.len() < 8 {
                    return Err(protocol("GOAWAY"));
                }
                let last = frame
                    .payload
                    .get(..4)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(|b| u32::from_be_bytes(b) & 0x7fff_ffff)
                    .unwrap_or(0);
                if last < STREAM && self.phase != Phase::Done {
                    return Err(H2Error::Reset);
                }
                Ok(())
            }
            WINDOW_UPDATE => {
                let increment = <[u8; 4]>::try_from(frame.payload.as_slice())
                    .map(|b| i64::from(u32::from_be_bytes(b) & 0x7fff_ffff))
                    .map_err(|_| protocol("WINDOW_UPDATE"))?;
                if increment == 0 {
                    return Err(protocol("WINDOW_UPDATE of zero"));
                }
                let window = match frame.stream {
                    0 => &mut self.send_conn,
                    STREAM => &mut self.send_stream,
                    _ => return Err(protocol("frame on a stream the node did not open")),
                };
                *window += increment;
                if *window > MAX_WINDOW {
                    return Err(protocol("flow-control window overflow"));
                }
                Ok(())
            }
            // Unknown frame types are ignored (RFC 9113, 4.1).
            _ => Ok(()),
        }
    }

    /// Refuses a frame on another stream than the request's.
    fn ours(&self, frame: &Frame) -> Result<(), H2Error> {
        if frame.stream != STREAM {
            return Err(protocol("frame on a stream the node did not open"));
        }
        Ok(())
    }

    fn settings(&mut self, frame: &Frame) -> Result<(), H2Error> {
        if frame.stream != 0 {
            return Err(protocol("SETTINGS on a stream"));
        }
        if frame.flags & ACK != 0 {
            return if frame.payload.is_empty() {
                Ok(())
            } else {
                Err(protocol("SETTINGS ACK with a payload"))
            };
        }
        if !frame.payload.len().is_multiple_of(6) {
            return Err(protocol("SETTINGS length"));
        }
        for entry in frame.payload.chunks(6) {
            let (Some(id), Some(value)) = (
                entry.get(..2).and_then(|b| <[u8; 2]>::try_from(b).ok()),
                entry.get(2..6).and_then(|b| <[u8; 4]>::try_from(b).ok()),
            ) else {
                return Err(protocol("SETTINGS length"));
            };
            let value = u32::from_be_bytes(value);
            match u16::from_be_bytes(id) {
                0x2 if value > 1 => return Err(protocol("SETTINGS_ENABLE_PUSH")),
                0x4 => {
                    let value = i64::from(value);
                    if value > MAX_WINDOW {
                        return Err(protocol("SETTINGS_INITIAL_WINDOW_SIZE"));
                    }
                    self.send_stream += value - self.peer_initial;
                    self.peer_initial = value;
                    if self.send_stream > MAX_WINDOW {
                        return Err(protocol("flow-control window overflow"));
                    }
                }
                0x5 => {
                    let value = usize::try_from(value).unwrap_or(usize::MAX);
                    if !(MAX_FRAME..=16_777_215).contains(&value) {
                        return Err(protocol("SETTINGS_MAX_FRAME_SIZE"));
                    }
                    self.peer_frame = value.min(MAX_FRAME);
                }
                // Table size (the encoder uses no table), concurrency, list size and unknown
                // settings change nothing for one literal request.
                _ => {}
            }
        }
        self.write_frame(SETTINGS, ACK, 0, &[])
    }

    fn data(&mut self, frame: Frame) -> Result<(), H2Error> {
        self.ours(&frame)?;
        if self.phase != Phase::Body {
            return Err(protocol("DATA outside the body"));
        }
        let payload = unpad(&frame)?;
        if !payload.is_empty() {
            self.out
                .extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            self.out.extend_from_slice(payload);
            self.out.extend_from_slice(b"\r\n");
        }
        self.data_len = self
            .data_len
            .saturating_add(u64::try_from(payload.len()).unwrap_or(u64::MAX));
        if self.length.is_some_and(|l| self.data_len > l) {
            return Err(protocol("body longer than content-length"));
        }
        let end = frame.flags & END_STREAM != 0;
        // The whole frame counts against the windows, padding included: give it back.
        let used = u32::try_from(frame.payload.len()).unwrap_or(u32::MAX);
        if used > 0 {
            let mut update = frame_bytes(WINDOW_UPDATE, 0, 0, &used.to_be_bytes());
            if !end {
                update.extend(frame_bytes(WINDOW_UPDATE, 0, STREAM, &used.to_be_bytes()));
            }
            self.write(&update)?;
        }
        if end {
            self.finish(&[])?;
        }
        Ok(())
    }

    fn finish(&mut self, trailers: &[(Vec<u8>, Vec<u8>)]) -> Result<(), H2Error> {
        if self.length.is_some_and(|l| l != self.data_len) {
            return Err(protocol("body shorter than content-length"));
        }
        self.out.extend_from_slice(b"0\r\n");
        lines(&mut self.out, trailers);
        self.out.extend_from_slice(b"\r\n");
        self.phase = Phase::Done;
        Ok(())
    }

    fn headers(&mut self, mut block: Vec<u8>, end_stream: bool) -> Result<(), H2Error> {
        let fields = self.decoder.decode(&block, MAX_HEADER_LIST);
        block.zeroize();
        let fields = fields?;
        match self.phase {
            Phase::Head => {
                let checked = check_fields(fields, false)?;
                let status = checked.status.unwrap_or(0);
                if (100..200).contains(&status) {
                    // An interim response: no protocol switch over HTTP/2, and it never ends
                    // the stream.
                    if status == 101 || end_stream {
                        return Err(protocol("interim response"));
                    }
                    return Ok(());
                }
                self.out
                    .extend_from_slice(format!("HTTP/1.1 {status} \r\n").as_bytes());
                lines(&mut self.out, &checked.fields);
                self.out
                    .extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
                // A response to HEAD and any 204 or 304 has no body, whatever its length says
                // (RFC 9113 section 8.1.1): a DATA frame on it is refused.
                self.length = if self.head_request || status == 204 || status == 304 {
                    Some(0)
                } else {
                    checked.length
                };
                self.phase = Phase::Body;
                if end_stream {
                    self.finish(&[])?;
                }
                Ok(())
            }
            Phase::Body => {
                if !end_stream {
                    return Err(protocol("trailers that do not end the stream"));
                }
                let checked = check_fields(fields, true)?;
                if checked.length.is_some() {
                    return Err(protocol("content-length in trailers"));
                }
                self.finish(&checked.fields)
            }
            Phase::Done => Err(protocol("HEADERS after the stream ended")),
        }
    }

    /// Reads what the response has for the caller within `wait`: HTTP/1.1 bytes, nothing, or
    /// the end.
    pub fn poll(&mut self, max: usize, wait: Duration) -> Result<Option<Vec<u8>>, H2Error> {
        let until = Instant::now() + wait;
        while self.out.is_empty() && self.phase != Phase::Done {
            let left = until.saturating_duration_since(Instant::now());
            if !self.step(left)? && Instant::now() >= until {
                return Ok(Some(Vec::new()));
            }
        }
        if self.out.is_empty() {
            return Ok(None);
        }
        let take = self.out.len().min(max.max(1));
        let rest = self.out.get(take..).unwrap_or_default().to_vec();
        let head = self.out.get(..take).unwrap_or_default().to_vec();
        self.out.zeroize();
        self.out = rest;
        Ok(Some(head))
    }

    /// Reads the whole response, at most `max` bytes in HTTP/1.1 form.
    pub fn finish_all(&mut self, max: usize) -> Result<Vec<u8>, H2Error> {
        let mut all = Vec::new();
        loop {
            match self.poll(max, self.io_timeout)? {
                None => return Ok(all),
                Some(bytes) => {
                    if all.len().saturating_add(bytes.len()) > max {
                        all.zeroize();
                        return Err(H2Error::TooLarge);
                    }
                    all.extend_from_slice(&bytes);
                }
            }
        }
    }

    /// The byte stream, to close it.
    pub fn io_mut(&mut self) -> &mut S {
        &mut self.io
    }
}

/// The payload of a `DATA` or `HEADERS` frame without its padding.
fn unpad(frame: &Frame) -> Result<&[u8], H2Error> {
    if frame.flags & PADDED == 0 {
        return Ok(&frame.payload);
    }
    let pad = usize::from(*frame.payload.first().ok_or(protocol("padding"))?);
    let end = frame
        .payload
        .len()
        .checked_sub(pad)
        .filter(|end| *end >= 1)
        .ok_or(protocol("padding longer than the frame"))?;
    frame.payload.get(1..end).ok_or(protocol("padding"))
}

/// An in-memory server side, for tests and the fuzz targets: reads are served from `input`,
/// writes are kept.
pub struct Script {
    input: Vec<u8>,
    at: usize,
    /// What the client wrote.
    pub written: Vec<u8>,
}

impl Script {
    /// A server that sends `input`, then ends the connection.
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            at: 0,
            written: Vec::new(),
        }
    }
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = self.input.get(self.at..).unwrap_or_default();
        // Small reads, so frames arrive split.
        let n = rest.len().min(buf.len()).min(7);
        if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
            to.copy_from_slice(from);
        }
        self.at += n;
        Ok(n)
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Io for Script {
    fn set_wait(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

/// Sends `wire` to a scripted server whose side of the connection is `server` (frames after
/// the server's preface), and reads the response in HTTP/1.1 form: the path the fuzz target
/// `h2_response` drives.
pub fn exchange_scripted(server: &[u8], wire: &[u8], max: usize) -> Result<Vec<u8>, H2Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut conn = Conn::start(
        Script::new(server.to_vec()),
        wire,
        Duration::from_secs(1),
        deadline,
    )?;
    conn.finish_all(max)
}

/// A frame, for tests and the fuzz targets.
pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    frame_bytes(kind, flags, stream, payload)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const WIRE: &[u8] = b"GET /v1/x?a=1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer t0ken-value\r\nContent-Length: 0\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";

    #[test]
    fn many_small_frames_split_across_reads() {
        // 64 KiB of the smallest frames (a 9-byte head and 1 byte), 16 KiB per read: every
        // frame comes out once, whole, also those split between two reads (#46).
        let unit = frame(DATA, 0, 1, b"x");
        let wire: Vec<u8> = unit
            .iter()
            .copied()
            .cycle()
            .take(64 * 1024 / 10 * 10)
            .collect();
        let mut reader = Reader::default();
        let mut frames = 0;
        for chunk in wire.chunks(16 * 1024) {
            reader.buf.push(chunk);
            while let Some(f) = reader.next().unwrap() {
                assert_eq!(
                    (f.kind, f.stream, f.payload.as_slice()),
                    (DATA, 1, &b"x"[..])
                );
                frames += 1;
            }
        }
        assert_eq!(frames, wire.len() / 10);
        assert!(reader.buf.pending().is_empty());
    }

    fn settings() -> Vec<u8> {
        frame(SETTINGS, 0, 0, &[])
    }

    fn head(fields: &[(&[u8], &[u8])], flags: u8) -> Vec<u8> {
        frame(HEADERS, END_HEADERS | flags, 1, &hpack::encode(fields))
    }

    fn run(server: Vec<u8>) -> Result<String, H2Error> {
        exchange_scripted(&server, WIRE, 1 << 20).map(|b| String::from_utf8(b).unwrap())
    }

    #[test]
    fn a_response_becomes_http1_with_trailers() {
        let mut server = settings();
        server.extend(head(
            &[(b":status", b"200"), (b"content-type", b"application/grpc")],
            0,
        ));
        server.extend(frame(DATA, 0, 1, b"hello"));
        server.extend(head(&[(b"grpc-status", b"0")], END_STREAM));
        assert_eq!(
            run(server).unwrap(),
            "HTTP/1.1 200 \r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\ngrpc-status: 0\r\n\r\n"
        );
    }

    #[test]
    fn head_204_and_304_have_no_body_whatever_their_length_says() {
        let head_wire = b"HEAD /f HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        let empty = "HTTP/1.1 200 \r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n";
        let mut server = settings();
        server.extend(head(
            &[(b":status", b"200"), (b"content-length", b"12")],
            END_STREAM,
        ));
        let out = exchange_scripted(&server, head_wire, 1 << 20).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), empty);
        // A DATA frame after the head of such a response is refused.
        server.truncate(settings().len());
        server.extend(head(&[(b":status", b"200"), (b"content-length", b"1")], 0));
        server.extend(frame(DATA, END_STREAM, 1, b"x"));
        assert!(matches!(
            exchange_scripted(&server, head_wire, 1 << 20),
            Err(H2Error::Protocol(_))
        ));
        for status in [&b"204"[..], b"304"] {
            let mut server = settings();
            server.extend(head(
                &[(b":status", status), (b"content-length", b"7")],
                END_STREAM,
            ));
            let out = run(server).unwrap();
            assert!(out.ends_with("\r\n\r\n0\r\n\r\n"), "{out}");
        }
    }

    #[test]
    fn the_request_is_translated() {
        let mut server = settings();
        server.extend(head(&[(b":status", b"204")], END_STREAM));
        let mut conn = Conn::start(
            Script::new(server),
            WIRE,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        conn.finish_all(1024).unwrap();
        let written = conn.io.written.clone();
        assert!(written.starts_with(PREFACE));
        let mut reader = Reader::default();
        reader.buf.push(&written[PREFACE.len()..]);
        let mut kinds = Vec::new();
        let mut decoded = None;
        while let Some(f) = reader.next().unwrap() {
            if f.kind == HEADERS {
                decoded = Some(Decoder::default().decode(&f.payload, 1 << 16).unwrap());
                assert_eq!(
                    f.flags & (END_HEADERS | END_STREAM),
                    END_HEADERS | END_STREAM
                );
            }
            kinds.push(f.kind);
        }
        assert_eq!(kinds[..3], [SETTINGS, WINDOW_UPDATE, HEADERS]);
        let names: Vec<String> = decoded
            .unwrap()
            .into_iter()
            .map(|(n, v)| {
                format!(
                    "{}={}",
                    String::from_utf8(n).unwrap(),
                    String::from_utf8(v).unwrap()
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                ":method=GET",
                ":scheme=https",
                ":authority=api.example.com",
                ":path=/v1/x?a=1",
                "authorization=Bearer t0ken-value",
                "content-length=0",
                "accept-encoding=identity",
            ]
        );
    }

    #[test]
    fn header_injection_through_hpack_is_refused() {
        for fields in [
            // A value with CR LF would start a line of its own in HTTP/1.1 form.
            vec![
                (&b":status"[..], &b"200"[..]),
                (b"x-a", b"1\r\nset-cookie: s=1"),
            ],
            vec![(b":status", b"200"), (b"x-a", b"1\nx-b: 2")],
            vec![(b":status", b"200"), (b"x-a", b"a\0b")],
            // Upper case, a colon or a space in a name.
            vec![(b":status", b"200"), (b"X-A", b"1")],
            vec![(b":status", b"200"), (b"x-a:b", b"1")],
            vec![(b":status", b"200"), (b"x a", b"1")],
            vec![(b":status", b"200"), (b"", b"1")],
            // Pseudo-headers: unknown, twice, after a field, missing.
            vec![(b":status", b"200"), (b":path", b"/")],
            vec![(b":status", b"200"), (b":status", b"204")],
            vec![(b"x-a", b"1"), (b":status", b"200")],
            vec![(b"x-a", b"1")],
            vec![(b":status", b"2000")],
            // Connection-specific fields, a length that disagrees with itself.
            vec![(b":status", b"200"), (b"transfer-encoding", b"chunked")],
            vec![(b":status", b"200"), (b"connection", b"close")],
            vec![
                (b":status", b"200"),
                (b"content-length", b"1"),
                (b"content-length", b"2"),
            ],
            vec![(b":status", b"200"), (b"x-a", b" padded")],
        ] {
            let mut server = settings();
            server.extend(head(&fields, END_STREAM));
            assert!(
                matches!(run(server), Err(H2Error::Protocol(_))),
                "{fields:?}"
            );
        }
        // Trailers hold no pseudo-header and no length.
        let mut server = settings();
        server.extend(head(&[(b":status", b"200")], 0));
        server.extend(head(&[(b":status", b"200")], END_STREAM));
        assert!(matches!(run(server), Err(H2Error::Protocol(_))));
    }

    #[test]
    fn framing_attacks_are_refused() {
        let ok_head = head(&[(b":status", b"200")], 0);
        let cases: Vec<Vec<u8>> = vec![
            // DATA before the head; on another stream; a push.
            frame(DATA, END_STREAM, 1, b"x"),
            [ok_head.clone(), frame(DATA, END_STREAM, 3, b"x")].concat(),
            frame(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2]),
            // A frame larger than the node's limit.
            {
                let mut f = frame(DATA, 0, 1, &[]);
                f[0] = 0x01;
                f
            },
            // A header block interrupted by another frame.
            [
                frame(HEADERS, 0, 1, &hpack::encode(&[(b":status", b"200")])),
                frame(PING, 0, 0, &[0; 8]),
            ]
            .concat(),
            // Padding longer than the frame.
            [ok_head.clone(), frame(DATA, PADDED, 1, &[9, 1])].concat(),
            // A body longer and one shorter than its length.
            [
                head(&[(b":status", b"200"), (b"content-length", b"1")], 0),
                frame(DATA, END_STREAM, 1, b"xy"),
            ]
            .concat(),
            [
                head(&[(b":status", b"200"), (b"content-length", b"3")], 0),
                frame(DATA, END_STREAM, 1, b"xy"),
            ]
            .concat(),
            // Bad settings, a window update of zero, a window that overflows.
            frame(SETTINGS, 0, 0, &[0, 5, 0, 0, 0, 1]),
            frame(SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 2]),
            frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0]),
            frame(WINDOW_UPDATE, 0, 0, &[0x7f, 0xff, 0xff, 0xff]),
            // A protocol switch, and trailers that do not end the stream.
            head(&[(b":status", b"101")], 0),
            [ok_head.clone(), head(&[(b"x", b"1")], 0)].concat(),
        ];
        for (i, case) in cases.into_iter().enumerate() {
            let mut server = settings();
            server.extend(case);
            assert!(matches!(run(server), Err(H2Error::Protocol(_))), "case {i}");
        }
        // A reset, and a connection that ends early.
        let mut server = settings();
        server.extend(frame(RST_STREAM, 0, 1, &[0, 0, 0, 2]));
        assert_eq!(run(server), Err(H2Error::Reset));
        let mut server = settings();
        server.extend(ok_head);
        assert_eq!(run(server), Err(H2Error::Closed));
    }

    #[test]
    fn interim_responses_pings_and_padding() {
        let mut server = settings();
        server.extend(frame(PING, 0, 0, b"12345678"));
        server.extend(head(&[(b":status", b"103"), (b"link", b"</a>")], 0));
        server.extend(head(&[(b":status", b"200")], 0));
        server.extend(frame(DATA, PADDED, 1, &[2, b'o', b'k', 0, 0]));
        server.extend(frame(0xfa, 0, 0, b"unknown"));
        server.extend(frame(DATA, END_STREAM, 1, b""));
        let mut conn = Conn::start(
            Script::new(server),
            WIRE,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let text = String::from_utf8(conn.finish_all(1 << 20).unwrap()).unwrap();
        assert_eq!(
            text,
            "HTTP/1.1 200 \r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        );
        // The ping was answered with its payload.
        let ack = frame(PING, ACK, 0, b"12345678");
        assert!(
            conn.io
                .written
                .windows(ack.len())
                .any(|w| w == ack.as_slice())
        );
    }

    #[test]
    fn large_bodies_wait_for_the_window() {
        let body = vec![b'b'; 200_000];
        let mut wire = format!(
            "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        wire.extend_from_slice(&body);
        let mut server = settings();
        // The default window is 65535: the client sends that much, then waits for updates.
        server.extend(frame(WINDOW_UPDATE, 0, 0, &200_000u32.to_be_bytes()));
        server.extend(frame(WINDOW_UPDATE, 0, 1, &200_000u32.to_be_bytes()));
        server.extend(head(&[(b":status", b"201")], END_STREAM));
        let mut conn = Conn::start(
            Script::new(server),
            &wire,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        conn.finish_all(1024).unwrap();
        let mut reader = Reader::default();
        reader.buf.push(&conn.io.written[PREFACE.len()..]);
        let mut sent = 0;
        while let Some(f) = reader.next().unwrap() {
            if f.kind == DATA {
                assert!(f.payload.len() <= MAX_FRAME);
                sent += f.payload.len();
            }
        }
        assert_eq!(sent, body.len());
    }
}
