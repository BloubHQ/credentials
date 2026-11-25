//! The wire between a node inside an AWS Nitro Enclave and the host program on its parent
//! instance (`credentials host`). An enclave has no network and no disk: its only link is
//! vsock to the parent, which carries three things.
//!
//! - **HTTP** ([`HTTP_PORT`], enclave side): the host forwards the bytes of each TCP
//!   connection of a client to this port, where the node server answers.
//! - **Egress** ([`EGRESS_PORT`], host side): to reach a destination, the node connects here
//!   and sends one line, `CONNECT host:port\n`; the host connects to it over TCP and answers
//!   `OK\n` (or `ERR reason\n`), then carries bytes both ways. TLS runs inside the enclave
//!   ([`RelayConnector`] under `transport::TlsTransport`), so the host sees only ciphertext.
//!   The node checks the destination against the signed policy before it asks.
//! - **Log** ([`LOG_PORT`], host side): one JSON message per line, each answered with one
//!   line. The node says who it is ([`LogMessage::Hello`]) and learns the last entry the host
//!   holds; then it sends entries and checkpoints. The host appends each entry to a file and
//!   syncs it before it answers [`LogReply::Confirmed`], and [`RelaySink`] reports an entry
//!   stored only after that answer.
//!
//! The host is not trusted with secrets or with the integrity of the log (every entry is
//! signed inside the enclave and chained), only with availability: it can refuse to carry
//! bytes or to store entries, and the node then stops (a halted log takes no act).

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use engine::keys::NodePublicKey;
use engine::log::{LogSink, SignedEntry, SignedHead};
use serde::{Deserialize, Serialize};
use transport::{Connector, Socket};

use crate::Sink;

/// The vsock CID of the parent instance, as seen from an enclave.
pub const PARENT_CID: u32 = 3;
/// The vsock port the node server listens on inside the enclave.
pub const HTTP_PORT: u32 = 5000;
/// The vsock port of the egress relay of the host.
pub const EGRESS_PORT: u32 = 5001;
/// The vsock port of the log writer of the host.
pub const LOG_PORT: u32 = 5002;

/// Longest `CONNECT` line, or answer to it.
const MAX_TUNNEL_LINE: usize = 512;
/// Longest log message or answer.
pub const MAX_LOG_LINE: usize = 1024 * 1024;
/// How long the node waits for the host to confirm a log message.
pub const LOG_TIMEOUT: Duration = Duration::from_secs(30);

/// Why the relay failed.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// Reading or writing the link failed.
    #[error("relay i/o: {0}")]
    Io(#[from] io::Error),
    /// A line was longer than allowed.
    #[error("a relay line is longer than {0} bytes")]
    TooLong(usize),
    /// The other side sent something that is not a message of this protocol.
    #[error("malformed relay message: {0}")]
    Malformed(String),
    /// The other side refused.
    #[error("refused by the relay: {0}")]
    Refused(String),
}

/// Whether `host` may be sent in a `CONNECT` line: a DNS name or an IP address (ASCII
/// letters, digits, `.`, `-`, `:`, `[`, `]`), 1 to 253 bytes.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Reads one line, a byte at a time so nothing after the newline is consumed. `None` at the
/// end of the stream before any byte.
fn read_short_line<R: Read>(stream: &mut R, max: usize) -> Result<Option<Vec<u8>>, RelayError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(RelayError::Io(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            Ok(_) => {
                if byte == *b"\n" {
                    return Ok(Some(line));
                }
                if line.len() >= max {
                    return Err(RelayError::TooLong(max));
                }
                line.extend_from_slice(&byte);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Asks the egress relay for a tunnel to `host:port` over `stream`, and waits for its
/// answer. After `Ok`, `stream` carries the bytes of that connection.
pub fn request_tunnel<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
) -> Result<(), RelayError> {
    if !valid_host(host) {
        return Err(RelayError::Malformed(format!(
            "{host:?} is not a host name or address"
        )));
    }
    stream.write_all(format!("CONNECT {host}:{port}\n").as_bytes())?;
    stream.flush()?;
    let line = read_short_line(stream, MAX_TUNNEL_LINE)?
        .ok_or_else(|| RelayError::Refused("the relay closed the link".into()))?;
    if line == b"OK" {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&line);
    Err(RelayError::Refused(
        text.strip_prefix("ERR ").unwrap_or(&text).to_string(),
    ))
}

/// Reads the `CONNECT host:port` line a node sent: the host side of [`request_tunnel`].
pub fn read_tunnel_request<S: Read>(stream: &mut S) -> Result<(String, u16), RelayError> {
    let line = read_short_line(stream, MAX_TUNNEL_LINE)?
        .ok_or_else(|| RelayError::Malformed("no CONNECT line".into()))?;
    let malformed = || RelayError::Malformed("expected CONNECT host:port".into());
    let line = std::str::from_utf8(&line).map_err(|_| malformed())?;
    let target = line.strip_prefix("CONNECT ").ok_or_else(malformed)?;
    let (host, port) = target.rsplit_once(':').ok_or_else(malformed)?;
    let port: u16 = port.parse().map_err(|_| malformed())?;
    if !valid_host(host) || port == 0 {
        return Err(malformed());
    }
    Ok((host.to_string(), port))
}

/// Answers a tunnel request: `OK` or `ERR reason` (the reason on one line).
pub fn answer_tunnel<S: Write>(stream: &mut S, result: Result<(), &str>) -> io::Result<()> {
    match result {
        Ok(()) => stream.write_all(b"OK\n")?,
        Err(reason) => {
            let reason: String = reason
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .take(200)
                .collect();
            stream.write_all(format!("ERR {reason}\n").as_bytes())?;
        }
    }
    stream.flush()
}

/// Opens a byte stream to the relay (a vsock connection to the parent, in an enclave).
pub type Dial = dyn Fn() -> io::Result<Box<dyn Socket>> + Send + Sync;

/// A [`Connector`] that reaches destinations through the egress relay: each connection is a
/// new link to the relay and a `CONNECT` request on it.
pub struct RelayConnector {
    dial: Box<Dial>,
}

impl RelayConnector {
    /// A connector that opens its links with `dial`.
    pub fn new(dial: impl Fn() -> io::Result<Box<dyn Socket>> + Send + Sync + 'static) -> Self {
        Self {
            dial: Box::new(dial),
        }
    }
}

impl Connector for RelayConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        attempt: Duration,
        deadline: Instant,
    ) -> io::Result<Box<dyn Socket>> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect deadline"));
        }
        let mut socket = (self.dial)()?;
        // The relay connects to the destination before it answers: that is the attempt.
        socket.set_timeouts(Some(attempt.min(left)))?;
        request_tunnel(&mut socket, host, port).map_err(|e| match e {
            RelayError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::ConnectionRefused, other.to_string()),
        })?;
        Ok(socket)
    }
}

/// Copies bytes both ways between `a` and `b` until either side ends or fails, then shuts
/// both down. `a2` and `b2` are second handles to the same streams (`try_clone`).
pub fn splice(
    mut a: Box<dyn Socket>,
    mut a2: Box<dyn Socket>,
    mut b: Box<dyn Socket>,
    mut b2: Box<dyn Socket>,
) {
    let forward = thread::Builder::new().name("splice".into()).spawn(move || {
        let _ = io::copy(&mut a, &mut b);
        let _ = a.shutdown();
        let _ = b.shutdown();
    });
    let _ = io::copy(&mut b2, &mut a2);
    let _ = a2.shutdown();
    let _ = b2.shutdown();
    if let Ok(forward) = forward {
        let _ = forward.join();
    }
}

/// A message of a node to the log writer of the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LogMessage {
    /// The first message of a link: whose log the entries are. Answered with
    /// [`LogReply::Ready`].
    Hello {
        /// The log key of the node.
        node: NodePublicKey,
    },
    /// An entry to append. Answered with [`LogReply::Confirmed`] once it is synced.
    Entry(SignedEntry),
    /// A checkpoint to keep next to the log.
    Head(SignedHead),
}

/// An answer of the log writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LogReply {
    /// The log is open; it ends with this entry (`None`: empty).
    Ready {
        /// The last entry the host holds.
        last: Option<Box<SignedEntry>>,
    },
    /// The entry or checkpoint is stored and synced.
    Confirmed,
    /// It was not stored.
    Refused(String),
}

/// Reads JSON lines from a stream, keeping what came after a line for the next one.
pub struct LineReader {
    pending: Vec<u8>,
    max: usize,
}

impl LineReader {
    /// A reader of lines of at most `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            pending: Vec::new(),
            max,
        }
    }

    /// The next line, without its newline; `None` at the end of the stream between lines.
    pub fn read_line<R: Read>(&mut self, stream: &mut R) -> Result<Option<Vec<u8>>, RelayError> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(at) = self.pending.iter().position(|b| *b == b'\n') {
                let rest = self.pending.split_off(at.saturating_add(1));
                let mut line = std::mem::replace(&mut self.pending, rest);
                line.pop();
                return Ok(Some(line));
            }
            if self.pending.len() > self.max {
                return Err(RelayError::TooLong(self.max));
            }
            match stream.read(&mut chunk) {
                Ok(0) if self.pending.is_empty() => return Ok(None),
                Ok(0) => {
                    return Err(RelayError::Io(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
                Ok(n) => self
                    .pending
                    .extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// The next line as a JSON value of type `T`.
    pub fn read_json<T: serde::de::DeserializeOwned, R: Read>(
        &mut self,
        stream: &mut R,
    ) -> Result<Option<T>, RelayError> {
        match self.read_line(stream)? {
            None => Ok(None),
            Some(line) => serde_json::from_slice(&line)
                .map(Some)
                .map_err(|e| RelayError::Malformed(e.to_string())),
        }
    }
}

/// Writes `value` as one JSON line.
pub fn write_json<T: Serialize, W: Write>(stream: &mut W, value: &T) -> Result<(), RelayError> {
    let mut line = serde_json::to_vec(value).map_err(|e| RelayError::Malformed(e.to_string()))?;
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    Ok(())
}

/// The node side of the log link: one connection to the log writer at a time, opened again
/// after a failure.
pub struct LogLink {
    dial: Box<Dial>,
    node: NodePublicKey,
    open: Option<(Box<dyn Socket>, LineReader)>,
}

impl LogLink {
    /// Opens the link for the log of `node` and returns the last entry the host holds.
    pub fn connect(
        dial: impl Fn() -> io::Result<Box<dyn Socket>> + Send + Sync + 'static,
        node: NodePublicKey,
    ) -> Result<(Self, Option<SignedEntry>), RelayError> {
        let mut link = Self {
            dial: Box::new(dial),
            node,
            open: None,
        };
        let last = link.reopen()?;
        Ok((link, last))
    }

    /// Opens a new connection, says hello and returns the last entry the host holds.
    fn reopen(&mut self) -> Result<Option<SignedEntry>, RelayError> {
        self.open = None;
        let mut socket = (self.dial)()?;
        socket.set_timeouts(Some(LOG_TIMEOUT))?;
        let mut reader = LineReader::new(MAX_LOG_LINE);
        write_json(&mut socket, &LogMessage::Hello { node: self.node })?;
        match reader.read_json(&mut socket)? {
            Some(LogReply::Ready { last }) => {
                self.open = Some((socket, reader));
                Ok(last.map(|last| *last))
            }
            Some(LogReply::Refused(reason)) => Err(RelayError::Refused(reason)),
            Some(other) => Err(RelayError::Malformed(format!(
                "expected ready, got {other:?}"
            ))),
            None => Err(RelayError::Refused("the log writer closed the link".into())),
        }
    }

    /// Sends an entry or a checkpoint and waits for the host to confirm it. A failed link is
    /// dropped; the next message opens a new one.
    pub fn send(&mut self, message: &LogMessage) -> Result<(), RelayError> {
        if self.open.is_none() {
            self.reopen()?;
        }
        let Some((socket, reader)) = self.open.as_mut() else {
            return Err(RelayError::Refused("no link to the log writer".into()));
        };
        let reply = write_json(socket, message).and_then(|()| reader.read_json(socket));
        match reply {
            Ok(Some(LogReply::Confirmed)) => Ok(()),
            Ok(Some(LogReply::Refused(reason))) => Err(RelayError::Refused(reason)),
            Ok(other) => {
                self.open = None;
                Err(RelayError::Malformed(format!(
                    "expected confirmed, got {other:?}"
                )))
            }
            Err(e) => {
                self.open = None;
                Err(e)
            }
        }
    }

    /// Asks the host again what its log ends with, over a new connection.
    pub fn last(&mut self) -> Result<Option<SignedEntry>, RelayError> {
        self.reopen()
    }
}

/// A log link shared by the sink of the node and the hooks that send checkpoints.
pub type SharedLink = Arc<Mutex<LogLink>>;

/// Sends a checkpoint over a shared link.
pub fn send_head(link: &SharedLink, head: &SignedHead) -> Result<(), RelayError> {
    link.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .send(&LogMessage::Head(head.clone()))
}

/// The [`Sink`] of a node in an enclave: an entry is stored once the host confirmed it.
pub struct RelaySink {
    link: SharedLink,
    confirmed: u64,
    stored: Option<Option<SignedEntry>>,
}

impl RelaySink {
    /// A sink over `link`, whose log ends with `last`.
    pub fn new(link: SharedLink, last: Option<SignedEntry>) -> Self {
        Self {
            link,
            confirmed: 0,
            stored: Some(last),
        }
    }
}

impl LogSink for RelaySink {
    fn append(&mut self, entry: &SignedEntry) -> engine::Result<()> {
        let sent = self
            .link
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send(&LogMessage::Entry(entry.clone()));
        match sent {
            Ok(()) => {
                self.confirmed = self.confirmed.saturating_add(1);
                self.stored = Some(Some(entry.clone()));
                Ok(())
            }
            Err(e) => {
                eprintln!("error: the host did not confirm a log entry: {e}");
                // The host may or may not hold it: ask before the next act.
                self.stored = None;
                Err(engine::Error::LogUnconfirmed)
            }
        }
    }
}

impl Sink for RelaySink {
    fn confirmed(&self) -> u64 {
        self.confirmed
    }

    fn stored(&mut self) -> Option<Option<SignedEntry>> {
        if self.stored.is_none() {
            let last = self
                .link
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .last();
            match last {
                Ok(last) => self.stored = Some(last),
                Err(e) => eprintln!("error: cannot ask the host for the end of the log: {e}"),
            }
        }
        self.stored.clone()
    }
}

/// What the log writer of the host stores. Shared by the connections of the node, so it
/// takes `&self`.
pub trait LogStore: Send + Sync {
    /// The last entry of the log of `node` (opened or created). An error refuses the link.
    fn open(&self, node: &NodePublicKey) -> Result<Option<SignedEntry>, String>;

    /// Appends an entry to the log of `node` and syncs it.
    fn append(&self, node: &NodePublicKey, entry: &SignedEntry) -> Result<(), String>;

    /// Keeps a checkpoint of the log of `node`.
    fn checkpoint(&self, node: &NodePublicKey, head: &SignedHead) -> Result<(), String>;
}

/// The host side of one log link: answers its messages until it ends.
pub fn serve_log<S: Read + Write, L: LogStore + ?Sized>(
    stream: &mut S,
    store: &L,
) -> Result<(), RelayError> {
    let mut reader = LineReader::new(MAX_LOG_LINE);
    let mut node: Option<NodePublicKey> = None;
    while let Some(message) = reader.read_json::<LogMessage, _>(stream)? {
        let reply = match (message, &node) {
            (LogMessage::Hello { node: hello }, None) => match store.open(&hello) {
                Ok(last) => {
                    node = Some(hello);
                    LogReply::Ready {
                        last: last.map(Box::new),
                    }
                }
                Err(e) => LogReply::Refused(e),
            },
            (LogMessage::Hello { .. }, Some(_)) => LogReply::Refused("hello sent twice".into()),
            (LogMessage::Entry(entry), Some(node)) => match store.append(node, &entry) {
                Ok(()) => LogReply::Confirmed,
                Err(e) => LogReply::Refused(e),
            },
            (LogMessage::Head(head), Some(node)) => match store.checkpoint(node, &head) {
                Ok(()) => LogReply::Confirmed,
                Err(e) => LogReply::Refused(e),
            },
            (_, None) => LogReply::Refused("the first message must be hello".into()),
        };
        write_json(stream, &reply)?;
    }
    Ok(())
}

/// vsock streams as sockets and connections (Linux: in an enclave and on its parent).
#[cfg(target_os = "linux")]
pub mod vsock {
    use std::io::{self, Read, Write};
    use std::net::Shutdown;
    use std::time::Duration;

    pub use ::vsock::{VMADDR_CID_ANY, VsockListener, VsockStream};

    /// A vsock stream that is a [`transport::Socket`] and a [`crate::Connection`].
    pub struct Vsock(pub VsockStream);

    impl Vsock {
        /// Connects to `port` of `cid`.
        pub fn connect(cid: u32, port: u32) -> io::Result<Self> {
            VsockStream::connect_with_cid_port(cid, port).map(Self)
        }

        /// A second handle to the same stream.
        pub fn try_clone(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }
    }

    impl Read for Vsock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Vsock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl transport::Socket for Vsock {
        fn set_timeouts(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(timeout)?;
            self.0.set_write_timeout(timeout)
        }

        fn shutdown(&self) -> io::Result<()> {
            self.0.shutdown(Shutdown::Both)
        }
    }

    impl crate::Connection for Vsock {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(timeout)
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_write_timeout(timeout)
        }

        fn shutdown_write(&self) -> io::Result<()> {
            self.0.shutdown(Shutdown::Write)
        }
    }

    /// Accepts vsock connections on `port` of any CID of this machine.
    pub fn listen(port: u32) -> io::Result<VsockListener> {
        VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn tunnel_handshake() {
        let parsed = read_tunnel_request(&mut &b"CONNECT api.example.com:443\n"[..]).ok();
        assert_eq!(parsed, Some(("api.example.com".to_string(), 443)));
        assert!(read_tunnel_request(&mut &b"GET / HTTP/1.1\n"[..]).is_err());
        assert!(read_tunnel_request(&mut &b"CONNECT a b:443\n"[..]).is_err());
        assert!(read_tunnel_request(&mut &b"CONNECT host:0\n"[..]).is_err());
        let mut ok = Vec::new();
        assert!(answer_tunnel(&mut ok, Ok(())).is_ok());
        assert_eq!(ok, b"OK\n");
        let mut refused = Vec::new();
        assert!(answer_tunnel(&mut refused, Err("not\nallowed")).is_ok());
        assert_eq!(refused, b"ERR not allowed\n");
    }

    #[test]
    fn hosts() {
        assert!(valid_host("api.example.com"));
        assert!(valid_host("[::1]"));
        assert!(valid_host("10.0.0.1"));
        assert!(!valid_host(""));
        assert!(!valid_host("a b"));
        assert!(!valid_host("a\nb"));
    }

    #[test]
    fn lines_keep_what_follows() {
        let mut reader = LineReader::new(16);
        let mut input: &[u8] = b"one\ntwo\nthree";
        assert_eq!(
            reader.read_line(&mut input).ok().flatten(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            reader.read_line(&mut input).ok().flatten(),
            Some(b"two".to_vec())
        );
        assert!(reader.read_line(&mut input).is_err());
        let mut long: &[u8] = &[b'x'; 64];
        assert!(matches!(
            LineReader::new(16).read_line(&mut long),
            Err(RelayError::TooLong(16))
        ));
    }

    /// The relay connector against a host that answers like `credentials host` and echoes.
    #[test]
    fn connector_through_relay() {
        let listener = TcpListener::bind("127.0.0.1:0").ok();
        let Some(listener) = listener else { return };
        let Ok(address) = listener.local_addr() else {
            return;
        };
        let host = thread::spawn(move || {
            let (mut stream, _) = listener.accept().ok()?;
            let target = read_tunnel_request(&mut stream).ok()?;
            answer_tunnel(&mut stream, Ok(())).ok()?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).ok()?;
            stream.write_all(&buf).ok()?;
            Some(target)
        });
        let connector = RelayConnector::new(move || {
            TcpStream::connect(address).map(|s| Box::new(s) as Box<dyn Socket>)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = connector.connect("example.org", 443, Duration::from_secs(5), deadline);
        assert!(socket.is_ok());
        if let Ok(mut socket) = socket {
            assert!(socket.write_all(b"ping").is_ok());
            let mut buf = [0u8; 4];
            assert!(socket.read_exact(&mut buf).is_ok());
            assert_eq!(&buf, b"ping");
        }
        let target = host.join().ok().flatten();
        assert_eq!(target, Some(("example.org".to_string(), 443)));
    }

    #[test]
    fn refusal_is_reported() {
        let mut duplex = Duplex {
            read: io::Cursor::new(b"ERR not allowed\n".to_vec()),
            written: Vec::new(),
        };
        let result = request_tunnel(&mut duplex, "example.org", 443);
        assert!(matches!(result, Err(RelayError::Refused(r)) if r == "not allowed"));
        assert_eq!(duplex.written, b"CONNECT example.org:443\n");
        assert!(request_tunnel(&mut duplex, "bad host", 443).is_err());
    }

    struct Duplex {
        read: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
