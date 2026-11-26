//! TLS transport for the credentials engine.
//!
//! [`TlsTransport`] implements [`engine::egress::Transport`] with rustls (ring provider, TLS 1.2
//! and 1.3) and the Mozilla root store by default. It:
//!
//! - verifies the certificate of the server for the host of the destination, and nothing else
//!   (the node operator controls DNS; the certificate is what binds the connection to the
//!   destination the owner signed);
//! - presents the client certificate of the operation, when there is one, for that connection
//!   only;
//! - stops at the connect, read and total deadlines and at the size the engine accepts;
//! - grows its buffers by copying into a new one and erasing the old one, so no unerased copy
//!   of a response is freed.
//!
//! rustls keeps TLS records in buffers of its own that are not erased when freed. Run a node
//! with a zeroizing global allocator to cover them (see the README of the repository).
//!
//! TLS runs over any byte stream a [`Connector`] opens: TCP by default ([`TcpConnector`]),
//! or a relay such as the vsock link of a Nitro Enclave to its parent instance. TLS ends in
//! this process either way, so whatever carries the bytes sees only ciphertext.
//!
//! HTTPS requests offer HTTP/2 and HTTP/1.1 by ALPN (`h2` first), or only the version the
//! policy pins; a server that agrees on another is refused before anything is sent
//! ([`TransportKind::Downgrade`]). HTTP/2 is the synchronous client of [`h2`] with the HPACK
//! of [`hpack`]: it reads the request the engine built in HTTP/1.1 form and hands the
//! response back in that form, checked, so one parser of the engine reads both versions.

pub mod h2;
pub mod hpack;
pub mod udp;

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine::egress::{Arrived, ClientIdentity, Stream, Transport, Version, Versions};
use engine::error::TransportKind;
use engine::policy::Destination;
use engine::{Error, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::{Zeroize, Zeroizing};

/// Resolves a host and port to the addresses to try, in order.
pub type Resolver = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;

const CHUNK: usize = 16 * 1024;

/// A connected byte stream that TLS runs over.
pub trait Socket: Read + Write + Send {
    /// Sets the timeout of each read and each write (`None`: block).
    fn set_timeouts(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Closes both directions.
    fn shutdown(&self) -> io::Result<()>;
}

impl Socket for TcpStream {
    fn set_timeouts(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }

    fn shutdown(&self) -> io::Result<()> {
        TcpStream::shutdown(self, Shutdown::Both)
    }
}

/// Opens the byte streams TLS runs over.
pub trait Connector: Send + Sync {
    /// Connects to `host:port`. Each attempt (one address, say) takes at most `attempt`, and
    /// no attempt starts after `deadline`.
    fn connect(
        &self,
        host: &str,
        port: u16,
        attempt: Duration,
        deadline: Instant,
    ) -> io::Result<Box<dyn Socket>>;
}

/// Connects over TCP to the addresses a resolver gives, in order.
pub struct TcpConnector {
    resolve: Box<Resolver>,
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnector {
    /// A connector that uses the system resolver.
    pub fn new() -> Self {
        Self::with_resolver(|host, port| Ok((host, port).to_socket_addrs()?.collect()))
    }

    /// A connector that uses `resolve`.
    pub fn with_resolver(
        resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            resolve: Box::new(resolve),
        }
    }
}

impl Connector for TcpConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        attempt: Duration,
        deadline: Instant,
    ) -> io::Result<Box<dyn Socket>> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address for the host");
        for address in (self.resolve)(host, port)? {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect deadline"));
            }
            match TcpStream::connect_timeout(&address, attempt.min(left)) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(Box::new(stream));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

fn fault(kind: TransportKind, sent: bool) -> Error {
    Error::transport(kind, sent)
}

/// The kind of an I/O error once bytes may have been written.
fn io_kind(error: &io::Error) -> TransportKind {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TransportKind::Timeout,
        io::ErrorKind::InvalidData => TransportKind::Tls,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => TransportKind::Closed,
        _ => TransportKind::Io,
    }
}

/// Appends `bytes` to `out`, growing it by copying into a larger buffer and erasing the old
/// one (a plain `Vec` would free its old buffer unerased).
fn push_erasing(out: &mut Vec<u8>, bytes: &[u8], limit: usize) {
    let need = out.len().saturating_add(bytes.len());
    if need > out.capacity() {
        let capacity = need
            .max(out.capacity().saturating_mul(2))
            .min(limit.max(need));
        let mut grown = Vec::with_capacity(capacity);
        grown.extend_from_slice(out);
        out.zeroize();
        *out = grown;
    }
    out.extend_from_slice(bytes);
}

/// The ALPN names of HTTP/2 and HTTP/1.1.
const H2: &[u8] = b"h2";
const HTTP1: &[u8] = b"http/1.1";

fn alpn_of(versions: Versions) -> &'static [&'static [u8]] {
    match versions {
        Versions::Any => &[H2, HTTP1],
        Versions::Http1 => &[HTTP1],
        Versions::Http2 => &[H2],
    }
}

type Tls = StreamOwned<ClientConnection, Box<dyn Socket>>;

impl h2::Io for Tls {
    fn set_wait(&mut self, wait: Duration) -> io::Result<()> {
        self.sock.set_timeouts(Some(wait))
    }
}

fn h2_fault(error: h2::H2Error) -> Error {
    let kind = match error {
        h2::H2Error::Protocol(_) | h2::H2Error::Hpack(_) => TransportKind::Protocol,
        h2::H2Error::Closed | h2::H2Error::Reset => TransportKind::Closed,
        h2::H2Error::Io(_) => TransportKind::Io,
        h2::H2Error::Timeout => TransportKind::Timeout,
        h2::H2Error::TooLarge => TransportKind::TooLarge,
    };
    fault(kind, true)
}

/// Sends requests and opens connections over TLS.
pub struct TlsTransport {
    roots: Arc<RootCertStore>,
    connect_timeout: Duration,
    io_timeout: Duration,
    total_timeout: Duration,
    stream_timeout: Duration,
    connector: Box<dyn Connector>,
    datagrams: Box<dyn udp::DatagramConnector>,
}

impl Default for TlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsTransport {
    /// A transport that trusts the Mozilla root store, with deadlines of 10 s to connect, 30 s
    /// per read or write, 120 s per request or TLS stream, and one hour for a response read
    /// as it arrives or a WebSocket (the engine ends those sooner, by the limits of the
    /// policy).
    pub fn new() -> Self {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::with_roots(roots)
    }

    /// A transport that trusts only `roots`.
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(120),
            stream_timeout: Duration::from_secs(3600),
            connector: Box::new(TcpConnector::new()),
            datagrams: Box::new(udp::UdpConnector::new()),
        }
    }

    /// Sets the deadlines: to connect, per read or write, and for a whole request or stream.
    pub fn timeouts(mut self, connect: Duration, io: Duration, total: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self.total_timeout = total;
        self
    }

    /// Sets the deadline of a response read as it arrives and of a WebSocket.
    pub fn stream_timeout(mut self, total: Duration) -> Self {
        self.stream_timeout = total;
        self
    }

    /// Connects over TCP with this resolver (the system resolver by default).
    pub fn resolver(
        self,
        resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.connector(TcpConnector::with_resolver(resolve))
    }

    /// Replaces what opens the datagram sockets of `udp` operations ([`udp::UdpConnector`] by
    /// default; in an enclave, the relay's).
    pub fn datagrams(mut self, connector: impl udp::DatagramConnector + 'static) -> Self {
        self.datagrams = Box::new(connector);
        self
    }

    /// Replaces what opens the byte streams TLS runs over ([`TcpConnector`] by default).
    pub fn connector(mut self, connector: impl Connector + 'static) -> Self {
        self.connector = Box::new(connector);
        self
    }

    fn config(
        &self,
        identity: Option<&ClientIdentity>,
        alpn: &[&[u8]],
    ) -> Result<Arc<ClientConfig>> {
        let tls = |_| fault(TransportKind::Tls, false);
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(tls)?
                .with_root_certificates(self.roots.clone());
        let mut config = match identity {
            None => builder.with_no_client_auth(),
            Some(identity) => {
                let chain = CertificateDer::pem_slice_iter(identity.cert())
                    .collect::<core::result::Result<Vec<_>, _>>()
                    .map_err(|_| fault(TransportKind::Tls, false))?;
                let key = PrivateKeyDer::from_pem_slice(identity.key())
                    .map_err(|_| fault(TransportKind::Tls, false))?;
                if chain.is_empty() {
                    return Err(fault(TransportKind::Tls, false));
                }
                builder.with_client_auth_cert(chain, key).map_err(tls)?
            }
        };
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(config))
    }

    fn connect(
        &self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        alpn: &[&[u8]],
        deadline: Instant,
    ) -> Result<Tls> {
        // The name is checked before anything is opened.
        ServerName::try_from(destination.host.clone())
            .map_err(|_| fault(TransportKind::Connect, false))?;
        let tcp = self.tcp(destination, deadline)?;
        self.handshake(tcp, destination, identity, alpn, deadline)
    }

    /// Opens the byte stream to `destination`.
    fn tcp(&self, destination: &Destination, deadline: Instant) -> Result<Box<dyn Socket>> {
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(fault(TransportKind::Timeout, false));
        }
        self.connector
            .connect(
                &destination.host,
                destination.port,
                self.connect_timeout,
                deadline,
            )
            .map_err(|_| {
                if Instant::now() >= deadline {
                    fault(TransportKind::Timeout, false)
                } else {
                    fault(TransportKind::Connect, false)
                }
            })
    }

    /// Makes TLS to `destination` over `tcp`.
    fn handshake(
        &self,
        mut tcp: Box<dyn Socket>,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        alpn: &[&[u8]],
        deadline: Instant,
    ) -> Result<Tls> {
        let name = ServerName::try_from(destination.host.clone())
            .map_err(|_| fault(TransportKind::Connect, false))?;
        let config = self.config(identity, alpn)?;
        let mut tls =
            ClientConnection::new(config, name).map_err(|_| fault(TransportKind::Tls, false))?;
        while tls.is_handshaking() {
            set_timeouts(tcp.as_ref(), self.io_timeout, deadline, false)?;
            tls.complete_io(&mut tcp).map_err(|e| match io_kind(&e) {
                TransportKind::Timeout => fault(TransportKind::Timeout, false),
                TransportKind::Io | TransportKind::Closed if !tls.is_handshaking() => {
                    fault(TransportKind::Io, false)
                }
                _ => fault(TransportKind::Tls, false),
            })?;
        }
        Ok(StreamOwned::new(tls, tcp))
    }

    /// Connects offering the versions `versions` allows, and says which one the server took.
    /// A server that takes none of them is refused before anything is sent.
    fn connect_http(
        &self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        versions: Versions,
        deadline: Instant,
    ) -> Result<(Tls, Version)> {
        let mut stream = self.connect(destination, identity, alpn_of(versions), deadline)?;
        let version = match stream.conn.alpn_protocol() {
            Some(H2) => Version::Http2,
            // A server that ignores ALPN speaks HTTP/1.1.
            Some(_) | None => Version::Http1,
        };
        if !versions.allows(version) {
            close_tls(&mut stream);
            return Err(fault(TransportKind::Downgrade, false));
        }
        Ok((stream, version))
    }
}

/// Sets the read and write timeouts to what is left before `deadline`, at most `io`.
fn set_timeouts(socket: &dyn Socket, io: Duration, deadline: Instant, sent: bool) -> Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(fault(TransportKind::Timeout, sent));
    }
    socket
        .set_timeouts(Some(io.min(left)))
        .map_err(|_| fault(TransportKind::Io, sent))
}

/// Writes `wire` and reads to the end of the connection, at most `max` bytes.
fn http1_exchange(
    stream: &mut Tls,
    wire: &[u8],
    max: usize,
    io_timeout: Duration,
    deadline: Instant,
) -> Result<Vec<u8>> {
    set_timeouts(stream.sock.as_ref(), io_timeout, deadline, true)?;
    stream
        .write_all(wire)
        .and_then(|()| stream.flush())
        .map_err(|e| fault(io_kind(&e), true))?;
    let mut out = Vec::with_capacity(CHUNK);
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    loop {
        set_timeouts(stream.sock.as_ref(), io_timeout, deadline, true)?;
        let n = match stream.read(chunk.as_mut_slice()) {
            Ok(0) => break,
            Ok(n) => n,
            // A server that closes without close_notify: the engine checks the framing
            // of what came.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                out.zeroize();
                return Err(fault(io_kind(&e), true));
            }
        };
        if out.len().saturating_add(n) > max {
            out.zeroize();
            return Err(fault(TransportKind::TooLarge, true));
        }
        push_erasing(&mut out, chunk.get(..n).unwrap_or_default(), max);
    }
    Ok(out)
}

impl Transport for TlsTransport {
    fn send(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max_response: usize,
    ) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.total_timeout;
        let mut stream = self.connect(destination, identity, &[HTTP1], deadline)?;
        http1_exchange(&mut stream, wire, max_response, self.io_timeout, deadline)
    }

    fn exchange(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max_response: usize,
        versions: Versions,
    ) -> Result<(Vec<u8>, Version)> {
        let deadline = Instant::now() + self.total_timeout;
        let (mut stream, version) = self.connect_http(destination, identity, versions, deadline)?;
        let response = match version {
            Version::Http1 => {
                http1_exchange(&mut stream, wire, max_response, self.io_timeout, deadline)?
            }
            Version::Http2 => {
                let mut conn =
                    h2::Conn::start(stream, wire, self.io_timeout, deadline).map_err(h2_fault)?;
                let all = conn.finish_all(max_response).map_err(h2_fault);
                close_tls(conn.io_mut());
                all?
            }
        };
        Ok((response, version))
    }

    fn exchange_streamed(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        versions: Versions,
    ) -> Result<(Box<dyn Stream + '_>, Version)> {
        let deadline = Instant::now() + self.stream_timeout;
        let (mut stream, version) = self.connect_http(destination, identity, versions, deadline)?;
        let opened: Box<dyn Stream> = match version {
            Version::Http1 => {
                set_timeouts(stream.sock.as_ref(), self.io_timeout, deadline, true)?;
                stream
                    .write_all(wire)
                    .and_then(|()| stream.flush())
                    .map_err(|e| fault(io_kind(&e), true))?;
                Box::new(TlsStream {
                    inner: stream,
                    pending: Vec::new(),
                    io_timeout: self.io_timeout,
                    deadline,
                })
            }
            Version::Http2 => Box::new(H2Stream {
                conn: h2::Conn::start(stream, wire, self.io_timeout, deadline).map_err(h2_fault)?,
                pending: Vec::new(),
                io_timeout: self.io_timeout,
            }),
        };
        Ok((opened, version))
    }

    fn open(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
    ) -> Result<Box<dyn Stream + '_>> {
        let deadline = Instant::now() + self.total_timeout;
        let stream = self.connect(destination, identity, &[], deadline)?;
        Ok(Box::new(TlsStream {
            inner: stream,
            pending: Vec::new(),
            io_timeout: self.io_timeout,
            deadline,
        }))
    }

    fn open_plain(&mut self, destination: &Destination) -> Result<Box<dyn Stream + '_>> {
        let deadline = Instant::now() + self.total_timeout;
        Ok(Box::new(PlainStream {
            sock: self.tcp(destination, deadline)?,
            io_timeout: self.io_timeout,
            deadline,
        }))
    }

    fn open_starttls(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        prelude: &mut dyn FnMut(&mut dyn Stream) -> Result<()>,
    ) -> Result<Box<dyn Stream + '_>> {
        let deadline = Instant::now() + self.total_timeout;
        let mut plain = PlainStream {
            sock: self.tcp(destination, deadline)?,
            io_timeout: self.io_timeout,
            deadline,
        };
        prelude(&mut plain)?;
        // The prelude reads with `read_some`, which hands over every byte it takes from the
        // socket; whatever the server sent after its go-ahead is still in the socket and goes
        // into the handshake, where it fails as a TLS record would.
        let stream = self.handshake(plain.sock, destination, identity, &[], deadline)?;
        Ok(Box::new(TlsStream {
            inner: stream,
            pending: Vec::new(),
            io_timeout: self.io_timeout,
            deadline,
        }))
    }

    fn open_datagrams(&mut self, destination: &Destination) -> Result<Box<dyn Stream + '_>> {
        let deadline = Instant::now() + self.total_timeout;
        let socket = self
            .datagrams
            .open(&destination.host, destination.port, deadline)
            .map_err(|e| fault(io_kind(&e), false))?;
        Ok(Box::new(udp::DatagramStream::new(
            socket,
            self.io_timeout.min(udp::READ_WAIT),
            deadline,
        )))
    }
}

/// A TCP connection with no TLS: an SSH connection (which encrypts itself), or the plain
/// prelude of a `STARTTLS` connection. It keeps no buffer: what it reads goes straight to the
/// engine.
struct PlainStream {
    sock: Box<dyn Socket>,
    io_timeout: Duration,
    deadline: Instant,
}

impl Stream for PlainStream {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        set_timeouts(self.sock.as_ref(), self.io_timeout, self.deadline, true)?;
        self.sock
            .write_all(bytes)
            .and_then(|()| self.sock.flush())
            .map_err(|e| fault(io_kind(&e), true))
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> Result<Vec<u8>> {
        // Protocol clients read with `read_some` and frame the bytes themselves.
        Err(fault(TransportKind::Unsupported, true))
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> Result<Arrived> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(fault(TransportKind::Timeout, true));
        }
        let wait = wait
            .min(self.io_timeout)
            .min(left)
            .max(Duration::from_millis(1));
        self.sock
            .set_timeouts(Some(wait))
            .map_err(|_| fault(TransportKind::Io, true))?;
        let mut chunk = Zeroizing::new(vec![0u8; max.clamp(1, CHUNK)]);
        match self.sock.read(chunk.as_mut_slice()) {
            Ok(0) => Ok(Arrived::End),
            Ok(n) => Ok(Arrived::Bytes(chunk.get(..n).unwrap_or_default().to_vec())),
            Err(e) => match io_kind(&e) {
                TransportKind::Timeout => Ok(Arrived::Nothing),
                kind => Err(fault(kind, true)),
            },
        }
    }

    fn close(&mut self) -> Result<()> {
        let _ = self.sock.shutdown();
        Ok(())
    }
}

fn close_tls(stream: &mut Tls) {
    stream.conn.send_close_notify();
    let _ = stream.flush();
    let _ = stream.sock.shutdown();
}

/// The end of the first delimiter found in `bytes` at or after `from`.
fn first_end(bytes: &[u8], delimiters: &[&[u8]], from: usize) -> Option<usize> {
    delimiters
        .iter()
        .filter(|d| !d.is_empty())
        .filter_map(|d| {
            let start = from.saturating_sub(d.len().saturating_sub(1));
            bytes
                .get(start..)?
                .windows(d.len())
                .position(|w| w == *d)
                .map(|i| start + i + d.len())
        })
        .min()
}

/// Takes the bytes up to the end of the first delimiter in `pending`, leaving the rest.
fn take_until(pending: &mut Vec<u8>, delimiters: &[&[u8]], from: usize) -> Option<Vec<u8>> {
    let end = first_end(pending, delimiters, from)?;
    // Both parts are copied to buffers of their exact size and the old buffer is erased, so
    // no copy of the bytes after the delimiter stays in spare capacity.
    let read = pending.get(..end).unwrap_or_default().to_vec();
    let rest = pending.get(end..).unwrap_or_default().to_vec();
    pending.zeroize();
    *pending = rest;
    Some(read)
}

/// Takes at most `max` bytes from the front of `pending`.
fn take_front(pending: &mut Vec<u8>, max: usize) -> Vec<u8> {
    let take = pending.len().min(max.max(1));
    let read = pending.get(..take).unwrap_or_default().to_vec();
    let rest = pending.get(take..).unwrap_or_default().to_vec();
    pending.zeroize();
    *pending = rest;
    read
}

/// The response of an HTTP/2 request, read as it arrives in HTTP/1.1 form.
struct H2Stream {
    conn: h2::Conn<Tls>,
    pending: Vec<u8>,
    io_timeout: Duration,
}

impl Stream for H2Stream {
    fn write(&mut self, _: &[u8]) -> Result<()> {
        // The request went with the exchange; this stream carries nothing more.
        Err(fault(TransportKind::Unsupported, true))
    }

    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> Result<Vec<u8>> {
        let mut searched = 0;
        loop {
            if let Some(read) = take_until(&mut self.pending, delimiters, searched) {
                return Ok(read);
            }
            searched = self.pending.len();
            if self.pending.len() > max {
                return Err(fault(TransportKind::TooLarge, true));
            }
            match self.conn.poll(CHUNK, self.io_timeout).map_err(h2_fault)? {
                None => return Err(fault(TransportKind::Closed, true)),
                Some(bytes) if bytes.is_empty() => {
                    return Err(fault(TransportKind::Timeout, true));
                }
                Some(bytes) => {
                    let limit = max.saturating_add(CHUNK);
                    push_erasing(&mut self.pending, &bytes, limit);
                }
            }
        }
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> Result<Arrived> {
        if !self.pending.is_empty() {
            return Ok(Arrived::Bytes(take_front(&mut self.pending, max)));
        }
        Ok(match self.conn.poll(max, wait).map_err(h2_fault)? {
            None => Arrived::End,
            Some(bytes) if bytes.is_empty() => Arrived::Nothing,
            Some(bytes) => Arrived::Bytes(bytes),
        })
    }

    fn close(&mut self) -> Result<()> {
        close_tls(self.conn.io_mut());
        Ok(())
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

/// An open TLS connection of a stream operation, or of an HTTP/1.1 response read as it
/// arrives.
struct TlsStream {
    inner: Tls,
    pending: Vec<u8>,
    io_timeout: Duration,
    deadline: Instant,
}

impl Stream for TlsStream {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        set_timeouts(
            self.inner.sock.as_ref(),
            self.io_timeout,
            self.deadline,
            true,
        )?;
        self.inner
            .write_all(bytes)
            .and_then(|()| self.inner.flush())
            .map_err(|e| fault(io_kind(&e), true))
    }

    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> Result<Vec<u8>> {
        let mut searched = 0;
        let mut chunk = Zeroizing::new([0u8; CHUNK]);
        loop {
            if let Some(read) = take_until(&mut self.pending, delimiters, searched) {
                return Ok(read);
            }
            searched = self.pending.len();
            if self.pending.len() > max {
                return Err(fault(TransportKind::TooLarge, true));
            }
            set_timeouts(
                self.inner.sock.as_ref(),
                self.io_timeout,
                self.deadline,
                true,
            )?;
            let n = match self.inner.read(chunk.as_mut_slice()) {
                Ok(0) => return Err(fault(TransportKind::Closed, true)),
                Ok(n) => n,
                Err(e) => return Err(fault(io_kind(&e), true)),
            };
            let limit = max.saturating_add(CHUNK);
            push_erasing(&mut self.pending, chunk.get(..n).unwrap_or_default(), limit);
        }
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> Result<Arrived> {
        if !self.pending.is_empty() {
            return Ok(Arrived::Bytes(take_front(&mut self.pending, max)));
        }
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(fault(TransportKind::Timeout, true));
        }
        let wait = wait
            .min(self.io_timeout)
            .min(left)
            .max(Duration::from_millis(1));
        self.inner
            .sock
            .set_timeouts(Some(wait))
            .map_err(|_| fault(TransportKind::Io, true))?;
        let mut chunk = Zeroizing::new(vec![0u8; max.clamp(1, CHUNK)]);
        match self.inner.read(chunk.as_mut_slice()) {
            Ok(0) => Ok(Arrived::End),
            Ok(n) => Ok(Arrived::Bytes(chunk.get(..n).unwrap_or_default().to_vec())),
            // A server that closes without close_notify ends what it sent; the engine checks
            // the framing.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(Arrived::End),
            Err(e) => match io_kind(&e) {
                TransportKind::Timeout => Ok(Arrived::Nothing),
                kind => Err(fault(kind, true)),
            },
        }
    }

    fn close(&mut self) -> Result<()> {
        close_tls(&mut self.inner);
        Ok(())
    }

    fn tls_exporter(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // TLS 1.3 only: over TLS 1.2 an exporter binds the connection only with the extended
        // master secret (RFC 9266 section 3), which rustls does not report.
        if self.inner.conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(fault(TransportKind::Unsupported, true));
        }
        let mut out = Zeroizing::new(vec![0u8; length]);
        self.inner
            .conn
            .export_keying_material(out.as_mut_slice(), label, Some(context))
            .map_err(|_| fault(TransportKind::Tls, true))?;
        Ok(out)
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}
