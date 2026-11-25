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

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine::egress::{ClientIdentity, Stream, Transport};
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

/// Sends requests and opens connections over TLS.
pub struct TlsTransport {
    roots: Arc<RootCertStore>,
    connect_timeout: Duration,
    io_timeout: Duration,
    total_timeout: Duration,
    connector: Box<dyn Connector>,
}

impl Default for TlsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsTransport {
    /// A transport that trusts the Mozilla root store, with deadlines of 10 s to connect, 30 s
    /// per read or write and 120 s per request or stream.
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
            connector: Box::new(TcpConnector::new()),
        }
    }

    /// Sets the deadlines: to connect, per read or write, and for a whole request or stream.
    pub fn timeouts(mut self, connect: Duration, io: Duration, total: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self.total_timeout = total;
        self
    }

    /// Connects over TCP with this resolver (the system resolver by default).
    pub fn resolver(
        self,
        resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.connector(TcpConnector::with_resolver(resolve))
    }

    /// Replaces what opens the byte streams TLS runs over ([`TcpConnector`] by default).
    pub fn connector(mut self, connector: impl Connector + 'static) -> Self {
        self.connector = Box::new(connector);
        self
    }

    fn config(&self, identity: Option<&ClientIdentity>, alpn: bool) -> Result<Arc<ClientConfig>> {
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
        if alpn {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Ok(Arc::new(config))
    }

    fn connect(
        &self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        alpn: bool,
        deadline: Instant,
    ) -> Result<StreamOwned<ClientConnection, Box<dyn Socket>>> {
        let name = ServerName::try_from(destination.host.clone())
            .map_err(|_| fault(TransportKind::Connect, false))?;
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(fault(TransportKind::Timeout, false));
        }
        let mut tcp = self
            .connector
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
            })?;
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

impl Transport for TlsTransport {
    fn send(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max_response: usize,
    ) -> Result<Vec<u8>> {
        let deadline = Instant::now() + self.total_timeout;
        let mut stream = self.connect(destination, identity, true, deadline)?;
        set_timeouts(stream.sock.as_ref(), self.io_timeout, deadline, true)?;
        stream
            .write_all(wire)
            .and_then(|()| stream.flush())
            .map_err(|e| fault(io_kind(&e), true))?;
        let mut out = Vec::with_capacity(CHUNK);
        let mut chunk = Zeroizing::new([0u8; CHUNK]);
        loop {
            set_timeouts(stream.sock.as_ref(), self.io_timeout, deadline, true)?;
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
            if out.len().saturating_add(n) > max_response {
                out.zeroize();
                return Err(fault(TransportKind::TooLarge, true));
            }
            push_erasing(&mut out, chunk.get(..n).unwrap_or_default(), max_response);
        }
        Ok(out)
    }

    fn open(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
    ) -> Result<Box<dyn Stream + '_>> {
        let deadline = Instant::now() + self.total_timeout;
        let stream = self.connect(destination, identity, false, deadline)?;
        Ok(Box::new(TlsStream {
            inner: stream,
            pending: Vec::new(),
            io_timeout: self.io_timeout,
            deadline,
        }))
    }
}

/// An open TLS connection of a stream operation.
struct TlsStream {
    inner: StreamOwned<ClientConnection, Box<dyn Socket>>,
    pending: Vec<u8>,
    io_timeout: Duration,
    deadline: Instant,
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
            if let Some(end) = first_end(&self.pending, delimiters, searched) {
                // Both parts are copied to buffers of their exact size and the old buffer is
                // erased, so no copy of the bytes after the delimiter stays in spare capacity.
                let read = self.pending.get(..end).unwrap_or_default().to_vec();
                let rest = self.pending.get(end..).unwrap_or_default().to_vec();
                self.pending.zeroize();
                self.pending = rest;
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

    fn close(&mut self) -> Result<()> {
        self.inner.conn.send_close_notify();
        let _ = self.inner.flush();
        let _ = self.inner.sock.shutdown();
        Ok(())
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}
