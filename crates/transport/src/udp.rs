//! Datagrams: the request and response exchanges of a `udp` operation (RADIUS, DNS with TSIG,
//! STUN and the like).
//!
//! A [`DatagramConnector`] opens a [`DatagramSocket`] bound to one destination: the kernel
//! (a connected UDP socket) or the host relay (`relay::RelayDatagramConnector`) passes back
//! only datagrams from that address. [`DatagramStream`] runs it under the engine's
//! [`Stream`]: a write sends one datagram, a read returns one datagram. A datagram that is
//! lost is sent again, unchanged, until an answer comes or the read times out, as the
//! request and response protocols over UDP expect of a client.
//!
//! There is no TLS: what is sent and received crosses the network, and in an enclave the host,
//! in clear. The policy analysis refuses a datagram that holds a secret in reversible form.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use engine::egress::{Arrived, Stream};
use engine::error::TransportKind;
use engine::{Error, Result};
use zeroize::Zeroize;

/// Largest datagram sent or received: the largest UDP payload over IPv4.
pub const MAX_DATAGRAM: usize = 65_507;

/// First wait before a datagram is sent again; it doubles after each try.
pub const RETRY_FIRST: Duration = Duration::from_secs(1);
/// Most times one datagram is sent again.
pub const MAX_RETRIES: u32 = 3;
/// Longest wait for the answer to one datagram, its resends included.
pub const READ_WAIT: Duration = Duration::from_secs(10);

/// A socket that exchanges datagrams with one destination.
pub trait DatagramSocket: Send {
    /// Sends one datagram.
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;

    /// Waits at most `wait` for one datagram from the destination; `None` when none came.
    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>>;
}

/// Opens datagram sockets.
pub trait DatagramConnector: Send + Sync {
    /// A socket that exchanges datagrams with `host:port` only.
    fn open(&self, host: &str, port: u16, deadline: Instant)
    -> io::Result<Box<dyn DatagramSocket>>;
}

/// A connected UDP socket.
pub struct Udp(UdpSocket);

impl Udp {
    /// A UDP socket bound to an ephemeral port and connected to `address`: the kernel drops
    /// datagrams from any other address.
    pub fn connect(address: SocketAddr) -> io::Result<Self> {
        let local: SocketAddr = if address.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(address)?;
        Ok(Self(socket))
    }
}

impl DatagramSocket for Udp {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let sent = self.0.send(datagram)?;
        if sent != datagram.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "datagram cut"));
        }
        Ok(())
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        self.0
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
        let mut buffer = vec![0u8; MAX_DATAGRAM + 1];
        match self.0.recv(&mut buffer) {
            Ok(n) if n > MAX_DATAGRAM => {
                buffer.zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "datagram too long",
                ))
            }
            Ok(n) => {
                let datagram = buffer.get(..n).unwrap_or_default().to_vec();
                buffer.zeroize();
                Ok(Some(datagram))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Resolves a host and port to the addresses to try, in order.
pub type Resolver = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;

/// Opens connected UDP sockets to the first address a resolver gives.
pub struct UdpConnector {
    resolve: Box<Resolver>,
}

impl Default for UdpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpConnector {
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

impl DatagramConnector for UdpConnector {
    fn open(&self, host: &str, port: u16, _: Instant) -> io::Result<Box<dyn DatagramSocket>> {
        // A datagram socket has no handshake that tells a live address from a dead one: the
        // first address is the destination.
        let address = (self.resolve)(host, port)?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for the host"))?;
        Ok(Box::new(Udp::connect(address)?))
    }
}

/// The [`Stream`] of a `udp` operation: a write sends one datagram, a read returns the next
/// datagram, sending the last one again while none comes.
pub struct DatagramStream {
    socket: Box<dyn DatagramSocket>,
    last: Vec<u8>,
    io_timeout: Duration,
    deadline: Instant,
}

impl DatagramStream {
    /// A stream over `socket`; each read waits at most `io_timeout`, and none after
    /// `deadline`.
    pub fn new(socket: Box<dyn DatagramSocket>, io_timeout: Duration, deadline: Instant) -> Self {
        Self {
            socket,
            last: Vec::new(),
            io_timeout,
            deadline,
        }
    }

    /// The next datagram within `wait`, sending the last datagram again at growing intervals.
    fn next(&mut self, wait: Duration, max: usize) -> Result<Option<Vec<u8>>> {
        let start = Instant::now();
        let end = start
            .checked_add(wait)
            .map_or(self.deadline, |end| end.min(self.deadline));
        let mut interval = RETRY_FIRST;
        let mut retries = 0;
        loop {
            let now = Instant::now();
            let left = end.saturating_duration_since(now);
            if left.is_zero() {
                return Ok(None);
            }
            let resend = !self.last.is_empty() && retries < MAX_RETRIES;
            let slice = if resend { left.min(interval) } else { left };
            match self.socket.recv(slice) {
                Ok(Some(mut datagram)) => {
                    if datagram.len() > max {
                        datagram.zeroize();
                        return Err(Error::transport(TransportKind::TooLarge, true));
                    }
                    return Ok(Some(datagram));
                }
                Ok(None) if resend && Instant::now() < end => {
                    self.socket
                        .send(&self.last)
                        .map_err(|_| Error::transport(TransportKind::Io, true))?;
                    retries += 1;
                    interval = interval.saturating_mul(2);
                }
                Ok(None) => {}
                Err(_) => return Err(Error::transport(TransportKind::Io, true)),
            }
        }
    }
}

impl Stream for DatagramStream {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
            return Err(Error::transport(TransportKind::TooLarge, true));
        }
        if Instant::now() >= self.deadline {
            return Err(Error::transport(TransportKind::Timeout, true));
        }
        self.socket
            .send(bytes)
            .map_err(|_| Error::transport(TransportKind::Io, true))?;
        self.last.zeroize();
        self.last = bytes.to_vec();
        Ok(())
    }

    /// Reads one datagram; delimiters do not apply to datagrams and must be empty.
    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> Result<Vec<u8>> {
        if !delimiters.is_empty() {
            return Err(Error::transport(TransportKind::Unsupported, true));
        }
        let datagram = self.next(self.io_timeout, max)?;
        // An answer ends the retries of the datagram it answers.
        self.last.zeroize();
        datagram.ok_or(Error::transport(TransportKind::Timeout, true))
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> Result<Arrived> {
        let datagram = self.next(wait.min(self.io_timeout), max)?;
        Ok(match datagram {
            Some(datagram) => {
                self.last.zeroize();
                Arrived::Bytes(datagram)
            }
            None => Arrived::Nothing,
        })
    }
}

impl Drop for DatagramStream {
    fn drop(&mut self) {
        self.last.zeroize();
    }
}
