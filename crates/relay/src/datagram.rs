//! Datagrams over the egress relay (design section 7b).
//!
//! The link is the same as for TCP: the node connects to [`super::EGRESS_PORT`] and sends one
//! line, here `DATAGRAM host:port\n`. The host resolves the name, opens a UDP socket connected
//! to the first address (the kernel then drops datagrams from any other address) and answers
//! `OK\n` or `ERR reason\n`. After `OK`, each datagram crosses the link both ways as a frame:
//! its length on two bytes, big-endian, then its bytes ([`write_datagram`],
//! [`read_datagram`]). A frame of length 0 or longer than [`MAX_DATAGRAM`] ends the link.
//!
//! The host checks the destination against its `--allow` list as for TCP, and stops relaying
//! when the link ends or after [`IDLE`] without a datagram either way. Datagrams are not
//! encrypted: the host reads them, which is why the node refuses to put a secret in reversible
//! form into one.

use std::io::{self, Read, Write};
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use engine::readbuf::ReadBuf;
use transport::Socket;
use transport::udp::{DatagramConnector, DatagramSocket};

use super::{Dial, MAX_TUNNEL_LINE, RelayError, read_short_line, valid_host};

/// Largest datagram carried.
pub const MAX_DATAGRAM: usize = transport::udp::MAX_DATAGRAM;
/// How long the host relays datagrams with none either way.
pub const IDLE: Duration = Duration::from_secs(130);

/// What a link to the egress relay asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Egress {
    /// A TCP connection (`CONNECT`).
    Connect,
    /// Datagrams to one UDP destination (`DATAGRAM`).
    Datagram,
}

/// Asks the egress relay for datagrams to `host:port` over `stream`, and waits for its
/// answer. After `Ok`, `stream` carries frames ([`write_datagram`], [`read_datagram`]).
pub fn request_datagrams<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
) -> Result<(), RelayError> {
    if !valid_host(host) || port == 0 {
        return Err(RelayError::Malformed(format!(
            "{host:?} is not a host name or address"
        )));
    }
    stream.write_all(format!("DATAGRAM {host}:{port}\n").as_bytes())?;
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

/// Reads the first line of an egress link: `CONNECT host:port` or `DATAGRAM host:port`. The
/// host side of [`super::request_tunnel`] and [`request_datagrams`].
pub fn read_egress_request<S: Read>(stream: &mut S) -> Result<(Egress, String, u16), RelayError> {
    let line = read_short_line(stream, MAX_TUNNEL_LINE)?
        .ok_or_else(|| RelayError::Malformed("no request line".into()))?;
    let malformed = || RelayError::Malformed("expected CONNECT or DATAGRAM host:port".into());
    let line = std::str::from_utf8(&line).map_err(|_| malformed())?;
    let (kind, target) = if let Some(target) = line.strip_prefix("CONNECT ") {
        (Egress::Connect, target)
    } else if let Some(target) = line.strip_prefix("DATAGRAM ") {
        (Egress::Datagram, target)
    } else {
        return Err(malformed());
    };
    let (host, port) = target.rsplit_once(':').ok_or_else(malformed)?;
    let port: u16 = port.parse().map_err(|_| malformed())?;
    if !valid_host(host) || port == 0 {
        return Err(malformed());
    }
    Ok((kind, host.to_string(), port))
}

/// Writes one datagram as a frame.
pub fn write_datagram<W: Write>(stream: &mut W, datagram: &[u8]) -> io::Result<()> {
    let len = u16::try_from(datagram.len())
        .ok()
        .filter(|n| *n > 0 && usize::from(*n) <= MAX_DATAGRAM)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "datagram length"))?;
    let mut frame = Vec::with_capacity(datagram.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(datagram);
    stream.write_all(&frame)?;
    stream.flush()
}

/// The length of the frame at the start of `pending`, when its header is there.
fn frame_len(pending: &[u8]) -> io::Result<Option<usize>> {
    let (Some(hi), Some(lo)) = (pending.first(), pending.get(1)) else {
        return Ok(None);
    };
    let len = usize::from(u16::from_be_bytes([*hi, *lo]));
    if len == 0 || len > MAX_DATAGRAM {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame length"));
    }
    Ok(Some(len))
}

/// Takes a whole frame off the front of `pending`, when one is there.
pub fn take_datagram(pending: &mut ReadBuf) -> io::Result<Option<Vec<u8>>> {
    let Some(len) = frame_len(pending.pending())? else {
        return Ok(None);
    };
    if pending.pending().len() < 2 + len {
        return Ok(None);
    }
    pending.skip(2);
    Ok(Some(std::mem::take(&mut *pending.take(len))))
}

/// Reads one frame; `None` at the end of the stream before a frame starts.
pub fn read_datagram<R: Read>(stream: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 2];
    let mut read = 0;
    while read < 2 {
        let into = header.get_mut(read..).unwrap_or_default();
        match stream.read(into) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = frame_len(&header)?.unwrap_or_default();
    let mut datagram = vec![0u8; len];
    stream.read_exact(&mut datagram)?;
    Ok(Some(datagram))
}

/// The node side: datagrams to one destination over a link to the relay.
struct RelayDatagrams {
    link: Box<dyn Socket>,
    pending: ReadBuf,
}

impl DatagramSocket for RelayDatagrams {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        write_datagram(&mut self.link, datagram)
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        let end = Instant::now().checked_add(wait);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(datagram) = take_datagram(&mut self.pending)? {
                return Ok(Some(datagram));
            }
            let left = end.map_or(wait, |end| end.saturating_duration_since(Instant::now()));
            if left.is_zero() {
                return Ok(None);
            }
            self.link.set_timeouts(Some(left))?;
            match self.link.read(&mut chunk) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.pending.push(chunk.get(..n).unwrap_or_default()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
            let held = self.pending.pending();
            if held.len() > MAX_DATAGRAM + 2 && frame_len(held)?.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "frame"));
            }
        }
    }
}

impl Drop for RelayDatagrams {
    fn drop(&mut self) {
        let _ = self.link.shutdown();
    }
}

/// A [`DatagramConnector`] that reaches destinations through the egress relay: each socket
/// is a new link to the relay and a `DATAGRAM` request on it.
pub struct RelayDatagramConnector {
    dial: Box<Dial>,
}

impl RelayDatagramConnector {
    /// A connector that opens its links with `dial`.
    pub fn new(dial: impl Fn() -> io::Result<Box<dyn Socket>> + Send + Sync + 'static) -> Self {
        Self {
            dial: Box::new(dial),
        }
    }
}

impl DatagramConnector for RelayDatagramConnector {
    fn open(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> io::Result<Box<dyn DatagramSocket>> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "connect deadline"));
        }
        let mut link = (self.dial)()?;
        link.set_timeouts(Some(left))?;
        request_datagrams(&mut link, host, port).map_err(|e| match e {
            RelayError::Io(e) => e,
            other => io::Error::new(io::ErrorKind::ConnectionRefused, other.to_string()),
        })?;
        Ok(Box::new(RelayDatagrams {
            link,
            pending: ReadBuf::new(),
        }))
    }
}

/// The UDP socket the host relays a node's datagrams to: bound to an ephemeral port and
/// connected to the first address of `host:port`.
pub fn connect_udp(host: &str, port: u16) -> io::Result<UdpSocket> {
    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for the host"))?;
    let local: std::net::SocketAddr = if address.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let udp = UdpSocket::bind(local)?;
    udp.connect(address)?;
    Ok(udp)
}

/// The host side, after `OK`: frames from the link go out on `udp`, datagrams that come back
/// on it go into the link, until the link ends, a frame is malformed, or `idle` passes with
/// no datagram either way. `link` and `link2` are two handles of the same link.
pub fn serve_datagrams(
    mut link: Box<dyn Socket>,
    mut link2: Box<dyn Socket>,
    udp: UdpSocket,
    idle: Duration,
) -> io::Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let last = Arc::new(std::sync::Mutex::new(Instant::now()));
    let udp_in = udp.try_clone()?;
    let back = {
        let done = Arc::clone(&done);
        let last = Arc::clone(&last);
        thread::Builder::new()
            .name("datagrams".into())
            .spawn(move || {
                let tick = Duration::from_millis(250);
                let _ = udp_in.set_read_timeout(Some(tick));
                let mut buffer = vec![0u8; MAX_DATAGRAM + 1];
                while !done.load(Ordering::SeqCst) {
                    match udp_in.recv(&mut buffer) {
                        Ok(n) if n == 0 || n > MAX_DATAGRAM => {}
                        Ok(n) => {
                            let datagram = buffer.get(..n).unwrap_or_default();
                            if write_datagram(&mut link2, datagram).is_err() {
                                break;
                            }
                            if let Ok(mut at) = last.lock() {
                                *at = Instant::now();
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            let quiet = last.lock().map_or(Duration::ZERO, |at| at.elapsed());
                            if quiet >= idle {
                                break;
                            }
                        }
                        // ICMP unreachable and the like: the destination may answer later.
                        Err(_) => {}
                    }
                }
                done.store(true, Ordering::SeqCst);
                let _ = link2.shutdown();
            })?
    };
    let tick = Duration::from_millis(250);
    let mut pending = ReadBuf::new();
    let mut chunk = [0u8; 4096];
    let result = loop {
        if done.load(Ordering::SeqCst) {
            break Ok(());
        }
        match take_datagram(&mut pending) {
            Ok(Some(datagram)) => {
                // A datagram the network drops is the node's to send again.
                let _ = udp.send(&datagram);
                if let Ok(mut at) = last.lock() {
                    *at = Instant::now();
                }
                continue;
            }
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        let _ = link.set_timeouts(Some(tick));
        match link.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => pending.push(chunk.get(..n).unwrap_or_default()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    done.store(true, Ordering::SeqCst);
    let _ = link.shutdown();
    let _ = back.join();
    result
}
