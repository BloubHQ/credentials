//! Reading and writing a protocol connection: whole frames and lines over a [`Stream`], with
//! the bounds of the policy (idle time, duration, bytes both ways).

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::egress::{Arrived, Stream};
use crate::error::TransportKind;
use crate::{Error, Result};

/// Most bytes read from the stream at once.
const READ: usize = 64 * 1024;

/// The bounds of one connection.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Longest time without a byte either way.
    pub idle: Duration,
    /// When the connection must end.
    pub deadline: Instant,
    /// Most bytes both ways together.
    pub max_bytes: u64,
}

impl Bounds {
    /// Bounds from milliseconds and bytes, counted from now.
    pub fn new(idle_ms: u64, duration_ms: u64, max_bytes: u64) -> Self {
        let now = Instant::now();
        Self {
            idle: Duration::from_millis(idle_ms),
            deadline: now
                .checked_add(Duration::from_millis(duration_ms))
                .unwrap_or(now),
            max_bytes,
        }
    }
}

/// A connection with a read buffer, byte counts and bounds.
pub struct Io<'s> {
    stream: &'s mut dyn Stream,
    buf: Zeroizing<Vec<u8>>,
    bounds: Bounds,
    last: Instant,
    started: Instant,
    /// Bytes read from the server.
    pub read: u64,
    /// Bytes written to the server.
    pub written: u64,
}

impl<'s> Io<'s> {
    /// Wraps `stream`.
    pub fn new(stream: &'s mut dyn Stream, bounds: Bounds) -> Self {
        let now = Instant::now();
        Self {
            stream,
            buf: Zeroizing::new(Vec::new()),
            bounds,
            last: now,
            started: now,
            read: 0,
            written: 0,
        }
    }

    /// How long the connection has been open, in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The bound reached, if any: `bytes`, `duration` or `idle`.
    pub fn reached(&self) -> Option<&'static str> {
        if self.read.saturating_add(self.written) > self.bounds.max_bytes {
            Some("bytes")
        } else if Instant::now() >= self.bounds.deadline {
            Some("duration")
        } else if self.last.elapsed() >= self.bounds.idle {
            Some("idle")
        } else {
            None
        }
    }

    fn check(&self) -> Result<()> {
        match self.reached() {
            None => Ok(()),
            Some("bytes") => Err(Error::Budget {
                what: "connection bytes",
            }),
            Some(_) => Err(Error::transport(TransportKind::Timeout, true)),
        }
    }

    /// Writes all of `bytes`.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.written = self.written.saturating_add(bytes.len() as u64);
        self.check()?;
        self.stream.write(bytes)?;
        self.last = Instant::now();
        Ok(())
    }

    /// Reads what arrives within `wait` into the buffer. True when bytes came.
    pub fn poll(&mut self, wait: Duration) -> Result<bool> {
        self.check()?;
        match self.stream.read_some(READ, wait)? {
            Arrived::Bytes(bytes) => {
                let bytes = Zeroizing::new(bytes);
                self.read = self.read.saturating_add(bytes.len() as u64);
                self.buf.extend_from_slice(&bytes);
                self.last = Instant::now();
                self.check()?;
                Ok(!bytes.is_empty())
            }
            Arrived::Nothing => Ok(false),
            Arrived::End => Err(Error::transport(TransportKind::Closed, true)),
        }
    }

    /// The bytes read and not taken yet.
    pub fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Waits until at least `n` bytes are buffered.
    pub fn need(&mut self, n: usize) -> Result<()> {
        while self.buf.len() < n {
            self.poll(Duration::from_millis(50))?;
        }
        Ok(())
    }

    /// Takes the first `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.need(n)?;
        let head = Zeroizing::new(self.buf.get(..n).unwrap_or_default().to_vec());
        let rest = Zeroizing::new(self.buf.get(n..).unwrap_or_default().to_vec());
        self.buf = rest;
        Ok(head)
    }

    /// Takes one line ending in `\n` (with it), of at most `max` bytes.
    pub fn line(&mut self, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut searched = 0;
        loop {
            if let Some(at) = memchr::memchr(b'\n', self.buf.get(searched..).unwrap_or_default()) {
                let end = searched + at + 1;
                // A line that arrived whole is held to the bound as one that did not.
                if end > max {
                    return Err(Error::ResponseInvalid {
                        rule: "line too long",
                    });
                }
                return self.take(end);
            }
            searched = self.buf.len();
            if searched > max {
                return Err(Error::ResponseInvalid {
                    rule: "line too long",
                });
            }
            self.poll(Duration::from_millis(50))?;
        }
    }

    /// Fails when bytes are buffered that the server sent before it should have (after a
    /// `STARTTLS` go-ahead, say).
    pub fn expect_empty(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::ServerUntrusted {
                rule: "the server sent bytes before the node asked for them",
            })
        }
    }

    /// Ends the connection.
    pub fn close(&mut self) {
        let _ = self.stream.close();
    }

    /// The address of the server, when the transport knows it.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.stream.peer_ip()
    }

    /// Opens a data connection to `port` on the same server ([`Stream::open_data`]). Its
    /// bytes count against this connection's bounds through [`Io::tally`].
    pub fn open_data(&mut self, port: u16) -> Result<Box<dyn Stream>> {
        self.check()?;
        self.stream.open_data(port)
    }

    /// Counts bytes moved on a data connection of this one, and checks the bounds.
    pub fn tally(&mut self, read: usize, written: usize) -> Result<()> {
        self.read = self.read.saturating_add(read as u64);
        self.written = self.written.saturating_add(written as u64);
        if read > 0 || written > 0 {
            self.last = Instant::now();
        }
        self.check()
    }

    /// The idle bound of the connection.
    pub fn idle_wait(&self) -> Duration {
        self.bounds.idle
    }
}

/// The values of a sign-in (the user name and the secret) that a server may echo in a reply,
/// replaced before a reply goes back: a server that answers `530 bad password hunter2` or
/// `+OK alice@example.com has 3 messages` hands back the text without them. Values shorter
/// than [`crate::reflection::MIN_NEEDLE`] are not searched, as the reflection search does
/// not search them either.
#[derive(Default)]
pub struct Scrub {
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl Scrub {
    /// Scrubs `values`, each raw and in base64 (a SASL exchange carries them so).
    pub fn new(values: &[&[u8]]) -> Self {
        use base64::Engine as _;
        let mut needles = Vec::new();
        for value in values {
            if value.len() < crate::reflection::MIN_NEEDLE {
                continue;
            }
            needles.push(Zeroizing::new(value.to_vec()));
            needles.push(Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .encode(value)
                    .into_bytes(),
            ));
        }
        // Longest first, so a value inside another is not replaced first.
        needles.sort_by_key(|n| core::cmp::Reverse(n.len()));
        Self { needles }
    }

    /// `text` with every needle replaced by [`crate::reflection::REDACTED`].
    pub fn apply(&self, text: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(text.to_vec());
        for needle in &self.needles {
            let mut next = Zeroizing::new(Vec::with_capacity(out.len()));
            let mut at = 0;
            while let Some(found) = memchr::memmem::find(out.get(at..).unwrap_or_default(), needle)
            {
                next.extend_from_slice(out.get(at..at + found).unwrap_or_default());
                next.extend_from_slice(crate::reflection::REDACTED);
                at += found + needle.len();
            }
            next.extend_from_slice(out.get(at..).unwrap_or_default());
            out = next;
        }
        out
    }
}
