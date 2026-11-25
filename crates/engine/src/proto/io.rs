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
                return self.take(searched + at + 1);
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
}
