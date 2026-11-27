//! Reading and writing a protocol connection: whole frames and lines over a [`Stream`], with
//! the bounds of the policy (idle time, duration, bytes both ways).

use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::egress::{Arrived, Stream};
use crate::error::TransportKind;
use crate::{Error, Result};

/// Most bytes read from the stream at once.
const READ: usize = 64 * 1024;
/// The smallest read buffer allocated, so that small reads do not move it often.
const MIN_BUFFER: usize = 16 * 1024;

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
    /// The bytes read; those before `pos` were taken. Taken bytes are wiped when the buffer
    /// is compacted or emptied, and all of it when it is dropped.
    buf: Zeroizing<Vec<u8>>,
    /// Where the bytes not taken yet start in `buf`.
    pos: usize,
    bounds: Bounds,
    last: Instant,
    started: Instant,
    /// Bytes read from the server.
    pub read: u64,
    /// Bytes written to the server.
    pub written: u64,
    /// Bytes moved inside the read buffer by takes (tests measure the cost of parsing).
    #[cfg(test)]
    pub(crate) copied: u64,
}

impl<'s> Io<'s> {
    /// Wraps `stream`.
    pub fn new(stream: &'s mut dyn Stream, bounds: Bounds) -> Self {
        let now = Instant::now();
        Self {
            stream,
            buf: Zeroizing::new(Vec::new()),
            pos: 0,
            bounds,
            last: now,
            started: now,
            read: 0,
            written: 0,
            #[cfg(test)]
            copied: 0,
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
                self.compact();
                self.grow(bytes.len());
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
        self.buf.get(self.pos..).unwrap_or_default()
    }

    /// Moves the bytes not taken yet to the start of the buffer and wipes the taken ones, so
    /// the buffer does not grow with what was taken. It runs before bytes are appended, and
    /// only after a take, so each byte read is moved at most once per take.
    fn compact(&mut self) {
        let len = self.buf.len();
        if self.pos == 0 || self.pos > len {
            return;
        }
        let rest = len - self.pos;
        self.buf.copy_within(self.pos.., 0);
        if let Some(stale) = self.buf.get_mut(rest..) {
            stale.zeroize();
        }
        self.buf.truncate(rest);
        #[cfg(test)]
        {
            self.copied = self.copied.saturating_add(rest as u64);
        }
        self.pos = 0;
    }

    /// Makes room for `more` bytes without letting `Vec` reallocate in place of us: a
    /// reallocation would free the old allocation unwiped. The buffer moves to a new one at
    /// least twice as large (so growing stays linear), and the old one is wiped as it drops.
    fn grow(&mut self, more: usize) {
        let need = self.buf.len().saturating_add(more);
        if need <= self.buf.capacity() {
            return;
        }
        let capacity = need
            .max(self.buf.capacity().saturating_mul(2))
            .max(MIN_BUFFER);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(&self.buf);
        #[cfg(test)]
        {
            self.copied = self.copied.saturating_add(self.buf.len() as u64);
        }
        self.buf = grown;
    }

    /// Waits until at least `n` bytes are buffered. The bounds are checked first, also when
    /// the bytes are buffered already, so a server that sent many small frames at once is
    /// held to the deadline while they are read.
    pub fn need(&mut self, n: usize) -> Result<()> {
        self.check()?;
        while self.buffered().len() < n {
            self.poll(Duration::from_millis(50))?;
        }
        Ok(())
    }

    /// Takes the first `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<Zeroizing<Vec<u8>>> {
        self.need(n)?;
        let head = Zeroizing::new(self.buffered().get(..n).unwrap_or_default().to_vec());
        self.pos = self.pos.saturating_add(head.len());
        #[cfg(test)]
        {
            self.copied = self.copied.saturating_add(head.len() as u64);
        }
        if self.pos >= self.buf.len() {
            // All taken: wipe what it holds (its spare capacity holds nothing: `compact`
            // wipes what it leaves behind, and `grow` never lets an allocation go unwiped) and start again at the front.
            self.buf.as_mut_slice().zeroize();
            self.buf.clear();
            self.pos = 0;
        }
        Ok(head)
    }

    /// Takes one line ending in `\n` (with it), of at most `max` bytes.
    pub fn line(&mut self, max: usize) -> Result<Zeroizing<Vec<u8>>> {
        let mut searched = 0;
        loop {
            if let Some(at) =
                memchr::memchr(b'\n', self.buffered().get(searched..).unwrap_or_default())
            {
                let end = searched + at + 1;
                // A line that arrived whole is held to the bound as one that did not.
                if end > max {
                    return Err(Error::ResponseInvalid {
                        rule: "line too long",
                    });
                }
                return self.take(end);
            }
            searched = self.buffered().len();
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
        if self.buffered().is_empty() {
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

#[cfg(test)]
pub(crate) mod testing {
    //! A fake connection for the tests of the protocol readers.

    use std::collections::VecDeque;
    use std::time::Duration;

    use super::Bounds;
    use crate::egress::{Arrived, Stream};
    use crate::error::TransportKind;
    use crate::{Error, Result};

    /// A connection that hands back `chunks` in order, then nothing more.
    pub(crate) struct Fed(pub(crate) VecDeque<Vec<u8>>);

    impl Stream for Fed {
        fn write(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_until(&mut self, _: &[&[u8]], _: usize) -> Result<Vec<u8>> {
            Err(Error::transport(TransportKind::Unsupported, true))
        }

        fn read_some(&mut self, _: usize, _: Duration) -> Result<Arrived> {
            Ok(self.0.pop_front().map_or(Arrived::Nothing, Arrived::Bytes))
        }
    }

    /// Bounds no test reaches.
    pub(crate) fn wide() -> Bounds {
        Bounds::new(60_000, 600_000, u64::MAX / 2)
    }

    /// The median of `runs` timings of `f`, in microseconds, and what the last run returned.
    pub(crate) fn median_us<T>(runs: usize, mut f: impl FnMut() -> T) -> (u128, T) {
        let mut times = Vec::new();
        let mut last = None;
        for _ in 0..runs {
            let start = std::time::Instant::now();
            last = Some(f());
            times.push(start.elapsed().as_micros());
        }
        times.sort_unstable();
        let mid = times.get(times.len() / 2).copied().unwrap_or_default();
        (mid, last.unwrap_or_else(f))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use std::collections::VecDeque;

    use super::testing::{Fed, wide};
    use super::*;

    #[test]
    fn takes_and_reads_interleave() {
        let mut stream = Fed(VecDeque::from([
            b"abcdef".to_vec(),
            b"ghij".to_vec(),
            b"klm\nnop".to_vec(),
        ]));
        let mut io = Io::new(&mut stream, wide());
        assert_eq!(io.take(2).unwrap().as_slice(), b"ab");
        assert_eq!(io.buffered(), b"cdef");
        // Needs the next read: the taken bytes are dropped from the front first.
        assert_eq!(io.take(6).unwrap().as_slice(), b"cdefgh");
        assert_eq!(
            io.buf.len(),
            8,
            "the four bytes left were moved to the front"
        );
        assert_eq!(io.buffered(), b"ij");
        assert_eq!(io.line(16).unwrap().as_slice(), b"ijklm\n");
        assert_eq!(io.buffered(), b"nop");
        assert!(io.expect_empty().is_err());
        assert_eq!(io.take(3).unwrap().as_slice(), b"nop");
        assert!(io.expect_empty().is_ok());
        assert!(io.buf.is_empty());
        assert_eq!(io.read, 17);
    }

    #[test]
    fn the_deadline_holds_while_buffered_bytes_are_taken() {
        let mut stream = Fed(VecDeque::from([vec![0u8; 100]]));
        let mut io = Io::new(&mut stream, wide());
        io.take(10).unwrap();
        io.bounds.deadline = Instant::now();
        // Ninety bytes are buffered, but the connection is over.
        assert_eq!(io.buffered().len(), 90);
        assert_eq!(
            io.take(10).err(),
            Some(Error::transport(TransportKind::Timeout, true))
        );
    }
}
