//! A read buffer that bytes are taken from the front of without moving the rest: the bytes
//! not taken yet start at an offset, and they move to the front at most once per push. Taking
//! a run of small frames out of a large read stays linear in the bytes read, where copying
//! the rest of the buffer after each frame was quadratic (#46, #52).
//!
//! Taken bytes are wiped when the buffer is compacted or emptied, and all of it when it is
//! dropped; the buffer never lets `Vec` reallocate it, which would free an allocation unwiped.

use zeroize::{Zeroize, Zeroizing};

/// The smallest allocation, so that small pushes do not move the buffer often.
const MIN_BUFFER: usize = 16 * 1024;

/// Bytes pushed at the back and taken from the front.
pub(crate) struct ReadBuf {
    /// The bytes pushed; those before `pos` were taken.
    buf: Zeroizing<Vec<u8>>,
    /// Where the bytes not taken yet start in `buf`.
    pos: usize,
    /// Bytes moved or copied inside the buffer (tests measure the cost of parsing).
    #[cfg(test)]
    pub(crate) copied: u64,
}

impl ReadBuf {
    /// An empty buffer.
    pub(crate) fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            pos: 0,
            #[cfg(test)]
            copied: 0,
        }
    }

    /// The bytes not taken yet.
    pub(crate) fn pending(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    /// Bytes held, taken or not (tests check that taken ones do not pile up).
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.buf.len()
    }

    /// Appends `bytes`, after moving the bytes not taken yet to the front.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.compact();
        self.grow(bytes.len());
        self.buf.extend_from_slice(bytes);
    }

    /// Takes the first `n` pending bytes (fewer when fewer are pending).
    pub(crate) fn take(&mut self, n: usize) -> Zeroizing<Vec<u8>> {
        let head = Zeroizing::new(self.pending().get(..n).unwrap_or(self.pending()).to_vec());
        #[cfg(test)]
        {
            self.copied = self.copied.saturating_add(head.len() as u64);
        }
        self.skip(head.len());
        head
    }

    /// Drops the first `n` pending bytes (fewer when fewer are pending).
    pub(crate) fn skip(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.buf.len());
        if self.pos >= self.buf.len() {
            // All taken: wipe what it holds (its spare capacity holds nothing: `compact`
            // wipes what it leaves behind, and `grow` never lets an allocation go unwiped)
            // and start again at the front.
            self.buf.as_mut_slice().zeroize();
            self.buf.clear();
            self.pos = 0;
        }
    }

    /// Moves the bytes not taken yet to the start of the buffer and wipes the taken ones, so
    /// the buffer does not grow with what was taken.
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

    /// Makes room for `more` bytes without letting `Vec` reallocate in place of us: the
    /// buffer moves to a new one at least twice as large (so growing stays linear), and the
    /// old one is wiped as it drops.
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn takes_skips_and_pushes_interleave() {
        let mut b = ReadBuf::new();
        b.push(b"abcdef");
        assert_eq!(b.take(2).as_slice(), b"ab");
        b.skip(1);
        assert_eq!(b.pending(), b"def");
        b.push(b"gh");
        assert_eq!(b.held(), 5, "the taken bytes were dropped from the front");
        assert_eq!(b.take(10).as_slice(), b"defgh");
        assert_eq!(b.held(), 0);
        b.skip(3);
        assert!(b.pending().is_empty());
    }
}
