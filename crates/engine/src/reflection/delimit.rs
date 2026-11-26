//! The reads of a caller's exchanges on a TLS connection, each up to a delimiter the caller
//! chose, where the server's replies may echo a secret.
//!
//! A read that ends where a caller's delimiter matches would tell the caller where those bytes
//! stand in the reply. Set the delimiter to the bytes known to come before an echoed secret
//! plus a guess of its next byte, and whether (and where) the read ends tells whether the
//! guess was right, one byte per call. So a match is taken only when no occurrence of a secret
//! (in any form the search knows) overlaps the delimiter; any other match is skipped and the
//! read goes on as if it had not matched. To know that, the reader looks ahead after a match,
//! as far as an occurrence that overlaps it could reach, while the bytes seen so far could
//! still be the start of one; the bytes read ahead stay, in order, for the next read.
//!
//! Which matches are taken then depends on the bytes around the secret only, never on the
//! secret's own bytes, except through time: deciding a match (and a look ahead that waits for
//! the server) takes longer next to a secret. See `docs/threat-model.md`.

use core::time::Duration;
use std::collections::VecDeque;

use zeroize::{Zeroize, Zeroizing};

use super::{LONGEST_ESCAPE, Search, Secrets};
use crate::egress::{Arrived, Stream};
use crate::error::TransportKind;
use crate::{Error, Result};

/// The most bytes asked of the connection at a time.
const CHUNK: usize = 16 * 1024;
/// The wait of one read of the connection; the transport bounds it by its own read timeout
/// and the deadline of the connection.
const WAIT: Duration = Duration::from_secs(3600);

/// What becomes of a delimiter match.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// The read ends there.
    Take,
    /// A secret overlaps it: the read goes on.
    Skip,
    /// The bytes after it could still make a secret that overlaps it.
    More,
}

/// Reads the exchanges of one call. The bytes it read past the end of a read are the start
/// of the next one.
pub(crate) struct Delimited {
    search: Search,
    /// How far an occurrence of a secret reaches at most, less one byte.
    hold: usize,
    /// The end of the reads before (as far back as a secret that overlaps the next match
    /// could start), then the bytes of the current read and the ones read ahead.
    seen: Zeroizing<Vec<u8>>,
    /// Where the current read starts in `seen`.
    base: usize,
}

impl Delimited {
    /// A reader that searches for the secrets of `secrets`.
    pub(crate) fn new(secrets: &Secrets<'_>) -> Result<Self> {
        Ok(Self::with_search(super::needles(secrets)?))
    }

    pub(crate) fn with_search(search: Search) -> Self {
        let hold = search.hold();
        Self {
            search,
            hold,
            seen: Zeroizing::new(Vec::new()),
            base: 0,
        }
    }

    /// Reads up to and including the first match of `delimiters` that no secret overlaps.
    /// With no delimiter it reads once (one datagram). Fails like [`Stream::read_until`]
    /// (after `max` bytes without a match, at the end of the connection or its read timeout),
    /// and with [`Error::Reflection`] when the bytes it read then hold a secret.
    pub(crate) fn read(
        &mut self,
        stream: &mut (dyn Stream + '_),
        delimiters: &[&[u8]],
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if delimiters.is_empty() {
            return stream.read_until(&[], max).map(Zeroizing::new);
        }
        let mut queue = VecDeque::new();
        let mut scanned = self.base;
        loop {
            self.enumerate(delimiters, &mut scanned, &mut queue);
            while let Some(&(start, end)) = queue.front() {
                match self.decide(start, end, false) {
                    Decision::Take => return Ok(self.take(end)),
                    Decision::Skip => {
                        queue.pop_front();
                    }
                    Decision::More => break,
                }
            }
            if queue.is_empty() && self.seen.len().saturating_sub(self.base) > max {
                return Err(self.fail(Error::transport(TransportKind::TooLarge, true)));
            }
            let arrived = match stream.read_some(CHUNK, WAIT) {
                Ok(arrived) => arrived,
                Err(error) => return Err(self.fail(error)),
            };
            let kind = match arrived {
                Arrived::Bytes(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    push_erasing(&mut self.seen, &bytes);
                    continue;
                }
                Arrived::Nothing => TransportKind::Timeout,
                Arrived::End => TransportKind::Closed,
            };
            // Nothing more comes: what was read is all a secret could be made of.
            while let Some(&(start, end)) = queue.front() {
                if self.decide(start, end, true) == Decision::Take {
                    return Ok(self.take(end));
                }
                queue.pop_front();
            }
            return Err(self.fail(Error::transport(kind, true)));
        }
    }

    /// Adds to `queue` the matches that end after `scanned`, by where they end (the first
    /// to end first, as [`Stream::read_until`] takes them), and moves `scanned` to the end.
    fn enumerate(
        &self,
        delimiters: &[&[u8]],
        scanned: &mut usize,
        queue: &mut VecDeque<(usize, usize)>,
    ) {
        let mut found = Vec::new();
        for delimiter in delimiters.iter().filter(|d| !d.is_empty()) {
            let mut at = scanned
                .saturating_sub(delimiter.len().saturating_sub(1))
                .max(self.base);
            while let Some(i) = self
                .seen
                .get(at..)
                .and_then(|rest| memchr::memmem::find(rest, delimiter))
            {
                let start = at + i;
                let end = start + delimiter.len();
                if end > *scanned {
                    found.push((start, end));
                }
                at = start + 1;
            }
        }
        found.sort_unstable_by_key(|&(start, end)| (end, start));
        found.dedup();
        queue.extend(found);
        *scanned = self.seen.len();
    }

    /// Whether the match `start..end` of `seen` ends the read. `last`: no more bytes come.
    fn decide(&self, start: usize, end: usize, last: bool) -> Decision {
        if self.search.is_empty() {
            return Decision::Take;
        }
        let reach = end.saturating_add(self.hold);
        let hi = self.seen.len().min(reach);
        let complete = last || hi >= reach;
        // From where an occurrence that overlaps the match could start, and one escape
        // earlier, so the decoding of the window is in step by then; never inside a run of
        // backslashes, whose pairs it would read the other way.
        let mut lo = start.saturating_sub(self.hold.saturating_add(LONGEST_ESCAPE));
        while lo > 0 && self.seen.get(lo - 1) == Some(&b'\\') {
            lo -= 1;
        }
        let window = self.seen.get(lo..hi).unwrap_or_default();
        let (start, end) = (start - lo, end - lo);
        if self.search.overlaps(window, start, end) {
            Decision::Skip
        } else if !complete && self.search.open(window, end) {
            Decision::More
        } else {
            Decision::Take
        }
    }

    /// Ends the current read at `end` of `seen`; keeps what comes after it and, before it,
    /// as much as a secret that overlaps the next match could start back.
    fn take(&mut self, end: usize) -> Zeroizing<Vec<u8>> {
        let read = Zeroizing::new(self.seen.get(self.base..end).unwrap_or_default().to_vec());
        let keep = end.saturating_sub(self.hold.saturating_add(LONGEST_ESCAPE));
        let rest = Zeroizing::new(self.seen.get(keep..).unwrap_or_default().to_vec());
        self.seen = rest;
        self.base = end - keep;
        read
    }

    /// The error of a read that failed: [`Error::Reflection`] when the bytes it read hold a
    /// secret, else `error`.
    fn fail(&mut self, error: Error) -> Error {
        let found = self.search.found_stream(&self.seen);
        self.seen.zeroize();
        self.base = 0;
        if found { Error::Reflection } else { error }
    }
}

/// Appends `bytes` to `out`; a buffer that has to grow is copied and the old one erased.
fn push_erasing(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let need = out.len().saturating_add(bytes.len());
    if need > out.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(
            need.max(out.capacity().saturating_mul(2)),
        ));
        grown.extend_from_slice(out);
        *out = grown;
    }
    out.extend_from_slice(bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A connection that hands back `chunks` in order, then ends.
    struct Chunks(VecDeque<Vec<u8>>);

    impl Stream for Chunks {
        fn write(&mut self, _: &[u8]) -> Result<()> {
            Ok(())
        }

        fn read_until(&mut self, _: &[&[u8]], _: usize) -> Result<Vec<u8>> {
            Err(Error::transport(TransportKind::Unsupported, true))
        }

        fn read_some(&mut self, _: usize, _: Duration) -> Result<Arrived> {
            Ok(self.0.pop_front().map_or(Arrived::End, Arrived::Bytes))
        }
    }

    fn reader(secret: &[u8]) -> Delimited {
        let mut search = Search::default();
        search.add_field(secret).unwrap();
        Delimited::with_search(search)
    }

    #[test]
    fn a_match_next_to_a_secret_is_taken_and_one_over_it_is_not() {
        let secret = b"0123456789abcdef";
        let mut text = b"head:".to_vec();
        text.extend_from_slice(secret);
        text.extend_from_slice(b":tail\n");
        for split in 1..text.len() {
            let mut stream = Chunks(VecDeque::from([
                text[..split].to_vec(),
                text[split..].to_vec(),
            ]));
            let mut r = reader(secret);
            // Ends just before the secret: taken.
            assert_eq!(
                r.read(&mut stream, &[b"head:"], 1024).unwrap().as_slice(),
                b"head:"
            );
            // The rest holds the secret; a match inside it is skipped, the line end is not.
            let rest = r.read(&mut stream, &[b"4567", b"\n"], 1024).unwrap();
            assert_eq!(rest.len(), text.len() - 5, "split at {split}");
        }
    }

    #[test]
    fn a_match_over_a_secret_in_an_encoded_form_is_skipped() {
        let secret = b"p@ss w0rd/secret";
        let forms = super::super::forms(secret).unwrap();
        for (f, form) in forms.iter().enumerate() {
            let mut text = b"x=".to_vec();
            text.extend_from_slice(form);
            text.extend_from_slice(b";\n");
            // Every match that starts or ends inside the form, cut anywhere.
            for at in 0..form.len() {
                let delimiter = &text[2 + at..(3 + at).min(text.len())];
                let mut stream = Chunks(VecDeque::from([text.clone()]));
                let mut r = reader(secret);
                let read = r.read(&mut stream, &[delimiter], 1024);
                match read {
                    Ok(read) => assert!(
                        read.len() <= 2 || read.len() >= 2 + form.len(),
                        "form {f}: a read ended inside it at {at}"
                    ),
                    Err(error) => assert_eq!(error, Error::Reflection, "form {f}"),
                }
            }
        }
    }
}
