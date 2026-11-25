//! The minimal DER reader the certificate checks need: one-byte tags, definite lengths of at
//! most four bytes, encoded in the fewest bytes (DER), and nothing read past its parent.
//!
//! Signatures and the certificate chain are checked by `webpki`; this reader only finds the
//! extensions a Fulcio certificate carries the signer's identity in.

use crate::{Error, Result};

/// `SEQUENCE`.
pub(crate) const SEQUENCE: u8 = 0x30;
/// `OBJECT IDENTIFIER`.
pub(crate) const OID: u8 = 0x06;
/// `BOOLEAN`.
pub(crate) const BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub(crate) const INTEGER: u8 = 0x02;
/// `OCTET STRING`.
pub(crate) const OCTET_STRING: u8 = 0x04;
/// `UTF8String`.
pub(crate) const UTF8_STRING: u8 = 0x0c;

fn malformed(what: &'static str) -> Error {
    Error::CertificateMalformed(what)
}

/// A reader over the contents of one DER value.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The tag of the next value, if any.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads the next value: its tag and its contents.
    pub(crate) fn read(&mut self) -> Result<(u8, &'a [u8])> {
        let (&tag, rest) = self
            .data
            .split_first()
            .ok_or(malformed("truncated value"))?;
        if tag & 0x1f == 0x1f {
            return Err(malformed("multi-byte tag"));
        }
        let (&first, rest) = rest.split_first().ok_or(malformed("truncated length"))?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return Err(malformed("indefinite or oversized length"));
            }
            let (bytes, rest) = rest
                .split_at_checked(count)
                .ok_or(malformed("truncated length"))?;
            if bytes.first() == Some(&0) {
                return Err(malformed("length not in the fewest bytes"));
            }
            let len = bytes
                .iter()
                .fold(0usize, |len, b| (len << 8) | usize::from(*b));
            if len < 0x80 {
                return Err(malformed("length not in the fewest bytes"));
            }
            (len, rest)
        };
        let (value, rest) = rest
            .split_at_checked(len)
            .ok_or(malformed("value longer than its parent"))?;
        self.data = rest;
        Ok((tag, value))
    }

    /// Reads the next value, which must have `tag`.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        match self.read()? {
            (found, value) if found == tag => Ok(value),
            _ => Err(malformed("unexpected tag")),
        }
    }

    /// Reads the next value if it has `tag`.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        if self.peek() == Some(tag) {
            self.expect(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The reader must be at its end.
    pub(crate) fn finish(&self) -> Result<()> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing data"))
        }
    }
}

/// Reads `data` as exactly one value with `tag` and returns its contents.
pub(crate) fn single(data: &[u8], tag: u8) -> Result<&[u8]> {
    let mut reader = Reader::new(data);
    let value = reader.expect(tag)?;
    reader.finish()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn lengths_are_definite_and_minimal() {
        assert_eq!(single(&[0x04, 0x02, 1, 2], OCTET_STRING).unwrap(), &[1, 2]);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        assert_eq!(single(&long, OCTET_STRING).unwrap().len(), 0x80);
        for bad in [
            &[0x04, 0x81, 0x01, 1][..],   // a short length in the long form
            &[0x04, 0x82, 0x00, 0x80],    // a leading zero
            &[0x04, 0x80, 1, 0, 0],       // indefinite
            &[0x04, 0x85, 1, 1, 1, 1, 1], // five length bytes
            &[0x04, 0x03, 1, 2],          // longer than the data
            &[0x1f, 0x01, 0x00],          // a multi-byte tag
            &[0x04, 0x01, 1, 9],          // trailing data
            &[],
        ] {
            assert!(single(bad, OCTET_STRING).is_err(), "{bad:?}");
        }
        assert!(single(&[0x30, 0x00], OCTET_STRING).is_err());
    }
}
