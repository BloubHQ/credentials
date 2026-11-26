//! The data types of the SSH wire format (RFC 4251, section 5), also used by other binary
//! protocols: big-endian integers, length-prefixed strings, name lists and `mpint`s.

use zeroize::Zeroizing;

use crate::{Error, Result};

fn short() -> Error {
    Error::ResponseInvalid {
        rule: "message truncated or malformed",
    }
}

/// A reader over the bytes of one message. Every read checks the bounds.
#[derive(Clone, Debug)]
pub struct Parse<'a> {
    bytes: &'a [u8],
}

impl<'a> Parse<'a> {
    /// A reader over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    /// True when every byte was read.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Fails unless every byte was read.
    pub fn end(&self) -> Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(short())
        }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or_else(short)?;
        self.bytes = rest;
        Ok(head)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or_else(short)
    }

    /// A boolean: any byte but 0 is true.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// A big-endian 16-bit integer.
    pub fn u16(&mut self) -> Result<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| short())?;
        Ok(u16::from_be_bytes(b))
    }

    /// A big-endian 32-bit integer.
    pub fn u32(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| short())?;
        Ok(u32::from_be_bytes(b))
    }

    /// A big-endian 64-bit integer.
    pub fn u64(&mut self) -> Result<u64> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| short())?;
        Ok(u64::from_be_bytes(b))
    }

    /// A string: a 32-bit length and that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| short())?;
        self.take(len)
    }

    /// A string of ASCII text.
    pub fn text(&mut self) -> Result<&'a str> {
        let bytes = self.string()?;
        if !bytes.is_ascii() {
            return Err(short());
        }
        core::str::from_utf8(bytes).map_err(|_| short())
    }

    /// A name list: comma-separated ASCII names, none empty.
    pub fn names(&mut self) -> Result<Vec<&'a str>> {
        let text = self.text()?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<&str> = text.split(',').collect();
        if names
            .iter()
            .any(|n| n.is_empty() || n.len() > 64 || n.bytes().any(|b| b <= b' ' || b >= 0x7f))
        {
            return Err(short());
        }
        Ok(names)
    }

    /// A non-negative `mpint`, as its magnitude without leading zero bytes.
    pub fn mpint(&mut self) -> Result<&'a [u8]> {
        let bytes = self.string()?;
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::ResponseInvalid {
                rule: "negative mpint",
            });
        }
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        Ok(bytes.get(start..).unwrap_or_default())
    }
}

/// A writer of one message. Its buffer is erased when dropped.
#[derive(Default)]
pub struct Put(pub Zeroizing<Vec<u8>>);

impl Put {
    /// An empty message.
    pub fn new() -> Self {
        Self::default()
    }

    /// A message that starts with the type byte `kind`.
    pub fn message(kind: u8) -> Self {
        let mut put = Self::new();
        put.u8(kind);
        put
    }

    /// One byte.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    /// A boolean.
    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.u8(u8::from(value))
    }

    /// A big-endian 16-bit integer.
    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A big-endian 32-bit integer.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Raw bytes.
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// A string. A string longer than 4 GiB cannot be written; the engine never makes one
    /// (its messages are bounded far below), so its length is cut, which the peer refuses.
    pub fn string(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        self.raw(bytes)
    }

    /// A name list.
    pub fn names(&mut self, names: &[&str]) -> &mut Self {
        self.string(names.join(",").as_bytes())
    }

    /// A non-negative `mpint` from its big-endian magnitude.
    pub fn mpint(&mut self, magnitude: &[u8]) -> &mut Self {
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        let magnitude = magnitude.get(start..).unwrap_or_default();
        let pad = magnitude.first().is_some_and(|b| b & 0x80 != 0);
        let len = magnitude.len() + usize::from(pad);
        self.u32(u32::try_from(len).unwrap_or(u32::MAX));
        if pad {
            self.u8(0);
        }
        self.raw(magnitude)
    }

    /// The bytes written.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes written, taken.
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn mpint_round_trip() {
        for value in [&[][..], &[0x00, 0x7f], &[0x80], &[0x00, 0x00, 0x01, 0x02]] {
            let mut put = Put::new();
            put.mpint(value);
            let mut parse = Parse::new(put.bytes());
            let read = parse.mpint().unwrap();
            let trimmed: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
            assert_eq!(read, &trimmed[..]);
            parse.end().unwrap();
        }
        // RFC 4251, section 5: 0x80 is written 00 00 00 02 00 80.
        let mut put = Put::new();
        put.mpint(&[0x80]);
        assert_eq!(put.bytes(), &[0, 0, 0, 2, 0, 0x80]);
        assert!(Parse::new(&[0, 0, 0, 1, 0x80]).mpint().is_err());
    }

    #[test]
    fn names_are_checked() {
        let mut put = Put::new();
        put.names(&["a", "b-c@d"]);
        assert_eq!(Parse::new(put.bytes()).names().unwrap(), vec!["a", "b-c@d"]);
        let mut put = Put::new();
        put.string(b"a,,b");
        assert!(Parse::new(put.bytes()).names().is_err());
        assert!(Parse::new(&[0, 0, 0, 9, 1]).string().is_err());
    }
}
