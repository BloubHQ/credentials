//! The plaintext of a record: named fields of bytes.
//!
//! A credential is whatever fields its owner puts in: one token, a user name and a password, a
//! certificate and its key, an image. The engine does not know kinds of credentials.

use core::fmt;

use zeroize::Zeroizing;

use crate::policy::is_token;
use crate::{Error, Result};

/// Most fields in one record.
pub const MAX_FIELDS: usize = 32;
/// Most bytes of all field values of one record.
pub const MAX_TOTAL: usize = 16 * 1024 * 1024;

/// Named byte values. They cannot be read, printed or cloned outside the engine.
#[derive(Default)]
pub struct Fields {
    items: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl Fields {
    /// No fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field. The name is a token and appears once; the value is not empty.
    pub fn insert(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        let value = Zeroizing::new(value);
        let total = self.total().saturating_add(value.len());
        if !is_token(name)
            || self.get(name).is_some()
            || value.is_empty()
            || self.items.len() >= MAX_FIELDS
            || total > MAX_TOTAL
        {
            return Err(Error::RecordInvalid);
        }
        self.items.push((name.to_string(), value));
        Ok(())
    }

    /// Replaces the value of a field, or adds it.
    pub(crate) fn set(&mut self, name: &str, value: Zeroizing<Vec<u8>>) -> Result<()> {
        let old = self.get(name).map_or(0, <[u8]>::len);
        let total = (self.total() - old).saturating_add(value.len());
        if value.is_empty() || total > MAX_TOTAL {
            return Err(Error::RecordInvalid);
        }
        match self.items.iter_mut().find(|(n, _)| n == name) {
            Some((_, slot)) => *slot = value,
            None => {
                if !is_token(name) || self.items.len() >= MAX_FIELDS {
                    return Err(Error::RecordInvalid);
                }
                self.items.push((name.to_string(), value));
            }
        }
        Ok(())
    }

    /// The names of the fields, in order.
    pub fn names(&self) -> Vec<&str> {
        self.items.iter().map(|(n, _)| n.as_str()).collect()
    }

    fn total(&self) -> usize {
        self.items.iter().map(|(_, v)| v.len()).sum()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.items.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    /// `u16 count`, then per field `u8 name length, name, u32 value length, value`.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let size = 2 + self
            .items
            .iter()
            .map(|(n, v)| 5 + n.len() + v.len())
            .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        let count = u16::try_from(self.items.len()).map_err(|_| Error::RecordInvalid)?;
        out.extend_from_slice(&count.to_be_bytes());
        for (name, value) in &self.items {
            out.push(u8::try_from(name.len()).map_err(|_| Error::RecordInvalid)?);
            out.extend_from_slice(name.as_bytes());
            let len = u32::try_from(value.len()).map_err(|_| Error::RecordInvalid)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            let (head, tail) = rest.split_at_checked(n).ok_or(Error::RecordInvalid)?;
            *rest = tail;
            Ok(head)
        }
        let mut rest = bytes;
        let count = u16::from_be_bytes(
            take(&mut rest, 2)?
                .try_into()
                .map_err(|_| Error::RecordInvalid)?,
        );
        let mut fields = Fields::new();
        for _ in 0..count {
            let name_len = usize::from(*take(&mut rest, 1)?.first().ok_or(Error::RecordInvalid)?);
            let name = core::str::from_utf8(take(&mut rest, name_len)?)
                .map_err(|_| Error::RecordInvalid)?;
            let len_bytes: [u8; 4] = take(&mut rest, 4)?
                .try_into()
                .map_err(|_| Error::RecordInvalid)?;
            let len =
                usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| Error::RecordInvalid)?;
            fields.insert(name, take(&mut rest, len)?.to_vec())?;
        }
        if !rest.is_empty() {
            return Err(Error::RecordInvalid);
        }
        Ok(fields)
    }
}

impl fmt::Debug for Fields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fields")
            .field("names", &self.names())
            .finish_non_exhaustive()
    }
}
