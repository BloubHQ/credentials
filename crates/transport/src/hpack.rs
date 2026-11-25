//! HPACK (RFC 7541), the header compression of HTTP/2: a decoder for the header blocks a
//! server sends, and an encoder for the requests of the node.
//!
//! The decoder keeps the dynamic table within the size the node announced
//! ([`TABLE_SIZE`]), bounds every integer, string and header list, and refuses a Huffman
//! string with more than seven bits of padding, padding that is not all ones, or the EOS
//! symbol. What it returns is checked again by the HTTP/2 client before anything reads it
//! (`h2::check_fields`): names, values and pseudo-headers.
//!
//! The encoder writes every field as a literal that is never indexed (RFC 7541, 6.2.3), with
//! no Huffman coding and no dynamic table: a secret in a header is never kept in a table of
//! the server or of an intermediary.

use std::collections::VecDeque;
use std::sync::OnceLock;

/// The dynamic table size the node announces (`SETTINGS_HEADER_TABLE_SIZE`, the default).
pub const TABLE_SIZE: usize = 4096;

/// Why a header block could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HpackError {
    /// The block ends inside a field.
    #[error("header block truncated")]
    Truncated,
    /// An integer is too large.
    #[error("integer too large")]
    Integer,
    /// An index names no entry of the tables.
    #[error("index out of range")]
    Index,
    /// A Huffman string is malformed (EOS, long or wrong padding).
    #[error("malformed Huffman string")]
    Huffman,
    /// A dynamic table size update is above the size announced, or after a field.
    #[error("dynamic table size update refused")]
    TableSize,
    /// The decoded header list is larger than the limit.
    #[error("header list too large")]
    ListSize,
}

/// A header field: name and value, as bytes.
pub type Field = (Vec<u8>, Vec<u8>);

/// The static table (RFC 7541, Appendix A).
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The length in bits of the Huffman code of each symbol (RFC 7541, Appendix B), 256 being
/// EOS. The code is canonical: codes of one length are consecutive, in symbol order, so the
/// lengths alone give it (`codes_are_canonical` checks the table against the RFC's vectors).
const LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 0-15
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 16-31
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, // 32-47
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, // 48-63
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 64-79
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, // 80-95
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, // 96-111
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, // 112-127
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, // 128-143
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, // 144-159
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, // 160-175
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, // 176-191
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, // 192-207
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, // 208-223
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, // 224-239
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, // 240-255
    30, // EOS
];

const EOS: u16 = 256;
const MAX_CODE: usize = 30;

/// The canonical decoding tables: for each length, the first code and the number of codes,
/// and the symbols in code order.
struct Huffman {
    first: [u32; MAX_CODE + 1],
    count: [u32; MAX_CODE + 1],
    offset: [usize; MAX_CODE + 1],
    symbols: Vec<u16>,
}

fn huffman() -> &'static Huffman {
    static TABLE: OnceLock<Huffman> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Huffman {
            first: [0; MAX_CODE + 1],
            count: [0; MAX_CODE + 1],
            offset: [0; MAX_CODE + 1],
            symbols: Vec::with_capacity(LENGTHS.len()),
        };
        let mut code = 0u32;
        for len in 1..=MAX_CODE {
            let symbols = (0u16..)
                .zip(LENGTHS)
                .filter(|(_, l)| usize::from(*l) == len);
            let start = table.symbols.len();
            table.symbols.extend(symbols.map(|(s, _)| s));
            let count = u32::try_from(table.symbols.len() - start).unwrap_or(u32::MAX);
            if let (Some(first), Some(n), Some(offset)) = (
                table.first.get_mut(len),
                table.count.get_mut(len),
                table.offset.get_mut(len),
            ) {
                *first = code;
                *n = count;
                *offset = start;
            }
            code = (code + count) << 1;
        }
        table
    })
}

/// The canonical Huffman code of `symbol`: its bits and their number.
pub fn huffman_code(symbol: u16) -> Option<(u32, u8)> {
    let table = huffman();
    let len = *LENGTHS.get(usize::from(symbol))?;
    let first = *table.first.get(usize::from(len))?;
    let offset = *table.offset.get(usize::from(len))?;
    let rank = table
        .symbols
        .get(offset..)?
        .iter()
        .position(|s| *s == symbol)?;
    Some((first + u32::try_from(rank).ok()?, len))
}

/// Decodes a Huffman string (RFC 7541, 5.2).
pub fn huffman_decode(bytes: &[u8]) -> Result<Vec<u8>, HpackError> {
    let table = huffman();
    // Five bits is the shortest code: the output is at most 8/5 of the input.
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(8) / 5 + 1);
    let mut code = 0u32;
    let mut len = 0usize;
    for byte in bytes {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            len += 1;
            if len > MAX_CODE {
                return Err(HpackError::Huffman);
            }
            let (Some(first), Some(count), Some(offset)) = (
                table.first.get(len),
                table.count.get(len),
                table.offset.get(len),
            ) else {
                return Err(HpackError::Huffman);
            };
            if *count == 0 || code < *first || code - first >= *count {
                continue;
            }
            let rank = usize::try_from(code - first).map_err(|_| HpackError::Huffman)?;
            let symbol = *table
                .symbols
                .get(offset + rank)
                .ok_or(HpackError::Huffman)?;
            if symbol == EOS {
                return Err(HpackError::Huffman);
            }
            out.push(u8::try_from(symbol).map_err(|_| HpackError::Huffman)?);
            code = 0;
            len = 0;
        }
    }
    // Padding: at most 7 bits, all ones (a prefix of EOS).
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(HpackError::Huffman);
    }
    Ok(out)
}

/// Encodes a string with the Huffman code (for tests and the fuzz targets: the node itself
/// sends literals).
pub fn huffman_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut acc = 0u64;
    let mut bits = 0u32;
    for byte in bytes {
        let Some((code, len)) = huffman_code(u16::from(*byte)) else {
            continue;
        };
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push((((acc << pad) | ((1u64 << pad) - 1)) & 0xff) as u8);
    }
    out
}

/// Decodes the integer of prefix `n` bits that starts at `bytes[*at]`.
fn integer(bytes: &[u8], at: &mut usize, n: u32) -> Result<usize, HpackError> {
    let mask = (1usize << n) - 1;
    let first = usize::from(*bytes.get(*at).ok_or(HpackError::Truncated)?) & mask;
    *at += 1;
    if first < mask {
        return Ok(first);
    }
    let mut value = mask;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*at).ok_or(HpackError::Truncated)?;
        *at += 1;
        // Integers above 2^28 name nothing a bounded decoder holds.
        if shift > 21 {
            return Err(HpackError::Integer);
        }
        value = value
            .checked_add(usize::from(byte & 0x7f) << shift)
            .ok_or(HpackError::Integer)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Encodes `value` with a prefix of `n` bits; `flags` are the bits above the prefix.
fn put_integer(out: &mut Vec<u8>, flags: u8, n: u32, value: usize) {
    let mask = (1usize << n) - 1;
    if value < mask {
        out.push(flags | (value as u8));
        return;
    }
    out.push(flags | (mask as u8));
    let mut rest = value - mask;
    while rest >= 0x80 {
        out.push(((rest & 0x7f) as u8) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn string(bytes: &[u8], at: &mut usize, limit: usize) -> Result<Vec<u8>, HpackError> {
    let huffman = bytes.get(*at).ok_or(HpackError::Truncated)? & 0x80 != 0;
    let len = integer(bytes, at, 7)?;
    if len > limit {
        return Err(HpackError::ListSize);
    }
    let end = at.checked_add(len).ok_or(HpackError::Truncated)?;
    let raw = bytes.get(*at..end).ok_or(HpackError::Truncated)?;
    *at = end;
    if huffman {
        huffman_decode(raw)
    } else {
        Ok(raw.to_vec())
    }
}

/// The size of an entry in the dynamic table (RFC 7541, 4.1).
fn entry_size(field: &Field) -> usize {
    field.0.len() + field.1.len() + 32
}

/// The decoder of one connection: its dynamic table.
pub struct Decoder {
    table: VecDeque<Field>,
    size: usize,
    max: usize,
    limit: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(TABLE_SIZE)
    }
}

impl Decoder {
    /// A decoder whose dynamic table holds at most `limit` bytes (the size announced).
    pub fn new(limit: usize) -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max: limit,
            limit,
        }
    }

    fn evict(&mut self, room: usize) {
        while self.size + room > self.max {
            match self.table.pop_back() {
                Some(field) => self.size -= entry_size(&field),
                None => break,
            }
        }
    }

    fn insert(&mut self, field: Field) {
        let size = entry_size(&field);
        if size > self.max {
            // An entry larger than the table empties it (RFC 7541, 4.4).
            self.table.clear();
            self.size = 0;
            return;
        }
        self.evict(size);
        self.size += size;
        self.table.push_front(field);
    }

    fn get(&self, index: usize) -> Result<Field, HpackError> {
        if index == 0 {
            return Err(HpackError::Index);
        }
        if let Some((name, value)) = STATIC.get(index - 1) {
            return Ok((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        self.table
            .get(index - 1 - STATIC.len())
            .cloned()
            .ok_or(HpackError::Index)
    }

    /// Decodes one header block into its fields, refusing a list larger than `max_list`
    /// (counted as RFC 9113 counts `SETTINGS_MAX_HEADER_LIST_SIZE`: name, value and 32 per
    /// field).
    pub fn decode(&mut self, block: &[u8], max_list: usize) -> Result<Vec<Field>, HpackError> {
        let mut out = Vec::new();
        let mut list = 0usize;
        let mut at = 0usize;
        while let Some(&byte) = block.get(at) {
            let field = if byte & 0x80 != 0 {
                let index = integer(block, &mut at, 7)?;
                self.get(index)?
            } else if byte & 0x20 != 0 && byte & 0x40 == 0 {
                // A dynamic table size update: only before the first field.
                let size = integer(block, &mut at, 5)?;
                if !out.is_empty() || size > self.limit {
                    return Err(HpackError::TableSize);
                }
                self.max = size;
                self.evict(0);
                continue;
            } else {
                let (prefix, indexed) = if byte & 0x40 != 0 {
                    (6, true)
                } else {
                    (4, false)
                };
                let index = integer(block, &mut at, prefix)?;
                let name = if index == 0 {
                    string(block, &mut at, max_list)?
                } else {
                    self.get(index)?.0
                };
                let value = string(block, &mut at, max_list)?;
                let field = (name, value);
                if indexed {
                    self.insert(field.clone());
                }
                field
            };
            list = list.saturating_add(entry_size(&field));
            if list > max_list {
                return Err(HpackError::ListSize);
            }
            out.push(field);
        }
        Ok(out)
    }
}

/// Encodes fields as literals never indexed, without Huffman coding.
pub fn encode(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let len = fields
        .iter()
        .map(|(n, v)| n.len() + v.len() + 12)
        .sum::<usize>();
    let mut out = Vec::with_capacity(len);
    for (name, value) in fields {
        out.push(0x10);
        put_integer(&mut out, 0, 7, name.len());
        out.extend_from_slice(name);
        put_integer(&mut out, 0, 7, value.len());
        out.extend_from_slice(value);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_code_is_complete() {
        // Kraft's sum of a complete prefix code is exactly one.
        let sum: u64 = LENGTHS.iter().map(|l| 1u64 << (30 - u32::from(*l))).sum();
        assert_eq!(sum, 1 << 30);
        assert_eq!(huffman_code(256), Some((0x3fff_ffff, 30)));
        assert_eq!(huffman_code(u16::from(b'0')), Some((0, 5)));
        assert_eq!(huffman_code(u16::from(b'&')), Some((0xf8, 8)));
        assert_eq!(huffman_code(10), Some((0x3fff_fffc, 30)));
    }

    #[test]
    fn codes_are_canonical() {
        // RFC 7541, Appendix C.4 and C.6.
        for (text, encoded) in [
            ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
            ("no-cache", "a8eb 1064 9cbf"),
            ("custom-key", "25a8 49e9 5ba9 7d7f"),
            ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
            ("302", "6402"),
            ("private", "aec3 771a 4b"),
            (
                "Mon, 21 Oct 2013 20:13:21 GMT",
                "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
            ),
            (
                "https://www.example.com",
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
            ),
            ("307", "640e ff"),
            ("gzip", "9bd9 ab"),
            (
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            ),
        ] {
            assert_eq!(huffman_encode(text.as_bytes()), hex(encoded), "{text}");
            assert_eq!(huffman_decode(&hex(encoded)).unwrap(), text.as_bytes());
        }
    }

    #[test]
    fn every_symbol_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(huffman_decode(&huffman_encode(&all)).unwrap(), all);
    }

    #[test]
    fn rfc_responses_decode() {
        // RFC 7541, Appendix C.6: three responses with Huffman coding and a 256-byte table.
        let mut decoder = Decoder::new(256);
        let first = decoder
            .decode(
                &hex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"),
                65536,
            )
            .unwrap();
        let text = |fields: &[Field]| -> Vec<(String, String)> {
            fields
                .iter()
                .map(|(n, v)| {
                    (
                        String::from_utf8(n.clone()).unwrap(),
                        String::from_utf8(v.clone()).unwrap(),
                    )
                })
                .collect()
        };
        assert_eq!(
            text(&first),
            [
                (":status".into(), "302".into()),
                ("cache-control".into(), "private".into()),
                ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
                ("location".into(), "https://www.example.com".into()),
            ]
        );
        let second = decoder.decode(&hex("4883 640e ffc1 c0bf"), 65536).unwrap();
        assert_eq!(text(&second)[0], (":status".into(), "307".into()));
        assert_eq!(text(&second)[3].1, "https://www.example.com");
        let third = decoder
            .decode(
                &hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07"),
                65536,
            )
            .unwrap();
        assert_eq!(third.len(), 6);
        assert_eq!(
            text(&third)[5].1,
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
        );
        // The table holds what C.6.3 lists: 215 bytes.
        assert_eq!(decoder.size, 215);
    }

    #[test]
    fn malformed_blocks_are_refused() {
        let mut d = Decoder::default();
        // Index 0, an index past both tables.
        assert_eq!(d.decode(&[0x80], 1 << 16), Err(HpackError::Index));
        assert_eq!(
            d.decode(&[0xff, 0x80, 0x01], 1 << 16),
            Err(HpackError::Index)
        );
        // An integer that never ends, or that overflows.
        assert_eq!(d.decode(&[0xff, 0xff], 1 << 16), Err(HpackError::Truncated));
        assert_eq!(
            d.decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], 1 << 16),
            Err(HpackError::Integer)
        );
        // A string longer than the block.
        assert_eq!(
            d.decode(&[0x00, 0x05, b'a'], 1 << 16),
            Err(HpackError::Truncated)
        );
        // A table size above the one announced, or after a field.
        assert_eq!(
            d.decode(&[0x3f, 0xe2, 0x1f], 1 << 16),
            Err(HpackError::TableSize)
        );
        assert_eq!(d.decode(&[0x88, 0x20], 1 << 16), Err(HpackError::TableSize));
        // Huffman: EOS inside, padding of eight bits, padding of zeros.
        assert_eq!(
            d.decode(&[0x00, 0x81, 0x00, 0x84, 0xff, 0xff, 0xff, 0xff], 1 << 16),
            Err(HpackError::Huffman)
        );
        assert_eq!(huffman_decode(&[0xff]), Err(HpackError::Huffman));
        assert_eq!(huffman_decode(&[0x00]), Err(HpackError::Huffman));
        // A list larger than the limit.
        let big = encode(&[(b"x-big", &[b'a'; 100])]);
        assert_eq!(d.decode(&big, 64), Err(HpackError::ListSize));
    }

    #[test]
    fn literals_round_trip_and_are_never_indexed() {
        let block = encode(&[(b"authorization", b"Bearer abc"), (b"x", &[b'y'; 300])]);
        assert_eq!(block[0], 0x10);
        let mut d = Decoder::default();
        let fields = d.decode(&block, 1 << 16).unwrap();
        assert_eq!(
            fields[0],
            (b"authorization".to_vec(), b"Bearer abc".to_vec())
        );
        assert_eq!(fields[1].1.len(), 300);
        assert!(d.table.is_empty());
    }
}
