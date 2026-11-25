//! CBOR encoding (RFC 8949) in the deterministic form of its section 4.2.1: the shortest
//! head for every integer and length, definite lengths only, map keys sorted by the bytes of
//! their encoding and never repeated. That is enough for COSE (RFC 9052): `COSE_Sign1`,
//! `COSE_Encrypt0`, `COSE_Mac0`, their tags, and the `Sig_structure`, `Enc_structure` and
//! `MAC_structure` that are signed, encrypted or MACed.
//!
//! Each function returns one encoded data item. `cbor_array`, `cbor_map` and `cbor_tag`
//! take items made by the others (or literals such as `hexdecode("f6")` for null) and check
//! that each is exactly one well-formed, deterministically encoded item. Floating-point
//! numbers are refused.

use zeroize::Zeroizing;

use super::bad;
use crate::Result;
use crate::template::Bytes;

/// Deepest nesting of arrays, maps and tags in one item.
const MAX_DEPTH: usize = 16;

const UINT: u8 = 0;
const NINT: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;
const SIMPLE: u8 = 7;

/// The head of an item: major type and argument, in the shortest form.
fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if value < 24 {
        out.push(m | u8::try_from(value).unwrap_or_default());
    } else if let Ok(v) = u8::try_from(value) {
        out.push(m | 24);
        out.push(v);
    } else if let Ok(v) = u16::try_from(value) {
        out.push(m | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(value) {
        out.push(m | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn len_u64(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| bad("cbor item too long"))
}

/// An item of major type `major` with `content` after its head.
fn wrap(major: u8, count: usize, content: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(content.len() + 9));
    head(major, len_u64(count)?, &mut out);
    out.extend_from_slice(content);
    Ok(out)
}

/// `cbor_int(n)`: an integer from -2^64 to 2^64 - 1, given as decimal text.
pub(super) fn int(text: &[u8]) -> Result<Bytes> {
    let n: i128 = core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(bad("cbor_int of a value that is not an integer"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(9));
    if n >= 0 {
        let v = u64::try_from(n).map_err(|_| bad("cbor_int out of range"))?;
        head(UINT, v, &mut out);
    } else {
        let v = u64::try_from(-1 - n).map_err(|_| bad("cbor_int out of range"))?;
        head(NINT, v, &mut out);
    }
    Ok(out)
}

/// `cbor_bytes(value)`: a byte string.
pub(super) fn bytes(value: &[u8]) -> Result<Bytes> {
    wrap(BYTES, value.len(), value)
}

/// `cbor_text(value)`: a text string; the value must be UTF-8.
pub(super) fn text(value: &[u8]) -> Result<Bytes> {
    core::str::from_utf8(value).map_err(|_| bad("cbor_text of a value that is not UTF-8"))?;
    wrap(TEXT, value.len(), value)
}

/// `cbor_array(item, ...)`: an array of the items.
pub(super) fn array(items: &[Bytes]) -> Result<Bytes> {
    for item in items {
        one_item(item)?;
    }
    let content: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(content + 9));
    head(ARRAY, len_u64(items.len())?, &mut out);
    items.iter().for_each(|i| out.extend_from_slice(i));
    Ok(out)
}

/// `cbor_map(key, value, ...)`: a map of the pairs, sorted by the encoding of their keys.
pub(super) fn map(items: &[Bytes]) -> Result<Bytes> {
    if !items.len().is_multiple_of(2) {
        return Err(bad("cbor_map of an odd number of items"));
    }
    for item in items {
        one_item(item)?;
    }
    let mut pairs: Vec<(&[u8], &[u8])> = items
        .chunks(2)
        .filter_map(|p| match p {
            [k, v] => Some((k.as_slice(), v.as_slice())),
            _ => None,
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    if pairs.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
        return Err(bad("cbor_map with a key twice"));
    }
    let content: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(content + 9));
    head(MAP, len_u64(pairs.len())?, &mut out);
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    Ok(out)
}

/// `cbor_tag(number, item)`: the item under a tag.
pub(super) fn tag(number: &[u8], item: &[u8]) -> Result<Bytes> {
    let number: u64 = core::str::from_utf8(number)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(bad("cbor_tag of a number that is not an unsigned integer"))?;
    one_item(item)?;
    let mut out = Zeroizing::new(Vec::with_capacity(item.len() + 9));
    head(TAG, number, &mut out);
    out.extend_from_slice(item);
    Ok(out)
}

/// Checks that `bytes` is exactly one well-formed, deterministically encoded item.
fn one_item(bytes: &[u8]) -> Result<()> {
    let end = item(bytes, 0, 0)?;
    if end != bytes.len() {
        return Err(bad("cbor argument is not exactly one item"));
    }
    Ok(())
}

fn not_cbor() -> crate::Error {
    bad("cbor argument is not one deterministically encoded item")
}

/// Reads the head at `at`: major type, argument, and where the content starts. Refuses
/// indefinite lengths, reserved values and arguments longer than needed.
fn read_head(bytes: &[u8], at: usize) -> Result<(u8, u64, usize)> {
    let first = *bytes.get(at).ok_or_else(not_cbor)?;
    let major = first >> 5;
    let info = first & 0x1f;
    let width = match info {
        0..=23 => return Ok((major, u64::from(info), at + 1)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(not_cbor()),
    };
    let arg = bytes.get(at + 1..at + 1 + width).ok_or_else(not_cbor)?;
    let value = arg.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b));
    let shortest = match width {
        1 => value >= 24,
        2 => value > 0xff,
        4 => value > 0xffff,
        _ => value > 0xffff_ffff,
    };
    if !shortest {
        return Err(not_cbor());
    }
    Ok((major, value, at + 1 + width))
}

/// The end of the item that starts at `at`.
fn item(bytes: &[u8], at: usize, depth: usize) -> Result<usize> {
    if depth > MAX_DEPTH {
        return Err(bad("cbor nested too deep"));
    }
    let (major, value, start) = read_head(bytes, at)?;
    let skip = |n: u64| -> Result<usize> {
        let n = usize::try_from(n).map_err(|_| not_cbor())?;
        let end = start.checked_add(n).ok_or_else(not_cbor)?;
        (end <= bytes.len()).then_some(end).ok_or_else(not_cbor)
    };
    match major {
        UINT | NINT => Ok(start),
        BYTES => skip(value),
        TEXT => {
            let end = skip(value)?;
            core::str::from_utf8(bytes.get(start..end).ok_or_else(not_cbor)?)
                .map_err(|_| not_cbor())?;
            Ok(end)
        }
        ARRAY => {
            let mut end = start;
            for _ in 0..value {
                end = item(bytes, end, depth + 1)?;
            }
            Ok(end)
        }
        MAP => {
            let mut end = start;
            let mut previous: Option<&[u8]> = None;
            for _ in 0..value {
                let key_end = item(bytes, end, depth + 1)?;
                let key = bytes.get(end..key_end).ok_or_else(not_cbor)?;
                if previous.is_some_and(|p| p >= key) {
                    return Err(not_cbor());
                }
                previous = Some(key);
                end = item(bytes, key_end, depth + 1)?;
            }
            Ok(end)
        }
        TAG => item(bytes, start, depth + 1),
        // Simple values: false, true, null, undefined, and the one-byte extension from 32;
        // no floating-point numbers.
        SIMPLE => match bytes.get(at).map(|b| b & 0x1f) {
            Some(20..=23) => Ok(start),
            Some(24) if value >= 32 => Ok(start),
            _ => Err(not_cbor()),
        },
        _ => Err(not_cbor()),
    }
}
