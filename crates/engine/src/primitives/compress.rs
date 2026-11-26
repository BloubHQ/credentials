//! DEFLATE (RFC 1951) and its two framings, zlib (RFC 1950) and gzip (RFC 1952), over the
//! `miniz_oxide` crate.
//!
//! Decompression is where a small input can become a large output (a "zip bomb"). Every
//! inflation writes into one buffer sized before it starts: [`MAX_INFLATED`] bytes or what is
//! left of the operation's byte budget, whichever is smaller. An input that would inflate past
//! it is refused, never truncated, and the buffer never grows, so a secret plaintext leaves no
//! unzeroized copy behind a reallocation. The bytes written count against the budget like any
//! other output.
//!
//! Compression is refused on a tainted value by the template analysis (`docs/policy.md`, rule
//! 10): its length depends on how the input repeats itself, which is what CRIME and BREACH
//! read.

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use zeroize::Zeroizing;

use super::bad;
use crate::{Error, Result};

/// Most bytes one inflation may produce: the size of a caller's input (`node::MAX_INPUT`).
pub const MAX_INFLATED: usize = 1024 * 1024;

/// The compression level of every DEFLATE stream the engine writes (zlib's default).
const LEVEL: u8 = 6;

/// The framing around a DEFLATE stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// Raw DEFLATE, RFC 1951.
    Raw,
    /// zlib, RFC 1950: a two-byte header and the Adler-32 of the data.
    Zlib,
    /// gzip, RFC 1952: a ten-byte header (and optional fields) and the CRC-32 and length.
    Gzip,
}

/// The gzip header the engine writes: no name, no time stamp (MTIME 0), OS 255 (unknown),
/// so the same input always gives the same bytes.
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];

const FTEXT: u8 = 1;
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Compresses `input` at level 6. The input is never a secret (the analysis refuses it), so
/// the growing buffer of the compressor holds nothing to erase.
pub fn deflate(input: &[u8], framing: Framing) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match framing {
        Framing::Raw => miniz_oxide::deflate::compress_to_vec(input, LEVEL),
        Framing::Zlib => miniz_oxide::deflate::compress_to_vec_zlib(input, LEVEL),
        Framing::Gzip => {
            let body = miniz_oxide::deflate::compress_to_vec(input, LEVEL);
            let mut out = Vec::with_capacity(GZIP_HEADER.len() + body.len() + 8);
            out.extend_from_slice(&GZIP_HEADER);
            out.extend_from_slice(&body);
            out.extend_from_slice(&crc32(input).to_le_bytes());
            // ISIZE is the length modulo 2^32 (RFC 1952 section 2.3.1): what `as u32` keeps.
            out.extend_from_slice(&(input.len() as u32).to_le_bytes());
            out
        }
    })
}

/// The most an upper bound on the output of [`deflate`] can be, for the budget check before
/// the call: stored blocks add 5 bytes per 65,535, plus the framing.
pub(crate) fn deflate_bound(len: usize) -> usize {
    len + len / 16_000 * 5 + 64
}

/// Decompresses `input`, refusing an output over [`MAX_INFLATED`] or over `limit` (what the
/// operation's budget has left), a damaged stream, a wrong checksum and any byte after the
/// end of the stream. An output that would pass `limit` when `limit` is below the cap is
/// [`Error::Budget`], as any other rendering over the budget is.
pub fn inflate(input: &[u8], framing: Framing, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    match inflate_capped(input, framing, MAX_INFLATED.min(limit)) {
        Err(Error::TemplateInvalid { rule: OVER_LIMIT }) if limit < MAX_INFLATED => {
            Err(Error::Budget { what: "bytes" })
        }
        other => other,
    }
}

const OVER_LIMIT: &str = "an inflated value over the size limit";

fn inflate_capped(input: &[u8], framing: Framing, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    match framing {
        Framing::Raw => {
            let (out, used) = inflate_into(input, 0, limit)?;
            if used != input.len() {
                return Err(bad("bytes after the end of a DEFLATE stream"));
            }
            Ok(out)
        }
        Framing::Zlib => {
            // miniz_oxide checks the header (CM 8, window, FCHECK), refuses a preset
            // dictionary, and checks the Adler-32 at the end.
            let (out, used) =
                inflate_into(input, inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER, limit)?;
            if used != input.len() {
                return Err(bad("bytes after the end of a zlib stream"));
            }
            Ok(out)
        }
        Framing::Gzip => gunzip(input, limit),
    }
}

/// Inflates a stream into a buffer of `limit` bytes; the output and the input bytes read.
fn inflate_into(input: &[u8], flags: u32, limit: usize) -> Result<(Zeroizing<Vec<u8>>, usize)> {
    let mut out = Zeroizing::new(vec![0u8; limit]);
    let mut state = Box::<DecompressorOxide>::default();
    let (status, used, written) = decompress(
        &mut state,
        input,
        out.as_mut_slice(),
        0,
        flags | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    match status {
        TINFLStatus::Done => {
            out.truncate(written);
            Ok((out, used))
        }
        TINFLStatus::HasMoreOutput => Err(bad(OVER_LIMIT)),
        TINFLStatus::Adler32Mismatch => Err(bad("a zlib stream with a wrong checksum")),
        _ => Err(bad("a damaged DEFLATE stream")),
    }
}

/// One gzip member (RFC 1952 section 2.3), and nothing after it.
fn gunzip(input: &[u8], limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let damaged = || bad("a damaged gzip header");
    let header = input.get(..10).ok_or_else(damaged)?;
    let (id, method, flags) = match header {
        [a, b, cm, flg, ..] => ([*a, *b], *cm, *flg),
        _ => return Err(damaged()),
    };
    if id != [0x1f, 0x8b]
        || method != 8
        || flags & !(FTEXT | FHCRC | FEXTRA | FNAME | FCOMMENT) != 0
    {
        return Err(damaged());
    }
    let mut at = 10usize;
    if flags & FEXTRA != 0 {
        let xlen = match input.get(at..at + 2) {
            Some([lo, hi]) => usize::from(u16::from_le_bytes([*lo, *hi])),
            _ => return Err(damaged()),
        };
        at = at.checked_add(2 + xlen).ok_or_else(damaged)?;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let rest = input.get(at..).ok_or_else(damaged)?;
            let nul = rest.iter().position(|b| *b == 0).ok_or_else(damaged)?;
            at += nul + 1;
        }
    }
    if flags & FHCRC != 0 {
        let stated = match input.get(at..at + 2) {
            Some([lo, hi]) => u16::from_le_bytes([*lo, *hi]),
            _ => return Err(damaged()),
        };
        let covered = input.get(..at).ok_or_else(damaged)?;
        if (crc32(covered) & 0xffff) as u16 != stated {
            return Err(bad("a gzip header with a wrong checksum"));
        }
        at += 2;
    }
    let body = input.get(at..).ok_or_else(damaged)?;
    let (out, used) = inflate_into(body, 0, limit)?;
    let trailer = body.get(used..).ok_or_else(damaged)?;
    let (crc, size) = match trailer {
        [c0, c1, c2, c3, s0, s1, s2, s3] => (
            u32::from_le_bytes([*c0, *c1, *c2, *c3]),
            u32::from_le_bytes([*s0, *s1, *s2, *s3]),
        ),
        // A second member, or anything else after the first, is refused: one value, one
        // member.
        _ => return Err(bad("a gzip stream without exactly one trailer")),
    };
    if crc != crc32(&out) || size != out.len() as u32 {
        return Err(bad("a gzip stream with a wrong checksum or length"));
    }
    Ok(out)
}

/// The CRC-32 of ISO 3309 and ITU-T V.42 that gzip uses (reflected polynomial 0xEDB88320).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    // Bit by bit, eight shifts a byte: no table to index.
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    c ^ 0xffff_ffff
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        // The check value of CRC-32/ISO-HDLC (the catalogue of parametrised CRC algorithms).
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn round_trips_in_every_framing() {
        for framing in [Framing::Raw, Framing::Zlib, Framing::Gzip] {
            for input in [&b""[..], b"a", &[7u8; 100_000][..]] {
                let packed = deflate(input, framing);
                assert!(packed.len() <= deflate_bound(input.len()));
                assert_eq!(
                    inflate(&packed, framing, usize::MAX).unwrap().as_slice(),
                    input
                );
            }
        }
    }

    /// A limit below the cap is the budget: passing it is a budget refusal; the cap itself is
    /// a refusal of the stream; exactly the limit is accepted.
    #[test]
    fn limits_are_the_cap_or_the_budget() {
        for framing in [Framing::Raw, Framing::Zlib, Framing::Gzip] {
            let packed = deflate(&[0u8; 1000], framing);
            assert_eq!(inflate(&packed, framing, 1000).unwrap().len(), 1000);
            assert!(matches!(
                inflate(&packed, framing, 999),
                Err(Error::Budget { what: "bytes" })
            ));
            let bomb = deflate(&vec![0u8; MAX_INFLATED + 1], framing);
            assert!(matches!(
                inflate(&bomb, framing, usize::MAX),
                Err(Error::TemplateInvalid { rule: OVER_LIMIT })
            ));
        }
    }
}
