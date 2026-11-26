//! OpenPGP framing (RFC 9580, and RFC 4880 for version 4): packets, signature subpackets,
//! multiprecision integers and ASCII armor. A signature is built by the template from these
//! and the signature functions the engine already has: the hashed data is the payload, the
//! signature fields and the trailer, which `+`, `be16`, `be32` and `len` write.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use super::{arg, bad};
use crate::Result;
use crate::template::{Bytes, Func};

/// The longest packet body or subpacket the template may frame: 1 MiB.
const MAX_BODY: usize = 1 << 20;

/// The longest integer `pgp_mpi` encodes: 65,535 bits.
const MAX_MPI: usize = 8192;

/// Base64 characters on an armor line (RFC 9580 section 6.3 allows up to 76).
const ARMOR_LINE: usize = 64;

/// The length of a packet body or subpacket as RFC 9580 section 4.2.1.1 writes it, in the
/// fewest octets: one below 192, two below 8384, else 0xFF and four.
fn length(len: usize, out: &mut Vec<u8>) -> Result<()> {
    if len > MAX_BODY {
        return Err(bad("an OpenPGP body longer than 1 MiB"));
    }
    let too_long = || bad("an OpenPGP body longer than 1 MiB");
    if len < 192 {
        out.push(u8::try_from(len).map_err(|_| too_long())?);
    } else if len < 8384 {
        let rest = len - 192;
        out.push(u8::try_from((rest >> 8) + 192).map_err(|_| too_long())?);
        out.push(u8::try_from(rest & 0xff).map_err(|_| too_long())?);
    } else {
        out.push(0xff);
        out.extend_from_slice(&u32::try_from(len).map_err(|_| too_long())?.to_be_bytes());
    }
    Ok(())
}

fn small(text: &[u8], range: core::ops::RangeInclusive<u8>, what: &'static str) -> Result<u8> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .filter(|n| range.contains(n))
        .ok_or(bad(what))
}

/// `pgp_packet(type, body)`: a packet in the OpenPGP format (RFC 9580 section 4.2.1), the
/// header `0xC0 | type` and the body length.
pub(super) fn packet(kind: &[u8], body: &[u8]) -> Result<Bytes> {
    let kind = small(kind, 1..=63, "an OpenPGP packet type from 1 to 63")?;
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 6));
    out.push(0xc0 | kind);
    length(body.len(), &mut out)?;
    out.extend_from_slice(body);
    Ok(out)
}

/// `pgp_subpacket(type, body)`: a signature subpacket (RFC 9580 section 5.2.3.7), its length
/// (of the type and the body), the type octet (bit 7 the critical flag) and the body.
pub(super) fn subpacket(kind: &[u8], body: &[u8]) -> Result<Bytes> {
    let kind = small(kind, 1..=255, "an OpenPGP subpacket type from 1 to 255")?;
    if kind & 0x7f == 0 {
        return Err(bad("an OpenPGP subpacket type from 1 to 255"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 6));
    length(body.len() + 1, &mut out)?;
    out.push(kind);
    out.extend_from_slice(body);
    Ok(out)
}

/// `pgp_mpi(value)`: a multiprecision integer (RFC 9580 section 3.2), the bit count in two
/// octets, then the big-endian value without leading zeros.
pub(super) fn mpi(value: &[u8]) -> Result<Bytes> {
    let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let digits = value.get(start..).unwrap_or_default();
    if digits.len() > MAX_MPI {
        return Err(bad("an OpenPGP integer longer than 65,535 bits"));
    }
    let top = digits.first().map_or(0, |b| 8 - b.leading_zeros() as usize);
    let bits = digits.len().saturating_sub(1) * 8 + top;
    let bits =
        u16::try_from(bits).map_err(|_| bad("an OpenPGP integer longer than 65,535 bits"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(digits.len() + 2));
    out.extend_from_slice(&bits.to_be_bytes());
    out.extend_from_slice(digits);
    Ok(out)
}

/// The CRC-24 of RFC 9580 section 6.1.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00b7_04ce;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

/// `pgp_armor(label, data[, "crc24"])`: ASCII armor (RFC 9580 section 6.2) with no armor
/// header, base64 lines of 64 characters, and the CRC-24 line only when asked: RFC 9580
/// readers ignore it, RFC 4880 readers want it.
pub(super) fn armor(label: &[u8], data: &[u8], checksum: Option<&[u8]>) -> Result<Bytes> {
    let label: &str = match label {
        b"SIGNATURE" => "SIGNATURE",
        b"MESSAGE" => "MESSAGE",
        b"PUBLIC KEY BLOCK" => "PUBLIC KEY BLOCK",
        b"PRIVATE KEY BLOCK" => "PRIVATE KEY BLOCK",
        _ => {
            return Err(bad(
                "an armor label of SIGNATURE, MESSAGE, PUBLIC or PRIVATE KEY BLOCK",
            ));
        }
    };
    let crc = match checksum {
        None => false,
        Some(b"crc24") => true,
        Some(_) => return Err(bad("the armor checksum is crc24")),
    };
    if data.len() > MAX_BODY * 8 {
        return Err(bad("armored data longer than 8 MiB"));
    }
    let encoded = Zeroizing::new(STANDARD.encode(data));
    let lines = encoded.len().div_ceil(ARMOR_LINE);
    let mut out = Zeroizing::new(Vec::with_capacity(encoded.len() + lines + 96));
    out.extend_from_slice(b"-----BEGIN PGP ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n\n");
    for line in encoded.as_bytes().chunks(ARMOR_LINE) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    if crc {
        let sum = crc24(data).to_be_bytes();
        out.push(b'=');
        out.extend_from_slice(STANDARD.encode(sum.get(1..).unwrap_or_default()).as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END PGP ");
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(b"-----\n");
    Ok(out)
}

/// The OpenPGP functions of the template language; `None` for any other.
pub(super) fn call(func: Func, args: &[Bytes]) -> Result<Option<Bytes>> {
    let at = |i: usize| arg(args, i);
    Ok(Some(match func {
        Func::PgpPacket => packet(at(0)?, at(1)?)?,
        Func::PgpSubpacket => subpacket(at(0)?, at(1)?)?,
        Func::PgpMpi => mpi(at(0)?)?,
        Func::PgpArmor => armor(at(0)?, at(1)?, args.get(2).map(|v| v.as_slice()))?,
        _ => return Ok(None),
    }))
}

/// The most bytes an OpenPGP function writes for inputs of these lengths.
pub(super) fn output_bound(func: Func, args: &[Bytes]) -> Option<usize> {
    let len = |i: usize| args.get(i).map_or(0, |a| a.len());
    match func {
        Func::PgpPacket | Func::PgpSubpacket => Some(len(1) + 6),
        Func::PgpMpi => Some(len(0) + 2),
        Func::PgpArmor => Some(len(1) / 3 * 4 + len(1) / 48 + 128),
        _ => None,
    }
}
