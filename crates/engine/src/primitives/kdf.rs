//! Key derivation: HKDF (RFC 5869), the single-step KDF of NIST SP 800-56A (Concat KDF, as
//! JOSE and COSE use it), and the counter-mode KDF of NIST SP 800-108 over HMAC; and the
//! SHA-3 extendable-output functions SHAKE128 and SHAKE256 (FIPS 202).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::bad;
use crate::template::Bytes;
use crate::{Error, Result};

/// Most bytes one KDF or SHAKE call derives.
pub(crate) const MAX_DERIVED: usize = 8192;

/// A SHA-2 hash a KDF takes by name.
#[derive(Clone, Copy)]
pub(super) enum Sha2 {
    Sha256,
    Sha384,
    Sha512,
}

impl Sha2 {
    pub(super) fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"sha256" => Sha2::Sha256,
            b"sha384" => Sha2::Sha384,
            b"sha512" => Sha2::Sha512,
            _ => return Err(bad("unknown hash name")),
        })
    }

    fn len(self) -> usize {
        match self {
            Sha2::Sha256 => 32,
            Sha2::Sha384 => 48,
            Sha2::Sha512 => 64,
        }
    }
}

/// A length argument: 1 to `max` bytes.
pub(super) fn length(text: &[u8], max: usize) -> Result<usize> {
    core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| (1..=max).contains(n))
        .ok_or(bad("length out of range"))
}

/// `hkdf(hash, ikm, salt, info, length)`: HKDF (RFC 5869), extract then expand. An empty
/// salt is a salt of zero bytes of the hash length, as the RFC says.
pub(super) fn hkdf(hash: Sha2, ikm: &[u8], salt: &[u8], info: &[u8], len: &[u8]) -> Result<Bytes> {
    let len = length(len, 255 * hash.len())?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let salt = (!salt.is_empty()).then_some(salt);
    let failed = |_| bad("hkdf length out of range");
    match hash {
        Sha2::Sha256 => hkdf::Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .map_err(failed)?,
        Sha2::Sha384 => hkdf::Hkdf::<Sha384>::new(salt, ikm)
            .expand(info, &mut out)
            .map_err(failed)?,
        Sha2::Sha512 => hkdf::Hkdf::<Sha512>::new(salt, ikm)
            .expand(info, &mut out)
            .map_err(failed)?,
    }
    Ok(out)
}

/// `hkdf_expand(hash, prk, info, length)`: the expand step of HKDF alone (RFC 5869 section
/// 2.3), for protocols that extract once and expand many labels.
pub(super) fn hkdf_expand(hash: Sha2, prk: &[u8], info: &[u8], len: &[u8]) -> Result<Bytes> {
    let len = length(len, 255 * hash.len())?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let short = |_| Error::KeyInvalid;
    let failed = |_| bad("hkdf length out of range");
    match hash {
        Sha2::Sha256 => hkdf::Hkdf::<Sha256>::from_prk(prk)
            .map_err(short)?
            .expand(info, &mut out)
            .map_err(failed)?,
        Sha2::Sha384 => hkdf::Hkdf::<Sha384>::from_prk(prk)
            .map_err(short)?
            .expand(info, &mut out)
            .map_err(failed)?,
        Sha2::Sha512 => hkdf::Hkdf::<Sha512>::from_prk(prk)
            .map_err(short)?
            .expand(info, &mut out)
            .map_err(failed)?,
    }
    Ok(out)
}

/// `concat_kdf(hash, z, other_info, length)`: the single-step KDF of NIST SP 800-56A
/// (revision 3, section 5.8.2.1.1) with a hash: `H(counter || Z || OtherInfo)` for a 32-bit
/// big-endian counter from 1, truncated. The template builds `OtherInfo` (for JOSE:
/// AlgorithmID, PartyUInfo, PartyVInfo and SuppPubInfo, each with its length prefix).
pub(super) fn concat_kdf(hash: Sha2, z: &[u8], other: &[u8], len: &[u8]) -> Result<Bytes> {
    let len = length(len, MAX_DERIVED)?;
    fn run<D: Digest>(z: &[u8], other: &[u8], len: usize) -> Bytes {
        let mut out = Zeroizing::new(Vec::with_capacity(len + 64));
        let mut counter = 1u32;
        while out.len() < len {
            let mut digest = D::new();
            digest.update(counter.to_be_bytes());
            digest.update(z);
            digest.update(other);
            out.extend_from_slice(&Zeroizing::new(digest.finalize().to_vec()));
            counter = counter.wrapping_add(1);
        }
        out.truncate(len);
        out
    }
    Ok(match hash {
        Sha2::Sha256 => run::<Sha256>(z, other, len),
        Sha2::Sha384 => run::<Sha384>(z, other, len),
        Sha2::Sha512 => run::<Sha512>(z, other, len),
    })
}

/// `kbkdf_counter(hash, key, fixed_input, length)`: the counter-mode KDF of NIST SP 800-108
/// (revision 1, section 4.1) with HMAC as PRF and a 32-bit big-endian counter from 1 before
/// the fixed input: `HMAC(key, counter || fixed_input)`, truncated. The template builds the
/// fixed input, usually `label || 0x00 || context || [L]32` (`be32` of the length in bits);
/// Kerberos (RFC 8009) uses `label || 0x00 || [L]32`.
pub(super) fn kbkdf_counter(hash: Sha2, key: &[u8], fixed: &[u8], len: &[u8]) -> Result<Bytes> {
    kbkdf_counter_bytes(hash, key, fixed, length(len, MAX_DERIVED)?)
}

/// [`kbkdf_counter`] with the length as a number of octets.
pub(super) fn kbkdf_counter_bytes(
    hash: Sha2,
    key: &[u8],
    fixed: &[u8],
    len: usize,
) -> Result<Bytes> {
    fn run<M: Mac + hmac::KeyInit>(key: &[u8], fixed: &[u8], len: usize) -> Result<Bytes> {
        let mut out = Zeroizing::new(Vec::with_capacity(len + 64));
        let mut counter = 1u32;
        while out.len() < len {
            let mut mac =
                <M as hmac::KeyInit>::new_from_slice(key).map_err(|_| Error::KeyInvalid)?;
            mac.update(&counter.to_be_bytes());
            mac.update(fixed);
            out.extend_from_slice(&Zeroizing::new(mac.finalize().into_bytes().to_vec()));
            counter = counter.wrapping_add(1);
        }
        out.truncate(len);
        Ok(out)
    }
    match hash {
        Sha2::Sha256 => run::<Hmac<Sha256>>(key, fixed, len),
        Sha2::Sha384 => run::<Hmac<Sha384>>(key, fixed, len),
        Sha2::Sha512 => run::<Hmac<Sha512>>(key, fixed, len),
    }
}

/// `shake128(message, length)` and `shake256(message, length)` (FIPS 202).
pub(super) fn shake(message: &[u8], len: &[u8], wide: bool) -> Result<Bytes> {
    use shake::digest::{ExtendableOutput, Update, XofReader};
    let len = length(len, MAX_DERIVED)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    if wide {
        let mut xof = shake::Shake256::default();
        xof.update(message);
        xof.finalize_xof().read(&mut out);
    } else {
        let mut xof = shake::Shake128::default();
        xof.update(message);
        xof.finalize_xof().read(&mut out);
    }
    Ok(out)
}
