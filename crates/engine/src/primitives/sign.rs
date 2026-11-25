//! Signatures beyond the first group: Ed448 (RFC 8032), ECDSA over a digest the template
//! gives (prehashed), and DSA (FIPS 186-4) with deterministic nonces (RFC 6979); and X448
//! (RFC 7748) for `ecdh`.

use zeroize::Zeroizing;

use super::{Hash, bad};
use crate::template::Bytes;
use crate::{Error, Result};

/// Longest Ed448 context (RFC 8032 section 5.2).
const MAX_ED448_CONTEXT: usize = 255;

/// `ed448_sign(key, message[, context])`: Ed448 (RFC 8032 section 5.2), the 114-byte
/// signature. The key is the 57-byte secret or PKCS#8 DER.
pub(super) fn ed448(key: &[u8], message: &[u8], context: &[u8]) -> Result<Bytes> {
    use ed448_goldilocks::SigningKey;
    use ed448_goldilocks::elliptic_curve::pkcs8::DecodePrivateKey as _;
    if context.len() > MAX_ED448_CONTEXT {
        return Err(bad("ed448_sign context of at most 255 bytes"));
    }
    let key = if key.len() == 57 {
        SigningKey::try_from(key).map_err(|_| Error::KeyInvalid)?
    } else {
        SigningKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
    };
    let signature = key
        .sign_ctx(context, message)
        .map_err(|_| Error::KeyInvalid)?;
    Ok(Zeroizing::new(signature.to_bytes().to_vec()))
}

/// `ecdsa_sign_prehash(curve, key, digest)`: ECDSA over a digest computed elsewhere (RFC 6979
/// deterministic nonce), `r || s`, on `p256`, `p384`, `p521` or `k256` (low s). The digest
/// is taken as the hash output the curve's standard would have produced, truncated or
/// padded as FIPS 186-5 says.
pub(super) fn ecdsa_prehash(curve: &[u8], key: &[u8], digest: &[u8]) -> Result<Bytes> {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    if digest.len() < 16 || digest.len() > 64 {
        return Err(bad("ecdsa_sign_prehash of a digest of 16 to 64 bytes"));
    }
    let failed = |_| bad("ecdsa_sign_prehash failed");
    macro_rules! sign {
        ($krate:ident, $len:literal) => {{
            use $krate::pkcs8::DecodePrivateKey as _;
            let key = if key.len() == $len {
                $krate::ecdsa::SigningKey::from_slice(key).map_err(|_| Error::KeyInvalid)?
            } else {
                $krate::ecdsa::SigningKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
            };
            let signature: $krate::ecdsa::Signature = key.sign_prehash(digest).map_err(failed)?;
            Zeroizing::new(signature.to_bytes().to_vec())
        }};
    }
    Ok(match curve {
        b"p256" => sign!(p256, 32),
        b"p384" => sign!(p384, 48),
        b"p521" => sign!(p521, 66),
        b"k256" => sign!(k256, 32),
        _ => return Err(bad("unknown curve name")),
    })
}

/// `dsa_sign(hash, key, message)` and `dsa_sign_der(...)`: DSA (FIPS 186-4) over the
/// `hash` of the message, nonce by RFC 6979. The key is PKCS#8 DER. `r || s`, each as long
/// as q, or the DER `Dss-Sig-Value` (RFC 3279).
pub(super) fn dsa(hash: Hash, key: &[u8], message: &[u8], der: bool) -> Result<Bytes> {
    use dsa::pkcs8::DecodePrivateKey as _;
    use dsa::signature::SignatureEncoding as _;
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    let key = dsa::SigningKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?;
    let failed = |_| bad("dsa_sign failed");
    let signature = match hash {
        Hash::Sha1 => key.sign_prehashed_rfc6979::<Sha1>(&Sha1::digest(message)),
        Hash::Sha256 => key.sign_prehashed_rfc6979::<Sha256>(&Sha256::digest(message)),
        Hash::Sha384 => key.sign_prehashed_rfc6979::<Sha384>(&Sha384::digest(message)),
        Hash::Sha512 => key.sign_prehashed_rfc6979::<Sha512>(&Sha512::digest(message)),
    }
    .map_err(failed)?;
    if der {
        return Ok(Zeroizing::new(signature.to_vec()));
    }
    let q_len = usize::try_from(key.verifying_key().components().q().bit_width())
        .map_err(|_| Error::KeyInvalid)?
        .div_ceil(8);
    let mut out = Zeroizing::new(Vec::with_capacity(2 * q_len));
    for part in [signature.r(), signature.s()] {
        let bytes = part.to_be_bytes();
        let skip = bytes.len().checked_sub(q_len).ok_or(Error::KeyInvalid)?;
        out.extend_from_slice(bytes.get(skip..).ok_or(Error::KeyInvalid)?);
    }
    Ok(out)
}

/// The X448 function of RFC 7748 section 5; an all-zero result (from a low-order point) is
/// refused.
pub(super) fn x448(scalar: &[u8], point: &[u8]) -> Result<Bytes> {
    let scalar = Zeroizing::new(<[u8; 56]>::try_from(scalar).map_err(|_| Error::KeyInvalid)?);
    let point = <[u8; 56]>::try_from(point).map_err(|_| Error::KeyInvalid)?;
    let shared = Zeroizing::new(x448::x448(*scalar, point).ok_or(Error::KeyInvalid)?);
    if shared.iter().all(|b| *b == 0) {
        return Err(Error::KeyInvalid);
    }
    Ok(Zeroizing::new(shared.to_vec()))
}

/// The X448 public key of a private key: X448 of the base point 5.
pub(super) fn x448_public(scalar: &[u8]) -> Result<Bytes> {
    x448(scalar, &x448::X448_BASEPOINT_BYTES)
}
