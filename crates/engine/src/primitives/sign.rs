//! Signatures beyond the first group: Ed448 (RFC 8032), ECDSA over a digest the template
//! gives (prehashed, also on the brainpool curves of RFC 5639), DSA (FIPS 186-4) with
//! deterministic nonces (RFC 6979), ML-DSA (FIPS 204) and SM2 (GB/T 32918.2); and X448
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

/// `ed448_public(key)`: the 57-byte Ed448 public key (RFC 8032 section 5.2.5) of the 57-byte
/// secret or PKCS#8 DER.
pub(super) fn ed448_public(key: &[u8]) -> Result<Bytes> {
    use ed448_goldilocks::SigningKey;
    use ed448_goldilocks::elliptic_curve::pkcs8::DecodePrivateKey as _;
    let key = if key.len() == 57 {
        SigningKey::try_from(key).map_err(|_| Error::KeyInvalid)?
    } else {
        SigningKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
    };
    Ok(Zeroizing::new(key.verifying_key().to_bytes().to_vec()))
}

/// `ecdsa_public(curve, key)`: the SEC1 uncompressed public key of a private key on `p256`,
/// `p384`, `p521`, `k256`, `bp256`, `bp384` or `sm2`; the key is the raw scalar or PKCS#8 DER,
/// as the signatures on the curve read it.
pub(super) fn ecdsa_public(curve: &[u8], key: &[u8]) -> Result<Bytes> {
    macro_rules! public {
        ($secret:ty, $len:literal) => {{
            use ecdsa::elliptic_curve::pkcs8::DecodePrivateKey as _;
            use ecdsa::elliptic_curve::sec1::ToSec1Point as _;
            let secret = if key.len() == $len {
                <$secret>::from_slice(key).map_err(|_| Error::KeyInvalid)?
            } else {
                <$secret>::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
            };
            Zeroizing::new(
                secret
                    .public_key()
                    .as_affine()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
            )
        }};
    }
    Ok(match curve {
        b"p256" => public!(p256::SecretKey, 32),
        b"p384" => public!(p384::SecretKey, 48),
        b"p521" => public!(p521::SecretKey, 66),
        b"k256" => public!(k256::SecretKey, 32),
        b"bp256" => public!(bp256::r1::SecretKey, 32),
        b"bp384" => public!(bp384::r1::SecretKey, 48),
        b"sm2" => public!(sm2::SecretKey, 32),
        _ => return Err(bad("unknown curve name")),
    })
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
    macro_rules! brainpool {
        ($curve:ty, $len:literal) => {{
            use ecdsa::elliptic_curve::pkcs8::DecodePrivateKey as _;
            let key = if key.len() == $len {
                ecdsa::SigningKey::<$curve>::from_slice(key).map_err(|_| Error::KeyInvalid)?
            } else {
                ecdsa::SigningKey::<$curve>::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
            };
            let signature: ecdsa::Signature<$curve> = key.sign_prehash(digest).map_err(failed)?;
            Zeroizing::new(signature.to_bytes().to_vec())
        }};
    }
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
        b"bp256" => brainpool!(bp256::BrainpoolP256r1, 32),
        b"bp384" => brainpool!(bp384::BrainpoolP384r1, 48),
        _ => return Err(bad("unknown curve name")),
    })
}

/// The parameter set of `mldsa_sign` and `mldsa_public`: `44`, `65` or `87`.
macro_rules! mldsa_level {
    ($level:expr, |$params:ident| $body:expr) => {
        match $level {
            b"44" => {
                type $params = ml_dsa::MlDsa44;
                $body
            }
            b"65" => {
                type $params = ml_dsa::MlDsa65;
                $body
            }
            b"87" => {
                type $params = ml_dsa::MlDsa87;
                $body
            }
            _ => return Err(bad("ML-DSA parameter set 44, 65 or 87")),
        }
    };
}

fn mldsa_seed(seed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(
        <[u8; 32]>::try_from(seed).map_err(|_| Error::KeyInvalid)?,
    ))
}

/// `mldsa_sign(level, seed, message[, context])`: ML-DSA (FIPS 204, Algorithm 2), hedged:
/// `rnd` is 32 fresh random bytes. The key is the 32-byte seed of `ML-DSA.KeyGen` (the
/// private key form of the JOSE and COSE drafts and of the LAMPS certificate profile).
pub(super) fn mldsa(
    level: &[u8],
    seed: &[u8],
    message: &[u8],
    context: &[u8],
    rnd: &[u8],
) -> Result<Bytes> {
    let context_len =
        u8::try_from(context.len()).map_err(|_| bad("mldsa_sign context of at most 255 bytes"))?;
    let rnd = <[u8; 32]>::try_from(rnd).map_err(|_| bad("mldsa_sign randomness"))?;
    let rnd = ml_dsa::B32::from(rnd);
    let seed = ml_dsa::Seed::from(*mldsa_seed(seed)?);
    // M' = 0 || |ctx| || ctx || M (FIPS 204, Algorithm 2, line 10).
    let header = [0u8, context_len];
    let signature = mldsa_level!(level, |P| {
        let key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed);
        let signature = key.sign_internal(&[&header, context, message], &rnd);
        Zeroizing::new(signature.encode().to_vec())
    });
    let mut seed = seed;
    zeroize::Zeroize::zeroize(seed.as_mut_slice());
    Ok(signature)
}

/// `mldsa_public(level, seed)`: the encoded ML-DSA public key of a seed.
pub(super) fn mldsa_public(level: &[u8], seed: &[u8]) -> Result<Bytes> {
    let seed = ml_dsa::Seed::from(*mldsa_seed(seed)?);
    let public = mldsa_level!(level, |P| {
        let key = ml_dsa::ExpandedSigningKey::<P>::from_seed(&seed);
        Zeroizing::new(key.verifying_key().encode().to_vec())
    });
    let mut seed = seed;
    zeroize::Zeroize::zeroize(seed.as_mut_slice());
    Ok(public)
}

/// The default distinguishing identifier of SM2 (GB/T 32918.2, RFC 8998 section 3.2.1).
const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";
/// Longest SM2 identifier: its length in bits is a 16-bit number.
const MAX_SM2_ID: usize = 8191;

/// `sm2_sign(key, message[, id])`: SM2 (GB/T 32918.2) over SM3 of `Z_A || message`, `r || s`;
/// the nonce is derived as RFC 6979 does. The key is the 32-byte scalar or PKCS#8 DER; the
/// identifier is `1234567812345678` unless given (UTF-8 text).
pub(super) fn sm2(key: &[u8], message: &[u8], id: Option<&[u8]>) -> Result<Bytes> {
    use sm2::dsa::signature::Signer as _;
    let id = id.unwrap_or(SM2_DEFAULT_ID);
    if id.is_empty() || id.len() > MAX_SM2_ID {
        return Err(bad("sm2_sign identifier of 1 to 8191 bytes"));
    }
    let id = core::str::from_utf8(id).map_err(|_| bad("sm2_sign identifier in UTF-8"))?;
    let key = if key.len() == 32 {
        sm2::dsa::SigningKey::from_slice(id, key).map_err(|_| Error::KeyInvalid)?
    } else {
        use sm2::pkcs8::DecodePrivateKey as _;
        let secret = sm2::SecretKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?;
        sm2::dsa::SigningKey::new(id, &secret).map_err(|_| Error::KeyInvalid)?
    };
    let signature: sm2::dsa::Signature = key.try_sign(message).map_err(|_| Error::KeyInvalid)?;
    Ok(Zeroizing::new(signature.to_bytes().to_vec()))
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
