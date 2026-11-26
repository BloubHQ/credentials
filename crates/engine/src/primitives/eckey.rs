//! An elliptic-curve private key derived from a key-derivation function: candidates from the
//! counter-mode KDF of NIST SP 800-108 (HMAC), each tested as FIPS 186-5 appendix A.2.2
//! ("rejection sampling") tests a random candidate `c`: kept when `c <= n - 2`, the key being
//! `d = c + 1`, else the next candidate. The candidate number is one octet, from 1 to 254,
//! placed in the KDF's fixed input between a prefix and a suffix the template writes, so the
//! fixed input of candidate `i` is `prefix || i || suffix`.

use zeroize::Zeroizing;

use super::bad;
use super::kdf::{Sha2, kbkdf_counter_bytes};
use crate::Result;
use crate::template::Bytes;

/// The last candidate number.
const LAST_CANDIDATE: u8 = 254;

/// A curve whose private keys are derived here.
#[derive(Clone, Copy)]
pub(super) enum Curve {
    P256,
    P384,
    K256,
}

impl Curve {
    pub(super) fn parse(name: &[u8]) -> Result<Self> {
        Ok(match name {
            b"p256" => Curve::P256,
            b"p384" => Curve::P384,
            b"k256" => Curve::K256,
            _ => return Err(bad("kbkdf_ec_key curve p256, p384 or k256")),
        })
    }

    /// The length of the order `n` in octets (each order here fills its last octet).
    fn len(self) -> usize {
        match self {
            Curve::P256 | Curve::K256 => 32,
            Curve::P384 => 48,
        }
    }

    /// `c + 1` when `c <= n - 2`, as the scalar's big-endian octets; `None` otherwise. The
    /// test is constant-time: `c < n` is the scalar decoding's own check, and `c + 1 != 0`
    /// (that is, `c != n - 1`) a constant-time comparison of the sum with zero.
    fn accept(self, candidate: &[u8]) -> Option<Bytes> {
        macro_rules! accept {
            ($krate:ident) => {{
                use $krate::elliptic_curve::ff::{Field, PrimeField as _};
                let repr = $krate::FieldBytes::try_from(candidate).ok()?;
                let scalar: Option<$krate::Scalar> = $krate::Scalar::from_repr(repr).into();
                let key = scalar? + <$krate::Scalar as Field>::ONE;
                if bool::from(Field::is_zero(&key)) {
                    return None;
                }
                Some(Zeroizing::new(key.to_repr().to_vec()))
            }};
        }
        match self {
            Curve::P256 => accept!(p256),
            Curve::P384 => accept!(p384),
            Curve::K256 => accept!(k256),
        }
    }
}

/// `kbkdf_ec_key(curve, hash, key, fixed_prefix, fixed_suffix)`: the private scalar of the
/// first candidate the test accepts.
pub(super) fn derive(
    curve: Curve,
    hash: Sha2,
    key: &[u8],
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Bytes> {
    derive_with(curve, prefix, suffix, |fixed, len| {
        kbkdf_counter_bytes(hash, key, fixed, len)
    })
}

/// The search of [`derive`] over the candidates `candidate` gives for each fixed input.
fn derive_with(
    curve: Curve,
    prefix: &[u8],
    suffix: &[u8],
    candidate: impl Fn(&[u8], usize) -> Result<Bytes>,
) -> Result<Bytes> {
    for number in 1..=LAST_CANDIDATE {
        let mut fixed = Zeroizing::new(Vec::with_capacity(prefix.len() + 1 + suffix.len()));
        fixed.extend_from_slice(prefix);
        fixed.push(number);
        fixed.extend_from_slice(suffix);
        let c = candidate(&fixed, curve.len())?;
        if let Some(key) = curve.accept(&c) {
            return Ok(key);
        }
    }
    Err(bad("kbkdf_ec_key found no candidate below the order"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        crate::vectors::unhex(text)
    }

    /// The order of P-256 (FIPS 186-5, SP 800-186 section 3.2.1.3).
    const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    #[test]
    fn the_boundary_of_the_test() {
        let n = unhex(P256_N);
        let mut n_minus_1 = n.clone();
        n_minus_1[31] -= 1;
        let mut n_minus_2 = n.clone();
        n_minus_2[31] -= 2;
        // `n - 1`, `n` and all ones are refused; `n - 2` gives `n - 1`, zero gives one.
        for refused in [&n_minus_1, &n, &vec![0xff; 32]] {
            assert!(Curve::P256.accept(refused).is_none());
        }
        assert_eq!(
            Curve::P256.accept(&n_minus_2).unwrap().as_slice(),
            n_minus_1
        );
        let mut one = vec![0u8; 32];
        one[31] = 1;
        assert_eq!(Curve::P256.accept(&[0u8; 32]).unwrap().as_slice(), one);
        // A candidate of the wrong length is refused.
        assert!(Curve::P256.accept(&[1u8; 31]).is_none());
    }

    #[test]
    fn a_refused_candidate_moves_to_the_next_number() {
        let n = unhex(P256_N);
        // Candidate 1 is `n - 1` (refused), candidate 2 is `n` (refused), candidate 3 is 41.
        let seen = core::cell::RefCell::new(Vec::new());
        let key = derive_with(Curve::P256, b"label\0ctx", b"\0\0\x01\0", |fixed, len| {
            assert_eq!(len, 32);
            let number = fixed[9];
            seen.borrow_mut().push(fixed.to_vec());
            let mut c = match number {
                1 => n.clone(),
                2 => n.clone(),
                _ => vec![0u8; 32],
            };
            if number == 1 {
                c[31] -= 1;
            }
            if number == 3 {
                c[31] = 41;
            }
            Ok(Zeroizing::new(c))
        })
        .unwrap();
        assert_eq!(key[31], 42);
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2], b"label\0ctx\x03\0\0\x01\0");
        // Every candidate refused: an error after the last number.
        let count = core::cell::Cell::new(0u32);
        assert!(
            derive_with(Curve::P384, b"", b"", |_, len| {
                count.set(count.get() + 1);
                Ok(Zeroizing::new(vec![0xff; len]))
            })
            .is_err()
        );
        assert_eq!(count.get(), 254);
    }
}
