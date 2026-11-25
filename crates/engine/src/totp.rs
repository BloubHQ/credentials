//! TOTP (RFC 6238) with HMAC-SHA-1.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::{Error, Result};

/// The code of `seed` at `unix_seconds`, with `digits` digits and a step of `period` seconds.
pub(crate) fn code(seed: &[u8], unix_seconds: u64, digits: u32, period: u64) -> Result<u32> {
    if !(6..=9).contains(&digits) || period == 0 || seed.is_empty() {
        return Err(Error::TemplateInvalid {
            rule: "totp digits or period out of range",
        });
    }
    let counter = unix_seconds / period;
    let mut mac = Hmac::<Sha1>::new_from_slice(seed).map_err(|_| Error::KeyInvalid)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash.get(19).copied().ok_or(Error::Encoding)? & 0x0f);
    let window: [u8; 4] = hash
        .get(offset..offset + 4)
        .ok_or(Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)?;
    Ok((u32::from_be_bytes(window) & 0x7fff_ffff) % 10u32.pow(digits))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::code;

    /// The SHA-1 vectors of RFC 6238, appendix B.
    #[test]
    fn rfc6238_vectors() {
        let seed = b"12345678901234567890";
        for (time, expected) in [
            (59, 94_287_082),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(code(seed, time, 8, 30).unwrap(), expected, "time {time}");
            assert_eq!(code(seed, time, 6, 30).unwrap(), expected % 1_000_000);
        }
    }
}
