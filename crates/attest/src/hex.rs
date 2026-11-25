//! Lowercase hexadecimal, for the PCRs of `measurements.json`.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `bytes` as lowercase hexadecimal.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

fn value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Exactly `N` bytes written as `2 * N` hexadecimal digits, either case.
pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let [high, low] = pair else {
            return None;
        };
        *byte = (value(*high)? << 4) | value(*low)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0x00, 0x7f, 0x80, 0xff, 0x1a];
        assert_eq!(encode(&bytes), "007f80ff1a");
        assert_eq!(decode_array::<5>("007F80ff1a"), Some(bytes));
        assert_eq!(decode_array::<5>("007f80ff1"), None);
        assert_eq!(decode_array::<5>("007f80ff1g"), None);
        assert_eq!(decode_array::<2>("+1ab"), None);
    }
}
