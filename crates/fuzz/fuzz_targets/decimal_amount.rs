//! Reads arbitrary bytes as the decimal amounts of spending limits (`12.50`) and as integer
//! amounts in minor units. Parsing must refuse with `None`, never panic; an amount it accepts
//! prints and reads back to the same value, and minor units scale exactly.

#![no_main]

use engine::limits::{SCALE, decimal, from_minor, scaled, show};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some(value) = scaled(&text) {
        assert_eq!(scaled(&show(value)), Some(value), "show does not read back");
    }
    // The first 9 bytes, when there are that many: minor units and an exponent.
    let Some((minor, rest)) = data.split_first_chunk::<8>() else {
        return;
    };
    let minor = u64::from_le_bytes(*minor);
    let exponent = rest.first().copied().unwrap_or(0) % 12;
    let printed = decimal(minor, exponent);
    match from_minor(minor, exponent) {
        Some(value) => {
            assert!(u32::from(exponent) <= SCALE);
            assert_eq!(scaled(&printed), Some(value), "minor units scale exactly");
        }
        None => assert!(u32::from(exponent) > SCALE),
    }
});
