//! Reads arbitrary bytes as the decimal amounts of spending limits (`12.50`) and as integer
//! amounts in minor units. Parsing must refuse with `None`, never panic; an amount it accepts
//! prints and reads back to the same value, and minor units scale exactly. The same bytes are
//! read as the amount of a body (`policy::read_amount`), in minor units and as a decimal, as a
//! JSON number and as text: an amount it accepts is within the bounds and prints back as the
//! very text it read, so no other spelling of an amount is ever counted.

#![no_main]

use engine::limits::{SCALE, decimal, from_minor, scaled, show};
use engine::policy::{AmountFormat, MAX_AMOUNT, MAX_JSON_NUMBER_AMOUNT, read_amount};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some(value) = scaled(&text) {
        assert_eq!(scaled(&show(value)), Some(value), "show does not read back");
    }
    let places = data.first().copied().unwrap_or(0) % 9;
    for format in [AmountFormat::Minor, AmountFormat::Decimal] {
        for number in [false, true] {
            let Some(minor) = read_amount(&text, number, format, places) else {
                continue;
            };
            let most = if number {
                MAX_JSON_NUMBER_AMOUNT
            } else {
                MAX_AMOUNT
            };
            assert!(minor <= most, "an amount above the bound was read");
            let printed = match format {
                AmountFormat::Minor => minor.to_string(),
                AmountFormat::Decimal => {
                    assert!(!number, "a decimal JSON number was read");
                    decimal(minor, places)
                }
            };
            assert_eq!(printed, text, "an amount read from another spelling");
        }
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
