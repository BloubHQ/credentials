//! Inflates arbitrary bytes as raw DEFLATE, zlib or gzip (the first byte picks the framing
//! and a limit): no panic; the output never passes the cap or the limit given; what inflates
//! compresses and inflates back to itself.

#![no_main]

use engine::compress::{Framing, MAX_INFLATED, deflate, inflate};
use libfuzzer_sys::fuzz_target;

const FRAMINGS: [Framing; 3] = [Framing::Raw, Framing::Zlib, Framing::Gzip];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, stream)) = data.split_first() else {
        return;
    };
    let framing = FRAMINGS[usize::from(pick) % FRAMINGS.len()];
    // Half the inputs run under a small budget, as late in an operation.
    let limit = if pick & 0x80 == 0 { usize::MAX } else { 4096 };
    let Ok(out) = inflate(stream, framing, limit) else {
        return;
    };
    assert!(out.len() <= MAX_INFLATED && out.len() <= limit);
    let again = deflate(&out, framing);
    let back = inflate(&again, framing, usize::MAX).expect("the engine reads what it writes");
    assert_eq!(back.as_slice(), out.as_slice());
});
