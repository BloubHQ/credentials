//! A secret placed in arbitrary bytes, in one of the forms the search knows, split into
//! arbitrary pieces: the stream search must find it and release no byte of it. Clean bytes
//! come out whole and in order. A chunked body decoder must not panic on any input. The search
//! is the one of a secret field (`Scrubber::for_secret`): its forms are found in any case of
//! percent and hex escapes, and in a longer base64 value.

#![no_main]

use engine::reflection::{Scrubber, forms};
use engine::response::BodyDecoder;
use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"s3cr3t-T0KEN/+=\"value";

fuzz_target!(|data: &[u8]| {
    let [form_at, step, cut, rest @ ..] = data else {
        return;
    };
    let mut decoder = BodyDecoder::chunked();
    let _ = decoder.push(rest);
    let _ = decoder.end();

    let all = forms(SECRET).unwrap_or_default();
    let Some(form) = all.get(usize::from(*form_at) % all.len().max(1)) else {
        return;
    };
    let at = usize::from(*cut).min(rest.len());
    let mut stream = rest[..at].to_vec();
    stream.extend_from_slice(form);
    stream.extend_from_slice(&rest[at..]);
    let step = usize::from(*step).max(1);
    let Ok(mut scrubber) = Scrubber::for_secret(SECRET) else {
        return;
    };
    let mut out = Vec::new();
    let mut found = false;
    for piece in stream.chunks(step) {
        match scrubber.push(piece) {
            Ok(released) => out.extend_from_slice(&released),
            Err(_) => {
                found = true;
                break;
            }
        }
    }
    assert!(found, "a secret in the stream was not found");
    assert!(out.len() <= at, "bytes of the secret were released");

    // Clean bytes pass whole (or are refused when they hold the secret in an escaped form).
    let Ok(mut scrubber) = Scrubber::for_secret(SECRET) else {
        return;
    };
    let mut out = Vec::new();
    for piece in rest.chunks(step) {
        match scrubber.push(piece) {
            Ok(released) => out.extend_from_slice(&released),
            Err(_) => return,
        }
    }
    out.extend_from_slice(&scrubber.finish());
    assert_eq!(out, rest);
});
