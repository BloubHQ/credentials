//! Reads arbitrary bytes as a Fulcio signing certificate (the DER reader of the continuity
//! crate: extensions, subject alternative names, the Fulcio OIDs), as a Rekor log entry body
//! and as a checkpoint.

#![no_main]

use continuity::fuzzing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzzing::certificate(data);
    fuzzing::rekord_body(data);
    if let Ok(note) = std::str::from_utf8(data) {
        fuzzing::checkpoint(note, 7, &[0; 32]);
    }
});
