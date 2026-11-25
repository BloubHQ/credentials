//! Reads arbitrary bytes as a Sigstore bundle and verifies it as the signature of a successor
//! statement, against a trust root whose authority and log are not real keys: every parser of
//! the bundle and of its certificate runs, and nothing verifies.

#![no_main]

use continuity::sigstore::{Bundle, WorkflowIdentity, verify};
use continuity::trust::{Authority, Log, TrustRoot};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(bundle) = Bundle::from_json(data) else {
        return;
    };
    let trust = TrustRoot {
        authorities: vec![Authority {
            root: vec![0x30, 0x00],
            intermediates: Vec::new(),
            valid_from_ms: 0,
            valid_until_ms: None,
        }],
        logs: vec![Log {
            key: Vec::new(),
            key_id: [0; 32],
            valid_from_ms: 0,
            valid_until_ms: None,
        }],
    };
    let verified = verify(
        &bundle,
        b"statement",
        "v1.0.0",
        &WorkflowIdentity::release_workflow(),
        &trust,
    );
    assert!(
        verified.is_err(),
        "a bundle verified under keys that are not keys"
    );
});
