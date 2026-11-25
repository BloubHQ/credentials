//! Reads arbitrary bytes as a signed log entry and verifies it as a one-entry chain.

#![no_main]

use engine::keys::NodeKey;
use engine::log::{ChainVerifier, SignedEntry, verify_chain};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(entry) = serde_json::from_slice::<SignedEntry>(data) else {
        return;
    };
    let node = NodeKey::from_bytes(&mut [9u8; 32]).public();
    let _ = entry.hash();
    let chained = verify_chain(core::slice::from_ref(&entry), &node);
    let mut verifier = ChainVerifier::new(node);
    let pushed = verifier.push(&entry);
    // Both ways of verifying must agree.
    assert_eq!(chained.is_ok(), pushed.is_ok());
});
