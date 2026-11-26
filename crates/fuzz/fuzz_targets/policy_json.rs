//! Reads arbitrary bytes as a policy and signs whatever deserializes. Signing checks every
//! rule of the policy, so it must refuse bad policies with an error, never a panic; a policy
//! it signs keeps every operation, loops and branches included, within the request bound.

#![no_main]

use engine::keys::DeviceKey;
use engine::policy::{MAX_REQUESTS, Policy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(policy) = serde_json::from_slice::<Policy>(data) else {
        return;
    };
    let _ = policy.summary();
    let _ = engine::policy::summarize(&policy, Some(&policy));
    let _ = engine::policy::summarize(&policy, Some(&Policy::new()));
    // A fixed key keeps runs reproducible; the key does not change which rules are checked.
    let device = DeviceKey::from_bytes(&mut [7u8; 32]);
    // Loops and branches: whatever the nesting, a signed operation makes at most the requests
    // of an operation, its loops counted as often as they may run.
    if let Ok(signed) = device.sign_policy(policy) {
        for operation in &signed.policy.operations {
            assert!(operation.most_requests() <= MAX_REQUESTS as u64);
        }
    }
});
