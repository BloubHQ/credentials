//! Reads arbitrary bytes as a policy and signs whatever deserializes. Signing checks every
//! rule of the policy, so it must refuse bad policies with an error, never a panic.

#![no_main]

use engine::keys::DeviceKey;
use engine::policy::Policy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(policy) = serde_json::from_slice::<Policy>(data) else {
        return;
    };
    let _ = policy.summary();
    // A fixed key keeps runs reproducible; the key does not change which rules are checked.
    let device = DeviceKey::from_bytes(&mut [7u8; 32]);
    let _ = device.sign_policy(policy);
});
