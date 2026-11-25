//! Converts arbitrary bytes read as a policy of the format before steps. The converter must
//! refuse bad input with an error, never a panic, and what it gives must be a policy that
//! signs or is refused with an error.

#![no_main]

use engine::keys::DeviceKey;
use engine::policy::legacy::upgrade_json;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(upgrade) = upgrade_json(text) else {
        return;
    };
    assert!(
        !upgrade.notes.is_empty(),
        "a conversion always says to sign again"
    );
    let _ = upgrade.policy.summary();
    let device = DeviceKey::from_bytes(&mut [7u8; 32]);
    let _ = device.sign_policy(upgrade.policy);
});
