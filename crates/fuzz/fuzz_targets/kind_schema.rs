//! Reads arbitrary bytes as a kind of item: a schema of fields with checks (a custom kind is
//! the owner's, so it is input like a policy). Validating it, signing it, checking values of
//! every field against it with every check, masking them, and binding it into a policy must
//! fail with an error, never a panic.

#![no_main]

use engine::fields::Fields;
use engine::item::{ItemBinding, KindSchema, describe};
use engine::keys::DeviceKey;
use engine::policy::{FieldSpec, Policy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first line is the kind; what follows, the value checked against each field.
    let (head, value) = match data.iter().position(|b| *b == b'\n') {
        Some(at) => data.split_at(at),
        None => (data, &[][..]),
    };
    let Ok(kind) = serde_json::from_slice::<KindSchema>(head) else {
        return;
    };
    let _ = kind.validate();
    let flags: Vec<String> = kind.signoff_flags().iter().map(|s| s.to_string()).collect();
    let other = |_: &str| Some(value.to_vec());
    for field in &kind.fields {
        let _ = kind.check_value(&field.name, value, &flags, Some(1_800_000_000_000), &other);
        let _ = kind.check_value(&field.name, value, &[], None, &|_| None);
    }
    // A fixed key keeps runs reproducible.
    let device = DeviceKey::from_bytes(&mut [7u8; 32]);
    let Ok(signed) = device.sign_kind(kind) else {
        return;
    };
    let _ = signed.verify_any(&[device.public()]);
    // Bound into a policy that declares every field, with the value as every pin and field.
    let mut binding = ItemBinding::custom(signed.clone());
    let mut policy = Policy::new();
    let mut fields = Fields::new();
    let text = String::from_utf8_lossy(value);
    for field in &signed.kind.fields {
        binding = binding.pin(&field.name, &text);
        policy = policy.with_field(FieldSpec::secret(&field.name));
        if !value.is_empty() {
            let _ = fields.insert(&field.name, value.to_vec());
        }
    }
    let policy = policy.with_item(binding);
    let _ = policy.validate();
    let _ = engine::item::check_values(&policy, &fields, Some(1_800_000_000_000));
    let _ = describe(&policy, &fields);
    let _ = engine::policy::summarize(&policy, None);
});
