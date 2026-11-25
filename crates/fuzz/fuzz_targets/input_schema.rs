//! Checks arbitrary bytes against fixed JSON, RLP and raw input schemas. A schema must refuse
//! bad input with an error, never a panic; what it accepts must pass the same schema again
//! (the output is the checked value, re-serialized), except for members the node sets.

#![no_main]

use engine::policy::Input;
use libfuzzer_sys::fuzz_target;

const SCHEMAS: [&str; 3] = [
    r#"{"json": {"members": [
        {"pointer": "/aud", "type": "string", "equals": "https://api.example.com"},
        {"pointer": "/scope", "one_of": ["read", "write"]},
        {"pointer": "/amount", "type": "number", "min": "1", "max": "100000"},
        {"pointer": "/tags", "type": "array", "optional": true},
        {"pointer": "/note", "optional": true},
        {"pointer": "/exp", "set": "unix", "offset": 300}
    ]}}"#,
    r#"{"rlp": {"prefix": "02", "items": [
        {"pointer": "/0", "equals": "01"},
        {"pointer": "/1"},
        {"pointer": "/2", "max": "5208"},
        {"pointer": "/3", "equals": "1111111111111111111111111111111111111111"},
        {"pointer": "/4", "min": "01", "max": "0de0b6b3a7640000"},
        {"pointer": "/5", "one_of": ["", "00"]},
        {"pointer": "/6", "optional": true},
        {"pointer": "/6/0", "optional": true}
    ]}}"#,
    r#"{"raw": {"max_len": 64, "pattern": "[a-z0-9]+"}}"#,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, input)) = data.split_first() else {
        return;
    };
    let Some(schema) = SCHEMAS.get(usize::from(pick) % SCHEMAS.len()) else {
        return;
    };
    let Ok(schema) = serde_json::from_str::<Input>(schema) else {
        return;
    };
    let now_ms = 1_700_000_000_000;
    if let Ok(checked) = schema.apply(input, now_ms) {
        assert!(
            schema.apply(&checked, now_ms).is_ok(),
            "an accepted input is refused once checked"
        );
    }
});
