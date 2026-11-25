//! Reads arbitrary bytes as a Nitro attestation document. A document no one signed must never
//! verify, and parsing must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let measurement = attest::Measurement {
        release: "fuzz".into(),
        git_commit: None,
        pcr0: [1; attest::PCR_LEN],
        pcr1: [1; attest::PCR_LEN],
        pcr2: [1; attest::PCR_LEN],
    };
    let verified = attest::verify(data, b"nonce", &[measurement], &[attest::aws_root()]);
    assert!(verified.is_err());
});
