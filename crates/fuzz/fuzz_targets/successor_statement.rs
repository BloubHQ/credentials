//! Reads arbitrary bytes as a successor statement, a signed statement, a Sigstore trust root
//! and a release name, and checks an inclusion proof built from them.

#![no_main]

use continuity::release::{Version, is_newer};
use continuity::trust::TrustRoot;
use continuity::{SignedStatement, Statement, fuzzing};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(statement) = Statement::from_json(data) {
        // A statement that reads is never a downgrade.
        assert!(is_newer(&statement.from.release, &statement.to.release));
    }
    let _ = serde_json::from_slice::<SignedStatement>(data);
    let _ = TrustRoot::from_json(data);
    if let Ok(name) = std::str::from_utf8(data) {
        if let Ok(version) = Version::parse(name) {
            assert!(!is_newer(name, name));
            assert_eq!(version, version.clone());
        }
    }
    if data.len() >= 80 {
        let (head, rest) = data.split_at(16);
        let index = u64::from_le_bytes(head[..8].try_into().unwrap_or_default());
        let size = u64::from_le_bytes(head[8..].try_into().unwrap_or_default());
        let mut hashes = rest
            .chunks_exact(32)
            .take(66)
            .map(|c| <[u8; 32]>::try_from(c).unwrap_or_default());
        let leaf = hashes.next().unwrap_or_default();
        let root = hashes.next().unwrap_or_default();
        let path: Vec<[u8; 32]> = hashes.collect();
        fuzzing::inclusion(index, size, &leaf, &path, &root);
    }
});
