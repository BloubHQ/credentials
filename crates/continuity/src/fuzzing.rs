//! Entry points of the parsers of this crate for the fuzz targets (`crates/fuzz`). Not an API.

use crate::trust::Log;

/// Reads a certificate as the signer of a statement (the Fulcio extensions, the URIs).
pub fn certificate(der: &[u8]) {
    if let Ok(signer) = crate::x509::signer(der) {
        for arc in [
            crate::x509::ISSUER_V2,
            crate::x509::RUNNER_ENVIRONMENT,
            crate::x509::SOURCE_REPOSITORY,
            crate::x509::SOURCE_REF,
        ] {
            let _ = signer.fulcio(arc);
        }
    }
}

/// Reads a checkpoint (signed note) of a tree of `size` leaves and root `root`, against a log
/// key that is not valid (no signature verifies; every other check runs).
pub fn checkpoint(note: &str, size: u64, root: &[u8; 32]) {
    let log = Log {
        key: Vec::new(),
        key_id: [0; 32],
        valid_from_ms: 0,
        valid_until_ms: None,
    };
    let _ = crate::sigstore::checkpoint(note, size, root, &log);
}

/// Checks an inclusion proof, and that it agrees with itself for the same input.
pub fn inclusion(index: u64, size: u64, leaf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) {
    let first = crate::sigstore::inclusion(index, size, leaf, path, root);
    assert_eq!(
        first,
        crate::sigstore::inclusion(index, size, leaf, path, root)
    );
}

/// Reads a log entry body (a hashedrekord) against a digest, a signature and a certificate.
pub fn rekord_body(body: &[u8]) {
    let _ = crate::sigstore::check_body(body, &[0; 32], b"", b"");
}
