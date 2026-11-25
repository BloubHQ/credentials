//! `credentials attest`, and the attestation check of `credentials grant`: an AWS Nitro
//! Enclaves attestation document of the node, checked with the `attest` crate against the
//! pinned AWS root, a nonce and the measurements of accepted releases.

use std::io::Read;
use std::path::Path;

use attest::{Measurements, Verified};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::grant::NodeIdentity;

use crate::files::{Failure, Res, exit};

/// The fewest bytes of a nonce: it must not be guessed before the node answers.
const MIN_NONCE: usize = 16;

/// Reads a document from a file, or from stdin when `path` is `-`. Reading stops one byte past
/// the largest document, which `attest::verify` then refuses.
fn read_document(path: &Path) -> Res<Vec<u8>> {
    let limit = u64::try_from(attest::MAX_DOCUMENT_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut out = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut out)
            .map_err(|e| Failure::io(format!("cannot read the document from stdin: {e}")))?;
    } else {
        std::fs::File::open(path)
            .and_then(|file| file.take(limit).read_to_end(&mut out))
            .map_err(|e| Failure::io(format!("cannot read {}: {e}", path.display())))?;
    }
    Ok(out)
}

/// A nonce in base64url (padding allowed), at least [`MIN_NONCE`] bytes.
fn read_nonce(text: &str) -> Res<Vec<u8>> {
    let nonce = URL_SAFE_NO_PAD
        .decode(text.trim().trim_end_matches('='))
        .map_err(|_| Failure::usage(format!("--nonce {text:?}: not base64url")))?;
    if nonce.len() < MIN_NONCE {
        return Err(Failure::usage(format!(
            "--nonce: {} bytes; a nonce is at least {MIN_NONCE} random bytes",
            nonce.len()
        )));
    }
    Ok(nonce)
}

/// The failure of an attestation check: a refused document exits 3, a measurements file that
/// cannot be read 5, an invalid one 1.
fn failure(error: attest::Error) -> Failure {
    match error {
        attest::Error::Io { .. } => Failure::io(error.to_string()),
        attest::Error::Measurements(_) => Failure::new(exit::OTHER, error.to_string()),
        refused => Failure::new(exit::REFUSED, format!("attestation refused: {refused}")),
    }
}

/// Verifies the document against the pinned AWS root and the measurements, and, when an
/// identity is given, that it binds that identity.
pub fn check(
    document: &Path,
    nonce: &str,
    measurements: &Path,
    identity: Option<&NodeIdentity>,
) -> Res<Verified> {
    let nonce = read_nonce(nonce)?;
    let accepted = Measurements::load(measurements).map_err(failure)?;
    let bytes = read_document(document)?;
    let verified = attest::verify(&bytes, &nonce, accepted.as_slice(), &[attest::aws_root()])
        .map_err(failure)?;
    if let Some(identity) = identity {
        attest::bind(identity, &verified).map_err(failure)?;
    }
    Ok(verified)
}

/// Prints what a verified document states.
pub fn print(verified: &Verified, identity: Option<&NodeIdentity>) {
    println!("attestation verified");
    println!("release: {}", verified.release);
    println!("module: {}", verified.module_id);
    println!("time: {}", verify::rfc3339(verified.timestamp_ms));
    for index in 0..3 {
        if let Some(pcr) = verified.pcr(index) {
            println!("pcr{index}: {}", attest::to_hex(pcr));
        }
    }
    match identity {
        Some(identity) => println!(
            "binding: the document vouches for node {} (seal key {})",
            identity.log_key.to_b64(),
            identity.seal_key.to_b64()
        ),
        None => println!("binding: not checked (give --identity <node identity json>)"),
    }
}

/// `credentials attest`.
pub fn attest(
    document: &Path,
    nonce: &str,
    measurements: &Path,
    identity: Option<&Path>,
) -> Res<()> {
    let identity: Option<NodeIdentity> = identity.map(crate::files::read_json).transpose()?;
    let verified = check(document, nonce, measurements, identity.as_ref())?;
    print(&verified, identity.as_ref());
    Ok(())
}
