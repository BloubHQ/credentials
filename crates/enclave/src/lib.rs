//! A credentials node inside an AWS Nitro Enclave.
//!
//! The `enclave` program generates a fresh node key at every boot (an enclave has no sealed
//! storage: a restarted enclave is a new node, and owners grant to it again), then serves the
//! HTTP API of `credentials serve` on vsock port [`relay::HTTP_PORT`], plus
//! `GET /attestation?nonce=<base64url>`: an attestation document of the Nitro Secure Module
//! whose `user_data` is [`engine::grant::NodeIdentity::report_data`] and whose `nonce` is the
//! caller's. An owner verifies the document (its certificate chain to the AWS Nitro root, and
//! PCR0, PCR1 and PCR2 against the published measurements of a release), then that its
//! `user_data` is the report data of the identity it is about to grant to.
//!
//! The enclave has no network and no disk. Its bytes reach destinations through the egress
//! relay of the host (TLS ends inside the enclave), and its log entries are stored by the log
//! writer of the host, which confirms each only after it is synced (see
//! [`relay`]). `credentials host` is that host program.
//!
//! The parts that need Nitro hardware (the `nitro` module) are compiled on Linux only; the
//! attestation endpoint ([`attestation`]) is portable and tested with a stand-in for the NSM.

//!
//! Node continuity: a node of a release built by the release workflow (which sets
//! `CREDENTIALS_RELEASE`, [`RELEASE`]) also listens on vsock port
//! [`continuity::wire::HANDOVER_PORT`] for the hand-over protocol, driven by
//! `credentials host hand-over`: it hands its state to a node of a newer release named by a
//! successor statement, or takes over from one. See `docs/design.md`, section 10.

pub mod attestation;

/// The release this image was built as (`CREDENTIALS_RELEASE` at build time, set by
/// `build/build.sh` from the tag). `None` for a build that is not a release: such a node
/// neither hands over nor takes over, as no successor statement can name it.
pub const RELEASE: Option<&str> = option_env!("CREDENTIALS_RELEASE");

/// The checks of the hand-over for this image, or why it cannot take part (not a release, or
/// no Sigstore trust root compiled in).
pub fn hand_over_checks() -> Result<continuity::Checks, String> {
    let release = RELEASE
        .filter(|release| !release.is_empty())
        .ok_or("this image is not a release build (no CREDENTIALS_RELEASE)")?;
    let checks = continuity::Checks::production(release).map_err(|e| e.to_string())?;
    if checks.trust.is_empty() {
        return Err(continuity::Error::TrustRootEmpty.to_string());
    }
    Ok(checks)
}

#[cfg(target_os = "linux")]
pub mod nitro;
