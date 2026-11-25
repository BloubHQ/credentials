//! Node continuity (`docs/design.md`, section 10).
//!
//! A Nitro node has no sealed storage: a new release is a new node. This crate lets an old node
//! hand its state to a node of a newer release without anyone else (the host, the operator)
//! seeing or choosing what moves:
//!
//! - [`statement`]: successor statements, "release X may hand over to the measurements of
//!   release Y", signed by the release workflow with Sigstore keyless signing;
//! - [`sigstore`] and [`trust`]: their offline verification against a pinned Fulcio root, the
//!   workflow identity compiled into the node, and a pinned Rekor key (signed entry timestamp
//!   and inclusion proof);
//! - [`release`]: the order of releases, so no hand-over goes to an older one;
//! - [`protocol`]: the four messages between the two nodes, each attesting the other.
//!
//! The `client` crate uses the same checks when an owner re-grants to a successor after the
//! old node is gone, and `credentials verify` when it checks a chain across a hand-over.
//!
//! With the `testing` feature, [`testing`] makes test roots (Nitro and Sigstore) at run time,
//! for tests only.

mod der;
#[doc(hidden)]
pub mod fuzzing;
pub mod protocol;
pub mod release;
pub mod sigstore;
pub mod statement;
pub mod trust;
pub mod wire;
mod x509;

#[cfg(feature = "testing")]
pub mod testing;

pub use protocol::{Attester, Challenge, Checks, Offer, Package, Predecessor, SuccessorSide};
pub use statement::{SignedStatement, Statement, VerifiedStatement, verify_statement};

/// Why a statement or a hand-over was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The statement is not one: its form, type or size.
    #[error("successor statement invalid: {0}")]
    StatementInvalid(&'static str),
    /// A release name is not a version.
    #[error("release name {0:?} is not a version (vMAJOR.MINOR.PATCH)")]
    ReleaseInvalid(String),
    /// The statement hands over to a release that is not newer.
    #[error("downgrade refused: {from} to {to}")]
    Downgrade {
        /// The release handing over.
        from: String,
        /// The release it would hand over to.
        to: String,
    },
    /// The statement is not about this node's release.
    #[error("the successor statement is not for the release of this node")]
    StatementNotForThisRelease,
    /// The Sigstore bundle is not one, or not of the form signed here.
    #[error("Sigstore bundle invalid: {0}")]
    BundleInvalid(&'static str),
    /// The trust root holds no authority or no log: nothing can be verified.
    #[error(
        "the Sigstore trust root of this build is empty: commit the trusted_root.json of the Sigstore root of trust (crates/continuity/trust)"
    )]
    TrustRootEmpty,
    /// The trust root cannot be read.
    #[error("Sigstore trust root invalid: {0}")]
    TrustRootInvalid(&'static str),
    /// A certificate cannot be read.
    #[error("certificate malformed: {0}")]
    CertificateMalformed(&'static str),
    /// The signing certificate does not chain to a pinned Fulcio root at the time of the log.
    #[error("the signing certificate is not trusted: {0}")]
    ChainUntrusted(String),
    /// The signing certificate is not the expected signer's.
    #[error("signer refused: {0}")]
    IdentityMismatch(&'static str),
    /// The signature over the statement does not verify.
    #[error("signature invalid: {0}")]
    SignatureInvalid(&'static str),
    /// The log entry is not the one of this signature.
    #[error("transparency log entry mismatch: {0}")]
    LogEntryMismatch(&'static str),
    /// The log is not a pinned one, or its key was not valid then.
    #[error("the transparency log is not trusted")]
    LogUntrusted,
    /// The signed entry timestamp or the inclusion proof does not verify.
    #[error("transparency log proof invalid: {0}")]
    LogProofInvalid(&'static str),
    /// The peer's attestation document was refused.
    #[error("attestation refused: {0}")]
    Attestation(#[from] attest::Error),
    /// This node could not attest itself.
    #[error("attestation of this node failed: {0}")]
    Attester(String),
    /// A message of the protocol does not fit the one before it.
    #[error("hand-over protocol: {0}")]
    Protocol(&'static str),
    /// The connection to the other side failed.
    #[error("hand-over transport: {0}")]
    Transport(String),
    /// The other side refused, and said why.
    #[error("the enclave refused: {0}")]
    Refused(String),
    /// The node refused.
    #[error("node: {0}")]
    Engine(#[from] engine::Error),
}

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;
