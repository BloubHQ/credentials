//! Successor statements: "release X may hand over to the measurements of release Y".
//!
//! The release workflow of release Y writes one per release it succeeds, as JSON:
//!
//! ```json
//! {"type": "https://github.com/BloubHQ/credentials/successor/v1",
//!  "from": {"release": "v1.0.0", "git_commit": "...", "pcr0": "...", "pcr1": "...", "pcr2": "..."},
//!  "to":   {"release": "v1.1.0", "git_commit": "...", "pcr0": "...", "pcr1": "...", "pcr2": "..."}}
//! ```
//!
//! and signs the exact bytes with Sigstore keyless signing (`cosign sign-blob --bundle`), as
//! the release workflow at the tag of Y. A [`SignedStatement`] carries the bytes and the
//! bundle; [`verify_statement`] checks both.

use attest::Measurement;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::release::Version;
use crate::sigstore::{self, Bundle, WorkflowIdentity};
use crate::trust::TrustRoot;
use crate::{Error, Result};

/// The `type` of a successor statement.
pub const STATEMENT_TYPE: &str = "https://github.com/BloubHQ/credentials/successor/v1";

/// The largest statement accepted, in bytes.
pub const MAX_STATEMENT_LEN: usize = 16 * 1024;

/// What a successor statement says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// [`STATEMENT_TYPE`].
    #[serde(rename = "type")]
    pub kind: String,
    /// The release that may hand over, and its measurements.
    pub from: Measurement,
    /// The release it may hand over to, and its measurements.
    pub to: Measurement,
}

impl Statement {
    /// Reads a statement (JSON) and checks its form: the type, two different releases whose
    /// names are versions, and `to` newer than `from`.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_STATEMENT_LEN {
            return Err(Error::StatementInvalid("larger than a statement may be"));
        }
        let statement: Statement = serde_json::from_slice(bytes)
            .map_err(|_| Error::StatementInvalid("not a successor statement"))?;
        if statement.kind != STATEMENT_TYPE {
            return Err(Error::StatementInvalid("not a successor statement type"));
        }
        let from = Version::parse(&statement.from.release)?;
        let to = Version::parse(&statement.to.release)?;
        if to <= from {
            return Err(Error::Downgrade {
                from: statement.from.release.clone(),
                to: statement.to.release.clone(),
            });
        }
        Ok(statement)
    }
}

/// A successor statement and its Sigstore bundle, as they travel: `{"statement":
/// "<base64url of the exact bytes signed>", "bundle": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStatement {
    /// The bytes of the statement, as signed.
    #[serde(with = "b64url")]
    pub statement: Vec<u8>,
    /// The Sigstore bundle of its signature.
    pub bundle: Bundle,
}

impl SignedStatement {
    /// Reads the two files the release publishes: `successor.json` and
    /// `successor.sigstore.json`.
    pub fn from_files(statement: &[u8], bundle: &[u8]) -> Result<Self> {
        Ok(Self {
            statement: statement.to_vec(),
            bundle: Bundle::from_json(bundle)?,
        })
    }
}

mod b64url {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::URL_SAFE_NO_PAD.encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        if text.len() > super::MAX_STATEMENT_LEN.saturating_mul(2) {
            return Err(de::Error::custom("too long"));
        }
        super::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| de::Error::custom("invalid base64url"))
    }
}

/// A statement whose signature, signer and log entry verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatement {
    /// What it says.
    pub statement: Statement,
    /// SHA-256 of its bytes, which the hand-over entry names.
    pub sha256: [u8; 32],
    /// When Rekor logged it, Unix seconds.
    pub integrated_time: u64,
    /// Its index in Rekor.
    pub log_index: u64,
}

/// Verifies a signed statement: its form ([`Statement::from_json`]: never a downgrade) and its
/// Sigstore bundle, signed by `identity` at the tag of the `to` release, logged in a log of
/// `trust` ([`sigstore::verify`]).
pub fn verify_statement(
    signed: &SignedStatement,
    trust: &TrustRoot,
    identity: &WorkflowIdentity,
) -> Result<VerifiedStatement> {
    let statement = Statement::from_json(&signed.statement)?;
    let verified = sigstore::verify(
        &signed.bundle,
        &signed.statement,
        &statement.to.release,
        identity,
        trust,
    )?;
    Ok(VerifiedStatement {
        statement,
        sha256: Sha256::digest(&signed.statement).into(),
        integrated_time: verified.integrated_time,
        log_index: verified.log_index,
    })
}
