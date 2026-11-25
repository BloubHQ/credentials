//! Node continuity on the owner's device (`docs/design.md`, section 10).
//!
//! When a node hands over, the owner has nothing to do: grants that allow a successor move
//! with it. When the old node is gone (it crashed, its instance was stopped), nothing can be
//! handed over, and the owner grants again. This module is that path: it checks a node of a
//! newer release against the signed successor statement of the release the owner had granted
//! to, and re-grants to it according to the owner's [`SuccessorPolicy`].
//!
//! [`verify_successor`] checks, in order:
//! - the successor statement: its Sigstore bundle (certificate chain to the pinned Fulcio
//!   root, signed by the release workflow of this repository at the tag of the newer
//!   release, logged in Rekor with a signed entry timestamp and an inclusion proof), never a
//!   downgrade, and that it starts from the release the owner granted to;
//! - the attestation document of the new node: chain to the pinned AWS root, nonce, not a
//!   debug enclave, the measurements the statement lists for the newer release and nothing
//!   else, and that it vouches for the node identity.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use continuity::sigstore::WorkflowIdentity;
use continuity::trust::TrustRoot;
use continuity::{SignedStatement, verify_statement};
use engine::grant::NodeIdentity;
use rustls_pki_types::CertificateDer;

use crate::attestation::{Nonce, VerifiedNode, identity};
use crate::error::{ClientError, Result};
use crate::time::now_ms;

/// What the owner decided about re-granting to a successor when the old node is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub enum SuccessorPolicy {
    /// Re-grant to a verified successor without asking: the app may do it in the background.
    Automatic,
    /// Ask the owner each time: [`regrant`] refuses unless the app says the owner approved.
    AskOwner,
    /// Never re-grant to a successor: the owner grants from scratch.
    Never,
}

impl From<continuity::Error> for ClientError {
    fn from(error: continuity::Error) -> Self {
        let error = match error {
            continuity::Error::Attestation(inner) => return inner.into(),
            other => other,
        };
        let reason = match &error {
            continuity::Error::Downgrade { .. } => "downgrade",
            continuity::Error::StatementNotForThisRelease => "not_for_this_release",
            continuity::Error::StatementInvalid(_) | continuity::Error::ReleaseInvalid(_) => {
                "statement_invalid"
            }
            continuity::Error::TrustRootEmpty => "trust_root_empty",
            continuity::Error::ChainUntrusted(_) => "chain_untrusted",
            continuity::Error::IdentityMismatch(_) => "signer_mismatch",
            continuity::Error::SignatureInvalid(_) => "signature_invalid",
            continuity::Error::LogEntryMismatch(_)
            | continuity::Error::LogUntrusted
            | continuity::Error::LogProofInvalid(_) => "log_proof_invalid",
            continuity::Error::BundleInvalid(_) => "bundle_invalid",
            _ => "statement_invalid",
        };
        ClientError::SuccessorRefused {
            reason: reason.into(),
            detail: error.to_string(),
        }
    }
}

/// The checks of [`verify_successor`], with the roots it trusts.
pub(crate) fn check_successor(
    document: &[u8],
    nonce: &Nonce,
    statement: &SignedStatement,
    previous_release: &str,
    node: NodeIdentity,
    trust: &TrustRoot,
    nitro_roots: &[CertificateDer<'static>],
) -> Result<VerifiedNode> {
    let now = now_ms();
    let nonce = nonce.take(now)?;
    let verified = verify_statement(statement, trust, &WorkflowIdentity::release_workflow())?;
    if verified.statement.from.release != previous_release {
        return Err(continuity::Error::StatementNotForThisRelease.into());
    }
    let to = verified.statement.to;
    let document = attest::verify(document, nonce, std::slice::from_ref(&to), nitro_roots)?;
    attest::bind(&node, &document)?;
    VerifiedNode::from_verified(node, document, now, Some(previous_release.to_string()))
}

fn trust_root(trusted_root_json: Option<String>) -> Result<TrustRoot> {
    Ok(match trusted_root_json {
        Some(json) => TrustRoot::from_json(json.as_bytes())?,
        None => TrustRoot::production()?,
    })
}

/// Verifies a node of a newer release as the successor of `previous_release` (the release
/// of the node the owner had granted to, [`VerifiedNode::release`]), when that node is gone.
///
/// `statement` and `bundle` are the `successor.json` and `successor.sigstore.json` the newer
/// release publishes; `document`, `nonce` and `identity_json` are as for
/// [`crate::verify_node`]. `trusted_root_json` replaces the Sigstore trust root compiled in
/// (a `trusted_root.json` the app updated through Sigstore's TUF repository); leave it out
/// to use the compiled one. The nonce is used up, even when the check fails.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn verify_successor(
    document: Vec<u8>,
    nonce: Arc<Nonce>,
    statement: Vec<u8>,
    bundle: Vec<u8>,
    previous_release: String,
    identity_json: String,
    trusted_root_json: Option<String>,
) -> Result<Arc<VerifiedNode>> {
    let parsed = identity(&identity_json).and_then(|node| {
        let signed = SignedStatement::from_files(&statement, &bundle)?;
        Ok((node, signed, trust_root(trusted_root_json)?))
    });
    let (node, signed, trust) = parsed.inspect_err(|_| {
        nonce.used.store(true, Ordering::SeqCst);
    })?;
    check_successor(
        &document,
        &nonce,
        &signed,
        &previous_release,
        node,
        &trust,
        &[attest::aws_root()],
    )
    .map(Arc::new)
}

/// Re-grants to a successor `node` (from [`verify_successor`]) after the old node is gone,
/// as [`crate::grant`] does, if `policy` allows: [`SuccessorPolicy::Automatic`] always,
/// [`SuccessorPolicy::AskOwner`] only with `owner_approved`, [`SuccessorPolicy::Never`]
/// never. The grant allows a further successor.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
#[allow(clippy::too_many_arguments)]
pub fn regrant(
    mut device_key: String,
    mut user_key: String,
    node: Arc<VerifiedNode>,
    owner: String,
    valid_for_secs: u64,
    pins_json: Vec<String>,
    policy: SuccessorPolicy,
    owner_approved: bool,
) -> Result<String> {
    let refused = if node.successor_of.is_none() {
        Some("this node was not verified as a successor (verify_successor): grant to it with grant")
    } else {
        match (policy, owner_approved) {
            (SuccessorPolicy::Never, _) => {
                Some("the owner's policy is never to re-grant to a successor")
            }
            (SuccessorPolicy::AskOwner, false) => {
                Some("the owner's policy is to be asked: ask, then call again")
            }
            _ => None,
        }
    };
    if let Some(detail) = refused {
        zeroize::Zeroize::zeroize(&mut device_key);
        zeroize::Zeroize::zeroize(&mut user_key);
        return Err(ClientError::Refused {
            detail: detail.into(),
        });
    }
    crate::owner::grant_with(
        device_key,
        user_key,
        &node,
        owner,
        valid_for_secs,
        pins_json,
        true,
    )
}
