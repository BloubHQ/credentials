//! Checking a node before a grant: a fresh [`Nonce`], the attestation document the node
//! answers with, and a [`VerifiedNode`] that only [`verify_node`] makes and [`crate::grant`]
//! requires.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::grant::NodeIdentity;
use serde::Deserialize;

use crate::error::{ClientError, Result};
use crate::time::now_ms;

/// The bytes of a nonce.
pub const NONCE_LEN: usize = 32;

/// How long a nonce, and then a verified node, may be used: five minutes, the window in which
/// a node accepts a grant by its issue time.
pub const MAX_AGE_MS: u64 = engine::caller::MAX_SKEW_MS;

/// A random nonce for one attestation request. Send [`Nonce::to_b64`] to the node
/// (`GET /attestation?nonce=<base64url>`), then hand the nonce to [`verify_node`] with the
/// answer. A nonce is good for one verification, within [`MAX_AGE_MS`].
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
#[derive(Debug)]
pub struct Nonce {
    bytes: [u8; NONCE_LEN],
    created_ms: u64,
    pub(crate) used: AtomicBool,
}

impl Nonce {
    pub(crate) fn from_parts(bytes: [u8; NONCE_LEN], created_ms: u64) -> Self {
        Self {
            bytes,
            created_ms,
            used: AtomicBool::new(false),
        }
    }

    /// Marks the nonce used and checks it was not used before and is not too old.
    pub(crate) fn take(&self, now: u64) -> Result<&[u8; NONCE_LEN]> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(ClientError::NonceRejected {
                detail: "this nonce was already used: ask the node again with a new one".into(),
            });
        }
        if now.saturating_sub(self.created_ms) > MAX_AGE_MS {
            return Err(ClientError::NonceRejected {
                detail: "this nonce is older than five minutes: ask the node again with a new one"
                    .into(),
            });
        }
        Ok(&self.bytes)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
impl Nonce {
    /// The bytes of the nonce.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// The nonce as unpadded base64url, for `GET /attestation?nonce=`.
    pub fn to_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.bytes)
    }
}

/// A new random nonce of [`NONCE_LEN`] bytes.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn nonce() -> Result<Arc<Nonce>> {
    let mut bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut bytes).map_err(|e| ClientError::Refused {
        detail: format!("no random source: {e}"),
    })?;
    Ok(Arc::new(Nonce::from_parts(bytes, now_ms())))
}

/// A node whose attestation document verified against the pinned AWS root, a nonce of this
/// app, and an accepted release, and which vouches for the node identity. Only
/// [`verify_node`] and [`verify_attestation_reply`] make one; a grant takes it within
/// [`MAX_AGE_MS`].
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Object))]
#[derive(Debug)]
pub struct VerifiedNode {
    pub(crate) identity: NodeIdentity,
    identity_json: String,
    release: String,
    module_id: String,
    timestamp_ms: u64,
    pcrs: BTreeMap<u8, String>,
    pub(crate) verified_ms: u64,
    /// For a node verified by [`crate::verify_successor`]: the release it succeeds.
    pub(crate) successor_of: Option<String>,
}

impl VerifiedNode {
    /// A verified node for the tests of the grant flow, which have no attestation document of
    /// the node they run.
    #[cfg(test)]
    pub(crate) fn for_test(identity: NodeIdentity, verified_ms: u64) -> Self {
        Self {
            identity_json: serde_json::to_string(&identity).unwrap_or_default(),
            identity,
            release: "test".into(),
            module_id: "test".into(),
            timestamp_ms: verified_ms,
            pcrs: BTreeMap::new(),
            verified_ms,
            successor_of: None,
        }
    }

    /// A node whose document verified and is bound to `identity`, at `now`.
    pub(crate) fn from_verified(
        identity: NodeIdentity,
        verified: attest::Verified,
        now: u64,
        successor_of: Option<String>,
    ) -> Result<Self> {
        let identity_json =
            serde_json::to_string(&identity).map_err(ClientError::json("node identity"))?;
        Ok(Self {
            identity,
            identity_json,
            release: verified.release,
            module_id: verified.module_id,
            timestamp_ms: verified.timestamp_ms,
            pcrs: verified
                .pcrs
                .iter()
                .map(|(index, pcr)| (*index, attest::to_hex(pcr)))
                .collect(),
            verified_ms: now,
            successor_of,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
impl VerifiedNode {
    /// The accepted release whose measurements the node runs, such as `v1.2.0`.
    pub fn release(&self) -> String {
        self.release.clone()
    }

    /// The enclave, such as `i-0123456789abcdef0-enc0123456789abcdef`.
    pub fn module_id(&self) -> String {
        self.module_id.clone()
    }

    /// When the Nitro Secure Module made the document, Unix milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// When this app verified it, Unix milliseconds.
    pub fn verified_ms(&self) -> u64 {
        self.verified_ms
    }

    /// PCR `index` of the document as lowercase hexadecimal, if it has it.
    pub fn pcr(&self, index: u8) -> Option<String> {
        self.pcrs.get(&index).cloned()
    }

    /// The node identity the document vouches for, as JSON (`{"log_key", "seal_key"}`).
    pub fn identity_json(&self) -> String {
        self.identity_json.clone()
    }

    /// The key that verifies the log of the node, as unpadded base64url.
    pub fn log_key(&self) -> String {
        self.identity.log_key.to_b64()
    }

    /// For a node verified as the successor of a release ([`crate::verify_successor`]):
    /// that release.
    pub fn successor_of(&self) -> Option<String> {
        self.successor_of.clone()
    }
}

/// Parses a node identity.
pub(crate) fn identity(json: &str) -> Result<NodeIdentity> {
    serde_json::from_str(json).map_err(ClientError::json("node identity"))
}

fn verify(
    document: &[u8],
    nonce: &Nonce,
    measurements_json: &str,
    identity: NodeIdentity,
) -> Result<VerifiedNode> {
    let now = now_ms();
    let nonce = nonce.take(now)?;
    let accepted = attest::Measurements::from_json(measurements_json.as_bytes())?;
    let verified = attest::verify(document, nonce, accepted.as_slice(), &[attest::aws_root()])?;
    attest::bind(&identity, &verified)?;
    VerifiedNode::from_verified(identity, verified, now, None)
}

/// Verifies the attestation `document` (CBOR, as the Nitro Secure Module wrote it) of the
/// node `identity_json` (`{"log_key", "seal_key"}`), asked for with `nonce`.
///
/// Checks, with the `attest` crate: the COSE structure, the certificate chain to the pinned
/// AWS Nitro Enclaves root at the time of the document, the signature, the nonce, that the
/// enclave is not a debug one, that PCR0, PCR1 and PCR2 are those of a release of
/// `measurements_json` (one `measurements.json` object or an array of them), and that the
/// user data of the document is the report data of the identity. The nonce is used up, even
/// when the check fails.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn verify_node(
    document: Vec<u8>,
    nonce: Arc<Nonce>,
    measurements_json: String,
    identity_json: String,
) -> Result<Arc<VerifiedNode>> {
    let node = identity(&identity_json);
    // Whatever the identity, the nonce is spent.
    let node = node.inspect_err(|_| {
        nonce.used.store(true, Ordering::SeqCst);
    })?;
    verify(&document, &nonce, &measurements_json, node).map(Arc::new)
}

#[derive(Deserialize)]
struct Reply {
    identity: NodeIdentity,
    document: String,
}

/// [`verify_node`] on the JSON a node in an enclave answers `GET /attestation?nonce=` with:
/// `{"identity": {...}, "document": "<base64url>"}`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn verify_attestation_reply(
    reply_json: String,
    nonce: Arc<Nonce>,
    measurements_json: String,
) -> Result<Arc<VerifiedNode>> {
    let parsed = serde_json::from_str::<Reply>(&reply_json)
        .map_err(ClientError::json("attestation reply"))
        .and_then(|reply| {
            let document = URL_SAFE_NO_PAD
                .decode(reply.document.trim_end_matches('='))
                .map_err(|_| {
                    ClientError::input("attestation reply: the document is not base64url")
                })?;
            Ok((reply.identity, document))
        });
    let (node, document) = parsed.inspect_err(|_| {
        nonce.used.store(true, Ordering::SeqCst);
    })?;
    verify(&document, &nonce, &measurements_json, node).map(Arc::new)
}
