//! Sessions, challenges and approvals at run time: what a parked operation tells its caller,
//! and how the owner's device answers a challenge.
//!
//! An operation parks when a step needs what only the owner can give: a one-time code
//! ([`crate::policy::Await`]), or the owner's approval (a card payment, an operation the owner
//! marked, a payment above the owner's spending limits). The node keeps the operation's values
//! in its memory under a random id, for at most five minutes, and hands its caller a
//! [`Pending`]: `challenge {id, kind, hint}` or `approval_required {id, summary}`. Nothing of
//! the parked values leaves the node; a restart of the node drops them.
//!
//! - A code comes from the owner's device, signed by a device key and sealed to the node
//!   ([`DeviceKey::answer_challenge`], [`crate::node::Node::answer`]): the caller can neither
//!   read it nor make one.
//! - An approval is an [`crate::approval::Approval`] the owner's device signs over the summary
//!   the node built ([`crate::node::Node::approve`]).
//! - An external challenge (the site waits for the owner in another app) is polled by the node
//!   each time the caller resumes, at most as often as the policy allows.
//!
//! The caller then resumes the operation with a call of the same operation on the same record
//! whose body is [`crate::call::Body::Resume`] with the id; the node takes it only from the
//! caller that started the operation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::approval::ApprovalSummary;
use crate::encoding::{b64_array, b64_vec, canonical};
use crate::grant::{NodeIdentity, SealSecret, seal_to};
use crate::keys::{DeviceKey, DevicePublicKey, NodePublicKey};
use crate::policy::ChallengeKind;
use crate::{Error, Result};

const ANSWER_DOMAIN: &[u8] = b"answer/v1\0";
const ANSWER_INFO: &[u8] = b"credentials answer/v1";
/// Longest code an answer carries, in bytes.
pub const MAX_CODE: usize = 256;

/// What a parked operation tells its caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Pending {
    /// The operation waits for a challenge: a code from the owner's device, or the owner's
    /// approval in another app that the node polls the site for.
    Challenge {
        /// The id to resume with, and the owner's device answers.
        #[serde(with = "b64_array")]
        id: [u8; 16],
        /// The kind of challenge.
        challenge: ChallengeKind,
        /// What the owner is told, as the policy wrote it.
        hint: String,
        /// When the operation stops waiting, Unix milliseconds.
        expires_ms: u64,
    },
    /// The operation waits for the owner's approval of the summary the node built.
    ApprovalRequired {
        /// The id to resume with.
        #[serde(with = "b64_array")]
        id: [u8; 16],
        /// What the owner's device shows and signs ([`DeviceKey::approve`]).
        summary: Box<ApprovalSummary>,
    },
}

impl Pending {
    /// The id to resume with.
    pub fn id(&self) -> [u8; 16] {
        match self {
            Pending::Challenge { id, .. } | Pending::ApprovalRequired { id, .. } => *id,
        }
    }
}

/// A code for a challenge, signed by a device of the owner and sealed to the node with HPKE,
/// so neither the caller nor the operator of the parent instance reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedAnswer {
    /// The encapsulated key of HPKE.
    #[serde(with = "b64_vec")]
    pub enc: Vec<u8>,
    /// The answer, encrypted.
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    owner: String,
    #[serde(with = "b64_array")]
    id: [u8; 16],
    #[serde(with = "b64_vec")]
    code: Vec<u8>,
    device: DevicePublicKey,
    issued_ms: u64,
    #[serde(with = "b64_array")]
    signature: [u8; 64],
}

impl Drop for AnswerBody {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.code.zeroize();
    }
}

#[derive(Serialize)]
struct AnswerMessage<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    #[serde(with = "b64_array")]
    id: [u8; 16],
    #[serde(with = "b64_array")]
    code_sha256: [u8; 32],
    device: &'a DevicePublicKey,
    issued_ms: u64,
}

fn answer_message(
    node: &NodePublicKey,
    owner: &str,
    id: [u8; 16],
    code: &[u8],
    device: &DevicePublicKey,
    issued_ms: u64,
) -> Result<Vec<u8>> {
    canonical(
        ANSWER_DOMAIN,
        &AnswerMessage {
            node,
            owner,
            id,
            code_sha256: Sha256::digest(code).into(),
            device,
            issued_ms,
        },
    )
}

fn invalid(rule: &'static str) -> Error {
    Error::AnswerInvalid { rule }
}

/// An answer the node opened. Its signature is checked against the devices of its owner by
/// [`OpenedAnswer::verify`].
pub(crate) struct OpenedAnswer {
    pub owner: String,
    pub id: [u8; 16],
    pub code: Zeroizing<Vec<u8>>,
    pub device: DevicePublicKey,
    pub issued_ms: u64,
    signature: [u8; 64],
}

impl OpenedAnswer {
    /// Checks the signature of the device named in the answer, for `node`.
    pub fn verify(&self, node: &NodePublicKey) -> Result<()> {
        let message = answer_message(
            node,
            &self.owner,
            self.id,
            &self.code,
            &self.device,
            self.issued_ms,
        )?;
        self.device
            .verify(&message, &self.signature)
            .map_err(|_| invalid("the signature does not verify"))
    }
}

impl SealedAnswer {
    /// Opens the answer with the seal secret of `node`.
    pub(crate) fn open(&self, secret: &SealSecret, node: &NodePublicKey) -> Result<OpenedAnswer> {
        let plain = secret
            .open(
                ANSWER_INFO,
                node.to_b64().as_bytes(),
                &self.enc,
                &self.ciphertext,
            )
            .ok_or(invalid("not sealed to this node"))?;
        let mut body: AnswerBody =
            serde_json::from_slice(&plain).map_err(|_| invalid("answer malformed"))?;
        if body.code.is_empty() || body.code.len() > MAX_CODE {
            return Err(invalid("a code of 1 to 256 bytes"));
        }
        Ok(OpenedAnswer {
            owner: core::mem::take(&mut body.owner),
            id: body.id,
            code: Zeroizing::new(core::mem::take(&mut body.code)),
            device: body.device,
            issued_ms: body.issued_ms,
            signature: body.signature,
        })
    }
}

impl DeviceKey {
    /// Answers the challenge `id` of `owner` on `node` with `code`, at `issued_ms`: signed by
    /// this device and sealed to the node. Runs on the owner's device; the caller that waits
    /// for the operation never sees the code.
    pub fn answer_challenge(
        &self,
        node: &NodeIdentity,
        owner: &str,
        id: [u8; 16],
        code: &[u8],
        issued_ms: u64,
    ) -> Result<SealedAnswer> {
        if code.is_empty() || code.len() > MAX_CODE {
            return Err(invalid("a code of 1 to 256 bytes"));
        }
        let device = self.public();
        let signature = self.sign(&answer_message(
            &node.log_key,
            owner,
            id,
            code,
            &device,
            issued_ms,
        )?);
        let body = AnswerBody {
            owner: owner.to_string(),
            id,
            code: code.to_vec(),
            device,
            issued_ms,
            signature,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| Error::Encoding)?);
        let (enc, ciphertext) = seal_to(
            &node.seal_key,
            ANSWER_INFO,
            node.log_key.to_b64().as_bytes(),
            &plain,
        )?;
        Ok(SealedAnswer { enc, ciphertext })
    }
}
