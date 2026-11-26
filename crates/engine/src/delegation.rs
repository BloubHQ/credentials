//! Delegation and emergency access: an owner lets another owner's callers use one item under a
//! narrower policy (`docs/design.md`, section 8b).
//!
//! A device of the owner signs a [`Delegation`] for one record on one node: the delegate (the
//! other owner's name on the node, for the log), a policy whose operations are those of the
//! record's policy or narrower and whose callers are the delegate's, how long it lasts, and,
//! for emergency access, a waiting period. The record's key and the key the node seals log
//! details under travel inside it, sealed to the node (HPKE, as a grant), so the delegate's
//! callers can use the item while the owner holds no grant on the node, and never see either
//! key.
//!
//! The node takes a delegation from a known device of the owner, issued within five minutes of
//! its clock and after the owner's last act, when the policy it carries is no wider than the
//! record's ([`check_narrower`]). A delegated call names the delegation; the node runs it with
//! the delegated policy, only while the record still carries the policy the delegation was
//! checked against. With a waiting period, the first call of a delegate starts the wait and is
//! refused, every call until the wait ends is refused, and a device of the owner can cancel
//! the request ([`Change::Cancel`]) or end the delegation ([`Change::Revoke`]) meanwhile.

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{b64_array, b64_vec, canonical};
use crate::grant::{NodeIdentity, SealSecret, seal_to};
use crate::keys::{DeviceKey, DevicePublicKey, KEY_LEN, NodePublicKey, UserKey};
use crate::policy::{Policy, SignedPolicy, diff};
use crate::record::{Record, check_name};
use crate::secret::Secret;
use crate::{Error, Result};

const DELEGATION_DOMAIN: &[u8] = b"delegation/v1\0";
const CHANGE_DOMAIN: &[u8] = b"delegation-change/v1\0";
const POLICY_HASH_DOMAIN: &[u8] = b"delegated-base/v1\0";
const KEYS_INFO: &[u8] = b"credentials delegation keys/v1";

/// Most delegations one record may have on a node.
pub const MAX_PER_RECORD: usize = 16;
/// Most delegations of one owner on a node.
pub const MAX_PER_OWNER: usize = 64;
/// Longest a delegation lasts: 366 days.
pub const MAX_LIFETIME_MS: u64 = 366 * 24 * 60 * 60 * 1000;
/// Shortest waiting period of emergency access: one hour, so the owner has time to see the
/// request and cancel it.
pub const MIN_WAIT_MS: u64 = 60 * 60 * 1000;
/// Longest waiting period of emergency access: 90 days.
pub const MAX_WAIT_MS: u64 = 90 * 24 * 60 * 60 * 1000;

fn invalid(rule: &'static str) -> Error {
    Error::DelegationInvalid { rule }
}

/// The keys a node opens one record with and seals its log details under: derived from the
/// user key, or carried sealed in a delegation.
pub(crate) struct RecordKeys {
    pub(crate) record: Secret<[u8; KEY_LEN]>,
    pub(crate) detail: Secret<[u8; KEY_LEN]>,
}

impl RecordKeys {
    /// The keys of `record_id` under `user_key`.
    pub(crate) fn of(user_key: &UserKey, record_id: &str) -> Result<Self> {
        Ok(Self {
            record: user_key.record_key(record_id)?,
            detail: crate::log::detail_key(user_key)?,
        })
    }

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
        out.extend_from_slice(self.record.expose());
        out.extend_from_slice(self.detail.expose());
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (record, detail) = bytes
            .split_at_checked(KEY_LEN)
            .filter(|(_, d)| d.len() == KEY_LEN)
            .ok_or(invalid("the sealed keys are malformed"))?;
        let mut r = Secret::new([0u8; KEY_LEN]);
        r.expose_mut().copy_from_slice(record);
        let mut d = Secret::new([0u8; KEY_LEN]);
        d.expose_mut().copy_from_slice(detail);
        Ok(Self {
            record: r,
            detail: d,
        })
    }
}

/// The record keys of a delegation, sealed to one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedKeys {
    /// The encapsulated key of HPKE.
    #[serde(with = "b64_vec")]
    pub enc: Vec<u8>,
    /// The record key and the log detail key, encrypted.
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

/// What the owner's device decides for a delegation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationTerms {
    /// The other owner, by its name on the node: written to the log of both owners.
    pub delegate: String,
    /// The delegated policy: the record's policy or narrower, with the delegate's callers.
    pub policy: Policy,
    /// 0 for a delegation that is open at once; otherwise the waiting period of emergency
    /// access, [`MIN_WAIT_MS`] to [`MAX_WAIT_MS`].
    pub wait_ms: u64,
    /// When the delegation ends, Unix milliseconds: at most [`MAX_LIFETIME_MS`] after
    /// `issued_ms`.
    pub expires_ms: u64,
    /// When the device signs it, Unix milliseconds.
    pub issued_ms: u64,
}

/// A delegation of one record on one node, signed by a device of the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// The node.
    pub node: NodePublicKey,
    /// The owner of the record.
    pub owner: String,
    /// The record.
    pub record_id: String,
    /// Random; names the delegation in calls and changes.
    #[serde(with = "b64_array")]
    pub id: [u8; 16],
    /// The other owner, by its name on the node.
    pub delegate: String,
    /// The delegated policy, signed by the same device.
    pub policy: SignedPolicy,
    /// [`policy_sha256`] of the record's signed policy the delegation was checked against.
    #[serde(with = "b64_array")]
    pub base_sha256: [u8; 32],
    /// 0, or the waiting period of emergency access.
    pub wait_ms: u64,
    /// When it ends, Unix milliseconds.
    pub expires_ms: u64,
    /// When the device signed it, Unix milliseconds.
    pub issued_ms: u64,
    /// The record key and the log detail key, sealed to the node.
    pub keys: SealedKeys,
    /// The device that signed.
    pub device: DevicePublicKey,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

/// What a node takes to start a delegation (`POST /delegate`): the delegation and the record
/// as the owner holds it, whose signed policy the delegation names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    /// The delegation.
    pub delegation: Delegation,
    /// The record (ciphertext); the node reads only its policy.
    pub record: Record,
}

#[derive(Serialize)]
struct DelegationMessage<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    record_id: &'a str,
    #[serde(with = "b64_array")]
    id: [u8; 16],
    delegate: &'a str,
    policy: &'a SignedPolicy,
    #[serde(with = "b64_array")]
    base_sha256: [u8; 32],
    wait_ms: u64,
    expires_ms: u64,
    issued_ms: u64,
    keys: &'a SealedKeys,
    device: &'a DevicePublicKey,
}

/// What a device of the owner changes in a delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Refuses the open request of emergency access: the delegation stays, and the next
    /// request waits the whole period again.
    Cancel,
    /// Ends the delegation.
    Revoke,
}

/// A change of a delegation, signed by a device of the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationChange {
    /// The node.
    pub node: NodePublicKey,
    /// The owner of the record.
    pub owner: String,
    /// The record.
    pub record_id: String,
    /// The delegation.
    #[serde(with = "b64_array")]
    pub id: [u8; 16],
    /// What changes.
    pub change: Change,
    /// When the device signed it, Unix milliseconds.
    pub issued_ms: u64,
    /// The device that signed.
    pub device: DevicePublicKey,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct ChangeMessage<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    record_id: &'a str,
    #[serde(with = "b64_array")]
    id: [u8; 16],
    change: Change,
    issued_ms: u64,
    device: &'a DevicePublicKey,
}

/// SHA-256 of a signed policy's canonical bytes: what a delegation pins of the record.
pub fn policy_sha256(policy: &SignedPolicy) -> Result<[u8; 32]> {
    Ok(Sha256::digest(canonical(POLICY_HASH_DOMAIN, policy)?).into())
}

/// Checks that `delegated` gives its callers nothing `base` does not give its own:
///
/// - the same fields and item binding;
/// - no operation the base lacks, and none wider than the base's of the same name, by the
///   same comparison the summary of a new version uses ([`diff`]), which counts what it
///   cannot rank as wider;
/// - no capture into a field: a delegate never seals a new generation of the owner's record,
///   which would leave the owner's copy stale.
///
/// The callers are the delegate's and are not compared.
pub fn check_narrower(base: &Policy, delegated: &Policy) -> Result<()> {
    if base.fields != delegated.fields || base.item != delegated.item {
        return Err(invalid(
            "the delegated policy declares the same fields and item binding as the record's",
        ));
    }
    if delegated
        .operations
        .iter()
        .any(|o| !o.field_captures().is_empty())
    {
        return Err(invalid(
            "a delegated policy captures into no field: the record stays the owner's",
        ));
    }
    let mut view = base.clone();
    view.callers.clone_from(&delegated.callers);
    let (wider, _) = diff(&view, delegated);
    if !wider.is_empty() {
        return Err(invalid(
            "the delegated policy is wider than the record's policy",
        ));
    }
    Ok(())
}

impl Delegation {
    /// Checks the form of the delegation (not its signature or its policy).
    pub fn validate(&self) -> Result<()> {
        check_name(&self.owner)?;
        check_name(&self.record_id)?;
        check_name(&self.delegate).map_err(|_| invalid("the delegate is an owner name"))?;
        if self.delegate == self.owner {
            return Err(invalid("an owner does not delegate to itself"));
        }
        if self.wait_ms != 0 && !(MIN_WAIT_MS..=MAX_WAIT_MS).contains(&self.wait_ms) {
            return Err(invalid("a waiting period is 0, or 1 hour to 90 days"));
        }
        let lifetime = self.expires_ms.saturating_sub(self.issued_ms);
        if lifetime == 0 || lifetime > MAX_LIFETIME_MS {
            return Err(invalid(
                "a delegation ends after it is issued, within 366 days",
            ));
        }
        if self.wait_ms >= lifetime {
            return Err(invalid(
                "the waiting period ends before the delegation does",
            ));
        }
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            DELEGATION_DOMAIN,
            &DelegationMessage {
                node: &self.node,
                owner: &self.owner,
                record_id: &self.record_id,
                id: self.id,
                delegate: &self.delegate,
                policy: &self.policy,
                base_sha256: self.base_sha256,
                wait_ms: self.wait_ms,
                expires_ms: self.expires_ms,
                issued_ms: self.issued_ms,
                keys: &self.keys,
                device: &self.device,
            },
        )
    }

    /// Checks the signature of the device named in the delegation.
    pub(crate) fn verify(&self) -> Result<()> {
        self.device
            .verify(&self.message()?, &self.signature)
            .map_err(|_| invalid("the signature does not verify"))
    }

    fn keys_aad(owner: &str, record_id: &str, id: &[u8; 16]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(owner.len() + record_id.len() + 18);
        aad.extend_from_slice(owner.as_bytes());
        aad.push(0);
        aad.extend_from_slice(record_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(id);
        aad
    }

    /// Opens the keys sealed to this node.
    pub(crate) fn open_keys(&self, seal: &SealSecret) -> Result<RecordKeys> {
        let plain = seal
            .open(
                KEYS_INFO,
                &Self::keys_aad(&self.owner, &self.record_id, &self.id),
                &self.keys.enc,
                &self.keys.ciphertext,
            )
            .ok_or(invalid("the keys are not sealed to this node"))?;
        RecordKeys::from_bytes(&plain)
    }
}

impl DelegationChange {
    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            CHANGE_DOMAIN,
            &ChangeMessage {
                node: &self.node,
                owner: &self.owner,
                record_id: &self.record_id,
                id: self.id,
                change: self.change,
                issued_ms: self.issued_ms,
                device: &self.device,
            },
        )
    }

    /// Checks the signature of the device named in the change.
    pub(crate) fn verify(&self) -> Result<()> {
        check_name(&self.owner)?;
        check_name(&self.record_id)?;
        self.device
            .verify(&self.message()?, &self.signature)
            .map_err(|_| invalid("the signature does not verify"))
    }
}

impl DeviceKey {
    /// Delegates `record` on `node` as `terms` say. Runs on the owner's device, which holds the
    /// user key: the record key and the log detail key are sealed to the node, never handed
    /// to the delegate. Checks that the delegated policy is no wider than the record's
    /// ([`check_narrower`]) and signs it. Check the attestation of the node first.
    pub fn delegate(
        &self,
        user_key: &UserKey,
        node: &NodeIdentity,
        record: &Record,
        terms: DelegationTerms,
    ) -> Result<Delegation> {
        check_narrower(&record.policy.policy, &terms.policy)?;
        let policy = self.sign_policy(terms.policy)?;
        let mut id = [0u8; 16];
        UnwrapErr(SysRng).fill_bytes(&mut id);
        let keys = RecordKeys::of(user_key, &record.id)?;
        let (enc, ciphertext) = seal_to(
            &node.seal_key,
            KEYS_INFO,
            &Delegation::keys_aad(&record.owner, &record.id, &id),
            &keys.to_bytes(),
        )?;
        let mut delegation = Delegation {
            node: node.log_key,
            owner: record.owner.clone(),
            record_id: record.id.clone(),
            id,
            delegate: terms.delegate,
            policy,
            base_sha256: policy_sha256(&record.policy)?,
            wait_ms: terms.wait_ms,
            expires_ms: terms.expires_ms,
            issued_ms: terms.issued_ms,
            keys: SealedKeys { enc, ciphertext },
            device: self.public(),
            signature: [0; 64],
        };
        delegation.validate()?;
        delegation.signature = self.sign(&delegation.message()?);
        Ok(delegation)
    }

    /// Cancels the open request of emergency access, or revokes the delegation `id` of
    /// `record_id` of `owner` on `node`, at `issued_ms`. Runs on the owner's device.
    pub fn change_delegation(
        &self,
        node: &NodePublicKey,
        owner: &str,
        record_id: &str,
        id: [u8; 16],
        change: Change,
        issued_ms: u64,
    ) -> Result<DelegationChange> {
        let mut out = DelegationChange {
            node: *node,
            owner: owner.to_string(),
            record_id: record_id.to_string(),
            id,
            change,
            issued_ms,
            device: self.public(),
            signature: [0; 64],
        };
        check_name(owner)?;
        check_name(record_id)?;
        out.signature = self.sign(&out.message()?);
        Ok(out)
    }
}
