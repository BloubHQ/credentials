//! What the owner's device signs and seals: policies, records, pins, grants, revocations and
//! device changes. Every function returns the JSON document the node server takes at the
//! endpoint it names.

use std::sync::Arc;
use std::time::Duration;

use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::DevicePublicKey;
use engine::policy::{Policy, SignedPolicy};
use engine::record::Record;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::attestation::{MAX_AGE_MS, VerifiedNode, identity};
use crate::error::{ClientError, Result};
use crate::keys;
use crate::time::now_ms;

/// One value of a record to seal. [`seal_record`] erases the value once it is sealed, or
/// refused.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
pub struct Field {
    /// The name the policy gives the field: 1 to 64 letters, digits, `-` or `_`.
    pub name: String,
    /// The value, at least one byte.
    pub value: Vec<u8>,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| ClientError::Refused {
        detail: format!("cannot encode JSON: {e}"),
    })
}

fn record(json: &str) -> Result<Record> {
    serde_json::from_str(json).map_err(ClientError::json("record"))
}

fn signed_policy(json: &str) -> Result<SignedPolicy> {
    serde_json::from_str(json).map_err(ClientError::json("signed policy"))
}

fn owner_name(owner: &str) -> Result<()> {
    if owner.is_empty() {
        return Err(ClientError::input("the owner is empty"));
    }
    Ok(())
}

/// Signs a policy (JSON, as in `docs/policy.md`) with the device key after checking its
/// rules. Returns the signed policy, which [`seal_record`] takes.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_policy(device_key: String, policy_json: String) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let policy: Policy = serde_json::from_str(&policy_json).map_err(ClientError::json("policy"))?;
    let signed = device
        .sign_policy(policy)
        .map_err(ClientError::engine("cannot sign the policy"))?;
    to_json(&signed)
}

/// Encrypts `fields` under the user key as generation 1 of record `record_id` of `owner`,
/// bound to `signed_policy_json`. Returns the record JSON: ciphertext the app or an operator
/// may store anywhere. Pin it ([`pin_record`], or in a [`crate::grant`]) so nodes refuse older
/// copies.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn seal_record(
    user_key: String,
    signed_policy_json: String,
    record_id: String,
    owner: String,
    fields: Vec<Field>,
) -> Result<String> {
    // Every value is erased on every path from here on.
    let fields: Vec<(String, Zeroizing<Vec<u8>>)> = fields
        .into_iter()
        .map(|field| (field.name, Zeroizing::new(field.value)))
        .collect();
    let key = keys::user_key(user_key)?;
    let policy = signed_policy(&signed_policy_json)?;
    let mut values = Fields::new();
    for (name, mut value) in fields {
        let value = std::mem::take(&mut *value);
        values.insert(&name, value).map_err(|_| {
            ClientError::input(format!(
                "field `{}`: a name of 1 to 64 letters, digits, '-' or '_', given once, and a value of at least one byte; at most {} fields and {} bytes in all",
                name,
                engine::fields::MAX_FIELDS,
                engine::fields::MAX_TOTAL
            ))
        })?;
    }
    let sealed = Record::seal(&key, &record_id, &owner, policy, &values)
        .map_err(ClientError::engine("cannot seal the record"))?;
    to_json(&sealed)
}

/// Rewraps `record_json` under a new signed policy, keeping its values, one generation later.
/// Fields the new policy does not list are dropped.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn rewrap_record(
    user_key: String,
    record_json: String,
    signed_policy_json: String,
) -> Result<String> {
    let key = keys::user_key(user_key)?;
    let old = record(&record_json)?;
    let policy = signed_policy(&signed_policy_json)?;
    let new = old
        .rewrap(&key, policy)
        .map_err(ClientError::engine("cannot rewrap the record"))?;
    to_json(&new)
}

/// Pins a record at its generation: nodes refuse any older copy of it. Send it to
/// `POST /pin`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn pin_record(device_key: String, record_json: String) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let record = record(&record_json)?;
    let pin = device
        .pin(&record)
        .map_err(ClientError::engine("cannot pin the record"))?;
    to_json(&pin)
}

/// Grants a verified node the user key of `owner` for `valid_for_secs` seconds (a node
/// shortens it to 30 days), pinning each record of `pins_json` (record JSON) at its
/// generation. Send the sealed grant to `POST /grant`.
///
/// Only a [`VerifiedNode`] can be granted to, so the attestation of the node is always
/// checked first, and it must have been verified within the last five minutes
/// ([`MAX_AGE_MS`]).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn grant(
    device_key: String,
    user_key: String,
    node: Arc<VerifiedNode>,
    owner: String,
    valid_for_secs: u64,
    pins_json: Vec<String>,
) -> Result<String> {
    // Both key strings are read (and erased) before either can fail.
    let device = keys::device_key(device_key);
    let key = keys::user_key(user_key);
    let (device, key) = (device?, key?);
    owner_name(&owner)?;
    if valid_for_secs == 0 {
        return Err(ClientError::input("a grant lasts at least one second"));
    }
    let now = now_ms();
    if now.saturating_sub(node.verified_ms) > MAX_AGE_MS {
        return Err(ClientError::VerificationExpired {
            detail: "the node was verified more than five minutes ago: verify it again".into(),
        });
    }
    let mut terms = GrantTerms::at(&owner, now, Duration::from_secs(valid_for_secs));
    for json in &pins_json {
        let record = record(json)?;
        if record.owner != owner {
            return Err(ClientError::input(format!(
                "pinned record `{}` belongs to {}, not {owner}",
                record.id, record.owner
            )));
        }
        terms = terms.pin(&record);
    }
    let sealed = device
        .grant(&key, &node.identity, terms)
        .map_err(ClientError::engine("cannot grant"))?;
    to_json(&sealed)
}

/// Takes the user key of `owner` back from the node `identity_json`. Send it to
/// `POST /revoke`. A revocation hands the node nothing, so it needs no attestation.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn revoke(device_key: String, owner: String, identity_json: String) -> Result<String> {
    let device = keys::device_key(device_key)?;
    owner_name(&owner)?;
    let node = identity(&identity_json)?;
    let revocation = device
        .revoke(&owner, &node.log_key, now_ms())
        .map_err(ClientError::engine("cannot revoke"))?;
    to_json(&revocation)
}

fn device_public(text: &str) -> Result<DevicePublicKey> {
    DevicePublicKey::from_b64(text.trim()).map_err(|_| ClientError::key("not a device public key"))
}

/// Vouches for another device of `owner` (its public key, `new_device_public_key`) on the
/// node `identity_json`, signed by a device the node already knows. Send it to
/// `POST /device/add`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn endorse_device(
    device_key: String,
    owner: String,
    identity_json: String,
    new_device_public_key: String,
) -> Result<String> {
    let device = keys::device_key(device_key)?;
    owner_name(&owner)?;
    let node = identity(&identity_json)?;
    let target = device_public(&new_device_public_key)?;
    let endorsement = device
        .endorse(&owner, &node.log_key, &target, now_ms())
        .map_err(ClientError::engine("cannot endorse the device"))?;
    to_json(&endorsement)
}

/// Withdraws another device of `owner` (lost, sold, replaced) on the node `identity_json`.
/// A device cannot withdraw itself. Send it to `POST /device/retire`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn retire_device(
    device_key: String,
    owner: String,
    identity_json: String,
    device_public_key: String,
) -> Result<String> {
    let device = keys::device_key(device_key)?;
    owner_name(&owner)?;
    let node = identity(&identity_json)?;
    let target = device_public(&device_public_key)?;
    let retirement = device
        .retire(&owner, &node.log_key, &target, now_ms())
        .map_err(ClientError::engine("cannot retire the device"))?;
    to_json(&retirement)
}
