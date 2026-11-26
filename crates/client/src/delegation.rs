//! Delegation and emergency access (`docs/design.md`, section 8b): the owner's device
//! delegates one record to another owner's callers under a narrower policy, cancels a request
//! of emergency access, or revokes the delegation; a delegate's app signs its calls under the
//! delegation.
//!
//! - [`delegate`] (to a [`VerifiedNode`] only: the record key travels sealed to it), sent to
//!   `POST /delegate`;
//! - [`change_delegation`] (`cancel` or `revoke`), sent to `POST /delegation/change`;
//! - [`sign_delegated_call`], sent to `POST /call` like any call.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::call::Body;
use engine::delegation::{Change, DelegationRequest, DelegationTerms};
use engine::policy::Policy;
use engine::record::Record;

use crate::attestation::{MAX_AGE_MS, VerifiedNode, identity};
use crate::error::{ClientError, Result};
use crate::keys;
use crate::owner::to_json;
use crate::time::now_ms;

fn delegation_id(text: &str) -> Result<[u8; 16]> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ClientError::input("the delegation id is not 16 bytes of base64url"))
}

/// Delegates `record_json` to the callers of the other owner `delegate_owner` on the verified node,
/// under `policy_json`: the record's policy or narrower (the same fields, no operation the
/// record lacks or wider, no capture into a field), whose callers are the delegate's. The
/// device signs the delegated policy itself. `wait_secs` is 0 for a delegation open at once,
/// or the waiting period of emergency access (1 hour to 90 days): the delegate's first call
/// starts it, and the owner can cancel it from a device meanwhile. It lasts `valid_for_secs`
/// (at most 366 days). The record key is sealed to the node, never handed to the delegate.
/// Send the result to `POST /delegate`; its `delegation.id` is what the delegate's calls name.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn delegate(
    device_key: String,
    user_key: String,
    node: Arc<VerifiedNode>,
    record_json: String,
    delegate_owner: String,
    policy_json: String,
    wait_secs: u64,
    valid_for_secs: u64,
) -> Result<String> {
    // Both key strings are read (and erased) before either can fail.
    let device = keys::device_key(device_key);
    let key = keys::user_key(user_key);
    let (device, key) = (device?, key?);
    let now = now_ms();
    if now.saturating_sub(node.verified_ms) > MAX_AGE_MS {
        return Err(ClientError::VerificationExpired {
            detail: "the node was verified more than five minutes ago: verify it again".into(),
        });
    }
    let record: Record = serde_json::from_str(&record_json).map_err(ClientError::json("record"))?;
    let policy: Policy =
        serde_json::from_str(&policy_json).map_err(ClientError::json("delegated policy"))?;
    let terms = DelegationTerms {
        delegate: delegate_owner,
        policy,
        wait_ms: wait_secs.saturating_mul(1000),
        expires_ms: now.saturating_add(valid_for_secs.saturating_mul(1000)),
        issued_ms: now,
    };
    let delegation = device
        .delegate(&key, &node.identity, &record, terms)
        .map_err(ClientError::engine("cannot delegate"))?;
    to_json(&DelegationRequest { delegation, record })
}

/// Cancels the open request of emergency access (`change` = `cancel`: the delegation stays,
/// and the next request waits the whole period again), or revokes the delegation `id`
/// (`revoke`), for `owner`'s record `record_id` on the node `identity_json`. Send it to
/// `POST /delegation/change`. A change hands the node nothing, so it needs no attestation.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn change_delegation(
    device_key: String,
    owner: String,
    identity_json: String,
    record_id: String,
    id: String,
    change: String,
) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let node = identity(&identity_json)?;
    let change = match change.as_str() {
        "cancel" => Change::Cancel,
        "revoke" => Change::Revoke,
        _ => return Err(ClientError::input("change is `cancel` or `revoke`")),
    };
    let signed = device
        .change_delegation(
            &node.log_key,
            &owner,
            &record_id,
            delegation_id(&id)?,
            change,
            now_ms(),
        )
        .map_err(ClientError::engine("cannot change the delegation"))?;
    to_json(&signed)
}

/// [`crate::sign_call`] for a caller of a delegated policy: `caller` is its name in that
/// policy, `delegation_id` the `id` of the delegation (unpadded base64url). The node runs the
/// call under the delegated policy. Send it to `POST /call`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_delegated_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    body_json: String,
    delegation_id_b64: String,
) -> Result<String> {
    let key = keys::caller_key(caller_key)?;
    let node = identity(&identity_json)?;
    let record: Record = serde_json::from_str(&record_json).map_err(ClientError::json("record"))?;
    let body: Body = serde_json::from_str(&body_json).map_err(ClientError::json("call body"))?;
    let call = key
        .sign_delegated_call_at(
            &caller,
            &node.log_key,
            record,
            &operation,
            body,
            now_ms(),
            Some(delegation_id(&delegation_id_b64)?),
        )
        .map_err(ClientError::engine("cannot sign the call"))?;
    to_json(&call)
}
