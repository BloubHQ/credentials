//! What the owner reads before signing: the summary of a policy and its risk flags, the JSON
//! Schema of the IR, the reviewed kinds of item; and what the owner's device signs besides a
//! policy: a custom kind, and an approval of a summary the node built.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::approval::ApprovalSummary;
use engine::item::KindSchema;
use engine::policy::{Policy, SignedPolicy};

use crate::attestation::identity;
use crate::error::{ClientError, Result};
use crate::keys;
use crate::owner::to_json;
use crate::time::now_ms;

/// A policy, signed or not.
fn policy(json: &str, what: &'static str) -> Result<Policy> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(ClientError::json(what))?;
    let signed = value
        .as_object()
        .is_some_and(|o| o.contains_key("signature") && o.contains_key("policy"));
    if signed {
        serde_json::from_value::<SignedPolicy>(value)
            .map(|s| s.policy)
            .map_err(ClientError::json(what))
    } else {
        serde_json::from_value::<Policy>(value).map_err(ClientError::json(what))
    }
}

/// Summarizes a policy (JSON, signed or not) for its owner: per secret, where it can go and in
/// what form; per operation, the destinations, requests, what returns and the inputs; the
/// callers; the item; and the risk flags. With `previous_policy_json` (the version the record
/// has now), it also lists what changed and flags each way the new version is wider.
///
/// The policy is checked first ([`engine::policy::Policy::validate`]): a policy the device
/// would refuse to sign is refused here too, so a summary is only ever of a policy that can be
/// signed. Returns the summary JSON (`docs/policy.md`, "Summaries").
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn summarize(policy_json: String, previous_policy_json: Option<String>) -> Result<String> {
    let current = policy(&policy_json, "policy")?;
    current
        .validate()
        .map_err(ClientError::engine("the policy breaks a rule"))?;
    let previous = previous_policy_json
        .as_deref()
        .map(|json| policy(json, "previous policy"))
        .transpose()?;
    to_json(&engine::policy::summarize(&current, previous.as_ref()))
}

/// The JSON Schema (draft 2020-12) of the policy IR, for editors and form builders. A draft
/// that holds against it is well formed; [`crate::sign_policy`] also runs the checks a
/// schema cannot express.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn policy_json_schema() -> String {
    engine::policy::JSON_SCHEMA.to_string()
}

/// The reviewed kinds of item, `{"kinds": [...]}`: each kind's fields (secret, masked or
/// public), their checks, and the shape of policy the kind allows.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn item_kinds() -> String {
    engine::item::ITEMS_JSON.to_string()
}

/// Signs a custom kind of item (JSON, as a kind of [`item_kinds`]) with the device key, after
/// checking its rules. A policy binds it with `{"kind": <name>, "custom": <signed kind>}`; a
/// node accepts it when a device of the owner signed it. A custom kind cannot take the name
/// of a reviewed kind.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_kind(device_key: String, kind_json: String) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let kind: KindSchema = serde_json::from_str(&kind_json).map_err(ClientError::json("kind"))?;
    let signed = device
        .sign_kind(kind)
        .map_err(ClientError::engine("cannot sign the kind"))?;
    to_json(&signed)
}

fn summary(json: &str) -> Result<ApprovalSummary> {
    let summary: ApprovalSummary =
        serde_json::from_str(json).map_err(ClientError::json("approval summary"))?;
    summary
        .validate()
        .map_err(ClientError::engine("the approval summary is malformed"))?;
    Ok(summary)
}

/// The SHA-256 of an approval summary (unpadded base64url): what an approval signs, for an
/// app that shows it beside the summary.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn approval_hash(summary_json: String) -> Result<String> {
    let hash = summary(&summary_json)?
        .sha256()
        .map_err(ClientError::engine("cannot hash the summary"))?;
    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Approves a summary the node `identity_json` built, with the device key, now. Show the
/// summary to the owner first. Refused when the summary names another node or has lapsed.
/// Returns the approval JSON for the node.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn approve(device_key: String, identity_json: String, summary_json: String) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let node = identity(&identity_json)?;
    let summary = summary(&summary_json)?;
    if summary.node != node.log_key {
        return Err(ClientError::input("the summary is for another node"));
    }
    let now = now_ms();
    if now < summary.created_ms || now >= summary.expires_ms {
        return Err(ClientError::input(
            "the summary is not open now: it lapsed, or the clocks disagree",
        ));
    }
    let approval = device
        .approve(&summary, now)
        .map_err(ClientError::engine("cannot approve"))?;
    to_json(&approval)
}
