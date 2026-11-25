//! Operations that wait for the owner, and what the owner's device does about them: answer a
//! challenge with a code, set the spending limits of an item, renew a session the node cannot
//! renew itself; and what the app that waits signs to go on.
//!
//! A call whose operation waits is answered `{"ok": <pending>, ...}`, where `<pending>` is
//! `{"kind": "challenge", "id", "challenge", "hint", "expires_ms"}` or
//! `{"kind": "approval_required", "id", "summary"}`. The app shows it to the owner's device;
//! the device answers ([`answer_challenge`], to `POST /answer`) or approves
//! ([`crate::approve`], to `POST /approve`); the app then resumes with [`sign_resume_call`].

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::call::Body;
use engine::fields::Fields;
use engine::limits::LimitRule;
use engine::policy::ChallengeKind;
use engine::record::Record;
use engine::session::Pending;
use zeroize::Zeroizing;

use crate::attestation::identity;
use crate::error::{ClientError, Result};
use crate::keys;
use crate::owner::{Field, to_json};
use crate::time::now_ms;

pub(crate) fn pending(json: &str) -> Result<Pending> {
    serde_json::from_str(json).map_err(ClientError::json("pending operation"))
}

/// Answers the challenge of a waiting operation (`pending_json`, as the node handed it to the
/// app) with `code`, for `owner`, sealed to the node `identity_json` and signed by the device
/// key. The code is erased once sealed. Send it to `POST /answer`. Only a device of the owner
/// can answer: the app that waits holds no device key, and the node takes no code from it.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn answer_challenge(
    device_key: String,
    owner: String,
    identity_json: String,
    pending_json: String,
    code: Vec<u8>,
) -> Result<String> {
    let code = Zeroizing::new(code);
    let device = keys::device_key(device_key)?;
    let node = identity(&identity_json)?;
    let Pending::Challenge { id, challenge, .. } = pending(&pending_json)? else {
        return Err(ClientError::input(
            "the operation waits for an approval, not a code",
        ));
    };
    if challenge == ChallengeKind::External {
        return Err(ClientError::input(
            "an external challenge is answered in the other app, not with a code",
        ));
    }
    let answer = device
        .answer_challenge(&node, &owner, id, &code, now_ms())
        .map_err(ClientError::engine("cannot answer the challenge"))?;
    to_json(&answer)
}

/// Signs the call that goes on with a waiting operation: the same caller, record and
/// operation as the call that started it, and the `id` of the pending operation (unpadded
/// base64url). Use the record the node handed back last. Send it to `POST /call`; while the
/// operation still waits, the node answers with the same pending operation.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_resume_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    id: String,
) -> Result<String> {
    let id: [u8; 16] = URL_SAFE_NO_PAD
        .decode(id.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ClientError::input("the id is not 16 bytes of base64url"))?;
    crate::caller::sign(
        caller_key,
        &caller,
        &identity_json,
        &record_json,
        &operation,
        Body::resume(id),
    )
}

/// Signs the spending limits of the record `record_id` of `owner` on the node
/// `identity_json`, with the device key, now. `rules_json` is a list of rules
/// (`[{"currency": "EUR", "merchant": "https://shop.example", "per_payment": "50",
/// "per_day": "100", "per_month": "500"}]`); a payment no rule covers, or one above a rule,
/// waits for the owner's approval; an empty list makes every payment wait. Send it to
/// `POST /limits`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_limits(
    device_key: String,
    owner: String,
    identity_json: String,
    record_id: String,
    rules_json: String,
) -> Result<String> {
    let device = keys::device_key(device_key)?;
    let node = identity(&identity_json)?;
    let rules: Vec<LimitRule> =
        serde_json::from_str(&rules_json).map_err(ClientError::json("limit rules"))?;
    let limits = device
        .sign_limits(&node.log_key, &owner, &record_id, rules, now_ms())
        .map_err(ClientError::engine("cannot sign the limits"))?;
    to_json(&limits)
}

/// Replaces values of `record_json` with `fields`, one generation later, with the user key:
/// what the device does when the owner renews a session the policy renews with
/// `{"by": "owner"}` (the node then refuses the operation with `session_expired`). A field
/// that holds a session gets its expiry written too. The values are erased once sealed.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn update_record(user_key: String, record_json: String, fields: Vec<Field>) -> Result<String> {
    // Every value is erased on every path from here on.
    let fields: Vec<(String, Zeroizing<Vec<u8>>)> = fields
        .into_iter()
        .map(|field| (field.name, Zeroizing::new(field.value)))
        .collect();
    let key = keys::user_key(user_key)?;
    let record: Record = serde_json::from_str(&record_json).map_err(ClientError::json("record"))?;
    let mut values = Fields::new();
    for (name, mut value) in fields {
        let value = core::mem::take(&mut *value);
        values
            .insert(&name, value)
            .map_err(ClientError::engine("a field is malformed"))?;
    }
    let next = record
        .update(&key, &values, now_ms())
        .map_err(ClientError::engine("cannot update the record"))?;
    to_json(&next)
}
