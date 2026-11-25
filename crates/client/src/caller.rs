//! What an app that uses a record signs: a call. The app holds the record (ciphertext) and its
//! caller key, never the values; the node checks the call and runs the operation.

use engine::call::Body;
use engine::record::Record;

use crate::attestation::identity;
use crate::error::{ClientError, Result};
use crate::keys;
use crate::owner::to_json;
use crate::time::now_ms;

fn sign(
    caller_key: String,
    caller: &str,
    identity_json: &str,
    record_json: &str,
    operation: &str,
    body: Body,
) -> Result<String> {
    let key = keys::caller_key(caller_key)?;
    let node = identity(identity_json)?;
    let record: Record = serde_json::from_str(record_json).map_err(ClientError::json("record"))?;
    let call = key
        .sign_call_at(caller, &node.log_key, record, operation, body, now_ms())
        .map_err(ClientError::engine("cannot sign the call"))?;
    to_json(&call)
}

/// Signs a call of the caller named `caller` in the policy to the node `identity_json`, on
/// `record_json`, for `operation`, with `body_json` (the body of a call:
/// `{"kind": "http"}`, `{"kind": "http", "request": {...}}`,
/// `{"kind": "derive", "input": "<base64url>"}` or `{"kind": "stream", ...}`). Send the
/// signed call to `POST /call` within five minutes.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    body_json: String,
) -> Result<String> {
    let body: Body = serde_json::from_str(&body_json).map_err(ClientError::json("call body"))?;
    sign(
        caller_key,
        &caller,
        &identity_json,
        &record_json,
        &operation,
        body,
    )
}

/// [`sign_call`] for a derivation of `input` (`$input` of the template of the operation).
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn sign_derive_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    input: Vec<u8>,
) -> Result<String> {
    sign(
        caller_key,
        &caller,
        &identity_json,
        &record_json,
        &operation,
        Body::derive(&input),
    )
}
