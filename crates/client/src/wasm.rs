//! The JavaScript API (wasm-bindgen), on `wasm32` only: the same functions in camel case.
//! A failure throws an `Error` whose `code` is [`ClientError::code`] (and `reason`, for a
//! refused attestation, the check that failed).
//!
//! Numbers of seconds and milliseconds are JavaScript numbers; record fields are a
//! `Map<string, Uint8Array>`.

use std::sync::Arc;

use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize as _;

use crate::error::ClientError;
use crate::keys::KeyKind;
use crate::owner::Field;

impl From<ClientError> for JsValue {
    fn from(error: ClientError) -> Self {
        let js = js_sys::Error::new(&error.to_string());
        // Setting a property of a fresh Error object does not fail.
        let _ = js_sys::Reflect::set(&js, &"code".into(), &error.code().into());
        if let ClientError::AttestationRefused { reason, .. } = &error {
            let _ = js_sys::Reflect::set(&js, &"reason".into(), &reason.as_str().into());
        }
        js.into()
    }
}

type Result<T> = std::result::Result<T, JsValue>;

/// A random nonce for one attestation request (see [`crate::Nonce`]).
#[wasm_bindgen(js_name = Nonce)]
pub struct JsNonce(Arc<crate::Nonce>);

#[wasm_bindgen(js_class = Nonce)]
impl JsNonce {
    /// The bytes of the nonce.
    pub fn bytes(&self) -> Vec<u8> {
        self.0.bytes()
    }

    /// The nonce as unpadded base64url, for `GET /attestation?nonce=`.
    #[wasm_bindgen(js_name = toB64)]
    pub fn to_b64(&self) -> String {
        self.0.to_b64()
    }
}

/// A node whose attestation verified (see [`crate::VerifiedNode`]).
#[wasm_bindgen(js_name = VerifiedNode)]
pub struct JsVerifiedNode(Arc<crate::VerifiedNode>);

#[wasm_bindgen(js_class = VerifiedNode)]
impl JsVerifiedNode {
    /// The accepted release the node runs.
    #[wasm_bindgen(getter)]
    pub fn release(&self) -> String {
        self.0.release()
    }

    /// The enclave.
    #[wasm_bindgen(getter, js_name = moduleId)]
    pub fn module_id(&self) -> String {
        self.0.module_id()
    }

    /// When the module made the document, Unix milliseconds.
    #[wasm_bindgen(getter, js_name = timestampMs)]
    pub fn timestamp_ms(&self) -> f64 {
        self.0.timestamp_ms() as f64
    }

    /// When this page verified it, Unix milliseconds.
    #[wasm_bindgen(getter, js_name = verifiedMs)]
    pub fn verified_ms(&self) -> f64 {
        self.0.verified_ms() as f64
    }

    /// PCR `index` as lowercase hexadecimal, if the document has it.
    pub fn pcr(&self, index: u8) -> Option<String> {
        self.0.pcr(index)
    }

    /// The node identity as JSON.
    #[wasm_bindgen(getter, js_name = identityJson)]
    pub fn identity_json(&self) -> String {
        self.0.identity_json()
    }

    /// The log key of the node.
    #[wasm_bindgen(getter, js_name = logKey)]
    pub fn log_key(&self) -> String {
        self.0.log_key()
    }
}

/// See [`crate::generate_key`].
#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key(kind: KeyKind) -> String {
    crate::generate_key(kind)
}

/// See [`crate::import_key`].
#[wasm_bindgen(js_name = importKey)]
pub fn import_key(kind: KeyKind, text: String) -> Result<String> {
    Ok(crate::import_key(kind, text)?)
}

/// See [`crate::public_key`].
#[wasm_bindgen(js_name = publicKey)]
pub fn public_key(kind: KeyKind, secret: String) -> Result<String> {
    Ok(crate::public_key(kind, secret)?)
}

/// See [`crate::nonce`].
#[wasm_bindgen(js_name = nonce)]
pub fn nonce() -> Result<JsNonce> {
    Ok(JsNonce(crate::nonce()?))
}

/// See [`crate::verify_node`].
#[wasm_bindgen(js_name = verifyNode)]
pub fn verify_node(
    document: Vec<u8>,
    nonce: &JsNonce,
    measurements_json: String,
    identity_json: String,
) -> Result<JsVerifiedNode> {
    Ok(JsVerifiedNode(crate::verify_node(
        document,
        Arc::clone(&nonce.0),
        measurements_json,
        identity_json,
    )?))
}

/// See [`crate::verify_attestation_reply`].
#[wasm_bindgen(js_name = verifyAttestationReply)]
pub fn verify_attestation_reply(
    reply_json: String,
    nonce: &JsNonce,
    measurements_json: String,
) -> Result<JsVerifiedNode> {
    Ok(JsVerifiedNode(crate::verify_attestation_reply(
        reply_json,
        Arc::clone(&nonce.0),
        measurements_json,
    )?))
}

/// See [`crate::grant`]. `valid_for_secs` is a whole number of seconds.
#[wasm_bindgen(js_name = grant)]
pub fn grant(
    device_key: String,
    user_key: String,
    node: &JsVerifiedNode,
    owner: String,
    valid_for_secs: u32,
    pins_json: Vec<String>,
) -> Result<String> {
    Ok(crate::grant(
        device_key,
        user_key,
        Arc::clone(&node.0),
        owner,
        u64::from(valid_for_secs),
        pins_json,
    )?)
}

/// See [`crate::revoke`].
#[wasm_bindgen(js_name = revoke)]
pub fn revoke(device_key: String, owner: String, identity_json: String) -> Result<String> {
    Ok(crate::revoke(device_key, owner, identity_json)?)
}

/// See [`crate::endorse_device`].
#[wasm_bindgen(js_name = endorseDevice)]
pub fn endorse_device(
    device_key: String,
    owner: String,
    identity_json: String,
    new_device_public_key: String,
) -> Result<String> {
    Ok(crate::endorse_device(
        device_key,
        owner,
        identity_json,
        new_device_public_key,
    )?)
}

/// See [`crate::retire_device`].
#[wasm_bindgen(js_name = retireDevice)]
pub fn retire_device(
    device_key: String,
    owner: String,
    identity_json: String,
    device_public_key: String,
) -> Result<String> {
    Ok(crate::retire_device(
        device_key,
        owner,
        identity_json,
        device_public_key,
    )?)
}

/// See [`crate::sign_policy`].
#[wasm_bindgen(js_name = signPolicy)]
pub fn sign_policy(device_key: String, policy_json: String) -> Result<String> {
    Ok(crate::sign_policy(device_key, policy_json)?)
}

/// See [`crate::seal_record`]. `fields` is a `Map<string, Uint8Array>`.
#[wasm_bindgen(js_name = sealRecord)]
pub fn seal_record(
    user_key: String,
    signed_policy_json: String,
    record_id: String,
    owner: String,
    fields: &js_sys::Map,
) -> Result<String> {
    let mut list = Vec::new();
    let mut malformed = false;
    fields.for_each(&mut |value, key| match (
        key.as_string(),
        value.dyn_into::<js_sys::Uint8Array>(),
    ) {
        (Some(name), Ok(bytes)) => list.push(Field {
            name,
            value: bytes.to_vec(),
        }),
        _ => malformed = true,
    });
    if malformed {
        let mut user_key = user_key;
        user_key.zeroize();
        for mut field in list {
            field.value.zeroize();
        }
        return Err(
            ClientError::input("fields: a Map of string names to Uint8Array values").into(),
        );
    }
    Ok(crate::seal_record(
        user_key,
        signed_policy_json,
        record_id,
        owner,
        list,
    )?)
}

/// See [`crate::rewrap_record`].
#[wasm_bindgen(js_name = rewrapRecord)]
pub fn rewrap_record(
    user_key: String,
    record_json: String,
    signed_policy_json: String,
) -> Result<String> {
    Ok(crate::rewrap_record(
        user_key,
        record_json,
        signed_policy_json,
    )?)
}

/// See [`crate::pin_record`].
#[wasm_bindgen(js_name = pinRecord)]
pub fn pin_record(device_key: String, record_json: String) -> Result<String> {
    Ok(crate::pin_record(device_key, record_json)?)
}

/// See [`crate::sign_call`].
#[wasm_bindgen(js_name = signCall)]
pub fn sign_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    body_json: String,
) -> Result<String> {
    Ok(crate::sign_call(
        caller_key,
        caller,
        identity_json,
        record_json,
        operation,
        body_json,
    )?)
}

/// See [`crate::sign_derive_call`].
#[wasm_bindgen(js_name = signDeriveCall)]
pub fn sign_derive_call(
    caller_key: String,
    caller: String,
    identity_json: String,
    record_json: String,
    operation: String,
    input: Vec<u8>,
) -> Result<String> {
    Ok(crate::sign_derive_call(
        caller_key,
        caller,
        identity_json,
        record_json,
        operation,
        input,
    )?)
}
