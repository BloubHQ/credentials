//! Keys kept in wasm memory and used by reference: `DeviceKey`, `UserKey` and `CallerKey`.
//!
//! The string API hands a key to JavaScript as a string on every call, and every copy of that
//! string lives in the JavaScript heap until it is garbage-collected. A key object holds the
//! key in wasm memory instead: JavaScript holds only a reference, the key is wiped when the
//! object is freed (`free()`), and it becomes a JavaScript string only when
//! the app asks for it with `exportKey()`, to store it. Each object signs or seals with the
//! same functions as the string API, so the two give the same results.
//!
//! The kinds are separate classes, so a caller key cannot be passed where a device key is
//! needed.

use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use super::{JsVerifiedNode, Result};
use crate::keys::KeyKind;

macro_rules! key_object {
    ($rust:ident, $js:ident, $kind:expr, $what:literal) => {
        #[doc = concat!("A ", $what, " kept in wasm memory; wiped when freed.")]
        #[wasm_bindgen(js_name = $js)]
        pub struct $rust(Zeroizing<String>);

        #[wasm_bindgen(js_class = $js)]
        impl $rust {
            #[doc = concat!("A new random ", $what, ".")]
            pub fn generate() -> Self {
                Self(Zeroizing::new(crate::generate_key($kind)))
            }

            #[doc = concat!(
                "A ", $what, " brought as text (see `importKey`). The text is erased in wasm ",
                "memory; the JavaScript string passed in is not the client's to erase."
            )]
            #[wasm_bindgen(js_name = fromString)]
            pub fn from_string(text: String) -> Result<Self> {
                Ok(Self(Zeroizing::new(crate::import_key($kind, text)?)))
            }

            /// The key as text, to store it. The string returned is a JavaScript string,
            /// which lives in the JavaScript heap until it is garbage-collected.
            #[wasm_bindgen(js_name = exportKey)]
            pub fn export_key(&self) -> js_sys::JsString {
                js_sys::JsString::from(self.0.as_str())
            }
        }

        impl $rust {
            /// A copy of the key text for one call of the string API, which erases it.
            fn text(&self) -> String {
                self.0.as_str().to_owned()
            }
        }
    };
}

key_object!(JsDeviceKey, DeviceKey, KeyKind::Device, "device key");
key_object!(JsUserKey, UserKey, KeyKind::User, "user key");
key_object!(JsCallerKey, CallerKey, KeyKind::Caller, "caller key");

#[wasm_bindgen(js_class = DeviceKey)]
impl JsDeviceKey {
    /// See `publicKey`.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<String> {
        super::public_key(KeyKind::Device, self.text())
    }

    /// See `grant`.
    pub fn grant(
        &self,
        user_key: &JsUserKey,
        node: &JsVerifiedNode,
        owner: String,
        valid_for_secs: u32,
        pins_json: Vec<String>,
    ) -> Result<String> {
        super::grant(
            self.text(),
            user_key.text(),
            node,
            owner,
            valid_for_secs,
            pins_json,
        )
    }

    /// See `grantWithoutSuccessor`.
    #[wasm_bindgen(js_name = grantWithoutSuccessor)]
    pub fn grant_without_successor(
        &self,
        user_key: &JsUserKey,
        node: &JsVerifiedNode,
        owner: String,
        valid_for_secs: u32,
        pins_json: Vec<String>,
    ) -> Result<String> {
        super::grant_without_successor(
            self.text(),
            user_key.text(),
            node,
            owner,
            valid_for_secs,
            pins_json,
        )
    }

    /// See `regrant`.
    #[allow(clippy::too_many_arguments)]
    pub fn regrant(
        &self,
        user_key: &JsUserKey,
        node: &JsVerifiedNode,
        owner: String,
        valid_for_secs: u32,
        pins_json: Vec<String>,
        policy: crate::SuccessorPolicy,
        owner_approved: bool,
    ) -> Result<String> {
        super::regrant(
            self.text(),
            user_key.text(),
            node,
            owner,
            valid_for_secs,
            pins_json,
            policy,
            owner_approved,
        )
    }

    /// See `revoke`.
    pub fn revoke(&self, owner: String, identity_json: String) -> Result<String> {
        super::revoke(self.text(), owner, identity_json)
    }

    /// See `endorseDevice`.
    #[wasm_bindgen(js_name = endorseDevice)]
    pub fn endorse_device(
        &self,
        owner: String,
        identity_json: String,
        new_device_public_key: String,
    ) -> Result<String> {
        super::endorse_device(self.text(), owner, identity_json, new_device_public_key)
    }

    /// See `retireDevice`.
    #[wasm_bindgen(js_name = retireDevice)]
    pub fn retire_device(
        &self,
        owner: String,
        identity_json: String,
        device_public_key: String,
    ) -> Result<String> {
        super::retire_device(self.text(), owner, identity_json, device_public_key)
    }

    /// See `signPolicy`.
    #[wasm_bindgen(js_name = signPolicy)]
    pub fn sign_policy(&self, policy_json: String) -> Result<String> {
        super::sign_policy(self.text(), policy_json)
    }

    /// See `pinRecord`.
    #[wasm_bindgen(js_name = pinRecord)]
    pub fn pin_record(&self, record_json: String) -> Result<String> {
        super::pin_record(self.text(), record_json)
    }

    /// See `signKind`.
    #[wasm_bindgen(js_name = signKind)]
    pub fn sign_kind(&self, kind_json: String) -> Result<String> {
        super::sign_kind(self.text(), kind_json)
    }

    /// See `approve`.
    pub fn approve(&self, identity_json: String, summary_json: String) -> Result<String> {
        super::approve(self.text(), identity_json, summary_json)
    }

    /// See `answerChallenge`.
    #[wasm_bindgen(js_name = answerChallenge)]
    pub fn answer_challenge(
        &self,
        owner: String,
        identity_json: String,
        pending_json: String,
        code: Vec<u8>,
    ) -> Result<String> {
        super::answer_challenge(self.text(), owner, identity_json, pending_json, code)
    }

    /// See `signLimits`.
    #[wasm_bindgen(js_name = signLimits)]
    pub fn sign_limits(
        &self,
        owner: String,
        identity_json: String,
        record_id: String,
        rules_json: String,
    ) -> Result<String> {
        super::sign_limits(self.text(), owner, identity_json, record_id, rules_json)
    }

    /// See `delegate`.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        user_key: &JsUserKey,
        node: &JsVerifiedNode,
        record_json: String,
        delegate_owner: String,
        policy_json: String,
        wait_secs: u32,
        valid_for_secs: u32,
    ) -> Result<String> {
        super::delegate(
            self.text(),
            user_key.text(),
            node,
            record_json,
            delegate_owner,
            policy_json,
            wait_secs,
            valid_for_secs,
        )
    }

    /// See `changeDelegation`.
    #[wasm_bindgen(js_name = changeDelegation)]
    pub fn change_delegation(
        &self,
        owner: String,
        identity_json: String,
        record_id: String,
        id: String,
        change: String,
    ) -> Result<String> {
        super::change_delegation(self.text(), owner, identity_json, record_id, id, change)
    }
}

#[wasm_bindgen(js_class = UserKey)]
impl JsUserKey {
    /// See `sealRecord`.
    #[wasm_bindgen(js_name = sealRecord)]
    pub fn seal_record(
        &self,
        signed_policy_json: String,
        record_id: String,
        owner: String,
        fields: &js_sys::Map,
    ) -> Result<String> {
        super::seal_record(self.text(), signed_policy_json, record_id, owner, fields)
    }

    /// See `rewrapRecord`.
    #[wasm_bindgen(js_name = rewrapRecord)]
    pub fn rewrap_record(&self, record_json: String, signed_policy_json: String) -> Result<String> {
        super::rewrap_record(self.text(), record_json, signed_policy_json)
    }

    /// See `updateRecord`.
    #[wasm_bindgen(js_name = updateRecord)]
    pub fn update_record(&self, record_json: String, fields: &js_sys::Map) -> Result<String> {
        super::update_record(self.text(), record_json, fields)
    }
}

#[wasm_bindgen(js_class = CallerKey)]
impl JsCallerKey {
    /// See `publicKey`.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Result<String> {
        super::public_key(KeyKind::Caller, self.text())
    }

    /// See `signCall`.
    #[wasm_bindgen(js_name = signCall)]
    pub fn sign_call(
        &self,
        caller: String,
        identity_json: String,
        record_json: String,
        operation: String,
        body_json: String,
    ) -> Result<String> {
        super::sign_call(
            self.text(),
            caller,
            identity_json,
            record_json,
            operation,
            body_json,
        )
    }

    /// See `signDeriveCall`.
    #[wasm_bindgen(js_name = signDeriveCall)]
    pub fn sign_derive_call(
        &self,
        caller: String,
        identity_json: String,
        record_json: String,
        operation: String,
        input: Vec<u8>,
    ) -> Result<String> {
        super::sign_derive_call(
            self.text(),
            caller,
            identity_json,
            record_json,
            operation,
            input,
        )
    }

    /// See `signDescribeCall`.
    #[wasm_bindgen(js_name = signDescribeCall)]
    pub fn sign_describe_call(
        &self,
        caller: String,
        identity_json: String,
        record_json: String,
    ) -> Result<String> {
        super::sign_describe_call(self.text(), caller, identity_json, record_json)
    }

    /// See `signResumeCall`.
    #[wasm_bindgen(js_name = signResumeCall)]
    pub fn sign_resume_call(
        &self,
        caller: String,
        identity_json: String,
        record_json: String,
        operation: String,
        id: String,
    ) -> Result<String> {
        super::sign_resume_call(
            self.text(),
            caller,
            identity_json,
            record_json,
            operation,
            id,
        )
    }

    /// See `signDelegatedCall`.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = signDelegatedCall)]
    pub fn sign_delegated_call(
        &self,
        caller: String,
        identity_json: String,
        record_json: String,
        operation: String,
        body_json: String,
        delegation_id: String,
    ) -> Result<String> {
        super::sign_delegated_call(
            self.text(),
            caller,
            identity_json,
            record_json,
            operation,
            body_json,
            delegation_id,
        )
    }
}
