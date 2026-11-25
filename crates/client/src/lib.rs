//! The app side of the credentials engine, for iOS, Android and the web.
//!
//! One Rust implementation over [`engine`] and [`attest`], with a small API of strings and
//! bytes: keys are unpadded base64url text, documents are the JSON the node server takes.
//! Swift and Kotlin reach it through UniFFI, JavaScript through wasm-bindgen (`wasm` module,
//! on `wasm32` only).
//!
//! - Keys: [`generate_key`], [`import_key`], [`public_key`] for device, user and caller keys
//!   ([`KeyKind`]).
//! - A node, before a grant: [`nonce`], then [`verify_node`] (or
//!   [`verify_attestation_reply`]) on the attestation document the node answers with. Only
//!   they make a [`VerifiedNode`].
//! - The owner's device: [`grant`] (to a [`VerifiedNode`] only), [`revoke`],
//!   [`endorse_device`], [`retire_device`], [`sign_policy`], [`seal_record`],
//!   [`rewrap_record`], [`pin_record`].
//! - An app that uses a record: [`sign_call`], [`sign_derive_call`], [`sign_describe_call`].
//! - Review: [`summarize`] a policy (and what a new version widens), [`policy_json_schema`],
//!   [`item_kinds`]; the owner's device also signs custom kinds ([`sign_kind`]) and approves
//!   summaries the node built ([`approve`], [`approval_hash`]).
//!
//! Every failure is a [`ClientError`] with a stable [`ClientError::code`].
//!
//! # A grant
//!
//! ```no_run
//! # fn main() -> Result<(), client::ClientError> {
//! # let measurements = String::new(); // the measurements.json of the accepted releases
//! # let fetch = |_: &str| -> (Vec<u8>, String) { (Vec::new(), String::new()) };
//! use client::{KeyKind, generate_key, grant, nonce, verify_node};
//!
//! let device = generate_key(KeyKind::Device); // keep both in protected storage
//! let user = generate_key(KeyKind::User);
//! let nonce = nonce()?;
//! // GET /attestation?nonce=<nonce.to_b64()> on the node: its document and identity.
//! let (document, identity) = fetch(&nonce.to_b64());
//! let node = verify_node(document, nonce, measurements, identity)?;
//! let sealed = grant(device, user, node, "alice".into(), 3600, Vec::new())?;
//! // POST sealed to /grant.
//! # Ok(())
//! # }
//! ```

mod attestation;
mod caller;
mod error;
mod keys;
mod owner;
mod review;
mod time;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(test)]
mod tests;

pub use attestation::{
    MAX_AGE_MS, NONCE_LEN, Nonce, VerifiedNode, nonce, verify_attestation_reply, verify_node,
};
pub use caller::{sign_call, sign_derive_call, sign_describe_call};
pub use error::{ClientError, Result};
pub use keys::{KeyKind, generate_key, import_key, public_key};
pub use owner::{
    Field, endorse_device, grant, pin_record, retire_device, revoke, rewrap_record, seal_record,
    sign_policy, upgrade_policy,
};
pub use review::{approval_hash, approve, item_kinds, policy_json_schema, sign_kind, summarize};

#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!();
