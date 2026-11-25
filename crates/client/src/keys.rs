//! Keys as text: 32 secret bytes as unpadded base64url, the form the `credentials` CLI writes
//! to its key files, so keys move between the CLI and an app.
//!
//! A secret key handed to the app is a `String` the app must keep in storage its platform
//! protects (Keychain, Android Keystore-wrapped storage); the client erases its own copies,
//! including every key string it is given, as soon as it is done with them.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::keys::{CallerKey, DeviceKey, UserKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ClientError, Result};

/// The kinds of keys an app holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Enum))]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub enum KeyKind {
    /// The key of a device of the owner (Ed25519): it signs policies, grants, revocations,
    /// pins and device changes. It never leaves the device.
    Device,
    /// The user key of the owner (32 random bytes): records are encrypted under keys derived
    /// from it, and a grant hands it to an attested node for a while.
    User,
    /// The key of a caller (Ed25519): an app or agent that signs calls.
    Caller,
}

/// The 32 bytes of a key in unpadded base64url; surrounding white space is ignored.
fn decode(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    let written = URL_SAFE_NO_PAD
        .decode_slice(text.trim(), bytes.as_mut_slice())
        .map_err(|_| ClientError::key("not 32 bytes as unpadded base64url"))?;
    if written != 32 {
        return Err(ClientError::key("not 32 bytes as unpadded base64url"));
    }
    Ok(bytes)
}

fn encode(bytes: &[u8; 32]) -> String {
    let mut text = Zeroizing::new(String::with_capacity(43));
    URL_SAFE_NO_PAD.encode_string(bytes, &mut text);
    // The caller of the client takes this copy; the buffer it was built in is erased.
    String::from(text.as_str())
}

/// Reads a device key and erases the text.
pub(crate) fn device_key(mut text: String) -> Result<DeviceKey> {
    let key = decode(&text).map(|mut bytes| DeviceKey::from_bytes(&mut bytes));
    text.zeroize();
    key
}

/// Reads a user key and erases the text.
pub(crate) fn user_key(mut text: String) -> Result<UserKey> {
    let key = decode(&text).map(|mut bytes| UserKey::from_bytes(&mut bytes));
    text.zeroize();
    key
}

/// Reads a caller key and erases the text.
pub(crate) fn caller_key(mut text: String) -> Result<CallerKey> {
    let key = decode(&text).map(|mut bytes| CallerKey::from_bytes(&mut bytes));
    text.zeroize();
    key
}

/// A new random key of `kind`, as unpadded base64url. Store it in protected storage.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn generate_key(kind: KeyKind) -> String {
    match kind {
        KeyKind::Device => encode(&DeviceKey::generate().to_bytes()),
        KeyKind::User => encode(&UserKey::generate().to_bytes()),
        KeyKind::Caller => encode(&CallerKey::generate().to_bytes()),
    }
}

/// Checks a key of `kind` brought from elsewhere (a key file of the `credentials` CLI, a
/// backup) and returns it in the canonical form, without surrounding white space.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn import_key(kind: KeyKind, text: String) -> Result<String> {
    Ok(match kind {
        KeyKind::Device => encode(&device_key(text)?.to_bytes()),
        KeyKind::User => encode(&user_key(text)?.to_bytes()),
        KeyKind::Caller => encode(&caller_key(text)?.to_bytes()),
    })
}

/// The public key of a device or caller key, as unpadded base64url: what a policy lists for a
/// caller, what an endorsement names for a device. A user key has none.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn public_key(kind: KeyKind, secret: String) -> Result<String> {
    match kind {
        KeyKind::Device => Ok(device_key(secret)?.public().to_b64()),
        KeyKind::Caller => Ok(caller_key(secret)?.public().to_b64()),
        KeyKind::User => {
            let mut secret = secret;
            secret.zeroize();
            Err(ClientError::key("a user key has no public key"))
        }
    }
}
