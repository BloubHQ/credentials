//! Key backup: the device and user keys of an owner, wrapped for storage the owner's platform
//! keeps end-to-end encrypted (iCloud Keychain, Google Block Store), so a new phone gets them
//! back. The platform glue (Keychain and Block Store calls) is the app's; this module makes
//! and opens the blob.
//!
//! Two pieces:
//! - a **backup key**, 32 random bytes ([`generate_backup_key`]): the app puts it only in the
//!   platform's end-to-end encrypted store (a synchronizable Keychain item; a Block Store
//!   entry with `setShouldBackupToCloud(true)`, which Google encrypts end to end with the
//!   screen lock);
//! - the **blob** ([`wrap_keys`]): the keys, encrypted under the backup key. It may be stored
//!   anywhere, next to the backup key or on a server: without the backup key it is noise.
//!
//! The blob is JSON, format `credentials-key-backup/v1`:
//!
//! ```json
//! {"format": "credentials-key-backup/v1", "owner": "alice", "created_ms": 1764115200000,
//!  "nonce": "<24 bytes, base64url>", "ciphertext": "<base64url>"}
//! ```
//!
//! `ciphertext` is XChaCha20-Poly1305 under `HKDF-SHA256(backup key, info
//! "credentials key backup/v1")`, with the nonce, over the JSON array
//! `[{"kind": "device" | "user" | "caller", "key": "<base64url>"}...]`; the additional data
//! is `format`, `owner` and `created_ms` (canonical JSON), so a blob of one owner does not
//! open as another's, and its time cannot be changed.
//!
//! No passphrase mode: a passphrase a person can remember is guessable offline from the
//! blob; the platform stores hold a random key instead, behind the device's screen lock and
//! the platform's own guess limits.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ClientError, Result};
use crate::keys::{self, KeyKind};
use crate::time::now_ms;

/// The format of a key backup blob.
pub const BACKUP_FORMAT: &str = "credentials-key-backup/v1";
/// Most keys in one blob.
pub const MAX_BACKUP_KEYS: usize = 16;
/// The largest blob [`unwrap_keys`] reads, in bytes.
pub const MAX_BACKUP_LEN: usize = 16 * 1024;

const KEY_INFO: &[u8] = b"credentials key backup/v1";

/// One key in a backup or a transfer.
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Record))]
#[derive(Clone, PartialEq, Eq)]
pub struct BackedUpKey {
    /// What kind of key.
    pub kind: KeyKind,
    /// The key, as unpadded base64url ([`crate::generate_key`]).
    pub key: String,
}

impl std::fmt::Debug for BackedUpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackedUpKey")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlainKey {
    kind: String,
    key: String,
}

impl Drop for PlainKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn kind_name(kind: KeyKind) -> &'static str {
    match kind {
        KeyKind::Device => "device",
        KeyKind::User => "user",
        KeyKind::Caller => "caller",
    }
}

/// The keys as the plain JSON of a backup or a transfer, each checked first.
pub(crate) fn encode_keys(keys: Vec<BackedUpKey>) -> Result<Zeroizing<Vec<u8>>> {
    // Every key string is erased on every path from here on.
    let keys: Vec<(KeyKind, Zeroizing<String>)> = keys
        .into_iter()
        .map(|k| (k.kind, Zeroizing::new(k.key)))
        .collect();
    if keys.is_empty() || keys.len() > MAX_BACKUP_KEYS {
        return Err(ClientError::input(format!(
            "give 1 to {MAX_BACKUP_KEYS} keys"
        )));
    }
    let plain = keys
        .iter()
        .map(|(kind, key)| {
            Ok(PlainKey {
                kind: kind_name(*kind).into(),
                key: crate::keys::import_key(*kind, String::from(key.as_str()))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Sized up front: a buffer that grew would free a copy of the keys before it, unwiped.
    // Each key is `{"kind":"...","key":"..."}` and a comma, with nothing to escape.
    let size = plain
        .iter()
        .map(|k| k.kind.len().saturating_add(k.key.len()).saturating_add(24))
        .fold(2usize, usize::saturating_add);
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    serde_json::to_writer(&mut *out, &plain)
        .map_err(|_| ClientError::input("cannot encode the keys"))?;
    Ok(out)
}

/// The keys of the plain JSON of a backup or a transfer.
pub(crate) fn decode_keys(plain: &[u8]) -> Result<Vec<BackedUpKey>> {
    let keys: Vec<PlainKey> = serde_json::from_slice(plain)
        .map_err(|_| ClientError::input("the keys are not in the backup format"))?;
    from_plain(&keys)
}

/// The keys of their plain form, each checked.
pub(crate) fn from_plain(keys: &[PlainKey]) -> Result<Vec<BackedUpKey>> {
    if keys.is_empty() || keys.len() > MAX_BACKUP_KEYS {
        return Err(ClientError::input("the backup holds no keys, or too many"));
    }
    keys.iter()
        .map(|k| {
            let kind = match k.kind.as_str() {
                "device" => KeyKind::Device,
                "user" => KeyKind::User,
                "caller" => KeyKind::Caller,
                _ => return Err(ClientError::input("a key of an unknown kind")),
            };
            Ok(BackedUpKey {
                kind,
                key: keys::import_key(kind, k.key.clone())?,
            })
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    format: String,
    owner: String,
    created_ms: u64,
    nonce: String,
    ciphertext: String,
}

fn aad(owner: &str, created_ms: u64) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::json!({
        "created_ms": created_ms,
        "format": BACKUP_FORMAT,
        "owner": owner,
    }))
    .map_err(|_| ClientError::input("cannot encode the backup header"))
}

fn cipher(mut backup_key: String) -> Result<XChaCha20Poly1305> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    let written = URL_SAFE_NO_PAD.decode_slice(backup_key.trim(), bytes.as_mut_slice());
    backup_key.zeroize();
    if written.ok() != Some(32) {
        return Err(ClientError::key(
            "not a backup key (32 bytes as unpadded base64url)",
        ));
    }
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, bytes.as_slice())
        .expand(KEY_INFO, okm.as_mut_slice())
        .map_err(|_| ClientError::key("cannot derive the backup cipher key"))?;
    XChaCha20Poly1305::new_from_slice(okm.as_slice())
        .map_err(|_| ClientError::key("cannot derive the backup cipher key"))
}

/// A new random backup key, as unpadded base64url. Keep it only in the platform's end-to-end
/// encrypted store.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn generate_backup_key() -> Result<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|e| ClientError::Refused {
        detail: format!("no random source: {e}"),
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

/// Wraps the keys of `owner` under `backup_key`: the blob (JSON, format
/// [`BACKUP_FORMAT`]) to store. The keys are checked and erased.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn wrap_keys(backup_key: String, owner: String, keys: Vec<BackedUpKey>) -> Result<String> {
    let cipher = cipher(backup_key);
    let plain = encode_keys(keys)?;
    let cipher = cipher?;
    if owner.is_empty() {
        return Err(ClientError::input("the owner is empty"));
    }
    let created_ms = now_ms();
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| ClientError::Refused {
        detail: format!("no random source: {e}"),
    })?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: &aad(&owner, created_ms)?,
            },
        )
        .map_err(|_| ClientError::input("cannot encrypt the keys"))?;
    crate::owner::to_json(&Blob {
        format: BACKUP_FORMAT.into(),
        owner,
        created_ms,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

/// Opens a blob of [`wrap_keys`] for `owner` with `backup_key`.
#[cfg_attr(not(target_arch = "wasm32"), uniffi::export)]
pub fn unwrap_keys(backup_key: String, owner: String, blob: String) -> Result<Vec<BackedUpKey>> {
    let cipher = cipher(backup_key)?;
    if blob.len() > MAX_BACKUP_LEN {
        return Err(ClientError::input("larger than a key backup may be"));
    }
    let blob: Blob = serde_json::from_str(&blob).map_err(ClientError::json("key backup"))?;
    if blob.format != BACKUP_FORMAT {
        return Err(ClientError::input(format!("not a {BACKUP_FORMAT} backup")));
    }
    let refused = |detail: &str| ClientError::BackupRefused {
        detail: detail.into(),
    };
    if blob.owner != owner {
        return Err(refused("the backup is of another owner"));
    }
    let nonce: [u8; 24] = URL_SAFE_NO_PAD
        .decode(&blob.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| ClientError::input("key backup: the nonce is not 24 bytes"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&blob.ciphertext)
        .map_err(|_| ClientError::input("key backup: the ciphertext is not base64url"))?;
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad(&blob.owner, blob.created_ms)?,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| refused("another backup key, or the backup was changed"))?;
    decode_keys(&plain)
}
