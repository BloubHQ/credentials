//! Keys.
//!
//! - [`UserKey`]: created on the device of the owner; a node holds it only while a grant is in
//!   force. Record keys are derived from it.
//! - [`DeviceKey`]: stays on a device of the owner; it signs policies, pins and the
//!   endorsements of other devices.
//! - [`CallerKey`]: held by an application or agent the owner lets use a record; it signs each
//!   call.
//! - [`NodeKey`]: held by a node; it signs the log entries of that node. Keep its bytes
//!   ([`NodeKey::to_bytes`]) to continue the chain after a restart.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::{self, b64_array};
use crate::secret::Secret;
use crate::{Error, Result};

/// Length of a symmetric key in bytes.
pub const KEY_LEN: usize = 32;

const RECORD_KEY_INFO: &[u8] = b"record-key/v1\0";

/// The user key of an owner.
pub struct UserKey(Secret<[u8; KEY_LEN]>);

impl UserKey {
    /// Creates a random user key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        UnwrapErr(SysRng).fill_bytes(&mut bytes);
        let key = Self(Secret::new(bytes));
        bytes.zeroize();
        key
    }

    /// Takes the bytes of a user key and erases the caller's copy.
    pub fn from_bytes(bytes: &mut [u8; KEY_LEN]) -> Self {
        let key = Self(Secret::new(*bytes));
        bytes.zeroize();
        key
    }

    /// The key of one record: HKDF-SHA256 of the user key with the record id.
    pub(crate) fn record_key(&self, record_id: &str) -> Result<Secret<[u8; KEY_LEN]>> {
        let hkdf = Hkdf::<Sha256>::new(None, self.0.expose());
        let mut info = Vec::with_capacity(RECORD_KEY_INFO.len() + record_id.len());
        info.extend_from_slice(RECORD_KEY_INFO);
        info.extend_from_slice(record_id.as_bytes());
        let mut okm = [0u8; KEY_LEN];
        hkdf.expand(&info, &mut okm)
            .map_err(|_| Error::KeyInvalid)?;
        let key = Secret::new(okm);
        okm.zeroize();
        Ok(key)
    }
}

macro_rules! public_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "b64_array")] [u8; 32]);

        impl $name {
            /// The key as unpadded URL-safe base64.
            pub fn to_b64(&self) -> String {
                encoding::to_b64(&self.0)
            }

            /// Reads a key from unpadded URL-safe base64.
            pub fn from_b64(text: &str) -> Result<Self> {
                let bytes = encoding::array_from_b64(text).map_err(|_| Error::KeyInvalid)?;
                VerifyingKey::from_bytes(&bytes).map_err(|_| Error::KeyInvalid)?;
                Ok(Self(bytes))
            }

            pub(crate) fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
                let key = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::KeyInvalid)?;
                key.verify_strict(message, &Signature::from_bytes(signature))
                    .map_err(|_| Error::SignatureInvalid)
            }
        }
    };
}

public_key!(
    DevicePublicKey,
    "The public key of a device: it verifies policies."
);
public_key!(
    NodePublicKey,
    "The public key of a node: it verifies log entries."
);
public_key!(
    CallerPublicKey,
    "The public key of a caller: it verifies the authorizations of calls."
);

macro_rules! signing_key {
    ($name:ident, $public:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(SigningKey);

        impl $name {
            /// Creates a random key.
            pub fn generate() -> Self {
                Self(SigningKey::generate(&mut UnwrapErr(SysRng)))
            }

            /// Takes the 32 secret bytes of a key and erases the caller's copy.
            pub fn from_bytes(bytes: &mut [u8; 32]) -> Self {
                let key = Self(SigningKey::from_bytes(bytes));
                bytes.zeroize();
                key
            }

            /// The 32 secret bytes, to store the key (encrypted) and restore it later.
            pub fn to_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
                zeroize::Zeroizing::new(self.0.to_bytes())
            }

            /// The public key.
            pub fn public(&self) -> $public {
                $public(self.0.verifying_key().to_bytes())
            }

            pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
                self.0.sign(message).to_bytes()
            }
        }
    };
}

signing_key!(
    DeviceKey,
    DevicePublicKey,
    "The signing key of a device. It never leaves the device."
);
signing_key!(NodeKey, NodePublicKey, "The signing key of a node.");
signing_key!(
    CallerKey,
    CallerPublicKey,
    "The signing key of a caller (an application or agent)."
);

const ENDORSE_DOMAIN: &[u8] = b"endorse/v2\0";
const RETIRE_DOMAIN: &[u8] = b"retire/v1\0";

/// A device of the owner vouching for another device on one node, so the node accepts the
/// policies, pins and grants the new device signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endorsement {
    /// The owner.
    pub owner: String,
    /// The node it is for.
    pub node: NodePublicKey,
    /// The new device.
    pub device: DevicePublicKey,
    /// When it was made, Unix milliseconds. A node takes it only within five minutes of its
    /// clock and after the last grant, revocation or device change of the owner.
    pub issued_ms: u64,
    /// Ed25519 signature of a device the node already accepts for the owner.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

/// A device of the owner withdrawing another device (lost, sold, replaced) on one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retirement {
    /// The owner.
    pub owner: String,
    /// The node it is for.
    pub node: NodePublicKey,
    /// The device withdrawn.
    pub device: DevicePublicKey,
    /// When it was made, Unix milliseconds, as for an [`Endorsement`].
    pub issued_ms: u64,
    /// Ed25519 signature of another device the node accepts for the owner.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct DeviceChangeBody<'a> {
    owner: &'a str,
    node: &'a NodePublicKey,
    device: &'a DevicePublicKey,
    issued_ms: u64,
}

fn change_message(
    domain: &[u8],
    owner: &str,
    node: &NodePublicKey,
    device: &DevicePublicKey,
    issued_ms: u64,
) -> Result<Vec<u8>> {
    encoding::canonical(
        domain,
        &DeviceChangeBody {
            owner,
            node,
            device,
            issued_ms,
        },
    )
}

/// The device of `devices` whose signature over `message` verifies.
fn signer(
    devices: &[DevicePublicKey],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<DevicePublicKey> {
    devices
        .iter()
        .find(|d| d.verify(message, signature).is_ok())
        .copied()
        .ok_or(Error::PolicySignature)
}

impl Endorsement {
    /// Verifies the signature under one of `devices` and returns that device.
    pub(crate) fn verify(&self, devices: &[DevicePublicKey]) -> Result<DevicePublicKey> {
        let message = change_message(
            ENDORSE_DOMAIN,
            &self.owner,
            &self.node,
            &self.device,
            self.issued_ms,
        )?;
        signer(devices, &message, &self.signature)
    }
}

impl Retirement {
    /// Verifies the signature under one of `devices` other than the one withdrawn.
    pub(crate) fn verify(&self, devices: &[DevicePublicKey]) -> Result<DevicePublicKey> {
        let message = change_message(
            RETIRE_DOMAIN,
            &self.owner,
            &self.node,
            &self.device,
            self.issued_ms,
        )?;
        let others: Vec<_> = devices
            .iter()
            .copied()
            .filter(|d| *d != self.device)
            .collect();
        signer(&others, &message, &self.signature)
    }
}

impl DeviceKey {
    /// Vouches for `device` as another device of `owner` on `node`, at `issued_ms`.
    pub fn endorse(
        &self,
        owner: &str,
        node: &NodePublicKey,
        device: &DevicePublicKey,
        issued_ms: u64,
    ) -> Result<Endorsement> {
        Ok(Endorsement {
            owner: owner.to_string(),
            node: *node,
            device: *device,
            issued_ms,
            signature: self.sign(&change_message(
                ENDORSE_DOMAIN,
                owner,
                node,
                device,
                issued_ms,
            )?),
        })
    }

    /// Withdraws `device` of `owner` on `node`, at `issued_ms`. A device cannot withdraw
    /// itself, and the last device of an owner cannot be withdrawn.
    pub fn retire(
        &self,
        owner: &str,
        node: &NodePublicKey,
        device: &DevicePublicKey,
        issued_ms: u64,
    ) -> Result<Retirement> {
        Ok(Retirement {
            owner: owner.to_string(),
            node: *node,
            device: *device,
            issued_ms,
            signature: self.sign(&change_message(
                RETIRE_DOMAIN,
                owner,
                node,
                device,
                issued_ms,
            )?),
        })
    }
}

impl UserKey {
    /// The 32 secret bytes, to store the key (encrypted, on the device of the owner) and
    /// restore it with [`UserKey::from_bytes`].
    pub fn to_bytes(&self) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        zeroize::Zeroizing::new(*self.0.expose())
    }

    /// The key as base64url, the form `credentials verify --user-key` reads.
    pub fn to_b64(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(crate::encoding::to_b64(self.0.expose()))
    }

    /// Reads a key written by [`UserKey::to_b64`].
    pub fn from_b64(text: &str) -> Result<Self> {
        use base64::Engine;
        let mut bytes = zeroize::Zeroizing::new([0u8; KEY_LEN]);
        let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(text.trim(), bytes.as_mut_slice())
            .map_err(|_| Error::KeyInvalid)?;
        if written != KEY_LEN {
            return Err(Error::KeyInvalid);
        }
        Ok(Self::from_bytes(&mut bytes))
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        self.0.expose()
    }
}
