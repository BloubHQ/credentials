//! Keys.
//!
//! - [`UserKey`]: created on the device of the owner; a node holds it only while a grant is in
//!   force. Record keys are derived from it.
//! - [`DeviceKey`]: stays on the device; it signs the policies of the owner.
//! - [`NodeKey`]: created by a node at start; it signs the log entries of that node.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
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
        OsRng.fill_bytes(&mut bytes);
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
                    .map_err(|_| Error::KeyInvalid)
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

macro_rules! signing_key {
    ($name:ident, $public:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(SigningKey);

        impl $name {
            /// Creates a random key.
            pub fn generate() -> Self {
                Self(SigningKey::generate(&mut OsRng))
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
signing_key!(
    NodeKey,
    NodePublicKey,
    "The signing key of a node, created at start, kept in memory."
);
