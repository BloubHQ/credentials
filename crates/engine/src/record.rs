//! Records: a credential at rest.
//!
//! The plaintext is the encoded [`Fields`]; the ciphertext is ChaCha20-Poly1305 under the
//! record key. The associated data binds the version, the id, the owner, the generation and
//! the signed policy, so none of them can be swapped without the record failing to open.
//!
//! The generation grows by one each time the record is sealed again (a node capturing a new
//! token, a device changing the policy). A node refuses a record older than one it saw, and
//! the owner can pin the lowest generation a node accepts ([`Pin`]); together they stop an
//! operator from handing back an older record (a rollback).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, b64_vec, canonical};
use crate::fields::Fields;
use crate::keys::{DeviceKey, DevicePublicKey, UserKey};
use crate::policy::{Policy, SignedPolicy};
use crate::{Error, Result};

/// The record format version.
pub const VERSION: u8 = 2;

const AAD_DOMAIN: &[u8] = b"record/v2\0";
const PIN_DOMAIN: &[u8] = b"pin/v1\0";

/// A stored credential. The operator stores it; only a holder of the user key opens it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Format version.
    pub v: u8,
    /// Record id, unique per owner.
    pub id: String,
    /// The owner (account id).
    pub owner: String,
    /// Grows by one with each sealing; a store can use it for compare-and-swap.
    pub generation: u64,
    /// The policy, signed by a device of the owner.
    pub policy: SignedPolicy,
    /// AEAD nonce.
    #[serde(with = "b64_array")]
    pub nonce: [u8; 12],
    /// AEAD ciphertext and tag.
    #[serde(with = "b64_vec")]
    pub ct: Vec<u8>,
}

#[derive(Serialize)]
struct Header<'a> {
    v: u8,
    id: &'a str,
    owner: &'a str,
    generation: u64,
    policy: &'a SignedPolicy,
}

/// Checks an id or an owner: 1 to 128 visible ASCII characters.
pub(crate) fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::RecordInvalid);
    }
    Ok(())
}

/// The fields hold every required field of the policy and no field it does not list.
fn check_fields(policy: &Policy, fields: &Fields) -> Result<()> {
    let have = fields.names();
    let unlisted = have
        .iter()
        .find(|n| !policy.fields.iter().any(|f| f.name == **n))
        .map(|n| n.to_string());
    let missing = policy
        .fields
        .iter()
        .find(|f| !f.optional && !have.contains(&f.name.as_str()))
        .map(|f| f.name.clone());
    match unlisted.or(missing) {
        None => Ok(()),
        Some(field) => Err(Error::FieldMissing { field }),
    }
}

fn cipher(user_key: &UserKey, id: &str) -> Result<ChaCha20Poly1305> {
    let key = user_key.record_key(id)?;
    ChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::KeyInvalid)
}

impl Record {
    fn aad(&self) -> Result<Vec<u8>> {
        canonical(
            AAD_DOMAIN,
            &Header {
                v: self.v,
                id: &self.id,
                owner: &self.owner,
                generation: self.generation,
                policy: &self.policy,
            },
        )
    }

    fn sealed(
        user_key: &UserKey,
        id: &str,
        owner: &str,
        generation: u64,
        policy: SignedPolicy,
        fields: &Fields,
    ) -> Result<Record> {
        check_name(id)?;
        check_name(owner)?;
        policy.policy.validate()?;
        check_fields(&policy.policy, fields)?;
        let plain = fields.encode()?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut record = Record {
            v: VERSION,
            id: id.to_string(),
            owner: owner.to_string(),
            generation,
            policy,
            nonce,
            ct: Vec::new(),
        };
        let aad = record.aad()?;
        record.ct = cipher(user_key, id)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Encoding)?;
        Ok(record)
    }

    /// Encrypts the fields under their policy, as generation 1. Runs on the device.
    pub fn seal(
        user_key: &UserKey,
        id: &str,
        owner: &str,
        policy: SignedPolicy,
        fields: &Fields,
    ) -> Result<Record> {
        Self::sealed(user_key, id, owner, 1, policy, fields)
    }

    fn next_generation(&self) -> Result<u64> {
        self.generation.checked_add(1).ok_or(Error::RecordInvalid)
    }

    /// The same record (id, owner, policy) with new field values, one generation later. Runs
    /// on the node after an operation captured a value into a field.
    pub(crate) fn reseal(&self, user_key: &UserKey, fields: &Fields) -> Result<Record> {
        Self::sealed(
            user_key,
            &self.id,
            &self.owner,
            self.next_generation()?,
            self.policy.clone(),
            fields,
        )
    }

    /// The record under a new policy, with the values it holds now and one generation later.
    /// Fields the new policy does not list are dropped; fields it requires must be present.
    /// Runs on the device: the values never leave the engine.
    pub fn rewrap(&self, user_key: &UserKey, policy: SignedPolicy) -> Result<Record> {
        let old = self.open(user_key)?;
        let mut fields = Fields::new();
        for (name, value) in old.values() {
            if policy.policy.fields.iter().any(|f| f.name == name) {
                fields.set(name, zeroize::Zeroizing::new(value.to_vec()))?;
            }
        }
        Self::sealed(
            user_key,
            &self.id,
            &self.owner,
            self.next_generation()?,
            policy,
            &fields,
        )
    }

    /// Decrypts the fields. Only the engine can call this.
    pub(crate) fn open(&self, user_key: &UserKey) -> Result<Fields> {
        if self.v != VERSION {
            return Err(Error::RecordInvalid);
        }
        check_name(&self.id)?;
        check_name(&self.owner)?;
        let aad = self.aad()?;
        let plain = zeroize::Zeroizing::new(
            cipher(user_key, &self.id)?
                .decrypt(
                    Nonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::RecordOpen)?,
        );
        let fields = Fields::decode(&plain)?;
        check_fields(&self.policy.policy, &fields)?;
        Ok(fields)
    }
}

/// The lowest generation of a record a node may accept, signed by a device of the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// The owner.
    pub owner: String,
    /// The record.
    pub record_id: String,
    /// The lowest generation accepted.
    pub generation: u64,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct PinBody<'a> {
    owner: &'a str,
    record_id: &'a str,
    generation: u64,
}

impl Pin {
    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            PIN_DOMAIN,
            &PinBody {
                owner: &self.owner,
                record_id: &self.record_id,
                generation: self.generation,
            },
        )
    }

    /// Verifies the signature under one of `devices`.
    pub(crate) fn verify(&self, devices: &[DevicePublicKey]) -> Result<()> {
        let message = self.message()?;
        if devices
            .iter()
            .any(|d| d.verify(&message, &self.signature).is_ok())
        {
            Ok(())
        } else {
            Err(Error::PolicySignature)
        }
    }
}

impl DeviceKey {
    /// Pins `record` on nodes: they refuse any older generation of it. Runs on the device
    /// after it sealed or rewrapped the record.
    pub fn pin(&self, record: &Record) -> Result<Pin> {
        let mut pin = Pin {
            owner: record.owner.clone(),
            record_id: record.id.clone(),
            generation: record.generation,
            signature: [0; 64],
        };
        pin.signature = self.sign(&pin.message()?);
        Ok(pin)
    }
}
