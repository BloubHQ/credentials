//! Records: a credential at rest.
//!
//! The plaintext is the encoded [`Fields`]; the ciphertext is ChaCha20-Poly1305 under the
//! record key. The associated data binds the version, the id, the owner and the signed policy,
//! so none of them can be swapped without the record failing to open.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, b64_vec, canonical};
use crate::fields::Fields;
use crate::keys::UserKey;
use crate::policy::{Policy, SignedPolicy};
use crate::{Error, Result};

/// The record format version.
pub const VERSION: u8 = 1;

const AAD_DOMAIN: &[u8] = b"record/v1\0";

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
    /// The policy, signed by the device of the owner.
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
    let listed = have
        .iter()
        .all(|n| policy.fields.iter().any(|f| f.name == *n));
    let complete = policy
        .fields
        .iter()
        .all(|f| f.optional || have.contains(&f.name.as_str()));
    if listed && complete {
        Ok(())
    } else {
        Err(Error::FieldMissing)
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
                policy: &self.policy,
            },
        )
    }

    /// Encrypts the fields under their policy. Runs on the device.
    pub fn seal(
        user_key: &UserKey,
        id: &str,
        owner: &str,
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

    /// The same record (id, owner, policy) with new field values and a new nonce. Runs on the
    /// node after an operation captured a value into a field.
    pub(crate) fn reseal(&self, user_key: &UserKey, fields: &Fields) -> Result<Record> {
        Record::seal(user_key, &self.id, &self.owner, self.policy.clone(), fields)
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
