//! Grants: how an owner hands a node its user key, and takes it back.
//!
//! A device of the owner signs the terms of a grant (owner, node, expiry, issue time, pinned
//! record generations) and seals them with the user key to the node with HPKE (RFC 9180,
//! DHKEM X25519 + HKDF-SHA256 + ChaCha20-Poly1305). Only the node that holds the matching
//! [`NodeSealKey`] can open it, and the node checks:
//!
//! - the signature, under the device named in the grant;
//! - that the device is one the node already knows for the owner (from an earlier grant or an
//!   endorsement), or that the user key is the one of the grant in force. The first grant of an
//!   owner on a node is trusted on first use;
//! - that the grant was issued within [`MAX_SKEW_MS`](crate::caller::MAX_SKEW_MS) of the clock
//!   of the node and after every grant or revocation of the owner before it, so a stored grant
//!   cannot be replayed.
//!
//! A [`Revocation`] is signed by a known device in the same way.
//!
//! [`NodeIdentity::report_data`] is the value a hardware attestation (TEE quote) of the node
//! carries, so an owner can check that the seal key belongs to attested code before it grants.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::encoding::{self, b64_array, b64_vec, canonical};
use crate::keys::{DeviceKey, DevicePublicKey, KEY_LEN, NodeKey, NodePublicKey, UserKey};
use crate::{Error, Result};

const GRANT_DOMAIN: &[u8] = b"grant/v1\0";
const REVOKE_DOMAIN: &[u8] = b"revoke/v1\0";
const REPORT_DOMAIN: &[u8] = b"node-identity/v1\0";
const SEAL_INFO: &[u8] = b"credentials grant/v1";
const SEAL_KEY_INFO: &[u8] = b"node-seal-key/v1\0";
const USER_KEY_ID: &[u8] = b"user-key-id/v1\0";
/// Most pins in one grant.
pub const MAX_PINS: usize = 256;

type Kem = X25519HkdfSha256;

fn invalid(rule: &'static str) -> Error {
    Error::GrantInvalid { rule }
}

/// The public key owners seal grants to (X25519).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeSealKey(#[serde(with = "b64_array")] [u8; 32]);

impl NodeSealKey {
    /// The key as unpadded URL-safe base64.
    pub fn to_b64(&self) -> String {
        encoding::to_b64(&self.0)
    }

    /// Reads a key from unpadded URL-safe base64.
    pub fn from_b64(text: &str) -> Result<Self> {
        let bytes = encoding::array_from_b64(text).map_err(|_| Error::KeyInvalid)?;
        <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes).map_err(|_| Error::KeyInvalid)?;
        Ok(Self(bytes))
    }
}

/// What an owner needs to know about a node: the key that verifies its log and the key grants
/// are sealed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeIdentity {
    /// Verifies the log entries of the node.
    pub log_key: NodePublicKey,
    /// Grants are sealed to it.
    pub seal_key: NodeSealKey,
}

impl NodeIdentity {
    /// The 64 bytes a hardware attestation of the node (the report data of an SGX, TDX or
    /// SEV-SNP quote) must carry: SHA-512 over both keys. An owner checks the quote, then
    /// that its report data equals this, before it seals a grant to `seal_key`.
    pub fn report_data(&self) -> [u8; 64] {
        let mut hash = Sha512::new();
        hash.update(REPORT_DOMAIN);
        hash.update(self.log_key.to_b64().as_bytes());
        hash.update(b".");
        hash.update(self.seal_key.to_b64().as_bytes());
        hash.finalize().into()
    }
}

/// The private half of a [`NodeSealKey`], derived from the node key.
pub(crate) struct SealSecret(<Kem as hpke::Kem>::PrivateKey);

impl SealSecret {
    /// The seal key pair of a node: SHA-256 of the node key under a domain, then the DHKEM
    /// key derivation of RFC 9180. A restored node key gives the same pair.
    pub(crate) fn of(node: &NodeKey) -> (Self, NodeSealKey) {
        let bytes = node.to_bytes();
        let mut hash = Sha256::new();
        hash.update(SEAL_KEY_INFO);
        hash.update(bytes.as_slice());
        let ikm = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
        let (private, public) = Kem::derive_keypair(ikm.as_slice());
        let mut key = [0u8; 32];
        key.copy_from_slice(public.to_bytes().as_slice());
        (Self(private), NodeSealKey(key))
    }
}

/// A record generation the owner pins with a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPin {
    /// The record.
    pub record_id: String,
    /// The lowest generation the node may accept.
    pub generation: u64,
}

/// The terms of a grant, as the device signs them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTerms {
    /// The owner.
    pub owner: String,
    /// End of the grant, Unix milliseconds; a node shortens it to 30 days.
    pub expires_ms: u64,
    /// When the device made the grant, Unix milliseconds.
    pub issued_ms: u64,
    /// The lowest generation of each record of the owner the node may accept.
    pub pins: Vec<RecordPin>,
}

#[derive(Serialize)]
struct GrantMessage<'a> {
    terms: &'a GrantTerms,
    node: &'a NodePublicKey,
    device: &'a DevicePublicKey,
    #[serde(with = "b64_array")]
    user_key_id: [u8; 32],
}

/// The part of a grant beside the user key, inside the seal.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    terms: GrantTerms,
    device: DevicePublicKey,
    #[serde(with = "b64_array")]
    signature: [u8; 64],
}

/// A grant sealed to one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedGrant {
    /// The encapsulated key of HPKE.
    #[serde(with = "b64_vec")]
    pub enc: Vec<u8>,
    /// The user key and the signed terms, encrypted.
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

/// A grant the node opened and whose signature verified.
pub(crate) struct OpenedGrant {
    pub(crate) terms: GrantTerms,
    pub(crate) device: DevicePublicKey,
    pub(crate) user_key: UserKey,
}

fn user_key_id(user_key: &UserKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(USER_KEY_ID);
    hash.update(user_key.bytes());
    hash.finalize().into()
}

fn grant_message(
    terms: &GrantTerms,
    node: &NodePublicKey,
    device: &DevicePublicKey,
    user_key: &UserKey,
) -> Result<Vec<u8>> {
    canonical(
        GRANT_DOMAIN,
        &GrantMessage {
            terms,
            node,
            device,
            user_key_id: user_key_id(user_key),
        },
    )
}

impl DeviceKey {
    /// Grants `node` the user key on `terms`, sealed so only that node can open it. Check the
    /// attestation of the node against [`NodeIdentity::report_data`] first.
    pub fn grant(
        &self,
        user_key: &UserKey,
        node: &NodeIdentity,
        terms: GrantTerms,
    ) -> Result<SealedGrant> {
        if terms.pins.len() > MAX_PINS {
            return Err(invalid("too many pins"));
        }
        let device = self.public();
        let signature = self.sign(&grant_message(&terms, &node.log_key, &device, user_key)?);
        let body = serde_json::to_vec(&GrantBody {
            terms,
            device,
            signature,
        })
        .map_err(|_| Error::Encoding)?;
        let mut plain = Zeroizing::new(Vec::with_capacity(KEY_LEN + body.len()));
        plain.extend_from_slice(user_key.bytes());
        plain.extend_from_slice(&body);
        let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(&node.seal_key.0)
            .map_err(|_| Error::KeyInvalid)?;
        let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &recipient,
            SEAL_INFO,
            &plain,
            node.log_key.to_b64().as_bytes(),
        )
        .map_err(|_| Error::KeyInvalid)?;
        Ok(SealedGrant {
            enc: enc.to_bytes().to_vec(),
            ciphertext,
        })
    }
}

impl SealedGrant {
    /// Opens the grant with the seal secret of `node` and verifies its signature.
    pub(crate) fn open(&self, secret: &SealSecret, node: &NodePublicKey) -> Result<OpenedGrant> {
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&self.enc)
            .map_err(|_| invalid("encapsulated key malformed"))?;
        let plain = Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeR::Base,
                &secret.0,
                &enc,
                SEAL_INFO,
                &self.ciphertext,
                node.to_b64().as_bytes(),
            )
            .map_err(|_| invalid("not sealed to this node"))?,
        );
        let (key, body) = plain
            .split_at_checked(KEY_LEN)
            .ok_or(invalid("grant too short"))?;
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(key);
        let user_key = UserKey::from_bytes(&mut bytes);
        let body: GrantBody =
            serde_json::from_slice(body).map_err(|_| invalid("grant body malformed"))?;
        let message = grant_message(&body.terms, node, &body.device, &user_key)?;
        body.device
            .verify(&message, &body.signature)
            .map_err(|_| invalid("grant signature does not verify"))?;
        Ok(OpenedGrant {
            terms: body.terms,
            device: body.device,
            user_key,
        })
    }
}

/// An owner taking its user key back from a node, signed by one of its devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    /// The owner.
    pub owner: String,
    /// The node.
    pub node: NodePublicKey,
    /// When the device made it, Unix milliseconds.
    pub issued_ms: u64,
    /// The device.
    pub device: DevicePublicKey,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct RevokeMessage<'a> {
    owner: &'a str,
    node: &'a NodePublicKey,
    issued_ms: u64,
}

impl Revocation {
    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            REVOKE_DOMAIN,
            &RevokeMessage {
                owner: &self.owner,
                node: &self.node,
                issued_ms: self.issued_ms,
            },
        )
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.device
            .verify(&self.message()?, &self.signature)
            .map_err(|_| invalid("revocation signature does not verify"))
    }
}

impl DeviceKey {
    /// Takes the user key of `owner` back from `node`.
    pub fn revoke(&self, owner: &str, node: &NodePublicKey, issued_ms: u64) -> Result<Revocation> {
        let mut revocation = Revocation {
            owner: owner.to_string(),
            node: *node,
            issued_ms,
            device: self.public(),
            signature: [0; 64],
        };
        revocation.signature = self.sign(&revocation.message()?);
        Ok(revocation)
    }
}
