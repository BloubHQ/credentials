//! The write-ahead log.
//!
//! Every act of a node (a grant, a use of a value, an update of a record) is an entry that the
//! node signs and chains to the entry before it. The node performs the act only after its
//! [`LogSink`] confirmed the entry: the act needs a [`Confirmed`], and only [`Log::commit`]
//! makes one, after the sink returned `Ok`.
//!
//! Each entry also chains to the previous entry of the same owner (`owner_prev`), so an owner
//! can verify its own entries without the entries of other owners ([`verify_owner_chain`]).
//! A [`SignedHead`] fixes the head of the chain at a point in time: given to owners or
//! published, it makes a cut tail visible.
//!
//! ```compile_fail
//! // A confirmation cannot be made outside this module.
//! let _ = engine::log::Confirmed { seq: 0 };
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

use crate::encoding::{b64_array, b64_vec, canonical};
use crate::grant::RecordPin;
use crate::keys::{DevicePublicKey, NodeKey, NodePublicKey, UserKey};
use crate::policy::Method;
use crate::{Error, Result};

const ENTRY_DOMAIN: &[u8] = b"entry/v2\0";
const HASH_DOMAIN: &[u8] = b"entry-hash/v2\0";
const HEAD_DOMAIN: &[u8] = b"head/v1\0";

/// What an entry records. The details of a use (where it went, what was sent) are sealed to
/// the owner ([`SealedDetail`]): the log store sees which record was used, when, by which
/// caller and for which operation, but not where or with what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// The node took the user key of the owner until `expires_ms`.
    Grant {
        /// End of the grant, Unix milliseconds.
        expires_ms: u64,
        /// The device that signed the grant.
        device: DevicePublicKey,
        /// When the device made the grant.
        issued_ms: u64,
        /// The record generations the grant pinned.
        pins: Vec<RecordPin>,
    },
    /// A known device endorsed another device.
    Device {
        /// The added device.
        device: DevicePublicKey,
        /// When the endorsement was made.
        issued_ms: u64,
    },
    /// A known device withdrew another device.
    Retire {
        /// The withdrawn device.
        device: DevicePublicKey,
        /// When the retirement was made.
        issued_ms: u64,
    },
    /// The node erased the user key of the owner, as a device of the owner signed.
    Revoke {
        /// When the device made the revocation.
        issued_ms: u64,
        /// The device that signed it.
        device: DevicePublicKey,
    },
    /// The owner pinned the lowest generation of a record.
    Pin {
        /// The lowest generation accepted.
        generation: u64,
    },
    /// The node sent one request that carries the value of a record (one step of an HTTP
    /// operation).
    Use {
        /// The operation.
        operation: String,
        /// The generation of the record.
        generation: u64,
        /// [`Detail::Use`], sealed to the owner.
        detail: SealedDetail,
    },
    /// The node opened one connection for a stream operation.
    Stream {
        /// The operation.
        operation: String,
        /// The generation of the record.
        generation: u64,
        /// [`Detail::Stream`], sealed to the owner.
        detail: SealedDetail,
    },
    /// The node rendered a derivation and handed the output back.
    Derive {
        /// The operation.
        operation: String,
        /// The generation of the record.
        generation: u64,
        /// [`Detail::Derive`], sealed to the owner.
        detail: SealedDetail,
    },
    /// The node sealed the record again with values an operation captured.
    Update {
        /// The operation.
        operation: String,
        /// The new generation.
        generation: u64,
        /// The fields that changed.
        fields: Vec<String>,
    },
    /// How the act of an earlier entry ended.
    Done {
        /// The sequence number of the act.
        of: u64,
        /// The HTTP status, when there was a response.
        status: Option<u16>,
        /// True when the result went back to the caller.
        ok: bool,
    },
}

/// Where a use went and what it carried, readable by the owner only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Detail {
    /// One request.
    Use {
        /// Method.
        method: Method,
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
        /// Path and query before injections (without the value).
        path: String,
        /// SHA-256 of the request body before injections.
        #[serde(with = "b64_array")]
        body_sha256: [u8; 32],
        /// Length of the request body before injections.
        body_len: u64,
    },
    /// One connection.
    Stream {
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
        /// SHA-256 over the sends of the caller, each prefixed by its length (u32,
        /// big-endian).
        #[serde(with = "b64_array")]
        sends_sha256: [u8; 32],
        /// Number of exchanges of the caller.
        exchanges: u32,
    },
    /// One derivation.
    Derive {
        /// SHA-256 of the input.
        #[serde(with = "b64_array")]
        input_sha256: [u8; 32],
        /// Length of the input.
        input_len: u64,
    },
}

/// A [`Detail`] encrypted with ChaCha20-Poly1305 under a key derived from the user key of the
/// owner, bound to the owner and the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDetail {
    /// Random nonce.
    #[serde(with = "b64_array")]
    pub nonce: [u8; 12],
    /// Ciphertext and tag.
    #[serde(with = "b64_vec")]
    pub ct: Vec<u8>,
}

const DETAIL_KEY_INFO: &[u8] = b"log-detail/v1\0";

fn detail_cipher(user_key: &UserKey) -> Result<ChaCha20Poly1305> {
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, user_key.bytes())
        .expand(DETAIL_KEY_INFO, okm.as_mut_slice())
        .map_err(|_| Error::KeyInvalid)?;
    ChaCha20Poly1305::new_from_slice(okm.as_slice()).map_err(|_| Error::KeyInvalid)
}

fn detail_aad(owner: &str, record_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(owner.len() + record_id.len() + 1);
    aad.extend_from_slice(owner.as_bytes());
    aad.push(0);
    aad.extend_from_slice(record_id.as_bytes());
    aad
}

impl Detail {
    /// Seals the detail of a use of `record_id` of `owner`.
    pub(crate) fn seal(
        &self,
        user_key: &UserKey,
        owner: &str,
        record_id: &str,
    ) -> Result<SealedDetail> {
        use chacha20poly1305::aead::{Aead, Payload};
        let plain = serde_json::to_vec(self).map_err(|_| Error::Encoding)?;
        let nonce: [u8; 12] =
            <ChaCha20Poly1305 as chacha20poly1305::aead::AeadCore>::generate_nonce(
                &mut rand_core::OsRng,
            )
            .into();
        let ct = detail_cipher(user_key)?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &detail_aad(owner, record_id),
                },
            )
            .map_err(|_| Error::Encoding)?;
        Ok(SealedDetail { nonce, ct })
    }
}

/// The detail of `entry`, for its owner. `None` for an entry without one.
pub fn open_detail(user_key: &UserKey, entry: &Entry) -> Result<Option<Detail>> {
    use chacha20poly1305::aead::{Aead, Payload};
    let sealed = match &entry.event {
        Event::Use { detail, .. } | Event::Stream { detail, .. } | Event::Derive { detail, .. } => {
            detail
        }
        _ => return Ok(None),
    };
    let plain = detail_cipher(user_key)?
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &detail_aad(&entry.owner, &entry.record_id),
            },
        )
        .map_err(|_| Error::RecordOpen)?;
    serde_json::from_slice(&plain)
        .map(Some)
        .map_err(|_| Error::Encoding)
}

/// One log entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Position in the chain of the node, from 0.
    pub seq: u64,
    /// Hash of the entry before; all zeros for the first.
    #[serde(with = "b64_array")]
    pub prev: [u8; 32],
    /// Hash of the previous entry of the same owner; all zeros for its first.
    #[serde(with = "b64_array")]
    pub owner_prev: [u8; 32],
    /// Time of the entry, Unix milliseconds; never less than the time before it.
    pub time_ms: u64,
    /// The owner.
    pub owner: String,
    /// The record, or empty.
    pub record_id: String,
    /// The caller, or empty.
    pub caller: String,
    /// The act.
    pub event: Event,
}

/// An entry with the signature of its node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEntry {
    /// The entry.
    pub entry: Entry,
    /// Ed25519 signature of the node over the canonical bytes of the entry.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl SignedEntry {
    /// The hash the next entry chains to.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(canonical(HASH_DOMAIN, &self.entry)?);
        hasher.update(self.signature);
        Ok(hasher.finalize().into())
    }

    fn verify(&self, node: &NodePublicKey) -> Result<()> {
        node.verify(&canonical(ENTRY_DOMAIN, &self.entry)?, &self.signature)
    }
}

/// The head of a chain at a point in time, signed by its node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHead {
    /// Number of entries in the chain.
    pub len: u64,
    /// Hash of the last entry; all zeros for an empty chain.
    #[serde(with = "b64_array")]
    pub head: [u8; 32],
    /// Time of the checkpoint, Unix milliseconds.
    pub time_ms: u64,
    /// Ed25519 signature of the node.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct HeadBody {
    len: u64,
    #[serde(with = "b64_array")]
    head: [u8; 32],
    time_ms: u64,
}

impl SignedHead {
    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            HEAD_DOMAIN,
            &HeadBody {
                len: self.len,
                head: self.head,
                time_ms: self.time_ms,
            },
        )
    }

    /// Verifies the signature of the node.
    pub fn verify(&self, node: &NodePublicKey) -> Result<()> {
        node.verify(&self.message()?, &self.signature)
    }
}

/// Durable storage of entries. `append` returns `Ok` only once the entry is stored for good.
pub trait LogSink {
    /// Stores one entry.
    fn append(&mut self, entry: &SignedEntry) -> Result<()>;
}

/// Proof that the sink confirmed the entry of an act. Only [`Log::commit`] makes one, and an
/// act consumes it.
#[derive(Debug)]
pub struct Confirmed {
    seq: u64,
}

impl Confirmed {
    /// The sequence number of the confirmed entry.
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// The chain state of a node.
pub struct Log {
    key: NodeKey,
    next_seq: u64,
    head: [u8; 32],
    last_time: u64,
    owner_heads: HashMap<String, [u8; 32]>,
    pending: Option<SignedEntry>,
}

impl Log {
    /// A new, empty chain signed by `key`.
    pub fn new(key: NodeKey) -> Self {
        Self {
            key,
            next_seq: 0,
            head: [0; 32],
            last_time: 0,
            owner_heads: HashMap::new(),
            pending: None,
        }
    }

    /// Continues the chain of `entries` (all of them, from seq 0), which `key` signed. Use it
    /// after a restart, with the entries the sink holds.
    pub fn resume(key: NodeKey, entries: &[SignedEntry]) -> Result<Self> {
        let head = verify_chain(entries, &key.public())?;
        let mut log = Self::new(key);
        for signed in entries {
            log.owner_heads
                .insert(signed.entry.owner.clone(), signed.hash()?);
            log.last_time = signed.entry.time_ms;
        }
        log.head = head;
        log.next_seq = u64::try_from(entries.len()).map_err(|_| Error::LogMismatch)?;
        Ok(log)
    }

    /// The public key that verifies the entries.
    pub fn public_key(&self) -> NodePublicKey {
        self.key.public()
    }

    /// True after an unconfirmed entry, until [`Log::reconcile`].
    pub fn is_halted(&self) -> bool {
        self.pending.is_some()
    }

    /// The head of the chain now, signed.
    pub fn checkpoint(&self, time_ms: u64) -> Result<SignedHead> {
        let mut head = SignedHead {
            len: self.next_seq,
            head: self.head,
            time_ms,
            signature: [0; 64],
        };
        head.signature = self.key.sign(&head.message()?);
        Ok(head)
    }

    /// Ends a halt. `stored` is the last entry the sink holds now (read back from it). If it
    /// is the unconfirmed entry, the chain goes on after it; if it is the entry before, the
    /// unconfirmed entry is dropped. Anything else is [`Error::LogMismatch`].
    pub fn reconcile(&mut self, stored: Option<&SignedEntry>) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        if stored == Some(&pending) {
            self.advance(&pending)?;
            return Ok(());
        }
        let at_head = match stored {
            None => self.next_seq == 0,
            Some(entry) => entry.hash()? == self.head,
        };
        if at_head {
            Ok(())
        } else {
            self.pending = Some(pending);
            Err(Error::LogMismatch)
        }
    }

    fn advance(&mut self, signed: &SignedEntry) -> Result<()> {
        let hash = signed.hash()?;
        self.head = hash;
        self.last_time = signed.entry.time_ms;
        self.owner_heads.insert(signed.entry.owner.clone(), hash);
        self.next_seq = self.next_seq.checked_add(1).ok_or(Error::LogHalted)?;
        Ok(())
    }

    /// Writes an entry and returns the confirmation of the act.
    ///
    /// When the sink fails, the entry may or may not be stored. The log halts: it refuses every
    /// later entry until [`Log::reconcile`], so no act happens on a chain whose state is
    /// unknown.
    pub fn commit<S: LogSink>(
        &mut self,
        sink: &mut S,
        time_ms: u64,
        who: (&str, &str, &str),
        event: Event,
    ) -> Result<(SignedEntry, Confirmed)> {
        if self.pending.is_some() {
            return Err(Error::LogHalted);
        }
        let (owner, record_id, caller) = who;
        let entry = Entry {
            seq: self.next_seq,
            prev: self.head,
            owner_prev: self.owner_heads.get(owner).copied().unwrap_or([0; 32]),
            time_ms: time_ms.max(self.last_time),
            owner: owner.to_string(),
            record_id: record_id.to_string(),
            caller: caller.to_string(),
            event,
        };
        let signature = self.key.sign(&canonical(ENTRY_DOMAIN, &entry)?);
        let signed = SignedEntry { entry, signature };
        if sink.append(&signed).is_err() {
            self.pending = Some(signed);
            return Err(Error::LogUnconfirmed);
        }
        let seq = self.next_seq;
        self.advance(&signed)?;
        Ok((signed, Confirmed { seq }))
    }
}

/// Verifies a whole chain from its first entry and returns the hash of its head.
pub fn verify_chain(entries: &[SignedEntry], node: &NodePublicKey) -> Result<[u8; 32]> {
    let mut verifier = ChainVerifier::new(*node);
    for signed in entries {
        verifier.push(signed)?;
    }
    Ok(verifier.head())
}

/// Verifies a chain entry by entry, without holding it in memory.
pub struct ChainVerifier {
    node: NodePublicKey,
    next_seq: u64,
    prev: [u8; 32],
    last_time: u64,
    owner_heads: HashMap<String, [u8; 32]>,
}

impl ChainVerifier {
    /// A verifier at the start of a chain.
    pub fn new(node: NodePublicKey) -> Self {
        Self {
            node,
            next_seq: 0,
            prev: [0; 32],
            last_time: 0,
            owner_heads: HashMap::new(),
        }
    }

    /// Checks the next entry.
    pub fn push(&mut self, signed: &SignedEntry) -> Result<()> {
        let seq = self.next_seq;
        let entry = &signed.entry;
        let owner_prev = self
            .owner_heads
            .get(&entry.owner)
            .copied()
            .unwrap_or([0; 32]);
        if entry.seq != seq
            || entry.prev != self.prev
            || entry.owner_prev != owner_prev
            || entry.time_ms < self.last_time
        {
            return Err(Error::ChainBroken { seq });
        }
        signed
            .verify(&self.node)
            .map_err(|_| Error::EntrySignature { seq })?;
        self.prev = signed.hash()?;
        self.owner_heads.insert(entry.owner.clone(), self.prev);
        self.last_time = entry.time_ms;
        self.next_seq = seq.checked_add(1).ok_or(Error::ChainBroken { seq })?;
        Ok(())
    }

    /// Number of entries checked.
    pub fn len(&self) -> u64 {
        self.next_seq
    }

    /// True before the first entry.
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Hash of the last entry checked.
    pub fn head(&self) -> [u8; 32] {
        self.prev
    }

    /// Checks that the chain so far ends at a signed head of the same node.
    pub fn matches(&self, head: &SignedHead) -> Result<()> {
        head.verify(&self.node)?;
        if head.len == self.next_seq && head.head == self.prev {
            Ok(())
        } else {
            Err(Error::ChainBroken {
                seq: self.next_seq.min(head.len),
            })
        }
    }
}

/// Verifies the entries of one owner (in order, without the entries of others) and returns
/// the hash of its last entry. Every entry must name `owner`, chain to the one before it
/// through `owner_prev`, and carry the signature of the node.
pub fn verify_owner_chain(
    entries: &[SignedEntry],
    owner: &str,
    node: &NodePublicKey,
) -> Result<[u8; 32]> {
    let mut prev = [0u8; 32];
    let mut last: Option<(u64, u64)> = None;
    for signed in entries {
        let entry = &signed.entry;
        let seq = entry.seq;
        let ordered = last.is_none_or(|(s, t)| seq > s && entry.time_ms >= t);
        if entry.owner != owner || entry.owner_prev != prev || !ordered {
            return Err(Error::ChainBroken { seq });
        }
        signed
            .verify(node)
            .map_err(|_| Error::EntrySignature { seq })?;
        prev = signed.hash()?;
        last = Some((seq, entry.time_ms));
    }
    Ok(prev)
}

/// The entries of `owner`, in the order of the chain: what a node operator hands an owner,
/// so the owner can check its own chain without seeing the entries of other owners.
///
/// The owner checks them with [`verify_owner_chain`], or offline with
/// `credentials verify <file> <node-public-key> --owner <owner>` after writing them one JSON
/// entry per line (add `--user-key <file>` to read the details).
pub fn owner_entries(entries: &[SignedEntry], owner: &str) -> Vec<SignedEntry> {
    entries
        .iter()
        .filter(|signed| signed.entry.owner == owner)
        .cloned()
        .collect()
}

/// A sink in memory, for tests and development. It can be told to fail.
#[derive(Default)]
pub struct MemorySink {
    entries: Vec<SignedEntry>,
    failing: bool,
    store_then_fail: bool,
}

impl MemorySink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// The stored entries.
    pub fn entries(&self) -> &[SignedEntry] {
        &self.entries
    }

    /// Makes every later append fail (or succeed again).
    pub fn set_failing(&mut self, failing: bool) {
        self.failing = failing;
    }

    /// Makes the next appends store the entry and then report failure (a lost acknowledgement).
    pub fn set_store_then_fail(&mut self, on: bool) {
        self.store_then_fail = on;
    }
}

impl LogSink for MemorySink {
    fn append(&mut self, entry: &SignedEntry) -> Result<()> {
        if self.failing {
            return Err(Error::LogUnconfirmed);
        }
        self.entries.push(entry.clone());
        if self.store_then_fail {
            return Err(Error::LogUnconfirmed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn owner_entries_form_the_chain_of_one_owner() {
        let key = NodeKey::generate();
        let node = key.public();
        let mut log = Log::new(key);
        let mut sink = MemorySink::new();
        for (time, owner) in [
            (1, "alice"),
            (2, "bob"),
            (3, "alice"),
            (4, "bob"),
            (5, "alice"),
        ] {
            log.commit(
                &mut sink,
                time,
                (owner, "rec", ""),
                Event::Pin { generation: 1 },
            )
            .unwrap();
        }
        let all = sink.entries();
        let alice = owner_entries(all, "alice");
        assert_eq!(
            alice.iter().map(|s| s.entry.seq).collect::<Vec<_>>(),
            [0, 2, 4]
        );
        let last = all.last().unwrap().hash().unwrap();
        assert_eq!(verify_owner_chain(&alice, "alice", &node).unwrap(), last);
        let bob = owner_entries(all, "bob");
        assert_eq!(bob.len(), 2);
        verify_owner_chain(&bob, "bob", &node).unwrap();
        assert!(owner_entries(all, "carol").is_empty());
        // The whole log is not the chain of one owner.
        assert_eq!(
            verify_owner_chain(all, "alice", &node),
            Err(Error::ChainBroken { seq: 1 })
        );
    }
}
