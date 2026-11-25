//! The write-ahead log.
//!
//! Every act of a node (a grant, a revoke, a use of a value) is an entry that the node signs
//! and chains to the entry before it. The node performs the act only after its [`LogSink`]
//! confirmed the entry: the act needs a [`Confirmed`], and only [`Log::commit`] makes one,
//! after the sink returned `Ok`.
//!
//! ```compile_fail
//! // A confirmation cannot be made outside this module.
//! let _ = engine::log::Confirmed { seq: 0 };
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64_array, canonical};
use crate::keys::{NodeKey, NodePublicKey};
use crate::policy::Method;
use crate::{Error, Result};

const ENTRY_DOMAIN: &[u8] = b"entry/v1\0";
const HASH_DOMAIN: &[u8] = b"entry-hash/v1\0";

/// What an entry records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// The node took the user key of the owner until `expires_ms`.
    Grant {
        /// End of the grant, Unix milliseconds.
        expires_ms: u64,
    },
    /// The node erased the user key of the owner.
    Revoke,
    /// The node sent one request that carries the value of a record (one step of an HTTP
    /// operation).
    Use {
        /// The operation.
        operation: String,
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
    },
    /// The node opened one connection for a stream operation.
    Stream {
        /// The operation.
        operation: String,
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
        /// SHA-256 over the sends of the caller, each prefixed by its length (u32, big-endian).
        #[serde(with = "b64_array")]
        sends_sha256: [u8; 32],
    },
    /// The node rendered a derivation and handed the output back.
    Derive {
        /// The operation.
        operation: String,
        /// SHA-256 of the input.
        #[serde(with = "b64_array")]
        input_sha256: [u8; 32],
    },
    /// The node sealed the record again with values an operation captured.
    Update {
        /// The operation.
        operation: String,
        /// The fields that changed.
        fields: Vec<String>,
    },
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
    /// Time of the entry, Unix milliseconds.
    pub time_ms: u64,
    /// The owner.
    pub owner: String,
    /// The record, or empty for grant and revoke.
    pub record_id: String,
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
    halted: bool,
}

impl Log {
    /// A new, empty chain signed by `key`.
    pub fn new(key: NodeKey) -> Self {
        Self {
            key,
            next_seq: 0,
            head: [0; 32],
            halted: false,
        }
    }

    /// The public key that verifies the entries.
    pub fn public_key(&self) -> NodePublicKey {
        self.key.public()
    }

    /// Writes an entry and returns the confirmation of the act.
    ///
    /// When the sink fails, the entry may or may not be stored. The log halts: it refuses every
    /// later entry, so no act happens on a chain whose state is unknown.
    pub fn commit<S: LogSink>(
        &mut self,
        sink: &mut S,
        time_ms: u64,
        owner: &str,
        record_id: &str,
        event: Event,
    ) -> Result<(SignedEntry, Confirmed)> {
        if self.halted {
            return Err(Error::LogHalted);
        }
        let entry = Entry {
            seq: self.next_seq,
            prev: self.head,
            time_ms,
            owner: owner.to_string(),
            record_id: record_id.to_string(),
            event,
        };
        let signature = self.key.sign(&canonical(ENTRY_DOMAIN, &entry)?);
        let signed = SignedEntry { entry, signature };
        let hash = signed.hash()?;
        if sink.append(&signed).is_err() {
            self.halted = true;
            return Err(Error::LogUnconfirmed);
        }
        let seq = self.next_seq;
        self.head = hash;
        self.next_seq = seq.checked_add(1).ok_or(Error::LogHalted)?;
        Ok((signed, Confirmed { seq }))
    }
}

/// Verifies a whole chain from its first entry and returns the hash of its head.
pub fn verify_chain(entries: &[SignedEntry], node: &NodePublicKey) -> Result<[u8; 32]> {
    let mut prev = [0u8; 32];
    let mut last_time = 0u64;
    for (seq, signed) in (0u64..).zip(entries) {
        let entry = &signed.entry;
        if entry.seq != seq || entry.prev != prev || entry.time_ms < last_time {
            return Err(Error::ChainBroken { seq });
        }
        signed
            .verify(node)
            .map_err(|_| Error::EntrySignature { seq })?;
        prev = signed.hash()?;
        last_time = entry.time_ms;
    }
    Ok(prev)
}

/// A sink in memory, for tests and development. It can be told to fail.
#[derive(Default)]
pub struct MemorySink {
    entries: Vec<SignedEntry>,
    failing: bool,
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
}

impl LogSink for MemorySink {
    fn append(&mut self, entry: &SignedEntry) -> Result<()> {
        if self.failing {
            return Err(Error::LogUnconfirmed);
        }
        self.entries.push(entry.clone());
        Ok(())
    }
}
