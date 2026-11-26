//! Operations that wait: kept in the memory of the node only, bounded per owner, in total and
//! in bytes, and dropped when they lapse, when the owner revokes and when the node restarts.

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::Captured;
use crate::approval::ApprovalSummary;
use crate::fields::Fields;
use crate::limits::Spend;
use crate::record::Record;
use crate::request::Request;
use crate::response::Http;
use crate::session::Pending;
use crate::template::Budget;
use crate::{Error, Result};

/// Most operations one owner may have waiting on a node.
pub const MAX_PARKED_PER_OWNER: usize = 8;
/// Most operations waiting on a node.
pub const MAX_PARKED: usize = 256;
/// Most bytes of values all waiting operations hold.
pub const MAX_PARKED_BYTES: usize = 128 * 1024 * 1024;

/// The sealing labels of the node's own state in the log.
pub(super) const SPEND: &str = "spend";
pub(super) const LIMITS: &str = "limits";

/// What an operation waits for.
pub(super) enum Wait {
    /// A code from a device of the owner, kept here once it came.
    Code {
        into: String,
        pattern: String,
        answer: Option<Zeroizing<Vec<u8>>>,
    },
    /// The site, which the node polls no sooner than `next_poll_ms`.
    External { next_poll_ms: u64 },
    /// The owner's approval of `summary`.
    Approval {
        summary: Box<ApprovalSummary>,
        approved: bool,
    },
}

/// What the caller gave when it started the operation.
pub(super) enum Given {
    Http(Option<Request>),
    Derive { given: Vec<u8>, input: Vec<u8> },
}

/// The values of an operation that waits at an `await`.
pub(super) struct Saved {
    pub fields: Fields,
    pub captured: Captured,
    pub tainted: Vec<Zeroizing<Vec<u8>>>,
    pub budget: Budget,
    pub last: Option<Http>,
    pub log_seqs: Vec<u64>,
}

impl Saved {
    fn bytes(&self) -> usize {
        let last = self.last.as_ref().map_or(0, |h| {
            h.body.len()
                + h.headers
                    .iter()
                    .map(|(n, v)| n.len() + v.len())
                    .sum::<usize>()
        });
        self.fields.total()
            + self.captured.temps_len
            + self.captured.secrets.iter().map(|s| s.len()).sum::<usize>()
            + self.tainted.iter().map(|t| t.len()).sum::<usize>()
            + last
    }
}

/// One operation that waits.
pub(super) struct Parked {
    pub owner: String,
    /// The record the caller resumes with: the one it called with, or the one the node sealed
    /// before the operation waited.
    pub record: Record,
    pub caller: String,
    pub operation: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// The index of the `await` the operation waits at (0 for an approval before any step).
    pub at: usize,
    pub wait: Wait,
    pub given: Given,
    /// The payment to count when an approved operation goes on.
    pub spend: Option<Spend>,
    /// The values of an operation that waits at an `await`; none for an approval.
    pub saved: Option<Saved>,
    /// What the caller was told, told again while the operation still waits.
    pub pending: Pending,
}

impl Parked {
    pub fn bytes(&self) -> usize {
        let given = match &self.given {
            Given::Http(None) => 0,
            Given::Http(Some(r)) => {
                r.path.len()
                    + r.body.len()
                    + r.headers
                        .iter()
                        .map(|(n, v)| n.len() + v.len())
                        .sum::<usize>()
            }
            Given::Derive { given, input } => given.len() + input.len(),
        };
        // A fixed part for the record and the bookkeeping.
        4096 + given + self.saved.as_ref().map_or(0, Saved::bytes)
    }
}

/// The operations that wait on a node.
#[derive(Default)]
pub(super) struct Registry {
    entries: HashMap<[u8; 16], (Parked, usize)>,
    bytes: usize,
}

impl Registry {
    /// Drops what lapsed.
    fn sweep(&mut self, now: u64) {
        let lapsed: Vec<[u8; 16]> = self
            .entries
            .iter()
            .filter(|(_, (p, _))| p.expires_ms <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in lapsed {
            self.remove(&id);
        }
    }

    /// Fails with [`Error::ParkedFull`] when the owner, or the node, has no room for one more
    /// operation that waits.
    pub fn room(&mut self, owner: &str, now: u64) -> Result<()> {
        self.sweep(now);
        let of_owner = self
            .entries
            .values()
            .filter(|(p, _)| p.owner == owner)
            .count();
        if self.entries.len() >= MAX_PARKED
            || of_owner >= MAX_PARKED_PER_OWNER
            || self.bytes >= MAX_PARKED_BYTES
        {
            return Err(Error::ParkedFull);
        }
        Ok(())
    }

    /// Keeps an operation that waits under `id`.
    pub fn insert(&mut self, id: [u8; 16], parked: Parked, now: u64) -> Result<()> {
        self.room(&parked.owner, now)?;
        let bytes = parked.bytes();
        if self.bytes.saturating_add(bytes) > MAX_PARKED_BYTES || self.entries.contains_key(&id) {
            return Err(Error::ParkedFull);
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.entries.insert(id, (parked, bytes));
        Ok(())
    }

    /// The operation that waits under `id`, unless it lapsed.
    pub fn get_mut(&mut self, id: &[u8; 16], now: u64) -> Option<&mut Parked> {
        self.sweep(now);
        self.entries.get_mut(id).map(|(p, _)| p)
    }

    /// Takes the operation that waits under `id` out.
    pub fn remove(&mut self, id: &[u8; 16]) -> Option<Parked> {
        let (parked, bytes) = self.entries.remove(id)?;
        self.bytes = self.bytes.saturating_sub(bytes);
        Some(parked)
    }

    /// Drops every operation of `owner`.
    pub fn drop_owner(&mut self, owner: &str) {
        let ids: Vec<[u8; 16]> = self
            .entries
            .iter()
            .filter(|(_, (p, _))| p.owner == owner)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove(&id);
        }
    }

    /// Drops the operations of `record_id` of `owner` whose caller name starts with
    /// `prefix` (the callers of one delegate).
    pub fn drop_callers(&mut self, owner: &str, record_id: &str, prefix: &str) {
        let ids: Vec<[u8; 16]> = self
            .entries
            .iter()
            .filter(|(_, (p, _))| {
                p.owner == owner && p.record.id == record_id && p.caller.starts_with(prefix)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove(&id);
        }
    }

    /// How many operations wait, after dropping what lapsed.
    pub fn len(&mut self, now: u64) -> usize {
        self.sweep(now);
        self.entries.len()
    }
}
