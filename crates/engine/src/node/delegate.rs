//! Delegations on a node: taking them, changing them, and admitting the calls of delegates
//! ([`crate::delegation`]).
//!
//! A delegation is kept in the node's state, and in its log sealed under the node's own state
//! key (like spending limits), so a restarted node keeps it, and the waiting period of
//! emergency access, and every change a device of the owner made. A hand-over to a successor
//! release does not carry it: its keys are sealed to this node, and the owner delegates again
//! on the successor.

use std::sync::Arc;

use super::{Clock, Node, State};
use crate::caller::{Authorization, MAX_SKEW_MS};
use crate::delegation::{
    Change, Delegation, DelegationChange, MAX_PER_OWNER, MAX_PER_RECORD, RecordKeys,
    check_narrower, policy_sha256,
};
use crate::grant::SealSecret;
use crate::keys::DevicePublicKey;
use crate::limits::StateKey;
use crate::log::{Entry, Event, LogSink, SealedDetail};
use crate::policy::SignedPolicy;
use crate::record::Record;
use crate::{Error, Result};

/// The sealing label of a delegation in the log.
const DELEGATION: &str = "delegation";

/// A delegation the node took: what a delegated call is checked and run with.
pub(super) struct Delegated {
    pub record_id: String,
    pub delegate: String,
    pub policy: SignedPolicy,
    pub base_sha256: [u8; 32],
    pub device: DevicePublicKey,
    pub wait_ms: u64,
    pub expires_ms: u64,
    pub keys: Arc<RecordKeys>,
}

/// A delegation in the state, with the end of the waiting period of an open request of
/// emergency access.
pub(super) struct Slot {
    pub delegated: Arc<Delegated>,
    pub opens_ms: Option<u64>,
}

fn invalid(rule: &'static str) -> Error {
    Error::DelegationInvalid { rule }
}

fn slot_of(delegation: &Delegation, keys: RecordKeys) -> Slot {
    Slot {
        delegated: Arc::new(Delegated {
            record_id: delegation.record_id.clone(),
            delegate: delegation.delegate.clone(),
            policy: delegation.policy.clone(),
            base_sha256: delegation.base_sha256,
            device: delegation.device,
            wait_ms: delegation.wait_ms,
            expires_ms: delegation.expires_ms,
            keys: Arc::new(keys),
        }),
        opens_ms: None,
    }
}

/// Takes back a delegation the node logged, when it restarts.
pub(super) fn restore<S: LogSink>(
    state: &mut State<S>,
    seal: &SealSecret,
    state_key: &StateKey,
    entry: &Entry,
    sealed: &SealedDetail,
) -> Result<()> {
    let delegation: Delegation =
        state_key.open(&entry.owner, &entry.record_id, DELEGATION, sealed)?;
    let keys = delegation.open_keys(seal)?;
    state.delegations.insert(
        (delegation.owner.clone(), delegation.id),
        slot_of(&delegation, keys),
    );
    Ok(())
}

/// Admits a call under `delegated` now, with the state locked: the delegation is still in
/// force for this record and not lapsed, and, with a waiting period, its request is past
/// the wait. The first call of a delegate starts the wait (logged under both owners) and is
/// refused, like every call until the wait ends.
pub(super) fn admit<S: LogSink>(
    state: &mut State<S>,
    record: &Record,
    id: [u8; 16],
    caller: &str,
    now: u64,
) -> Result<()> {
    let key = (record.owner.clone(), id);
    let (delegated, opens) = match state.delegations.get(&key) {
        Some(slot) => (slot.delegated.clone(), slot.opens_ms),
        None => return Err(Error::DelegationUnknown),
    };
    if delegated.record_id != record.id {
        return Err(Error::DelegationUnknown);
    }
    if now >= delegated.expires_ms {
        state.delegations.remove(&key);
        return Err(Error::DelegationUnknown);
    }
    if delegated.wait_ms == 0 {
        return Ok(());
    }
    match opens {
        Some(opens_ms) if now >= opens_ms => Ok(()),
        Some(opens_ms) => Err(Error::DelegationWaiting { opens_ms }),
        None => {
            let opens_ms = now.saturating_add(delegated.wait_ms);
            state.commit(
                now,
                (&record.owner, &record.id, caller),
                Event::AccessRequest { id, opens_ms },
            )?;
            state.commit(
                now,
                (&delegated.delegate, "", ""),
                Event::AccessRequest { id, opens_ms },
            )?;
            if let Some(slot) = state.delegations.get_mut(&key) {
                slot.opens_ms = Some(opens_ms);
            }
            Err(Error::DelegationWaiting { opens_ms })
        }
    }
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// The delegation a call names, if it names one. A call that names a delegation the node
    /// does not hold for the record's owner is refused.
    pub(super) fn delegation_of(
        &self,
        record: &Record,
        auth: &Authorization,
    ) -> Result<Option<Arc<Delegated>>> {
        let Some(id) = auth.delegation else {
            return Ok(None);
        };
        self.lock()?
            .delegations
            .get(&(record.owner.clone(), id))
            .map(|slot| Some(slot.delegated.clone()))
            .ok_or(Error::DelegationUnknown)
    }

    /// Takes a delegation a known device of the owner signed for this node: issued within five
    /// minutes of the node's clock and after the owner's last act, not yet ended, for a record
    /// whose signed policy it names, with a delegated policy signed by the same device and no
    /// wider than the record's. The node logs it under the owner (sealed: the policy and the
    /// keys) and under the delegate, then keeps it.
    ///
    /// `record` is the record as the owner holds it now: the node checks its policy against
    /// the delegation's, never opens it, and keeps nothing of it.
    pub fn delegate(&self, delegation: &Delegation, record: &Record) -> Result<()> {
        if delegation.node != self.public {
            return Err(invalid("delegation for another node"));
        }
        delegation.validate()?;
        if record.owner != delegation.owner || record.id != delegation.record_id {
            return Err(invalid("the record is not the one delegated"));
        }
        if policy_sha256(&record.policy)? != delegation.base_sha256 {
            return Err(invalid("the record's policy is not the one delegated"));
        }
        let now = self.clock.now_ms();
        if delegation.expires_ms <= now {
            return Err(invalid("the delegation has ended"));
        }
        let owner = delegation.owner.as_str();
        let devices = self.lock()?.devices(owner);
        if !devices.contains(&delegation.device) {
            return Err(Error::GrantDenied);
        }
        delegation.verify()?;
        let base = record.policy.verify_any(&devices)?;
        let delegated = delegation
            .policy
            .verify(&delegation.device)
            .map_err(|_| invalid("the delegated policy is not signed by the same device"))?;
        check_narrower(base, delegated)?;
        let keys = delegation.open_keys(&self.seal)?;
        let sealed = self
            .state_key
            .seal(owner, &delegation.record_id, DELEGATION, delegation)?;
        let mut state = self.lock()?;
        state.check_issued(owner, delegation.issued_ms, now)?;
        let key = (owner.to_string(), delegation.id);
        if state.delegations.contains_key(&key) {
            return Err(invalid("a delegation of this id exists"));
        }
        let of_owner = state.delegations.keys().filter(|(o, _)| o == owner).count();
        let of_record = state
            .delegations
            .iter()
            .filter(|((o, _), s)| o == owner && s.delegated.record_id == delegation.record_id)
            .count();
        if of_owner >= MAX_PER_OWNER || of_record >= MAX_PER_RECORD {
            return Err(invalid(
                "at most 16 delegations per record and 64 per owner",
            ));
        }
        state.commit(
            now,
            (owner, &delegation.record_id, ""),
            Event::Delegate {
                id: delegation.id,
                delegate: delegation.delegate.clone(),
                wait_ms: delegation.wait_ms,
                expires_ms: delegation.expires_ms,
                issued_ms: delegation.issued_ms,
                device: Box::new(delegation.device),
                sealed: Box::new(sealed),
            },
        )?;
        state.commit(
            now,
            (&delegation.delegate, "", ""),
            Event::Delegated {
                id: delegation.id,
                from: owner.to_string(),
                record_id: delegation.record_id.clone(),
                wait_ms: delegation.wait_ms,
                expires_ms: delegation.expires_ms,
            },
        )?;
        state.issued(owner, delegation.issued_ms);
        state.delegations.insert(key, slot_of(delegation, keys));
        Ok(())
    }

    /// Cancels the open request of emergency access, or revokes a delegation, as a known
    /// device of the owner signed for this node, issued within five minutes of its clock and
    /// after the owner's last act. Logged under both owners. A call of the delegate already
    /// running finishes; waiting operations it started are dropped on a revoke.
    pub fn change_delegation(&self, change: &DelegationChange) -> Result<()> {
        if change.node != self.public {
            return Err(invalid("change for another node"));
        }
        change.verify()?;
        let now = self.clock.now_ms();
        if change.issued_ms.abs_diff(now) > MAX_SKEW_MS {
            return Err(invalid("issued too long ago or in the future"));
        }
        let owner = change.owner.as_str();
        let mut state = self.lock()?;
        if !state.devices(owner).contains(&change.device) {
            return Err(Error::GrantDenied);
        }
        state.check_issued(owner, change.issued_ms, now)?;
        let key = (owner.to_string(), change.id);
        let delegate = match state.delegations.get(&key) {
            Some(slot) if slot.delegated.record_id == change.record_id => {
                if change.change == Change::Cancel && slot.opens_ms.is_none() {
                    return Err(invalid("no request of emergency access is open"));
                }
                slot.delegated.delegate.clone()
            }
            _ => return Err(Error::DelegationUnknown),
        };
        let revoke = change.change == Change::Revoke;
        let event = || Event::Undelegate {
            id: change.id,
            revoke,
            issued_ms: change.issued_ms,
            device: change.device,
        };
        state.commit(now, (owner, &change.record_id, ""), event())?;
        state.commit(now, (&delegate, "", ""), event())?;
        state.issued(owner, change.issued_ms);
        if revoke {
            state.delegations.remove(&key);
            let prefix = format!("{delegate}/");
            state.parked.drop_callers(owner, &change.record_id, &prefix);
        } else if let Some(slot) = state.delegations.get_mut(&key) {
            slot.opens_ms = None;
        }
        Ok(())
    }
}
