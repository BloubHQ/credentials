//! Hand-over to a successor node (`docs/design.md`, section 10).
//!
//! A Nitro node has no sealed storage: a new release is a new node, with a new key. The old
//! node (the predecessor) moves what it holds to the new one (the successor) once the
//! hand-over protocol (crate `continuity`) checked the successor's attestation against a
//! successor statement signed by the release workflow:
//!
//! 1. [`Node::hand_over`] gathers, for every owner, the devices it knows and the ones that
//!    were withdrawn, the issue time of the owner's last grant, revocation or device change,
//!    the floors of its records, its spending limits with the payments counted, the head of
//!    its chain, and its grant (the user key) when the owner allowed a successor
//!    ([`crate::grant::GrantTerms::allow_successor`]). It seals all of it with HPKE to the
//!    successor's seal key, bound to both nodes, the sequence number, the release and the
//!    statement; writes an [`Event::HandOver`] entry naming the successor, the release, the
//!    statement and the SHA-256 of the sealed package; and then stops for good: every later
//!    act is refused ([`Error::HandedOver`]), so its chain ends at the hand-over and cannot
//!    fork.
//! 2. [`Node::take_over`], on a new node with an empty log, checks the entry under the
//!    predecessor's key, that it names this node, and that the package is the one it names;
//!    opens the package, starts its chain after the hand-over entry with an
//!    [`Event::Continue`] entry, and writes an [`Event::Carry`] entry per owner before it takes
//!    the state on. `credentials verify` then checks one chain across both nodes.
//!
//! Records (items) are sealed under the owner's user key, not the node's: they move with the
//! grant, and the floors keep older copies out on the successor too.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{Clock, Grant, Node, State};
use crate::encoding::{b64_array, b64_vec, canonical};
use crate::grant::{NodeIdentity, RecordPin};
use crate::keys::{DevicePublicKey, NodePublicKey, UserKey};
use crate::limits::{Ledger, LedgerState, StateKey};
use crate::log::{CarriedLimits, Event, LogSink, SignedEntry};
use crate::record::check_name;
use crate::{Error, Result};

/// The largest sealed package a successor opens, in bytes.
pub const MAX_PACKAGE: usize = 256 * 1024 * 1024;

const PACKAGE_INFO: &[u8] = b"credentials hand-over/v1";
const PACKAGE_DOMAIN: &[u8] = b"hand-over/v1\0";
const PACKAGE_HASH_DOMAIN: &[u8] = b"hand-over-package/v1\0";
/// What the state key seals carried limits as.
const CARRIED_LIMITS: &str = "carried-limits";

fn invalid(rule: &'static str) -> Error {
    Error::HandOverInvalid { rule }
}

/// The successor a node hands over to, after the hand-over protocol checked its attestation
/// against a signed successor statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Successor {
    /// The keys of the successor its attestation vouches for.
    pub identity: NodeIdentity,
    /// The release the successor runs, as the statement names it.
    pub release: String,
    /// SHA-256 of the successor statement.
    pub statement_sha256: [u8; 32],
}

/// What a node hands its successor: the hand-over entry, the last of its chain, and the
/// package sealed to the successor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandOver {
    /// The [`Event::HandOver`] entry, signed by the predecessor.
    pub entry: SignedEntry,
    /// The encapsulated key of HPKE.
    #[serde(with = "b64_vec")]
    pub enc: Vec<u8>,
    /// The state of the predecessor, encrypted to the successor.
    #[serde(with = "b64_vec")]
    pub ciphertext: Vec<u8>,
}

impl HandOver {
    /// The SHA-256 the hand-over entry names: over the encapsulated key (with its length)
    /// and the ciphertext.
    pub fn package_sha256(&self) -> [u8; 32] {
        package_sha256(&self.enc, &self.ciphertext)
    }
}

fn package_sha256(enc: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PACKAGE_HASH_DOMAIN);
    hash.update(u64::try_from(enc.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(enc);
    hash.update(ciphertext);
    hash.finalize().into()
}

/// What a successor took over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakenOver {
    /// Owners whose devices, floors and limits came over.
    pub owners: u64,
    /// Grants that came over.
    pub grants: u64,
}

/// The state of a node that handed over.
pub(super) struct Done {
    /// The successor and what it was handed, to hand it again if it did not arrive; `None`
    /// after a restore.
    hand_over: Option<(NodeIdentity, HandOver)>,
}

impl Done {
    pub(super) fn restored(_hash: [u8; 32]) -> Self {
        Self { hand_over: None }
    }
}

#[derive(Serialize)]
struct PackageHeader<'a> {
    predecessor: &'a NodePublicKey,
    successor: &'a NodeIdentity,
    seq: u64,
    release: &'a str,
    #[serde(with = "b64_array")]
    statement_sha256: [u8; 32],
}

fn header(
    predecessor: &NodePublicKey,
    successor: &NodeIdentity,
    seq: u64,
    release: &str,
    statement_sha256: [u8; 32],
) -> Result<Vec<u8>> {
    canonical(
        PACKAGE_DOMAIN,
        &PackageHeader {
            predecessor,
            successor,
            seq,
            release,
            statement_sha256,
        },
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    predecessor: NodePublicKey,
    seq: u64,
    owners: Vec<CarriedOwner>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedOwner {
    owner: String,
    devices: Vec<DevicePublicKey>,
    retired: Vec<DevicePublicKey>,
    issued_ms: u64,
    floors: Vec<RecordPin>,
    #[serde(with = "b64_array")]
    head: [u8; 32],
    grant: Option<CarriedGrant>,
    limits: Vec<CarriedLedger>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct CarriedGrant {
    #[serde(with = "b64_array")]
    user_key: [u8; 32],
    expires_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedLedger {
    record_id: String,
    ledger: LedgerState,
}

/// Every owner the state knows of, with what moves to a successor.
fn gather<S: LogSink>(state: &State<S>, now: u64) -> Result<(Vec<CarriedOwner>, u64)> {
    let mut floors: HashMap<&str, Vec<RecordPin>> = HashMap::new();
    for ((owner, id), generation) in &state.floors {
        floors.entry(owner).or_default().push(RecordPin {
            record_id: id.clone(),
            generation: *generation,
        });
    }
    let mut limits: HashMap<&str, Vec<CarriedLedger>> = HashMap::new();
    for ((owner, id), ledger) in &state.limits {
        limits.entry(owner).or_default().push(CarriedLedger {
            record_id: id.clone(),
            ledger: ledger.snapshot(),
        });
    }
    let names: BTreeSet<&str> = state
        .owners
        .keys()
        .map(String::as_str)
        .chain(state.grants.keys().map(String::as_str))
        .chain(floors.keys().copied())
        .chain(limits.keys().copied())
        .collect();
    let mut grants = 0u64;
    let mut carried = Vec::with_capacity(names.len());
    for name in names {
        let owner = state.owners.get(name);
        let grant = state
            .grants
            .get(name)
            .filter(|g| g.allow_successor && g.expires_ms > now)
            .map(|g| CarriedGrant {
                user_key: *g.user_key.to_bytes(),
                expires_ms: g.expires_ms,
            });
        if grant.is_some() {
            grants = grants.saturating_add(1);
        }
        let mut pins = floors.remove(name).unwrap_or_default();
        pins.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        let mut ledgers = limits.remove(name).unwrap_or_default();
        ledgers.sort_by(|a, b| a.record_id.cmp(&b.record_id));
        carried.push(CarriedOwner {
            owner: name.to_string(),
            devices: owner.map(|o| o.devices.clone()).unwrap_or_default(),
            retired: owner.map(|o| o.retired.clone()).unwrap_or_default(),
            issued_ms: owner.map_or(0, |o| o.issued_ms),
            floors: pins,
            head: state.log.owner_head(name).unwrap_or([0; 32]),
            grant,
            limits: ledgers,
        });
    }
    Ok((carried, grants))
}

/// Takes on the devices, issue time, floors and limits of one owner a successor took over.
pub(super) fn restore_carry<S: LogSink>(
    state: &mut State<S>,
    key: &StateKey,
    owner: &str,
    (devices, retired, issued_ms): (&[DevicePublicKey], &[DevicePublicKey], u64),
    pins: &[RecordPin],
    limits: &[CarriedLimits],
) -> Result<()> {
    for device in devices {
        state.know_device(owner, *device);
    }
    for device in retired {
        state.forget_device(owner, device);
    }
    state.issued(owner, issued_ms);
    for pin in pins {
        state.raise(owner, &pin.record_id, pin.generation);
    }
    for carried in limits {
        let ledger: LedgerState =
            key.open(owner, &carried.record_id, CARRIED_LIMITS, &carried.sealed)?;
        state.limits.insert(
            (owner.to_string(), carried.record_id.clone()),
            Ledger::from_state(ledger)?,
        );
    }
    Ok(())
}

fn check_carried(owner: &CarriedOwner) -> Result<()> {
    check_name(&owner.owner).map_err(|_| invalid("an owner name is invalid"))?;
    for pin in &owner.floors {
        check_name(&pin.record_id).map_err(|_| invalid("a record name is invalid"))?;
    }
    for ledger in &owner.limits {
        check_name(&ledger.record_id).map_err(|_| invalid("a record name is invalid"))?;
    }
    if owner.devices.iter().any(|d| owner.retired.contains(d)) {
        return Err(invalid("a device is both known and retired"));
    }
    Ok(())
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Hands everything this node holds over to `successor` and stops: see the module
    /// documentation. Call it only after the hand-over protocol checked the successor's
    /// attestation against a signed successor statement (crate `continuity` does).
    ///
    /// Grants whose owners did not allow a successor stay behind and are erased. Called again
    /// with the same successor, it hands back the same [`HandOver`] (one that did not arrive);
    /// with another, it fails with [`Error::HandedOver`].
    pub fn hand_over(&self, successor: &Successor) -> Result<HandOver> {
        let now = self.clock.now_ms();
        let mut guard = self.lock()?;
        let state = &mut *guard;
        if let Some(done) = &state.handed_over {
            return match &done.hand_over {
                Some((to, hand_over)) if *to == successor.identity => Ok(hand_over.clone()),
                _ => Err(Error::HandedOver),
            };
        }
        if successor.identity.log_key == self.public
            || successor.identity.seal_key == self.identity.seal_key
        {
            return Err(invalid("a node cannot hand over to itself"));
        }
        if state.log.is_halted() {
            return Err(Error::LogHalted);
        }
        let (owners, grants) = gather(state, now)?;
        let count = u64::try_from(owners.len()).unwrap_or(u64::MAX);
        let seq = state.log.len();
        let package = Package {
            predecessor: self.public,
            seq,
            owners,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&package).map_err(|_| Error::Encoding)?);
        drop(package);
        if plain.len() > MAX_PACKAGE {
            return Err(invalid("the state is larger than a package holds"));
        }
        let aad = header(
            &self.public,
            &successor.identity,
            seq,
            &successor.release,
            successor.statement_sha256,
        )?;
        let (enc, ciphertext) =
            crate::grant::seal_to(&successor.identity.seal_key, PACKAGE_INFO, &aad, &plain)?;
        let event = Event::HandOver {
            successor: Box::new(successor.identity),
            release: successor.release.clone(),
            statement_sha256: Box::new(successor.statement_sha256),
            package_sha256: Box::new(package_sha256(&enc, &ciphertext)),
            owners: count,
            grants,
        };
        // Logged first, like every act: a hand-over the sink did not take changes nothing.
        let (entry, _confirmed) = state
            .log
            .commit(&mut state.sink, now, ("", "", ""), event)?;
        let hand_over = HandOver {
            entry,
            enc,
            ciphertext,
        };
        state.handed_over = Some(Done {
            hand_over: Some((successor.identity, hand_over.clone())),
        });
        self.handed_over
            .store(true, std::sync::atomic::Ordering::Release);
        // The user keys stay only in the package now; operations that wait are dropped.
        let owners: Vec<String> = state.grants.keys().cloned().collect();
        state.grants.clear();
        for owner in owners {
            state.parked.drop_owner(&owner);
        }
        Ok(hand_over)
    }

    /// Takes over the state `hand_over` carries from the node `predecessor`, on a node that
    /// has done nothing yet: see the module documentation. Call it only after the hand-over
    /// protocol checked the predecessor's attestation (crate `continuity` does).
    ///
    /// When a write to the log fails part way, the node is halted with part of the state
    /// written and none taken on; it should be dropped, and owners grant to a new node.
    pub fn take_over(
        &self,
        predecessor: &NodePublicKey,
        hand_over: &HandOver,
    ) -> Result<TakenOver> {
        let entry = &hand_over.entry;
        entry
            .verify(predecessor)
            .map_err(|_| invalid("the hand-over entry is not signed by the predecessor"))?;
        let Event::HandOver {
            successor,
            release,
            statement_sha256,
            package_sha256: named,
            owners,
            grants,
        } = &entry.entry.event
        else {
            return Err(invalid("the entry is not a hand-over"));
        };
        if **successor != self.identity {
            return Err(invalid("the hand-over names another successor"));
        }
        if hand_over.ciphertext.len() > MAX_PACKAGE.saturating_add(64) {
            return Err(invalid("the package is too large"));
        }
        if hand_over.package_sha256() != **named {
            return Err(invalid(
                "the package is not the one the hand-over entry names",
            ));
        }
        let aad = header(
            predecessor,
            &self.identity,
            entry.entry.seq,
            release,
            **statement_sha256,
        )?;
        let plain = self
            .seal
            .open(PACKAGE_INFO, &aad, &hand_over.enc, &hand_over.ciphertext)
            .ok_or(invalid("the package is not sealed to this node"))?;
        let package: Package =
            serde_json::from_slice(&plain).map_err(|_| invalid("the package is malformed"))?;
        drop(plain);
        if package.predecessor != *predecessor || package.seq != entry.entry.seq {
            return Err(invalid("the package is not the one of this hand-over"));
        }
        let carried_grants = package.owners.iter().filter(|o| o.grant.is_some()).count();
        if u64::try_from(package.owners.len()).ok() != Some(*owners)
            || u64::try_from(carried_grants).ok() != Some(*grants)
        {
            return Err(invalid("the package does not hold what its entry counts"));
        }
        if package.owners.len() > super::MAX_OWNERS {
            return Err(invalid("too many owners"));
        }
        let mut names = BTreeSet::new();
        for owner in &package.owners {
            check_carried(owner)?;
            if !names.insert(owner.owner.as_str()) {
                return Err(invalid("an owner is carried twice"));
            }
        }
        let now = self.clock.now_ms();
        let mut guard = self.lock()?;
        let state = &mut *guard;
        if !state.log.is_empty()
            || !state.owners.is_empty()
            || !state.grants.is_empty()
            || state.handed_over.is_some()
        {
            return Err(invalid("only a node that has done nothing yet takes over"));
        }
        let heads: HashMap<String, [u8; 32]> = package
            .owners
            .iter()
            .filter(|o| o.head != [0; 32])
            .map(|o| (o.owner.clone(), o.head))
            .collect();
        state.log.rebase(entry, heads)?;
        state.commit(
            now,
            ("", "", ""),
            Event::Continue {
                predecessor: *predecessor,
                owners: *owners,
                grants: *grants,
            },
        )?;
        // Every owner is written before any state is taken on.
        let mut take = Vec::with_capacity(package.owners.len());
        for carried in &package.owners {
            let mut sealed = Vec::with_capacity(carried.limits.len());
            for ledger in &carried.limits {
                Ledger::from_state(ledger.ledger.clone())?;
                sealed.push(CarriedLimits {
                    record_id: ledger.record_id.clone(),
                    sealed: self.state_key.seal(
                        &carried.owner,
                        &ledger.record_id,
                        CARRIED_LIMITS,
                        &ledger.ledger,
                    )?,
                });
            }
            state.commit(
                now,
                (&carried.owner, "", ""),
                Event::Carry(Box::new(crate::log::Carried {
                    devices: carried.devices.clone(),
                    retired: carried.retired.clone(),
                    issued_ms: carried.issued_ms,
                    pins: carried.floors.clone(),
                    grant_expires_ms: carried.grant.as_ref().map(|g| g.expires_ms),
                    limits: sealed.clone(),
                })),
            )?;
            take.push(sealed);
        }
        for (carried, sealed) in package.owners.iter().zip(take) {
            restore_carry(
                state,
                &self.state_key,
                &carried.owner,
                (&carried.devices, &carried.retired, carried.issued_ms),
                &carried.floors,
                &sealed,
            )?;
            if let Some(grant) = &carried.grant {
                let mut bytes = grant.user_key;
                state.grants.insert(
                    carried.owner.clone(),
                    Grant {
                        user_key: Arc::new(UserKey::from_bytes(&mut bytes)),
                        expires_ms: grant.expires_ms,
                        allow_successor: true,
                    },
                );
            }
        }
        Ok(TakenOver {
            owners: *owners,
            grants: *grants,
        })
    }

    /// True once this node handed over to a successor.
    ///
    /// It reads a flag set under the state lock with the hand-over itself, without taking
    /// that lock: the live loops ask every few milliseconds, and a write to the log (under
    /// the lock) does not hold them up. Every write still checks the state under the lock.
    pub fn is_handed_over(&self) -> bool {
        self.handed_over.load(std::sync::atomic::Ordering::Acquire)
    }
}
