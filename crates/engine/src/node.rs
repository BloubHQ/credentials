//! A node: it holds grants and performs the operations of owners.
//!
//! Order of every act, and why:
//! 1. grant in force; record pinned by its owner and not older than one the node saw or the
//!    owner pinned; policy signed by a known device of the owner;
//! 2. the caller is one the policy lists for the operation, its signature over this call
//!    verifies, the call is fresh and not a replay, and within the limit of the caller;
//! 3. request within the operation; record opened; templates rendered within the budget
//!    (failures up to here leave no entry: nothing happened);
//! 4. entry confirmed by the sink ([`Log::commit`]), else nothing is sent or handed back;
//! 5. request sent (or connection opened) through the [`Transport`], once per entry, outside
//!    the lock of the node;
//! 6. values captured; a changed field is logged ([`Event::Update`]) and sealed into a new
//!    record, which the caller gets back even when a later step fails;
//! 7. captured secrets redacted and the response checked for secrets before it is handed back.
//!
//! A node is shared between threads: every method takes `&self`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::call::{Body, Output, SignedCall};
use crate::caller::{Authorization, Call, MAX_SKEW_MS, Payload};
use crate::egress::Stream;
use crate::egress::{ClientIdentity, Transport, dispatch, open_stream};
use crate::fields::Fields;
use crate::grant::{NodeIdentity, NodeSealKey, OpenedGrant, Revocation, SealSecret, SealedGrant};
use crate::item::Description;
use crate::keys::{DevicePublicKey, Endorsement, NodeKey, NodePublicKey, Retirement, UserKey};
use crate::log::{Detail, Event, Log, LogSink, SignedEntry, SignedHead};
use crate::policy::{
    Capture, Compute, Connection, Destination, Identity, Kinds, MAX_DELIMITER, MAX_DELIMITERS,
    Method, ModuleRef, Open, Operation, Policy, RunModule, Send, Step, StepRequest, Store,
};
use crate::record::{Pin, Record, check_name};
use crate::reflection::{self, MIN_NEEDLE, Secrets};
use crate::request::{self, Inputs, MAX_BODY, Outbound, Request};
use crate::response::{Http, MAX_RESPONSE};
use crate::template::{Budget, Context, Template, Temps, Var};
use crate::{Error, Result};

mod browser;
mod handover;
mod live;
mod park;
mod proto;
mod waits;

pub use browser::{Filled, MAX_CDP_COMMANDS, MAX_CDP_EVENTS};
pub use handover::{HandOver, MAX_PACKAGE, Successor, TakenOver};
pub use live::{
    CallerFrame, Closed, FromCaller, MAX_STREAMS, MAX_STREAMS_PER_CALLER, MAX_STREAMS_PER_OWNER,
    Part, Relay,
};
pub use park::{MAX_PARKED, MAX_PARKED_BYTES, MAX_PARKED_PER_OWNER};
pub use proto::{CommandResult, MAX_COMMANDS_PER_CALL, MAX_MAIL_PER_CALL, SessionOutput};

pub use crate::caller::{CallerExchange, DESCRIBE};
pub use crate::response::Response;

/// Longest grant: 30 days.
pub const MAX_GRANT_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Longest input of a derivation, in bytes.
pub const MAX_INPUT: usize = 1024 * 1024;
/// Most exchanges of the caller on one stream.
pub const MAX_EXCHANGES: usize = 64;
/// Largest datagram of a `udp` operation: the largest UDP payload over IPv4.
pub const MAX_DATAGRAM: usize = 65_507;
/// Most bytes of all temporary values of one operation.
pub const MAX_TEMPS: usize = 1024 * 1024;
/// Most nonces a node remembers.
pub const MAX_NONCES: usize = 1_000_000;
/// The most owners one node keeps state for.
pub const MAX_OWNERS: usize = 1_000_000;
/// Calls one caller may make on one owner within the replay window (five minutes), whatever
/// its policy limit: a caller cannot fill the replay cache all owners share.
pub const MAX_NONCES_PER_CALLER: usize = 100_000;
/// How far ahead of the node clock an authorization may be dated.
pub const MAX_FUTURE_MS: u64 = 60 * 1000;

/// A source of time.
pub trait Clock {
    /// Now, Unix milliseconds.
    fn now_ms(&self) -> u64;
}

/// Now by the system clock, Unix milliseconds: the time unit of every `_ms` value.
pub fn now_ms() -> u64 {
    SystemClock.now_ms()
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// The result of an operation, and the record sealed again when the operation captured a
/// value into a field. The new record replaces the old one even when `result` is an error:
/// store it, or the next call fails with [`Error::RecordStale`].
#[derive(Debug)]
#[must_use = "a new record in `record` must replace the old one, even when `result` is an error"]
pub struct Outcome<T> {
    /// What the operation handed back.
    pub result: Result<T>,
    /// The record with the captured values, when one changed.
    pub record: Option<Record>,
}

/// What a stream operation handed back: the reads of the exchanges that ran, and the error
/// that stopped the rest, if any.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamOutput {
    /// One read per exchange that completed, after redaction and the reflection check.
    pub reads: Vec<Vec<u8>>,
    /// The error that ended the exchanges early.
    pub error: Option<Error>,
}

/// Values captured during one operation.
#[derive(Default)]
struct Captured {
    temps: Temps,
    temps_len: usize,
    secrets: Vec<Zeroizing<Vec<u8>>>,
    changed: Vec<String>,
}

impl Captured {
    fn store(
        &mut self,
        policy: &Policy,
        fields: &mut Fields,
        capture: &Capture,
        value: Option<Zeroizing<Vec<u8>>>,
        now: u64,
    ) -> Result<()> {
        let Some(value) = value else {
            return if capture.optional {
                Ok(())
            } else {
                Err(Error::CaptureMissing)
            };
        };
        match &capture.into {
            Store::Field { name } => {
                // A server must not move another secret into this field.
                let holds_other = fields.values().any(|(other, secret)| {
                    other != name
                        && policy.is_secret(other)
                        && secret.len() >= MIN_NEEDLE
                        && reflection_contains(&value, secret)
                });
                if holds_other {
                    return Err(Error::Reflection);
                }
                self.secrets.push(value.clone());
                fields.set(name, value)?;
                if !self.changed.contains(name) {
                    self.changed.push(name.clone());
                }
                // A session the node obtained lasts what its rule says, from now.
                let rule = policy
                    .fields
                    .iter()
                    .find(|f| f.name == *name)
                    .and_then(|f| f.session.as_ref());
                if let Some(rule) = rule {
                    let expires = now.saturating_add(rule.lifetime_ms).to_string();
                    fields.set(&rule.expires, Zeroizing::new(expires.into_bytes()))?;
                    if !self.changed.contains(&rule.expires) {
                        self.changed.push(rule.expires.clone());
                    }
                }
            }
            Store::Temp { name, secret } => {
                self.temps_len = self.temps_len.saturating_add(value.len());
                if self.temps_len > MAX_TEMPS {
                    return Err(Error::Budget {
                        what: "captured values",
                    });
                }
                if *secret {
                    self.secrets.push(value.clone());
                }
                self.temps.insert(name.clone(), value);
            }
        }
        Ok(())
    }
}

fn reflection_contains(haystack: &[u8], needle: &[u8]) -> bool {
    crate::response::find(haystack, needle).is_some()
}

fn stream_vars(host: &str, now: u64) -> HashMap<Var, Vec<u8>> {
    let mut random = [0u8; 16];
    UnwrapErr(SysRng).fill_bytes(&mut random);
    HashMap::from([
        (Var::Host, host.as_bytes().to_vec()),
        (Var::Unix, (now / 1000).to_string().into_bytes()),
        (Var::UnixMs, now.to_string().into_bytes()),
        (Var::Nonce, crate::primitives::hex(&random).to_vec()),
    ])
}

fn render_identity(
    identity: Option<&Identity>,
    fields: &Fields,
    host: &str,
    now: u64,
    budget: &Budget,
) -> Result<Option<ClientIdentity>> {
    let Some(identity) = identity else {
        return Ok(None);
    };
    let temps = Temps::new();
    let ctx = Context {
        fields,
        temps: &temps,
        vars: stream_vars(host, now),
        unix: now / 1000,
        budget,
    };
    let cert = Template::parse(&identity.cert)?.render(&ctx)?;
    let key = Template::parse(&identity.key)?.render(&ctx)?;
    Ok(Some(ClientIdentity::new(cert, key)))
}

/// The clock and a fresh nonce, for a `compute` step of an operation with a connection.
fn compute_vars(now: u64) -> HashMap<Var, Vec<u8>> {
    let mut vars = stream_vars("", now);
    vars.remove(&Var::Host);
    vars
}

/// Redacts and checks the projected response before it is handed back.
fn release_http(mut response: Response, secrets: &Secrets<'_>) -> Result<Response> {
    for (_, value) in &mut response.headers {
        reflection::redact(value, secrets.captured);
    }
    reflection::redact(&mut response.body, secrets.captured);
    let bytes = Zeroizing::new(response.to_bytes());
    reflection::check(&bytes, secrets)?;
    Ok(response)
}

struct Grant {
    user_key: Arc<UserKey>,
    expires_ms: u64,
    /// The owner lets a hand-over move this grant to a successor release.
    allow_successor: bool,
}

/// What a node keeps about an owner after its grants end: the devices it knows and the issue
/// time of the last grant or revocation, so a stored one cannot be replayed.
#[derive(Default)]
struct Owner {
    devices: Vec<DevicePublicKey>,
    /// Devices withdrawn: they cannot come back by granting, only by a new endorsement.
    retired: Vec<DevicePublicKey>,
    issued_ms: u64,
}

type RecordKey = (String, String);

/// The one-time nonces of recent authorizations, expired in time order, with a quota for
/// each caller of each owner.
#[derive(Default)]
struct Nonces {
    seen: HashMap<[u8; 32], [u8; 32]>,
    by_expiry: std::collections::BTreeSet<(u64, [u8; 32])>,
    per_caller: HashMap<[u8; 32], usize>,
}

impl Nonces {
    fn expire(&mut self, now: u64) {
        while let Some(&(expires, tag)) = self.by_expiry.first() {
            if expires > now {
                break;
            }
            self.by_expiry.pop_first();
            if let Some(who) = self.seen.remove(&tag)
                && let Some(count) = self.per_caller.get_mut(&who)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_caller.remove(&who);
                }
            }
        }
    }

    fn insert(&mut self, tag: [u8; 32], who: [u8; 32], expires: u64, now: u64) -> Result<()> {
        self.expire(now);
        if self.seen.contains_key(&tag) {
            return Err(Error::CallerInvalid {
                rule: "authorization used before",
            });
        }
        if self.per_caller.get(&who).copied().unwrap_or(0) >= MAX_NONCES_PER_CALLER {
            return Err(Error::RateLimited);
        }
        if self.seen.len() >= MAX_NONCES {
            return Err(Error::CallerInvalid {
                rule: "too many recent calls to check for replay",
            });
        }
        self.seen.insert(tag, who);
        self.by_expiry.insert((expires, tag));
        *self.per_caller.entry(who).or_default() += 1;
        Ok(())
    }
}

struct State<S> {
    log: Log,
    sink: S,
    grants: HashMap<String, Grant>,
    owners: HashMap<String, Owner>,
    floors: HashMap<RecordKey, u64>,
    nonces: Nonces,
    /// When this node started (or restarted). Grants and authorizations made before it are
    /// refused: a restart loses the replay state of those.
    started_ms: u64,
    calls: HashMap<(String, String, String), VecDeque<u64>>,
    /// Operations that wait for a challenge or an approval, in memory only.
    parked: park::Registry,
    /// Spending limits and the payments counted against them, per record.
    limits: HashMap<RecordKey, crate::limits::Ledger>,
    /// Set once this node handed over to a successor: the node takes no act after it.
    handed_over: Option<handover::Done>,
}

impl<S: LogSink> State<S> {
    fn grant_of(&mut self, owner: &str, now: u64) -> Result<&Grant> {
        let expired = match self.grants.get(owner) {
            None => return Err(Error::NoGrant),
            Some(grant) => grant.expires_ms <= now,
        };
        if expired {
            self.grants.remove(owner);
            return Err(Error::GrantExpired);
        }
        self.grants.get(owner).ok_or(Error::NoGrant)
    }

    fn floor(&self, record: &Record) -> Option<u64> {
        self.floors
            .get(&(record.owner.clone(), record.id.clone()))
            .copied()
    }

    fn devices(&self, owner: &str) -> Vec<DevicePublicKey> {
        self.owners
            .get(owner)
            .map(|o| o.devices.clone())
            .unwrap_or_default()
    }

    fn forget_device(&mut self, owner: &str, device: &DevicePublicKey) {
        let o = self.owners.entry(owner.to_string()).or_default();
        o.devices.retain(|d| d != device);
        if !o.retired.contains(device) {
            o.retired.push(*device);
        }
    }

    fn know_device(&mut self, owner: &str, device: DevicePublicKey) {
        let o = self.owners.entry(owner.to_string()).or_default();
        o.retired.retain(|d| *d != device);
        if !o.devices.contains(&device) {
            o.devices.push(device);
        }
    }

    fn is_retired(&self, owner: &str, device: &DevicePublicKey) -> bool {
        self.owners
            .get(owner)
            .is_some_and(|o| o.retired.contains(device))
    }

    /// The earliest time a grant, endorsement or authorization may carry: when this node
    /// started. If the clock steps back behind it, nothing new is accepted until the clock
    /// passes it again, so what was signed before a restart never opens the node.
    fn since(&self, _now: u64) -> u64 {
        self.started_ms
    }

    fn issued(&mut self, owner: &str, issued_ms: u64) {
        let owner = self.owners.entry(owner.to_string()).or_default();
        owner.issued_ms = owner.issued_ms.max(issued_ms);
    }

    /// Checks the issue time of a grant or revocation against the clock and the last one of
    /// the owner.
    fn check_issued(&self, owner: &str, issued_ms: u64, now: u64) -> Result<()> {
        if issued_ms.abs_diff(now) > MAX_SKEW_MS {
            return Err(Error::GrantInvalid {
                rule: "issued too long ago or in the future",
            });
        }
        if issued_ms < self.since(now) {
            return Err(Error::GrantInvalid {
                rule: "issued before this node started",
            });
        }
        if self
            .owners
            .get(owner)
            .is_some_and(|o| issued_ms <= o.issued_ms)
        {
            return Err(Error::GrantInvalid {
                rule: "issued before the last grant or revocation of the owner",
            });
        }
        Ok(())
    }

    fn raise(&mut self, owner: &str, id: &str, generation: u64) {
        let floor = self
            .floors
            .entry((owner.to_string(), id.to_string()))
            .or_insert(0);
        *floor = (*floor).max(generation);
    }

    fn commit(
        &mut self,
        now: u64,
        who: (&str, &str, &str),
        event: Event,
    ) -> Result<(u64, crate::log::Confirmed)> {
        // A node that handed over writes nothing more: its chain ended at the hand-over, and
        // an entry after it would fork the chain its successor continues.
        if self.handed_over.is_some() {
            return Err(Error::HandedOver);
        }
        let (entry, confirmed) = self.log.commit(&mut self.sink, now, who, event)?;
        Ok((entry.entry.seq, confirmed))
    }
}

/// What a checked call carries into the operation.
struct Checked {
    policy_owner: Arc<UserKey>,
    caller: String,
}

/// A node.
pub struct Node<S: LogSink, C: Clock> {
    public: NodePublicKey,
    identity: NodeIdentity,
    seal: SealSecret,
    state_key: crate::limits::StateKey,
    clock: C,
    state: Mutex<State<S>>,
    /// The connections open now (WebSockets, streamed responses).
    live: live::Slots,
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Runs a [`SignedCall`]: the HTTP, stream or derive operation it names, with the record
    /// and payload its caller signed.
    pub fn run<T: Transport>(&self, call: &SignedCall, transport: &mut T) -> Outcome<Output> {
        let (record, operation, auth) = (&call.record, call.operation.as_str(), &call.auth);
        let mut updated = None;
        match &call.body {
            Body::Http { .. }
            | Body::Stream { .. }
            | Body::Resume { .. }
            | Body::Session { .. } => {
                let result = self.execute(
                    record,
                    operation,
                    auth,
                    call.body.payload(),
                    transport,
                    &mut updated,
                    None,
                );
                Outcome {
                    result,
                    record: updated,
                }
            }
            Body::Derive { .. } => {
                let result = self.execute(
                    record,
                    operation,
                    auth,
                    call.body.payload(),
                    &mut NoTransport,
                    &mut updated,
                    None,
                );
                Outcome {
                    result,
                    record: updated,
                }
            }
            Body::Describe {} => Outcome {
                result: if operation == DESCRIBE {
                    self.describe(record, auth).map(Output::Describe)
                } else {
                    Err(Error::OperationUnknown {
                        name: operation.to_string(),
                    })
                },
                record: None,
            },
            Body::Socket { .. } => Outcome {
                result: Err(Error::RequestInvalid {
                    rule: "a WebSocket operation runs on a streaming call",
                }),
                record: None,
            },
        }
    }

    /// Runs a [`SignedCall`] whose result goes to the caller as it arrives: a WebSocket
    /// operation ([`Body::Socket`]) or an HTTPS operation whose `return` streams the body.
    /// The parts go through `relay`; the result is [`Output::Closed`], or what the operation
    /// handed back when it did not get to stream (it waits for approval, say).
    pub fn relay<T: Transport>(
        &self,
        call: &SignedCall,
        transport: &mut T,
        relay: &mut dyn live::Relay,
    ) -> Outcome<Output> {
        let (record, operation, auth) = (&call.record, call.operation.as_str(), &call.auth);
        let mut updated = None;
        let result = match &call.body {
            Body::Http { .. } | Body::Socket { .. } | Body::Session { .. } => self.execute(
                record,
                operation,
                auth,
                call.body.payload(),
                transport,
                &mut updated,
                Some(relay),
            ),
            _ => Err(Error::RequestInvalid {
                rule: "a streaming call runs a WebSocket or a streamed response",
            }),
        };
        Outcome {
            result,
            record: updated,
        }
    }

    /// A node with a fresh chain.
    pub fn new(key: NodeKey, sink: S, clock: C) -> Self {
        let seal = SealSecret::of(&key);
        let state_key = crate::limits::StateKey::of(&key);
        Self::with_log(Log::new(key), seal, state_key, sink, clock)
    }

    fn with_log(
        log: Log,
        seal: (SealSecret, NodeSealKey),
        state_key: crate::limits::StateKey,
        sink: S,
        clock: C,
    ) -> Self {
        let public = log.public_key();
        let started_ms = clock.now_ms();
        Self {
            public,
            identity: NodeIdentity {
                log_key: public,
                seal_key: seal.1,
            },
            seal: seal.0,
            state_key,
            clock,
            live: live::Slots::default(),
            state: Mutex::new(State {
                log,
                sink,
                grants: HashMap::new(),
                owners: HashMap::new(),
                floors: HashMap::new(),
                nonces: Nonces::default(),
                started_ms,
                calls: HashMap::new(),
                parked: park::Registry::default(),
                limits: HashMap::new(),
                handed_over: None,
            }),
        }
    }

    /// A node that continues its chain after a restart: `entries` are all the entries its
    /// sink holds, from seq 0. The generations they name become the floors of the records, and
    /// the devices and last issue times of the owners come back. Grants do not: owners grant
    /// again, and the node takes no grant, endorsement or authorization made before it
    /// restarted.
    ///
    /// The operator supplies `entries` and could cut them. Where the platform keeps state the
    /// operator cannot roll back (a TEE monotonic counter or sealed storage), store
    /// [`Node::checkpoint`] there and use [`Node::restore_anchored`].
    pub fn restore(key: NodeKey, sink: S, clock: C, entries: &[SignedEntry]) -> Result<Self> {
        let seal = SealSecret::of(&key);
        let state_key = crate::limits::StateKey::of(&key);
        let node = Self::with_log(Log::resume(key, entries)?, seal, state_key, sink, clock);
        {
            let mut state = node.lock();
            // Something signed in the very millisecond of the restart may predate it.
            state.started_ms = state.started_ms.saturating_add(1);
            for signed in entries {
                let e = &signed.entry;
                match &e.event {
                    Event::Use { generation, .. }
                    | Event::Describe { generation }
                    | Event::Stream { generation, .. }
                    | Event::Derive { generation, .. }
                    | Event::Update { generation, .. }
                    | Event::Approve { generation, .. }
                    | Event::Pin { generation } => {
                        state.raise(&e.owner, &e.record_id, *generation);
                    }
                    Event::Spend {
                        generation, sealed, ..
                    } => {
                        state.raise(&e.owner, &e.record_id, *generation);
                        let spend: crate::limits::Spend =
                            node.state_key
                                .open(&e.owner, &e.record_id, park::SPEND, sealed)?;
                        state
                            .limits
                            .entry((e.owner.clone(), e.record_id.clone()))
                            .or_default()
                            .record(spend, e.time_ms);
                    }
                    Event::Limits {
                        issued_ms, sealed, ..
                    } => {
                        let rules: Vec<crate::limits::LimitRule> =
                            node.state_key
                                .open(&e.owner, &e.record_id, park::LIMITS, sealed)?;
                        state
                            .limits
                            .entry((e.owner.clone(), e.record_id.clone()))
                            .or_default()
                            .set(rules, *issued_ms);
                    }
                    Event::Answer { .. } => {}
                    Event::Grant {
                        device,
                        issued_ms,
                        pins,
                        ..
                    } => {
                        state.know_device(&e.owner, *device);
                        state.issued(&e.owner, *issued_ms);
                        for pin in pins {
                            state.raise(&e.owner, &pin.record_id, pin.generation);
                        }
                    }
                    Event::Device { device, issued_ms } => {
                        state.know_device(&e.owner, *device);
                        state.issued(&e.owner, *issued_ms);
                    }
                    Event::Retire { device, issued_ms } => {
                        state.forget_device(&e.owner, device);
                        state.issued(&e.owner, *issued_ms);
                    }
                    Event::Revoke { issued_ms, .. } => state.issued(&e.owner, *issued_ms),
                    Event::HandOver { .. } => {
                        // The chain of this node ended there: it stays stopped.
                        state.handed_over = Some(handover::Done::restored(signed.hash()?));
                    }
                    Event::Continue { .. } => {}
                    Event::Carry(carried) => {
                        handover::restore_carry(
                            &mut state,
                            &node.state_key,
                            &e.owner,
                            (&carried.devices, &carried.retired, carried.issued_ms),
                            &carried.pins,
                            &carried.limits,
                        )?;
                    }
                    Event::Done { .. } | Event::Closed { .. } => {}
                }
            }
        }
        Ok(node)
    }

    /// [`Node::restore`], refusing `entries` that end before `anchor`, the last checkpoint
    /// this node signed and the platform kept where the operator cannot roll it back.
    pub fn restore_anchored(
        key: NodeKey,
        sink: S,
        clock: C,
        entries: &[SignedEntry],
        anchor: &SignedHead,
    ) -> Result<Self> {
        anchor.verify(&key.public())?;
        let len = usize::try_from(anchor.len).map_err(|_| Error::LogMismatch)?;
        let reaches = match len.checked_sub(1) {
            None => true,
            Some(last) => match entries.get(last) {
                Some(entry) => entry.hash()? == anchor.head,
                None => false,
            },
        };
        if !reaches {
            return Err(Error::LogBehindAnchor {
                len: u64::try_from(entries.len()).unwrap_or(u64::MAX),
                anchor: anchor.len,
            });
        }
        Self::restore(key, sink, clock, entries)
    }

    fn lock(&self) -> MutexGuard<'_, State<S>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The key that verifies the log of this node.
    pub fn public_key(&self) -> NodePublicKey {
        self.public
    }

    /// The keys an owner needs to grant to this node and to check its log.
    pub fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// Runs `f` with the log sink.
    pub fn with_sink<R>(&self, f: impl FnOnce(&mut S) -> R) -> R {
        f(&mut self.lock().sink)
    }

    /// The head of the chain now, signed.
    pub fn checkpoint(&self) -> Result<SignedHead> {
        let now = self.clock.now_ms();
        self.lock().log.checkpoint(now)
    }

    /// True after an unconfirmed entry, until [`Node::reconcile`].
    pub fn is_halted(&self) -> bool {
        self.lock().log.is_halted()
    }

    /// Ends a halt of the log; `stored` is the last entry the sink holds now. See
    /// [`Log::reconcile`].
    pub fn reconcile(&self, stored: Option<&SignedEntry>) -> Result<()> {
        self.lock().log.reconcile(stored)
    }

    /// Opens a grant sealed to this node and takes the user key it carries.
    ///
    /// The device that signed it must be one the node knows for the owner, unless the owner
    /// has none yet (the first grant) or the user key is the one of the grant in force (a new
    /// device of the owner). The grant must be fresh and newer than the last grant or
    /// revocation of the owner. The entry is confirmed before the key is kept; the pins of the
    /// grant raise the floors of its records.
    pub fn grant(&self, sealed: &SealedGrant) -> Result<()> {
        let OpenedGrant {
            terms,
            device,
            user_key,
        } = sealed.open(&self.seal, &self.public)?;
        check_name(&terms.owner)?;
        if terms.pins.len() > crate::grant::MAX_PINS {
            return Err(Error::GrantInvalid {
                rule: "too many pins",
            });
        }
        for pin in &terms.pins {
            check_name(&pin.record_id)?;
        }
        let now = self.clock.now_ms();
        let expires_ms = terms.expires_ms.min(now.saturating_add(MAX_GRANT_MS));
        if expires_ms <= now {
            return Err(Error::GrantExpired);
        }
        let owner = terms.owner.as_str();
        let mut state = self.lock();
        state.check_issued(owner, terms.issued_ms, now)?;
        // Once an owner has devices, a new one joins only through an endorsement by a known
        // device: the user key alone does not make a device known, or a retired device could
        // come back under a fresh key.
        if !state.owners.contains_key(owner) && state.owners.len() >= MAX_OWNERS {
            // Anyone may become an owner (the first device is trusted on first use); the
            // number of owners is bounded so the state and the log cannot grow without end.
            return Err(Error::GrantDenied);
        }
        let known = state.devices(owner);
        if state.is_retired(owner, &device) || (!known.is_empty() && !known.contains(&device)) {
            return Err(Error::GrantDenied);
        }
        state.commit(
            now,
            (owner, "", ""),
            Event::Grant {
                expires_ms,
                device,
                issued_ms: terms.issued_ms,
                pins: terms.pins.clone(),
            },
        )?;
        state.know_device(owner, device);
        state.issued(owner, terms.issued_ms);
        for pin in &terms.pins {
            state.raise(owner, &pin.record_id, pin.generation);
        }
        state.grants.insert(
            owner.to_string(),
            Grant {
                user_key: Arc::new(user_key),
                expires_ms,
                allow_successor: terms.allow_successor,
            },
        );
        Ok(())
    }

    /// Adds a device a known device of the owner endorsed for this node.
    pub fn add_device(&self, endorsement: &Endorsement) -> Result<()> {
        if endorsement.node != self.public {
            return Err(Error::GrantInvalid {
                rule: "endorsement for another node",
            });
        }
        let now = self.clock.now_ms();
        let owner = endorsement.owner.as_str();
        let mut state = self.lock();
        state.grant_of(owner, now)?;
        endorsement.verify(&state.devices(owner))?;
        state.check_issued(owner, endorsement.issued_ms, now)?;
        state.commit(
            now,
            (owner, "", ""),
            Event::Device {
                device: endorsement.device,
                issued_ms: endorsement.issued_ms,
            },
        )?;
        state.know_device(owner, endorsement.device);
        state.issued(owner, endorsement.issued_ms);
        Ok(())
    }

    /// Withdraws a device of the owner, as another known device signed for this node. The
    /// node then takes no policy, pin, grant or revocation that device signs. The last
    /// device of an owner cannot be withdrawn.
    pub fn retire_device(&self, retirement: &Retirement) -> Result<()> {
        if retirement.node != self.public {
            return Err(Error::GrantInvalid {
                rule: "retirement for another node",
            });
        }
        let now = self.clock.now_ms();
        let owner = retirement.owner.as_str();
        let mut state = self.lock();
        let devices = state.devices(owner);
        retirement.verify(&devices)?;
        if !devices.contains(&retirement.device) {
            return Err(Error::GrantInvalid {
                rule: "the device is not known for the owner",
            });
        }
        state.check_issued(owner, retirement.issued_ms, now)?;
        state.commit(
            now,
            (owner, "", ""),
            Event::Retire {
                device: retirement.device,
                issued_ms: retirement.issued_ms,
            },
        )?;
        state.forget_device(owner, &retirement.device);
        state.issued(owner, retirement.issued_ms);
        Ok(())
    }

    /// Erases the user key of the owner, as a known device of the owner signed, then records
    /// the revoke. An operation already running finishes with the key it took.
    pub fn revoke(&self, revocation: &Revocation) -> Result<()> {
        if revocation.node != self.public {
            return Err(Error::GrantInvalid {
                rule: "revocation for another node",
            });
        }
        revocation.verify()?;
        let now = self.clock.now_ms();
        let owner = revocation.owner.as_str();
        let mut state = self.lock();
        if !state.devices(owner).contains(&revocation.device) {
            return Err(Error::GrantDenied);
        }
        state.check_issued(owner, revocation.issued_ms, now)?;
        // Logged first, like every act: a revocation the sink did not take changes nothing,
        // and the owner sends it again.
        state.commit(
            now,
            (owner, "", ""),
            Event::Revoke {
                issued_ms: revocation.issued_ms,
                device: revocation.device,
            },
        )?;
        state.grants.remove(owner);
        // Operations that wait hold values opened under the key just taken back.
        state.parked.drop_owner(owner);
        state.issued(owner, revocation.issued_ms);
        Ok(())
    }

    /// Raises the lowest generation of a record this node accepts, as a device of the owner
    /// signed.
    pub fn pin(&self, pin: &Pin) -> Result<()> {
        let now = self.clock.now_ms();
        let mut state = self.lock();
        state.grant_of(&pin.owner, now)?;
        pin.verify(&state.devices(&pin.owner))?;
        state.commit(
            now,
            (&pin.owner, &pin.record_id, ""),
            Event::Pin {
                generation: pin.generation,
            },
        )?;
        state.raise(&pin.owner, &pin.record_id, pin.generation);
        Ok(())
    }

    /// Checks the grant, the record generation, the policy and the caller of a call.
    fn check_call<'r>(
        &self,
        record: &'r Record,
        name: &str,
        auth: &Authorization,
        payload: &Payload<'_>,
        now: u64,
    ) -> Result<(&'r Policy, &'r Operation, Checked)> {
        let (policy, operation, checked) = self.check_auth(record, name, auth, payload, now)?;
        let operation = operation.ok_or_else(|| Error::OperationUnknown {
            name: name.to_string(),
        })?;
        Ok((policy, operation, checked))
    }

    /// [`Node::check_call`] for an operation of the policy, or for [`DESCRIBE`] (any caller
    /// the policy lists, no operation).
    fn check_auth<'r>(
        &self,
        record: &'r Record,
        name: &str,
        auth: &Authorization,
        payload: &Payload<'_>,
        now: u64,
    ) -> Result<(&'r Policy, Option<&'r Operation>, Checked)> {
        // The state of the owner (grant, floor) is told only to a caller whose signature
        // verifies; anyone else learns nothing about the owner's grants or records.
        let (grant, floor, devices) = {
            let mut state = self.lock();
            let grant = state
                .grant_of(&record.owner, now)
                .map(|g| g.user_key.clone());
            (grant, state.floor(record), state.devices(&record.owner))
        };
        let policy = record.policy.verify_any(&devices)?;
        let operation = match payload {
            Payload::Describe if name == DESCRIBE => None,
            Payload::Describe => {
                return Err(Error::OperationUnknown {
                    name: name.to_string(),
                });
            }
            _ => {
                let operation = policy.operation(name)?;
                // A call whose payload does not fit the connection of the operation is
                // refused before it spends a nonce or the rate limit.
                let kind_ok = matches!(
                    (operation.connection(), payload),
                    (
                        Some(Connection::Https | Connection::Browser),
                        Payload::Http(_)
                    ) | (
                        Some(Connection::Tls | Connection::Udp),
                        Payload::Stream { .. }
                    ) | (Some(Connection::Websocket), Payload::Socket(_))
                        | (
                            Some(
                                Connection::Ssh
                                    | Connection::Postgres
                                    | Connection::Smtp
                                    | Connection::Imap
                                    | Connection::Redis
                            ),
                            Payload::Session { .. }
                        )
                        | (None, Payload::Derive(_))
                        | (_, Payload::Resume(_))
                );
                if !kind_ok {
                    return Err(operation.unknown());
                }
                Some(operation)
            }
        };
        let caller = policy.caller(&auth.caller)?;
        if operation.is_some() && !caller.operations.iter().any(|o| o == name) {
            return Err(Error::CallerDenied {
                caller: auth.caller.clone(),
                operation: name.to_string(),
            });
        }
        if now.saturating_sub(auth.time_ms) > MAX_SKEW_MS
            || auth.time_ms.saturating_sub(now) > MAX_FUTURE_MS
        {
            return Err(Error::CallerInvalid {
                rule: "authorization too old or from the future",
            });
        }
        let call = Call {
            node: &self.public,
            record,
            operation: name,
            payload: payload.sha256(),
        };
        auth.verify(&caller.key, &call)?;
        let user_key = grant?;
        let need = floor.ok_or(Error::RecordUnpinned)?;
        if record.generation < need {
            return Err(Error::RecordStale {
                have: record.generation,
                need,
            });
        }
        let mut tag = Sha256::new();
        tag.update(caller.key.to_b64().as_bytes());
        tag.update(auth.nonce);
        let tag: [u8; 32] = tag.finalize().into();
        let mut who = Sha256::new();
        who.update(record.owner.as_bytes());
        who.update([0]);
        who.update(caller.key.to_b64().as_bytes());
        let who: [u8; 32] = who.finalize().into();
        let mut state = self.lock();
        if auth.time_ms < state.since(now) {
            // The replay cache of calls before a restart is gone.
            return Err(Error::CallerInvalid {
                rule: "authorization made before this node started",
            });
        }
        state
            .nonces
            .insert(tag, who, auth.time_ms.saturating_add(MAX_SKEW_MS), now)?;
        if let Some(limit) = caller.limit {
            let key = (record.owner.clone(), record.id.clone(), caller.name.clone());
            let calls = state.calls.entry(key).or_default();
            while calls
                .front()
                .is_some_and(|t| t.saturating_add(limit.window_ms) <= now)
            {
                calls.pop_front();
            }
            if calls.len() >= usize::try_from(limit.count).unwrap_or(usize::MAX) {
                return Err(Error::RateLimited);
            }
            calls.push_back(now);
        }
        Ok((
            policy,
            operation,
            Checked {
                policy_owner: user_key,
                caller: auth.caller.clone(),
            },
        ))
    }

    fn open(&self, record: &Record, user_key: &UserKey) -> Result<Fields> {
        let fields = record.open(user_key)?;
        self.lock()
            .raise(&record.owner, &record.id, record.generation);
        // A typed item is checked against its kind each time, with the clock: an expired card
        // or a value that no longer equals its pin is refused before anything is logged.
        crate::item::check_values(&record.policy.policy, &fields, Some(self.clock.now_ms()))?;
        Ok(fields)
    }

    /// What the caller of `auth` may learn of the typed item `record`: its public fields and
    /// the projections of its masked ones ([`crate::item::describe`]), never a secret field.
    /// Any caller the policy lists may ask; the authorization is signed for the operation
    /// [`DESCRIBE`] with the payload [`Payload::Describe`]. The node logs it like a use.
    pub fn describe(&self, record: &Record, auth: &Authorization) -> Result<Description> {
        let now = self.clock.now_ms();
        let (policy, _, checked) =
            self.check_auth(record, DESCRIBE, auth, &Payload::Describe, now)?;
        if policy.item.is_none() {
            return Err(Error::NotAnItem);
        }
        let fields = self.open(record, &checked.policy_owner)?;
        let description = crate::item::describe(policy, &fields)?;
        self.lock().commit(
            now,
            (&record.owner, &record.id, &checked.caller),
            Event::Describe {
                generation: record.generation,
            },
        )?;
        Ok(description)
    }

    /// Runs the HTTPS operation `operation` of `record` for the caller of `auth`. `request` is
    /// the request of the caller; it is required exactly when a step sends the request of the
    /// caller.
    pub fn http<T: Transport>(
        &self,
        record: &Record,
        operation: &str,
        auth: &Authorization,
        request: Option<&Request>,
        transport: &mut T,
    ) -> Outcome<Response> {
        let mut updated = None;
        let result = self
            .execute(
                record,
                operation,
                auth,
                Payload::Http(request),
                transport,
                &mut updated,
                None,
            )
            .and_then(|output| match output {
                Output::Http(response) => Ok(response),
                Output::Pending(_) => Err(Error::Pending),
                _ => Err(Error::OperationUnknown {
                    name: operation.to_string(),
                }),
            });
        Outcome {
            result,
            record: updated,
        }
    }

    /// Runs the TLS stream operation `operation` of `record` on a connection to
    /// `destination`: the steps of the policy, then the exchanges of the caller its `return`
    /// relays, whose reads are handed back. Values the steps captured are sealed before the
    /// exchanges of the caller run.
    pub fn stream<T: Transport>(
        &self,
        record: &Record,
        operation: &str,
        auth: &Authorization,
        destination: &Destination,
        exchanges: &[CallerExchange],
        transport: &mut T,
    ) -> Outcome<StreamOutput> {
        let mut updated = None;
        let payload = Payload::Stream {
            destination,
            exchanges,
        };
        let result = self
            .execute(
                record,
                operation,
                auth,
                payload,
                transport,
                &mut updated,
                None,
            )
            .and_then(|output| match output {
                Output::Stream(output) => Ok(output),
                Output::Pending(_) => Err(Error::Pending),
                _ => Err(Error::OperationUnknown {
                    name: operation.to_string(),
                }),
            });
        Outcome {
            result,
            record: updated,
        }
    }

    /// Runs the operation with no connection `operation` of `record`: the caller's `input`,
    /// checked by the input schema, is `$input`, and the output of its `return` is handed
    /// back. The policy was checked to hand back no secret in reversible form.
    pub fn derive(
        &self,
        record: &Record,
        operation: &str,
        auth: &Authorization,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let mut updated = None;
        let output = self.execute(
            record,
            operation,
            auth,
            Payload::Derive(input),
            &mut NoTransport,
            &mut updated,
            None,
        )?;
        match output {
            Output::Derive(bytes) => Ok(bytes),
            Output::Pending(_) => Err(Error::Pending),
            _ => Err(Error::OperationUnknown {
                name: operation.to_string(),
            }),
        }
    }

    /// Checks the call and what the caller sends against the operation, then runs its steps
    /// over its connection.
    #[allow(clippy::too_many_arguments)]
    fn execute<T: Transport>(
        &self,
        record: &Record,
        name: &str,
        auth: &Authorization,
        payload: Payload<'_>,
        transport: &mut T,
        updated: &mut Option<Record>,
        relay: Option<&mut dyn live::Relay>,
    ) -> Result<Output> {
        if let Payload::Resume(id) = payload {
            return self.resume(record, name, auth, id, transport, updated);
        }
        if let Payload::Derive(input) = payload
            && input.len() > MAX_INPUT
        {
            return Err(Error::RequestInvalid {
                rule: "input larger than 1 MiB",
            });
        }
        let now = self.clock.now_ms();
        let (policy, operation, checked) = self.check_call(record, name, auth, &payload, now)?;
        // What the caller sends is checked in full before the record is opened, so a refused
        // request leaves no entry and reaches no server.
        let mut input = Vec::new();
        // A streaming call is for an operation that streams, and takes one of the bounded
        // number of open connections; a WebSocket operation needs one.
        let _slot = match (&relay, live::streams(operation)) {
            (Some(_), true) => Some(self.live.take(&record.owner, &auth.caller, policy)?),
            (Some(_), false) => {
                return Err(Error::RequestInvalid {
                    rule: "the operation does not stream",
                });
            }
            (None, _) if operation.connection() == Some(Connection::Websocket) => {
                return Err(Error::RequestInvalid {
                    rule: "a WebSocket operation runs on a streaming call",
                });
            }
            (None, true) if operation.connection() == Some(Connection::Ssh) => {
                return Err(Error::RequestInvalid {
                    rule: "an SSH shell runs on a streaming call",
                });
            }
            // A protocol connection is open for the whole call: it takes a slot too.
            (None, _) if operation.connection().is_some_and(Connection::is_protocol) => {
                Some(self.live.take(&record.owner, &auth.caller, policy)?)
            }
            // A browser fill holds its CDP connection for the call: it takes a slot too.
            (None, _) if operation.connection() == Some(Connection::Browser) => {
                if !matches!(payload, Payload::Http(_)) {
                    return Err(Error::RequestInvalid {
                        rule: "a browser operation runs on an HTTP call",
                    });
                }
                Some(self.live.take(&record.owner, &auth.caller, policy)?)
            }
            (None, _) => None,
        };
        match payload {
            Payload::Describe | Payload::Resume(_) => return Err(operation.unknown()),
            Payload::Http(request) | Payload::Socket(request) => {
                match (request, operation.takes_request()) {
                    (Some(request), true) => request.validate(operation)?,
                    (None, false) => {}
                    (Some(_), false) => {
                        return Err(Error::RequestInvalid {
                            rule: "the operation takes no request",
                        });
                    }
                    (None, true) => {
                        return Err(Error::RequestInvalid {
                            rule: "the operation needs a request",
                        });
                    }
                }
            }
            Payload::Stream {
                destination,
                exchanges,
            } => check_exchanges(operation, destination, exchanges)?,
            Payload::Session {
                destination,
                commands,
                mail,
            } => proto::check_session(operation, destination, commands, mail)?,
            Payload::Derive(given) => {
                input = match &operation.input {
                    Some(schema) => schema.apply(given, now)?,
                    None if given.is_empty() => Vec::new(),
                    None => {
                        return Err(Error::InputInvalid {
                            rule: "the operation takes no input",
                        });
                    }
                };
            }
        }
        let user_key = checked.policy_owner;
        let fields = self.open(record, &user_key)?;
        let mut run = Run {
            record,
            name,
            who: (
                record.owner.as_str(),
                record.id.as_str(),
                checked.caller.as_str(),
            ),
            policy,
            operation,
            kinds: policy.kinds(operation),
            fields,
            user_key,
            budget: Budget::default(),
            captured: Captured::default(),
            tainted: Vec::new(),
            now,
            start: 0,
            last: None,
            log_seqs: Vec::new(),
        };
        // An operation that may wait needs room to wait in, checked before anything is sent.
        if operation.parks() {
            self.lock().parked.room(&record.owner, now)?;
        }
        // The owner's approval and the spending limits, before anything is sent.
        if let Some(pending) = self.gate(&mut run, payload, &input)? {
            return Ok(Output::Pending(pending));
        }
        match (relay, payload) {
            (Some(relay), Payload::Http(request) | Payload::Socket(request)) => {
                self.renew_sessions(&mut run, transport, updated)?;
                let live = live::Live { auth, relay };
                self.run_live(&mut run, request, transport, live, updated)
                    .map(Output::Closed)
            }
            (Some(relay), Payload::Session { destination, .. }) => {
                let live = live::Live { auth, relay };
                self.run_shell(&mut run, &payload, destination, transport, live, updated)
                    .map(Output::Closed)
            }
            _ => self.proceed(&mut run, payload, &input, transport, updated),
        }
    }

    /// Runs the steps of `run` from `run.start` over the connection of the operation, and parks
    /// it at an `await`.
    fn proceed<T: Transport>(
        &self,
        run: &mut Run<'_>,
        payload: Payload<'_>,
        input: &[u8],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Output> {
        if run.start == 0 {
            self.renew_sessions(run, transport, updated)?;
        }
        match payload {
            Payload::Http(request) if run.operation.connection() == Some(Connection::Browser) => {
                let open = run
                    .operation
                    .open()
                    .ok_or_else(|| run.operation.unknown())?;
                self.run_browser(run, open, request, transport, updated)
                    .map(Output::Fill)
            }
            Payload::Http(request) => match self.run_https(run, request, transport, updated)? {
                Flow::Done(response) => Ok(Output::Http(response)),
                Flow::Park(at) => self
                    .park_challenge(run, at, payload, input, updated)
                    .map(Output::Pending),
            },
            Payload::Stream {
                destination,
                exchanges,
            } => self
                .run_tls(run, &payload, destination, exchanges, transport, updated)
                .map(Output::Stream),
            Payload::Derive(given) => match self.run_local(run, given, input)? {
                Flow::Done(output) => Ok(Output::Derive(output)),
                Flow::Park(at) => self
                    .park_challenge(run, at, payload, input, updated)
                    .map(Output::Pending),
            },
            Payload::Session {
                destination,
                commands,
                mail,
            } => self
                .run_session(
                    run,
                    &payload,
                    destination,
                    commands,
                    mail,
                    transport,
                    updated,
                )
                .map(Output::Session),
            Payload::Describe | Payload::Resume(_) | Payload::Socket(_) => {
                Err(run.operation.unknown())
            }
        }
    }

    fn run_https<T: Transport>(
        &self,
        run: &mut Run<'_>,
        request: Option<&Request>,
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Flow<Response>> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        let (now, who) = (run.now, run.who);
        // The log entry of the last request, until its outcome is known.
        let mut pending: Option<(u64, u16)> = None;
        for (i, step) in operation.steps.iter().enumerate().skip(run.start) {
            let result: Result<Option<Flow<Response>>> = match step {
                Step::Open(_) => Ok(None),
                Step::Send(send) => {
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), true);
                    }
                    self.https_send(run, open, send, request, transport, updated)
                        .map(|(seq, http)| {
                            run.log_seqs.push(seq);
                            pending = Some((seq, http.status));
                            run.last = Some(http);
                            None
                        })
                }
                Step::Receive(receive) => {
                    let stored = match &run.last {
                        Some(http) => receive.capture.iter().try_for_each(|capture| {
                            let value = http.capture(&capture.source)?;
                            run.captured
                                .store(run.policy, &mut run.fields, capture, value, now)
                        }),
                        None => Err(operation.unknown()),
                    };
                    let persisted = self.persist(run, updated);
                    stored.and(persisted).map(|()| None)
                }
                Step::Compute(compute) => run.compute(compute, compute_vars(now)).map(|()| None),
                Step::Run(step) => {
                    // A module fetch is a request of its own: the one before it is done.
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), true);
                    }
                    self.run_module(run, open, step, transport, updated)
                        .map(|()| None)
                }
                Step::Await(_) => {
                    // The request before it has ended; the operation waits from here.
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), true);
                    }
                    Ok(Some(Flow::Park(i)))
                }
                Step::Return(ret) => {
                    let log_seqs = run.log_seqs.clone();
                    let response = run
                        .last
                        .take()
                        .ok_or_else(|| operation.unknown())
                        .and_then(|http| http.project(ret.response.as_ref(), log_seqs))
                        .and_then(|response| {
                            let secrets = Secrets {
                                policy: run.policy,
                                fields: &run.fields,
                                captured: &run.captured.secrets,
                                rendered: &run.tainted,
                            };
                            release_http(response, &secrets)
                        });
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), response.is_ok());
                    }
                    response.map(|r| Some(Flow::Done(r)))
                }
                Step::Repeat(_) | Step::If(_) => Err(operation.unknown()),
            };
            match result {
                Ok(Some(flow)) => return Ok(flow),
                Ok(None) => {}
                Err(error) => {
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), false);
                    }
                    return Err(error);
                }
            }
        }
        Err(operation.unknown())
    }

    /// A `run` step: gets the module (a reviewed library, or `GET` on the module's origin
    /// over the operation's connection, logged like any request, its pin checked), renders
    /// the inputs, runs the module in the sandbox and keeps the output as a secret temporary
    /// value. The output is added to what responses are searched for; the policy check made
    /// sure it goes nowhere but a fixed request to the module's origin.
    fn run_module<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        step: &RunModule,
        transport: &mut T,
        updated: &Option<Record>,
    ) -> Result<()> {
        let fetched;
        let module: &[u8] = match step.source() {
            Some(ModuleRef::Library(name)) => {
                sandbox::library(name).ok_or(Error::ModuleRefused {
                    rule: "unknown library module",
                })?
            }
            Some(ModuleRef::Url {
                origin,
                path,
                sha256,
            }) => {
                fetched = self.fetch_module(run, open, origin, path, sha256, transport, updated)?;
                &fetched
            }
            None => return Err(run.operation.unknown()),
        };
        let ctx = Context {
            fields: &run.fields,
            temps: &run.captured.temps,
            vars: compute_vars(run.now),
            unix: run.now / 1000,
            budget: &run.budget,
        };
        let inputs = step
            .inputs
            .iter()
            .map(|text| Template::parse(text).and_then(|t| t.render(&ctx)))
            .collect::<Result<Vec<_>>>()?;
        let slices: Vec<&[u8]> = inputs.iter().map(|i| i.as_slice()).collect();
        let ran = sandbox::run(module, &step.entry, &slices).map_err(Error::Sandbox)?;
        drop(inputs);
        let output = ran.output;
        run.captured.temps_len = run.captured.temps_len.saturating_add(output.len());
        if run.captured.temps_len > MAX_TEMPS {
            return Err(Error::Budget {
                what: "captured values",
            });
        }
        run.tainted.push(output.clone());
        run.captured.temps.insert(step.into.clone(), output);
        Ok(())
    }

    /// Fetches a module with `GET` from its origin, as a logged request of the operation,
    /// and checks the status, the size and the pin.
    #[allow(clippy::too_many_arguments)]
    fn fetch_module<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        origin: Destination,
        path: &str,
        sha256: Option<[u8; 32]>,
        transport: &mut T,
        updated: &Option<Record>,
    ) -> Result<Vec<u8>> {
        let send = Send {
            request: Some(StepRequest::Fixed {
                method: Method::Get,
                path: path.to_string(),
                destination: Some(origin),
            }),
            ..Send::default()
        };
        let (seq, http) = self.https_send(run, open, &send, None, transport, updated)?;
        let checked = if http.status != 200 {
            Err(Error::ModuleRefused {
                rule: "the module's origin did not answer 200",
            })
        } else if http.body.len() > sandbox::MAX_MODULE {
            Err(Error::ModuleRefused {
                rule: "module larger than the limit",
            })
        } else if sha256.is_some_and(|pin| <[u8; 32]>::from(Sha256::digest(&*http.body)) != pin) {
            Err(Error::ModuleRefused {
                rule: "the module does not match its sha256 pin",
            })
        } else {
            Ok(http.body.to_vec())
        };
        self.done(run.now, run.who, seq, Some(http.status), checked.is_ok());
        checked
    }

    /// Builds and logs one HTTPS request: what [`Node::https_send`] and the streamed sends
    /// of [`live`] share. The request goes out with the confirmation it returns.
    fn prepare<'o>(
        &self,
        run: &Run<'_>,
        open: &'o Open,
        send: &'o Send,
        request: Option<&'o Request>,
        updated: &Option<Record>,
        kind: request::Wire<'_>,
    ) -> Result<live::Prepared<'o>> {
        let now = run.now;
        let outbound = Outbound::of(send, &open.destinations, request)?;
        if !run.operation.allows_destination(outbound.destination) {
            return Err(outbound.destination.denied());
        }
        let built = request::build(
            send,
            &outbound,
            &Inputs {
                kinds: &run.kinds,
                fields: &run.fields,
                temps: &run.captured.temps,
                unix_ms: now,
                budget: &run.budget,
            },
            kind,
        )?;
        let client = render_identity(
            open.identity.as_ref(),
            &run.fields,
            &outbound.destination.host,
            now,
            &run.budget,
        )?;
        let detail = Detail::Use {
            method: outbound.method,
            host: outbound.destination.host.clone(),
            port: outbound.destination.port,
            path: outbound.path.to_string(),
            body_sha256: Sha256::digest(outbound.body).into(),
            body_len: outbound.body.len() as u64,
        };
        let event = Event::Use {
            operation: run.name.to_string(),
            generation: updated.as_ref().unwrap_or(run.record).generation,
            detail: detail.seal(&run.user_key, &run.record.owner, &run.record.id)?,
        };
        let (seq, confirmed) = self.lock().commit(now, run.who, event)?;
        Ok(live::Prepared {
            seq,
            confirmed,
            wire: built.wire,
            tainted: built.tainted,
            client,
            destination: outbound.destination,
        })
    }

    /// Builds, logs and sends one HTTPS request, and parses its response.
    fn https_send<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        send: &Send,
        request: Option<&Request>,
        transport: &mut T,
        updated: &Option<Record>,
    ) -> Result<(u64, Http)> {
        let (now, who) = (run.now, run.who);
        let kind = if send.grpc {
            request::Wire::Grpc
        } else {
            request::Wire::Plain
        };
        let prepared = self.prepare(run, open, send, request, updated, kind)?;
        let seq = prepared.seq;
        let built = request::Built {
            wire: prepared.wire,
            tainted: prepared.tainted,
        };
        let client = prepared.client;
        let sent = dispatch(
            prepared.confirmed,
            transport,
            prepared.destination,
            client.as_ref(),
            &built.wire,
            open.protocol.unwrap_or_default(),
        );
        drop(client);
        let (_, mut bytes) = match sent {
            Ok(sent) => sent,
            Err(error) => {
                self.done(now, who, seq, None, false);
                return Err(error);
            }
        };
        run.tainted.extend(built.tainted);
        let parsed = Http::parse(&bytes).and_then(|http| {
            if send.grpc {
                live::grpc_answer(http)
            } else {
                Ok(http)
            }
        });
        bytes.zeroize();
        match parsed {
            Ok(http) => Ok((seq, http)),
            Err(error) => {
                self.done(now, who, seq, None, false);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_tls<T: Transport>(
        &self,
        run: &mut Run<'_>,
        payload: &Payload<'_>,
        destination: &Destination,
        exchanges: &[CallerExchange],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<StreamOutput> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        let (now, who) = (run.now, run.who);
        let client = render_identity(
            open.identity.as_ref(),
            &run.fields,
            &destination.host,
            now,
            &run.budget,
        )?;
        let detail = Detail::Stream {
            host: destination.host.clone(),
            port: destination.port,
            sends_sha256: payload.sha256(),
            exchanges: u32::try_from(exchanges.len()).unwrap_or(u32::MAX),
        };
        let event = Event::Stream {
            operation: run.name.to_string(),
            generation: run.record.generation,
            detail: detail.seal(&run.user_key, &run.record.owner, &run.record.id)?,
        };
        let (seq, confirmed) = self.lock().commit(now, who, event)?;
        let opened = if open.connection == Connection::Udp {
            crate::egress::open_datagrams(confirmed, transport, destination)
        } else {
            open_stream(confirmed, transport, destination, client.as_ref())
        };
        let (_, mut stream) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.done(now, who, seq, None, false);
                return Err(error);
            }
        };
        drop(client);
        let mut steps_result = Ok(());
        for step in &operation.steps {
            let result = match step {
                Step::Open(_) | Step::Return(_) => Ok(()),
                Step::Send(send) => run.stream_send(send, &destination.host, &mut *stream),
                Step::Receive(receive) => {
                    let delimiters: Vec<&[u8]> =
                        receive.until.iter().map(|u| u.as_bytes()).collect();
                    stream
                        .read_until(&delimiters, MAX_RESPONSE)
                        .map(Zeroizing::new)
                        .and_then(|read| {
                            receive.capture.iter().try_for_each(|c| {
                                let value = crate::response::capture_bytes(&read, &c.source)?;
                                run.captured
                                    .store(run.policy, &mut run.fields, c, value, now)
                            })
                        })
                }
                Step::Compute(compute) => run.compute(compute, compute_vars(now)),
                Step::Run(_) | Step::Repeat(_) | Step::If(_) | Step::Await(_) => {
                    Err(operation.unknown())
                }
            };
            if let Err(error) = result {
                steps_result = Err(error);
                break;
            }
        }
        let persisted = self.persist(run, updated);
        if let Err(error) = steps_result.and(persisted) {
            let _ = stream.close();
            self.done(now, who, seq, None, false);
            return Err(error);
        }

        let secrets = Secrets {
            policy: run.policy,
            fields: &run.fields,
            captured: &run.captured.secrets,
            rendered: &run.tainted,
        };
        let mut output = StreamOutput::default();
        let mut history = Zeroizing::new(Vec::new());
        for exchange in exchanges {
            let delimiters: Vec<&[u8]> = exchange.until.iter().map(Vec::as_slice).collect();
            let read = stream
                .write(&exchange.send)
                .and_then(|()| stream.read_until(&delimiters, MAX_RESPONSE))
                .and_then(|read| reflection::release(read, &secrets))
                .and_then(|read| {
                    history.extend_from_slice(&read);
                    reflection::check(&history, &secrets).map(|()| read)
                });
            match read {
                Ok(read) => output.reads.push(read),
                Err(error) => {
                    output.error = Some(error);
                    break;
                }
            }
        }
        let _ = stream.close();
        self.done(now, who, seq, None, output.error.is_none());
        Ok(output)
    }

    /// Runs an operation with no connection: its `compute` steps, then the template of its
    /// `return`, logged before the output is handed back.
    fn run_local(&self, run: &mut Run<'_>, given: &[u8], input: &[u8]) -> Result<Flow<Vec<u8>>> {
        let operation = run.operation;
        // One nonce and one clock reading for the whole derivation (for each part of it, when
        // it waits).
        let mut vars = compute_vars(run.now);
        vars.insert(Var::Input, input.to_vec());
        for (i, step) in operation.steps.iter().enumerate().skip(run.start) {
            match step {
                Step::Compute(compute) => run.compute(compute, vars.clone())?,
                Step::Await(_) => return Ok(Flow::Park(i)),
                Step::Return(ret) => {
                    let template = ret.template.as_deref().ok_or_else(|| operation.unknown())?;
                    let template = Template::parse(template)?;
                    let ctx = Context {
                        fields: &run.fields,
                        temps: &run.captured.temps,
                        vars,
                        unix: run.now / 1000,
                        budget: &run.budget,
                    };
                    let output = template.render(&ctx)?;
                    let detail = Detail::Derive {
                        input_sha256: Sha256::digest(given).into(),
                        input_len: given.len() as u64,
                    };
                    let event = Event::Derive {
                        operation: run.name.to_string(),
                        generation: run.record.generation,
                        detail: detail.seal(&run.user_key, &run.record.owner, &run.record.id)?,
                    };
                    self.lock().commit(run.now, run.who, event)?;
                    return Ok(Flow::Done(output.to_vec()));
                }
                Step::Open(_)
                | Step::Send(_)
                | Step::Receive(_)
                | Step::Run(_)
                | Step::Repeat(_)
                | Step::If(_) => return Err(operation.unknown()),
            }
        }
        Err(operation.unknown())
    }

    /// Records how an act ended. A failure halts the log, so the next act fails; the result of
    /// this one is already decided.
    fn done(&self, now: u64, who: (&str, &str, &str), of: u64, status: Option<u16>, ok: bool) {
        let _ = self.lock().commit(now, who, Event::Done { of, status, ok });
    }

    /// Logs the fields an operation changed and seals them into a new record.
    fn persist(&self, run: &mut Run<'_>, updated: &mut Option<Record>) -> Result<()> {
        if run.captured.changed.is_empty() {
            return Ok(());
        }
        let record = run.record;
        let current = updated.as_ref().unwrap_or(record);
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(Error::RecordInvalid)?;
        let next = current.reseal(&run.user_key, &run.fields)?;
        let event = Event::Update {
            operation: run.name.to_string(),
            generation,
            fields: core::mem::take(&mut run.captured.changed),
        };
        let mut state = self.lock();
        state.commit(run.now, run.who, event)?;
        state.raise(&record.owner, &record.id, generation);
        *updated = Some(next);
        Ok(())
    }
}

/// A transport for operations with no connection: they send nothing.
struct NoTransport;

impl Transport for NoTransport {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> Result<Vec<u8>> {
        Err(Error::transport(crate::error::TransportKind::Closed, false))
    }
}

/// Checks the caller's side of a stream call before anything happens: the destination, the
/// bounds of the exchanges, and each send against the patterns the `return` relays.
fn check_exchanges(
    operation: &Operation,
    destination: &Destination,
    exchanges: &[CallerExchange],
) -> Result<()> {
    if !operation.allows_destination(destination) {
        return Err(destination.denied());
    }
    if operation.connection() == Some(Connection::Udp) {
        // One datagram each way: no delimiter, and a send that fits one datagram.
        let datagrams_ok = exchanges.len() <= MAX_EXCHANGES
            && exchanges
                .iter()
                .all(|e| !e.send.is_empty() && e.send.len() <= MAX_DATAGRAM && e.until.is_empty());
        if !datagrams_ok {
            return Err(Error::RequestInvalid {
                rule: "exchanges: at most 64 datagrams of 1 to 65507 bytes, with no delimiters",
            });
        }
    }
    let delimited = operation.connection() != Some(Connection::Udp);
    let exchanges_ok = exchanges.len() <= MAX_EXCHANGES
        && exchanges.iter().all(|e| {
            e.send.len() <= MAX_BODY
                && (!delimited || !e.until.is_empty())
                && e.until.len() <= MAX_DELIMITERS
                && e.until
                    .iter()
                    .all(|u| !u.is_empty() && u.len() <= MAX_DELIMITER)
        });
    if !exchanges_ok {
        return Err(Error::RequestInvalid {
            rule: "exchanges: at most 64, sends of at most 8 MiB, 1 to 8 delimiters",
        });
    }
    if exchanges.is_empty() {
        return Ok(());
    }
    let Some(relay) = operation.returns().and_then(|r| r.relay.as_ref()) else {
        return Err(Error::RequestInvalid {
            rule: "the operation relays no exchange of the caller",
        });
    };
    let patterns = relay
        .sends
        .iter()
        .map(|p| crate::extract::compile_whole(p).ok_or_else(|| operation.unknown()))
        .collect::<Result<Vec<_>>>()?;
    if exchanges
        .iter()
        .any(|e| !patterns.iter().any(|p| p.is_match(&e.send)))
    {
        return Err(Error::RequestInvalid {
            rule: "a send of the caller matches no pattern the operation relays",
        });
    }
    Ok(())
}

/// The state of one operation while its steps run.
struct Run<'a> {
    record: &'a Record,
    name: &'a str,
    who: (&'a str, &'a str, &'a str),
    policy: &'a Policy,
    operation: &'a Operation,
    kinds: Kinds<'a>,
    fields: Fields,
    user_key: Arc<UserKey>,
    budget: Budget,
    captured: Captured,
    /// Rendered values that hold a secret in reversible form.
    tainted: Vec<Zeroizing<Vec<u8>>>,
    now: u64,
    /// The first step to run: 0, or the step after an `await` the operation waited at.
    start: usize,
    /// The response of the last HTTPS request.
    last: Option<Http>,
    /// The log entries of the HTTPS requests so far.
    log_seqs: Vec<u64>,
}

/// How the steps of an operation ended: done, or waiting at the `await` of this index.
enum Flow<T> {
    Done(T),
    Park(usize),
}

impl Run<'_> {
    /// Renders a `compute` step into a temporary value.
    fn compute(&mut self, compute: &Compute, vars: HashMap<Var, Vec<u8>>) -> Result<()> {
        let template = Template::parse(&compute.template)?;
        let ctx = Context {
            fields: &self.fields,
            temps: &self.captured.temps,
            vars,
            unix: self.now / 1000,
            budget: &self.budget,
        };
        let value = template.render(&ctx)?;
        if template.tainted(&|n| self.kinds.kind(n)) {
            self.tainted.push(value.clone());
        }
        self.captured.temps_len = self.captured.temps_len.saturating_add(value.len());
        if self.captured.temps_len > MAX_TEMPS {
            return Err(Error::Budget {
                what: "captured values",
            });
        }
        self.captured.temps.insert(compute.into.clone(), value);
        Ok(())
    }

    /// Renders the template of a `send` on a stream and writes it.
    fn stream_send(&mut self, send: &Send, host: &str, stream: &mut dyn Stream) -> Result<()> {
        let text = send
            .template
            .as_deref()
            .ok_or_else(|| self.operation.unknown())?;
        let template = Template::parse(text)?;
        let ctx = Context {
            fields: &self.fields,
            temps: &self.captured.temps,
            vars: stream_vars(host, self.now),
            unix: self.now / 1000,
            budget: &self.budget,
        };
        // Rendered on the connection, after its handshake: `tls_exporter` reads it.
        let bytes = template.render_on(&ctx, &*stream)?;
        if template.tainted(&|n| self.kinds.kind(n)) {
            self.tainted.push(bytes.clone());
        }
        stream.write(&bytes)
    }
}
