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

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::call::{Body, Output, SignedCall};
use crate::caller::{Authorization, Call, MAX_SKEW_MS, Payload};
use crate::egress::{ClientIdentity, Transport, dispatch, open_stream};
use crate::fields::Fields;
use crate::grant::{NodeIdentity, NodeSealKey, OpenedGrant, Revocation, SealSecret, SealedGrant};
use crate::keys::{DevicePublicKey, Endorsement, NodeKey, NodePublicKey, Retirement, UserKey};
use crate::log::{Detail, Event, Log, LogSink, SignedEntry, SignedHead};
use crate::policy::{
    Capture, Destination, Exchange, Identity, MAX_DELIMITER, MAX_DELIMITERS, Operation, Policy,
    Store,
};
use crate::record::{Pin, Record, check_name};
use crate::reflection::{self, MIN_NEEDLE, Secrets};
use crate::request::{self, Inputs, MAX_BODY, Outbound, Request};
use crate::response::{Http, MAX_RESPONSE};
use crate::template::{Budget, Context, Template, Temps, Var};
use crate::{Error, Result};

pub use crate::caller::CallerExchange;
pub use crate::response::Response;

/// Longest grant: 30 days.
pub const MAX_GRANT_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Longest input of a derivation, in bytes.
pub const MAX_INPUT: usize = 1024 * 1024;
/// Most exchanges of the caller on one stream.
pub const MAX_EXCHANGES: usize = 64;
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
    OsRng.fill_bytes(&mut random);
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

/// Redacts and checks a parsed response before it is handed back.
fn release_http(http: Http, log_seqs: Vec<u64>, secrets: &Secrets<'_>) -> Result<Response> {
    let mut response = http.into_response(log_seqs);
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
            if let Some(who) = self.seen.remove(&tag) {
                if let Some(count) = self.per_caller.get_mut(&who) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.per_caller.remove(&who);
                    }
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
    clock: C,
    state: Mutex<State<S>>,
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Runs a [`SignedCall`]: the HTTP, stream or derive operation it names, with the record
    /// and payload its caller signed.
    pub fn run<T: Transport>(&self, call: &SignedCall, transport: &mut T) -> Outcome<Output> {
        let (record, operation, auth) = (&call.record, call.operation.as_str(), &call.auth);
        match &call.body {
            Body::Http { request } => {
                let o = self.http(record, operation, auth, request.as_ref(), transport);
                Outcome {
                    result: o.result.map(Output::Http),
                    record: o.record,
                }
            }
            Body::Stream {
                destination,
                exchanges,
            } => {
                let o = self.stream(record, operation, auth, destination, exchanges, transport);
                Outcome {
                    result: o.result.map(Output::Stream),
                    record: o.record,
                }
            }
            Body::Derive { input } => Outcome {
                result: self
                    .derive(record, operation, auth, input)
                    .map(Output::Derive),
                record: None,
            },
        }
    }

    /// A node with a fresh chain.
    pub fn new(key: NodeKey, sink: S, clock: C) -> Self {
        let seal = SealSecret::of(&key);
        Self::with_log(Log::new(key), seal, sink, clock)
    }

    fn with_log(log: Log, seal: (SealSecret, NodeSealKey), sink: S, clock: C) -> Self {
        let public = log.public_key();
        let started_ms = clock.now_ms();
        Self {
            public,
            identity: NodeIdentity {
                log_key: public,
                seal_key: seal.1,
            },
            seal: seal.0,
            clock,
            state: Mutex::new(State {
                log,
                sink,
                grants: HashMap::new(),
                owners: HashMap::new(),
                floors: HashMap::new(),
                nonces: Nonces::default(),
                started_ms,
                calls: HashMap::new(),
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
        let node = Self::with_log(Log::resume(key, entries)?, seal, sink, clock);
        {
            let mut state = node.lock();
            // Something signed in the very millisecond of the restart may predate it.
            state.started_ms = state.started_ms.saturating_add(1);
            for signed in entries {
                let e = &signed.entry;
                match &e.event {
                    Event::Use { generation, .. }
                    | Event::Stream { generation, .. }
                    | Event::Derive { generation, .. }
                    | Event::Update { generation, .. }
                    | Event::Pin { generation } => {
                        state.raise(&e.owner, &e.record_id, *generation);
                    }
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
                    Event::Done { .. } => {}
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
        let operation = policy.operation(name)?;
        // A call of the wrong kind is refused before it spends a nonce or the rate limit.
        let kind_ok = matches!(
            (operation, payload),
            (Operation::Http { .. }, Payload::Http(_))
                | (Operation::Stream { .. }, Payload::Stream { .. })
                | (Operation::Derive { .. }, Payload::Derive(_))
        );
        if !kind_ok {
            return Err(operation.unknown());
        }
        let caller = policy.caller(&auth.caller)?;
        if !caller.operations.iter().any(|o| o == name) {
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
        Ok(fields)
    }

    /// Runs the HTTP operation `operation` of `record` for the caller of `auth`. `request` is
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
        let result = self.http_steps(record, operation, auth, request, transport, &mut updated);
        Outcome {
            result,
            record: updated,
        }
    }

    fn http_steps<T: Transport>(
        &self,
        record: &Record,
        name: &str,
        auth: &Authorization,
        request: Option<&Request>,
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Response> {
        let now = self.clock.now_ms();
        let (policy, operation, checked) =
            self.check_call(record, name, auth, &Payload::Http(request), now)?;
        let Operation::Http {
            destinations,
            identity,
            steps,
            ..
        } = operation
        else {
            return Err(operation.unknown());
        };
        match request {
            Some(request) if operation.takes_request() => request.validate(operation)?,
            None if !operation.takes_request() => {}
            Some(_) => {
                return Err(Error::RequestInvalid {
                    rule: "the operation takes no request",
                });
            }
            None => {
                return Err(Error::RequestInvalid {
                    rule: "the operation needs a request",
                });
            }
        }
        let user_key = checked.policy_owner;
        let mut fields = self.open(record, &user_key)?;
        let budget = Budget::default();
        let mut captured = Captured::default();
        let mut tainted = Vec::new();
        let mut log_seqs = Vec::with_capacity(steps.len());
        let who = (
            record.owner.as_str(),
            record.id.as_str(),
            checked.caller.as_str(),
        );

        for (index, step) in steps.iter().enumerate() {
            let outbound = Outbound::of(step, destinations, request)?;
            if !operation.allows_destination(outbound.destination) {
                return Err(outbound.destination.denied());
            }
            let built = request::build(
                step,
                &outbound,
                &Inputs {
                    policy,
                    operation,
                    fields: &fields,
                    temps: &captured.temps,
                    unix_ms: now,
                    budget: &budget,
                },
            )?;
            let client = render_identity(
                identity.as_ref(),
                &fields,
                &outbound.destination.host,
                now,
                &budget,
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
                operation: name.to_string(),
                generation: updated.as_ref().unwrap_or(record).generation,
                detail: detail.seal(&user_key, &record.owner, &record.id)?,
            };
            let (seq, confirmed) = self.lock().commit(now, who, event)?;
            log_seqs.push(seq);
            let sent = dispatch(
                confirmed,
                transport,
                outbound.destination,
                client.as_ref(),
                &built.wire,
            );
            drop(client);
            let (_, mut bytes) = match sent {
                Ok(sent) => sent,
                Err(error) => {
                    self.done(now, who, seq, None, false);
                    return Err(error);
                }
            };
            tainted.extend(built.tainted);
            let parsed = Http::parse(&bytes);
            bytes.zeroize();
            let http = match parsed {
                Ok(http) => http,
                Err(error) => {
                    self.done(now, who, seq, None, false);
                    return Err(error);
                }
            };
            let status = http.status;
            let mut stored = Ok(());
            for capture in &step.capture {
                stored = http
                    .capture(&capture.source)
                    .and_then(|value| captured.store(policy, &mut fields, capture, value));
                if stored.is_err() {
                    break;
                }
            }
            let persisted = self.persist(
                record,
                name,
                who,
                &fields,
                &mut captured,
                &user_key,
                now,
                updated,
            );
            if let Err(error) = stored.and(persisted) {
                self.done(now, who, seq, Some(status), false);
                return Err(error);
            }
            if index + 1 == steps.len() {
                let secrets = Secrets {
                    policy,
                    fields: &fields,
                    captured: &captured.secrets,
                    rendered: &tainted,
                };
                let released = release_http(http, log_seqs, &secrets);
                self.done(now, who, seq, Some(status), released.is_ok());
                return released;
            }
            self.done(now, who, seq, Some(status), true);
        }
        Err(operation.unknown())
    }

    /// Records how an act ended. A failure halts the log, so the next act fails; the result of
    /// this one is already decided.
    fn done(&self, now: u64, who: (&str, &str, &str), of: u64, status: Option<u16>, ok: bool) {
        let _ = self.lock().commit(now, who, Event::Done { of, status, ok });
    }

    /// Logs the fields an operation changed and seals them into a new record.
    #[allow(clippy::too_many_arguments)]
    fn persist(
        &self,
        record: &Record,
        operation: &str,
        who: (&str, &str, &str),
        fields: &Fields,
        captured: &mut Captured,
        user_key: &UserKey,
        now: u64,
        updated: &mut Option<Record>,
    ) -> Result<()> {
        if captured.changed.is_empty() {
            return Ok(());
        }
        let current = updated.as_ref().unwrap_or(record);
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(Error::RecordInvalid)?;
        let next = current.reseal(user_key, fields)?;
        let event = Event::Update {
            operation: operation.to_string(),
            generation,
            fields: core::mem::take(&mut captured.changed),
        };
        let mut state = self.lock();
        state.commit(now, who, event)?;
        state.raise(&record.owner, &record.id, generation);
        *updated = Some(next);
        Ok(())
    }

    /// Runs the stream operation `operation` of `record` on a connection to `destination`:
    /// the script of the policy, then the exchanges of the caller, whose reads are handed
    /// back. Values the script captured are sealed before the exchanges of the caller run.
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
        let result = self.stream_script(
            record,
            operation,
            auth,
            destination,
            exchanges,
            transport,
            &mut updated,
        );
        Outcome {
            result,
            record: updated,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn stream_script<T: Transport>(
        &self,
        record: &Record,
        name: &str,
        auth: &Authorization,
        destination: &Destination,
        exchanges: &[CallerExchange],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<StreamOutput> {
        let now = self.clock.now_ms();
        let payload = Payload::Stream {
            destination,
            exchanges,
        };
        let (policy, operation, checked) = self.check_call(record, name, auth, &payload, now)?;
        let Operation::Stream {
            identity, script, ..
        } = operation
        else {
            return Err(operation.unknown());
        };
        if !operation.allows_destination(destination) {
            return Err(destination.denied());
        }
        let exchanges_ok = exchanges.len() <= MAX_EXCHANGES
            && exchanges.iter().all(|e| {
                e.send.len() <= MAX_BODY
                    && !e.until.is_empty()
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
        let user_key = checked.policy_owner;
        let mut fields = self.open(record, &user_key)?;
        let budget = Budget::default();
        let kind = |n: &str| policy.name_kind(operation, n);
        let client = render_identity(identity.as_ref(), &fields, &destination.host, now, &budget)?;
        let who = (
            record.owner.as_str(),
            record.id.as_str(),
            checked.caller.as_str(),
        );

        let detail = Detail::Stream {
            host: destination.host.clone(),
            port: destination.port,
            sends_sha256: payload.sha256(),
            exchanges: u32::try_from(exchanges.len()).unwrap_or(u32::MAX),
        };
        let event = Event::Stream {
            operation: name.to_string(),
            generation: record.generation,
            detail: detail.seal(&user_key, &record.owner, &record.id)?,
        };
        let (seq, confirmed) = self.lock().commit(now, who, event)?;

        let mut captured = Captured::default();
        let mut output = StreamOutput::default();
        let mut tainted = Vec::new();
        let (_, mut stream) = match open_stream(confirmed, transport, destination, client.as_ref())
        {
            Ok(opened) => opened,
            Err(error) => {
                self.done(now, who, seq, None, false);
                return Err(error);
            }
        };
        drop(client);
        let mut script_result = Ok(());
        for exchange in script {
            let step = match exchange {
                Exchange::Send { template } => Template::parse(template).and_then(|template| {
                    let ctx = Context {
                        fields: &fields,
                        temps: &captured.temps,
                        vars: stream_vars(&destination.host, now),
                        unix: now / 1000,
                        budget: &budget,
                    };
                    let bytes = template.render(&ctx)?;
                    if template.tainted(&kind) {
                        tainted.push(bytes.clone());
                    }
                    stream.write(&bytes)
                }),
                Exchange::Expect { until, capture } => {
                    let delimiters: Vec<&[u8]> = until.iter().map(|u| u.as_bytes()).collect();
                    stream
                        .read_until(&delimiters, MAX_RESPONSE)
                        .map(Zeroizing::new)
                        .and_then(|read| {
                            capture.iter().try_for_each(|c| {
                                let value = crate::response::capture_bytes(&read, &c.source)?;
                                captured.store(policy, &mut fields, c, value)
                            })
                        })
                }
            };
            if let Err(error) = step {
                script_result = Err(error);
                break;
            }
        }
        let persisted = self.persist(
            record,
            name,
            who,
            &fields,
            &mut captured,
            &user_key,
            now,
            updated,
        );
        if let Err(error) = script_result.and(persisted) {
            let _ = stream.close();
            self.done(now, who, seq, None, false);
            return Err(error);
        }

        let secrets = Secrets {
            policy,
            fields: &fields,
            captured: &captured.secrets,
            rendered: &tainted,
        };
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

    /// Renders the derivation `operation` of `record` with `input` as `$input` and hands the
    /// output back. The policy was checked to hand back no secret in reversible form.
    pub fn derive(
        &self,
        record: &Record,
        operation: &str,
        auth: &Authorization,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        if input.len() > MAX_INPUT {
            return Err(Error::RequestInvalid {
                rule: "input larger than 1 MiB",
            });
        }
        let now = self.clock.now_ms();
        let (_, operation_ref, checked) =
            self.check_call(record, operation, auth, &Payload::Derive(input), now)?;
        let Operation::Derive { template, .. } = operation_ref else {
            return Err(operation_ref.unknown());
        };
        let template = Template::parse(template)?;
        let fields = self.open(record, &checked.policy_owner)?;
        let temps = Temps::new();
        let mut vars = stream_vars("", now);
        vars.remove(&Var::Host);
        vars.insert(Var::Input, input.to_vec());
        let budget = Budget::default();
        let ctx = Context {
            fields: &fields,
            temps: &temps,
            vars,
            unix: now / 1000,
            budget: &budget,
        };
        let output = template.render(&ctx)?;
        let detail = Detail::Derive {
            input_sha256: Sha256::digest(input).into(),
            input_len: input.len() as u64,
        };
        let event = Event::Derive {
            operation: operation.to_string(),
            generation: record.generation,
            detail: detail.seal(&checked.policy_owner, &record.owner, &record.id)?,
        };
        self.lock()
            .commit(now, (&record.owner, &record.id, &checked.caller), event)?;
        Ok(output.to_vec())
    }
}
