//! A node: it holds grants and performs the operations of owners.
//!
//! Order of every act, and why:
//! 1. grant in force; record not older than one the node saw or the owner pinned; policy
//!    signed by a device of the grant;
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

use crate::caller::{Authorization, Call, MAX_SKEW_MS, Payload};
use crate::egress::{ClientIdentity, Transport, dispatch, open_stream};
use crate::fields::Fields;
use crate::keys::{DevicePublicKey, Endorsement, NodeKey, NodePublicKey, UserKey};
use crate::log::{Event, Log, LogSink, SignedEntry, SignedHead};
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

/// A source of time.
pub trait Clock {
    /// Now, Unix milliseconds.
    fn now_ms(&self) -> u64;
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
/// value into a field. The new record replaces the old one even when `result` is an error.
#[derive(Debug)]
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
    devices: Vec<DevicePublicKey>,
    expires_ms: u64,
}

type RecordKey = (String, String);

struct State<S> {
    log: Log,
    sink: S,
    grants: HashMap<String, Grant>,
    floors: HashMap<RecordKey, u64>,
    nonces: HashMap<[u8; 32], u64>,
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

    fn floor(&self, record: &Record) -> u64 {
        self.floors
            .get(&(record.owner.clone(), record.id.clone()))
            .copied()
            .unwrap_or(0)
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
    clock: C,
    state: Mutex<State<S>>,
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// A node with a fresh chain.
    pub fn new(key: NodeKey, sink: S, clock: C) -> Self {
        Self::with_log(Log::new(key), sink, clock)
    }

    fn with_log(log: Log, sink: S, clock: C) -> Self {
        Self {
            public: log.public_key(),
            clock,
            state: Mutex::new(State {
                log,
                sink,
                grants: HashMap::new(),
                floors: HashMap::new(),
                nonces: HashMap::new(),
                calls: HashMap::new(),
            }),
        }
    }

    /// A node that continues its chain after a restart: `entries` are all the entries its
    /// sink holds, from seq 0. The generations they name become the floors of the records;
    /// grants are not restored (owners grant again).
    pub fn restore(key: NodeKey, sink: S, clock: C, entries: &[SignedEntry]) -> Result<Self> {
        let node = Self::with_log(Log::resume(key, entries)?, sink, clock);
        {
            let mut state = node.lock();
            for signed in entries {
                let e = &signed.entry;
                let generation = match &e.event {
                    Event::Use { generation, .. }
                    | Event::Stream { generation, .. }
                    | Event::Derive { generation, .. }
                    | Event::Update { generation, .. }
                    | Event::Pin { generation } => *generation,
                    _ => continue,
                };
                state.raise(&e.owner, &e.record_id, generation);
            }
        }
        Ok(node)
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

    /// Takes the user key of `owner` until `expires_ms` (at most [`MAX_GRANT_MS`] from now).
    /// When a grant with the same user key is in force, `device` is added to its devices;
    /// otherwise the grant replaces it. The entry is confirmed before the key is kept.
    pub fn grant(
        &self,
        owner: &str,
        user_key: UserKey,
        device: DevicePublicKey,
        expires_ms: u64,
    ) -> Result<()> {
        check_name(owner)?;
        let now = self.clock.now_ms();
        let expires_ms = expires_ms.min(now.saturating_add(MAX_GRANT_MS));
        if expires_ms <= now {
            return Err(Error::GrantExpired);
        }
        let mut state = self.lock();
        state.commit(now, (owner, "", ""), Event::Grant { expires_ms, device })?;
        let mut devices = match state.grant_of(owner, now) {
            Ok(old) if old.user_key.same(&user_key) => old.devices.clone(),
            _ => Vec::new(),
        };
        if !devices.contains(&device) {
            devices.push(device);
        }
        state.grants.insert(
            owner.to_string(),
            Grant {
                user_key: Arc::new(user_key),
                devices,
                expires_ms,
            },
        );
        Ok(())
    }

    /// Adds a device a device of the grant endorsed.
    pub fn add_device(&self, endorsement: &Endorsement) -> Result<()> {
        let now = self.clock.now_ms();
        let mut state = self.lock();
        endorsement.verify(&state.grant_of(&endorsement.owner, now)?.devices)?;
        state.commit(
            now,
            (&endorsement.owner, "", ""),
            Event::Device {
                device: endorsement.device,
            },
        )?;
        if let Some(grant) = state.grants.get_mut(&endorsement.owner) {
            if !grant.devices.contains(&endorsement.device) {
                grant.devices.push(endorsement.device);
            }
        }
        Ok(())
    }

    /// Erases the user key of `owner` first, then records the revoke. An operation already
    /// running finishes with the key it took.
    pub fn revoke(&self, owner: &str) -> Result<()> {
        let now = self.clock.now_ms();
        let mut state = self.lock();
        state.grants.remove(owner);
        state.commit(now, (owner, "", ""), Event::Revoke)?;
        Ok(())
    }

    /// Raises the lowest generation of a record this node accepts, as a device of the owner
    /// signed.
    pub fn pin(&self, pin: &Pin) -> Result<()> {
        let now = self.clock.now_ms();
        let mut state = self.lock();
        pin.verify(&state.grant_of(&pin.owner, now)?.devices)?;
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
        let (user_key, devices) = {
            let mut state = self.lock();
            let need = state.floor(record);
            let grant = state.grant_of(&record.owner, now)?;
            let found = (grant.user_key.clone(), grant.devices.clone());
            if record.generation < need {
                return Err(Error::RecordStale {
                    have: record.generation,
                    need,
                });
            }
            found
        };
        let policy = record.policy.verify_any(&devices)?;
        let operation = policy.operation(name)?;
        let caller = policy.caller(&auth.caller)?;
        if !caller.operations.iter().any(|o| o == name) {
            return Err(Error::CallerDenied);
        }
        if auth.time_ms.abs_diff(now) > MAX_SKEW_MS {
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
        let mut tag = Sha256::new();
        tag.update(caller.key.to_b64().as_bytes());
        tag.update(auth.nonce);
        let tag: [u8; 32] = tag.finalize().into();
        let mut state = self.lock();
        if state.nonces.len() >= MAX_NONCES / 2 {
            state.nonces.retain(|_, expires| *expires > now);
        }
        if state.nonces.len() >= MAX_NONCES {
            return Err(Error::CallerInvalid {
                rule: "too many recent calls to check for replay",
            });
        }
        if state.nonces.contains_key(&tag) {
            return Err(Error::CallerInvalid {
                rule: "authorization used before",
            });
        }
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
        state
            .nonces
            .insert(tag, auth.time_ms.saturating_add(MAX_SKEW_MS));
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
            return Err(Error::OperationUnknown);
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
                return Err(Error::DestinationDenied);
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
            let event = Event::Use {
                operation: name.to_string(),
                generation: updated.as_ref().unwrap_or(record).generation,
                method: outbound.method,
                host: outbound.destination.host.clone(),
                port: outbound.destination.port,
                path: outbound.path.to_string(),
                body_sha256: Sha256::digest(outbound.body).into(),
                body_len: outbound.body.len() as u64,
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
        Err(Error::OperationUnknown)
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
            return Err(Error::OperationUnknown);
        };
        if !operation.allows_destination(destination) {
            return Err(Error::DestinationDenied);
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

        let event = Event::Stream {
            operation: name.to_string(),
            generation: record.generation,
            host: destination.host.clone(),
            port: destination.port,
            sends_sha256: payload.sha256(),
            exchanges: u32::try_from(exchanges.len()).unwrap_or(u32::MAX),
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
            return Err(Error::OperationUnknown);
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
        let event = Event::Derive {
            operation: operation.to_string(),
            generation: record.generation,
            input_sha256: Sha256::digest(input).into(),
            input_len: input.len() as u64,
        };
        self.lock()
            .commit(now, (&record.owner, &record.id, &checked.caller), event)?;
        Ok(output.to_vec())
    }
}
