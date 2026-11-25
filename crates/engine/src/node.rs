//! A node: it holds grants and performs the operations of owners.
//!
//! Order of every act, and why:
//! 1. grant in force, policy signed by the device of the grant, request within the operation;
//! 2. record opened, templates rendered (failures here leave no entry: nothing happened);
//! 3. entry confirmed by the sink ([`Log::commit`]), else nothing is sent or handed back;
//! 4. request sent (or connection opened) through the [`Transport`], once per entry;
//! 5. values captured; a changed field is logged ([`Event::Update`]) and sealed into a new
//!    record, which the caller gets back even when a later step fails;
//! 6. captured secrets redacted and the response checked for secrets before it is handed back.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::egress::{ClientIdentity, Transport, dispatch, open_stream};
use crate::fields::Fields;
use crate::keys::{DevicePublicKey, NodeKey, NodePublicKey, UserKey};
use crate::log::{Event, Log, LogSink};
use crate::policy::{
    Capture, Destination, Exchange, Identity, MAX_DELIMITER, Operation, Policy, StepRequest, Store,
};
use crate::record::{Record, check_name};
use crate::request::{self, MAX_BODY, Outbound, Request};
use crate::response::{self, Http, MAX_RESPONSE};
use crate::template::{Context, Template, Temps, Var, hex};
use crate::{Error, Result, reflection};

/// Longest grant: 30 days.
pub const MAX_GRANT_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Longest input of a derivation, in bytes.
pub const MAX_INPUT: usize = 1024 * 1024;
/// Most exchanges of the caller on one stream.
pub const MAX_EXCHANGES: usize = 64;

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

/// The response of a request sent with the values of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The raw response bytes, after redaction and the reflection check.
    pub bytes: Vec<u8>,
    /// The sequence number of the log entry of the request.
    pub log_seq: u64,
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

/// One exchange of the caller on an authenticated stream: bytes written, then bytes read up
/// to and including `until`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerExchange {
    /// What is written.
    pub send: Vec<u8>,
    /// The delimiter that ends the read.
    pub until: Vec<u8>,
}

/// Values captured during one operation.
#[derive(Default)]
struct Captured {
    temps: Temps,
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
                if policy.is_secret(name) {
                    self.secrets.push(value.clone());
                }
                fields.set(name, value)?;
                if !self.changed.contains(name) {
                    self.changed.push(name.clone());
                }
            }
            Store::Temp { name, secret } => {
                if *secret {
                    self.secrets.push(value.clone());
                }
                self.temps.insert(name.clone(), value);
            }
        }
        Ok(())
    }
}

fn stream_vars(host: &str, now: u64) -> HashMap<Var, Vec<u8>> {
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    HashMap::from([
        (Var::Host, host.as_bytes().to_vec()),
        (Var::Unix, (now / 1000).to_string().into_bytes()),
        (Var::UnixMs, now.to_string().into_bytes()),
        (Var::Nonce, hex(&random).to_vec()),
    ])
}

fn render_identity(
    identity: Option<&Identity>,
    fields: &Fields,
    host: &str,
    now: u64,
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
    };
    let cert = Template::parse(&identity.cert)?.render(&ctx)?;
    let key = Template::parse(&identity.key)?.render(&ctx)?;
    Ok(Some(ClientIdentity::new(cert, key)))
}

/// Redacts, then checks a response before it is handed back; zeroizes it when it fails.
fn release(
    mut bytes: Vec<u8>,
    policy: &Policy,
    fields: &Fields,
    captured: &Captured,
    tainted: &[Zeroizing<Vec<u8>>],
) -> Result<Vec<u8>> {
    response::redact(&mut bytes, &captured.secrets);
    let mut needles = tainted.to_vec();
    needles.extend(captured.secrets.iter().cloned());
    if let Err(error) = reflection::check(&bytes, policy, fields, &needles) {
        bytes.zeroize();
        return Err(error);
    }
    Ok(bytes)
}

struct Grant {
    user_key: UserKey,
    device: DevicePublicKey,
    expires_ms: u64,
}

/// A node.
pub struct Node<S: LogSink, C: Clock> {
    log: Log,
    sink: S,
    clock: C,
    grants: HashMap<String, Grant>,
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// A node with a fresh chain.
    pub fn new(key: NodeKey, sink: S, clock: C) -> Self {
        Self {
            log: Log::new(key),
            sink,
            clock,
            grants: HashMap::new(),
        }
    }

    /// The key that verifies the log of this node.
    pub fn public_key(&self) -> NodePublicKey {
        self.log.public_key()
    }

    /// The log sink.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// The log sink, mutable.
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Takes the user key of `owner` until `expires_ms` (at most [`MAX_GRANT_MS`] from now).
    /// The entry is confirmed before the key is kept.
    pub fn grant(
        &mut self,
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
        self.log
            .commit(&mut self.sink, now, owner, "", Event::Grant { expires_ms })?;
        self.grants.insert(
            owner.to_string(),
            Grant {
                user_key,
                device,
                expires_ms,
            },
        );
        Ok(())
    }

    /// Erases the user key of `owner` first, then records the revoke.
    pub fn revoke(&mut self, owner: &str) -> Result<()> {
        self.grants.remove(owner);
        let now = self.clock.now_ms();
        self.log
            .commit(&mut self.sink, now, owner, "", Event::Revoke)?;
        Ok(())
    }

    fn grant_of(&mut self, owner: &str) -> Result<&Grant> {
        let now = self.clock.now_ms();
        match self.grants.get(owner) {
            None => Err(Error::NoGrant),
            Some(grant) if grant.expires_ms <= now => {
                self.grants.remove(owner);
                Err(Error::GrantExpired)
            }
            Some(_) => self.grants.get(owner).ok_or(Error::NoGrant),
        }
    }

    fn checked_policy<'r>(&mut self, record: &'r Record) -> Result<&'r Policy> {
        let device = self.grant_of(&record.owner)?.device;
        record.policy.verify(&device)
    }

    /// Runs the HTTP operation `operation` of `record`. `request` is the request of the
    /// caller; it is required exactly when a step sends the request of the caller.
    pub fn http<T: Transport>(
        &mut self,
        record: &Record,
        operation: &str,
        request: Option<&Request>,
        transport: &mut T,
    ) -> Outcome<Response> {
        let mut updated = None;
        let result = self.http_steps(record, operation, request, transport, &mut updated);
        Outcome {
            result,
            record: updated,
        }
    }

    fn http_steps<T: Transport>(
        &mut self,
        record: &Record,
        name: &str,
        request: Option<&Request>,
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Response> {
        let policy = self.checked_policy(record)?;
        let operation = policy.operation(name)?;
        let Operation::Http {
            destinations,
            identity,
            steps,
            ..
        } = operation
        else {
            return Err(Error::OperationUnknown);
        };
        let has_caller = steps.iter().any(|s| s.request == StepRequest::Caller);
        match request {
            Some(request) if has_caller => request.validate(operation)?,
            None if !has_caller => {}
            _ => return Err(Error::RequestInvalid),
        }
        let mut fields = record.open(&self.grant_of(&record.owner)?.user_key)?;
        let now = self.clock.now_ms();
        let secret = |n: &str| policy.is_secret_in(operation, n);
        let mut captured = Captured::default();
        let mut tainted = Vec::new();

        for (index, step) in steps.iter().enumerate() {
            let outbound = Outbound::of(step, destinations, request)?;
            if !operation.allows_destination(outbound.destination) {
                return Err(Error::DestinationDenied);
            }
            let built = request::build(step, &outbound, &fields, &captured.temps, now, &secret)?;
            let client =
                render_identity(identity.as_ref(), &fields, &outbound.destination.host, now)?;
            let event = Event::Use {
                operation: name.to_string(),
                method: outbound.method,
                host: outbound.destination.host.clone(),
                port: outbound.destination.port,
                path: outbound.path.to_string(),
                body_sha256: Sha256::digest(outbound.body).into(),
            };
            let (_, confirmed) =
                self.log
                    .commit(&mut self.sink, now, &record.owner, &record.id, event)?;
            let (log_seq, mut bytes) = dispatch(
                confirmed,
                transport,
                outbound.destination,
                client.as_ref(),
                &built.wire,
            )?;
            tainted.extend(built.tainted);

            if !step.capture.is_empty() {
                let stored = Http::parse(&bytes).and_then(|http| {
                    step.capture.iter().try_for_each(|c| {
                        captured.store(policy, &mut fields, c, http.capture(&c.source)?)
                    })
                });
                if let Err(error) = stored {
                    bytes.zeroize();
                    return Err(error);
                }
                self.persist(record, name, &fields, &mut captured, now, updated)?;
            }

            if index + 1 == steps.len() {
                let bytes = release(bytes, policy, &fields, &captured, &tainted)?;
                return Ok(Response { bytes, log_seq });
            }
            bytes.zeroize();
        }
        Err(Error::PolicyInvalid)
    }

    /// Logs the fields an operation changed and seals them into a new record.
    fn persist(
        &mut self,
        record: &Record,
        operation: &str,
        fields: &Fields,
        captured: &mut Captured,
        now: u64,
        updated: &mut Option<Record>,
    ) -> Result<()> {
        if captured.changed.is_empty() {
            return Ok(());
        }
        let event = Event::Update {
            operation: operation.to_string(),
            fields: core::mem::take(&mut captured.changed),
        };
        self.log
            .commit(&mut self.sink, now, &record.owner, &record.id, event)?;
        let user_key = &self.grant_of(&record.owner)?.user_key;
        *updated = Some(record.reseal(user_key, fields)?);
        Ok(())
    }

    /// Runs the stream operation `operation` of `record` on a connection to `destination`:
    /// the script of the policy, then the exchanges of the caller, whose reads are handed
    /// back.
    pub fn stream<T: Transport>(
        &mut self,
        record: &Record,
        operation: &str,
        destination: &Destination,
        exchanges: &[CallerExchange],
        transport: &mut T,
    ) -> Outcome<Vec<Vec<u8>>> {
        let mut updated = None;
        let result = self.stream_script(
            record,
            operation,
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

    fn stream_script<T: Transport>(
        &mut self,
        record: &Record,
        name: &str,
        destination: &Destination,
        exchanges: &[CallerExchange],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<Vec<Vec<u8>>> {
        let policy = self.checked_policy(record)?;
        let operation = policy.operation(name)?;
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
                e.send.len() <= MAX_BODY && !e.until.is_empty() && e.until.len() <= MAX_DELIMITER
            });
        if !exchanges_ok {
            return Err(Error::RequestInvalid);
        }
        let mut fields = record.open(&self.grant_of(&record.owner)?.user_key)?;
        let now = self.clock.now_ms();
        let secret = |n: &str| policy.is_secret_in(operation, n);
        let client = render_identity(identity.as_ref(), &fields, &destination.host, now)?;

        let mut hasher = Sha256::new();
        for exchange in exchanges {
            let len = u32::try_from(exchange.send.len()).map_err(|_| Error::RequestInvalid)?;
            hasher.update(len.to_be_bytes());
            hasher.update(&exchange.send);
        }
        let event = Event::Stream {
            operation: name.to_string(),
            host: destination.host.clone(),
            port: destination.port,
            sends_sha256: hasher.finalize().into(),
        };
        let (_, confirmed) =
            self.log
                .commit(&mut self.sink, now, &record.owner, &record.id, event)?;

        let mut captured = Captured::default();
        let mut out = Vec::with_capacity(exchanges.len());
        {
            let (_, mut stream) = open_stream(confirmed, transport, destination, client.as_ref())?;
            let mut tainted = Vec::new();
            for exchange in script {
                match exchange {
                    Exchange::Send { template } => {
                        let template = Template::parse(template)?;
                        let ctx = Context {
                            fields: &fields,
                            temps: &captured.temps,
                            vars: stream_vars(&destination.host, now),
                            unix: now / 1000,
                        };
                        let bytes = template.render(&ctx)?;
                        if template.tainted(&secret) {
                            tainted.push(bytes.clone());
                        }
                        stream.write(&bytes)?;
                    }
                    Exchange::Expect { until, capture } => {
                        let read =
                            Zeroizing::new(stream.read_until(until.as_bytes(), MAX_RESPONSE)?);
                        for c in capture {
                            let value = response::capture_bytes(&read, &c.source)?;
                            captured.store(policy, &mut fields, c, value)?;
                        }
                    }
                }
            }
            for exchange in exchanges {
                stream.write(&exchange.send)?;
                let read = stream.read_until(&exchange.until, MAX_RESPONSE)?;
                out.push(release(read, policy, &fields, &captured, &tainted)?);
            }
        }
        self.persist(record, name, &fields, &mut captured, now, updated)?;
        Ok(out)
    }

    /// Renders the derivation `operation` of `record` with `input` as `$input` and hands the
    /// output back. The policy was checked to hand back no secret in reversible form.
    pub fn derive(&mut self, record: &Record, operation: &str, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() > MAX_INPUT {
            return Err(Error::RequestInvalid);
        }
        let policy = self.checked_policy(record)?;
        let Operation::Derive { template, .. } = policy.operation(operation)? else {
            return Err(Error::OperationUnknown);
        };
        let template = Template::parse(template)?;
        let fields = record.open(&self.grant_of(&record.owner)?.user_key)?;
        let now = self.clock.now_ms();
        let temps = Temps::new();
        let mut vars = stream_vars("", now);
        vars.remove(&Var::Host);
        vars.insert(Var::Input, input.to_vec());
        let ctx = Context {
            fields: &fields,
            temps: &temps,
            vars,
            unix: now / 1000,
        };
        let output = template.render(&ctx)?;
        let event = Event::Derive {
            operation: operation.to_string(),
            input_sha256: Sha256::digest(input).into(),
        };
        self.log
            .commit(&mut self.sink, now, &record.owner, &record.id, event)?;
        Ok(output.to_vec())
    }
}
