//! Connections that stay open: a response handed to the caller as it arrives, and
//! WebSockets.
//!
//! Both run on one thread, the node's, in a loop that waits on the server a few milliseconds
//! at a time and then on the caller, through a [`Relay`] the server side of the node gives.
//! There is no async runtime: a connection is a thread, as every call is, and the number open
//! at once is bounded per caller, per owner and per node ([`MAX_STREAMS`]).
//!
//! What goes back to the caller passes the stream search ([`Scrubber`]): it holds back the
//! last bytes of what came, as many as the longest form of a secret less one, until the next
//! part shows they are not the start of one. A WebSocket message goes back whole; the search
//! covers it together with the end of the messages before it.
//!
//! The caller's frames on a WebSocket are signed with its key and numbered
//! ([`crate::keys::CallerKey::sign_frame`]), so whoever carries them between the caller and
//! the node cannot add, drop or reorder one unseen; each must match a [`FrameRule`] of the
//! policy, and the node sends the rule's template in its place.
//!
//! The log gets one entry when the connection opens (the request, as any) and one when it
//! closes ([`Event::Closed`]), with what went each way.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{Clock, Node, Run, compute_vars, release_http, stream_vars};
use crate::caller::Authorization;
use crate::egress::{Arrived, ClientIdentity, Stream, Transport, Versions, dispatch_streamed};
use crate::error::TransportKind;
use crate::log::{Confirmed, Event, LogSink};
use crate::policy::{
    Connection, FrameKind, Open, Operation, Policy, Projection, Relay as Rules, Send, Step,
    StreamLimits,
};
use crate::record::Record;
use crate::reflection::{self, Scrubber, Secrets};
use crate::request::{Request, Wire};
use crate::response::{self, BodyDecoder, Fields, Http, MAX_HEAD, find};
use crate::secret::Secret;
use crate::template::{Context, Template, Var};
use crate::websocket::{self, Decoder, FrameError, Message};
use crate::{Error, Result};

/// Most connections open at once on a node.
pub const MAX_STREAMS: usize = 256;
/// Most connections open at once for one owner.
pub const MAX_STREAMS_PER_OWNER: usize = 16;
/// Most connections open at once for one caller key.
pub const MAX_STREAMS_PER_CALLER: usize = 4;
/// Longest message from the server, in bytes.
const MAX_MESSAGE: usize = crate::response::MAX_RESPONSE;
/// Longest frame from the caller, in bytes.
const MAX_FRAME: usize = super::MAX_INPUT;
/// Most bytes read at once.
pub(super) const READ: usize = 64 * 1024;
/// How long one wait on the server lasts before the caller's side is looked at.
pub(super) const POLL: Duration = Duration::from_millis(10);

/// A part of what goes back to the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum Part {
    /// The response head (no body): the status and the headers the projection names; for a
    /// WebSocket, `101` once the steps ran and the relay starts.
    Head(super::Response),
    /// Body bytes of a streamed response, after the stream search.
    Body(Zeroizing<Vec<u8>>),
    /// A text message of the server (WebSocket).
    Text(Zeroizing<Vec<u8>>),
    /// A binary message of the server (WebSocket).
    Binary(Zeroizing<Vec<u8>>),
}

/// A frame of the caller for a WebSocket, signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerFrame {
    /// Its number: 0 for the first frame of the call, one more each frame.
    pub seq: u64,
    /// Text or binary.
    pub kind: FrameKind,
    /// The bytes.
    pub data: Vec<u8>,
    /// [`crate::keys::CallerKey::sign_frame`] over the call, `seq`, the kind and the bytes.
    pub signature: [u8; 64],
}

/// What the caller sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FromCaller {
    /// A frame for the server.
    Frame(CallerFrame),
    /// The caller closes.
    Close,
}

/// The caller's side of an open connection, as the node's server gives it.
pub trait Relay {
    /// Hands a part to the caller. An error ends the connection (the caller is gone).
    fn deliver(&mut self, part: Part) -> Result<()>;

    /// What the caller sent, waiting at most `wait`; `None` when nothing came. An error ends
    /// the connection.
    fn next(&mut self, wait: Duration) -> Result<Option<FromCaller>>;
}

/// How an open connection ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closed {
    /// Why: `server` (it closed or the response ended), `caller`, `idle`, `duration`,
    /// `bytes` (a limit), or `steps` (a WebSocket that relays nothing ran its steps).
    pub reason: String,
    /// The status of the response or the handshake.
    pub status: Option<u16>,
    /// The trailers the projection names, after the stream search.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::encoding::b64_pairs"
    )]
    pub trailers: Vec<(String, Vec<u8>)>,
    /// Messages (or none for a response) and bytes sent to the server after the request.
    pub to_server: (u64, u64),
    /// Parts and bytes handed to the caller.
    pub to_caller: (u64, u64),
    /// How long it was open, in milliseconds.
    pub duration_ms: u64,
    /// The sequence numbers of the log entries of the requests of the operation.
    pub log_seqs: Vec<u64>,
}

/// The connections open now, counted.
#[derive(Default)]
pub(crate) struct Slots(Mutex<Counts>);

#[derive(Default)]
struct Counts {
    total: usize,
    owners: HashMap<String, usize>,
    callers: HashMap<String, usize>,
}

/// One open connection, counted until it is dropped.
#[must_use]
pub(crate) struct Slot<'n> {
    slots: &'n Slots,
    owner: String,
    caller: String,
}

impl Slots {
    /// The counts, or [`Error::StateLost`] once a panic poisoned their lock: counts a panic
    /// left half updated could let more connections open than the bounds allow, so no new
    /// one opens then. The rest of the node goes on: the counts only bound connections.
    fn counts(&self) -> Result<std::sync::MutexGuard<'_, Counts>> {
        self.0.lock().map_err(|_| Error::StateLost { sent: false })
    }

    /// Takes a slot for a connection of `caller` (its name in `policy`) on `owner`'s record,
    /// or fails with [`Error::StreamsFull`].
    pub(crate) fn take(&self, owner: &str, caller: &str, policy: &Policy) -> Result<Slot<'_>> {
        let caller = policy.caller(caller)?.key.to_b64();
        let mut counts = self.counts()?;
        let owned = counts.owners.get(owner).copied().unwrap_or(0);
        let called = counts.callers.get(&caller).copied().unwrap_or(0);
        if counts.total >= MAX_STREAMS {
            return Err(Error::StreamsFull { who: "node" });
        }
        if owned >= MAX_STREAMS_PER_OWNER {
            return Err(Error::StreamsFull { who: "owner" });
        }
        if called >= MAX_STREAMS_PER_CALLER {
            return Err(Error::StreamsFull { who: "caller" });
        }
        counts.total += 1;
        counts.owners.insert(owner.to_string(), owned + 1);
        counts.callers.insert(caller.clone(), called + 1);
        Ok(Slot {
            slots: self,
            owner: owner.to_string(),
            caller,
        })
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        // Poisoned counts are not used again, so there is nothing to give back to.
        if let Ok(mut counts) = self.slots.counts() {
            counts.total = counts.total.saturating_sub(1);
            release(&mut counts.owners, &self.owner);
            release(&mut counts.callers, &self.caller);
        }
    }
}

fn release(map: &mut HashMap<String, usize>, key: &str) {
    if let Some(n) = map.get_mut(key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(key);
        }
    }
}

/// True when the operation runs on a streaming call: a WebSocket, or HTTPS whose `return`
/// streams the body.
pub(crate) fn streams(operation: &Operation) -> bool {
    operation.streams()
}

/// The answer of a unary gRPC call: its message unframed, when the answer is gRPC.
pub(crate) fn grpc_answer(mut http: Http) -> Result<Http> {
    let grpc = http
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-type") && crate::grpc::is_grpc(v));
    if http.status == 200 && grpc {
        http.body = crate::grpc::unframe(&http.body)?;
    }
    Ok(http)
}

/// A request built and logged, ready to go out.
pub(crate) struct Prepared<'o> {
    pub seq: u64,
    pub confirmed: Confirmed,
    pub wire: Secret<Vec<u8>>,
    pub tainted: Vec<Zeroizing<Vec<u8>>>,
    pub client: Option<ClientIdentity>,
    pub destination: &'o crate::policy::Destination,
}

/// The caller's side of a streaming call.
pub(crate) struct Live<'a> {
    pub auth: &'a Authorization,
    pub relay: &'a mut dyn Relay,
}

/// Counts and bounds of one open connection.
pub(super) struct Meter {
    pub(super) started: Instant,
    last: Instant,
    idle: Duration,
    duration: Duration,
    max_bytes: u64,
    bytes: u64,
    pub(super) to_server: (u64, u64),
    pub(super) to_caller: (u64, u64),
}

impl Meter {
    pub(super) fn new(limits: Option<&StreamLimits>) -> Self {
        let (idle, duration, bytes) = limits.copied().unwrap_or_default().effective();
        let now = Instant::now();
        Self {
            started: now,
            last: now,
            idle: Duration::from_millis(idle),
            duration: Duration::from_millis(duration),
            max_bytes: bytes,
            bytes: 0,
            to_server: (0, 0),
            to_caller: (0, 0),
        }
    }

    pub(super) fn received(&mut self, raw: usize) {
        self.bytes = self.bytes.saturating_add(raw as u64);
        self.last = Instant::now();
    }

    fn sent(&mut self, raw: usize, payload: usize) {
        self.bytes = self.bytes.saturating_add(raw as u64);
        self.to_server.0 += 1;
        self.to_server.1 = self.to_server.1.saturating_add(payload as u64);
        self.last = Instant::now();
    }

    fn delivered(&mut self, len: usize) {
        self.to_caller.0 += 1;
        self.to_caller.1 = self.to_caller.1.saturating_add(len as u64);
    }

    /// The limit reached, if any.
    pub(super) fn reached(&self) -> Option<&'static str> {
        if self.bytes > self.max_bytes {
            Some("bytes")
        } else if self.started.elapsed() >= self.duration {
            Some("duration")
        } else if self.last.elapsed() >= self.idle {
            Some("idle")
        } else {
            None
        }
    }

    /// A limit reached before the relay, as an error.
    pub(super) fn check(&self) -> Result<()> {
        match self.reached() {
            None => Ok(()),
            Some("bytes") => Err(Error::Budget {
                what: "connection bytes",
            }),
            Some(_) => Err(Error::transport(TransportKind::Timeout, true)),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// How the relay ended.
pub(super) struct End {
    pub(super) reason: &'static str,
    pub(super) ok: bool,
    pub(super) trailers: Vec<(String, Vec<u8>)>,
}

impl End {
    pub(super) fn of(reason: &'static str, ok: bool) -> Self {
        Self {
            reason,
            ok,
            trailers: Vec::new(),
        }
    }
}

pub(super) fn reason_of(error: &Error) -> &'static str {
    match error {
        Error::Reflection => "reflection",
        Error::FrameRefused { .. } => "refused",
        Error::ServerUntrusted { .. } => "untrusted",
        Error::AuthRefused { .. } => "auth",
        _ => "error",
    }
}

pub(super) fn ws_error(error: FrameError) -> Error {
    match error {
        FrameError::Protocol(rule) => Error::ResponseInvalid { rule },
        FrameError::TooLarge => Error::transport(TransportKind::TooLarge, true),
    }
}

fn has(headers: &Fields, name: &str, test: impl Fn(&[u8]) -> bool) -> bool {
    headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case(name) && test(v.trim_ascii()))
}

/// Checks the answer to a WebSocket handshake (RFC 6455, 4.1): `101`, the upgrade, the
/// accept value of the key, no extension (the node offered none), and a subprotocol only
/// when the request offered one.
pub(super) fn check_upgrade(status: u16, headers: &Fields, key: &str, offered: bool) -> Result<()> {
    let invalid = |rule| Err(Error::ResponseInvalid { rule });
    if status != 101 {
        return invalid("WebSocket handshake refused (status other than 101)");
    }
    if !has(headers, "upgrade", |v| v.eq_ignore_ascii_case(b"websocket")) {
        return invalid("WebSocket handshake without Upgrade: websocket");
    }
    let upgrade_token = |v: &[u8]| {
        v.split(|b| *b == b',')
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
    };
    if !has(headers, "connection", upgrade_token) {
        return invalid("WebSocket handshake without Connection: upgrade");
    }
    let expected = websocket::accept(key);
    if !has(headers, "sec-websocket-accept", |v| {
        v == expected.as_bytes()
    }) {
        return invalid("WebSocket handshake with a wrong Sec-WebSocket-Accept");
    }
    if has(headers, "sec-websocket-extensions", |_| true) {
        return invalid("WebSocket extension the node did not offer");
    }
    if !offered && has(headers, "sec-websocket-protocol", |_| true) {
        return invalid("WebSocket subprotocol the request did not offer");
    }
    Ok(())
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Runs an operation that streams, its parts going through `live`.
    pub(super) fn run_live<T: Transport>(
        &self,
        run: &mut Run<'_>,
        request: Option<&Request>,
        transport: &mut T,
        mut live: Live<'_>,
        updated: &mut Option<Record>,
    ) -> Result<Closed> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        match open.connection {
            Connection::Websocket => self.socket(run, open, request, transport, &mut live, updated),
            Connection::Https => self.streamed(run, open, request, transport, &mut live, updated),
            Connection::Tls
            | Connection::Udp
            | Connection::Dtls
            | Connection::Ssh
            | Connection::Postgres
            | Connection::Smtp
            | Connection::Imap
            | Connection::Redis
            | Connection::Browser
            | Connection::Mysql
            | Connection::Mqtt
            | Connection::Amqp
            | Connection::Amqp1
            | Connection::Ftp
            | Connection::Pop3 => Err(operation.unknown()),
        }
    }

    /// Logs how an open connection ended and builds what goes back.
    pub(super) fn closed(
        &self,
        run: &Run<'_>,
        of: u64,
        status: Option<u16>,
        meter: &Meter,
        end: std::result::Result<End, (&'static str, Error)>,
    ) -> Result<Closed> {
        let (reason, ok) = match &end {
            Ok(end) => (end.reason, end.ok),
            Err((reason, _)) => (*reason, false),
        };
        let event = Event::Closed {
            of,
            status,
            ok,
            reason: reason.to_string(),
            to_server: meter.to_server,
            to_caller: meter.to_caller,
            duration_ms: meter.elapsed_ms(),
        };
        let logged = self.lock().and_then(|mut state| {
            state.commit(
                self.clock.checked_now_ms().unwrap_or(run.now),
                run.who,
                event,
            )
        });
        let end = end.map_err(|(_, error)| error)?;
        logged?;
        Ok(Closed {
            reason: end.reason.to_string(),
            status,
            trailers: end.trailers,
            to_server: meter.to_server,
            to_caller: meter.to_caller,
            duration_ms: meter.elapsed_ms(),
            log_seqs: run.log_seqs.clone(),
        })
    }

    pub(super) fn scrubber(run: &Run<'_>) -> Result<Scrubber> {
        Scrubber::new(&Secrets {
            policy: run.policy,
            fields: &run.fields,
            captured: &run.captured.secrets,
            rendered: &run.tainted,
        })
    }

    /// An HTTPS operation whose last response streams: the steps before its last send as
    /// usual, then that request, its head and its body as they arrive.
    fn streamed<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        request: Option<&Request>,
        transport: &mut T,
        live: &mut Live<'_>,
        updated: &mut Option<Record>,
    ) -> Result<Closed> {
        let operation = run.operation;
        let (now, who) = (run.now, run.who);
        let count = operation.steps.len();
        let (Some(Step::Send(last)), Some(Step::Return(ret))) = (
            count.checked_sub(2).and_then(|i| operation.steps.get(i)),
            operation.steps.last(),
        ) else {
            return Err(operation.unknown());
        };
        let projection = ret.response.as_ref();
        let mut pending: Option<(u64, u16)> = None;
        for step in operation.steps.iter().take(count - 2) {
            let result = match step {
                Step::Open(_) => Ok(()),
                Step::Send(send) => {
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), true);
                    }
                    self.https_send(run, open, send, request, transport, updated)
                        .map(|(seq, http)| {
                            run.log_seqs.push(seq);
                            pending = Some((seq, http.status));
                            run.last = Some(http);
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
                    stored.and(persisted)
                }
                Step::Compute(compute) => run.compute(compute, compute_vars(now)),
                Step::Run(step) => {
                    if let Some((seq, status)) = pending.take() {
                        self.done(now, who, seq, Some(status), true);
                    }
                    self.run_module(run, open, step, transport, updated)
                }
                Step::Return(_) | Step::Await(_) | Step::Repeat(_) | Step::If(_) => {
                    Err(operation.unknown())
                }
            };
            if let Err(error) = result {
                if let Some((seq, status)) = pending.take() {
                    self.done(now, who, seq, Some(status), false);
                }
                return Err(error);
            }
        }
        if let Some((seq, status)) = pending.take() {
            self.done(now, who, seq, Some(status), true);
        }
        run.last = None;

        let prepared = self.prepare(run, open, last, request, updated, Wire::Plain)?;
        let seq = prepared.seq;
        run.log_seqs.push(seq);
        let client = prepared.client;
        let opened = dispatch_streamed(
            prepared.confirmed,
            transport,
            prepared.destination,
            client.as_ref(),
            &prepared.wire,
            open.protocol.unwrap_or_default(),
        );
        drop(client);
        run.tainted.extend(prepared.tainted);
        let mut meter = Meter::new(open.limits.as_ref());
        let mut stream = match opened {
            Ok((_, stream)) => stream,
            Err(error) => return self.closed(run, seq, None, &meter, Err(("error", error))),
        };
        let mut status = None;
        let head = response::is_head_request(prepared.wire.expose());
        let end = self.stream_body(
            run,
            &mut *stream,
            projection,
            live,
            &mut meter,
            &mut status,
            head,
        );
        let _ = stream.close();
        let end = end.map_err(|error| (reason_of(&error), error));
        self.closed(run, seq, status, &meter, end)
    }

    /// Reads a streamed response: its head, then its body through the stream search.
    #[allow(clippy::too_many_arguments)]
    fn stream_body(
        &self,
        run: &mut Run<'_>,
        stream: &mut dyn Stream,
        projection: Option<&Projection>,
        live: &mut Live<'_>,
        meter: &mut Meter,
        status_out: &mut Option<u16>,
        head: bool,
    ) -> Result<End> {
        let mut buf = Zeroizing::new(Vec::new());
        let (status, headers, rest) = loop {
            match stream.read_some(READ, POLL)? {
                Arrived::Bytes(bytes) => {
                    meter.received(bytes.len());
                    buf.extend_from_slice(&bytes);
                }
                Arrived::Nothing => {}
                Arrived::End => {
                    return Err(Error::ResponseInvalid {
                        rule: "response ended in its head",
                    });
                }
            }
            meter.check()?;
            let mut found = None;
            while let Some(at) = find(&buf, b"\r\n\r\n") {
                let head = buf.get(..at).unwrap_or_default();
                let rest = Zeroizing::new(buf.get(at + 4..).unwrap_or_default().to_vec());
                match response::parse_head(head)? {
                    None => buf = rest,
                    Some((status, headers)) => {
                        found = Some((status, headers, rest));
                        break;
                    }
                }
            }
            if let Some(found) = found {
                break found;
            }
            if buf.len() > MAX_HEAD + 4 {
                return Err(Error::ResponseInvalid {
                    rule: "head missing or too long",
                });
            }
        };
        *status_out = Some(status);
        let mut decoder = BodyDecoder::new(response::framing(status, &headers, head)?);
        let mut scrubber = Self::scrubber(run)?;
        let head = {
            let secrets = Secrets {
                policy: run.policy,
                fields: &run.fields,
                captured: &run.captured.secrets,
                rendered: &run.tainted,
            };
            let head = response::project_head(status, headers, projection, run.log_seqs.clone());
            release_http(head, &secrets)?
        };
        live.relay.deliver(Part::Head(head))?;
        let mut pending = rest;
        loop {
            if !pending.is_empty() {
                let body = decoder.push(&pending)?;
                let released = scrubber.push(&body)?;
                if !released.is_empty() {
                    meter.delivered(released.len());
                    live.relay.deliver(Part::Body(released))?;
                }
                pending = Zeroizing::new(Vec::new());
            }
            if decoder.is_done() {
                break;
            }
            if let Some(reason) = meter.reached() {
                return Ok(End::of(reason, false));
            }
            // A node that handed over acts no more: its chain ended at the hand-over.
            self.alive()?;
            if self.is_handed_over() {
                return Ok(End::of("handed_over", false));
            }
            match live.relay.next(Duration::ZERO)? {
                Some(FromCaller::Close) => return Ok(End::of("caller", true)),
                Some(FromCaller::Frame(_)) => {
                    return Err(Error::FrameRefused {
                        rule: "a streamed response takes no frames",
                    });
                }
                None => {}
            }
            match stream.read_some(READ, POLL)? {
                Arrived::Bytes(bytes) => {
                    meter.received(bytes.len());
                    pending = Zeroizing::new(bytes);
                }
                Arrived::Nothing => {}
                Arrived::End => {
                    decoder.end()?;
                    break;
                }
            }
        }
        let tail = scrubber.finish();
        if !tail.is_empty() {
            meter.delivered(tail.len());
            live.relay.deliver(Part::Body(tail))?;
        }
        let trailers = response::project_trailers(decoder.take_trailers(), projection);
        let secrets = Secrets {
            policy: run.policy,
            fields: &run.fields,
            captured: &run.captured.secrets,
            rendered: &run.tainted,
        };
        for (name, value) in &trailers {
            let mut line = Zeroizing::new(name.as_bytes().to_vec());
            line.extend_from_slice(b": ");
            line.extend_from_slice(value);
            reflection::check(&line, &secrets)?;
        }
        Ok(End {
            reason: "server",
            ok: true,
            trailers,
        })
    }

    /// A WebSocket operation: the handshake, the steps, then the relay of frames.
    fn socket<T: Transport>(
        &self,
        run: &mut Run<'_>,
        open: &Open,
        request: Option<&Request>,
        transport: &mut T,
        live: &mut Live<'_>,
        updated: &mut Option<Record>,
    ) -> Result<Closed> {
        let operation = run.operation;
        let steps = &operation.steps;
        let Some((at, handshake)) = steps.iter().enumerate().find_map(|(i, s)| match s {
            Step::Send(send) => Some((i, send)),
            _ => None,
        }) else {
            return Err(operation.unknown());
        };
        for step in steps.iter().take(at) {
            match step {
                Step::Open(_) => {}
                Step::Compute(compute) => run.compute(compute, compute_vars(run.now))?,
                _ => return Err(operation.unknown()),
            }
        }
        let key = websocket::key();
        let prepared = self.prepare(run, open, handshake, request, updated, Wire::Upgrade(&key))?;
        let seq = prepared.seq;
        run.log_seqs.push(seq);
        let offered = memchr::memmem::find(
            &prepared.wire.expose().to_ascii_lowercase(),
            b"\r\nsec-websocket-protocol:",
        )
        .is_some();
        let host = prepared.destination.host.clone();
        let client = prepared.client;
        let opened = dispatch_streamed(
            prepared.confirmed,
            transport,
            prepared.destination,
            client.as_ref(),
            &prepared.wire,
            Versions::Http1,
        );
        drop(client);
        run.tainted.extend(prepared.tainted);
        let mut meter = Meter::new(open.limits.as_ref());
        let mut stream = match opened {
            Ok((_, stream)) => stream,
            Err(error) => return self.closed(run, seq, None, &meter, Err(("error", error))),
        };
        let mut status = None;
        let session = Session {
            key: &key,
            offered,
            host: &host,
            at,
        };
        let end = self.session(
            run,
            &mut *stream,
            &session,
            live,
            &mut meter,
            &mut status,
            updated,
        );
        let _ = stream.close();
        let end = end.map_err(|error| (reason_of(&error), error));
        self.closed(run, seq, status, &meter, end)
    }

    /// The handshake answer, the steps after it and the relay.
    #[allow(clippy::too_many_arguments)]
    fn session(
        &self,
        run: &mut Run<'_>,
        stream: &mut dyn Stream,
        session: &Session<'_>,
        live: &mut Live<'_>,
        meter: &mut Meter,
        status_out: &mut Option<u16>,
        updated: &mut Option<Record>,
    ) -> Result<End> {
        let operation = run.operation;
        let now = run.now;
        let head = Zeroizing::new(stream.read_until(&[b"\r\n\r\n"], MAX_HEAD + 4)?);
        meter.received(head.len());
        let (status, headers) = response::parse_upgrade(&head)?;
        *status_out = Some(status);
        check_upgrade(status, &headers, session.key, session.offered)?;
        let answer = Http {
            status,
            headers,
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let mut decoder = Decoder::new(MAX_MESSAGE);
        let mut rules: Option<&Rules> = None;
        for (i, step) in operation.steps.iter().enumerate().skip(session.at + 1) {
            match step {
                Step::Receive(receive) if i == session.at + 1 => {
                    for capture in &receive.capture {
                        let value = answer.capture(&capture.source)?;
                        run.captured
                            .store(run.policy, &mut run.fields, capture, value, now)?;
                    }
                }
                Step::Receive(receive) => {
                    let message = self.next_message(stream, &mut decoder, meter)?;
                    for capture in &receive.capture {
                        let value = response::capture_bytes(&message, &capture.source)?;
                        run.captured
                            .store(run.policy, &mut run.fields, capture, value, now)?;
                    }
                }
                Step::Send(send) => self.socket_send(run, send, session.host, stream, meter)?,
                Step::Compute(compute) => run.compute(compute, compute_vars(now))?,
                Step::Return(ret) => rules = ret.relay.as_ref(),
                _ => return Err(operation.unknown()),
            }
            meter.check()?;
        }
        self.persist(run, updated)?;
        let Some(rules) = rules else {
            let _ = stream.write(&websocket::encode(
                websocket::OP_CLOSE,
                &1000u16.to_be_bytes(),
            ));
            return Ok(End::of("steps", true));
        };
        let head = response::project_head(101, Vec::new(), None, run.log_seqs.clone());
        live.relay.deliver(Part::Head(head))?;
        self.relay_frames(run, stream, &mut decoder, rules, session.host, live, meter)
    }

    /// Renders a `send` of a WebSocket step and writes it as one message.
    fn socket_send(
        &self,
        run: &mut Run<'_>,
        send: &Send,
        host: &str,
        stream: &mut dyn Stream,
        meter: &mut Meter,
    ) -> Result<()> {
        let operation = run.operation;
        let (Some(kind), Some(text)) = (send.frame, send.template.as_deref()) else {
            return Err(operation.unknown());
        };
        let template = Template::parse(text)?;
        let ctx = Context {
            fields: &run.fields,
            temps: &run.captured.temps,
            vars: stream_vars(host, run.now),
            headers: &[],
            unix: run.now / 1000,
            budget: &run.budget,
        };
        let bytes = template.render(&ctx)?;
        if template.tainted(&|n| run.kinds.kind(n)) {
            run.tainted.push(bytes.clone());
        }
        write_message(stream, kind, &bytes, meter)
    }

    /// The next data message of the server, answering pings.
    fn next_message(
        &self,
        stream: &mut dyn Stream,
        decoder: &mut Decoder,
        meter: &mut Meter,
    ) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            while let Some(message) = decoder.message().map_err(ws_error)? {
                match message {
                    Message::Text(data) | Message::Binary(data) => return Ok(data),
                    Message::Ping(payload) => pong(stream, &payload, meter)?,
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        return Err(Error::transport(TransportKind::Closed, true));
                    }
                }
            }
            match stream.read_some(READ, POLL)? {
                Arrived::Bytes(bytes) => {
                    meter.received(bytes.len());
                    decoder.push(&bytes).map_err(ws_error)?;
                }
                Arrived::Nothing => {}
                Arrived::End => return Err(Error::transport(TransportKind::Closed, true)),
            }
            meter.check()?;
        }
    }

    /// Relays frames both ways until one side closes or a limit is reached.
    #[allow(clippy::too_many_arguments)]
    fn relay_frames(
        &self,
        run: &mut Run<'_>,
        stream: &mut dyn Stream,
        decoder: &mut Decoder,
        rules: &Rules,
        host: &str,
        live: &mut Live<'_>,
        meter: &mut Meter,
    ) -> Result<End> {
        let mut scrubber = Self::scrubber(run)?;
        let caller_key = run.policy.caller(&live.auth.caller)?.key;
        let mut expected = 0u64;
        loop {
            while let Some(message) = decoder.message().map_err(ws_error)? {
                match message {
                    Message::Ping(payload) => pong(stream, &payload, meter)?,
                    Message::Pong(_) => {}
                    Message::Close(_) => {
                        let _ = stream.write(&websocket::encode(
                            websocket::OP_CLOSE,
                            &1000u16.to_be_bytes(),
                        ));
                        return Ok(End::of("server", true));
                    }
                    Message::Text(data) | Message::Binary(data) if !rules.server => {
                        drop(data);
                    }
                    Message::Text(data) => {
                        scrubber.message(&data)?;
                        meter.delivered(data.len());
                        live.relay.deliver(Part::Text(data))?;
                    }
                    Message::Binary(data) => {
                        scrubber.message(&data)?;
                        meter.delivered(data.len());
                        live.relay.deliver(Part::Binary(data))?;
                    }
                }
            }
            if let Some(reason) = meter.reached() {
                // 1008: policy violation (a limit of the policy was reached).
                let _ = stream.write(&websocket::encode(
                    websocket::OP_CLOSE,
                    &1008u16.to_be_bytes(),
                ));
                return Ok(End::of(reason, false));
            }
            // A node that handed over acts no more: no frame of the caller is written after
            // its chain ended.
            self.alive()?;
            if self.is_handed_over() {
                let _ = stream.write(&websocket::encode(
                    websocket::OP_CLOSE,
                    &1001u16.to_be_bytes(),
                ));
                return Ok(End::of("handed_over", false));
            }
            match live.relay.next(Duration::ZERO)? {
                None => {}
                Some(FromCaller::Close) => {
                    let _ = stream.write(&websocket::encode(
                        websocket::OP_CLOSE,
                        &1000u16.to_be_bytes(),
                    ));
                    return Ok(End::of("caller", true));
                }
                Some(FromCaller::Frame(frame)) => {
                    if frame.seq != expected {
                        return Err(Error::FrameRefused {
                            rule: "frame out of sequence",
                        });
                    }
                    live.auth.verify_frame(
                        &caller_key,
                        frame.seq,
                        frame.kind == FrameKind::Binary,
                        &frame.data,
                        &frame.signature,
                    )?;
                    expected += 1;
                    // Checked again here: the hand-over may have happened while the caller's
                    // frame was awaited, and its template may read a secret.
                    self.alive()?;
                    if self.is_handed_over() {
                        let _ = stream.write(&websocket::encode(
                            websocket::OP_CLOSE,
                            &1001u16.to_be_bytes(),
                        ));
                        return Ok(End::of("handed_over", false));
                    }
                    let bytes = frame_bytes(run, rules, &frame, host, &mut scrubber)?;
                    write_message(stream, frame.kind, &bytes, meter)?;
                }
            }
            match stream.read_some(READ, POLL)? {
                Arrived::Bytes(bytes) => {
                    meter.received(bytes.len());
                    decoder.push(&bytes).map_err(ws_error)?;
                }
                Arrived::Nothing => {}
                Arrived::End => return Ok(End::of("server", false)),
            }
        }
    }
}

/// What a WebSocket session needs from its handshake.
struct Session<'a> {
    key: &'a str,
    offered: bool,
    host: &'a str,
    /// The index of the handshake send.
    at: usize,
}

pub(super) fn write_message(
    stream: &mut dyn Stream,
    kind: FrameKind,
    bytes: &[u8],
    meter: &mut Meter,
) -> Result<()> {
    let opcode = match kind {
        FrameKind::Text => {
            if core::str::from_utf8(bytes).is_err() {
                return Err(Error::FrameRefused {
                    rule: "a text frame that is not UTF-8",
                });
            }
            websocket::OP_TEXT
        }
        FrameKind::Binary => websocket::OP_BINARY,
    };
    let frame = websocket::encode(opcode, bytes);
    stream.write(&frame)?;
    meter.sent(frame.len(), bytes.len());
    Ok(())
}

pub(super) fn pong(stream: &mut dyn Stream, payload: &[u8], meter: &mut Meter) -> Result<()> {
    let frame = websocket::encode(websocket::OP_PONG, payload);
    stream.write(&frame)?;
    meter.received(0);
    meter.bytes = meter.bytes.saturating_add(frame.len() as u64);
    Ok(())
}

/// The bytes the node sends for a frame of the caller: the first rule of its kind whose shape
/// it matches, and that rule's template. A frame that matches no rule is refused.
pub(super) fn frame_bytes(
    run: &mut Run<'_>,
    rules: &Rules,
    frame: &CallerFrame,
    host: &str,
    scrubber: &mut Scrubber,
) -> Result<Zeroizing<Vec<u8>>> {
    if frame.data.len() > MAX_FRAME {
        return Err(Error::FrameRefused {
            rule: "a frame larger than 1 MiB",
        });
    }
    for rule in rules.frames.iter().filter(|r| r.kind == frame.kind) {
        let checked = match &rule.shape {
            None => Some(frame.data.clone()),
            Some(shape) => shape.apply(&frame.data, run.now).ok(),
        };
        let Some(checked) = checked else {
            continue;
        };
        let checked = Zeroizing::new(checked);
        let Some(text) = &rule.template else {
            return Ok(checked);
        };
        let template = Template::parse(text)?;
        let mut vars = stream_vars(host, run.now);
        vars.insert(Var::Input, checked.to_vec());
        let ctx = Context {
            fields: &run.fields,
            temps: &run.captured.temps,
            vars,
            headers: &[],
            unix: run.now / 1000,
            budget: &run.budget,
        };
        let bytes = template.render(&ctx)?;
        if template.tainted(&|n| run.kinds.kind(n)) {
            // What the server echoes of it is searched for too.
            scrubber.add(bytes.clone());
            run.tainted.push(bytes.clone());
        }
        return Ok(bytes);
    }
    Err(Error::FrameRefused {
        rule: "a frame of the caller matches no rule of the policy",
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn poisoned_counts_open_no_connection() {
        let slots = Slots::default();
        let open = Slot {
            slots: &slots,
            owner: "owner".into(),
            caller: "caller".into(),
        };
        slots.counts().unwrap().total = 1;
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let mut counts = slots.counts().unwrap();
            counts.total = 2;
            panic!("a panic part way through a count");
        }));
        assert!(poisoned.is_err());
        assert_eq!(slots.counts().err(), Some(Error::StateLost { sent: false }));
        // A connection that ends after it gives back nothing, and does not panic.
        drop(open);
        assert_eq!(slots.counts().err(), Some(Error::StateLost { sent: false }));
    }
}
