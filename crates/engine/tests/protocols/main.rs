//! Protocol connections end to end through a node, against servers that run in the test
//! process: SSH, PostgreSQL, SMTP, IMAP and Redis. No network.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity,
    missing_docs
)]

mod amqp;
mod fake_mail;
mod fake_pg;
mod fake_ssh;
mod hostile;
mod mail;
mod mqtt;
mod mysql;
mod policy;
mod postgres;
mod redis;
mod ssh;
mod ssh_paths;

use std::collections::VecDeque;
use std::time::Duration;

use engine::call::{Body, Output, SignedCall};
use engine::caller::{CallerCommand, CallerMail};
use engine::egress::{Arrived, ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink};
use engine::node::{FromCaller, Node, Part, Relay, SessionOutput, SystemClock};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy};

pub type TestNode = Node<MemorySink, SystemClock>;

pub fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

pub struct Setup {
    pub node: TestNode,
    pub record: engine::record::Record,
}

pub fn operation(value: serde_json::Value) -> Operation {
    serde_json::from_value(value).unwrap()
}

/// A node holding a record with these fields and operations, granted and pinned.
pub fn setup(fields: &[(FieldSpec, &[u8])], operations: Vec<Operation>) -> Setup {
    let names = operations.iter().map(|o| o.name().to_string()).collect();
    let policy = Policy {
        item: None,
        fields: fields.iter().map(|(f, _)| f.clone()).collect(),
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: names,
            limit: None,
        }],
        operations,
    };
    policy.validate().unwrap();
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let mut values = Fields::new();
    for (spec, value) in fields {
        values.insert(&spec.name, value.to_vec()).unwrap();
    }
    let record = engine::record::Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        "user-1",
        device.sign_policy(policy).unwrap(),
        &values,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms {
        owner: "user-1".into(),
        expires_ms: engine::node::now_ms() + 3_600_000,
        issued_ms: engine::node::now_ms(),
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
        allow_successor: true,
    };
    let sealed = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            terms,
        )
        .unwrap();
    node.grant(&sealed).unwrap();
    Setup { node, record }
}

pub fn sign(s: &Setup, operation: &str, body: Body) -> SignedCall {
    caller_key()
        .sign_call(
            "app",
            &s.node.public_key(),
            s.record.clone(),
            operation,
            body,
        )
        .unwrap()
}

pub fn session(host: &str, port: u16, commands: Vec<CallerCommand>, mail: Vec<CallerMail>) -> Body {
    Body::Session {
        destination: Destination::new(host, port),
        commands,
        mail,
    }
}

pub fn command(name: &str, params: &[&str]) -> CallerCommand {
    CallerCommand {
        name: name.into(),
        params: params.iter().map(|p| p.to_string()).collect(),
    }
}

pub fn session_output(output: engine::Result<Output>) -> SessionOutput {
    match output {
        Ok(Output::Session(out)) => out,
        Ok(other) => panic!("not a session output: {other:?}"),
        Err(e) => panic!("failed: {e}"),
    }
}

pub fn events(s: &Setup) -> Vec<Event> {
    s.node.with_sink(|sink| {
        sink.entries()
            .iter()
            .map(|e| e.entry.event.clone())
            .collect()
    })
}

/// The last `closed` entry: whether it ended well and why.
pub fn last_closed(s: &Setup) -> (bool, String) {
    match events(s)
        .into_iter()
        .rev()
        .find(|e| matches!(e, Event::Closed { .. }))
    {
        Some(Event::Closed { ok, reason, .. }) => (ok, reason),
        _ => panic!("no closed entry"),
    }
}

/// A server that runs in the test: it reads what the node writes and answers.
pub trait Peer {
    /// Bytes the node wrote.
    fn feed(&mut self, bytes: &[u8]);
    /// Bytes for the node, taken.
    fn take(&mut self) -> Vec<u8>;
    /// True once the server closed the connection.
    fn closed(&self) -> bool;
}

/// A transport whose every connection goes to one in-process server.
pub struct Fake<P: Peer> {
    pub peer: P,
    /// What kind of connection the node asked for: `tls`, `plain` or `starttls`.
    pub opened: Vec<&'static str>,
    /// For STARTTLS: what the plain server answers before the upgrade, and what the node
    /// wrote in the clear.
    pub plain: VecDeque<Vec<u8>>,
    pub plain_written: Vec<u8>,
    /// Bytes the server sends in the clear after its go-ahead (an injection).
    pub plain_extra: Vec<u8>,
}

impl<P: Peer> Fake<P> {
    pub fn new(peer: P) -> Self {
        Self {
            peer,
            opened: Vec::new(),
            plain: VecDeque::new(),
            plain_written: Vec::new(),
            plain_extra: Vec::new(),
        }
    }
}

pub struct PeerStream<'a, P: Peer>(&'a mut P);

impl<P: Peer> Stream for PeerStream<'_, P> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.feed(bytes);
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        Err(engine::Error::transport(TransportKind::Unsupported, true))
    }

    fn read_some(&mut self, max: usize, _: Duration) -> engine::Result<Arrived> {
        let bytes = self.0.take();
        if bytes.is_empty() {
            return Ok(if self.0.closed() {
                Arrived::End
            } else {
                Arrived::Nothing
            });
        }
        let _ = max;
        Ok(Arrived::Bytes(bytes))
    }
}

/// The plain side of a STARTTLS connection: scripted answers, one per read.
struct PlainStream<'a> {
    answers: &'a mut VecDeque<Vec<u8>>,
    written: &'a mut Vec<u8>,
}

impl Stream for PlainStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.written.extend_from_slice(bytes);
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        Err(engine::Error::transport(TransportKind::Unsupported, true))
    }

    fn read_some(&mut self, _: usize, _: Duration) -> engine::Result<Arrived> {
        Ok(match self.answers.pop_front() {
            Some(bytes) => Arrived::Bytes(bytes),
            None => Arrived::Nothing,
        })
    }
}

impl<P: Peer> Transport for Fake<P> {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(engine::Error::transport(TransportKind::Unsupported, false))
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.opened.push("tls");
        Ok(Box::new(PeerStream(&mut self.peer)))
    }

    fn open_plain(&mut self, _: &Destination) -> engine::Result<Box<dyn Stream + '_>> {
        self.opened.push("plain");
        Ok(Box::new(PeerStream(&mut self.peer)))
    }

    fn open_starttls(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        prelude: &mut dyn FnMut(&mut dyn Stream) -> engine::Result<()>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.opened.push("starttls");
        // The server's injected bytes arrive with its go-ahead, in the same read.
        if let Some(last) = self.plain.back_mut() {
            last.extend_from_slice(&self.plain_extra);
        }
        let mut plain = PlainStream {
            answers: &mut self.plain,
            written: &mut self.plain_written,
        };
        prelude(&mut plain)?;
        Ok(Box::new(PeerStream(&mut self.peer)))
    }
}

/// The caller of a streaming call: what it was handed, and what it sends.
#[derive(Default)]
pub struct TestCaller {
    pub parts: Vec<Part>,
    pub sends: VecDeque<FromCaller>,
    pub close: bool,
}

impl Relay for TestCaller {
    fn deliver(&mut self, part: Part) -> engine::Result<()> {
        self.parts.push(part);
        Ok(())
    }

    fn next(&mut self, _: Duration) -> engine::Result<Option<FromCaller>> {
        match self.sends.pop_front() {
            Some(sent) => Ok(Some(sent)),
            None if self.close => Ok(Some(FromCaller::Close)),
            None => Ok(None),
        }
    }
}

impl TestCaller {
    pub fn output(&self) -> Vec<u8> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Binary(b) => Some(b.to_vec()),
                _ => None,
            })
            .flatten()
            .collect()
    }
}

/// True when `haystack` holds `needle`; for assertions that must not print either.
pub fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
