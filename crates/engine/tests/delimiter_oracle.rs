//! The delimiters of a caller's TLS exchanges are no oracle on a secret the server echoes:
//! a delimiter match that overlaps a secret is not taken, a reflection anywhere in a call
//! discards every read of it, and delimiters that touch no secret still end reads where
//! they match, with the bytes after them kept, in order, for the next read.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::time::Duration;

use engine::Error;
use engine::caller::Payload;
use engine::egress::{Arrived, ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Clock, Node, Outcome, StreamOutput};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy, Receive, Return, Send};
use engine::record::Record;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const SECRET: &[u8] = b"sk-test-not-a-real-secret-0123456789";
/// What the server writes just before it echoes the secret.
const PREFIX: &[u8] = b"VALUE=";

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(0) };
}

struct TestClock;

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        TIME.with(Cell::get)
    }
}

fn clock() -> TestClock {
    TIME.with(|t| t.set(NOW));
    TestClock
}

/// A server that answers each write with the chunks of its next reply. The connection reads
/// like a real one: `read_until` stops at the first delimiter that ends and keeps the rest,
/// `read_some` hands back what is pending first.
#[derive(Default)]
struct FakeServer {
    /// The chunks of the reply to each write, in order.
    replies: VecDeque<Vec<Vec<u8>>>,
    written: Vec<Vec<u8>>,
}

struct Connection<'a> {
    server: &'a mut FakeServer,
    incoming: VecDeque<Vec<u8>>,
    pending: Vec<u8>,
}

impl Transport for FakeServer {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        Ok(Box::new(Connection {
            server: self,
            incoming: VecDeque::new(),
            pending: Vec::new(),
        }))
    }
}

impl Stream for Connection<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.server.written.push(bytes.to_vec());
        if let Some(reply) = self.server.replies.pop_front() {
            self.incoming.extend(reply);
        }
        Ok(())
    }

    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> engine::Result<Vec<u8>> {
        loop {
            let end = delimiters
                .iter()
                .filter_map(|d| {
                    self.pending
                        .windows(d.len())
                        .position(|w| w == *d)
                        .map(|i| i + d.len())
                })
                .min();
            if let Some(end) = end {
                let rest = self.pending.split_off(end);
                return Ok(core::mem::replace(&mut self.pending, rest));
            }
            if self.pending.len() > max {
                return Err(Error::transport(TransportKind::TooLarge, true));
            }
            match self.incoming.pop_front() {
                Some(chunk) => self.pending.extend_from_slice(&chunk),
                None => return Err(Error::transport(TransportKind::Closed, true)),
            }
        }
    }

    fn read_some(&mut self, max: usize, _: Duration) -> engine::Result<Arrived> {
        if self.pending.is_empty() {
            match self.incoming.pop_front() {
                Some(chunk) => self.pending = chunk,
                None => return Ok(Arrived::End),
            }
        }
        let take = self.pending.len().min(max.max(1));
        let rest = self.pending.split_off(take);
        Ok(Arrived::Bytes(core::mem::replace(&mut self.pending, rest)))
    }
}

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

struct Setup<'c> {
    node: Node<MemorySink, &'c TestClock>,
    record: Record,
}

fn destination() -> Destination {
    Destination::new("echo.example.com", 993)
}

/// Logs in with the secret, then relays the caller's `ECHO` and `NOOP` lines.
fn policy() -> Policy {
    let operation = Operation::tls("call", destination())
        .then(Send::write("LOGIN {{key}}\r\n"))
        .then(Receive::until(["\r\n"]))
        .then(Return::relay(["(ECHO|NOOP)\\r\\n"]));
    let mut policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("key")],
        callers: vec![],
        operations: vec![operation],
    };
    policy.callers = vec![Caller::new(
        "app",
        caller_key().public(),
        ["call".to_string()],
    )];
    policy
}

fn setup(clock: &TestClock) -> Setup<'_> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(policy()).unwrap();
    let mut f = Fields::new();
    f.insert("key", SECRET.to_vec()).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        OWNER,
        signed,
        &f,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), clock);
    let terms = GrantTerms {
        owner: OWNER.into(),
        allow_successor: true,
        expires_ms: NOW + DAY,
        issued_ms: NOW,
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
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

fn call(s: &Setup<'_>, exchanges: &[CallerExchange], server: &mut FakeServer) -> StreamOutput {
    let destination = destination();
    let payload = Payload::Stream {
        destination: &destination,
        exchanges,
    };
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "call",
            &payload,
            NOW,
        )
        .unwrap();
    let outcome: Outcome<StreamOutput> =
        s.node
            .stream(&s.record, "call", &auth, &destination, exchanges, server);
    outcome.result.unwrap()
}

/// A server that greets the login, then echoes the secret after [`PREFIX`] for each `ECHO`,
/// in chunks of `chunk` bytes.
fn echo_server(echoes: usize, chunk: usize) -> FakeServer {
    let mut replies = VecDeque::from([vec![b"OK\r\n".to_vec()]]);
    for _ in 0..echoes {
        let mut reply = PREFIX.to_vec();
        reply.extend_from_slice(SECRET);
        reply.extend_from_slice(b"\r\nDONE\r\n");
        replies.push_back(reply.chunks(chunk).map(<[u8]>::to_vec).collect());
    }
    FakeServer {
        replies,
        written: Vec::new(),
    }
}

fn echo(until: Vec<Vec<u8>>) -> CallerExchange {
    CallerExchange {
        send: b"ECHO\r\n".to_vec(),
        until,
    }
}

/// The attack of the review: the caller knows the bytes before the secret and asks for reads
/// that end at the prefix and one of eight candidate bytes; a read that ends tells the next
/// byte. Returns how many bytes of the secret it learned, at most `want`.
fn attack(s: &Setup<'_>, want: usize, chunk: usize) -> usize {
    let mut known = PREFIX.to_vec();
    let mut learned = 0;
    'byte: while learned < want {
        for group in (0..=255u8).collect::<Vec<_>>().chunks(8) {
            let until: Vec<Vec<u8>> = group
                .iter()
                .map(|c| {
                    let mut d = known.clone();
                    d.push(*c);
                    d
                })
                .collect();
            let mut server = echo_server(1, chunk);
            let out = call(s, &[echo(until.clone())], &mut server);
            if let Some(read) = out.reads.first()
                && let Some(d) = until.iter().find(|d| read.ends_with(d))
            {
                known.push(*d.last().unwrap());
                learned += 1;
                continue 'byte;
            }
        }
        break;
    }
    learned
}

#[test]
fn caller_delimiters_tell_nothing_of_an_echoed_secret() {
    let clock = clock();
    let s = setup(&clock);
    // The whole reply in one chunk, and in pieces of a few bytes.
    for chunk in [4096, 3] {
        let learned = attack(&s, 3, chunk);
        assert_eq!(
            learned, 0,
            "the delimiters told {learned} bytes of the secret (chunks of {chunk})"
        );
    }
}

#[test]
fn a_delimiter_inside_an_echoed_secret_ends_no_read() {
    let clock = clock();
    let s = setup(&clock);
    // Bytes from the middle of the secret, and from its end with the line end after it.
    for until in [&SECRET[10..18], &SECRET[SECRET.len() - 3..]] {
        let mut server = echo_server(1, 5);
        let out = call(&s, &[echo(vec![until.to_vec()])], &mut server);
        assert!(out.reads.is_empty(), "a read ended inside the secret");
        assert_eq!(out.error, Some(Error::Reflection));
    }
}

#[test]
fn a_reflection_discards_every_read_of_the_call() {
    let clock = clock();
    let s = setup(&clock);
    // A clean read first, then one that ends just before the secret, then one that holds the
    // rest of it: the search over the reads finds it, and no read goes back.
    let mut server = echo_server(0, 4096);
    server.replies.push_back(vec![b"PONG\r\n".to_vec()]);
    let mut reply = PREFIX.to_vec();
    reply.extend_from_slice(SECRET);
    reply.extend_from_slice(b"\r\n");
    server.replies.push_back(vec![reply]);
    let exchanges = [
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
        echo(vec![PREFIX.to_vec()]),
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
    ];
    let out = call(&s, &exchanges, &mut server);
    assert_eq!(out.error, Some(Error::Reflection));
    assert!(
        out.reads.is_empty(),
        "{} reads went back with the reflection error",
        out.reads.len()
    );
}

#[test]
fn legitimate_delimiters_still_end_reads_and_keep_the_rest() {
    let clock = clock();
    let s = setup(&clock);
    let mut server = FakeServer {
        replies: VecDeque::from([
            vec![b"OK\r\n".to_vec()],
            // Two lines in one chunk: the second is the next read.
            vec![
                b"* 3 EXISTS\r\na2 OK SEL".to_vec(),
                b"ECT done\r\n".to_vec(),
            ],
            vec![],
            vec![],
            // A near miss of the secret after the delimiter: looked at, then taken.
            vec![b"VALUE=sk-test-not-a-real-secreX\r\n".to_vec()],
            vec![],
        ]),
        written: Vec::new(),
    };
    let exchanges = [
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"a2 OK".to_vec(), b"a2 NO".to_vec()],
        },
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
        echo(vec![b"VALUE=s".to_vec()]),
        CallerExchange {
            send: b"NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
    ];
    let out = call(&s, &exchanges, &mut server);
    assert_eq!(out.error, None);
    assert_eq!(
        out.reads,
        vec![
            b"* 3 EXISTS\r\n".to_vec(),
            b"a2 OK".to_vec(),
            b" SELECT done\r\n".to_vec(),
            b"VALUE=s".to_vec(),
            b"k-test-not-a-real-secreX\r\n".to_vec(),
        ]
    );
}
