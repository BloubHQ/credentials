//! The `dtls` connection: what a policy may say of it (sends that hold secrets, records with
//! no delimiter, no client certificate, pins that read), how a node bounds the caller's
//! records and searches every read, and what the summary and the diff of a policy say.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;

use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Clock, Node, Outcome, StreamOutput};
use engine::policy::{
    Caller, Capture, Destination, FieldSpec, Method, Operation, Policy, Receive, Return, Send,
    Source, Store, parse_pin,
};
use engine::record::Record;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const PIN: &str = "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SECRET: &[u8] = b"sk-test-not-a-real-secret-0123456789";

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

/// What the fake connection was asked to do.
#[derive(Default)]
struct FakeTransport {
    replies: VecDeque<Vec<u8>>,
    written: Vec<Vec<u8>>,
    /// The delimiters of each read.
    reads: Vec<usize>,
    datagrams: usize,
    /// The pins of each DTLS connection.
    dtls: Vec<Vec<[u8; 32]>>,
    intermediates: Vec<Vec<Vec<u8>>>,
}

impl Transport for FakeTransport {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    fn open_datagrams(&mut self, _: &Destination) -> engine::Result<Box<dyn Stream + '_>> {
        self.datagrams += 1;
        Ok(Box::new(FakeStream(self)))
    }

    fn open_dtls(
        &mut self,
        _: &Destination,
        pins: &[[u8; 32]],
        intermediates: &[Vec<u8>],
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.dtls.push(pins.to_vec());
        self.intermediates.push(intermediates.to_vec());
        Ok(Box::new(FakeStream(self)))
    }
}

struct FakeStream<'a>(&'a mut FakeTransport);

impl Stream for FakeStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.written.push(bytes.to_vec());
        Ok(())
    }

    fn read_until(&mut self, delimiters: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        self.0.reads.push(delimiters.len());
        self.0
            .replies
            .pop_front()
            .ok_or(Error::transport(TransportKind::Closed, false))
    }
}

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

fn with_caller(mut policy: Policy) -> Policy {
    policy.callers = vec![Caller::new(
        "app",
        caller_key().public(),
        policy.operations.iter().map(|o| o.name().to_string()),
    )];
    policy
}

fn policy(operations: Vec<Operation>) -> Policy {
    Policy {
        item: None,
        fields: vec![FieldSpec::secret("key"), FieldSpec::guessable("password")],
        callers: vec![],
        operations,
    }
}

fn sign(operations: Vec<Operation>) -> Result<(), Error> {
    DeviceKey::generate()
        .sign_policy(with_caller(policy(operations)))
        .map(|_| ())
}

fn refused(operations: Vec<Operation>) -> &'static str {
    match sign(operations) {
        Err(Error::PolicyInvalid { rule, .. }) => rule,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(()) => panic!("signed"),
    }
}

fn coap() -> Destination {
    Destination::new("coap.example.com", 5684)
}

fn dtls_op() -> Operation {
    Operation::dtls("call", coap())
        .pin(PIN)
        .then(Send::write("auth {{key}}"))
        .then(Receive::response().capture(Capture::new(
            Source::between("state=", ";"),
            Store::temp("state", false),
        )))
        .then(Send::write("{{password}} {{state}}"))
        .then(Receive::response())
        .then(Return::relay(["[a-z]{1,16}"]))
}

struct Setup<'c> {
    node: Node<MemorySink, &'c TestClock>,
    record: Record,
}

fn setup<'c>(clock: &'c TestClock, operations: Vec<Operation>) -> Setup<'c> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(with_caller(policy(operations))).unwrap();
    let mut f = Fields::new();
    f.insert("key", SECRET.to_vec()).unwrap();
    f.insert("password", b"hunter2".to_vec()).unwrap();
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

fn call_stream(
    s: &Setup<'_>,
    destination: &Destination,
    exchanges: &[CallerExchange],
    transport: &mut FakeTransport,
) -> Outcome<StreamOutput> {
    let payload = Payload::Stream {
        destination,
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
    s.node
        .stream(&s.record, "call", &auth, destination, exchanges, transport)
}

#[test]
fn a_pin_has_one_spelling() {
    assert_eq!(parse_pin(PIN), Some(core::array::from_fn(|i| i as u8)));
    for bad in [
        "",
        "sha256/",
        "sha1/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        // Unpadded, URL-safe, too short, too long, trailing bits set.
        "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-=",
        "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
        "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIQ==",
        "sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
        " sha256/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ] {
        assert_eq!(parse_pin(bad), None, "{bad}");
    }
}

#[test]
fn a_dtls_operation_signs_and_its_rules_hold() {
    // A DTLS record is encrypted to the checked server: it may hold a secret, a guessable
    // one too, as a TLS write may.
    assert!(sign(vec![dtls_op()]).is_ok());
    let plain = Operation::dtls("call", coap())
        .then(Send::write("{{key}}"))
        .then(Return::relay(["[a-z]+"]));
    assert!(sign(vec![plain]).is_ok());
    // A receive reads one record: no delimiters.
    let until = Operation::dtls("call", coap())
        .then(Send::write("ping"))
        .then(Receive::until(["\n"]))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(
        refused(vec![until]),
        "a DTLS receive reads one record; until is for TLS streams"
    );
    // No client certificate, HTTP version or stream limits.
    let identity = Operation::dtls("call", coap())
        .identity("{{key}}", "{{key}}")
        .then(Send::write("ping"))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(
        refused(vec![identity]),
        "a DTLS connection takes no identity, protocol or limits"
    );
    // A send is a template, nothing else.
    let empty = Operation::dtls("call", coap())
        .then(Send::fixed(Method::Get, "/"))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(refused(vec![empty]), "a DTLS send takes template only");
    // A return relays, it hands back no response or template.
    let returns = Operation::dtls("call", coap())
        .then(Send::write("ping"))
        .then(Return::output("{{key}}"));
    assert_eq!(
        refused(vec![returns]),
        "a TLS or UDP return takes relay only"
    );
    // tls_exporter has no value on DTLS here.
    let exporter = Operation::dtls("call", coap())
        .then(Send::write(
            r#"{{ hex(tls_exporter("EXPORTER-x", "", "32")) }}"#,
        ))
        .then(Return::relay(["[a-z]+"]));
    assert!(sign(vec![exporter]).is_err());
}

#[test]
fn pins_read_and_belong_to_dtls() {
    let pins = |pins: &[&str]| {
        let mut op = Operation::dtls("call", coap());
        for pin in pins {
            op = op.pin(pin);
        }
        op.then(Send::write("ping")).then(Return::relay(["[a-z]+"]))
    };
    assert!(sign(vec![pins(&[PIN])]).is_ok());
    assert_eq!(
        refused(vec![pins(&["sha256/not-base64"])]),
        "a pin is sha256/ and the base64 of 32 bytes, each once"
    );
    assert_eq!(
        refused(vec![pins(&[PIN, PIN])]),
        "a pin is sha256/ and the base64 of 32 bytes, each once"
    );
    let many: Vec<String> = (0..17u8)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[0] = i;
            let mut op_pin = String::from("sha256/");
            op_pin.push_str(&b64(&hash));
            op_pin
        })
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(refused(vec![pins(&many)]), "1 to 16 pins");
    assert!(sign(vec![pins(&many[..16])]).is_ok());
    // Another connection takes no pins.
    let tls = Operation::tls("call", coap())
        .pin(PIN)
        .then(Send::write("ping\n"))
        .then(Return::relay(["[a-z]+\n"]));
    assert_eq!(refused(vec![tls]), "pins are for a DTLS connection");
}

/// A DER `SEQUENCE` the policy check takes as an intermediate; the transport parses it.
const CA: &str = "MAMBAgM=";

#[test]
fn intermediates_read_and_belong_to_dtls() {
    let with = |certs: &[&str]| {
        let mut op = Operation::dtls("call", coap());
        for cert in certs {
            op = op.intermediate(cert);
        }
        op.then(Send::write("ping")).then(Return::relay(["[a-z]+"]))
    };
    let rule = "an intermediate is the base64 of a DER certificate of at most 8 KiB, each once";
    assert!(sign(vec![with(&[CA])]).is_ok());
    assert_eq!(refused(vec![with(&["not base64"])]), rule);
    assert_eq!(refused(vec![with(&[CA, CA])]), rule);
    // Not a DER SEQUENCE, not the one spelling, more than 8 KiB.
    assert_eq!(refused(vec![with(&["AQID"])]), rule);
    assert_eq!(refused(vec![with(&["MAMBAgM"])]), rule);
    let mut big = vec![0x30u8];
    big.resize(8 * 1024 + 1, 0);
    assert_eq!(refused(vec![with(&[&b64(&big)])]), rule);
    let mut most = vec![0x30u8];
    most.resize(8 * 1024, 0);
    assert!(sign(vec![with(&[&b64(&most)])]).is_ok());
    let nine: Vec<String> = (0..9u8).map(|i| b64(&[0x30, 1, i])).collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    assert_eq!(refused(vec![with(&nine)]), "1 to 8 intermediates");
    assert!(sign(vec![with(&nine[..8])]).is_ok());
    // Another connection takes none.
    let tls = Operation::tls("call", coap())
        .intermediate(CA)
        .then(Send::write("ping\n"))
        .then(Return::relay(["[a-z]+\n"]));
    assert_eq!(
        refused(vec![tls]),
        "intermediates are for a DTLS connection"
    );
}

#[test]
fn the_policys_intermediates_reach_the_transport() {
    let clock = clock();
    let op = Operation::dtls("call", coap())
        .pin(PIN)
        .intermediate(CA)
        .then(Send::write("ping"))
        .then(Return::relay(["[a-z]{1,16}"]));
    let s = setup(&clock, vec![op]);
    let mut transport = FakeTransport {
        replies: VecDeque::from([b"pong".to_vec()]),
        ..FakeTransport::default()
    };
    let exchanges = [CallerExchange {
        send: b"ping".to_vec(),
        until: vec![],
    }];
    let outcome = call_stream(&s, &coap(), &exchanges, &mut transport);
    assert!(outcome.result.is_ok(), "{:?}", outcome.result.err());
    assert_eq!(transport.dtls, vec![vec![parse_pin(PIN).unwrap()]]);
    assert_eq!(transport.intermediates, vec![vec![vec![0x30, 3, 1, 2, 3]]]);
}

#[test]
fn a_dtls_operation_exchanges_records_and_searches_every_read() {
    let clock = clock();
    let s = setup(&clock, vec![dtls_op()]);
    let destination = coap();
    let mut transport = FakeTransport {
        replies: VecDeque::from([
            b"state=abc;".to_vec(),
            b"accept".to_vec(),
            b"pong".to_vec(),
            // A server that answers with the secret.
            SECRET.to_vec(),
        ]),
        ..FakeTransport::default()
    };
    let exchanges = [
        CallerExchange {
            send: b"ping".to_vec(),
            until: vec![],
        },
        CallerExchange {
            send: b"echo".to_vec(),
            until: vec![],
        },
    ];
    let out = call_stream(&s, &destination, &exchanges, &mut transport)
        .result
        .unwrap();
    // One DTLS connection, with the policy's pin; no plain datagrams.
    assert_eq!(transport.datagrams, 0);
    assert_eq!(transport.dtls, vec![vec![parse_pin(PIN).unwrap()]]);
    // Two records of the policy (the first with the secret), then the caller's.
    assert_eq!(transport.written.len(), 4);
    assert!(
        transport.written[0].ends_with(SECRET),
        "the policy's record holds the secret"
    );
    assert_eq!(transport.written[1], b"hunter2 abc");
    assert!(transport.reads.iter().all(|n| *n == 0));
    // The echoed secret ends the exchanges, and no read of the call goes back.
    assert!(out.reads.is_empty());
    assert_eq!(out.error, Some(Error::Reflection));
}

#[test]
fn the_callers_records_have_a_size_and_no_delimiters() {
    let clock = clock();
    let s = setup(&clock, vec![dtls_op()]);
    let destination = coap();
    for exchange in [
        CallerExchange {
            send: b"ping".to_vec(),
            until: vec![b"\n".to_vec()],
        },
        CallerExchange {
            send: vec![b'a'; 16_385],
            until: vec![],
        },
        CallerExchange {
            send: Vec::new(),
            until: vec![],
        },
    ] {
        let mut transport = FakeTransport::default();
        let outcome = call_stream(&s, &destination, &[exchange], &mut transport);
        assert_eq!(
            outcome.result.err(),
            Some(Error::RequestInvalid {
                rule: "exchanges: at most 64 records of 1 to 16384 bytes, with no delimiters"
            })
        );
        assert!(
            transport.dtls.is_empty(),
            "refused before anything is opened"
        );
    }
    // 64 records of the most bytes pass the check; 65 do not.
    let most = vec![
        CallerExchange {
            send: b"a".repeat(16_384),
            until: vec![],
        };
        65
    ];
    let mut transport = FakeTransport::default();
    let outcome = call_stream(&s, &destination, &most, &mut transport);
    assert!(matches!(outcome.result, Err(Error::RequestInvalid { .. })));
    assert!(transport.dtls.is_empty());
}

#[test]
fn the_summary_and_the_diff_name_a_dtls_operation_and_its_pins() {
    let signed = DeviceKey::generate()
        .sign_policy(with_caller(policy(vec![dtls_op()])))
        .unwrap();
    let summary = engine::policy::summarize(&signed.policy, None);
    assert!(
        summary
            .lines
            .iter()
            .any(|l| l.contains("DTLS records over UDP")),
        "{:?}",
        summary.lines
    );
    assert!(
        !summary
            .flags
            .iter()
            .any(|f| f.code == engine::policy::summary::FlagCode::PlainDatagram)
    );
    // A new pin widens the policy; so does dropping every pin. Fewer pins do not.
    let other = "sha256/HyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4=";
    assert!(parse_pin(other).is_some());
    let with = |pins: &[&str]| {
        let mut op = Operation::dtls("call", coap());
        for pin in pins {
            op = op.pin(pin);
        }
        let op = op.then(Send::write("ping")).then(Return::relay(["[a-z]+"]));
        with_caller(policy(vec![op]))
    };
    let wider = |from: &[&str], to: &[&str]| {
        engine::policy::summarize(&with(to), Some(&with(from)))
            .flags
            .iter()
            .any(|f| f.code == engine::policy::summary::FlagCode::Wider && f.detail.contains("pin"))
    };
    assert!(wider(&[PIN], &[PIN, other]));
    assert!(wider(&[PIN], &[]));
    assert!(wider(&[PIN], &[other]));
    assert!(!wider(&[PIN, other], &[PIN]));
    assert!(!wider(&[PIN], &[PIN]));
}

/// Standard, padded base64 of 32 bytes.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
