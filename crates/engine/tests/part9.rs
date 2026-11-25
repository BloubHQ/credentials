//! The families of part 9 (`docs/design.md` section 11): HPKE, TurboSHAKE and KangarooTwelve,
//! `tls_exporter`, and the `udp` connection. Each new function is held to the rules of the
//! analysis at signing (a length that depends on a secret is refused, rule 9; an algorithm the
//! caller picks, rule 6; a key the caller picks, rule 7; a key derived from a secret stays
//! secret, rule 8), and the UDP connection runs and is bounded like a TLS stream.
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
use engine::policy::Input;
use engine::policy::{
    Caller, Capture, Destination, FieldSpec, Operation, Policy, Receive, Return, Send, Source,
    Store,
};
use engine::record::Record;
use zeroize::Zeroizing;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const SUITE: &str = "x25519,sha256,aes128gcm";
/// The rule a tainted length breaks.
const LENGTH: &str = "a length must not depend on a secret";

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
    streams: usize,
    datagrams: usize,
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

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.streams += 1;
        Ok(Box::new(FakeStream(self)))
    }

    fn open_datagrams(&mut self, _: &Destination) -> engine::Result<Box<dyn Stream + '_>> {
        self.datagrams += 1;
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

    /// Keying material that shows what it was asked for: `length` bytes, each the length of
    /// the label.
    fn tls_exporter(
        &self,
        label: &[u8],
        _: &[u8],
        length: usize,
    ) -> engine::Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![
            u8::try_from(label.len()).unwrap();
            length
        ]))
    }
}

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

struct Setup<'c> {
    node: TestNode<'c>,
    record: Record,
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
        fields: vec![
            FieldSpec::secret("key"),
            FieldSpec::secret("psk"),
            FieldSpec::public("pk"),
        ],
        callers: vec![],
        operations,
    }
}

/// Signs a policy of `operations`; the error when it is refused.
fn sign(operations: Vec<Operation>) -> Result<(), Error> {
    DeviceKey::generate()
        .sign_policy(with_caller(policy(operations)))
        .map(|_| ())
}

/// The rule a refused policy breaks.
fn refused(operations: Vec<Operation>) -> &'static str {
    match sign(operations) {
        Err(Error::PolicyInvalid { rule, .. }) => rule,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(()) => panic!("signed"),
    }
}

fn derive(template: &str) -> Operation {
    Operation::local("derive")
        .input(Input::any())
        .then(Return::output(template))
}

fn tls_send(template: &str) -> Operation {
    Operation::tls("call", Destination::new("imap.example.com", 993))
        .then(Send::write(template))
        .then(Return::relay(["[A-Z]+\\r\\n"]))
}

fn radius() -> Destination {
    Destination::new("radius.example.com", 1812)
}

fn setup<'c>(clock: &'c TestClock, operations: Vec<Operation>) -> Setup<'c> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(with_caller(policy(operations))).unwrap();
    let mut f = Fields::new();
    f.insert("key", b"sk-test-not-a-real-secret-0123456789".to_vec())
        .unwrap();
    f.insert("psk", vec![0x42; 32]).unwrap();
    f.insert("pk", vec![9; 32]).unwrap();
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

fn call_derive(s: &Setup<'_>, input: &[u8]) -> engine::Result<Vec<u8>> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "derive",
            &Payload::Derive(input),
            NOW,
        )
        .unwrap();
    s.node.derive(&s.record, "derive", &auth, input)
}

#[test]
fn a_tainted_length_is_refused_in_every_new_function() {
    // Each new function with a length argument, with the length read from a secret field,
    // next to the same call with a fixed length, which signs (wrapped in an HMAC where the
    // output is a secret, so the derivation may hand it back).
    let cases: [(&str, String, String); 7] = [
        (
            "turboshake128",
            r#"{{ hex(turboshake128("m", "31", key)) }}"#.into(),
            r#"{{ hex(turboshake128("m", "31", "32")) }}"#.into(),
        ),
        (
            "turboshake256",
            r#"{{ hex(turboshake256("m", "31", key)) }}"#.into(),
            r#"{{ hex(turboshake256("m", "31", "64")) }}"#.into(),
        ),
        (
            "kt128",
            r#"{{ hex(kt128("m", "", key)) }}"#.into(),
            r#"{{ hex(kt128("m", "", "32")) }}"#.into(),
        ),
        (
            "kt256",
            r#"{{ hex(kt256("m", "", key)) }}"#.into(),
            r#"{{ hex(kt256("m", "", "64")) }}"#.into(),
        ),
        (
            "hpke_export",
            format!(
                r#"{{{{ hex(hmac_sha256(hpke_export("{SUITE}", "base", pk, "", "", key), "x")) }}}}"#
            ),
            format!(
                r#"{{{{ hex(hmac_sha256(hpke_export("{SUITE}", "base", pk, "", "", "32"), "x")) }}}}"#
            ),
        ),
        (
            "hpke_receiver_export",
            format!(
                r#"{{{{ hex(hmac_sha256(hpke_receiver_export("{SUITE}", "base", key, pk, "", "", key), "x")) }}}}"#
            ),
            format!(
                r#"{{{{ hex(hmac_sha256(hpke_receiver_export("{SUITE}", "base", key, pk, "", "", "32"), "x")) }}}}"#
            ),
        ),
        (
            "tls_exporter",
            r#"{{ hex(tls_exporter("EXPORTER-Channel-Binding", "", key)) }}"#.into(),
            r#"{{ hex(tls_exporter("EXPORTER-Channel-Binding", "", "32")) }}"#.into(),
        ),
    ];
    for (name, tainted, fixed) in cases {
        let op = |t: &str| {
            if name == "tls_exporter" {
                tls_send(t)
            } else {
                derive(t)
            }
        };
        let rule = refused(vec![op(&tainted)]);
        println!("{name} with a secret length -> {rule}");
        assert_eq!(rule, LENGTH, "{name}");
        assert!(sign(vec![op(&fixed)]).is_ok(), "{name} with a fixed length");
    }
}

#[test]
fn hpke_algorithms_and_keys_are_fixed_by_the_policy() {
    // The suite, the mode and the domain byte are the policy's (rule 6).
    for template in [
        r#"{{ hex(hpke_seal($input, "base", pk, "", "", "hello")) }}"#,
        r#"{{ hex(hpke_seal("x25519,sha256,aes128gcm", $input, pk, "", "", "hello")) }}"#,
        r#"{{ hex(turboshake128("m", $input, "32")) }}"#,
        r#"{{ hex(hpke_public($input, pk)) }}"#,
    ] {
        assert_eq!(
            refused(vec![derive(template)]),
            "a hash or curve name must be fixed by the policy",
            "{template}"
        );
    }
    // The recipient key, the PSK, its id and the sender key are not the caller's (rule 7).
    for template in [
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "base", hexdecode($input), "", "", key)) }}}}"#),
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "psk", pk, "", "", key, $input, "id")) }}}}"#),
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "psk", pk, "", "", key, psk, $input)) }}}}"#),
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "auth", pk, "", "", "m", $input)) }}}}"#),
        format!(
            r#"{{{{ hex(hmac_sha256(hpke_open("{SUITE}", "auth", key, pk, "", "", pk, $input), "x")) }}}}"#
        ),
    ] {
        assert_eq!(
            refused(vec![derive(&template)]),
            "an encryption key must come from the policy or the destination, not the caller",
            "{template}"
        );
    }
    // Whether opening fails tells whether a chosen info matches: no secret mixed into it.
    let mixed = format!(
        r#"{{{{ hex(hmac_sha256(hpke_open("{SUITE}", "base", key, pk, key + $input, "", pk), "x")) }}}}"#
    );
    assert_eq!(
        refused(vec![derive(&mixed)]),
        "a secret mixed with a chosen value reaches a decoder, number or key"
    );
}

#[test]
fn hpke_outputs_that_hold_a_secret_stay_tainted() {
    // An encryption of a secret, a decryption, an exported secret and a key derived from a
    // secret cannot be handed back by a derivation (rules 5 and 8).
    for template in [
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "base", pk, "", "", key)) }}}}"#),
        format!(r#"{{{{ hex(hpke_open("{SUITE}", "base", psk, pk, "", "", pk)) }}}}"#),
        format!(r#"{{{{ hex(hpke_export("{SUITE}", "base", pk, "", "", "32")) }}}}"#),
        r#"{{ hex(hpke_derive_key("x25519", key)) }}"#.to_string(),
        // A plain hash of nothing but a secret stays a secret (rule 3).
        r#"{{ hex(kt128(key, "", "32")) }}"#.to_string(),
        r#"{{ hex(turboshake256(key, "31", "32")) }}"#.to_string(),
    ] {
        assert!(sign(vec![derive(&template)]).is_err(), "{template}");
    }
    // A secret sealed under a PSK that is a secret key, with public bytes only, is not a
    // secret to whoever reads the ciphertext without the key; the public key of a derived
    // key is public.
    for template in [
        format!(r#"{{{{ hex(hpke_seal("{SUITE}", "psk", pk, "", "", "hello", psk, "id")) }}}}"#),
        r#"{{ hex(hpke_public("x25519", hpke_derive_key("x25519", key))) }}"#.to_string(),
        r#"{{ hex(kt128(key + $input, "", "32")) }}"#.to_string(),
    ] {
        assert!(sign(vec![derive(&template)]).is_ok(), "{template}");
    }
}

#[test]
fn hpke_and_kangarootwelve_run_in_a_derivation() {
    let clock = clock();
    let template = r#"{{ hex(hpke_public("x25519", hpke_derive_key("x25519", key))) }}:{{ hex(kt128($input, "c", "16")) }}"#;
    let s = setup(&clock, vec![derive(template)]);
    let out = String::from_utf8(call_derive(&s, b"abc").unwrap()).unwrap();
    let (public, hash) = out.split_once(':').unwrap();
    assert_eq!(public.len(), 64);
    assert_eq!(hash.len(), 32);
    // The same input gives the same key.
    let again = String::from_utf8(call_derive(&s, b"abc").unwrap()).unwrap();
    assert_eq!(again, out);
}

#[test]
fn tls_exporter_is_only_in_a_tls_send() {
    let exporter = r#"{{ hex(tls_exporter("EXPORTER-Channel-Binding", "", "32")) }}"#;
    let only_there = "tls_exporter is available only in the send of a TLS connection";
    assert_eq!(refused(vec![derive(exporter)]), only_there);
    let compute = Operation::tls("call", Destination::new("imap.example.com", 993))
        .compute("cb", exporter)
        .then(Send::write("{{cb}}\r\n"))
        .then(Return::relay(["[A-Z]+\\r\\n"]));
    assert_eq!(refused(vec![compute]), only_there);
    let udp = Operation::udp("call", radius())
        .then(Send::write(exporter))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(refused(vec![udp]), only_there);
    // In the send of a TLS connection, after its handshake, it signs.
    assert!(sign(vec![tls_send(exporter)]).is_ok());
}

#[test]
fn tls_exporter_is_rendered_on_the_connection() {
    let clock = clock();
    let op = tls_send(r#"a1 AUTH {{ hex(tls_exporter("EXPORTER-Channel-Binding", "", "4")) }}"#);
    let s = setup(&clock, vec![op]);
    let mut transport = FakeTransport::default();
    let destination = Destination::new("imap.example.com", 993);
    let out = call_stream(&s, &destination, &[], &mut transport);
    assert!(out.result.unwrap().error.is_none());
    // Four bytes, each the length of the label (24).
    assert_eq!(transport.written, vec![b"a1 AUTH 18181818".to_vec()]);
}

fn udp_op() -> Operation {
    Operation::udp("call", radius())
        .then(Send::write(r#"{{ hex(hmac_md5(key, "access-request")) }}"#))
        .then(Receive::response().capture(Capture::new(
            Source::between("state=", ";"),
            Store::temp("state", false),
        )))
        .then(Send::write(r#"{{ hex(hmac_sha256(key, state)) }}"#))
        .then(Receive::response())
        .then(Return::relay(["[a-z]{1,16}"]))
}

#[test]
fn a_udp_datagram_holds_no_secret_in_reversible_form() {
    let rule = "a UDP datagram is sent in clear: it may not hold a secret in reversible form";
    for template in [
        "{{key}}",
        "{{ b64(key) }}",
        r#"{{ hex(aes_gcm_encrypt(psk, "0123456789ab", key)) }}"#,
        r#"{{ hex(hpke_seal("x25519,sha256,aes128gcm", "base", pk, "", "", key)) }}"#,
    ] {
        let op = Operation::udp("call", radius())
            .then(Send::write(template))
            .then(Return::relay(["[a-z]+"]));
        assert_eq!(refused(vec![op]), rule, "{template}");
    }
    assert!(sign(vec![udp_op()]).is_ok());
    // A MAC of a guessable secret lets whoever reads the datagram test guesses offline.
    let mut guessable = policy(vec![
        Operation::udp("call", radius())
            .then(Send::write(r#"{{ hex(hmac_md5(password, "m")) }}"#))
            .then(Return::relay(["[a-z]+"])),
    ]);
    guessable.fields.push(FieldSpec::guessable("password"));
    match DeviceKey::generate().sign_policy(with_caller(guessable)) {
        Err(Error::PolicyInvalid { rule, .. }) => assert_eq!(
            rule,
            "a UDP datagram is sent in clear: it may not depend on a guessable secret"
        ),
        _ => panic!("a guessable secret went into a datagram"),
    }
    // A receive reads one datagram: no delimiters.
    let until = Operation::udp("call", radius())
        .then(Send::write("ping"))
        .then(Receive::until(["\n"]))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(
        refused(vec![until]),
        "a UDP receive reads one datagram; until is for TLS streams"
    );
    // No client certificate, HTTP version or stream limits on UDP.
    let identity = Operation::udp("call", radius())
        .identity("{{pk}}", "{{key}}")
        .then(Send::write("ping"))
        .then(Return::relay(["[a-z]+"]));
    assert_eq!(
        refused(vec![identity]),
        "a UDP connection takes no identity, protocol or limits"
    );
}

#[test]
fn a_udp_operation_exchanges_datagrams_and_searches_every_read() {
    let clock = clock();
    let s = setup(&clock, vec![udp_op()]);
    let destination = radius();
    let mut transport = FakeTransport {
        replies: VecDeque::from([
            b"state=abc;".to_vec(),
            b"accept".to_vec(),
            b"pong".to_vec(),
            // A server that answers with the secret.
            b"sk-test-not-a-real-secret-0123456789".to_vec(),
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
    assert_eq!((transport.datagrams, transport.streams), (1, 0));
    // Two datagrams of the policy, then the caller's; every read with no delimiter.
    assert_eq!(transport.written.len(), 4);
    assert!(transport.reads.iter().all(|n| *n == 0));
    let secret: &[u8] = b"sk-test-not-a-real-secret-0123456789";
    assert!(
        !transport
            .written
            .iter()
            .any(|w| w.windows(secret.len()).any(|x| x == secret)),
        "a datagram held the secret"
    );
    assert_eq!(out.reads, vec![b"pong".to_vec()]);
    assert!(out.error.is_some(), "the echoed secret ends the exchanges");

    // Delimiters do not apply to datagrams, and a datagram has a size.
    for exchange in [
        CallerExchange {
            send: b"ping".to_vec(),
            until: vec![b"\n".to_vec()],
        },
        CallerExchange {
            send: vec![b'a'; 65_508],
            until: vec![],
        },
    ] {
        let mut transport = FakeTransport::default();
        let outcome = call_stream(&s, &destination, &[exchange], &mut transport);
        assert!(matches!(outcome.result, Err(Error::RequestInvalid { .. })));
        assert_eq!(transport.datagrams, 0, "refused before anything is sent");
    }
}

#[test]
fn the_summary_flags_a_udp_operation() {
    let signed = DeviceKey::generate()
        .sign_policy(with_caller(policy(vec![udp_op()])))
        .unwrap();
    let summary = engine::policy::summarize(&signed.policy, None);
    assert!(
        summary
            .flags
            .iter()
            .any(|f| f.code == engine::policy::summary::FlagCode::PlainDatagram)
    );
    assert!(summary.lines.iter().any(|l| l.contains("UDP datagrams")));
}

#[test]
fn the_new_signatures_are_one_way_with_fixed_algorithms() {
    // A signature hides its key: a derivation may hand it back.
    for template in [
        r#"{{ hex(mldsa_sign("65", psk, $input)) }}"#,
        r#"{{ hex(mldsa_sign("44", psk, $input, "ctx")) }}"#,
        r#"{{ hex(mldsa_public("87", psk)) }}"#,
        r#"{{ hex(sm2_sign(psk, $input)) }}"#,
        r#"{{ hex(ecdsa_sign_prehash("bp256", psk, sha256($input))) }}"#,
    ] {
        assert!(sign(vec![derive(template)]).is_ok(), "{template}");
    }
    // The parameter set is the policy's (rule 6); a key mixed with a chosen value is refused.
    assert_eq!(
        refused(vec![derive(r#"{{ hex(mldsa_sign($input, psk, "m")) }}"#)]),
        "a hash or curve name must be fixed by the policy"
    );
    assert_eq!(
        refused(vec![derive(r#"{{ hex(sm2_sign(psk + $input, "m")) }}"#)]),
        "a secret mixed with a chosen value reaches a decoder, number or key"
    );
    assert_eq!(
        refused(vec![derive(
            r#"{{ hex(mldsa_public("44", psk + $input)) }}"#
        )]),
        "a secret mixed with a chosen value reaches a decoder, number or key"
    );
}
