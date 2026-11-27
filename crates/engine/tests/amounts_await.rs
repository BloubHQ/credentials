//! Payment amounts read from a body contract, and `await` on TLS before the connection opens.
//!
//! - The amount the spending limits count and the approval shows is the amount on the wire:
//!   the node checks the body, writes it again and reads the amount from what it sends, by
//!   the parser that wrote it. Duplicate keys, other spellings of a number, big numbers, a
//!   currency the payment does not name and a second amount hidden in the body are refused
//!   before anything is sent.
//! - A TLS operation waits for a code only before its connection opens: nothing is logged,
//!   rendered or sent, and no connection is held while it waits; only its caller resumes it,
//!   and a restart drops it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use engine::Error;
use engine::approval::{Amount, ApprovalSummary};
use engine::call::{Body, Output, SignedCall};
use engine::egress::{Arrived, ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::limits::LimitRule;
use engine::log::{Event, MemorySink};
use engine::node::{CallerExchange, Clock, Node, StreamOutput};
use engine::policy::summary::FlagCode;
use engine::policy::{
    AmountFormat, AmountSource, BodyContract, Caller, CallerRequest, Challenge, ChallengeKind,
    Destination, FieldSpec, FormBody, Injection, JsonInput, JsonType, Member, Method, Operation,
    Payment, Policy, QueryRule, Receive, Return, Send, summarize,
};
use engine::record::Record;
use engine::request::Request;
use engine::session::Pending;

/// 2026-11-25T00:00:00Z.
const NOW: u64 = 1_795_564_800_000;
const USER: [u8; 32] = [7; 32];
/// The one-time code of the tests (a test value, never printed).
const CODE: &str = "493817";
const PASSWORD: &str = "correct horse battery";

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A site: HTTP requests answered `200 {}` and kept; TLS connections counted, their writes
/// kept, each write answered with the next line.
#[derive(Default)]
struct Site {
    sent: Vec<Vec<u8>>,
    opens: usize,
    written: Vec<Vec<u8>>,
    lines: VecDeque<Vec<u8>>,
}

struct Connection<'a> {
    site: &'a mut Site,
    pending: Vec<u8>,
}

impl Transport for Site {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec())
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.opens += 1;
        Ok(Box::new(Connection {
            site: self,
            pending: Vec::new(),
        }))
    }

    fn open_datagrams(&mut self, _: &Destination) -> engine::Result<Box<dyn Stream + '_>> {
        self.opens += 1;
        Ok(Box::new(Connection {
            site: self,
            pending: Vec::new(),
        }))
    }
}

impl Stream for Connection<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.site.written.push(bytes.to_vec());
        if let Some(line) = self.site.lines.pop_front() {
            self.pending.extend(line);
        }
        Ok(())
    }

    fn read_until(&mut self, delimiters: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        // A datagram: everything that came, at once.
        if delimiters.is_empty() && !self.pending.is_empty() {
            return Ok(core::mem::take(&mut self.pending));
        }
        let end = delimiters
            .iter()
            .filter_map(|d| {
                self.pending
                    .windows(d.len())
                    .position(|w| w == *d)
                    .map(|i| i + d.len())
            })
            .min()
            .ok_or_else(|| Error::transport(TransportKind::Closed, true))?;
        let rest = self.pending.split_off(end);
        Ok(core::mem::replace(&mut self.pending, rest))
    }

    fn read_some(&mut self, max: usize, _: Duration) -> engine::Result<Arrived> {
        if self.pending.is_empty() {
            return Ok(Arrived::End);
        }
        let take = self.pending.len().min(max.max(1));
        let rest = self.pending.split_off(take);
        Ok(Arrived::Bytes(core::mem::replace(&mut self.pending, rest)))
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The body of an HTTP request as it went on the wire.
fn body_of(wire: &[u8]) -> &[u8] {
    let at = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    &wire[at + 4..]
}

struct World {
    node: Node<MemorySink, SharedClock>,
    node_key: [u8; 32],
    clock: Arc<AtomicU64>,
    device: DeviceKey,
    agent: CallerKey,
    other: CallerKey,
    record: Record,
}

fn user() -> UserKey {
    UserKey::from_bytes(&mut USER.clone())
}

fn world(policy: impl Fn(&CallerKey, &CallerKey) -> Policy, values: &[(&str, &str)]) -> World {
    let clock = Arc::new(AtomicU64::new(NOW));
    let device = DeviceKey::generate();
    let agent = CallerKey::generate();
    let other = CallerKey::generate();
    let mut fields = Fields::new();
    for (name, value) in values {
        fields.insert(name, value.as_bytes().to_vec()).unwrap();
    }
    let signed = device.sign_policy(policy(&agent, &other)).unwrap();
    let record = Record::seal(&user(), "item", "alice", signed, &fields).unwrap();
    let node_key = NodeKey::generate();
    let bytes = *node_key.to_bytes();
    let node = Node::new(node_key, MemorySink::new(), SharedClock(clock.clone()));
    let world = World {
        node,
        node_key: bytes,
        clock,
        device,
        agent,
        other,
        record,
    };
    world.grant();
    world
}

impl World {
    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn grant(&self) {
        let terms = GrantTerms::at("alice", self.now(), Duration::from_secs(10 * 24 * 3600))
            .pin(&self.record);
        self.node
            .grant(
                &self
                    .device
                    .grant(&user(), &self.node.identity(), terms)
                    .unwrap(),
            )
            .unwrap();
    }

    fn call_as(&self, key: &CallerKey, name: &str, op: &str, body: Body) -> SignedCall {
        key.sign_call_at(
            name,
            &self.node.public_key(),
            self.record.clone(),
            op,
            body,
            self.now(),
        )
        .unwrap()
    }

    fn run(&self, op: &str, body: Body, site: &mut Site) -> engine::Result<Output> {
        let call = self.call_as(&self.agent, "agent", op, body);
        self.node.run(&call, site).result
    }

    fn resume(&self, op: &str, id: [u8; 16], site: &mut Site) -> engine::Result<Output> {
        self.run(op, Body::resume(id), site)
    }

    fn set_limits(&self, rules: Vec<LimitRule>) {
        self.advance(1);
        let limits = self
            .device
            .sign_limits(&self.node.public_key(), "alice", "item", rules, self.now())
            .unwrap();
        self.node.set_limits(&limits).unwrap();
    }

    fn spends(&self) -> usize {
        self.node.with_sink(|sink| {
            sink.entries()
                .iter()
                .filter(|e| matches!(e.entry.event, Event::Spend { .. }))
                .count()
        })
    }

    fn log(&self) -> Vec<u8> {
        let entries = self.node.with_sink(|sink| sink.entries().to_vec());
        serde_json::to_vec(&entries).unwrap()
    }
}

fn approval_of(output: engine::Result<Output>) -> ApprovalSummary {
    match output {
        Ok(Output::Pending(Pending::ApprovalRequired { summary, .. })) => *summary,
        other => panic!("not an approval: {:?}", other.map(|_| ()).err()),
    }
}

fn challenge_of(output: engine::Result<Output>) -> [u8; 16] {
    match output {
        Ok(Output::Pending(Pending::Challenge { id, .. })) => id,
        other => panic!("not a challenge: {:?}", other.map(|_| ()).err()),
    }
}

fn sent_ok(output: engine::Result<Output>) {
    match output {
        Ok(Output::Http(response)) => assert_eq!(response.status(), 200),
        other => panic!("not a response: {:?}", other.map(|_| ()).err()),
    }
}

fn refused(output: engine::Result<Output>) -> &'static str {
    match output {
        Err(Error::RequestInvalid { rule }) => rule,
        other => panic!("not refused: {:?}", other.map(|_| ()).err()),
    }
}

fn eur(per_payment: Option<&str>, per_day: Option<&str>) -> LimitRule {
    LimitRule {
        currency: "EUR".into(),
        merchant: None,
        per_payment: per_payment.map(Into::into),
        per_day: per_day.map(Into::into),
        per_month: None,
    }
}

fn amount(value: &str) -> Option<Amount> {
    Some(Amount {
        value: value.into(),
        currency: "EUR".into(),
    })
}

// --- Amounts from a JSON body ------------------------------------------------------------------

fn json_body(amount: Member) -> BodyContract {
    BodyContract::Json(JsonInput {
        members: vec![
            amount,
            Member::equals("/currency", "EUR"),
            Member::any("/description").of(JsonType::String).optional(),
        ],
    })
}

fn minor_number() -> Member {
    Member::any("/amount")
        .of(JsonType::Number)
        .between(Some("0"), Some("100000000"))
}

fn paying(body: BodyContract, amount: AmountSource) -> impl Fn(&CallerKey, &CallerKey) -> Policy {
    move |agent, other| {
        let contract = CallerRequest::new([Method::Post])
            .paths(["/v1/charges"])
            .body(body.clone());
        Policy::new()
            .with_field(FieldSpec::secret("key"))
            .with_operation(
                Operation::https("charge", Destination::https("pay.example"))
                    .then(
                        Send::caller(contract)
                            .inject(Injection::header("Authorization", "Bearer {{key}}")),
                    )
                    .then(Return::status())
                    .pays(Payment {
                        amount: amount.clone(),
                        currency: "EUR".into(),
                        exponent: 2,
                    }),
            )
            .with_caller(Caller::new("agent", agent.public(), ["charge"]))
            .with_caller(Caller::new("other", other.public(), ["charge"]))
    }
}

fn from_body(pointer: &str) -> AmountSource {
    AmountSource::Body {
        pointer: pointer.into(),
        format: AmountFormat::Minor,
        currency_at: None,
    }
}

fn json_world() -> World {
    world(
        paying(json_body(minor_number()), from_body("/amount")),
        &[("key", "sk-0123456789abcdef")],
    )
}

fn charge(body: &str) -> Body {
    Body::http(Request {
        method: Method::Post,
        destination: Destination::https("pay.example"),
        path: "/v1/charges".into(),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    })
}

/// The amount a server reads from the body on the wire, by a parser other than the node's.
fn wire_amount(wire: &[u8]) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_slice(body_of(wire)).unwrap();
    value["amount"].clone()
}

#[test]
fn the_amount_counted_and_shown_is_the_amount_sent() {
    let w = json_world();
    let mut site = Site::default();
    // No limit: the owner is asked, with the amount the body carries.
    let summary = approval_of(w.run(
        "charge",
        charge(r#" { "amount" : 1234 , "currency":"EUR", "description":"a b" } "#),
        &mut site,
    ));
    assert_eq!(summary.amount, amount("12.34"));
    assert_eq!(summary.delegate, None, "the owner's own caller");
    assert!(site.sent.is_empty(), "nothing is sent before the approval");
    w.node
        .approve(&w.device.approve(&summary, w.now()).unwrap())
        .unwrap();
    sent_ok(w.resume("charge", summary.id, &mut site));
    let wire = &site.sent[0];
    // The node sent the body it checked, written again, with the content type it names.
    assert_eq!(
        body_of(wire),
        br#"{"amount":1234,"currency":"EUR","description":"a b"}"#
    );
    assert!(contains(wire, b"Content-Type: application/json\r\n"));
    assert_eq!(wire_amount(wire), serde_json::json!(1234));
    assert_eq!(w.spends(), 1);

    // Within a limit: counted at once, and exactly the amount sent (a day later, so the
    // approved payment is out of the window).
    w.advance(24 * 60 * 60 * 1000);
    w.set_limits(vec![eur(Some("20"), Some("30"))]);
    sent_ok(w.run(
        "charge",
        charge(r#"{"amount":2000,"currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(wire_amount(&site.sent[1]), serde_json::json!(2000));
    // 20.00 counted: 10.01 more the same day is above 30, by one cent.
    let over = approval_of(w.run(
        "charge",
        charge(r#"{"amount":1001,"currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(over.amount, amount("10.01"));
    sent_ok(w.run(
        "charge",
        charge(r#"{"amount":1000,"currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(wire_amount(&site.sent[2]), serde_json::json!(1000));
    // 20.01 in one payment is above the per-payment limit, whatever the day allows.
    w.advance(24 * 60 * 60 * 1000);
    let big = approval_of(w.run(
        "charge",
        charge(r#"{"amount":2001,"currency":"EUR"}"#),
        &mut site,
    ));
    assert!(big.lines.iter().any(|l| l.contains("per payment")));
    assert_eq!(site.sent.len(), 3);
    assert_eq!(w.spends(), 3);
}

#[test]
fn duplicate_keys_never_reach_the_site() {
    let w = json_world();
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("1000"))]);
    for body in [
        r#"{"amount":1,"amount":99999,"currency":"EUR"}"#,
        r#"{"amount":99999,"currency":"EUR","amount":1}"#,
        r#"{"amount":1,"currency":"EUR","currency":"USD"}"#,
        r#"{"amount":1,"currency":"EUR","description":"x","description":"y"}"#,
        r#"{"amount":1,"currency":"EUR","amount":99999}"#,
    ] {
        let rule = refused(w.run("charge", charge(body), &mut site));
        assert!(rule.contains("duplicate"), "{rule}");
    }
    assert!(site.sent.is_empty());
    assert_eq!(w.spends(), 0);
}

#[test]
fn only_the_canonical_spelling_of_an_amount_is_read() {
    let w = json_world();
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("1000000"))]);
    for number in [
        "1e3", "1E3", "10.0", "1000.", "-0", "-5", "007", "0x10", "+5", "1_000", "Infinity", "NaN",
        "\"100\"", "true", "null", "[100]", "{}",
    ] {
        let body = format!(r#"{{"amount":{number},"currency":"EUR"}}"#);
        assert!(
            w.run("charge", charge(&body), &mut site).is_err(),
            "a non-canonical amount was accepted"
        );
    }
    assert!(site.sent.is_empty());
    assert_eq!(w.spends(), 0);
    // The canonical forms go through.
    for (number, sent) in [("0", 0), ("100000000", 100_000_000)] {
        let body = format!(r#"{{"amount":{number},"currency":"EUR"}}"#);
        sent_ok(w.run("charge", charge(&body), &mut site));
        assert_eq!(
            wire_amount(site.sent.last().unwrap()),
            serde_json::json!(sent)
        );
    }
}

#[test]
fn big_numbers_are_refused_where_a_server_could_round_them() {
    let w = json_world();
    let mut site = Site::default();
    for number in [
        "100000001",
        "9007199254740993",
        "1000000000000000000000000000000",
        "18446744073709551616",
    ] {
        let body = format!(r#"{{"amount":{number},"currency":"EUR"}}"#);
        assert!(w.run("charge", charge(&body), &mut site).is_err());
    }
    assert!(site.sent.is_empty());

    // A JSON number amount above 2^53 - 1 is refused when the policy is signed: a server that
    // reads numbers as doubles would charge another amount than the one counted.
    let wide = Member::any("/amount")
        .of(JsonType::Number)
        .between(Some("0"), Some("9007199254740992"));
    let policy = paying(json_body(wide), from_body("/amount"))(
        &CallerKey::generate(),
        &CallerKey::generate(),
    );
    assert!(policy.validate().is_err());
    // As a string it may go up to 10^18 minor units, and no further.
    let text = Member::any("/amount")
        .of(JsonType::String)
        .between(Some("0"), Some("1000000000000000000"));
    let w = world(
        paying(json_body(text), from_body("/amount")),
        &[("key", "sk-0123456789abcdef")],
    );
    let top = approval_of(w.run(
        "charge",
        charge(r#"{"amount":"1000000000000000000","currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(top.amount, amount("10000000000000000.00"));
    assert!(
        w.run(
            "charge",
            charge(r#"{"amount":"1000000000000000001","currency":"EUR"}"#),
            &mut site
        )
        .is_err()
    );
    let beyond = Member::any("/amount")
        .of(JsonType::String)
        .between(Some("0"), Some("1000000000000000001"));
    let policy = paying(json_body(beyond), from_body("/amount"))(
        &CallerKey::generate(),
        &CallerKey::generate(),
    );
    assert!(policy.validate().is_err());
}

#[test]
fn the_currency_in_the_body_is_the_payments() {
    let w = json_world();
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("1000"))]);
    for body in [
        r#"{"amount":100,"currency":"USD"}"#,
        r#"{"amount":100,"currency":"eur"}"#,
        r#"{"amount":100}"#,
    ] {
        assert!(w.run("charge", charge(body), &mut site).is_err());
    }
    assert!(site.sent.is_empty());

    let keys = (CallerKey::generate(), CallerKey::generate());
    let sign = |body: BodyContract, source: AmountSource| {
        paying(body, source)(&keys.0, &keys.1).validate()
    };
    // A currency member the caller chooses, by its name or where the policy says it is.
    let open_currency = BodyContract::Json(JsonInput {
        members: vec![minor_number(), {
            let mut m = Member::any("/currency").of(JsonType::String);
            m.one_of = vec!["EUR".into(), "USD".into()];
            m
        }],
    });
    assert!(sign(open_currency, from_body("/amount")).is_err());
    let elsewhere = BodyContract::Json(JsonInput {
        members: vec![minor_number(), Member::any("/ccy").of(JsonType::String)],
    });
    let named = AmountSource::Body {
        pointer: "/amount".into(),
        format: AmountFormat::Minor,
        currency_at: Some("/ccy".into()),
    };
    assert!(sign(elsewhere, named.clone()).is_err());
    // Fixed to the payment's currency where the policy names it: signed, and checked again on
    // the body the node sends.
    let fixed = BodyContract::Json(JsonInput {
        members: vec![minor_number(), Member::equals("/ccy", "EUR")],
    });
    assert!(sign(fixed.clone(), named.clone()).is_ok());
    let w = world(paying(fixed, named), &[("key", "sk-0123456789abcdef")]);
    w.set_limits(vec![eur(None, Some("1000"))]);
    sent_ok(w.run("charge", charge(r#"{"amount":5,"ccy":"EUR"}"#), &mut site));
    assert!(
        w.run("charge", charge(r#"{"amount":5,"ccy":"JPY"}"#), &mut site)
            .is_err()
    );
    assert_eq!(site.sent.len(), 1);
}

#[test]
fn a_decimal_amount_has_exactly_the_currencys_digits() {
    let text = Member::any("/amount").of(JsonType::String);
    let decimal = AmountSource::Body {
        pointer: "/amount".into(),
        format: AmountFormat::Decimal,
        currency_at: None,
    };
    let w = world(
        paying(json_body(text), decimal.clone()),
        &[("key", "sk-0123456789abcdef")],
    );
    let mut site = Site::default();
    let summary = approval_of(w.run(
        "charge",
        charge(r#"{"amount":"12.50","currency":"EUR"}"#),
        &mut site,
    ));
    // The owner sees the very text the site gets.
    assert_eq!(summary.amount, amount("12.50"));
    let small = approval_of(w.run(
        "charge",
        charge(r#"{"amount":"0.05","currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(small.amount, amount("0.05"));
    for bad in [
        "12.5",
        "12.500",
        "012.50",
        "12",
        "1e1",
        "12,50",
        "+12.50",
        "-12.50",
        " 12.50",
        "12.50 ",
        ".50",
        "12.",
        "١٢.٥٠",
    ] {
        let body = format!(r#"{{"amount":"{bad}","currency":"EUR"}}"#);
        assert!(
            w.run("charge", charge(&body), &mut site).is_err(),
            "a non-canonical decimal was accepted"
        );
    }
    assert!(site.sent.is_empty());
    // A decimal JSON number is read as binary floating point by many servers: refused when
    // the policy is signed.
    let number = Member::any("/amount").of(JsonType::Number);
    let policy = paying(json_body(number), decimal)(&CallerKey::generate(), &CallerKey::generate());
    assert!(policy.validate().is_err());
}

// --- Amounts from a form body ----------------------------------------------------------------

fn form_world() -> World {
    let body = BodyContract::Form(FormBody {
        fields: vec![
            QueryRule {
                name: "amount".into(),
                required: true,
                min: Some("0".into()),
                max: Some("100000".into()),
                ..QueryRule::default()
            },
            QueryRule::fixed("currency", "EUR"),
            QueryRule::any("note"),
        ],
    });
    let source = AmountSource::Form {
        name: "amount".into(),
        format: AmountFormat::Minor,
        currency_at: None,
    };
    world(paying(body, source), &[("key", "sk-0123456789abcdef")])
}

/// The fields a server reads from a form body, decoded.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8(body.to_vec()).unwrap();
    text.split('&')
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let decode = |s: &str| {
                let bytes = s.replace('+', " ").into_bytes();
                let mut out = Vec::new();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'%' {
                        let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                        out.push(u8::from_str_radix(hex, 16).unwrap());
                        i += 3;
                    } else {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
                String::from_utf8(out).unwrap()
            };
            (decode(name), decode(value))
        })
        .collect()
}

#[test]
fn a_form_body_carries_one_amount_the_node_wrote() {
    let w = form_world();
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("1000"))]);
    // A second amount hidden in a free field, by every separator a server may read: the node
    // writes the field again, so the site reads one amount.
    sent_ok(w.run(
        "charge",
        charge("amount=700&currency=EUR&note=x;amount=99999%26amount%3D99999+y"),
        &mut site,
    ));
    let fields = form_fields(body_of(&site.sent[0]));
    let amounts: Vec<&str> = fields
        .iter()
        .filter(|(n, _)| n == "amount")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(amounts, ["700"]);
    assert!(
        !body_of(&site.sent[0]).contains(&b';') && !body_of(&site.sent[0]).contains(&b'+'),
        "the body is written with every separator encoded"
    );
    assert!(contains(
        &site.sent[0],
        b"Content-Type: application/x-www-form-urlencoded\r\n"
    ));
    for body in [
        "amount=1&amount=99999&currency=EUR",
        "amount=1&AMOUNT=99999&currency=EUR",
        "amount=1&am%6Funt=99999&currency=EUR",
        "amount=1e3&currency=EUR",
        "amount=01&currency=EUR",
        "amount=1&currency=USD",
        "amount=1&currency=EUR&extra=1",
        "amount=1&&currency=EUR",
        "amount=%zz&currency=EUR",
        "currency=EUR",
    ] {
        assert!(w.run("charge", charge(body), &mut site).is_err(), "{body}");
    }
    assert_eq!(site.sent.len(), 1);
    assert_eq!(w.spends(), 1);
}

// --- Splitting and widening ------------------------------------------------------------------

#[test]
fn splitting_a_body_payment_does_not_get_around_a_limit() {
    let w = json_world();
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("50"))]);
    sent_ok(w.run(
        "charge",
        charge(r#"{"amount":3000,"currency":"EUR"}"#),
        &mut site,
    ));
    approval_of(w.run(
        "charge",
        charge(r#"{"amount":3000,"currency":"EUR"}"#),
        &mut site,
    ));
    sent_ok(w.run(
        "charge",
        charge(r#"{"amount":2000,"currency":"EUR"}"#),
        &mut site,
    ));
    approval_of(w.run(
        "charge",
        charge(r#"{"amount":1,"currency":"EUR"}"#),
        &mut site,
    ));
    assert_eq!(site.sent.len(), 2);
    assert_eq!(w.spends(), 2);

    let keys = (CallerKey::generate(), CallerKey::generate());
    // A paying body with a member the caller fills with any structure could carry a second
    // amount the node does not read: refused when the policy is signed.
    let open = BodyContract::Json(JsonInput {
        members: vec![
            minor_number(),
            Member::equals("/currency", "EUR"),
            Member::any("/items"),
        ],
    });
    assert!(
        paying(open, from_body("/amount"))(&keys.0, &keys.1)
            .validate()
            .is_err()
    );
    // One request, sent twice by two sends of the caller's request, would pay twice for one
    // count.
    let twice = |agent: &CallerKey| {
        let contract = CallerRequest::new([Method::Post])
            .paths(["/v1/charges"])
            .body(json_body(minor_number()));
        Policy::new()
            .with_field(FieldSpec::secret("key"))
            .with_operation(
                Operation::https("charge", Destination::https("pay.example"))
                    .then(Send::caller(contract.clone()))
                    .then(Send::caller(contract))
                    .then(Return::status())
                    .pays(Payment {
                        amount: from_body("/amount"),
                        currency: "EUR".into(),
                        exponent: 2,
                    }),
            )
            .with_caller(Caller::new("agent", agent.public(), ["charge"]))
    };
    assert!(twice(&keys.0).validate().is_err());
    // An amount from a body with no body contract, or from a pointer it does not declare.
    assert!(
        paying(json_body(minor_number()), from_body("/total"))(&keys.0, &keys.1)
            .validate()
            .is_err()
    );
    let form = BodyContract::Form(FormBody {
        fields: vec![QueryRule::any("amount")],
    });
    assert!(
        paying(form, from_body("/amount"))(&keys.0, &keys.1)
            .validate()
            .is_err()
    );
}

#[test]
fn the_body_the_node_checked_is_the_body_it_sends() {
    let keys = (CallerKey::generate(), CallerKey::generate());
    let with = |edit: fn(&mut Send)| {
        let mut policy = paying(json_body(minor_number()), from_body("/amount"))(&keys.0, &keys.1);
        if let Some(engine::policy::Step::Send(send)) = policy.operations[0].steps.get_mut(1) {
            edit(send);
        }
        policy.validate()
    };
    assert!(with(|_| {}).is_ok());
    // An injected body would replace the one checked; a content type of the caller's or an
    // injected one would make the server read the body as another format.
    assert!(with(|s| s.inject.push(Injection::body("amount=99999"))).is_err());
    assert!(
        with(|s| s
            .inject
            .push(Injection::header("Content-Type", "text/plain")))
        .is_err()
    );
    assert!(
        with(|s| {
            if let Some(engine::policy::StepRequest::Caller(c)) = &mut s.request {
                c.headers.push("Content-Type".into());
            }
        })
        .is_err()
    );
    assert!(
        with(|s| {
            if let Some(engine::policy::StepRequest::Caller(c)) = &mut s.request {
                c.headers.push("Content-Encoding".into());
            }
        })
        .is_err()
    );
    // A caller's own Content-Type header is not in the contract: refused at run time.
    let w = json_world();
    let mut site = Site::default();
    let mut request = Request {
        method: Method::Post,
        destination: Destination::https("pay.example"),
        path: "/v1/charges".into(),
        headers: vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )],
        body: br#"{"amount":1,"currency":"EUR"}"#.to_vec(),
    };
    assert!(
        w.run("charge", Body::http(request.clone()), &mut site)
            .is_err()
    );
    request.headers.clear();
    request.body = vec![b' '; 1024 * 1024 + 1];
    assert!(w.run("charge", Body::http(request), &mut site).is_err());
    assert!(site.sent.is_empty());
}

#[test]
fn summaries_flag_who_chooses_the_amount_and_count_a_new_source_as_wider() {
    let keys = (CallerKey::generate(), CallerKey::generate());
    let body_policy = paying(json_body(minor_number()), from_body("/amount"))(&keys.0, &keys.1);
    let summary = summarize(&body_policy, None);
    assert!(
        summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::CallerAmount && f.detail.contains("/amount"))
    );
    assert!(
        summary
            .lines
            .iter()
            .any(|l| l.contains("the body member /amount (in minor units)"))
    );
    assert!(
        summary
            .lines
            .iter()
            .any(|l| l.contains("checked and sent as application/json"))
    );
    let json = serde_json::to_value(&summary).unwrap();
    assert!(json.to_string().contains("\"body\":{\"json\""));

    let wider = |a: &Policy, b: &Policy| {
        summarize(b, Some(a))
            .flags
            .iter()
            .any(|f| f.code == FlagCode::Wider)
    };
    // The same policy is not wider than itself.
    assert!(!wider(&body_policy, &body_policy));
    // A fixed amount that becomes one the caller writes in the body.
    let mut fixed = body_policy.clone();
    fixed.operations[0].payment = Some(Payment {
        amount: AmountSource::Fixed {
            value: "500".into(),
        },
        currency: "EUR".into(),
        exponent: 2,
    });
    assert!(wider(&fixed, &body_policy));
    // A looser bound on the amount.
    let looser = paying(
        json_body(
            Member::any("/amount")
                .of(JsonType::Number)
                .between(Some("0"), Some("900000000")),
        ),
        from_body("/amount"),
    )(&keys.0, &keys.1);
    assert!(wider(&body_policy, &looser));
    // A body contract dropped.
    let mut dropped = body_policy.clone();
    dropped.operations[0].payment = None;
    if let Some(engine::policy::Step::Send(send)) = dropped.operations[0].steps.get_mut(1)
        && let Some(engine::policy::StepRequest::Caller(c)) = &mut send.request
    {
        c.body = None;
    }
    let mut checked = dropped.clone();
    if let Some(engine::policy::Step::Send(send)) = checked.operations[0].steps.get_mut(1)
        && let Some(engine::policy::StepRequest::Caller(c)) = &mut send.request
    {
        c.body = Some(json_body(minor_number()));
    }
    assert!(wider(&checked, &dropped));
    // Adding one narrows what the caller sends.
    assert!(!wider(&dropped, &checked));
    // A fixed amount is not chosen by the caller.
    assert!(
        !summarize(&fixed, None)
            .flags
            .iter()
            .any(|f| f.code == FlagCode::CallerAmount)
    );
}

#[test]
fn a_query_amount_refuses_a_second_separator() {
    let shop = |agent: &CallerKey, _: &CallerKey| {
        let contract = CallerRequest::new([Method::Post])
            .paths(["/v1/charge"])
            .query(QueryRule {
                name: "amount".into(),
                required: true,
                min: Some("0".into()),
                max: Some("100000000".into()),
                ..QueryRule::default()
            })
            .query(QueryRule::any("note"));
        Policy::new()
            .with_field(FieldSpec::secret("key"))
            .with_operation(
                Operation::https("charge", Destination::https("pay.example"))
                    .then(Send::caller(contract))
                    .then(Return::status())
                    .pays(Payment {
                        amount: AmountSource::Query {
                            name: "amount".into(),
                        },
                        currency: "EUR".into(),
                        exponent: 2,
                    }),
            )
            .with_caller(Caller::new("agent", agent.public(), ["charge"]))
    };
    let w = world(shop, &[("key", "sk-0123456789abcdef")]);
    let mut site = Site::default();
    w.set_limits(vec![eur(None, Some("1000"))]);
    let at = |path: &str| {
        Body::http(Request::new(
            Method::Post,
            Destination::https("pay.example"),
            path,
        ))
    };
    let rule = refused(w.run(
        "charge",
        at("/v1/charge?amount=1&note=x;amount=99999"),
        &mut site,
    ));
    assert!(rule.contains(';'), "{rule}");
    sent_ok(w.run(
        "charge",
        at("/v1/charge?amount=1&note=x%3Bamount"),
        &mut site,
    ));
    assert_eq!(site.sent.len(), 1);
    // A currency the caller may name in the query is refused when the policy is signed.
    let named = |agent: &CallerKey, other: &CallerKey| {
        let mut policy = shop(agent, other);
        if let Some(engine::policy::Step::Send(send)) = policy.operations[0].steps.get_mut(1)
            && let Some(engine::policy::StepRequest::Caller(c)) = &mut send.request
        {
            c.query.push(QueryRule::any("currency"));
        }
        policy
    };
    let keys = (CallerKey::generate(), CallerKey::generate());
    assert!(named(&keys.0, &keys.1).validate().is_err());
}

// --- await on TLS ----------------------------------------------------------------------------

fn mail() -> Destination {
    Destination::new("mail.example", 993)
}

/// Waits for a code from the owner's device, then signs in with the password and the code and
/// relays the caller's `NOOP`s.
fn tls_login(agent: &CallerKey, other: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::secret("password"))
        .with_operation(
            Operation::tls("login", mail())
                .then(Challenge::code(
                    ChallengeKind::App,
                    "The code of your authenticator",
                    "otp",
                ))
                .then(Send::write("a1 LOGIN alice {{password}}{{otp}}\r\n"))
                .then(Receive::until(["\r\n"]))
                .then(Return::relay(["a[0-9] NOOP\\r\\n"])),
        )
        .with_caller(Caller::new("agent", agent.public(), ["login"]))
        .with_caller(Caller::new("other", other.public(), ["login"]))
}

fn tls_world() -> World {
    world(tls_login, &[("password", PASSWORD)])
}

fn noop() -> Body {
    Body::Stream {
        destination: mail(),
        exchanges: vec![CallerExchange {
            send: b"a2 NOOP\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        }],
    }
}

fn answer(w: &World, id: [u8; 16]) -> engine::Result<()> {
    let sealed = w
        .device
        .answer_challenge(&w.node.identity(), "alice", id, CODE.as_bytes(), w.now())
        .unwrap();
    w.node.answer(&sealed)
}

fn stream_of(output: engine::Result<Output>) -> StreamOutput {
    match output {
        Ok(Output::Stream(output)) => output,
        other => panic!("not a stream: {:?}", other.map(|_| ()).err()),
    }
}

fn mail_site() -> Site {
    Site {
        lines: VecDeque::from([b"a1 OK\r\n".to_vec(), b"a2 OK NOOP\r\n".to_vec()]),
        ..Site::default()
    }
}

#[test]
fn a_tls_operation_waits_for_its_code_before_it_connects() {
    let w = tls_world();
    let mut site = mail_site();
    let first = w.run("login", noop(), &mut site);
    let Ok(Output::Pending(pending)) = &first else {
        panic!("a pending operation");
    };
    let pending = serde_json::to_vec(pending).unwrap();
    let id = challenge_of(first);
    // Nothing was connected, written or logged as a stream while it waits.
    assert_eq!(site.opens, 0);
    assert!(site.written.is_empty());
    let streams = |w: &World| {
        w.node.with_sink(|sink| {
            sink.entries()
                .iter()
                .filter(|e| matches!(e.entry.event, Event::Stream { .. }))
                .count()
        })
    };
    assert_eq!(streams(&w), 0);
    // Resumed before the code came: told again, still not connected.
    challenge_of(w.resume("login", id, &mut site));
    assert_eq!(site.opens, 0);

    answer(&w, id).unwrap();
    let output = stream_of(w.resume("login", id, &mut site));
    assert_eq!(site.opens, 1);
    assert_eq!(output.error, None);
    assert_eq!(output.reads, vec![b"a2 OK NOOP\r\n".to_vec()]);
    // The login carried the password and the code; then the exchange the caller signed.
    assert!(contains(
        &site.written[0],
        format!("{PASSWORD}{CODE}").as_bytes()
    ));
    assert_eq!(site.written[1], b"a2 NOOP\r\n");
    assert_eq!(streams(&w), 1);
    // The id is spent.
    assert_eq!(w.resume("login", id, &mut site), Err(Error::ParkedUnknown));
    // Neither the code nor the password is in the pending reply or the log.
    let log = w.log();
    for secret in [CODE.as_bytes(), PASSWORD.as_bytes()] {
        assert!(
            !contains(&pending, secret),
            "a secret is in the pending reply"
        );
        assert!(!contains(&log, secret), "a secret is in the log");
    }
}

#[test]
fn only_its_caller_resumes_a_waiting_tls_operation() {
    let w = tls_world();
    let mut site = mail_site();
    let id = challenge_of(w.run("login", noop(), &mut site));
    answer(&w, id).unwrap();
    let call = w.call_as(&w.other, "other", "login", Body::resume(id));
    assert_eq!(
        w.node.run(&call, &mut site).result,
        Err(Error::ParkedUnknown)
    );
    assert_eq!(
        w.resume("login", [9; 16], &mut site),
        Err(Error::ParkedUnknown)
    );
    assert_eq!(site.opens, 0);
    // Still waiting for its own caller, with the exchanges it signed when it started.
    let output = stream_of(w.resume("login", id, &mut site));
    assert_eq!(output.reads.len(), 1);
    assert_eq!(site.opens, 1);
}

#[test]
fn a_waiting_tls_operation_lapses_and_does_not_survive_a_restart() {
    let w = tls_world();
    let mut site = mail_site();
    let id = challenge_of(w.run("login", noop(), &mut site));
    w.advance(5 * 60 * 1000);
    assert_eq!(answer(&w, id), Err(Error::ParkedUnknown));
    assert_eq!(w.resume("login", id, &mut site), Err(Error::ParkedUnknown));

    let id = challenge_of(w.run("login", noop(), &mut site));
    answer(&w, id).unwrap();
    let entries = w.node.with_sink(|sink| sink.entries().to_vec());
    let restarted = World {
        node: Node::restore(
            NodeKey::from_bytes(&mut w.node_key.clone()),
            MemorySink::new(),
            SharedClock(w.clock.clone()),
            &entries,
        )
        .unwrap(),
        node_key: w.node_key,
        clock: w.clock.clone(),
        device: w.device,
        agent: w.agent,
        other: w.other,
        record: w.record,
    };
    restarted.advance(1);
    restarted.grant();
    assert_eq!(restarted.node.waiting(), 0);
    assert_eq!(
        restarted.resume("login", id, &mut site),
        Err(Error::ParkedUnknown)
    );
    assert_eq!(site.opens, 0);
}

#[test]
fn an_approved_tls_operation_runs_the_exchanges_it_was_called_with() {
    let approved = |agent: &CallerKey, other: &CallerKey| {
        let mut policy = tls_login(agent, other);
        policy.operations[0].approval = true;
        policy.operations[0].steps.remove(1);
        policy.operations[0].steps[1] = Send::write("a1 LOGIN alice {{password}}\r\n").into();
        policy
    };
    let w = world(approved, &[("password", PASSWORD)]);
    let mut site = mail_site();
    let summary = approval_of(w.run("login", noop(), &mut site));
    assert_eq!(site.opens, 0);
    w.node
        .approve(&w.device.approve(&summary, w.now()).unwrap())
        .unwrap();
    let output = stream_of(w.resume("login", summary.id, &mut site));
    assert_eq!(output.reads, vec![b"a2 OK NOOP\r\n".to_vec()]);
    assert_eq!(site.written[1], b"a2 NOOP\r\n");
    assert_eq!(site.opens, 1);
}

#[test]
fn await_on_tls_is_refused_where_it_would_hold_a_connection() {
    let keys = (CallerKey::generate(), CallerKey::generate());
    let code = || Challenge::code(ChallengeKind::Sms, "The code", "otp");
    let sign = |operation: Operation| {
        Policy::new()
            .with_field(FieldSpec::secret("password"))
            .with_operation(operation)
            .with_caller(Caller::new("agent", keys.0.public(), ["login"]))
            .validate()
    };
    let relay = || Return::relay(["a[0-9] NOOP\\r\\n"]);
    // Directly after open, before anything touches the connection: signed.
    assert!(
        sign(
            Operation::tls("login", mail())
                .then(code())
                .then(Challenge::code(ChallengeKind::Email, "Another", "otp2"))
                .then(Send::write("a1 LOGIN {{password}}{{otp}}{{otp2}}\r\n"))
                .then(relay())
        )
        .is_ok()
    );
    // After a send or a receive the connection is open: waiting would hold it, and resuming
    // after a reconnect would replay what was sent.
    assert!(
        sign(
            Operation::tls("login", mail())
                .then(Send::write("a1 LOGIN {{password}}\r\n"))
                .then(code())
                .then(Send::write("a2 OTP {{otp}}\r\n"))
                .then(relay())
        )
        .is_err()
    );
    assert!(
        sign(
            Operation::tls("login", mail())
                .then(Receive::until(["\r\n"]))
                .then(code())
                .then(Send::write("a1 LOGIN {{password}}{{otp}}\r\n"))
                .then(relay())
        )
        .is_err()
    );
    // After another step, even one that sends nothing.
    assert!(
        sign(
            Operation::tls("login", mail())
                .then(engine::policy::Compute {
                    into: "pw".into(),
                    template: "{{password}}".into(),
                })
                .then(code())
                .then(Send::write("a1 LOGIN {{pw}}{{otp}}\r\n"))
                .then(relay())
        )
        .is_err()
    );
    // An external challenge polls over HTTPS: there is none on TLS.
    let poll = engine::policy::Poll {
        send: Send::fixed(Method::Get, "/status"),
        success: engine::policy::Condition {
            source: engine::policy::Source::json("/state"),
            one_of: vec!["approved".into()],
        },
        failure: None,
        every_ms: 2000,
    };
    assert!(
        sign(
            Operation::tls("login", mail())
                .then(Challenge::external("Approve", poll))
                .then(Send::write("a1 LOGIN {{password}}\r\n"))
                .then(relay())
        )
        .is_err()
    );
    // Datagrams keep the refusal.
    assert!(
        sign(
            Operation::udp("login", Destination::new("radius.example", 1812))
                .then(code())
                .then(Send::write("{{ hmac_sha256(password, otp) }}"))
                .then(Receive::until(Vec::<String>::new()))
                .then(Return::status())
        )
        .is_err()
    );
}

// --- Approvals of every payload that waits ---------------------------------------------------

fn radius() -> Destination {
    Destination::new("radius.example", 1812)
}

/// Asks with a MAC over the password, then relays the caller's pings; waits for the owner's
/// approval when `approval`.
fn udp_ask(approval: bool) -> impl Fn(&CallerKey, &CallerKey) -> Policy {
    move |agent, other| {
        let mut operation = Operation::udp("ask", radius())
            .then(Send::write("{{ hex(hmac_sha256(password, \"hello\")) }}"))
            .then(Receive::until(Vec::<String>::new()))
            .then(Return::relay(["ping [0-9]"]));
        operation.approval = approval;
        Policy::new()
            .with_field(FieldSpec::secret("password"))
            .with_operation(operation)
            .with_caller(Caller::new("agent", agent.public(), ["ask"]))
            .with_caller(Caller::new("other", other.public(), ["ask"]))
    }
}

fn pings() -> Body {
    Body::Stream {
        destination: radius(),
        exchanges: vec![CallerExchange {
            send: b"ping 1".to_vec(),
            until: Vec::new(),
        }],
    }
}

fn radius_site() -> Site {
    Site {
        lines: VecDeque::from([b"accept".to_vec(), b"pong 1".to_vec()]),
        ..Site::default()
    }
}

#[test]
fn an_approved_udp_operation_sends_the_datagrams_it_was_called_with() {
    let plain = world(udp_ask(false), &[("password", PASSWORD)]);
    let mut site = radius_site();
    let expected = stream_of(plain.run("ask", pings(), &mut site));
    assert_eq!(expected.reads, vec![b"pong 1".to_vec()]);

    let w = world(udp_ask(true), &[("password", PASSWORD)]);
    let mut site = radius_site();
    let summary = approval_of(w.run("ask", pings(), &mut site));
    assert_eq!(site.opens, 0, "nothing is opened before the approval");
    approval_of(w.resume("ask", summary.id, &mut site));
    assert_eq!(site.opens, 0);
    // Another caller does not get to run it, approved or not.
    w.node
        .approve(&w.device.approve(&summary, w.now()).unwrap())
        .unwrap();
    let call = w.call_as(&w.other, "other", "ask", Body::resume(summary.id));
    assert_eq!(
        w.node.run(&call, &mut site).result,
        Err(Error::ParkedUnknown)
    );
    let output = stream_of(w.resume("ask", summary.id, &mut site));
    assert_eq!(output.reads, expected.reads);
    assert_eq!(output.error, None);
    assert_eq!(site.opens, 1);
    assert_eq!(site.written[1], b"ping 1");
    assert_eq!(
        w.resume("ask", summary.id, &mut site),
        Err(Error::ParkedUnknown)
    );
}

fn mac(approval: bool) -> impl Fn(&CallerKey, &CallerKey) -> Policy {
    move |agent, other| {
        let mut operation = Operation::derive("mac", "{{ hex(hmac_sha256(password, $input)) }}")
            .input(engine::policy::Input::any());
        operation.approval = approval;
        Policy::new()
            .with_field(FieldSpec::secret("password"))
            .with_operation(operation)
            .with_caller(Caller::new("agent", agent.public(), ["mac"]))
            .with_caller(Caller::new("other", other.public(), ["mac"]))
    }
}

fn derived(output: engine::Result<Output>) -> Vec<u8> {
    match output {
        Ok(Output::Derive(bytes)) => bytes,
        other => panic!("not derived: {:?}", other.map(|_| ()).err()),
    }
}

#[test]
fn an_approved_derivation_runs_on_the_input_it_was_called_with() {
    let input = || Body::derive(b"message to sign");
    let mut site = Site::default();
    let plain = world(mac(false), &[("password", PASSWORD)]);
    let expected = derived(plain.run("mac", input(), &mut site));

    let w = world(mac(true), &[("password", PASSWORD)]);
    let summary = approval_of(w.run("mac", input(), &mut site));
    approval_of(w.resume("mac", summary.id, &mut site));
    w.node
        .approve(&w.device.approve(&summary, w.now()).unwrap())
        .unwrap();
    assert_eq!(derived(w.resume("mac", summary.id, &mut site)), expected);
    assert_eq!(
        w.resume("mac", summary.id, &mut site),
        Err(Error::ParkedUnknown)
    );
}
