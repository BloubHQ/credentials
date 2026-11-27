//! Operations that wait for the owner, on a node: challenges answered by the owner's device
//! (never by the caller), external challenges the node polls, approvals over exactly the
//! summary the node built, spending limits counted before anything is sent, and sessions the
//! node renews. Each guarantee is shown against the attack it stops.
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
use engine::egress::{ClientIdentity, Transport};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::item::ItemBinding;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::limits::LimitRule;
use engine::log::{Event, MemorySink, verify_chain};
use engine::node::{Clock, MAX_PARKED, MAX_PARKED_PER_OWNER, Node};
use engine::policy::{
    AmountSource, Caller, CallerRequest, Capture, Challenge, ChallengeKind, Condition, Destination,
    FieldSpec, Injection, Method, Operation, Payment, Policy, Poll, QueryRule, Receive, Renew,
    Return, Send, SessionRule, Source, Store,
};
use engine::record::Record;
use engine::request::Request;
use engine::session::Pending;

/// 2026-11-25T00:00:00Z.
const NOW: u64 = 1_795_564_800_000;
const USER: [u8; 32] = [7; 32];
/// The one-time code of the tests (a test value, never printed).
const CODE: &str = "493817";

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers each request with the next scripted reply (`200 {}` when none is left) and keeps
/// what it was asked to send.
#[derive(Default)]
struct Script {
    replies: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
}

impl Script {
    fn reply(mut self, status: u16, headers: &str, body: &str) -> Self {
        self.replies.push_back(http(status, headers, body));
        self
    }

    fn then(&mut self, status: u16, headers: &str, body: &str) {
        self.replies.push_back(http(status, headers, body));
    }
}

fn http(status: u16, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

impl Transport for Script {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| http(200, "", "{}")))
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
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

    fn call_as(
        &self,
        key: &CallerKey,
        name: &str,
        record: &Record,
        op: &str,
        body: Body,
    ) -> SignedCall {
        key.sign_call_at(
            name,
            &self.node.public_key(),
            record.clone(),
            op,
            body,
            self.now(),
        )
        .unwrap()
    }

    fn run(&self, op: &str, body: Body, transport: &mut Script) -> engine::Result<Output> {
        let call = self.call_as(&self.agent, "agent", &self.record, op, body);
        self.node.run(&call, transport).result
    }

    fn resume(&self, op: &str, id: [u8; 16], transport: &mut Script) -> engine::Result<Output> {
        self.run(op, Body::resume(id), transport)
    }

    fn log(&self) -> Vec<u8> {
        let entries = self.node.with_sink(|sink| sink.entries().to_vec());
        verify_chain(&entries, &self.node.public_key()).unwrap();
        serde_json::to_vec(&entries).unwrap()
    }

    fn events(&self, wanted: fn(&Event) -> bool) -> usize {
        self.node.with_sink(|sink| {
            sink.entries()
                .iter()
                .filter(|e| wanted(&e.entry.event))
                .count()
        })
    }
}

fn challenge_of(output: engine::Result<Output>) -> ([u8; 16], ChallengeKind) {
    match output {
        Ok(Output::Pending(Pending::Challenge { id, challenge, .. })) => (id, challenge),
        other => panic!("not a challenge: {:?}", other.map(|_| ()).err()),
    }
}

fn approval_of(output: engine::Result<Output>) -> ApprovalSummary {
    match output {
        Ok(Output::Pending(Pending::ApprovalRequired { id, summary })) => {
            assert_eq!(id, summary.id);
            *summary
        }
        other => panic!("not an approval: {:?}", other.map(|_| ()).err()),
    }
}

fn status_of(output: engine::Result<Output>) -> u16 {
    match output {
        Ok(Output::Http(response)) => response.status(),
        other => panic!("not a response: {:?}", other.map(|_| ()).err()),
    }
}

// --- Code challenges -------------------------------------------------------------------------

/// A login with a password, then a code the bank texts the owner, then the code sent on.
fn bank(agent: &CallerKey, other: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::secret("password"))
        .with_operation(
            Operation::https("login", Destination::https("bank.example"))
                .then(
                    Send::fixed(Method::Post, "/login").inject(Injection::body("pw={{password}}")),
                )
                .then(Challenge::code(
                    ChallengeKind::Sms,
                    "The code your bank texts you",
                    "otp",
                ))
                .then(Send::fixed(Method::Post, "/otp").inject(Injection::body("otp={{otp}}")))
                .then(Return::status().body()),
        )
        .with_caller(Caller::new("agent", agent.public(), ["login"]))
        .with_caller(Caller::new("other", other.public(), ["login"]))
}

fn bank_world() -> World {
    world(bank, &[("password", "correct horse battery")])
}

fn answer(w: &World, id: [u8; 16], code: &str) -> engine::Result<()> {
    let sealed = w
        .device
        .answer_challenge(&w.node.identity(), "alice", id, code.as_bytes(), w.now())
        .unwrap();
    w.node.answer(&sealed)
}

#[test]
fn a_code_challenge_parks_until_the_owners_device_answers() {
    let w = bank_world();
    let mut t = Script::default();
    let (id, kind) = challenge_of(w.run("login", Body::http_fixed(), &mut t));
    assert_eq!(kind, ChallengeKind::Sms);
    assert_eq!(t.sent.len(), 1);
    assert_eq!(w.node.waiting(), 1);

    // Until the device answers, resuming tells the caller the same challenge and sends nothing.
    let (again, _) = challenge_of(w.resume("login", id, &mut t));
    assert_eq!(again, id);
    assert_eq!(t.sent.len(), 1);

    answer(&w, id, CODE).unwrap();
    assert_eq!(status_of(w.resume("login", id, &mut t)), 200);
    assert_eq!(t.sent.len(), 2);
    assert!(
        contains(&t.sent[1], format!("otp={CODE}").as_bytes()),
        "the code reached the request after the await"
    );
    assert_eq!(w.events(|e| matches!(e, Event::Answer { .. })), 1);
    // Once it went on, the id is spent.
    assert_eq!(w.node.waiting(), 0);
    assert_eq!(w.resume("login", id, &mut t), Err(Error::ParkedUnknown));
}

#[test]
fn the_caller_cannot_answer_a_challenge() {
    let w = bank_world();
    let mut t = Script::default();
    let (id, _) = challenge_of(w.run("login", Body::http_fixed(), &mut t));

    // The caller holds a caller key, no device key of the owner: an answer signed by any key
    // the node does not know for the owner is refused, whoever made it.
    let stranger = DeviceKey::generate();
    let forged = stranger
        .answer_challenge(&w.node.identity(), "alice", id, CODE.as_bytes(), w.now())
        .unwrap();
    assert_eq!(w.node.answer(&forged), Err(Error::GrantDenied));
    // Signed by the owner's device but sealed to another node: this node cannot open it.
    let elsewhere = Node::new(
        NodeKey::generate(),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
    );
    let misrouted = w
        .device
        .answer_challenge(&elsewhere.identity(), "alice", id, CODE.as_bytes(), w.now())
        .unwrap();
    assert!(matches!(
        w.node.answer(&misrouted),
        Err(Error::AnswerInvalid { .. })
    ));
    // A code that breaks the pattern of the challenge.
    assert!(matches!(
        answer(&w, id, "not a code!"),
        Err(Error::AnswerInvalid { .. })
    ));
    // Nothing went on, and nothing more was sent.
    challenge_of(w.resume("login", id, &mut t));
    assert_eq!(t.sent.len(), 1);
    assert_eq!(w.events(|e| matches!(e, Event::Answer { .. })), 0);

    // The device answers; the same answer again is refused.
    let sealed = w
        .device
        .answer_challenge(&w.node.identity(), "alice", id, CODE.as_bytes(), w.now())
        .unwrap();
    w.node.answer(&sealed).unwrap();
    assert!(matches!(
        w.node.answer(&sealed),
        Err(Error::AnswerInvalid { .. })
    ));
}

#[test]
fn someone_elses_parked_id_cannot_be_resumed() {
    let w = bank_world();
    let mut t = Script::default();
    let (id, _) = challenge_of(w.run("login", Body::http_fixed(), &mut t));
    answer(&w, id, CODE).unwrap();

    // Another caller of the same policy, with the id.
    let call = w.call_as(&w.other, "other", &w.record, "login", Body::resume(id));
    assert_eq!(w.node.run(&call, &mut t).result, Err(Error::ParkedUnknown));
    // An id nobody parked.
    assert_eq!(
        w.resume("login", [9; 16], &mut t),
        Err(Error::ParkedUnknown)
    );
    assert_eq!(t.sent.len(), 1);

    // Another owner's caller, on its own record, with the id.
    let bob = bank_world();
    let call = bob.call_as(&bob.agent, "agent", &bob.record, "login", Body::resume(id));
    assert_eq!(
        bob.node.run(&call, &mut t).result,
        Err(Error::ParkedUnknown)
    );

    // The operation still waits for its own caller.
    assert_eq!(status_of(w.resume("login", id, &mut t)), 200);
}

#[test]
fn parked_values_never_leave_the_node() {
    let w = bank_world();
    // The site echoes the code back; the node redacts it before anything is handed back.
    let mut t =
        Script::default()
            .reply(200, "", "{}")
            .reply(200, "", &format!("{{\"echo\": \"{CODE}\"}}"));
    let first = w.run("login", Body::http_fixed(), &mut t);
    let Ok(Output::Pending(waiting)) = &first else {
        panic!("a pending operation");
    };
    let pending = serde_json::to_vec(waiting).unwrap();
    let (id, _) = challenge_of(first);
    answer(&w, id, CODE).unwrap();
    let Ok(Output::Http(response)) = w.resume("login", id, &mut t) else {
        panic!("a response");
    };
    let password = b"correct horse battery";
    assert!(
        !contains(response.body(), CODE.as_bytes()),
        "the code is in the response"
    );
    assert!(
        !contains(&pending, CODE.as_bytes()),
        "the code is in the pending reply"
    );
    assert!(
        !contains(&pending, password),
        "the password is in the pending reply"
    );
    let log = w.log();
    for secret in [CODE.as_bytes(), password.as_slice()] {
        assert!(!contains(&log, secret), "a parked value is in the log");
    }
}

#[test]
fn a_flood_of_waiting_operations_hits_the_cap_before_anything_is_sent() {
    let w = bank_world();
    let mut t = Script::default();
    for _ in 0..MAX_PARKED_PER_OWNER {
        challenge_of(w.run("login", Body::http_fixed(), &mut t));
    }
    let sent = t.sent.len();
    assert_eq!(sent, MAX_PARKED_PER_OWNER);
    assert_eq!(
        w.run("login", Body::http_fixed(), &mut t),
        Err(Error::ParkedFull)
    );
    assert_eq!(t.sent.len(), sent);
    assert_eq!(w.node.waiting(), MAX_PARKED_PER_OWNER);
    // Another owner on the same node still has room.
    let mut other = Script::default();
    let bob = bank_world();
    challenge_of(bob.run("login", Body::http_fixed(), &mut other));
}

/// While its request is out, runs one more call of the same owner on the same node.
struct Overlap<'w> {
    world: &'w World,
    inner: Option<engine::Result<Output>>,
    inner_sent: usize,
}

impl Transport for Overlap<'_> {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        if self.inner.is_none() {
            let mut t = Script::default();
            self.inner = Some(self.world.run("login", Body::http_fixed(), &mut t));
            self.inner_sent = t.sent.len();
        }
        Ok(http(200, "", "{}"))
    }
}

#[test]
fn the_last_waiting_slot_is_held_while_the_request_is_out() {
    let w = bank_world();
    let mut t = Script::default();
    for _ in 0..MAX_PARKED_PER_OWNER - 1 {
        challenge_of(w.run("login", Body::http_fixed(), &mut t));
    }
    // One slot is left: the call that took it holds it while its login is out, so a call that
    // overlaps it is refused before it sends anything, not after.
    let mut overlap = Overlap {
        world: &w,
        inner: None,
        inner_sent: 0,
    };
    let call = w.call_as(&w.agent, "agent", &w.record, "login", Body::http_fixed());
    challenge_of(w.node.run(&call, &mut overlap).result);
    assert_eq!(overlap.inner, Some(Err(Error::ParkedFull)));
    assert_eq!(overlap.inner_sent, 0);
    assert_eq!(w.node.waiting(), MAX_PARKED_PER_OWNER);
}

#[test]
fn waiting_operations_lapse_and_are_dropped_on_revoke_and_restart() {
    let w = bank_world();
    let mut t = Script::default();
    let (id, _) = challenge_of(w.run("login", Body::http_fixed(), &mut t));
    // Five minutes later the challenge has lapsed with its values.
    w.advance(5 * 60 * 1000);
    assert_eq!(w.node.waiting(), 0);
    assert_eq!(answer(&w, id, CODE), Err(Error::ParkedUnknown));
    assert_eq!(w.resume("login", id, &mut t), Err(Error::ParkedUnknown));

    // A revocation drops what the owner had waiting.
    challenge_of(w.run("login", Body::http_fixed(), &mut t));
    assert_eq!(w.node.waiting(), 1);
    w.advance(1);
    let revocation = w
        .device
        .revoke("alice", &w.node.public_key(), w.now())
        .unwrap();
    w.node.revoke(&revocation).unwrap();
    assert_eq!(w.node.waiting(), 0);

    // A restart drops everything that waited: it lives in memory only.
    let w = bank_world();
    challenge_of(w.run("login", Body::http_fixed(), &mut t));
    let entries = w.node.with_sink(|sink| sink.entries().to_vec());
    let restarted = Node::restore(
        NodeKey::from_bytes(&mut w.node_key.clone()),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
        &entries,
    )
    .unwrap();
    assert_eq!(restarted.waiting(), 0);
}

// --- External challenges ---------------------------------------------------------------------

fn external(agent: &CallerKey, _: &CallerKey) -> Policy {
    let state = |values: &[&str]| Condition {
        source: Source::json("/state"),
        one_of: values.iter().map(|v| (*v).to_string()).collect(),
    };
    let poll = Poll {
        send: Send::fixed(Method::Get, "/status"),
        success: state(&["approved"]),
        failure: Some(state(&["declined"])),
        every_ms: 2000,
    };
    Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_operation(
            Operation::https("pay", Destination::https("bank.example"))
                .then(Send::fixed(Method::Post, "/start").inject(Injection::body("t={{token}}")))
                .then(
                    Challenge::external("Approve in your bank's app", poll).waiting_at_most(60_000),
                )
                .then(Send::fixed(Method::Post, "/finish").inject(Injection::body("t={{token}}")))
                .then(Return::status()),
        )
        .with_caller(Caller::new("agent", agent.public(), ["pay"]))
}

#[test]
fn an_external_challenge_is_polled_until_the_site_says_yes() {
    let w = world(external, &[("token", "tok-123456789")]);
    let mut t = Script::default();
    let (id, kind) = challenge_of(w.run("pay", Body::http_fixed(), &mut t));
    assert_eq!(kind, ChallengeKind::External);
    // Polled no sooner than the policy allows.
    challenge_of(w.resume("pay", id, &mut t));
    assert_eq!(t.sent.len(), 1);
    // Still pending at the site.
    w.advance(2000);
    t.then(200, "", r#"{"state": "pending"}"#);
    challenge_of(w.resume("pay", id, &mut t));
    assert_eq!(t.sent.len(), 2);
    // An external challenge takes no code.
    assert!(matches!(
        answer(&w, id, CODE),
        Err(Error::AnswerInvalid { .. })
    ));
    // Approved at the site: the operation goes on.
    w.advance(2000);
    t.then(200, "", r#"{"state": "approved"}"#);
    assert_eq!(status_of(w.resume("pay", id, &mut t)), 200);
    assert_eq!(t.sent.len(), 4);
    assert!(contains(&t.sent[3], b"/finish"));
}

#[test]
fn an_external_challenge_fails_when_declined_or_late() {
    let w = world(external, &[("token", "tok-123456789")]);
    let mut t = Script::default();
    let (id, _) = challenge_of(w.run("pay", Body::http_fixed(), &mut t));
    w.advance(2000);
    t.then(200, "", r#"{"state": "declined"}"#);
    assert!(matches!(
        w.resume("pay", id, &mut t),
        Err(Error::ChallengeFailed { .. })
    ));
    assert_eq!(t.sent.len(), 2);
    assert_eq!(w.node.waiting(), 0);

    // At the deadline the operation is gone.
    let (id, _) = challenge_of(w.run("pay", Body::http_fixed(), &mut t));
    w.advance(60_000);
    assert_eq!(w.resume("pay", id, &mut t), Err(Error::ParkedUnknown));
    assert_eq!(t.sent.len(), 3);
}

// --- Approvals -------------------------------------------------------------------------------

fn card(agent: &CallerKey, _: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::guessable("number"))
        .with_field(FieldSpec::guessable("expiry"))
        .with_field(FieldSpec::guessable("cvc"))
        .with_field(FieldSpec::public("holder").optional())
        .with_operation(
            Operation::https("pay", Destination::https("pay.example"))
                .then(
                    Send::fixed(Method::Post, "/v1/charges").inject(Injection::body(
                        "number={{number}}&exp={{expiry}}&cvc={{cvc}}",
                    )),
                )
                .then(Return::status()),
        )
        .with_caller(Caller::new("agent", agent.public(), ["pay"]))
        .with_item(ItemBinding::reviewed("card"))
}

#[test]
fn every_use_of_a_card_waits_for_the_owners_approval() {
    let w = world(
        card,
        &[
            ("number", "4242424242424242"),
            ("expiry", "12/40"),
            ("cvc", "737"),
            ("holder", "Jane Doe"),
        ],
    );
    let mut t = Script::default();
    let summary = approval_of(w.run("pay", Body::http_fixed(), &mut t));
    assert_eq!(t.sent.len(), 0);
    assert_eq!(summary.destination.as_deref(), Some("pay.example:443"));
    assert_eq!(summary.caller, "agent");
    // The owner sees the masked card, never its secrets.
    let text = serde_json::to_string(&summary).unwrap();
    assert!(text.contains("4242"), "the masked number is shown");
    for secret in ["4242424242424242", "737", "12/40"] {
        assert!(!text.contains(secret), "a secret value is in the summary");
    }
    // Not yet approved: the caller is told again.
    approval_of(w.resume("pay", summary.id, &mut t));

    let approval = w.device.approve(&summary, w.now()).unwrap();
    // Only a device of the owner approves.
    let stranger = DeviceKey::generate().approve(&summary, w.now()).unwrap();
    assert_eq!(w.node.approve(&stranger), Err(Error::GrantDenied));
    w.node.approve(&approval).unwrap();
    assert_eq!(status_of(w.resume("pay", summary.id, &mut t)), 200);
    assert_eq!(t.sent.len(), 1);
    assert_eq!(w.events(|e| matches!(e, Event::Approve { .. })), 1);

    // The approval was for that use only.
    let next = approval_of(w.run("pay", Body::http_fixed(), &mut t));
    assert_ne!(next.id, summary.id);
    assert_eq!(w.node.approve(&approval), Err(Error::ParkedUnknown));
    approval_of(w.resume("pay", next.id, &mut t));
    assert_eq!(t.sent.len(), 1);
}

// --- Payments and spending limits ------------------------------------------------------------

fn shop(agent: &CallerKey, _: &CallerKey) -> Policy {
    let contract = CallerRequest::new([Method::Post])
        .paths(["/v1/charge"])
        .query(QueryRule {
            name: "amount".into(),
            required: true,
            min: Some("0".into()),
            max: Some("100000000".into()),
            ..QueryRule::default()
        });
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
                    amount: AmountSource::Query {
                        name: "amount".into(),
                    },
                    currency: "EUR".into(),
                    exponent: 2,
                }),
        )
        .with_caller(Caller::new("agent", agent.public(), ["charge"]))
}

fn shop_world() -> World {
    world(shop, &[("key", "sk-0123456789abcdef")])
}

fn charge(cents: &str) -> Body {
    Body::http(Request {
        method: Method::Post,
        destination: Destination::https("pay.example"),
        path: format!("/v1/charge?amount={cents}"),
        headers: Vec::new(),
        body: Vec::new(),
    })
}

fn set_limits(w: &World, rules: Vec<LimitRule>) -> engine::Result<()> {
    w.advance(1);
    let limits = w
        .device
        .sign_limits(&w.node.public_key(), "alice", "item", rules, w.now())
        .unwrap();
    w.node.set_limits(&limits)
}

fn per_day(max: &str) -> LimitRule {
    LimitRule {
        currency: "EUR".into(),
        merchant: None,
        per_payment: None,
        per_day: Some(max.into()),
        per_month: None,
    }
}

#[test]
fn a_payment_no_limit_covers_waits_with_the_amount_the_contract_checked() {
    let w = shop_world();
    let mut t = Script::default();
    let summary = approval_of(w.run("charge", charge("3000"), &mut t));
    assert_eq!(t.sent.len(), 0);
    assert_eq!(
        summary.amount,
        Some(Amount {
            value: "30.00".into(),
            currency: "EUR".into()
        })
    );
    assert_eq!(summary.origin.as_deref(), Some("https://pay.example"));
    assert!(
        summary
            .lines
            .iter()
            .any(|l| l.contains("no spending limit"))
    );

    // An amount that is not an integer of minor units is refused before anything happens.
    for bad in ["30.5", "3e3"] {
        let refused = w.run("charge", charge(bad), &mut t);
        assert!(
            matches!(refused, Err(Error::RequestInvalid { .. })),
            "a malformed amount is refused"
        );
    }
    assert_eq!(t.sent.len(), 0);
}

#[test]
fn an_approval_cannot_be_replayed_for_a_different_amount() {
    let w = shop_world();
    let mut t = Script::default();
    let small = approval_of(w.run("charge", charge("3000"), &mut t));
    let approval = w.device.approve(&small, w.now()).unwrap();
    w.node.approve(&approval).unwrap();
    assert_eq!(status_of(w.resume("charge", small.id, &mut t)), 200);
    assert_eq!(t.sent.len(), 1);

    let large = approval_of(w.run("charge", charge("90000"), &mut t));
    // The old approval: its id is spent.
    assert_eq!(w.node.approve(&approval), Err(Error::ParkedUnknown));
    // An approval of the new id over the old amount: not the summary the node built.
    let mut forged = large.clone();
    forged.amount = small.amount.clone();
    let forged = w.device.approve(&forged, w.now()).unwrap();
    assert!(matches!(
        w.node.approve(&forged),
        Err(Error::ApprovalInvalid { .. })
    ));
    approval_of(w.resume("charge", large.id, &mut t));
    assert_eq!(t.sent.len(), 1);
}

#[test]
fn splitting_a_payment_does_not_get_around_a_limit() {
    let w = shop_world();
    let mut t = Script::default();
    set_limits(&w, vec![per_day("50")]).unwrap();
    // 30 EUR: within the limit, sent at once.
    assert_eq!(status_of(w.run("charge", charge("3000"), &mut t)), 200);
    // 30 EUR more the same day: 60 is above 50, so it waits.
    let summary = approval_of(w.run("charge", charge("3000"), &mut t));
    assert!(
        summary
            .lines
            .iter()
            .any(|l| l.contains("per day") && l.contains("30 spent before")),
        "the summary says why"
    );
    assert_eq!(t.sent.len(), 1);
    // 20 EUR: exactly at the limit, sent.
    assert_eq!(status_of(w.run("charge", charge("2000"), &mut t)), 200);
    // Even one cent more waits.
    approval_of(w.run("charge", charge("1"), &mut t));
    assert_eq!(t.sent.len(), 2);
    // A day later the window has moved on.
    w.advance(24 * 60 * 60 * 1000);
    assert_eq!(status_of(w.run("charge", charge("3000"), &mut t)), 200);
    assert_eq!(w.events(|e| matches!(e, Event::Spend { .. })), 3);
}

#[test]
fn limits_are_per_merchant_signed_by_the_owner_and_survive_a_restart() {
    let w = shop_world();
    let mut t = Script::default();
    // A rule for another merchant does not cover this one.
    let mut elsewhere = per_day("1000");
    elsewhere.merchant = Some("https://other.example".into());
    set_limits(&w, vec![elsewhere]).unwrap();
    approval_of(w.run("charge", charge("100"), &mut t));

    // Limits signed by a key the node does not know for the owner, for another node, or older
    // than the ones it holds, are refused.
    let stranger = DeviceKey::generate()
        .sign_limits(
            &w.node.public_key(),
            "alice",
            "item",
            vec![per_day("1")],
            w.now(),
        )
        .unwrap();
    assert_eq!(w.node.set_limits(&stranger), Err(Error::GrantDenied));
    let other_node = NodeKey::generate().public();
    let misrouted = w
        .device
        .sign_limits(&other_node, "alice", "item", vec![per_day("1")], w.now())
        .unwrap();
    assert!(matches!(
        w.node.set_limits(&misrouted),
        Err(Error::LimitsInvalid { .. })
    ));
    let older = w
        .device
        .sign_limits(
            &w.node.public_key(),
            "alice",
            "item",
            vec![per_day("1000")],
            NOW,
        )
        .unwrap();
    assert!(matches!(
        w.node.set_limits(&older),
        Err(Error::LimitsInvalid { .. })
    ));

    // Within a limit for this merchant: spent, then counted again after a restart.
    let mut here = per_day("50");
    here.merchant = Some("https://pay.example".into());
    set_limits(&w, vec![here]).unwrap();
    assert_eq!(status_of(w.run("charge", charge("4000"), &mut t)), 200);
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
    // 40 counted before the restart, 20 now: above 50, so it waits.
    approval_of(restarted.run("charge", charge("2000"), &mut t));
    assert_eq!(restarted.events(|e| matches!(e, Event::Spend { .. })), 0);
}

// --- Sessions --------------------------------------------------------------------------------

fn site(renew: Renew) -> impl Fn(&CallerKey, &CallerKey) -> Policy {
    move |agent, _| {
        Policy::new()
            .with_field(FieldSpec::secret("password"))
            .with_field(
                FieldSpec::secret("session")
                    .optional()
                    .session(SessionRule {
                        lifetime_ms: 60 * 60 * 1000,
                        expires: "session_expires".into(),
                        renew: renew.clone(),
                    }),
            )
            .with_field(FieldSpec::public("session_expires").optional())
            .with_operation(
                Operation::https("login", Destination::https("site.example"))
                    .then(
                        Send::fixed(Method::Post, "/login")
                            .inject(Injection::body("pw={{password}}")),
                    )
                    .then(
                        Receive::response()
                            .capture(Capture::new(Source::cookie("sid"), Store::field("session"))),
                    )
                    .then(Return::status()),
            )
            .with_operation(
                Operation::https("fetch", Destination::https("site.example"))
                    .then(
                        Send::fixed(Method::Get, "/data")
                            .inject(Injection::header("Cookie", "sid={{session}}")),
                    )
                    .then(Return::status()),
            )
            .with_caller(Caller::new("agent", agent.public(), ["fetch"]))
    }
}

#[test]
fn a_lapsed_session_is_renewed_by_its_login_operation_first() {
    let mut w = world(
        site(Renew::Operation {
            name: "login".into(),
        }),
        &[("password", "correct horse battery")],
    );
    let mut t = Script::default().reply(200, "Set-Cookie: sid=s3ss10n-one\r\n", "{}");
    let call = w.call_as(&w.agent, "agent", &w.record, "fetch", Body::http_fixed());
    let outcome = w.node.run(&call, &mut t);
    assert_eq!(status_of(outcome.result), 200);
    // The login ran first; its cookie went into the request that was asked for.
    assert_eq!(t.sent.len(), 2);
    assert!(contains(&t.sent[0], b"/login"));
    assert!(contains(&t.sent[1], b"sid=s3ss10n-one"));
    w.record = outcome
        .record
        .expect("the session is sealed into the record");

    // Within its lifetime the session is used as is.
    let mut t = Script::default();
    assert_eq!(status_of(w.run("fetch", Body::http_fixed(), &mut t)), 200);
    assert_eq!(t.sent.len(), 1);

    // An hour later it is renewed again.
    w.advance(60 * 60 * 1000);
    let mut t = Script::default().reply(200, "Set-Cookie: sid=s3ss10n-two\r\n", "{}");
    assert_eq!(status_of(w.run("fetch", Body::http_fixed(), &mut t)), 200);
    assert_eq!(t.sent.len(), 2);
    assert!(contains(&t.sent[1], b"sid=s3ss10n-two"));
}

#[test]
fn a_session_the_owner_renews_is_refused_until_the_device_seals_a_new_one() {
    let mut w = world(
        site(Renew::Owner {}),
        &[("password", "correct horse battery")],
    );
    let mut t = Script::default();
    assert_eq!(
        w.run("fetch", Body::http_fixed(), &mut t),
        Err(Error::SessionExpired {
            field: "session".into()
        })
    );
    assert_eq!(t.sent.len(), 0);

    // On the owner's device: the new session, sealed one generation later with its expiry.
    let mut values = Fields::new();
    values.insert("session", b"s3ss10n-owner".to_vec()).unwrap();
    w.record = w.record.update(&user(), &values, w.now()).unwrap();
    assert_eq!(w.record.generation, 2);
    assert_eq!(status_of(w.run("fetch", Body::http_fixed(), &mut t)), 200);
    assert!(contains(&t.sent[0], b"sid=s3ss10n-owner"));
}

#[test]
fn the_node_caps_all_waiting_operations_across_owners() {
    let clock = Arc::new(AtomicU64::new(NOW));
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SharedClock(clock));
    let mut t = Script::default();
    let owners = MAX_PARKED / MAX_PARKED_PER_OWNER;
    for i in 0..=owners {
        let owner = format!("owner{i}");
        let device = DeviceKey::generate();
        let agent = CallerKey::generate();
        let mut fields = Fields::new();
        fields.insert("password", b"pw".to_vec()).unwrap();
        let signed = device
            .sign_policy(bank(&agent, &CallerKey::generate()))
            .unwrap();
        let record = Record::seal(&user(), "item", &owner, signed, &fields).unwrap();
        let terms = GrantTerms::at(&owner, NOW, Duration::from_secs(3600)).pin(&record);
        node.grant(&device.grant(&user(), &node.identity(), terms).unwrap())
            .unwrap();
        let tries = if i == owners { 1 } else { MAX_PARKED_PER_OWNER };
        for _ in 0..tries {
            let call = agent
                .sign_call_at(
                    "agent",
                    &node.public_key(),
                    record.clone(),
                    "login",
                    Body::http_fixed(),
                    NOW,
                )
                .unwrap();
            let result = node.run(&call, &mut t).result;
            if i == owners {
                assert_eq!(result, Err(Error::ParkedFull));
            } else {
                challenge_of(result);
            }
        }
    }
    assert_eq!(node.waiting(), MAX_PARKED);
    assert_eq!(t.sent.len(), MAX_PARKED);
}
