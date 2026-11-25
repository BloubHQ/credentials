//! Typed items on a node: `describe` returns public fields and masked projections and never a
//! secret field, any listed caller may ask and the node logs it, and every use checks the
//! values against the kind with the node's clock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use engine::Error;
use engine::call::{Body, Output, SignedCall};
use engine::caller::DESCRIBE;
use engine::egress::{ClientIdentity, Transport};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::item::{Disclosure, ItemBinding};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink, verify_chain};
use engine::node::{Clock, Node};
use engine::policy::{
    Caller, Destination, FieldSpec, Injection, Method, Operation, Policy, Return, Send,
};
use engine::record::Record;

/// 2026-11-25T00:00:00Z.
const NOW: u64 = 1_795_564_800_000;
/// 2026-12-01T00:00:00Z: after a card of 11/26.
const DECEMBER: u64 = 1_796_083_200_000;

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Counts what it would send; sends nothing.
#[derive(Default)]
struct Counting(usize);

impl Transport for Counting {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.0 += 1;
        Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec())
    }
}

struct Setup {
    node: Node<MemorySink, SharedClock>,
    clock: Arc<AtomicU64>,
    record: Record,
    agent: CallerKey,
}

fn card_policy(agent: &CallerKey, typed: bool) -> Policy {
    let policy = Policy::new()
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
        .with_caller(Caller::new("agent", agent.public(), ["pay"]));
    if typed {
        policy.with_item(ItemBinding::reviewed("card"))
    } else {
        policy
    }
}

fn setup(typed: bool) -> Setup {
    setup_with(typed, "12/27")
}

fn setup_with(typed: bool, expiry: &str) -> Setup {
    let clock = Arc::new(AtomicU64::new(NOW));
    let device = DeviceKey::generate();
    let user = [5u8; 32];
    let agent = CallerKey::generate();
    let mut values = Fields::new();
    for (name, value) in [
        ("number", "4242424242424242"),
        ("expiry", expiry),
        ("cvc", "737"),
        ("holder", "Jane Doe"),
    ] {
        values.insert(name, value.as_bytes().to_vec()).unwrap();
    }
    let signed = device.sign_policy(card_policy(&agent, typed)).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user.clone()),
        "card",
        "alice",
        signed,
        &values,
    )
    .unwrap();
    let node = Node::new(
        NodeKey::generate(),
        MemorySink::new(),
        SharedClock(clock.clone()),
    );
    let terms = GrantTerms::at("alice", NOW, Duration::from_secs(10 * 24 * 3600)).pin(&record);
    node.grant(
        &device
            .grant(
                &UserKey::from_bytes(&mut user.clone()),
                &node.identity(),
                terms,
            )
            .unwrap(),
    )
    .unwrap();
    Setup {
        node,
        clock,
        record,
        agent,
    }
}

fn describe_call(s: &Setup, key: &CallerKey, name: &str) -> SignedCall {
    key.sign_call_at(
        name,
        &s.node.public_key(),
        s.record.clone(),
        DESCRIBE,
        Body::describe(),
        s.clock.load(Ordering::SeqCst),
    )
    .unwrap()
}

fn describes(s: &Setup) -> usize {
    s.node.with_sink(|sink| {
        sink.entries()
            .iter()
            .filter(|e| matches!(e.entry.event, Event::Describe { .. }))
            .count()
    })
}

#[test]
fn describe_returns_the_masked_view_and_is_logged() {
    let s = setup(true);
    let call = describe_call(&s, &s.agent, "agent");
    let outcome = s.node.run(&call, &mut Counting::default());
    let Output::Describe(description) = outcome.result.unwrap() else {
        panic!("a description");
    };
    assert_eq!(description.kind, "card");
    let fields: Vec<(&str, Disclosure, &str)> = description
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.disclosure, f.value.as_str()))
        .collect();
    assert_eq!(
        fields,
        [
            (
                "number",
                Disclosure::Masked,
                "visa \u{2022}\u{2022}\u{2022}\u{2022}4242"
            ),
            ("expiry", Disclosure::Masked, "2027"),
            ("holder", Disclosure::Public, "Jane Doe"),
        ]
    );
    // No secret value in any form in what goes back.
    let json = serde_json::to_string(&description).unwrap();
    for secret in ["4242424242424242", "12/27", "737"] {
        assert!(
            !json.contains(secret),
            "a secret value is in the description"
        );
    }
    assert_eq!(describes(&s), 1);
    let entries = s.node.with_sink(|sink| sink.entries().to_vec());
    verify_chain(&entries, &s.node.public_key()).unwrap();
    let last = &entries.last().unwrap().entry;
    assert_eq!(last.caller, "agent");
    assert_eq!(last.record_id, "card");

    // The same authorization again is a replay.
    let again = s.node.run(&call, &mut Counting::default());
    assert!(matches!(again.result, Err(Error::CallerInvalid { .. })));
    assert_eq!(describes(&s), 1);
}

#[test]
fn describe_is_for_callers_of_the_policy_only() {
    let s = setup(true);
    // A key the policy does not list, under the listed name.
    let stranger = CallerKey::generate();
    let call = describe_call(&s, &stranger, "agent");
    assert!(matches!(
        s.node.run(&call, &mut Counting::default()).result,
        Err(Error::CallerInvalid { .. })
    ));
    // A name the policy does not list.
    let call = describe_call(&s, &stranger, "stranger");
    assert!(matches!(
        s.node.run(&call, &mut Counting::default()).result,
        Err(Error::CallerDenied { .. })
    ));
    assert_eq!(describes(&s), 0);
}

#[test]
fn a_describe_authorization_is_not_one_for_an_operation() {
    let s = setup(true);
    // Signed for describe, sent as the operation `pay`: the signature names another
    // operation and payload.
    let mut call = describe_call(&s, &s.agent, "agent");
    call.operation = "pay".into();
    call.body = Body::http_fixed();
    let mut transport = Counting::default();
    assert!(s.node.run(&call, &mut transport).result.is_err());
    assert_eq!(transport.0, 0);
    // A describe body under another operation name.
    let call = s
        .agent
        .sign_call_at(
            "agent",
            &s.node.public_key(),
            s.record.clone(),
            "pay",
            Body::describe(),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        s.node.run(&call, &mut Counting::default()).result,
        Err(Error::OperationUnknown { .. })
    ));
    // The describe name with another body.
    let call = s
        .agent
        .sign_call_at(
            "agent",
            &s.node.public_key(),
            s.record.clone(),
            DESCRIBE,
            Body::derive(b""),
            NOW,
        )
        .unwrap();
    assert!(matches!(
        s.node.run(&call, &mut Counting::default()).result,
        Err(Error::OperationUnknown { .. })
    ));
    assert_eq!(describes(&s), 0);
    // In JSON the body is `{"kind": "describe"}`, and nothing else beside the tag.
    let json = serde_json::to_value(describe_call(&s, &s.agent, "agent")).unwrap();
    assert_eq!(json["body"], serde_json::json!({"kind": "describe"}));
    let mut junk = json.clone();
    junk["body"]["field"] = "cvc".into();
    assert!(serde_json::from_value::<SignedCall>(junk).is_err());
}

#[test]
fn a_record_without_a_kind_describes_nothing() {
    let s = setup(false);
    let call = describe_call(&s, &s.agent, "agent");
    assert_eq!(
        s.node.run(&call, &mut Counting::default()).result,
        Err(Error::NotAnItem)
    );
    assert_eq!(describes(&s), 0);
}

#[test]
fn an_expired_card_is_refused_before_anything_is_sent() {
    let s = setup_with(true, "11/26");
    let pay = |s: &Setup, transport: &mut Counting| {
        let call = s
            .agent
            .sign_call_at(
                "agent",
                &s.node.public_key(),
                s.record.clone(),
                "pay",
                Body::http_fixed(),
                s.clock.load(Ordering::SeqCst),
            )
            .unwrap();
        s.node.run(&call, transport).result
    };
    let mut transport = Counting::default();
    pay(&s, &mut transport).unwrap();
    assert_eq!(transport.0, 1);
    let entries = s.node.with_sink(|sink| sink.entries().len());

    // Six days later the card has expired; the grant has not.
    s.clock.store(DECEMBER, Ordering::SeqCst);
    let mut transport = Counting::default();
    assert_eq!(
        pay(&s, &mut transport),
        Err(Error::FieldInvalid {
            field: "expiry".into(),
            rule: "the card has expired"
        })
    );
    assert_eq!(transport.0, 0);
    assert_eq!(s.node.with_sink(|sink| sink.entries().len()), entries);
}

#[test]
fn a_typed_record_is_checked_when_sealed() {
    let device = DeviceKey::generate();
    let agent = CallerKey::generate();
    let signed = device.sign_policy(card_policy(&agent, true)).unwrap();
    let user = UserKey::from_bytes(&mut [5u8; 32]);
    let mut values = Fields::new();
    values
        .insert("number", b"4242424242424241".to_vec())
        .unwrap();
    values.insert("expiry", b"12/27".to_vec()).unwrap();
    values.insert("cvc", b"737".to_vec()).unwrap();
    assert_eq!(
        Record::seal(&user, "card", "alice", signed, &values).unwrap_err(),
        Error::FieldInvalid {
            field: "number".into(),
            rule: "the Luhn checksum does not hold"
        }
    );
}
