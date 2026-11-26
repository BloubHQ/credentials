//! Owner controls (`docs/design.md`, section 8b): delegation to another owner's callers,
//! emergency access with a waiting period, and credential vending, end to end through a node.
//! Every behaviour below is policy and owner data; no test needs code that knows a site.
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
use engine::delegation::{
    Change, Delegation, DelegationTerms, MAX_LIFETIME_MS, MIN_WAIT_MS, check_narrower,
};
use engine::egress::{ClientIdentity, Transport};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink, SignedEntry, verify_chain};
use engine::node::{Clock, Node};
use engine::policy::summary::FlagCode;
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy, summarize};
use engine::record::Record;
use serde_json::{Value, json};

const OWNER: &str = "alice";
const DELEGATE: &str = "bob";
const START: u64 = 1_800_000_000_000;
const HOUR: u64 = 60 * 60 * 1000;
const TOKEN: &[u8] = b"tok_live_owner_controls_7Hq2";

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers every request with `reply` and keeps what it was asked to send.
struct Site {
    reply: Vec<u8>,
    sent: Vec<Vec<u8>>,
}

impl Site {
    fn ok() -> Self {
        Self::answering(200, "{\"id\": 7}")
    }

    fn answering(status: u16, body: &str) -> Self {
        Self {
            reply: format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
            sent: Vec::new(),
        }
    }

    fn carried_token(&self) -> bool {
        self.sent
            .iter()
            .any(|w| w.windows(TOKEN.len()).any(|x| x == TOKEN))
    }
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
        Ok(self.reply.clone())
    }
}

fn operation(value: Value) -> Operation {
    serde_json::from_value(value).unwrap()
}

/// An HTTPS operation that sends a fixed request with the token to `host`, and returns what
/// `ret` says.
fn fetch(name: &str, host: &str, ret: Value) -> Operation {
    operation(json!({"name": name, "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": host, "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/v1/me"},
         "inject": [{"target": {"kind": "header", "name": "Authorization"},
                     "template": "Bearer {{token}}"}]},
        ret
    ]}))
}

fn mac() -> Operation {
    operation(json!({"name": "mac", "input": {"raw": {"max_len": 64}},
                     "steps": [{"do": "return", "template": "{{ hex(hmac_sha256(token, $input)) }}"}]}))
}

fn caller(name: &str, key: &CallerKey, operations: &[&str]) -> Caller {
    Caller::new(name, key.public(), operations.iter().copied())
}

struct World {
    clock: Arc<AtomicU64>,
    node_key: [u8; 32],
    node: Node<MemorySink, SharedClock>,
    device: DeviceKey,
    user_key: [u8; 32],
    owner_app: CallerKey,
    agent: CallerKey,
    record: Record,
}

fn base_policy(owner_app: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_operation(fetch("read", "api.example.com", json!({"do": "return"})))
        .with_operation(fetch(
            "detail",
            "api.example.com",
            json!({"do": "return", "response": {"body": {"json": ["/id"]}}}),
        ))
        .with_operation(mac())
        .with_caller(caller("app", owner_app, &["read", "detail", "mac"]))
}

impl World {
    fn new() -> Self {
        let clock = Arc::new(AtomicU64::new(START));
        let node_key = [3u8; 32];
        let node = Node::new(
            NodeKey::from_bytes(&mut node_key.clone()),
            MemorySink::new(),
            SharedClock(clock.clone()),
        );
        let device = DeviceKey::generate();
        let user_key = [9u8; 32];
        let owner_app = CallerKey::generate();
        let agent = CallerKey::generate();
        let mut values = Fields::new();
        values.insert("token", TOKEN.to_vec()).unwrap();
        let record = Record::seal(
            &UserKey::from_bytes(&mut user_key.clone()),
            "api",
            OWNER,
            device.sign_policy(base_policy(&owner_app)).unwrap(),
            &values,
        )
        .unwrap();
        let world = Self {
            clock,
            node_key,
            node,
            device,
            user_key,
            owner_app,
            agent,
            record,
        };
        world.grant();
        world
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    fn user_key(&self) -> UserKey {
        UserKey::from_bytes(&mut self.user_key.clone())
    }

    fn grant(&self) {
        self.advance(1);
        let terms = GrantTerms::at(OWNER, self.now(), Duration::from_secs(3600)).pin(&self.record);
        let sealed = self
            .device
            .grant(&self.user_key(), &self.node.identity(), terms)
            .unwrap();
        self.node.grant(&sealed).unwrap();
    }

    /// The delegated policy most tests use: `read` only, for the delegate's caller `agent`.
    fn narrow(&self) -> Policy {
        Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(fetch("read", "api.example.com", json!({"do": "return"})))
            .with_caller(caller("agent", &self.agent, &["read"]))
    }

    fn terms(&self, policy: Policy, wait_ms: u64) -> DelegationTerms {
        self.advance(1);
        DelegationTerms {
            delegate: DELEGATE.into(),
            policy,
            wait_ms,
            expires_ms: self.now() + 30 * 24 * HOUR,
            issued_ms: self.now(),
        }
    }

    fn delegation(&self, policy: Policy, wait_ms: u64) -> Delegation {
        self.device
            .delegate(
                &self.user_key(),
                &self.node.identity(),
                &self.record,
                self.terms(policy, wait_ms),
            )
            .unwrap()
    }

    fn delegate(&self, policy: Policy, wait_ms: u64) -> Delegation {
        let delegation = self.delegation(policy, wait_ms);
        self.node.delegate(&delegation, &self.record).unwrap();
        delegation
    }

    fn change(&self, delegation: &Delegation, change: Change) -> engine::Result<()> {
        self.advance(1);
        let signed = self
            .device
            .change_delegation(
                &self.node.public_key(),
                OWNER,
                "api",
                delegation.id,
                change,
                self.now(),
            )
            .unwrap();
        self.node.change_delegation(&signed)
    }

    fn delegated_call(&self, operation: &str, body: Body, id: [u8; 16]) -> SignedCall {
        self.agent
            .sign_delegated_call_at(
                "agent",
                &self.node.public_key(),
                self.record.clone(),
                operation,
                body,
                self.now(),
                Some(id),
            )
            .unwrap()
    }

    fn run(&self, call: &SignedCall, site: &mut Site) -> engine::Result<Output> {
        let outcome = self.node.run(call, site);
        assert!(outcome.record.is_none(), "a delegate never seals a record");
        outcome.result
    }

    fn entries(&self) -> Vec<SignedEntry> {
        self.node.with_sink(|sink| sink.entries().to_vec())
    }

    fn count(&self, owner: &str, pick: impl Fn(&Event) -> bool) -> usize {
        self.entries()
            .iter()
            .filter(|e| e.entry.owner == owner && pick(&e.entry.event))
            .count()
    }
}

fn status(output: engine::Result<Output>) -> u16 {
    match output {
        Ok(Output::Http(response)) => response.status(),
        other => panic!("not a response: {:?}", other.map(|_| ()).err()),
    }
}

// --- Delegation ------------------------------------------------------------------------------

#[test]
fn a_delegate_uses_the_item_under_the_narrower_policy_and_both_logs_say_so() {
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    let mut site = Site::ok();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert_eq!(status(w.run(&call, &mut site)), 200);
    assert!(site.carried_token(), "the site got the owner's token");

    assert_eq!(w.count(OWNER, |e| matches!(e, Event::Delegate { .. })), 1);
    assert_eq!(
        w.count(DELEGATE, |e| matches!(e, Event::Delegated { .. })),
        1
    );
    let uses: Vec<_> = w
        .entries()
        .into_iter()
        .filter(|e| matches!(e.entry.event, Event::Use { .. }))
        .collect();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].entry.owner, OWNER);
    assert_eq!(uses[0].entry.caller, "bob/agent");
    verify_chain(&w.entries(), &w.node.public_key()).unwrap();
}

#[test]
fn a_delegate_cannot_exceed_its_delegation() {
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    let mut site = Site::ok();
    // An operation of the record the delegation does not give.
    let call = w.delegated_call("detail", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::OperationUnknown { .. })
    ));
    let call = w.delegated_call("mac", Body::derive(b"x"), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::OperationUnknown { .. })
    ));
    // The same caller without the delegation is nobody the record's policy knows.
    let plain = w
        .agent
        .sign_call_at(
            "agent",
            &w.node.public_key(),
            w.record.clone(),
            "read",
            Body::http_fixed(),
            w.now(),
        )
        .unwrap();
    assert!(matches!(
        w.run(&plain, &mut site),
        Err(Error::CallerDenied { .. })
    ));
    // A delegation id the node does not hold.
    let call = w.delegated_call("read", Body::http_fixed(), [0xAA; 16]);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationUnknown)
    ));
    // The owner's caller cannot borrow the delegation either: it is not in its policy.
    let borrowed = w
        .owner_app
        .sign_delegated_call_at(
            "app",
            &w.node.public_key(),
            w.record.clone(),
            "read",
            Body::http_fixed(),
            w.now(),
            Some(d.id),
        )
        .unwrap();
    assert!(matches!(
        w.run(&borrowed, &mut site),
        Err(Error::CallerDenied { .. })
    ));
    assert!(site.sent.is_empty(), "nothing reached the site");
}

#[test]
fn a_delegated_call_cannot_be_replayed_or_moved_to_another_delegation() {
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    let other = w.delegate(w.narrow(), 0);
    let mut site = Site::ok();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert_eq!(status(w.run(&call, &mut site)), 200);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::CallerInvalid { .. })
    ));
    // The signature covers the delegation id.
    let mut moved = w.delegated_call("read", Body::http_fixed(), d.id);
    moved.auth.delegation = Some(other.id);
    assert!(matches!(
        w.run(&moved, &mut site),
        Err(Error::CallerInvalid { .. })
    ));
    // Dropping the id makes it a call of a caller the record does not list.
    let mut dropped = w.delegated_call("read", Body::http_fixed(), d.id);
    dropped.auth.delegation = None;
    assert!(matches!(
        w.run(&dropped, &mut site),
        Err(Error::CallerDenied { .. })
    ));
    assert_eq!(site.sent.len(), 1);
}

#[test]
fn a_wider_delegated_policy_is_refused() {
    let w = World::new();
    let base = base_policy(&w.owner_app);
    let with_agent = |op: Operation| {
        Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(op)
            .with_caller(caller("agent", &w.agent, &["read"]))
    };
    let wider = [
        (
            "another destination",
            with_agent(fetch("read", "evil.example.com", json!({"do": "return"}))),
        ),
        (
            "the whole body back",
            with_agent(fetch(
                "read",
                "api.example.com",
                json!({"do": "return", "response": {"body": "all"}}),
            )),
        ),
        (
            "an operation the record lacks",
            with_agent(fetch("other", "api.example.com", json!({"do": "return"})))
                .with_caller(caller("agent2", &w.agent, &["other"])),
        ),
        (
            "a field made public",
            Policy::new()
                .with_field(FieldSpec::public("token"))
                .with_operation(fetch("read", "api.example.com", json!({"do": "return"})))
                .with_caller(caller("agent", &w.agent, &["read"])),
        ),
    ];
    for (what, policy) in wider {
        let refused = check_narrower(&base, &policy).is_err()
            && w.device
                .delegate(
                    &w.user_key(),
                    &w.node.identity(),
                    &w.record,
                    w.terms(policy, 0),
                )
                .is_err();
        assert!(refused, "{what}");
    }
    // A delegated policy that would seal a new generation of the owner's record.
    let capturing = Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_operation(operation(json!({"name": "read", "steps": [
            {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
            {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/v1/me"}},
            {"do": "receive", "capture": [{"source": {"from": "json", "pointer": "/t"},
                                           "into": {"kind": "field", "name": "token"}}]},
            {"do": "return"}]})))
        .with_caller(caller("agent", &w.agent, &["read"]));
    assert!(matches!(
        check_narrower(&base, &capturing),
        Err(Error::DelegationInvalid { .. })
    ));
    // Narrower is fine: an approval added.
    let mut approving = w.narrow();
    approving.operations[0].approval = true;
    check_narrower(&base, &approving).unwrap();
}

#[test]
fn the_node_refuses_tampered_stale_or_foreign_delegations() {
    let w = World::new();
    // The delegated policy swapped after signing: the signature no longer verifies.
    let mut swapped = w.delegation(w.narrow(), 0);
    swapped.policy = w
        .device
        .sign_policy(base_policy(&w.agent).with_caller(caller("agent", &w.agent, &["read"])))
        .unwrap_or_else(|_| swapped.policy.clone());
    swapped.wait_ms = 0;
    swapped.expires_ms += 1;
    assert!(w.node.delegate(&swapped, &w.record).is_err());
    // Another node.
    let other = Node::new(
        NodeKey::generate(),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
    );
    let foreign = w
        .device
        .delegate(
            &w.user_key(),
            &other.identity(),
            &w.record,
            w.terms(w.narrow(), 0),
        )
        .unwrap();
    assert!(matches!(
        w.node.delegate(&foreign, &w.record),
        Err(Error::DelegationInvalid { .. })
    ));
    // A device the node does not know for the owner.
    let stranger = DeviceKey::generate();
    let unknown = stranger.delegate(
        &w.user_key(),
        &w.node.identity(),
        &w.record,
        w.terms(w.narrow(), 0),
    );
    // The record's policy was signed by the owner's device, so the stranger's delegation
    // names it but the node does not know the stranger.
    let unknown = unknown.unwrap();
    assert!(matches!(
        w.node.delegate(&unknown, &w.record),
        Err(Error::GrantDenied)
    ));
    // Replayed: the same delegation again, and an older one after a newer act.
    let first = w.delegation(w.narrow(), 0);
    let second = w.delegation(w.narrow(), 0);
    w.node.delegate(&second, &w.record).unwrap();
    assert!(w.node.delegate(&first, &w.record).is_err());
    assert!(w.node.delegate(&second, &w.record).is_err());
    // Too long, or a waiting period out of bounds.
    let mut long = w.terms(w.narrow(), 0);
    long.expires_ms = long.issued_ms + MAX_LIFETIME_MS + 1;
    assert!(
        w.device
            .delegate(&w.user_key(), &w.node.identity(), &w.record, long)
            .is_err()
    );
    let short_wait = w.terms(w.narrow(), MIN_WAIT_MS - 1);
    assert!(
        w.device
            .delegate(&w.user_key(), &w.node.identity(), &w.record, short_wait)
            .is_err()
    );
}

#[test]
fn a_delegation_ends_on_revoke_expiry_policy_change_and_the_owners_revocation() {
    let mut site = Site::ok();
    // Revoked by a device of the owner.
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    w.change(&d, Change::Revoke).unwrap();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationUnknown)
    ));
    assert_eq!(
        w.count(OWNER, |e| matches!(
            e,
            Event::Undelegate { revoke: true, .. }
        )),
        1
    );
    assert_eq!(
        w.count(DELEGATE, |e| matches!(
            e,
            Event::Undelegate { revoke: true, .. }
        )),
        1
    );

    // Lapsed.
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    w.advance(31 * 24 * HOUR);
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationUnknown)
    ));

    // The owner changed the record's policy: the delegation was checked against the old one.
    let mut w = World::new();
    let d = w.delegate(w.narrow(), 0);
    let mut changed = base_policy(&w.owner_app);
    changed.operations[0].approval = true;
    w.record = w
        .record
        .rewrap(&w.user_key(), w.device.sign_policy(changed).unwrap())
        .unwrap();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationUnknown)
    ));

    // The owner revoked the node's grant: every key of the owner goes, delegations too.
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    w.advance(1);
    let revocation = w
        .device
        .revoke(OWNER, &w.node.public_key(), w.now())
        .unwrap();
    w.node.revoke(&revocation).unwrap();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationUnknown)
    ));

    // The device that signed it was withdrawn.
    let w = World::new();
    let second = DeviceKey::generate();
    w.advance(1);
    let endorsement = w
        .device
        .endorse(OWNER, &w.node.public_key(), &second.public(), w.now())
        .unwrap();
    w.node.add_device(&endorsement).unwrap();
    let d = w.delegate(w.narrow(), 0);
    w.advance(1);
    let retirement = second
        .retire(OWNER, &w.node.public_key(), &w.device.public(), w.now())
        .unwrap();
    w.node.retire_device(&retirement).unwrap();
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(w.run(&call, &mut site).is_err());
    assert!(site.sent.is_empty());
}

#[test]
fn a_delegation_works_while_the_owner_holds_no_grant() {
    let w = World::new();
    let d = w.delegate(w.narrow(), 0);
    // The owner's grant lapses (an hour); the delegation carries the record key itself.
    w.advance(2 * HOUR);
    let mut site = Site::ok();
    let own = w
        .owner_app
        .sign_call_at(
            "app",
            &w.node.public_key(),
            w.record.clone(),
            "read",
            Body::http_fixed(),
            w.now(),
        )
        .unwrap();
    assert!(matches!(w.run(&own, &mut site), Err(Error::GrantExpired)));
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert_eq!(status(w.run(&call, &mut site)), 200);
}

// --- Emergency access ------------------------------------------------------------------------

#[test]
fn emergency_access_opens_only_after_the_wait_and_the_owner_can_cancel_it() {
    let w = World::new();
    let wait = 24 * HOUR;
    let d = w.delegate(w.narrow(), wait);
    let mut site = Site::ok();
    // Cancelling before any request is refused.
    assert!(matches!(
        w.change(&d, Change::Cancel),
        Err(Error::DelegationInvalid { .. })
    ));
    // The first call starts the wait and is refused; it is logged under both owners.
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    let opens = match w.run(&call, &mut site) {
        Err(Error::DelegationWaiting { opens_ms }) => opens_ms,
        other => panic!("not waiting: {:?}", other.map(|_| ())),
    };
    assert_eq!(opens, w.now() + wait);
    assert_eq!(
        w.count(OWNER, |e| matches!(e, Event::AccessRequest { .. })),
        1
    );
    assert_eq!(
        w.count(DELEGATE, |e| matches!(e, Event::AccessRequest { .. })),
        1
    );
    // During the wait: refused, with the same opening, and no new request.
    w.advance(wait - 1000);
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationWaiting { opens_ms }) if opens_ms == opens
    ));
    // The owner cancels from a device: the next call waits the whole period again.
    w.change(&d, Change::Cancel).unwrap();
    w.advance(2000);
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    let reopened = match w.run(&call, &mut site) {
        Err(Error::DelegationWaiting { opens_ms }) => opens_ms,
        other => panic!("not waiting: {:?}", other.map(|_| ())),
    };
    assert_eq!(reopened, w.now() + wait);
    assert!(
        site.sent.is_empty(),
        "nothing reached the site while waiting"
    );
    // Nobody cancels: after the wait, access is open.
    w.advance(wait);
    let call = w.delegated_call("read", Body::http_fixed(), d.id);
    assert_eq!(status(w.run(&call, &mut site)), 200);
}

#[test]
fn a_restarted_node_keeps_delegations_requests_and_revocations() {
    let w = World::new();
    let open = w.delegate(w.narrow(), 0);
    let waiting = w.delegate(w.narrow(), 2 * HOUR);
    let revoked = w.delegate(w.narrow(), 0);
    w.change(&revoked, Change::Revoke).unwrap();
    let mut site = Site::ok();
    let call = w.delegated_call("read", Body::http_fixed(), waiting.id);
    assert!(matches!(
        w.run(&call, &mut site),
        Err(Error::DelegationWaiting { .. })
    ));
    let restarted = Node::restore(
        NodeKey::from_bytes(&mut w.node_key.clone()),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
        &w.entries(),
    )
    .unwrap();
    w.advance(10);
    let sign = |id: [u8; 16]| {
        w.agent
            .sign_delegated_call_at(
                "agent",
                &restarted.public_key(),
                w.record.clone(),
                "read",
                Body::http_fixed(),
                w.now(),
                Some(id),
            )
            .unwrap()
    };
    assert_eq!(status(restarted.run(&sign(open.id), &mut site).result), 200);
    assert!(matches!(
        restarted.run(&sign(revoked.id), &mut site).result,
        Err(Error::DelegationUnknown)
    ));
    // The request made before the restart still counts: no new wait, and it opens on time.
    assert!(matches!(
        restarted.run(&sign(waiting.id), &mut site).result,
        Err(Error::DelegationWaiting { .. })
    ));
    w.advance(2 * HOUR);
    assert_eq!(
        status(restarted.run(&sign(waiting.id), &mut site).result),
        200
    );
}

// --- Vending ---------------------------------------------------------------------------------

fn minting(lifetime_ms: u64, format: &str, pointer: &str) -> Operation {
    operation(json!({"name": "mint",
    "vend": {"lifetime_ms": lifetime_ms,
             "expires": {"source": {"from": "json", "pointer": pointer}, "format": format}},
    "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "sts.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/token"},
         "inject": [{"target": {"kind": "header", "name": "Authorization"}, "template": "Bearer {{token}}"},
                    {"target": {"kind": "body"}, "template": "scope=read&duration=900"}]},
        {"do": "return", "response": {"body": {"json": ["/credential", "/expires"]}}}
    ]}))
}

struct Vending {
    w: World,
}

impl Vending {
    fn new(op: Operation) -> Self {
        let mut w = World::new();
        let policy = Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(op)
            .with_caller(caller("app", &w.owner_app, &["mint"]));
        let mut values = Fields::new();
        values.insert("token", TOKEN.to_vec()).unwrap();
        w.record = Record::seal(
            &w.user_key(),
            "sts",
            OWNER,
            w.device.sign_policy(policy).unwrap(),
            &values,
        )
        .unwrap();
        w.grant();
        Self { w }
    }

    fn call(&self, body: Body, site: &mut Site) -> engine::Result<Output> {
        let call = self
            .w
            .owner_app
            .sign_call_at(
                "app",
                &self.w.node.public_key(),
                self.w.record.clone(),
                "mint",
                body,
                self.w.now(),
            )
            .unwrap();
        self.w.node.run(&call, site).result
    }

    fn vends(&self) -> Vec<u64> {
        self.w
            .entries()
            .iter()
            .filter_map(|e| match e.entry.event {
                Event::Vend { expires_ms, .. } => Some(expires_ms),
                _ => None,
            })
            .collect()
    }
}

fn rfc3339(ms: u64) -> String {
    // Days and time of day from Unix milliseconds (UTC), enough for the test's dates.
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[test]
fn a_vended_credential_within_its_lifetime_goes_back_and_is_logged() {
    let v = Vending::new(minting(HOUR, "rfc3339", "/expires"));
    let expires = v.w.now() + 15 * 60 * 1000;
    let body = format!(
        "{{\"credential\": \"short-lived-abc\", \"expires\": \"{}\", \"long_term\": \"x\"}}",
        rfc3339(expires)
    );
    let mut site = Site::answering(200, &body);
    let response = match v.call(Body::http_fixed(), &mut site) {
        Ok(Output::Http(r)) => r,
        other => panic!("not a response: {:?}", other.map(|_| ())),
    };
    let text = String::from_utf8(response.body().to_vec()).unwrap();
    assert!(text.contains("short-lived-abc") && !text.contains("long_term"));
    assert_eq!(v.vends(), vec![expires / 1000 * 1000]);
}

#[test]
fn a_vended_credential_that_outlives_its_bounds_never_goes_back() {
    let v = Vending::new(minting(HOUR, "seconds", "/expires"));
    for (what, body) in [
        (
            "valid two hours",
            "{\"credential\": \"abc\", \"expires\": 7200}",
        ),
        ("no expiry", "{\"credential\": \"abc\"}"),
        (
            "not a number",
            "{\"credential\": \"abc\", \"expires\": \"soon\"}",
        ),
        (
            "a negative number",
            "{\"credential\": \"abc\", \"expires\": -1}",
        ),
    ] {
        let mut site = Site::answering(200, body);
        let refused = matches!(
            v.call(Body::http_fixed(), &mut site),
            Err(Error::VendRefused { .. })
        );
        assert!(refused, "{what}");
    }
    assert!(v.vends().is_empty());
    // Within the hour plus the clock allowance: handed back.
    let mut site = Site::answering(200, "{\"credential\": \"abc\", \"expires\": 3660}");
    assert!(matches!(
        v.call(Body::http_fixed(), &mut site),
        Ok(Output::Http(_))
    ));
    let mut site = Site::answering(200, "{\"credential\": \"abc\", \"expires\": 3661}");
    assert!(matches!(
        v.call(Body::http_fixed(), &mut site),
        Err(Error::VendRefused { .. })
    ));
}

#[test]
fn a_caller_cannot_widen_what_is_vended() {
    let policy = |op: Operation| {
        Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(op)
            .with_caller(caller("app", &CallerKey::generate(), &["mint"]))
            .validate()
    };
    policy(minting(HOUR, "unix", "/expires")).unwrap();
    // The caller's own request (it would choose the scope and the duration).
    let mut caller_request = minting(HOUR, "unix", "/expires");
    let mut raw = serde_json::to_value(&caller_request).unwrap();
    raw["steps"][1]["request"] =
        json!({"from": "caller", "methods": ["POST"], "paths": ["/token"]});
    caller_request = serde_json::from_value(raw).unwrap();
    assert!(policy(caller_request).is_err());
    // The whole body back, a lifetime above 12 hours, reading `all`, a TLS stream.
    let mut whole = serde_json::to_value(minting(HOUR, "unix", "/expires")).unwrap();
    whole["steps"][2] = json!({"do": "return", "response": {"body": "all"}});
    assert!(policy(serde_json::from_value(whole).unwrap()).is_err());
    assert!(policy(minting(12 * HOUR + 1, "unix", "/expires")).is_err());
    let mut all = serde_json::to_value(minting(HOUR, "unix", "/expires")).unwrap();
    all["vend"]["expires"]["source"] = json!({"from": "all"});
    assert!(policy(serde_json::from_value(all).unwrap()).is_err());
    let tls = operation(json!({"name": "mint",
        "vend": {"lifetime_ms": HOUR, "expires": {"source": {"from": "all"}, "format": "unix"}},
        "steps": [
            {"do": "open", "connection": "tls", "destinations": [{"host": "db.example.com", "port": 5432}]},
            {"do": "return"}]}));
    assert!(policy(tls).is_err());
}

fn signing(lifetime_ms: u64, offset: i64, format: &str) -> Operation {
    operation(json!({"name": "mint",
        "vend": {"lifetime_ms": lifetime_ms, "expires": {"input": "/exp", "format": format}},
        "input": {"json": {"members": [
            {"pointer": "/scope", "one_of": ["read"]},
            {"pointer": "/exp", "set": "unix", "offset": offset}]}},
        "steps": [{"do": "return",
                   "template": "{{ b64urlraw($input) }}.{{ b64urlraw(hmac_sha256(token, $input)) }}"}]}))
}

#[test]
fn a_token_the_node_signs_carries_an_expiry_the_node_sets_within_the_lifetime() {
    let v = Vending::new(signing(10 * 60 * 1000, 300, "unix"));
    // The caller's own `exp` is overwritten by the node's clock.
    let output = match v.call(
        Body::derive(br#"{"scope": "read", "exp": 99999999999}"#),
        &mut Site::ok(),
    ) {
        Ok(Output::Derive(bytes)) => bytes,
        other => panic!("not a derivation: {:?}", other.map(|_| ())),
    };
    let expected = v.w.now() / 1000 + 300;
    assert!(String::from_utf8(output).unwrap().contains('.'));
    assert_eq!(v.vends(), vec![expected * 1000]);
    // A wider scope is refused by the closed input schema.
    assert!(matches!(
        v.call(
            Body::derive(br#"{"scope": "admin", "exp": 1}"#),
            &mut Site::ok()
        ),
        Err(Error::InputInvalid { .. })
    ));
    // An offset beyond the lifetime, or a format the node does not set, is refused at signing.
    let policy = |op: Operation| {
        Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(op)
            .with_caller(caller("app", &CallerKey::generate(), &["mint"]))
            .validate()
    };
    assert!(policy(signing(10 * 60 * 1000, 601, "unix")).is_err());
    assert!(policy(signing(10 * 60 * 1000, 300, "rfc3339")).is_err());
    assert!(policy(signing(10 * 60 * 1000, 300, "unix_ms")).is_err());
}

#[test]
fn summaries_flag_vending_and_count_a_longer_lifetime_as_wider() {
    let policy = |lifetime: u64| {
        Policy::new()
            .with_field(FieldSpec::secret("token"))
            .with_operation(minting(lifetime, "unix", "/expires"))
            .with_caller(caller(
                "app",
                &CallerKey::from_bytes(&mut [1; 32]),
                &["mint"],
            ))
    };
    let summary = summarize(&policy(HOUR), None);
    assert!(summary.flags.iter().any(|f| f.code == FlagCode::Vend));
    assert!(summary.lines.iter().any(|l| l.contains("vends")));
    let longer = summarize(&policy(2 * HOUR), Some(&policy(HOUR)));
    assert!(longer.flags.iter().any(|f| f.code == FlagCode::Wider));
    let shorter = summarize(&policy(HOUR / 2), Some(&policy(HOUR)));
    assert!(!shorter.flags.iter().any(|f| f.code == FlagCode::Wider));
}
