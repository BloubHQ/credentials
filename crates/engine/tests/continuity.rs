//! Node continuity: a node hands its grants, devices, floors and limits over to a successor,
//! stops, and the successor's chain continues the predecessor's (`docs/design.md`, section
//! 10). The attestation and successor-statement checks are the `continuity` crate's; these
//! tests cover the state, the package and the chain.
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
use engine::call::{Body, Output};
use engine::egress::{ClientIdentity, Transport};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::limits::LimitRule;
use engine::log::{ChainVerifier, Event, MemorySink, SignedEntry};
use engine::node::{Clock, HandOver, Node, Successor};
use engine::policy::{Caller, Destination, FieldSpec, Input, Operation, Policy};
use engine::record::Record;

/// 2026-11-25T00:00:00Z.
const NOW: u64 = 1_795_564_800_000;

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct NoNetwork;

impl Transport for NoNetwork {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(Error::Encoding)
    }
}

type TestNode = Node<MemorySink, SharedClock>;

struct Owner {
    name: &'static str,
    device: DeviceKey,
    user: [u8; 32],
    record: Record,
}

struct World {
    clock: Arc<AtomicU64>,
    caller: CallerKey,
    old_key: [u8; 32],
    new_key: [u8; 32],
    old: TestNode,
    new: TestNode,
    alice: Owner,
    bob: Owner,
}

fn policy(caller: &CallerKey) -> Policy {
    Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(
            Operation::derive("mac", "{{ hex(hmac_sha256(key, $input)) }}").input(Input::any()),
        )
        .with_caller(Caller::new("app", caller.public(), ["mac"]))
}

fn owner(name: &'static str, caller: &CallerKey, seed: u8) -> Owner {
    let device = DeviceKey::generate();
    let user = [seed; 32];
    let mut values = Fields::new();
    values
        .insert("key", b"0123456789abcdef0123456789abcdef".to_vec())
        .unwrap();
    let signed = device.sign_policy(policy(caller)).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user.clone()),
        "mac",
        name,
        signed,
        &values,
    )
    .unwrap();
    Owner {
        name,
        device,
        user,
        record,
    }
}

fn node(clock: &Arc<AtomicU64>) -> TestNode {
    Node::new(
        NodeKey::generate(),
        MemorySink::new(),
        SharedClock(clock.clone()),
    )
}

/// A node whose key bytes the test keeps, to restart it or forge with its key.
fn keyed(clock: &Arc<AtomicU64>) -> (TestNode, [u8; 32]) {
    let bytes = *NodeKey::generate().to_bytes();
    let node = Node::new(
        NodeKey::from_bytes(&mut bytes.clone()),
        MemorySink::new(),
        SharedClock(clock.clone()),
    );
    (node, bytes)
}

fn grant(node: &TestNode, owner: &Owner, at: u64, allow_successor: bool) {
    let mut terms =
        GrantTerms::at(owner.name, at, Duration::from_secs(24 * 3600)).pin(&owner.record);
    if !allow_successor {
        terms = terms.without_successor();
    }
    let sealed = owner
        .device
        .grant(
            &UserKey::from_bytes(&mut owner.user.clone()),
            &node.identity(),
            terms,
        )
        .unwrap();
    node.grant(&sealed).unwrap();
}

fn world() -> World {
    let clock = Arc::new(AtomicU64::new(NOW));
    let caller = CallerKey::generate();
    let (old, old_key) = keyed(&clock);
    let alice = owner("alice", &caller, 1);
    let bob = owner("bob", &caller, 2);
    grant(&old, &alice, NOW, true);
    clock.store(NOW + 1, Ordering::SeqCst);
    grant(&old, &bob, NOW + 1, false);
    clock.store(NOW + 10, Ordering::SeqCst);
    // The successor boots before the hand-over.
    let (new, new_key) = keyed(&clock);
    clock.store(NOW + 20, Ordering::SeqCst);
    World {
        clock,
        caller,
        old_key,
        new_key,
        old,
        new,
        alice,
        bob,
    }
}

fn now(w: &World) -> u64 {
    w.clock.load(Ordering::SeqCst)
}

fn mac(w: &World, node: &TestNode, owner: &Owner) -> engine::Result<Vec<u8>> {
    let call = w
        .caller
        .sign_call_at(
            "app",
            &node.public_key(),
            owner.record.clone(),
            "mac",
            Body::derive(b"hello"),
            now(w),
        )
        .unwrap();
    match node.run(&call, &mut NoNetwork).result? {
        Output::Derive(bytes) => Ok(bytes),
        other => panic!("not a derivation: {other:?}"),
    }
}

fn successor(w: &World) -> Successor {
    Successor {
        identity: w.new.identity(),
        release: "v1.1.0".into(),
        statement_sha256: [7; 32],
    }
}

fn entries(node: &TestNode) -> Vec<SignedEntry> {
    node.with_sink(|sink| sink.entries().to_vec())
}

fn verify_across(chains: &[Vec<SignedEntry>], first: &TestNode) -> engine::Result<u64> {
    let mut verifier = ChainVerifier::new(first.public_key());
    for entry in chains.iter().flatten() {
        verifier.push(entry)?;
    }
    Ok(verifier.hand_overs())
}

#[test]
fn a_hand_over_moves_the_state_and_one_chain_runs_across_both_nodes() {
    let w = world();
    let before = mac(&w, &w.old, &w.alice).unwrap();
    // A second device of alice, and spending limits on her record.
    let tablet = DeviceKey::generate();
    w.old
        .add_device(
            &w.alice
                .device
                .endorse("alice", &w.old.public_key(), &tablet.public(), now(&w))
                .unwrap(),
        )
        .unwrap();
    w.clock.store(NOW + 30, Ordering::SeqCst);
    let rules = vec![LimitRule {
        currency: "EUR".into(),
        merchant: None,
        per_payment: Some("10".into()),
        per_day: None,
        per_month: None,
    }];
    w.old
        .set_limits(
            &w.alice
                .device
                .sign_limits(&w.old.public_key(), "alice", "mac", rules, now(&w))
                .unwrap(),
        )
        .unwrap();
    w.clock.store(NOW + 40, Ordering::SeqCst);

    let hand_over = w.old.hand_over(&successor(&w)).unwrap();
    assert!(w.old.is_handed_over());
    let Event::HandOver {
        owners,
        grants,
        release,
        ..
    } = &hand_over.entry.entry.event
    else {
        panic!("not a hand-over entry");
    };
    assert_eq!((*owners, *grants), (2, 1), "bob did not allow a successor");
    assert_eq!(release, "v1.1.0");
    // The package holds no secret in the clear.
    let wire = serde_json::to_string(&hand_over).unwrap();
    assert!(!wire.contains(&engine::encoding::to_b64(&w.alice.user)));

    w.clock.store(NOW + 50, Ordering::SeqCst);
    let taken = w.new.take_over(&w.old.public_key(), &hand_over).unwrap();
    assert_eq!((taken.owners, taken.grants), (2, 1));

    // Alice's grant came over: the same derivation on the successor, with no new grant.
    assert_eq!(mac(&w, &w.new, &w.alice).unwrap(), before);
    // Bob's did not: he grants again.
    assert_eq!(mac(&w, &w.new, &w.bob), Err(Error::NoGrant));
    // The devices came over: the tablet alice endorsed may revoke on the successor.
    w.clock.store(NOW + 60, Ordering::SeqCst);
    w.new
        .revoke(
            &tablet
                .revoke("alice", &w.new.public_key(), now(&w))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(mac(&w, &w.new, &w.alice), Err(Error::NoGrant));

    // One chain: the old node's entries, then the successor's, which start with a
    // `continue` entry chained to the hand-over.
    let old = entries(&w.old);
    let new = entries(&w.new);
    assert_eq!(new[0].entry.prev, hand_over.entry.hash().unwrap());
    assert_eq!(new[0].entry.seq, hand_over.entry.entry.seq + 1);
    assert!(matches!(new[0].entry.event, Event::Continue { .. }));
    assert_eq!(
        new.iter()
            .filter(|e| matches!(e.entry.event, Event::Carry(_)))
            .count(),
        2
    );
    assert_eq!(verify_across(&[old.clone(), new.clone()], &w.old), Ok(1));
    // The successor's chain alone does not verify from the start of a chain.
    assert!(verify_across(std::slice::from_ref(&new), &w.new).is_err());
    // But it verifies from its first entry.
    let mut alone = ChainVerifier::continued(w.new.public_key(), &new[0]);
    for entry in &new {
        alone.push(entry).unwrap();
    }
    // The carried limits are sealed: no amount in the clear.
    let carry = serde_json::to_string(&new[1]).unwrap();
    assert!(!carry.contains("EUR"));
}

#[test]
fn the_old_node_refuses_every_act_after_the_hand_over_and_a_fork_breaks_the_chain() {
    let w = world();
    let hand_over = w.old.hand_over(&successor(&w)).unwrap();
    // No call, grant or second hand-over on the old node.
    assert_eq!(mac(&w, &w.old, &w.alice), Err(Error::NoGrant));
    w.clock.store(NOW + 100, Ordering::SeqCst);
    let terms = GrantTerms::at("alice", now(&w), Duration::from_secs(60));
    let sealed = w
        .alice
        .device
        .grant(
            &UserKey::from_bytes(&mut w.alice.user.clone()),
            &w.old.identity(),
            terms,
        )
        .unwrap();
    assert_eq!(w.old.grant(&sealed), Err(Error::HandedOver));
    let other = node(&w.clock);
    let elsewhere = Successor {
        identity: other.identity(),
        ..successor(&w)
    };
    assert_eq!(w.old.hand_over(&elsewhere), Err(Error::HandedOver));
    // The same successor gets the same package again (one lost on the way).
    assert_eq!(w.old.hand_over(&successor(&w)).unwrap(), hand_over);

    w.new.take_over(&w.old.public_key(), &hand_over).unwrap();
    let old = entries(&w.old);
    let new = entries(&w.new);

    // A fork: an entry the old node's key signs after its hand-over. The node itself writes
    // none (above); someone holding its key, or its log resumed elsewhere, could.
    let mut log =
        engine::log::Log::resume(NodeKey::from_bytes(&mut w.old_key.clone()), &old).unwrap();
    let mut sink = MemorySink::new();
    log.commit(
        &mut sink,
        now(&w),
        ("alice", "mac", ""),
        Event::Pin { generation: 9 },
    )
    .unwrap();
    let fork = sink.entries().to_vec();
    assert_eq!(
        verify_across(&[old.clone(), fork.clone()], &w.old),
        Err(Error::ChainBroken {
            seq: hand_over.entry.entry.seq + 1
        })
    );
    // A `continue` the old key signs, naming itself: the hand-over named another successor.
    let mut sink = MemorySink::new();
    let mut log =
        engine::log::Log::resume(NodeKey::from_bytes(&mut w.old_key.clone()), &old).unwrap();
    log.commit(
        &mut sink,
        now(&w),
        ("", "", ""),
        Event::Continue {
            predecessor: w.old.public_key(),
            owners: 0,
            grants: 0,
        },
    )
    .unwrap();
    assert!(matches!(
        verify_across(&[old.clone(), sink.entries().to_vec()], &w.old),
        Err(Error::EntrySignature { .. })
    ));
    // The fork placed after the successor's entries: the chain breaks there too.
    assert!(verify_across(&[old.clone(), new.clone(), fork], &w.old).is_err());
    // A second successor from the same hand-over: the predecessor named one successor only.
    let second = node(&w.clock);
    assert!(matches!(
        second.take_over(&w.old.public_key(), &hand_over),
        Err(Error::HandOverInvalid { .. })
    )); // The whole chain still verifies.
    assert_eq!(verify_across(&[old, new], &w.old), Ok(1));
}

#[test]
fn a_package_that_was_changed_or_is_for_another_node_is_refused() {
    let w = world();
    let hand_over = w.old.hand_over(&successor(&w)).unwrap();
    let refused = |h: &HandOver| match w.new.take_over(&w.old.public_key(), h) {
        Err(Error::HandOverInvalid { rule }) => rule,
        other => panic!("not refused: {other:?}"),
    };
    // A byte of the ciphertext.
    let mut changed = hand_over.clone();
    changed.ciphertext[0] ^= 1;
    assert_eq!(
        refused(&changed),
        "the package is not the one the hand-over entry names"
    );
    // The entry, re-pointed at the package: the signature breaks.
    let mut entry = hand_over.clone();
    if let Event::HandOver { package_sha256, .. } = &mut entry.entry.entry.event {
        **package_sha256 = changed.package_sha256();
    }
    entry.ciphertext = changed.ciphertext.clone();
    assert_eq!(
        refused(&entry),
        "the hand-over entry is not signed by the predecessor"
    );
    // Not from the node named.
    let stranger = node(&w.clock);
    assert!(matches!(
        w.new.take_over(&stranger.public_key(), &hand_over),
        Err(Error::HandOverInvalid { .. })
    ));
    // Nothing above changed the successor: the real package still goes through.
    w.new.take_over(&w.old.public_key(), &hand_over).unwrap();
    // And only once.
    assert_eq!(
        refused(&hand_over),
        "only a node that has done nothing yet takes over"
    );
}

#[test]
fn a_node_with_state_does_not_take_over_and_a_node_does_not_hand_over_to_itself() {
    let w = world();
    // The successor took a grant of its own first.
    grant(&w.new, &w.bob, now(&w), true);
    let hand_over = w.old.hand_over(&successor(&w)).unwrap();
    assert!(matches!(
        w.new.take_over(&w.old.public_key(), &hand_over),
        Err(Error::HandOverInvalid { .. })
    ));
    let lone = world();
    let itself = Successor {
        identity: lone.old.identity(),
        ..successor(&lone)
    };
    assert!(matches!(
        lone.old.hand_over(&itself),
        Err(Error::HandOverInvalid { .. })
    ));
    assert!(!lone.old.is_handed_over());
}

#[test]
fn both_nodes_restore_from_their_logs() {
    let w = world();
    let hand_over = w.old.hand_over(&successor(&w)).unwrap();
    w.new.take_over(&w.old.public_key(), &hand_over).unwrap();
    w.clock.store(NOW + 1000, Ordering::SeqCst);
    // The successor restarts outside a TEE with the same key: its chain starts at its
    // `continue` entry, and the owners' devices come back (grants do not: owners grant
    // again, and the device must be one the node knows).
    let restored = Node::restore(
        NodeKey::from_bytes(&mut w.new_key.clone()),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
        &entries(&w.new),
    )
    .unwrap();
    assert!(!restored.is_handed_over());
    w.clock.store(NOW + 2000, Ordering::SeqCst);
    assert_eq!(mac(&w, &restored, &w.alice), Err(Error::NoGrant));
    let stranger = owner("alice", &w.caller, 9);
    let sealed = stranger
        .device
        .grant(
            &UserKey::from_bytes(&mut stranger.user.clone()),
            &restored.identity(),
            GrantTerms::at("alice", now(&w), Duration::from_secs(60)),
        )
        .unwrap();
    assert_eq!(restored.grant(&sealed), Err(Error::GrantDenied));
    grant(&restored, &w.alice, now(&w), true);
    // The predecessor, restored from its own log, stays stopped.
    let old = Node::restore(
        NodeKey::from_bytes(&mut w.old_key.clone()),
        MemorySink::new(),
        SharedClock(w.clock.clone()),
        &entries(&w.old),
    )
    .unwrap();
    assert!(old.is_handed_over());
    assert_eq!(old.hand_over(&successor(&w)), Err(Error::HandedOver));
}
