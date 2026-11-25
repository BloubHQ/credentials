//! Node continuity, key backup and device transfer on the owner's device, and the attacks on
//! them. Roots are TEST ONLY roots generated at run time (`continuity::testing`); no AWS or
//! Sigstore service is reached.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use continuity::sigstore::WorkflowIdentity;
use continuity::testing::{TestNitro, TestSigstore, measurement};
use engine::grant::SealedGrant;
use engine::keys::NodeKey;
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};

use crate::attestation::{Nonce, VerifiedNode};
use crate::backup::{BackedUpKey, generate_backup_key, unwrap_keys, wrap_keys};
use crate::continuity::{SuccessorPolicy, check_successor, regrant};
use crate::error::ClientError;
use crate::keys::{KeyKind, generate_key};
use crate::time::now_ms;
use crate::transfer::{MAX_ATTEMPTS, TRANSFER_TTL_MS, TransferReceiver, TransferSender};

struct World {
    nitro: TestNitro,
    sigstore: TestSigstore,
    node: Node<MemorySink, SystemClock>,
}

fn world() -> World {
    World {
        nitro: TestNitro::new(),
        sigstore: TestSigstore::new(),
        node: Node::new(NodeKey::generate(), MemorySink::new(), SystemClock),
    }
}

fn nonce() -> Nonce {
    Nonce::from_parts([5u8; 32], now_ms())
}

/// Verifies the world's node as the successor of `previous` for the statement `from -> to`,
/// with the node really running `runs`.
fn successor(
    w: &World,
    previous: &str,
    from: &attest::Measurement,
    to: &attest::Measurement,
    runs: &attest::Measurement,
) -> Result<VerifiedNode, ClientError> {
    let signed = w
        .sigstore
        .statement(&WorkflowIdentity::release_workflow(), from, to);
    let n = nonce();
    let document = w
        .nitro
        .document(runs, &w.node.identity().report_data(), &n.bytes());
    check_successor(
        &document,
        &n,
        &signed,
        previous,
        w.node.identity(),
        &w.sigstore.trust_root(),
        &[w.nitro.root()],
    )
}

fn reason(result: Result<VerifiedNode, ClientError>) -> String {
    match result {
        Err(ClientError::SuccessorRefused { reason, .. })
        | Err(ClientError::AttestationRefused { reason, .. }) => reason,
        Err(other) => panic!("unexpected error kind {}", other.code()),
        Ok(_) => panic!("a successor was accepted"),
    }
}

#[test]
fn a_successor_is_regranted_after_the_old_node_is_gone() {
    let w = world();
    let (v1, v2) = (measurement("v1.0.0", 1), measurement("v1.1.0", 2));
    let node = Arc::new(successor(&w, "v1.0.0", &v1, &v2, &v2).unwrap());
    assert_eq!(node.release(), "v1.1.0");
    assert_eq!(node.successor_of().as_deref(), Some("v1.0.0"));
    let (device, user) = (generate_key(KeyKind::Device), generate_key(KeyKind::User));
    let grant = |policy, approved| {
        regrant(
            device.clone(),
            user.clone(),
            Arc::clone(&node),
            "alice".into(),
            600,
            Vec::new(),
            policy,
            approved,
        )
    };
    // The owner's policy decides.
    assert!(matches!(
        grant(SuccessorPolicy::Never, true),
        Err(ClientError::Refused { .. })
    ));
    assert!(matches!(
        grant(SuccessorPolicy::AskOwner, false),
        Err(ClientError::Refused { .. })
    ));
    let sealed: SealedGrant =
        serde_json::from_str(&grant(SuccessorPolicy::AskOwner, true).unwrap()).unwrap();
    w.node.grant(&sealed).unwrap();
    let automatic: SealedGrant =
        serde_json::from_str(&grant(SuccessorPolicy::Automatic, false).unwrap()).unwrap();
    assert!(!automatic.ciphertext.is_empty());

    // A node verified the ordinary way is not a successor for regrant.
    let plain = Arc::new(VerifiedNode::for_test(w.node.identity(), now_ms()));
    assert!(matches!(
        regrant(
            device.clone(),
            user.clone(),
            plain,
            "alice".into(),
            600,
            Vec::new(),
            SuccessorPolicy::Automatic,
            true
        ),
        Err(ClientError::Refused { .. })
    ));
}

#[test]
fn downgrades_unlisted_images_and_forged_statements_are_refused() {
    let w = world();
    let (v1, v2) = (measurement("v1.0.0", 1), measurement("v1.1.0", 2));
    // A downgrade, even signed at the tag.
    assert_eq!(reason(successor(&w, "v1.1.0", &v2, &v1, &v1)), "downgrade");
    // A statement of another release than the one the owner granted to (a replay of an
    // older hand-over).
    let v0 = measurement("v0.9.0", 9);
    assert_eq!(
        reason(successor(&w, "v1.0.0", &v0, &v1, &v1)),
        "not_for_this_release"
    );
    // A node that does not run the measurements the statement lists.
    let mut other = v2.clone();
    other.pcr0[0] ^= 1;
    assert_eq!(
        reason(successor(&w, "v1.0.0", &v1, &v2, &other)),
        "unknown_measurement"
    );
    // A statement signed under another Fulcio root.
    let signed = TestSigstore::new().statement(&WorkflowIdentity::release_workflow(), &v1, &v2);
    let n = nonce();
    let document = w
        .nitro
        .document(&v2, &w.node.identity().report_data(), &n.bytes());
    let refused = check_successor(
        &document,
        &n,
        &signed,
        "v1.0.0",
        w.node.identity(),
        &w.sigstore.trust_root(),
        &[w.nitro.root()],
    );
    assert_eq!(reason(refused), "chain_untrusted");
    // The compiled trust root of this build is empty: nothing verifies against it.
    let n = Arc::new(nonce());
    let refused = crate::continuity::verify_successor(
        document,
        Arc::clone(&n),
        signed.statement.clone(),
        serde_json::to_vec(&signed.bundle).unwrap(),
        "v1.0.0".into(),
        serde_json::to_string(&w.node.identity()).unwrap(),
        None,
    );
    assert!(matches!(
        refused,
        Err(ClientError::SuccessorRefused { ref reason, .. }) if reason == "trust_root_empty"
    ));
    // The nonce was spent.
    assert!(n.take(now_ms()).is_err());
}

#[test]
fn a_grant_without_successor_says_so() {
    let w = world();
    let node = Arc::new(VerifiedNode::for_test(w.node.identity(), now_ms()));
    let sealed = crate::owner::grant_without_successor(
        generate_key(KeyKind::Device),
        generate_key(KeyKind::User),
        Arc::clone(&node),
        "bob".into(),
        600,
        Vec::new(),
    )
    .unwrap();
    let grant: SealedGrant = serde_json::from_str(&sealed).unwrap();
    w.node.grant(&grant).unwrap();
    // The node keeps the owner's choice: it would not hand this grant over.
    let successor = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let hand_over = w
        .node
        .hand_over(&engine::node::Successor {
            identity: successor.identity(),
            release: "v1.1.0".into(),
            statement_sha256: [1; 32],
        })
        .unwrap();
    let taken = successor
        .take_over(&w.node.public_key(), &hand_over)
        .unwrap();
    assert_eq!((taken.owners, taken.grants), (1, 0));
}

fn keys() -> Vec<BackedUpKey> {
    vec![
        BackedUpKey {
            kind: KeyKind::Device,
            key: generate_key(KeyKind::Device),
        },
        BackedUpKey {
            kind: KeyKind::User,
            key: generate_key(KeyKind::User),
        },
    ]
}

#[test]
fn a_backup_opens_only_with_its_key_for_its_owner_unchanged() {
    let backup_key = generate_backup_key().unwrap();
    let original = keys();
    let blob = wrap_keys(backup_key.clone(), "alice".into(), original.clone()).unwrap();
    let opened = unwrap_keys(backup_key.clone(), "alice".into(), blob.clone()).unwrap();
    assert!(opened == original, "the keys did not come back");
    // The blob does not hold a key in the clear.
    for key in &original {
        assert!(!blob.contains(&key.key), "a key is in the blob");
    }
    let refused = |result: Result<Vec<BackedUpKey>, ClientError>| match result {
        Err(e) => e.code(),
        Ok(_) => panic!("a backup opened"),
    };
    assert_eq!(
        refused(unwrap_keys(
            generate_backup_key().unwrap(),
            "alice".into(),
            blob.clone()
        )),
        "backup_refused"
    );
    assert_eq!(
        refused(unwrap_keys(backup_key.clone(), "bob".into(), blob.clone())),
        "backup_refused"
    );
    // Another owner or time written into the blob: the additional data no longer matches.
    let mut value: serde_json::Value = serde_json::from_str(&blob).unwrap();
    value["owner"] = "bob".into();
    assert_eq!(
        refused(unwrap_keys(
            backup_key.clone(),
            "bob".into(),
            value.to_string()
        )),
        "backup_refused"
    );
    let mut value: serde_json::Value = serde_json::from_str(&blob).unwrap();
    value["created_ms"] = 1.into();
    assert_eq!(
        refused(unwrap_keys(
            backup_key.clone(),
            "alice".into(),
            value.to_string()
        )),
        "backup_refused"
    );
    assert_eq!(
        refused(unwrap_keys("short".into(), "alice".into(), blob)),
        "invalid_key"
    );
}

fn transfer(
    sender: &TransferSender,
    code: &str,
) -> Result<crate::transfer::TransferredKeys, ClientError> {
    let now = now_ms();
    let offer = sender.offer_at(now)?;
    let receiver = TransferReceiver::join(code.into(), &offer, now)?;
    let sealed = sender.seal_at(&receiver.answer(), "alice", keys(), now)?;
    receiver.open_at(&sealed, now)
}

#[test]
fn a_transfer_with_the_code_moves_the_keys() {
    let sender = TransferSender::new(now_ms()).unwrap();
    let code = sender.code();
    assert_eq!(code.len(), 6);
    let now = now_ms();
    let offer = sender.offer_at(now).unwrap();
    let receiver = TransferReceiver::join(code.clone(), &offer, now).unwrap();
    let sent = keys();
    let sealed = sender
        .seal_at(&receiver.answer(), "alice", sent.clone(), now)
        .unwrap();
    for key in &sent {
        assert!(!sealed.contains(&key.key), "a key is in the sealed message");
    }
    let got = receiver.open_at(&sealed, now).unwrap();
    assert_eq!(got.owner, "alice");
    assert!(got.keys == sent, "the keys did not arrive");
    // Each side once.
    assert!(receiver.open_at(&sealed, now).is_err());
    assert!(transfer(&sender, &code).is_err());
}

#[test]
fn a_changed_transcript_is_refused() {
    // The offer's SPAKE2 message changed: the sender refuses the answer.
    let sender = TransferSender::new(now_ms()).unwrap();
    let now = now_ms();
    let offer = sender.offer_at(now).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&offer).unwrap();
    let other = TransferSender::new(now).unwrap();
    let other_offer: serde_json::Value =
        serde_json::from_str(&other.offer_at(now).unwrap()).unwrap();
    value["message"] = other_offer["message"].clone();
    let receiver = TransferReceiver::join(sender.code(), &value.to_string(), now).unwrap();
    assert_eq!(
        sender
            .seal_at(&receiver.answer(), "alice", keys(), now)
            .unwrap_err()
            .code(),
        "transfer_refused"
    );

    // The answer's message, its confirmation or the session changed.
    for field in ["message", "confirm", "session"] {
        let sender = TransferSender::new(now).unwrap();
        let offer = sender.offer_at(now).unwrap();
        let receiver = TransferReceiver::join(sender.code(), &offer, now).unwrap();
        let mut answer: serde_json::Value = serde_json::from_str(&receiver.answer()).unwrap();
        let decoy = TransferReceiver::join(sender.code(), &offer, now).unwrap();
        let decoy: serde_json::Value = serde_json::from_str(&decoy.answer()).unwrap();
        answer[field] = if field == "session" {
            "AAAAAAAAAAAAAAAAAAAAAA".into()
        } else if field == "message" {
            decoy["message"].clone()
        } else {
            decoy["confirm"].clone()
        };
        assert!(
            sender
                .seal_at(&answer.to_string(), "alice", keys(), now)
                .is_err(),
            "{field}"
        );
    }

    // The sealed message changed: the new device refuses it.
    for field in ["ciphertext", "confirm", "nonce"] {
        let sender = TransferSender::new(now).unwrap();
        let offer = sender.offer_at(now).unwrap();
        let receiver = TransferReceiver::join(sender.code(), &offer, now).unwrap();
        let sealed = sender
            .seal_at(&receiver.answer(), "alice", keys(), now)
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&sealed).unwrap();
        let text = value[field].as_str().unwrap().to_string();
        let flipped: String = text
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 2 {
                    if c == 'A' { 'B' } else { 'A' }
                } else {
                    c
                }
            })
            .collect();
        value[field] = flipped.into();
        assert!(
            receiver.open_at(&value.to_string(), now).is_err(),
            "{field}"
        );
    }
}

#[test]
fn the_code_cannot_be_guessed_offline_and_online_guesses_are_limited() {
    // A recorded transcript gives no test for a guess: replaying the new device's side with
    // a guess, even the right code, does not reproduce its confirmation, because the
    // SPAKE2 secrets of both runs are needed.
    let now = now_ms();
    let sender = TransferSender::new(now).unwrap();
    let offer = sender.offer_at(now).unwrap();
    let receiver = TransferReceiver::join(sender.code(), &offer, now).unwrap();
    let recorded: serde_json::Value = serde_json::from_str(&receiver.answer()).unwrap();
    let right: u32 = sender.code().parse().unwrap();
    let mut matches = 0;
    for guess in (0..1000u32).chain([right]) {
        let replay = TransferReceiver::join(format!("{guess:06}"), &offer, now).unwrap();
        let replayed: serde_json::Value = serde_json::from_str(&replay.answer()).unwrap();
        if replayed["confirm"] == recorded["confirm"] {
            matches += 1;
        }
    }
    assert_eq!(matches, 0, "a guess could be tested offline");

    // Online: wrong codes are counted, and after MAX_ATTEMPTS even the right code fails.
    let sender = TransferSender::new(now).unwrap();
    let wrong = if sender.code() == "000000" {
        "000001"
    } else {
        "000000"
    };
    for left in (0..MAX_ATTEMPTS).rev() {
        assert_eq!(
            transfer(&sender, wrong).unwrap_err().code(),
            "transfer_refused"
        );
        assert_eq!(sender.attempts_left(), left);
    }
    assert!(transfer(&sender, &sender.code()).is_err());

    // A transfer expires.
    let old = TransferSender::new(now - TRANSFER_TTL_MS - 1).unwrap();
    assert!(old.offer_at(now).is_err());
    // A code is six digits.
    assert!(TransferReceiver::join("12345".into(), &offer, now).is_err());
    assert!(TransferReceiver::join("12345a".into(), &offer, now).is_err());
}
