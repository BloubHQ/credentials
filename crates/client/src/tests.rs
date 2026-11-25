//! Tests of every function of the client on the host: attestation failures on real Nitro
//! documents, and the whole flow of an owner and an app against a real engine node.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use engine::call::{Output, SignedCall};
use engine::egress::{ClientIdentity, Transport};
use engine::grant::{NodeIdentity, Revocation, SealedGrant};
use engine::keys::{Endorsement, NodeKey, Retirement};
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use engine::policy::{Caller, Destination, FieldSpec, Input, Operation, Policy};
use engine::record::{Pin, Record};

use crate::attestation::{MAX_AGE_MS, Nonce, VerifiedNode};
use crate::time::now_ms;
use crate::*;

/// A production enclave of another program, 2026-10-01T04:26:30Z: it verifies, but its user
/// data binds no identity of this engine.
const DOCUMENT: &[u8] =
    include_bytes!("../../attest/tests/fixtures/nitro-attestation-prerelease.cbor");
const DOCUMENT_NONCE: &[u8] =
    include_bytes!("../../attest/tests/fixtures/nitro-attestation-prerelease.nonce");
const MEASUREMENTS: &str = include_str!("../../attest/tests/fixtures/measurements-prerelease.json");
/// A debug enclave (PCRs all zero), asked with a nonce of 256 bytes.
const DEBUG_DOCUMENT: &[u8] =
    include_bytes!("../../attest/tests/fixtures/nitro-attestation-debug.cbor");

/// The nonce of the fixture, as a fresh nonce of this app.
fn fixture_nonce() -> Arc<Nonce> {
    let bytes: [u8; NONCE_LEN] = DOCUMENT_NONCE.try_into().unwrap();
    Arc::new(Nonce::from_parts(bytes, now_ms()))
}

fn a_node() -> Node<MemorySink, SystemClock> {
    Node::new(NodeKey::generate(), MemorySink::new(), SystemClock)
}

fn identity_json(identity: &NodeIdentity) -> String {
    serde_json::to_string(identity).unwrap()
}

fn code<T: std::fmt::Debug>(result: Result<T>) -> &'static str {
    result.unwrap_err().code()
}

fn reason<T: std::fmt::Debug>(result: Result<T>) -> String {
    match result.unwrap_err() {
        ClientError::AttestationRefused { reason, .. } => reason,
        other => panic!("not a refused attestation: {other:?}"),
    }
}

#[test]
fn keys_are_generated_imported_and_made_public() {
    for kind in [KeyKind::Device, KeyKind::User, KeyKind::Caller] {
        let key = generate_key(kind);
        assert_eq!(key.len(), 43);
        assert_ne!(key, generate_key(kind));
        // A key file of the CLI ends with a newline.
        assert_eq!(import_key(kind, format!("{key}\n")).unwrap(), key);
        assert_eq!(code(import_key(kind, "not a key".into())), "invalid_key");
        assert_eq!(
            code(import_key(kind, URL_SAFE_NO_PAD.encode([1u8; 31]))),
            "invalid_key"
        );
    }
    let device = generate_key(KeyKind::Device);
    let public = public_key(KeyKind::Device, device.clone()).unwrap();
    assert_eq!(public, public_key(KeyKind::Device, device).unwrap());
    engine::keys::DevicePublicKey::from_b64(&public).unwrap();
    let caller = generate_key(KeyKind::Caller);
    engine::keys::CallerPublicKey::from_b64(&public_key(KeyKind::Caller, caller).unwrap()).unwrap();
    assert_eq!(
        code(public_key(KeyKind::User, generate_key(KeyKind::User))),
        "invalid_key"
    );
    assert_eq!(
        code(public_key(KeyKind::Caller, String::new())),
        "invalid_key"
    );
}

#[test]
fn a_nonce_is_random_and_good_once_within_five_minutes() {
    let one = nonce().unwrap();
    let two = nonce().unwrap();
    assert_eq!(one.bytes().len(), NONCE_LEN);
    assert_ne!(one.bytes(), two.bytes());
    assert_eq!(URL_SAFE_NO_PAD.decode(one.to_b64()).unwrap(), one.bytes());

    let identity = identity_json(&a_node().identity());
    let fresh = fixture_nonce();
    let first = verify_node(
        DOCUMENT.to_vec(),
        Arc::clone(&fresh),
        MEASUREMENTS.into(),
        identity.clone(),
    );
    assert_eq!(code(first), "binding_mismatch");
    let again = verify_node(
        DOCUMENT.to_vec(),
        fresh,
        MEASUREMENTS.into(),
        identity.clone(),
    );
    assert_eq!(code(again), "nonce_rejected");

    let bytes: [u8; NONCE_LEN] = DOCUMENT_NONCE.try_into().unwrap();
    let old = Arc::new(Nonce::from_parts(bytes, now_ms() - MAX_AGE_MS - 1));
    let late = verify_node(DOCUMENT.to_vec(), old, MEASUREMENTS.into(), identity);
    assert_eq!(code(late), "nonce_rejected");
}

#[test]
fn a_real_document_of_another_program_is_refused_at_the_binding() {
    let identity = identity_json(&a_node().identity());
    let result = verify_node(
        DOCUMENT.to_vec(),
        fixture_nonce(),
        MEASUREMENTS.into(),
        identity,
    );
    match result.unwrap_err() {
        ClientError::BindingMismatch { detail } => assert!(detail.contains("user data")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn verification_failures_have_their_codes() {
    let identity = identity_json(&a_node().identity());
    let verify = |document: &[u8], nonce: Arc<Nonce>, measurements: &str| {
        verify_node(
            document.to_vec(),
            nonce,
            measurements.into(),
            identity.clone(),
        )
    };
    // Not this app's nonce.
    assert_eq!(
        reason(verify(DOCUMENT, nonce().unwrap(), MEASUREMENTS)),
        "nonce_mismatch"
    );
    // Not an accepted release.
    let mut list: serde_json::Value = serde_json::from_str(MEASUREMENTS).unwrap();
    list["pcr0"] = serde_json::Value::String("00".repeat(47) + "01");
    let other_list = serde_json::to_string(&list).unwrap();
    assert_eq!(
        reason(verify(DOCUMENT, fixture_nonce(), &other_list)),
        "unknown_measurement"
    );
    // No accepted release at all, or a list that does not parse.
    assert_eq!(
        code(verify(DOCUMENT, fixture_nonce(), "[]")),
        "measurements_invalid"
    );
    assert_eq!(
        code(verify(DOCUMENT, fixture_nonce(), "{")),
        "measurements_invalid"
    );
    // Not a document.
    assert_eq!(
        reason(verify(b"\x00\x01", fixture_nonce(), MEASUREMENTS)),
        "not_cbor"
    );
    assert_eq!(
        reason(verify(&[0u8; 20_000], fixture_nonce(), MEASUREMENTS)),
        "document_too_large"
    );
    // A flipped signature byte.
    let mut flipped = DOCUMENT.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        reason(verify(&flipped, fixture_nonce(), MEASUREMENTS)),
        "signature_invalid"
    );
    // A debug enclave: its nonce (256 bytes) is not one of this app (32 bytes), so it is
    // refused there already; the attest crate checks the debug rule itself.
    let zero = format!(
        r#"{{"release": "debug", "pcr0": "{0}", "pcr1": "{0}", "pcr2": "{0}"}}"#,
        "00".repeat(48)
    );
    assert_eq!(
        reason(verify(DEBUG_DOCUMENT, nonce().unwrap(), &zero)),
        "nonce_mismatch"
    );
}

#[test]
fn malformed_arguments_spend_the_nonce() {
    let fresh = fixture_nonce();
    let bad = verify_node(
        DOCUMENT.to_vec(),
        Arc::clone(&fresh),
        MEASUREMENTS.into(),
        "{}".into(),
    );
    assert_eq!(code(bad), "invalid_input");
    let identity = identity_json(&a_node().identity());
    let again = verify_node(DOCUMENT.to_vec(), fresh, MEASUREMENTS.into(), identity);
    assert_eq!(code(again), "nonce_rejected");
}

#[test]
fn an_attestation_reply_is_verified_like_a_document() {
    let identity = a_node().identity();
    let reply = serde_json::json!({
        "identity": identity,
        "document": URL_SAFE_NO_PAD.encode(DOCUMENT),
    })
    .to_string();
    assert_eq!(
        code(verify_attestation_reply(
            reply,
            fixture_nonce(),
            MEASUREMENTS.into()
        )),
        "binding_mismatch"
    );
    let bad = serde_json::json!({ "identity": identity, "document": "!!" }).to_string();
    assert_eq!(
        code(verify_attestation_reply(
            bad,
            fixture_nonce(),
            MEASUREMENTS.into()
        )),
        "invalid_input"
    );
    assert_eq!(
        code(verify_attestation_reply(
            "[]".into(),
            fixture_nonce(),
            MEASUREMENTS.into()
        )),
        "invalid_input"
    );
}

/// A transport that sends nothing: a derivation needs none.
struct NoNetwork;

impl Transport for NoNetwork {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        panic!("a derivation sends nothing")
    }
}

/// The policy of the flow: the caller `app` may get an HMAC of its input.
fn policy_json(caller_public: &str) -> String {
    let caller = engine::keys::CallerPublicKey::from_b64(caller_public).unwrap();
    let policy = Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(
            Operation::derive("mac", "{{ hex(hmac_sha256(key, $input)) }}").input(Input::any()),
        )
        .with_caller(Caller::new("app", caller, ["mac"]));
    serde_json::to_string(&policy).unwrap()
}

fn run_derive(node: &Node<MemorySink, SystemClock>, call_json: &str) -> engine::Result<Vec<u8>> {
    let call: SignedCall = serde_json::from_str(call_json).unwrap();
    match node.run(&call, &mut NoNetwork).result? {
        Output::Derive(mac) => Ok(mac),
        other => panic!("{other:?}"),
    }
}

/// Waits a millisecond, so the next act of the device is issued after the last one.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(2));
}

#[test]
fn a_grant_sealed_by_the_client_opens_on_the_node() {
    let node = a_node();
    let identity = node.identity();
    let ident = identity_json(&identity);
    let device = generate_key(KeyKind::Device);
    let user = generate_key(KeyKind::User);
    let caller = generate_key(KeyKind::Caller);
    let caller_public = public_key(KeyKind::Caller, caller.clone()).unwrap();

    // The owner's device signs the policy and seals the record.
    let signed = sign_policy(device.clone(), policy_json(&caller_public)).unwrap();
    let fields = vec![Field {
        name: "key".into(),
        value: b"0123456789abcdef0123456789abcdef".to_vec(),
    }];
    let record = seal_record(
        user.clone(),
        signed.clone(),
        "mac".into(),
        "alice".into(),
        fields,
    )
    .unwrap();

    // It grants the verified node, pinning the record.
    let verified = Arc::new(VerifiedNode::for_test(identity, now_ms()));
    assert_eq!(verified.log_key(), identity.log_key.to_b64());
    assert_eq!(verified.identity_json(), ident);
    let sealed = grant(
        device.clone(),
        user.clone(),
        Arc::clone(&verified),
        "alice".into(),
        600,
        vec![record.clone()],
    )
    .unwrap();
    let sealed: SealedGrant = serde_json::from_str(&sealed).unwrap();
    node.grant(&sealed).unwrap();

    // The app signs calls; the node runs them.
    let call = sign_derive_call(
        caller.clone(),
        "app".into(),
        ident.clone(),
        record.clone(),
        "mac".into(),
        b"hello".to_vec(),
    )
    .unwrap();
    let mac = run_derive(&node, &call).unwrap();
    assert_eq!(mac.len(), 64);
    let body = format!(
        r#"{{"kind": "derive", "input": "{}"}}"#,
        URL_SAFE_NO_PAD.encode(b"hello")
    );
    let generic = sign_call(
        caller.clone(),
        "app".into(),
        ident.clone(),
        record.clone(),
        "mac".into(),
        body,
    )
    .unwrap();
    assert_eq!(run_derive(&node, &generic).unwrap(), mac);
    assert_eq!(
        code(sign_call(
            caller.clone(),
            "app".into(),
            ident.clone(),
            record.clone(),
            "mac".into(),
            "{}".into()
        )),
        "invalid_input"
    );

    // A rewrapped record, pinned: the node takes it, and refuses the older generation.
    let rewrapped = rewrap_record(user.clone(), record.clone(), signed.clone()).unwrap();
    let parsed: Record = serde_json::from_str(&rewrapped).unwrap();
    assert_eq!(parsed.generation, 2);
    let pin: Pin =
        serde_json::from_str(&pin_record(device.clone(), rewrapped.clone()).unwrap()).unwrap();
    node.pin(&pin).unwrap();
    let call = sign_derive_call(
        caller.clone(),
        "app".into(),
        ident.clone(),
        rewrapped,
        "mac".into(),
        b"hello".to_vec(),
    )
    .unwrap();
    assert_eq!(run_derive(&node, &call).unwrap(), mac);
    let stale = sign_derive_call(
        caller.clone(),
        "app".into(),
        ident.clone(),
        record,
        "mac".into(),
        b"hello".to_vec(),
    )
    .unwrap();
    assert!(run_derive(&node, &stale).is_err());

    // A second device is endorsed, then retired.
    tick();
    let second = generate_key(KeyKind::Device);
    let second_public = public_key(KeyKind::Device, second).unwrap();
    let endorsement: Endorsement = serde_json::from_str(
        &endorse_device(
            device.clone(),
            "alice".into(),
            ident.clone(),
            second_public.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    node.add_device(&endorsement).unwrap();
    tick();
    let retirement: Retirement = serde_json::from_str(
        &retire_device(device.clone(), "alice".into(), ident.clone(), second_public).unwrap(),
    )
    .unwrap();
    node.retire_device(&retirement).unwrap();

    // The owner takes the key back: calls fail.
    tick();
    let revocation: Revocation =
        serde_json::from_str(&revoke(device, "alice".into(), ident.clone()).unwrap()).unwrap();
    node.revoke(&revocation).unwrap();
    assert!(matches!(
        run_derive(&node, &call),
        Err(engine::Error::NoGrant)
    ));
}

#[test]
fn a_grant_needs_a_recent_verification_and_sound_terms() {
    let node = a_node();
    let device = generate_key(KeyKind::Device);
    let user = generate_key(KeyKind::User);
    let fresh = Arc::new(VerifiedNode::for_test(node.identity(), now_ms()));
    let old = Arc::new(VerifiedNode::for_test(
        node.identity(),
        now_ms() - MAX_AGE_MS - 1,
    ));
    let attempt = |node: &Arc<VerifiedNode>, owner: &str, secs: u64, pins: Vec<String>| {
        grant(
            device.clone(),
            user.clone(),
            Arc::clone(node),
            owner.into(),
            secs,
            pins,
        )
    };
    assert_eq!(
        code(attempt(&old, "alice", 600, Vec::new())),
        "verification_expired"
    );
    assert_eq!(code(attempt(&fresh, "", 600, Vec::new())), "invalid_input");
    assert_eq!(
        code(attempt(&fresh, "alice", 0, Vec::new())),
        "invalid_input"
    );
    assert_eq!(
        code(attempt(&fresh, "alice", 600, vec!["{".into()])),
        "invalid_input"
    );

    // A pinned record of another owner.
    let caller_public = public_key(KeyKind::Caller, generate_key(KeyKind::Caller)).unwrap();
    let signed = sign_policy(device.clone(), policy_json(&caller_public)).unwrap();
    let bob = seal_record(
        user.clone(),
        signed,
        "mac".into(),
        "bob".into(),
        vec![Field {
            name: "key".into(),
            value: vec![7; 32],
        }],
    )
    .unwrap();
    assert_eq!(
        code(attempt(&fresh, "alice", 600, vec![bob])),
        "invalid_input"
    );
    assert_eq!(
        code(grant(
            "bad".into(),
            user,
            fresh,
            "alice".into(),
            600,
            Vec::new()
        )),
        "invalid_key"
    );
}

#[test]
fn sealing_refuses_what_the_engine_refuses() {
    let device = generate_key(KeyKind::Device);
    let user = generate_key(KeyKind::User);
    let caller_public = public_key(KeyKind::Caller, generate_key(KeyKind::Caller)).unwrap();
    assert_eq!(
        code(sign_policy(device.clone(), "{".into())),
        "invalid_input"
    );
    // A policy the engine refuses: no operation.
    let empty = serde_json::to_string(&Policy::new()).unwrap();
    assert_eq!(code(sign_policy(device.clone(), empty)), "refused");
    let signed = sign_policy(device, policy_json(&caller_public)).unwrap();
    let seal = |fields: Vec<Field>| {
        seal_record(
            user.clone(),
            signed.clone(),
            "mac".into(),
            "alice".into(),
            fields,
        )
    };
    // The required field is missing, empty, or given twice.
    assert_eq!(code(seal(Vec::new())), "refused");
    let field = |value: &[u8]| Field {
        name: "key".into(),
        value: value.to_vec(),
    };
    assert_eq!(code(seal(vec![field(b"")])), "invalid_input");
    assert_eq!(code(seal(vec![field(b"a"), field(b"b")])), "invalid_input");
    assert_eq!(
        code(seal_record(
            user.clone(),
            "{}".into(),
            "mac".into(),
            "alice".into(),
            vec![field(b"a")]
        )),
        "invalid_input"
    );
    assert_eq!(
        code(rewrap_record(user, "{}".into(), signed.clone())),
        "invalid_input"
    );
    assert_eq!(
        code(pin_record(generate_key(KeyKind::Device), "[]".into())),
        "invalid_input"
    );
    let device = generate_key(KeyKind::Device);
    assert_eq!(
        code(revoke(device.clone(), "alice".into(), "{}".into())),
        "invalid_input"
    );
    let ident = identity_json(&a_node().identity());
    assert_eq!(
        code(endorse_device(
            device.clone(),
            "alice".into(),
            ident.clone(),
            "x".into()
        )),
        "invalid_key"
    );
    assert_eq!(
        code(retire_device(device, "".into(), ident, "x".into())),
        "invalid_input"
    );
}

#[test]
fn error_codes_are_stable_and_distinct() {
    let detail = String::new;
    let all = [
        ClientError::InvalidKey { detail: detail() },
        ClientError::InvalidInput { detail: detail() },
        ClientError::NonceRejected { detail: detail() },
        ClientError::MeasurementsInvalid { detail: detail() },
        ClientError::AttestationRefused {
            reason: detail(),
            detail: detail(),
        },
        ClientError::BindingMismatch { detail: detail() },
        ClientError::VerificationExpired { detail: detail() },
        ClientError::Refused { detail: detail() },
    ];
    let codes: Vec<_> = all.iter().map(ClientError::code).collect();
    assert_eq!(
        codes,
        [
            "invalid_key",
            "invalid_input",
            "nonce_rejected",
            "measurements_invalid",
            "attestation_refused",
            "binding_mismatch",
            "verification_expired",
            "refused"
        ]
    );
}

#[test]
fn an_old_policy_converts_and_signs_again() {
    let device = generate_key(KeyKind::Device);
    let caller_public = public_key(KeyKind::Caller, generate_key(KeyKind::Caller)).unwrap();
    let old = serde_json::json!({
        "fields": [{"name": "key", "secret": true}],
        "callers": [{"name": "app", "key": caller_public, "operations": ["sign"]}],
        "operations": [{"kind": "derive", "name": "sign",
                        "template": "{{ hex(hmac_sha256(key, $input)) }}"}]
    })
    .to_string();
    // The old format no longer signs.
    assert_eq!(
        code(sign_policy(device.clone(), old.clone())),
        "invalid_input"
    );
    let upgrade: serde_json::Value = serde_json::from_str(&upgrade_policy(old).unwrap()).unwrap();
    let notes = upgrade["notes"].as_array().unwrap();
    assert!(
        notes[0].as_str().unwrap().contains("signed again"),
        "{notes:?}"
    );
    sign_policy(device, upgrade["policy"].to_string()).unwrap();
    assert_eq!(code(upgrade_policy("{".into())), "refused");
}
