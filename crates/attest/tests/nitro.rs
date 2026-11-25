//! Verification of real Nitro attestation documents (see `tests/fixtures/README.md`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use attest::{
    AWS_NITRO_ROOT_G1, CertificateDer, Error, Measurement, Measurements, PCR_LEN, Verified,
    aws_root, bind, verify,
};
use ciborium::Value;
use engine::keys::NodeKey;
use engine::log::MemorySink;
use engine::node::{Node, SystemClock};
use sha2::{Digest, Sha256};

/// A production enclave, 2026-10-01T04:26:30Z.
const DOCUMENT: &[u8] = include_bytes!("fixtures/nitro-attestation-prerelease.cbor");
/// The nonce the production document was asked for, read at run time.
fn fixture_nonce() -> &'static [u8] {
    static NONCE: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/nitro-attestation-prerelease.nonce"
        );
        std::fs::read(path).unwrap()
    });
    &NONCE
}
const MEASUREMENTS: &[u8] = include_bytes!("fixtures/measurements-prerelease.json");
/// A debug enclave (PCRs all zero), 2023-09-18T15:03:30Z.
const DEBUG_DOCUMENT: &[u8] = include_bytes!("fixtures/nitro-attestation-debug.cbor");
const UNRELATED_ROOT: &[u8] = include_bytes!("fixtures/unrelated-root.der");

const TIMESTAMP_S: u64 = 1_790_828_790;
const DAY_MS: u64 = 24 * 3600 * 1000;

fn accepted() -> Vec<Measurement> {
    Measurements::from_json(MEASUREMENTS)
        .unwrap()
        .as_slice()
        .to_vec()
}

fn roots() -> Vec<CertificateDer<'static>> {
    vec![aws_root()]
}

fn decode(bytes: &[u8]) -> Value {
    ciborium::de::from_reader(bytes).unwrap()
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).unwrap();
    out
}

/// The four items of the COSE_Sign1 of a document.
fn items(document: &[u8]) -> Vec<Value> {
    match decode(document) {
        Value::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

/// The payload map of a document.
fn payload(document: &[u8]) -> Vec<(Value, Value)> {
    match &items(document)[2] {
        Value::Bytes(bytes) => match decode(bytes) {
            Value::Map(entries) => entries,
            other => panic!("not a map: {other:?}"),
        },
        other => panic!("not bytes: {other:?}"),
    }
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> &'a Value {
    &entries
        .iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap()
        .1
}

/// The document with its payload changed by `change` (the signature no longer covers it).
fn with_payload(document: &[u8], change: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut entries = payload(document);
    change(&mut entries);
    let mut items = items(document);
    items[2] = Value::Bytes(encode(&Value::Map(entries)));
    encode(&Value::Array(items))
}

fn set(entries: &mut [(Value, Value)], name: &str, value: Value) {
    let entry = entries
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .unwrap();
    entry.1 = value;
}

#[test]
fn the_pinned_root_is_aws_nitro_enclaves_root_g1() {
    assert_eq!(
        Sha256::digest(AWS_NITRO_ROOT_G1).as_slice(),
        [
            0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6,
            0x06, 0x31, 0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6,
            0x8f, 0x79, 0xbb, 0x5b
        ]
    );
}

#[test]
fn a_real_document_verifies() {
    let verified = verify(DOCUMENT, fixture_nonce(), &accepted(), &roots()).unwrap();
    let measurement = &accepted()[0];
    assert_eq!(verified.release, "v1.0.0");
    assert_eq!(
        verified.module_id,
        "i-00e27c4213a488340-enc01a0f5b621ecd411"
    );
    assert_eq!(verified.timestamp_ms / 1000, TIMESTAMP_S);
    assert_eq!(verified.pcr(0), Some(&measurement.pcr0));
    assert_eq!(verified.pcr(1), Some(&measurement.pcr1));
    assert_eq!(verified.pcr(2), Some(&measurement.pcr2));
    assert!(!verified.user_data.is_empty());
    // Among other releases, it is still found.
    let mut other = measurement.clone();
    other.release = "v0.9.0".to_string();
    other.pcr0[0] ^= 1;
    let list = vec![other, measurement.clone()];
    assert_eq!(
        verify(DOCUMENT, fixture_nonce(), &list, &roots())
            .unwrap()
            .release,
        "v1.0.0"
    );
}

#[test]
fn a_tagged_document_verifies() {
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(DOCUMENT);
    verify(&tagged, fixture_nonce(), &accepted(), &roots()).unwrap();
    // Any other tag is refused.
    tagged[0] = 0xd1;
    assert!(matches!(
        verify(&tagged, fixture_nonce(), &accepted(), &roots()),
        Err(Error::NotCoseSign1(_))
    ));
}

#[test]
fn a_wrong_nonce_is_refused() {
    let mut nonce = fixture_nonce().to_vec();
    nonce[0] ^= 1;
    assert!(matches!(
        verify(DOCUMENT, &nonce, &accepted(), &roots()),
        Err(Error::NonceMismatch)
    ));
    assert!(matches!(
        verify(DOCUMENT, &fixture_nonce()[..31], &accepted(), &roots()),
        Err(Error::NonceMismatch)
    ));
    assert!(matches!(
        verify(DOCUMENT, &fixture_nonce()[..0], &accepted(), &roots()),
        Err(Error::NonceEmpty)
    ));
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    // The signature is the last item: its 96 bytes end the document.
    for at in [DOCUMENT.len() - 1, DOCUMENT.len() - 50, DOCUMENT.len() - 96] {
        let mut document = DOCUMENT.to_vec();
        document[at] ^= 0x01;
        assert!(matches!(
            verify(&document, fixture_nonce(), &accepted(), &roots()),
            Err(Error::SignatureInvalid)
        ));
    }
}

#[test]
fn a_flipped_payload_byte_is_refused() {
    let Value::Bytes(user_data) = field(&payload(DOCUMENT), "user_data").clone() else {
        panic!("no user data");
    };
    let at = DOCUMENT
        .windows(user_data.len())
        .position(|window| window == user_data.as_slice())
        .unwrap();
    for offset in [0, user_data.len() / 2, user_data.len() - 1] {
        let mut document = DOCUMENT.to_vec();
        document[at + offset] ^= 0x80;
        assert!(matches!(
            verify(&document, fixture_nonce(), &accepted(), &roots()),
            Err(Error::SignatureInvalid)
        ));
    }
    // The nonce inside the payload too: the signature fails before the nonce is compared.
    let at = DOCUMENT
        .windows(fixture_nonce().len())
        .position(|window| window == fixture_nonce())
        .unwrap();
    let mut document = DOCUMENT.to_vec();
    document[at] ^= 1;
    assert!(matches!(
        verify(&document, fixture_nonce(), &accepted(), &roots()),
        Err(Error::SignatureInvalid)
    ));
}

#[test]
fn pcrs_not_in_the_list_are_refused() {
    for pcr in 0..3 {
        let mut list = accepted();
        match pcr {
            0 => list[0].pcr0[47] ^= 1,
            1 => list[0].pcr1[0] ^= 1,
            _ => list[0].pcr2[20] ^= 1,
        }
        assert!(matches!(
            verify(DOCUMENT, fixture_nonce(), &list, &roots()),
            Err(Error::UnknownMeasurement)
        ));
    }
    assert!(matches!(
        verify(DOCUMENT, fixture_nonce(), &[], &roots()),
        Err(Error::UnknownMeasurement)
    ));
}

#[test]
fn a_debug_enclave_is_refused() {
    let entries = payload(DEBUG_DOCUMENT);
    let Value::Bytes(nonce) = field(&entries, "nonce").clone() else {
        panic!("no nonce");
    };
    let zero = Measurement {
        release: "debug".to_string(),
        git_commit: None,
        pcr0: [0; PCR_LEN],
        pcr1: [0; PCR_LEN],
        pcr2: [0; PCR_LEN],
    };
    // Even when the owner lists all-zero measurements, the document is refused.
    assert!(matches!(
        verify(DEBUG_DOCUMENT, &nonce, &[zero], &roots()),
        Err(Error::DebugEnclave)
    ));
    assert!(matches!(
        verify(DEBUG_DOCUMENT, &nonce, &accepted(), &roots()),
        Err(Error::DebugEnclave)
    ));
}

#[test]
fn a_wrong_root_is_refused() {
    // The document carries the AWS root as the first entry of its bundle: that copy is no
    // ground for trust, only the pinned roots are.
    let unrelated = vec![CertificateDer::from_slice(UNRELATED_ROOT)];
    assert!(matches!(
        verify(DOCUMENT, fixture_nonce(), &accepted(), &unrelated),
        Err(Error::ChainUntrusted(_))
    ));
    assert!(matches!(
        verify(DOCUMENT, fixture_nonce(), &accepted(), &[]),
        Err(Error::RootInvalid(_))
    ));
}

#[test]
fn a_time_outside_the_validity_of_the_certificates_is_refused() {
    let timestamp = TIMESTAMP_S * 1000;
    for time in [timestamp + DAY_MS, timestamp - DAY_MS, 0] {
        let document = with_payload(DOCUMENT, |entries| {
            set(entries, "timestamp", Value::Integer(time.into()));
        });
        assert!(
            matches!(
                verify(&document, fixture_nonce(), &accepted(), &roots()),
                Err(Error::CertificateNotValidAt { timestamp_ms, .. }) if timestamp_ms == time
            ),
            "{time}"
        );
    }
    // Within the validity, the chain holds and the changed payload fails the signature.
    let document = with_payload(DOCUMENT, |entries| {
        set(entries, "timestamp", Value::Integer((timestamp + 1).into()));
    });
    assert!(matches!(
        verify(&document, fixture_nonce(), &accepted(), &roots()),
        Err(Error::SignatureInvalid)
    ));
}

#[test]
fn malformed_documents_are_refused() {
    assert!(matches!(
        verify(
            &DOCUMENT[..DOCUMENT.len() - 1],
            fixture_nonce(),
            &accepted(),
            &roots()
        ),
        Err(Error::NotCbor)
    ));
    let mut trailing = DOCUMENT.to_vec();
    trailing.push(0);
    assert!(matches!(
        verify(&trailing, fixture_nonce(), &accepted(), &roots()),
        Err(Error::NotCbor)
    ));
    assert!(matches!(
        verify(&vec![0u8; 20_000], fixture_nonce(), &accepted(), &roots()),
        Err(Error::DocumentTooLarge)
    ));
    let mut three = items(DOCUMENT);
    three.pop();
    assert!(matches!(
        verify(
            &encode(&Value::Array(three)),
            fixture_nonce(),
            &accepted(),
            &roots()
        ),
        Err(Error::NotCoseSign1(_))
    ));
    // ES256 instead of ES384.
    let mut es256 = items(DOCUMENT);
    es256[0] = Value::Bytes(vec![0xa1, 0x01, 0x26]);
    assert!(matches!(
        verify(
            &encode(&Value::Array(es256)),
            fixture_nonce(),
            &accepted(),
            &roots()
        ),
        Err(Error::UnsupportedAlgorithm)
    ));
    let sha256 = with_payload(DOCUMENT, |entries| {
        set(entries, "digest", Value::Text("SHA256".to_string()));
    });
    assert!(matches!(
        verify(&sha256, fixture_nonce(), &accepted(), &roots()),
        Err(Error::UnsupportedDigest(_))
    ));
    let empty = with_payload(DOCUMENT, |entries| {
        set(entries, "cabundle", Value::Array(Vec::new()));
    });
    assert!(matches!(
        verify(&empty, fixture_nonce(), &accepted(), &roots()),
        Err(Error::EmptyCaBundle)
    ));
    let no_pcrs = with_payload(DOCUMENT, |entries| {
        entries.retain(|(key, _)| key.as_text() != Some("pcrs"));
    });
    assert!(matches!(
        verify(&no_pcrs, fixture_nonce(), &accepted(), &roots()),
        Err(Error::PayloadInvalid(_))
    ));
    let short_pcr = with_payload(DOCUMENT, |entries| {
        set(
            entries,
            "pcrs",
            Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![0; 32]))]),
        );
    });
    assert!(matches!(
        verify(&short_pcr, fixture_nonce(), &accepted(), &roots()),
        Err(Error::PayloadInvalid(_))
    ));
    let bad_leaf = with_payload(DOCUMENT, |entries| {
        set(entries, "certificate", Value::Bytes(vec![0x30, 0x00]));
    });
    assert!(matches!(
        verify(&bad_leaf, fixture_nonce(), &accepted(), &roots()),
        Err(Error::CertificateInvalid(_))
    ));
}

fn identity() -> engine::grant::NodeIdentity {
    Node::new(NodeKey::generate(), MemorySink::new(), SystemClock).identity()
}

#[test]
fn the_binding_must_be_the_node_identity() {
    let verified = verify(DOCUMENT, fixture_nonce(), &accepted(), &roots()).unwrap();
    // The fixture binds a node of another program, not this identity.
    assert!(matches!(
        bind(&identity(), &verified),
        Err(Error::BindingMismatch)
    ));
    let node = identity();
    let bound = Verified {
        user_data: node.report_data().to_vec(),
        ..verified
    };
    bind(&node, &bound).unwrap();
    assert!(matches!(
        bind(&identity(), &bound),
        Err(Error::BindingMismatch)
    ));
    let empty = Verified {
        user_data: Vec::new(),
        ..bound
    };
    assert!(matches!(bind(&node, &empty), Err(Error::BindingMismatch)));
}

#[test]
fn measurements_round_trip_through_a_file() {
    let list = Measurements::from_json(MEASUREMENTS).unwrap();
    assert_eq!(list.as_slice()[0].release, "v1.0.0");
    assert_eq!(
        list.as_slice()[0].git_commit.as_deref(),
        Some("7a7f628d991bc6646bafcc4a2a3fa4a424f74995")
    );
    let dir = std::env::temp_dir().join(format!("attest-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("measurements.json");
    list.save(&path).unwrap();
    assert_eq!(Measurements::load(&path).unwrap(), list);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(matches!(
        Measurements::load(&dir.join("missing.json")),
        Err(Error::Io { .. })
    ));
}
