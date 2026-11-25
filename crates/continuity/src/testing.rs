//! TEST ONLY: roots generated at run time that stand in for the AWS Nitro root, the Sigstore
//! Fulcio authority and the Rekor log, so the hand-over and the re-grant are tested without
//! Nitro hardware, AWS or Sigstore. Nothing here is a real key: every root is made fresh by
//! the test that uses it and trusted only by that test.
//!
//! - [`TestNitro`]: a P-384 root and signing certificate, and documents in the form the
//!   Nitro Secure Module writes them (COSE_Sign1, ES384), for measurements of the test's
//!   choosing ([`TestEnclave`] is an [`Attester`]).
//! - [`TestSigstore`]: a Fulcio-like authority (P-384 root and intermediate) that issues
//!   short-lived P-256 code-signing certificates with the Fulcio extensions, and a Rekor-like
//!   log (P-256) that logs `hashedrekord` entries in a Merkle tree, signs the entry timestamp
//!   and a checkpoint, and returns a Sigstore bundle v0.3.
#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use attest::Measurement;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ciborium::Value;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::protocol::{Attester, Checks};
use crate::sigstore::{
    Bundle, Checkpoint, KindVersion, LogId, Material, MessageDigest, MessageSignature, Promise,
    Proof, Raw, TlogEntry, WorkflowIdentity, leaf_hash, node_hash,
};
use crate::statement::{STATEMENT_TYPE, SignedStatement, Statement};
use crate::trust::{Authority, Log, TrustRoot};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

fn ca(name: &str, alg: &'static rcgen::SignatureAlgorithm) -> (CertificateParams, KeyPair) {
    let key = KeyPair::generate_for(alg).expect("a key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    (params, key)
}

/// TEST ONLY: a stand-in for the AWS Nitro root and the Nitro Secure Module.
pub struct TestNitro {
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: p384::ecdsa::SigningKey,
}

impl Default for TestNitro {
    fn default() -> Self {
        Self::new()
    }
}

impl TestNitro {
    /// A fresh test root and signing certificate.
    pub fn new() -> Self {
        let (root_params, root_key) = ca("TEST ONLY Nitro root", &rcgen::PKCS_ECDSA_P384_SHA384);
        let root = root_params
            .self_signed(&root_key)
            .expect("root")
            .der()
            .to_vec();
        let issuer = Issuer::new(root_params, root_key);
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "TEST ONLY enclave");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2045, 1, 1);
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf")
            .der()
            .to_vec();
        let key = p384::ecdsa::SigningKey::from_pkcs8_der(&leaf_key.serialize_der())
            .expect("a P-384 key");
        Self { root, leaf, key }
    }

    /// The test root, to pin instead of the AWS root.
    pub fn root(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.root.clone())
    }

    /// A document of an enclave with the PCRs of `measurement`, `user_data` and `nonce`.
    pub fn document(&self, measurement: &Measurement, user_data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let encode = |value: &Value| {
            let mut out = Vec::new();
            ciborium::ser::into_writer(value, &mut out).expect("CBOR");
            out
        };
        let pcrs = [&measurement.pcr0, &measurement.pcr1, &measurement.pcr2]
            .iter()
            .enumerate()
            .map(|(i, pcr)| (Value::Integer(i.into()), Value::Bytes(pcr.to_vec())))
            .collect();
        let payload = encode(&Value::Map(vec![
            (
                Value::Text("module_id".into()),
                Value::Text("i-test-enc-test".into()),
            ),
            (Value::Text("digest".into()), Value::Text("SHA384".into())),
            (
                Value::Text("timestamp".into()),
                Value::Integer(now_ms().into()),
            ),
            (Value::Text("pcrs".into()), Value::Map(pcrs)),
            (
                Value::Text("certificate".into()),
                Value::Bytes(self.leaf.clone()),
            ),
            (
                Value::Text("cabundle".into()),
                Value::Array(vec![Value::Bytes(self.root.clone())]),
            ),
            (Value::Text("public_key".into()), Value::Null),
            (
                Value::Text("user_data".into()),
                Value::Bytes(user_data.to_vec()),
            ),
            (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        ]));
        let protected = encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-35).into()),
        )]));
        let to_sign = encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]));
        let signature: p384::ecdsa::Signature = self.key.sign(&to_sign);
        encode(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
    }

    /// An attester of an enclave that runs `measurement`.
    pub fn enclave(&self, measurement: &Measurement) -> TestEnclave<'_> {
        TestEnclave {
            nitro: self,
            measurement: measurement.clone(),
        }
    }
}

/// TEST ONLY: an enclave of a [`TestNitro`].
pub struct TestEnclave<'a> {
    nitro: &'a TestNitro,
    measurement: Measurement,
}

impl Attester for TestEnclave<'_> {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.nitro.document(&self.measurement, user_data, nonce))
    }
}

/// TEST ONLY: who a test certificate names.
#[derive(Clone, Debug)]
pub struct TestSigner {
    /// The subject alternative name URI.
    pub subject: String,
    /// Fulcio extension .8, the token issuer.
    pub issuer: String,
    /// Fulcio extension .11, the runner environment.
    pub runner: String,
    /// Fulcio extension .12, the source repository.
    pub repository: String,
    /// Fulcio extension .14, the ref.
    pub git_ref: String,
}

impl TestSigner {
    /// The release workflow of `identity` at the tag `release`.
    pub fn release(identity: &WorkflowIdentity, release: &str) -> Self {
        Self {
            subject: identity.subject(release),
            issuer: identity.issuer.clone(),
            runner: identity.runner.clone(),
            repository: identity.repository.clone(),
            git_ref: format!("refs/tags/{release}"),
        }
    }
}

fn utf8_string(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = vec![0x0c];
    if bytes.len() < 0x80 {
        out.push(u8::try_from(bytes.len()).expect("short"));
    } else {
        out.extend([0x81, u8::try_from(bytes.len()).expect("short")]);
    }
    out.extend_from_slice(bytes);
    out
}

fn tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => [0; 32],
        [one] => *one,
        _ => {
            let mut k = 1;
            while k * 2 < leaves.len() {
                k *= 2;
            }
            let (l, r) = leaves.split_at(k);
            node_hash(&tree(l), &tree(r))
        }
    }
}

fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let mut k = 1;
    while k * 2 < leaves.len() {
        k *= 2;
    }
    let (l, r) = leaves.split_at(k);
    if index < k {
        let mut p = audit_path(index, l);
        p.push(tree(r));
        p
    } else {
        let mut p = audit_path(index - k, r);
        p.push(tree(l));
        p
    }
}

/// TEST ONLY: a stand-in for Fulcio and Rekor.
pub struct TestSigstore {
    root: Vec<u8>,
    intermediate: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    rekor: p256::ecdsa::SigningKey,
    rekor_spki: Vec<u8>,
}

impl Default for TestSigstore {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSigstore {
    /// A fresh test authority and log.
    pub fn new() -> Self {
        let (root_params, root_key) = ca("TEST ONLY Fulcio root", &rcgen::PKCS_ECDSA_P384_SHA384);
        let root = root_params
            .self_signed(&root_key)
            .expect("root")
            .der()
            .to_vec();
        let root_issuer = Issuer::new(root_params, root_key);
        let (mut mid_params, mid_key) = ca(
            "TEST ONLY Fulcio intermediate",
            &rcgen::PKCS_ECDSA_P384_SHA384,
        );
        // As the Sigstore intermediate: it carries the code-signing usage, which webpki requires
        // along the whole path.
        mid_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let intermediate = mid_params
            .signed_by(&mid_key, &root_issuer)
            .expect("intermediate")
            .der()
            .to_vec();
        let rekor_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let rekor = p256::ecdsa::SigningKey::from_pkcs8_der(&rekor_pair.serialize_der())
            .expect("a P-256 key");
        let rekor_spki = rekor
            .verifying_key()
            .to_public_key_der()
            .expect("SPKI")
            .as_bytes()
            .to_vec();
        Self {
            root,
            intermediate,
            issuer: Issuer::new(mid_params, mid_key),
            rekor,
            rekor_spki,
        }
    }

    /// The trust root that trusts this authority and log only.
    pub fn trust_root(&self) -> TrustRoot {
        TrustRoot {
            authorities: vec![Authority {
                root: self.root.clone(),
                intermediates: vec![self.intermediate.clone()],
                valid_from_ms: 0,
                valid_until_ms: None,
            }],
            logs: vec![Log {
                key: self.rekor_spki.clone(),
                key_id: Sha256::digest(&self.rekor_spki).into(),
                valid_from_ms: 0,
                valid_until_ms: None,
            }],
        }
    }

    /// The same trust root as a `trusted_root.json`.
    pub fn trusted_root_json(&self) -> String {
        serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [{
                "baseUrl": "https://rekor.test.invalid",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": STANDARD.encode(&self.rekor_spki),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "validFor": {"start": "2020-01-01T00:00:00Z"},
                },
                "logId": {"keyId": STANDARD.encode(Sha256::digest(&self.rekor_spki))},
            }],
            "certificateAuthorities": [{
                "subject": {"organization": "TEST ONLY", "commonName": "TEST ONLY"},
                "uri": "https://fulcio.test.invalid",
                "certChain": {"certificates": [
                    {"rawBytes": STANDARD.encode(&self.intermediate)},
                    {"rawBytes": STANDARD.encode(&self.root)},
                ]},
                "validFor": {"start": "2020-01-01T00:00:00Z"},
            }],
            "ctlogs": [],
            "timestampAuthorities": [],
        })
        .to_string()
    }

    /// Signs `message` as `signer` with a fresh certificate, logs it, and returns the bundle.
    pub fn sign(&self, message: &[u8], signer: &TestSigner) -> Bundle {
        let leaf_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let leaf_key = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_pair.serialize_der())
            .expect("a P-256 key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![SanType::URI(
            signer.subject.clone().try_into().expect("an IA5 URI"),
        )];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::minutes(10);
        for (arc, value) in [
            (8, &signer.issuer),
            (11, &signer.runner),
            (12, &signer.repository),
            (14, &signer.git_ref),
        ] {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 57264, 1, arc],
                    utf8_string(value),
                ));
        }
        let certificate = params
            .signed_by(&leaf_pair, &self.issuer)
            .expect("leaf")
            .der()
            .to_vec();
        let signature: p256::ecdsa::Signature = leaf_key.sign(message);
        let signature = signature.to_der().as_bytes().to_vec();
        self.log(message, &certificate, &signature)
    }

    /// Logs a signature made elsewhere and returns its bundle.
    pub fn log(&self, message: &[u8], certificate: &[u8], signature: &[u8]) -> Bundle {
        let digest = Sha256::digest(message);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(certificate);
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        let body = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": attest::to_hex(&digest)}},
                "signature": {
                    "content": STANDARD.encode(signature),
                    "publicKey": {"content": STANDARD.encode(pem.as_bytes())},
                },
            },
        })
        .to_string();
        let canonicalized = STANDARD.encode(body.as_bytes());
        let key_id: [u8; 32] = Sha256::digest(&self.rekor_spki).into();
        let integrated_time = now_ms() / 1000;
        // The entry is leaf 5 of a tree of 7.
        let index = 5usize;
        let mut leaves: Vec<[u8; 32]> = (0u8..7).map(|i| leaf_hash(&[i; 9])).collect();
        if let Some(leaf) = leaves.get_mut(index) {
            *leaf = leaf_hash(body.as_bytes());
        }
        let root = tree(&leaves);
        let path = audit_path(index, &leaves);
        let log_index = 1000 + u64::try_from(index).expect("small");
        let promise = serde_json::to_vec(&serde_json::json!({
            "body": canonicalized,
            "integratedTime": integrated_time,
            "logID": attest::to_hex(&key_id),
            "logIndex": log_index,
        }))
        .expect("JSON");
        let set: p256::ecdsa::Signature = self.rekor.sign(&promise);
        let note = format!("rekor.test.invalid - 1\n7\n{}\n", STANDARD.encode(root));
        let note_sig: p256::ecdsa::Signature = self.rekor.sign(note.as_bytes());
        let mut hinted = key_id.get(..4).expect("four bytes").to_vec();
        hinted.extend_from_slice(note_sig.to_der().as_bytes());
        let envelope = format!(
            "{note}\n\u{2014} rekor.test.invalid {}\n",
            STANDARD.encode(hinted)
        );
        Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".into(),
            verification_material: Material {
                certificate: Some(Raw {
                    raw_bytes: STANDARD.encode(certificate),
                }),
                x509_certificate_chain: None,
                tlog_entries: vec![TlogEntry {
                    log_index,
                    log_id: LogId {
                        key_id: STANDARD.encode(key_id),
                    },
                    kind_version: KindVersion {
                        kind: "hashedrekord".into(),
                        version: "0.0.1".into(),
                    },
                    integrated_time,
                    inclusion_promise: Promise {
                        signed_entry_timestamp: STANDARD.encode(set.to_der().as_bytes()),
                    },
                    inclusion_proof: Proof {
                        log_index: u64::try_from(index).expect("small"),
                        root_hash: STANDARD.encode(root),
                        tree_size: 7,
                        hashes: path.iter().map(|h| STANDARD.encode(h)).collect(),
                        checkpoint: Checkpoint { envelope },
                    },
                    canonicalized_body: canonicalized,
                }],
            },
            message_signature: MessageSignature {
                message_digest: MessageDigest {
                    algorithm: "SHA2_256".into(),
                    digest: STANDARD.encode(digest),
                },
                signature: STANDARD.encode(signature),
            },
        }
    }

    /// A successor statement from `from` to `to`, signed by the release workflow of
    /// `identity` at the tag of `to`.
    pub fn statement(
        &self,
        identity: &WorkflowIdentity,
        from: &Measurement,
        to: &Measurement,
    ) -> SignedStatement {
        let bytes = statement_bytes(from, to);
        let bundle = self.sign(&bytes, &TestSigner::release(identity, &to.release));
        SignedStatement {
            statement: bytes,
            bundle,
        }
    }
}

/// The bytes of a statement from `from` to `to`, as the release workflow writes it.
pub fn statement_bytes(from: &Measurement, to: &Measurement) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&Statement {
        kind: STATEMENT_TYPE.into(),
        from: from.clone(),
        to: to.clone(),
    })
    .expect("JSON");
    bytes.push(b'\n');
    bytes
}

/// TEST ONLY measurements of `release`: every PCR byte is `seed` (never all zero).
pub fn measurement(release: &str, seed: u8) -> Measurement {
    Measurement {
        release: release.into(),
        git_commit: Some(format!("{seed:02x}").repeat(20)),
        pcr0: [seed.max(1); 48],
        pcr1: [seed.max(1).wrapping_add(1); 48],
        pcr2: [seed.max(1).wrapping_add(2); 48],
    }
}

/// The checks of a node of `release` that trusts only the test roots.
pub fn checks(nitro: &TestNitro, sigstore: &TestSigstore, release: &str) -> Checks {
    Checks {
        nitro_roots: vec![nitro.root()],
        trust: sigstore.trust_root(),
        identity: WorkflowIdentity::release_workflow(),
        release: release.into(),
    }
}

/// The PCRs of a measurement, by index, as a document states them.
pub fn pcrs(measurement: &Measurement) -> BTreeMap<u8, [u8; 48]> {
    BTreeMap::from([
        (0, measurement.pcr0),
        (1, measurement.pcr1),
        (2, measurement.pcr2),
    ])
}
