//! Offline verification of a Sigstore bundle (`application/vnd.dev.sigstore.bundle`, v0.1
//! to v0.3) of a message signature, logged in Rekor as a `hashedrekord` entry.
//!
//! No maintained pure-Rust Sigstore verifier of the current RustCrypto generation exists
//! (`sigstore` 0.x pulls the previous generation, an async runtime and a network client),
//! so this module implements the minimal checks, each fuzzed (`crates/fuzz`):
//!
//! 1. the signing certificate chains, through the authority's intermediates, to a pinned
//!    Fulcio root at the time Rekor integrated the entry, with the code-signing extended key
//!    usage (`webpki`), and that authority was valid then;
//! 2. the certificate names the expected signer ([`WorkflowIdentity`]): the release workflow
//!    of this repository at the tag of the release, run by GitHub Actions on a GitHub-hosted
//!    runner;
//! 3. the signature over the message verifies under the certificate's key (ECDSA P-256 with
//!    SHA-256, or P-384 with SHA-384), and the digest the bundle states is the message's;
//! 4. the Rekor entry is a `hashedrekord` of exactly that digest, signature and certificate;
//! 5. its signed entry timestamp (the log's promise) verifies under a pinned Rekor key valid at
//!    the integration time;
//! 6. its inclusion proof leads from the entry to the root hash of a checkpoint the same key
//!    signed (RFC 6962 audit path, signed note).
//!
//! Not checked: the certificate's embedded SCTs (Certificate Transparency of Fulcio). The
//! Rekor inclusion, required here, makes the signature itself public; a Fulcio compromise is
//! a residual risk listed in `docs/threat-model.md`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage};

use crate::trust::{TrustRoot, within};
use crate::x509;
use crate::{Error, Result};

/// The largest bundle accepted, in bytes (a bundle is about 5 KiB).
pub const MAX_BUNDLE_LEN: usize = 64 * 1024;
/// Most hashes of an inclusion proof (a tree of 2^64 leaves needs 64).
pub const MAX_PROOF_HASHES: usize = 64;

/// `id-kp-codeSigning`, 1.3.6.1.5.5.7.3.3.
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

/// Who must have signed: a GitHub Actions workflow of one repository, at a tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowIdentity {
    /// The OIDC issuer of the workflow's identity token.
    pub issuer: String,
    /// The repository, as a URL.
    pub repository: String,
    /// The workflow file, as a URL; the certificate names it `@refs/tags/<release>`.
    pub workflow: String,
    /// The runner environment Fulcio records.
    pub runner: String,
}

impl WorkflowIdentity {
    /// The release workflow of this repository, compiled into the node and the client.
    pub fn release_workflow() -> Self {
        Self {
            issuer: "https://token.actions.githubusercontent.com".into(),
            repository: "https://github.com/BloubHQ/credentials".into(),
            workflow: "https://github.com/BloubHQ/credentials/.github/workflows/release.yml".into(),
            runner: "github-hosted".into(),
        }
    }

    /// The URI the certificate of the run for `release` carries.
    pub fn subject(&self, release: &str) -> String {
        format!("{}@refs/tags/{release}", self.workflow)
    }
}

/// A Sigstore bundle, as `cosign sign-blob --bundle` writes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    /// The media type, `application/vnd.dev.sigstore.bundle...`.
    pub media_type: String,
    /// The certificate and the log entries.
    pub verification_material: Material,
    /// The signature over the message.
    pub message_signature: MessageSignature,
}

/// The certificate and the log entries of a bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Material {
    /// The signing certificate (bundle v0.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Raw>,
    /// The signing certificate first (bundle v0.1, v0.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Chain>,
    /// The Rekor entries: exactly one is read.
    pub tlog_entries: Vec<TlogEntry>,
}

/// Bytes, as standard base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Raw {
    /// The bytes.
    pub raw_bytes: String,
}

/// A certificate chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// The certificates, signing certificate first.
    pub certificates: Vec<Raw>,
}

/// One Rekor entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlogEntry {
    /// Its index in the log.
    #[serde(deserialize_with = "int")]
    pub log_index: u64,
    /// The log.
    pub log_id: LogId,
    /// Its kind.
    pub kind_version: KindVersion,
    /// When the log integrated it, Unix seconds.
    #[serde(deserialize_with = "int")]
    pub integrated_time: u64,
    /// The signed entry timestamp.
    pub inclusion_promise: Promise,
    /// The audit path to a signed checkpoint.
    pub inclusion_proof: Proof,
    /// The entry, as the log canonicalized it (standard base64).
    pub canonicalized_body: String,
}

/// A log id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogId {
    /// SHA-256 of the log key (standard base64).
    pub key_id: String,
}

/// The kind of an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindVersion {
    /// `hashedrekord`.
    pub kind: String,
    /// `0.0.1`.
    pub version: String,
}

/// A signed entry timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Promise {
    /// ECDSA (DER) of the log over the entry, standard base64.
    pub signed_entry_timestamp: String,
}

/// An inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    /// The index of the entry.
    #[serde(deserialize_with = "int")]
    pub log_index: u64,
    /// The root hash of the tree, standard base64.
    pub root_hash: String,
    /// The size of the tree.
    #[serde(deserialize_with = "int")]
    pub tree_size: u64,
    /// The audit path, standard base64.
    pub hashes: Vec<String>,
    /// The checkpoint of the tree, signed by the log.
    pub checkpoint: Checkpoint,
}

/// A checkpoint (signed note).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The note.
    pub envelope: String,
}

/// A message signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    /// The digest of the message.
    pub message_digest: MessageDigest,
    /// The signature (DER), standard base64.
    pub signature: String,
}

/// A digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDigest {
    /// `SHA2_256`.
    pub algorithm: String,
    /// The digest, standard base64.
    pub digest: String,
}

/// Protobuf JSON writes 64-bit integers as strings; numbers are taken too.
fn int<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Int {
        Number(u64),
        Text(String),
    }
    match Int::deserialize(deserializer)? {
        Int::Number(n) => Ok(n),
        Int::Text(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text
            .parse()
            .map_err(|_| serde::de::Error::custom("not a 64-bit integer")),
        Int::Text(_) => Err(serde::de::Error::custom("not a 64-bit integer")),
    }
}

/// What a verified bundle states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// When Rekor integrated the entry, Unix seconds.
    pub integrated_time: u64,
    /// The index of the entry in the log.
    pub log_index: u64,
    /// The signer's URI (the workflow at the tag).
    pub subject: String,
}

fn invalid(what: &'static str) -> Error {
    Error::BundleInvalid(what)
}

fn b64(text: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|_| invalid("a value is not base64"))
}

fn b64_32(text: &str) -> Result<[u8; 32]> {
    b64(text)?
        .try_into()
        .map_err(|_| invalid("a hash is not 32 bytes"))
}

impl Bundle {
    /// Reads a bundle (JSON).
    pub fn from_json(json: &[u8]) -> Result<Self> {
        if json.len() > MAX_BUNDLE_LEN {
            return Err(invalid("larger than a bundle may be"));
        }
        let bundle: Bundle =
            serde_json::from_slice(json).map_err(|_| invalid("not a Sigstore bundle"))?;
        if !bundle
            .media_type
            .starts_with("application/vnd.dev.sigstore.bundle")
        {
            return Err(invalid("not a Sigstore bundle media type"));
        }
        Ok(bundle)
    }

    fn certificate(&self) -> Result<Vec<u8>> {
        let material = &self.verification_material;
        match (&material.certificate, &material.x509_certificate_chain) {
            (Some(cert), None) => b64(&cert.raw_bytes),
            (None, Some(chain)) => b64(&chain
                .certificates
                .first()
                .ok_or(invalid("the certificate chain is empty"))?
                .raw_bytes),
            _ => Err(invalid("not exactly one signing certificate")),
        }
    }
}

/// Verifies `bundle` as a signature of `message` by `identity` for `release`, against
/// `trust`. See the module documentation for every check.
pub fn verify(
    bundle: &Bundle,
    message: &[u8],
    release: &str,
    identity: &WorkflowIdentity,
    trust: &TrustRoot,
) -> Result<Verified> {
    if trust.is_empty() {
        return Err(Error::TrustRootEmpty);
    }
    let [entry] = bundle.verification_material.tlog_entries.as_slice() else {
        return Err(invalid("not exactly one transparency log entry"));
    };
    let certificate = bundle.certificate()?;
    let digest: [u8; 32] = Sha256::digest(message).into();

    // 3. The digest and the signature.
    let stated = &bundle.message_signature.message_digest;
    if stated.algorithm != "SHA2_256" || b64(&stated.digest)? != digest {
        return Err(Error::SignatureInvalid(
            "the bundle digest is not the message's",
        ));
    }
    let signature = b64(&bundle.message_signature.signature)?;

    // 1. The chain, at the time the log integrated the entry.
    let time_ms = entry
        .integrated_time
        .checked_mul(1000)
        .ok_or(invalid("integration time out of range"))?;
    let leaf_key = chain(&certificate, time_ms, trust)?;
    verify_signature(&leaf_key, message, &signature)?;

    // 2. The signer.
    let signer = x509::signer(&certificate)?;
    let subject = identity.subject(release);
    let refuse = |what| Err(Error::IdentityMismatch(what));
    if signer.uris.as_slice() != [subject.clone()] {
        return refuse("the certificate is not for the release workflow at this release");
    }
    if signer.fulcio(x509::ISSUER_V2) != Some(identity.issuer.as_str()) {
        return refuse("the certificate is not from the expected token issuer");
    }
    if signer.fulcio(x509::RUNNER_ENVIRONMENT) != Some(identity.runner.as_str()) {
        return refuse("the workflow did not run on the expected runner environment");
    }
    if signer.fulcio(x509::SOURCE_REPOSITORY) != Some(identity.repository.as_str()) {
        return refuse("the certificate is not for this repository");
    }
    let tag = format!("refs/tags/{release}");
    if signer.fulcio(x509::SOURCE_REF) != Some(tag.as_str()) {
        return refuse("the certificate is not for the tag of this release");
    }

    // 4. The entry.
    if entry.kind_version.kind != "hashedrekord" || entry.kind_version.version != "0.0.1" {
        return Err(invalid("the log entry is not a hashedrekord 0.0.1"));
    }
    let body = b64(&entry.canonicalized_body)?;
    check_body(&body, &digest, &signature, &certificate)?;

    // 5. The signed entry timestamp.
    let key_id = b64_32(&entry.log_id.key_id)?;
    let log = trust
        .logs
        .iter()
        .find(|log| log.key_id == key_id)
        .ok_or(Error::LogUntrusted)?;
    if !within(time_ms, log.valid_from_ms, log.valid_until_ms) {
        return Err(Error::LogUntrusted);
    }
    let promise = serde_json::to_vec(&serde_json::json!({
        "body": entry.canonicalized_body,
        "integratedTime": entry.integrated_time,
        "logID": hex(&key_id),
        "logIndex": entry.log_index,
    }))
    .map_err(|_| invalid("the entry cannot be encoded"))?;
    verify_p256(
        &log.key,
        &promise,
        &b64(&entry.inclusion_promise.signed_entry_timestamp)?,
    )
    .map_err(|_| Error::LogProofInvalid("the signed entry timestamp does not verify"))?;

    // 6. The inclusion proof and its checkpoint.
    let proof = &entry.inclusion_proof;
    // The proof's index is the entry's place in the tree of its shard; the entry's own index is
    // global across shards. The leaf (the body) is what the signed entry timestamp binds.
    if proof.hashes.len() > MAX_PROOF_HASHES {
        return Err(Error::LogProofInvalid("the proof is too long"));
    }
    let path = proof
        .hashes
        .iter()
        .map(|h| b64_32(h))
        .collect::<Result<Vec<_>>>()?;
    let root = b64_32(&proof.root_hash)?;
    if !inclusion(
        proof.log_index,
        proof.tree_size,
        &leaf_hash(&body),
        &path,
        &root,
    ) {
        return Err(Error::LogProofInvalid(
            "the inclusion proof does not lead to the root hash",
        ));
    }
    checkpoint(&proof.checkpoint.envelope, proof.tree_size, &root, log)?;
    Ok(Verified {
        integrated_time: entry.integrated_time,
        log_index: entry.log_index,
        subject,
    })
}

fn hex(bytes: &[u8]) -> String {
    attest::to_hex(bytes)
}

/// Validates the chain of `certificate` to a pinned Fulcio root at `time_ms` and returns its
/// SubjectPublicKeyInfo.
fn chain(certificate: &[u8], time_ms: u64, trust: &TrustRoot) -> Result<Vec<u8>> {
    let leaf_der = CertificateDer::from_slice(certificate);
    let leaf = EndEntityCert::try_from(&leaf_der)
        .map_err(|_| Error::CertificateMalformed("the signing certificate does not parse"))?;
    let time = UnixTime::since_unix_epoch(std::time::Duration::from_millis(time_ms));
    let algorithms = [
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P256_SHA384,
        webpki::ring::ECDSA_P384_SHA256,
        webpki::ring::ECDSA_P384_SHA384,
    ];
    let mut last = Error::ChainUntrusted("no authority was valid at the integration time".into());
    for authority in &trust.authorities {
        if !within(time_ms, authority.valid_from_ms, authority.valid_until_ms) {
            continue;
        }
        let root = CertificateDer::from_slice(&authority.root);
        let anchor = match webpki::anchor_from_trusted_cert(&root) {
            Ok(anchor) => anchor,
            Err(_) => {
                last = Error::TrustRootInvalid("a root certificate cannot be an anchor");
                continue;
            }
        };
        let intermediates: Vec<CertificateDer<'_>> = authority
            .intermediates
            .iter()
            .map(|der| CertificateDer::from_slice(der))
            .collect();
        match leaf.verify_for_usage(
            &algorithms,
            &[anchor],
            &intermediates,
            time,
            KeyUsage::required(CODE_SIGNING),
            None,
            None,
        ) {
            Ok(_) => return Ok(leaf.subject_public_key_info().as_ref().to_vec()),
            Err(e) => last = Error::ChainUntrusted(format!("{e}")),
        }
    }
    Err(last)
}

fn verify_signature(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    use p256::pkcs8::DecodePublicKey as _;
    if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) {
        use p256::ecdsa::signature::Verifier as _;
        let sig = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| Error::SignatureInvalid("the signature is not DER ECDSA"))?;
        return key
            .verify(message, &sig)
            .map_err(|_| Error::SignatureInvalid("the signature does not verify"));
    }
    if let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_der(spki) {
        use p384::ecdsa::signature::Verifier as _;
        let sig = p384::ecdsa::Signature::from_der(signature)
            .map_err(|_| Error::SignatureInvalid("the signature is not DER ECDSA"))?;
        return key
            .verify(message, &sig)
            .map_err(|_| Error::SignatureInvalid("the signature does not verify"));
    }
    Err(Error::SignatureInvalid(
        "the certificate key is not ECDSA P-256 or P-384",
    ))
}

/// Verifies an ECDSA P-256 (SHA-256, DER) signature under a SubjectPublicKeyInfo (DER).
pub(crate) fn verify_p256(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki)
        .map_err(|_| Error::TrustRootInvalid("a log key is not ECDSA P-256"))?;
    let sig = p256::ecdsa::Signature::from_der(signature)
        .map_err(|_| Error::SignatureInvalid("the signature is not DER ECDSA"))?;
    key.verify(message, &sig)
        .map_err(|_| Error::SignatureInvalid("the signature does not verify"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rekord {
    api_version: String,
    kind: String,
    spec: RekordSpec,
}

#[derive(Deserialize)]
struct RekordSpec {
    data: RekordData,
    signature: RekordSignature,
}

#[derive(Deserialize)]
struct RekordData {
    hash: RekordHash,
}

#[derive(Deserialize)]
struct RekordHash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekordSignature {
    content: String,
    public_key: RekordKey,
}

#[derive(Deserialize)]
struct RekordKey {
    content: String,
}

/// The DER of the one certificate of a PEM text.
fn pem_certificate(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).map_err(|_| invalid("the logged key is not PEM"))?;
    let body = text
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|rest| rest.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or(invalid("the logged key is not one PEM certificate"))?;
    let joined: String = body.split_whitespace().collect();
    b64(&joined)
}

pub(crate) fn check_body(
    body: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
    certificate: &[u8],
) -> Result<()> {
    let rekord: Rekord =
        serde_json::from_slice(body).map_err(|_| invalid("the log entry is not a hashedrekord"))?;
    let mismatch = |what| Err(Error::LogEntryMismatch(what));
    if rekord.api_version != "0.0.1" || rekord.kind != "hashedrekord" {
        return mismatch("the log entry is not a hashedrekord 0.0.1");
    }
    if rekord.spec.data.hash.algorithm != "sha256" || rekord.spec.data.hash.value != hex(digest) {
        return mismatch("the log entry is for another message");
    }
    if b64(&rekord.spec.signature.content)? != signature {
        return mismatch("the log entry holds another signature");
    }
    if pem_certificate(&b64(&rekord.spec.signature.public_key.content)?)? != certificate {
        return mismatch("the log entry holds another certificate");
    }
    Ok(())
}

/// The hash of a leaf of a Merkle tree (RFC 6962).
pub(crate) fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash.update(data);
    hash.finalize().into()
}

/// The hash of an inner node of a Merkle tree (RFC 6962).
pub(crate) fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

/// Verifies an inclusion proof (RFC 9162, section 2.1.3.2).
pub(crate) fn inclusion(
    index: u64,
    size: u64,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// Verifies a checkpoint (a signed note: origin, tree size, root hash, then signature lines)
/// of `size` and `root`, signed by `log`.
pub(crate) fn checkpoint(
    note: &str,
    size: u64,
    root: &[u8; 32],
    log: &crate::trust::Log,
) -> Result<()> {
    let bad = |what| Error::LogProofInvalid(what);
    let (body, signatures) = note
        .split_once("\n\n")
        .ok_or(bad("the checkpoint is not a signed note"))?;
    let mut lines = body.split('\n');
    let (origin, tree, hash) = (lines.next(), lines.next(), lines.next());
    if origin.is_none_or(str::is_empty) {
        return Err(bad("the checkpoint has no origin"));
    }
    if tree != Some(size.to_string().as_str()) {
        return Err(bad("the checkpoint is for another tree size"));
    }
    if hash != Some(STANDARD.encode(root).as_str()) {
        return Err(bad("the checkpoint is for another root hash"));
    }
    let signed = format!("{body}\n");
    let hint = log.key_id.get(..4).ok_or(bad("no key hint"))?;
    for line in signatures.lines() {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((_, encoded)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Ok(bytes) = STANDARD.decode(encoded) else {
            continue;
        };
        let Some((key_hint, signature)) = bytes.split_at_checked(4) else {
            continue;
        };
        if key_hint == hint && verify_p256(&log.key, signed.as_bytes(), signature).is_ok() {
            return Ok(());
        }
    }
    Err(bad("the checkpoint is not signed by the log"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]

    use super::*;

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

    fn path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if leaves.len() <= 1 {
            return Vec::new();
        }
        let mut k = 1;
        while k * 2 < leaves.len() {
            k *= 2;
        }
        let (l, r) = leaves.split_at(k);
        if index < k {
            let mut p = path(index, l);
            p.push(tree(r));
            p
        } else {
            let mut p = path(index - k, r);
            p.push(tree(l));
            p
        }
    }

    #[test]
    fn every_leaf_of_every_small_tree_is_included_and_nothing_else() {
        for size in 1..=17usize {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| leaf_hash(&[i as u8])).collect();
            let root = tree(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let p = path(i, &leaves);
                let (i64_, n) = (i as u64, size as u64);
                assert!(inclusion(i64_, n, leaf, &p, &root), "{i} of {size}");
                assert!(!inclusion(i64_ + 1, n, leaf, &p, &root) || size == 1);
                assert!(!inclusion(i64_, n, &leaf_hash(b"x"), &p, &root));
                if let Some(first) = p.first() {
                    let mut bent = p.clone();
                    bent[0] = node_hash(first, first);
                    assert!(!inclusion(i64_, n, leaf, &bent, &root));
                }
            }
        }
    }
}
