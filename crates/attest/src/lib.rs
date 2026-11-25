//! Verifier of AWS Nitro Enclaves attestation documents.
//!
//! Before an owner seals a grant to a node, it asks the node for an attestation document over a
//! fresh nonce and checks, with [`verify`]:
//!
//! 1. the structure: a COSE_Sign1 (RFC 9052), untagged or with tag 18, whose protected header
//!    is exactly `{1: -35}` (ES384), and whose payload is the map the Nitro Secure Module writes
//!    (`module_id`, `digest` = `"SHA384"`, `timestamp`, `pcrs`, `certificate`, `cabundle`,
//!    and optional `public_key`, `user_data`, `nonce`);
//! 2. the certificate chain: the signing certificate, through the intermediates of `cabundle`
//!    (whose first entry is the root, and is not trusted for being there), to a pinned root,
//!    usually [`aws_root`]. The chain is validated at the time the document states, not the
//!    time of the machine: the signing certificate lives for a few hours, and the document
//!    stays checkable as long as its signature holds;
//! 3. the signature: ECDSA P-384 with SHA-384 by the key of the signing certificate;
//! 4. the nonce: the one the owner asked for, so the document is fresh;
//! 5. the measurements: PCR0, PCR1 and PCR2 are present, not all zero (a debug enclave, which
//!    the host can inspect), and equal to those of an accepted release.
//!
//! Then [`bind`] checks that the user data of the document is
//! [`NodeIdentity::report_data`]: the enclave that runs the accepted release holds the keys
//! the owner is about to grant to.
//!
//! Every failure has its own [`Error`].

mod cose;
mod hex;
mod measurement;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use engine::grant::NodeIdentity;
use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey as _;
use rustls_pki_types::UnixTime;
use webpki::{EndEntityCert, KeyUsage};

pub use measurement::{Measurement, Measurements};
pub use rustls_pki_types::CertificateDer;

/// The length of a PCR of the Nitro Secure Module (SHA-384).
pub const PCR_LEN: usize = 48;

/// The largest document accepted, in bytes. A document of the module is about 4.5 KiB.
pub const MAX_DOCUMENT_LEN: usize = 16 * 1024;

/// The AWS Nitro Enclaves Root-G1 certificate (DER), as AWS publishes it in
/// `AWS_NitroEnclaves_Root-G1.zip`. Its SHA-256 is
/// `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
pub const AWS_NITRO_ROOT_G1: &[u8] = include_bytes!("aws-nitro-enclaves-root-g1.der");

/// `bytes` as lowercase hexadecimal, the form of the PCRs in `measurements.json`.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// The pinned AWS Nitro Enclaves Root-G1 certificate.
pub fn aws_root() -> CertificateDer<'static> {
    CertificateDer::from_slice(AWS_NITRO_ROOT_G1)
}

/// Why a document was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The document is larger than [`MAX_DOCUMENT_LEN`].
    #[error("the document is larger than {MAX_DOCUMENT_LEN} bytes")]
    DocumentTooLarge,
    /// The document is not one well-formed CBOR item.
    #[error("the document is not one well-formed CBOR item")]
    NotCbor,
    /// The document is CBOR, but not a COSE_Sign1.
    #[error("the document is not a COSE_Sign1: {0}")]
    NotCoseSign1(&'static str),
    /// The protected header is not exactly `{1: -35}` (ES384).
    #[error("the protected header is not exactly {{1: -35}} (ES384)")]
    UnsupportedAlgorithm,
    /// The payload is not the map of an attestation document.
    #[error("the payload is invalid: {0}")]
    PayloadInvalid(&'static str),
    /// The PCRs are not SHA-384 digests.
    #[error("the digest of the document is {0:?}, not \"SHA384\"")]
    UnsupportedDigest(String),
    /// `cabundle` is empty.
    #[error("the CA bundle of the document is empty")]
    EmptyCaBundle,
    /// A certificate of the document cannot be parsed.
    #[error("a certificate of the document cannot be parsed: {0}")]
    CertificateInvalid(String),
    /// A trust root cannot be parsed, or none was given.
    #[error("a trust root cannot be used: {0}")]
    RootInvalid(String),
    /// A certificate of the chain was not valid at the time the document states.
    #[error(
        "a certificate of the chain is not valid at the time of the document ({timestamp_ms} ms since the epoch): {reason}"
    )]
    CertificateNotValidAt {
        /// The time of the document, Unix milliseconds.
        timestamp_ms: u64,
        /// What the chain verification found.
        reason: String,
    },
    /// The certificate chain does not lead to a pinned root.
    #[error("the certificate chain does not lead to a pinned root: {0}")]
    ChainUntrusted(String),
    /// The key of the signing certificate is not an ECDSA P-384 key.
    #[error("the key of the signing certificate is not an ECDSA P-384 key")]
    LeafKeyNotP384,
    /// The signature does not verify under the signing certificate.
    #[error("the signature of the document does not verify")]
    SignatureInvalid,
    /// No nonce was given to check the document against.
    #[error("no nonce was given: ask for the document with a fresh random nonce")]
    NonceEmpty,
    /// The nonce of the document is missing or is not the one given.
    #[error("the nonce of the document is not the one asked for")]
    NonceMismatch,
    /// PCR0, PCR1 or PCR2 is missing.
    #[error("PCR{0} is missing")]
    PcrMissing(u8),
    /// PCR0, PCR1 and PCR2 are all zero: the enclave runs in debug mode.
    #[error("PCR0, PCR1 and PCR2 are all zero: a debug enclave, whose memory the host can read")]
    DebugEnclave,
    /// PCR0, PCR1 and PCR2 are not those of an accepted release.
    #[error("PCR0, PCR1 and PCR2 are not those of an accepted release")]
    UnknownMeasurement,
    /// The user data of the document is not the report data of the node identity.
    #[error("the user data of the document is not the report data of the node identity")]
    BindingMismatch,
    /// A measurements file is invalid.
    #[error("measurements: {0}")]
    Measurements(String),
    /// A file cannot be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
}

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// What a verified document states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The user data the enclave put in the document; empty when it put none.
    pub user_data: Vec<u8>,
    /// Every PCR of the document, by index.
    pub pcrs: BTreeMap<u8, [u8; PCR_LEN]>,
    /// When the module made the document, Unix milliseconds.
    pub timestamp_ms: u64,
    /// The accepted release whose measurements the PCRs equal.
    pub release: String,
    /// The enclave, such as `i-0123456789abcdef0-enc0123456789abcdef`.
    pub module_id: String,
    /// The public key the enclave put in the document, if any.
    pub public_key: Option<Vec<u8>>,
}

impl Verified {
    /// PCR `index`, if the document has it.
    pub fn pcr(&self, index: u8) -> Option<&[u8; PCR_LEN]> {
        self.pcrs.get(&index)
    }
}

/// Validates the chain of the signing certificate at `timestamp_ms` and returns its key.
fn verify_chain(
    certificate: &[u8],
    cabundle: &[Vec<u8>],
    timestamp_ms: u64,
    roots: &[CertificateDer<'_>],
) -> Result<VerifyingKey> {
    if roots.is_empty() {
        return Err(Error::RootInvalid("no root was given".to_string()));
    }
    let anchors = roots
        .iter()
        .map(|root| {
            webpki::anchor_from_trusted_cert(root).map_err(|e| Error::RootInvalid(format!("{e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let leaf_der = CertificateDer::from_slice(certificate);
    let leaf = EndEntityCert::try_from(&leaf_der)
        .map_err(|e| Error::CertificateInvalid(format!("{e}")))?;
    // AWS orders the bundle from the root down: its first entry is the root, which only a
    // pinned root may stand for. The others are intermediates, in any order for webpki.
    let intermediates: Vec<CertificateDer<'_>> = cabundle
        .iter()
        .skip(1)
        .map(|der| CertificateDer::from_slice(der))
        .collect();
    let time = UnixTime::since_unix_epoch(Duration::from_millis(timestamp_ms));
    // The certificates of the module carry no extended key usage, which webpki accepts for a
    // usage that is required only if present. One that does carry them must allow client
    // authentication.
    leaf.verify_for_usage(
        &[webpki::ring::ECDSA_P384_SHA384],
        &anchors,
        &intermediates,
        time,
        KeyUsage::client_auth(),
        None,
        None,
    )
    .map_err(|e| match e {
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            Error::CertificateNotValidAt {
                timestamp_ms,
                reason: format!("{e}"),
            }
        }
        other => Error::ChainUntrusted(format!("{other}")),
    })?;
    VerifyingKey::from_public_key_der(leaf.subject_public_key_info().as_ref())
        .map_err(|_| Error::LeafKeyNotP384)
}

/// Verifies an attestation document asked for with `nonce`, and returns what it states.
///
/// `accepted` are the measurements of the releases the owner trusts; `roots` the pinned roots,
/// usually `&[aws_root()]`. See the [crate] documentation for every check.
pub fn verify(
    document: &[u8],
    nonce: &[u8],
    accepted: &[Measurement],
    roots: &[CertificateDer<'_>],
) -> Result<Verified> {
    if nonce.is_empty() {
        return Err(Error::NonceEmpty);
    }
    if document.len() > MAX_DOCUMENT_LEN {
        return Err(Error::DocumentTooLarge);
    }
    let sign1 = cose::parse_sign1(document)?;
    let payload = cose::parse_payload(&sign1.payload)?;
    let key = verify_chain(
        &payload.certificate,
        &payload.cabundle,
        payload.timestamp_ms,
        roots,
    )?;
    let signature = Signature::from_slice(&sign1.signature).map_err(|_| Error::SignatureInvalid)?;
    key.verify(&cose::sig_structure(&sign1)?, &signature)
        .map_err(|_| Error::SignatureInvalid)?;
    if payload.nonce.as_deref() != Some(nonce) {
        return Err(Error::NonceMismatch);
    }
    let pcr = |index: u8| payload.pcrs.get(&index).ok_or(Error::PcrMissing(index));
    let (pcr0, pcr1, pcr2) = (pcr(0)?, pcr(1)?, pcr(2)?);
    if [pcr0, pcr1, pcr2]
        .iter()
        .all(|digest| digest.iter().all(|byte| *byte == 0))
    {
        return Err(Error::DebugEnclave);
    }
    let release = accepted
        .iter()
        .find(|measurement| measurement.matches(pcr0, pcr1, pcr2))
        .ok_or(Error::UnknownMeasurement)?
        .release
        .clone();
    Ok(Verified {
        user_data: payload.user_data.unwrap_or_default(),
        pcrs: payload.pcrs,
        timestamp_ms: payload.timestamp_ms,
        release,
        module_id: payload.module_id,
        public_key: payload.public_key,
    })
}

/// Checks that a verified document vouches for `identity`: its user data must be
/// [`NodeIdentity::report_data`], so the keys the owner grants to belong to the attested
/// enclave.
pub fn bind(identity: &NodeIdentity, verified: &Verified) -> Result<()> {
    if verified.user_data.as_slice() == identity.report_data().as_slice() {
        Ok(())
    } else {
        Err(Error::BindingMismatch)
    }
}
