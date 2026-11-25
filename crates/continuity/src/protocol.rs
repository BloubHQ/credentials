//! The hand-over protocol between two nodes, relayed by the host.
//!
//! Neither node trusts the host: every message is checked by its content. The host only
//! carries four messages, and the successor statement and its bundle (public files of the
//! release), between the two enclaves:
//!
//! 1. **Challenge** (predecessor): its identity, its release and a fresh nonce `n1`.
//! 2. **Offer** (successor): checks the statement (signature, signer, log, not a downgrade,
//!    `to` is its own release, `from` is the challenger's), and answers with its identity, an
//!    attestation document over `n1` whose user data is its identity's report data, and a
//!    fresh nonce `n2`.
//! 3. **Package** (predecessor): checks the statement the same way (`from` is its own
//!    release), the successor's document against the measurements of `to` only (an unlisted
//!    or older image is refused), its nonce `n1` (once, within five minutes) and its binding
//!    to the successor's identity; then hands over ([`engine::node::Node::hand_over`]: the
//!    state sealed with HPKE to the successor's seal key, the hand-over entry logged, the node
//!    stopped) and answers with the package and its own document over `n2`.
//! 4. **Take-over** (successor): checks the predecessor's document against the measurements of
//!    `from`, its nonce `n2` and its binding to the predecessor's identity, that the
//!    hand-over entry names the statement it checked, then takes over
//!    ([`engine::node::Node::take_over`]).
//!
//! The package is a sealed message: HPKE to a key the successor's attestation vouches for,
//! inside a hand-over entry signed by a key the predecessor's attestation vouches for. No TLS
//! session is needed between the enclaves, and the host sees only ciphertext.

use std::sync::{Mutex, PoisonError};

use attest::Measurement;
use engine::grant::NodeIdentity;
use engine::log::{Event, LogSink};
use engine::node::{Clock, HandOver, Node, Successor, TakenOver};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use crate::sigstore::WorkflowIdentity;
use crate::statement::{SignedStatement, VerifiedStatement, verify_statement};
use crate::trust::TrustRoot;
use crate::{Error, Result};

/// Bytes of a nonce of the protocol.
pub const NONCE_LEN: usize = 32;
/// How long a nonce of the protocol may be answered: five minutes.
pub const MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// Makes attestation documents: the Nitro Secure Module in an enclave, a test attester in
/// tests.
pub trait Attester {
    /// A signed document that carries `user_data` and `nonce`.
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> std::result::Result<Vec<u8>, String>;
}

/// What a node checks its peer against: the pinned roots, the signer of statements and its
/// own release.
#[derive(Clone, Debug)]
pub struct Checks {
    /// The roots of attestation documents (the AWS Nitro root).
    pub nitro_roots: Vec<CertificateDer<'static>>,
    /// The Sigstore trust root.
    pub trust: TrustRoot,
    /// The signer of successor statements.
    pub identity: WorkflowIdentity,
    /// The release this node runs, compiled into its image.
    pub release: String,
}

impl Checks {
    /// The checks compiled into a release: the AWS Nitro root, the Sigstore root of
    /// `trust/trusted_root.json` and the release workflow of this repository.
    pub fn production(release: &str) -> Result<Self> {
        Ok(Self {
            nitro_roots: vec![attest::aws_root()],
            trust: TrustRoot::production()?,
            identity: WorkflowIdentity::release_workflow(),
            release: release.to_string(),
        })
    }

    fn statement(&self, signed: &SignedStatement) -> Result<VerifiedStatement> {
        verify_statement(signed, &self.trust, &self.identity)
    }

    /// Verifies the document of the peer: chain, signature, nonce, not a debug enclave, the
    /// measurements of `expected` and nothing else, and its binding to `identity`.
    fn peer(
        &self,
        document: &[u8],
        nonce: &[u8],
        expected: &Measurement,
        identity: &NodeIdentity,
    ) -> Result<()> {
        let verified = attest::verify(
            document,
            nonce,
            std::slice::from_ref(expected),
            &self.nitro_roots,
        )?;
        attest::bind(identity, &verified)?;
        Ok(())
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&engine::encoding::to_b64(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::Engine as _;
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| de::Error::custom("invalid base64url"))
    }
}

/// Message 1, from the predecessor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// The predecessor.
    pub predecessor: NodeIdentity,
    /// Its release.
    pub release: String,
    /// The nonce the successor's document must carry.
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
}

/// Message 2, from the successor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// The successor.
    pub successor: NodeIdentity,
    /// Its release.
    pub release: String,
    /// Its attestation document over the challenge's nonce.
    #[serde(with = "b64")]
    pub document: Vec<u8>,
    /// The nonce the predecessor's document must carry.
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
}

/// Message 3, from the predecessor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    /// The predecessor.
    pub predecessor: NodeIdentity,
    /// Its attestation document over the offer's nonce.
    #[serde(with = "b64")]
    pub document: Vec<u8>,
    /// The hand-over entry and the sealed state.
    pub hand_over: HandOver,
}

fn fresh_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::Protocol("no random source"))?;
    Ok(nonce)
}

/// A nonce this side issued, kept until it is answered once.
struct Issued<T> {
    nonce: [u8; NONCE_LEN],
    issued_ms: u64,
    context: T,
}

fn take<T>(slot: &Mutex<Option<Issued<T>>>, now: u64) -> Result<Issued<T>> {
    let issued = slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or(Error::Protocol("no hand-over is in progress"))?;
    if now.saturating_sub(issued.issued_ms) > MAX_AGE_MS || issued.issued_ms > now {
        return Err(Error::Protocol(
            "the hand-over took longer than five minutes",
        ));
    }
    Ok(issued)
}

fn attest_self<A: Attester + ?Sized>(
    attester: &A,
    identity: &NodeIdentity,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    if nonce.is_empty() || nonce.len() > 512 {
        return Err(Error::Protocol("the peer's nonce is not 1 to 512 bytes"));
    }
    attester
        .attest(&identity.report_data(), nonce)
        .map_err(Error::Attester)
}

/// The predecessor's side.
pub struct Predecessor {
    checks: Checks,
    issued: Mutex<Option<Issued<()>>>,
}

impl Predecessor {
    /// The side of a node that will hand over.
    pub fn new(checks: Checks) -> Self {
        Self {
            checks,
            issued: Mutex::new(None),
        }
    }

    /// Message 1. A new challenge replaces any earlier one.
    ///
    /// A node that already handed over still answers, so that a package lost on the way can be
    /// asked for again by the same successor; to any other successor [`Node::hand_over`]
    /// refuses.
    pub fn challenge<S: LogSink, C: Clock>(
        &self,
        node: &Node<S, C>,
        now: u64,
    ) -> Result<Challenge> {
        let nonce = fresh_nonce()?;
        *self.issued.lock().unwrap_or_else(PoisonError::into_inner) = Some(Issued {
            nonce,
            issued_ms: now,
            context: (),
        });
        Ok(Challenge {
            predecessor: node.identity(),
            release: self.checks.release.clone(),
            nonce: nonce.to_vec(),
        })
    }

    /// Message 3: checks the offer and hands over. The challenge is spent, also on failure.
    pub fn hand_over<S: LogSink, C: Clock, A: Attester + ?Sized>(
        &self,
        node: &Node<S, C>,
        attester: &A,
        offer: &Offer,
        signed: &SignedStatement,
        now: u64,
    ) -> Result<Package> {
        let issued = take(&self.issued, now)?;
        let verified = self.checks.statement(signed)?;
        let statement = &verified.statement;
        if statement.from.release != self.checks.release {
            return Err(Error::StatementNotForThisRelease);
        }
        if offer.release != statement.to.release {
            return Err(Error::Protocol(
                "the offer is for another release than the statement",
            ));
        }
        self.checks.peer(
            &offer.document,
            &issued.nonce,
            &statement.to,
            &offer.successor,
        )?;
        let hand_over = node.hand_over(&Successor {
            identity: offer.successor,
            release: statement.to.release.clone(),
            statement_sha256: verified.sha256,
        })?;
        let document = attest_self(attester, &node.identity(), &offer.nonce)?;
        Ok(Package {
            predecessor: node.identity(),
            document,
            hand_over,
        })
    }
}

/// What the successor remembers between its offer and the package.
struct Offered {
    predecessor: NodeIdentity,
    statement_sha256: [u8; 32],
}

/// The successor's side.
pub struct SuccessorSide {
    checks: Checks,
    issued: Mutex<Option<Issued<Offered>>>,
}

impl SuccessorSide {
    /// The side of a new node that will take over.
    pub fn new(checks: Checks) -> Self {
        Self {
            checks,
            issued: Mutex::new(None),
        }
    }

    /// Message 2: checks the statement and answers the challenge.
    pub fn offer<S: LogSink, C: Clock, A: Attester + ?Sized>(
        &self,
        node: &Node<S, C>,
        attester: &A,
        challenge: &Challenge,
        signed: &SignedStatement,
        now: u64,
    ) -> Result<Offer> {
        let verified = self.checks.statement(signed)?;
        let statement = &verified.statement;
        if statement.to.release != self.checks.release {
            return Err(Error::StatementNotForThisRelease);
        }
        if statement.from.release != challenge.release {
            return Err(Error::Protocol(
                "the challenge comes from another release than the statement",
            ));
        }
        if challenge.predecessor == node.identity() {
            return Err(Error::Protocol("a node does not take over from itself"));
        }
        let document = attest_self(attester, &node.identity(), &challenge.nonce)?;
        let nonce = fresh_nonce()?;
        *self.issued.lock().unwrap_or_else(PoisonError::into_inner) = Some(Issued {
            nonce,
            issued_ms: now,
            context: Offered {
                predecessor: challenge.predecessor,
                statement_sha256: verified.sha256,
            },
        });
        Ok(Offer {
            successor: node.identity(),
            release: self.checks.release.clone(),
            document,
            nonce: nonce.to_vec(),
        })
    }

    /// Message 4: checks the package and takes over. The offer is spent, also on failure.
    pub fn take_over<S: LogSink, C: Clock>(
        &self,
        node: &Node<S, C>,
        package: &Package,
        signed: &SignedStatement,
        now: u64,
    ) -> Result<TakenOver> {
        let issued = take(&self.issued, now)?;
        if package.predecessor != issued.context.predecessor {
            return Err(Error::Protocol(
                "the package comes from another node than the challenge",
            ));
        }
        let verified = self.checks.statement(signed)?;
        if verified.sha256 != issued.context.statement_sha256 {
            return Err(Error::Protocol("another statement than the one offered on"));
        }
        self.checks.peer(
            &package.document,
            &issued.nonce,
            &verified.statement.from,
            &package.predecessor,
        )?;
        match &package.hand_over.entry.entry.event {
            Event::HandOver {
                statement_sha256,
                release,
                ..
            } if **statement_sha256 == verified.sha256 && *release == self.checks.release => {}
            _ => {
                return Err(Error::Protocol(
                    "the hand-over entry names another statement or release",
                ));
            }
        }
        Ok(node.take_over(&package.predecessor.log_key, &package.hand_over)?)
    }
}
