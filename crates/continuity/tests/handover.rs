//! The hand-over protocol between two nodes, and the attacks on it: a downgrade, unlisted
//! measurements, forged and replayed successor statements, a package delivered twice, a
//! grant without `allow_successor`.
//!
//! Every root here is a TEST ONLY root generated at run time (`continuity::testing`): Nitro
//! hardware, AWS and Sigstore are never reached. The paths that only real hardware takes
//! (the NSM, vsock) are not covered by these tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::time::Duration;

use attest::Measurement;
use continuity::sigstore::{self, WorkflowIdentity};
use continuity::testing::{
    TestNitro, TestSigner, TestSigstore, checks, measurement, statement_bytes,
};
use continuity::trust::TrustRoot;
use continuity::{Error, Predecessor, SignedStatement, SuccessorSide, verify_statement};
use engine::grant::GrantTerms;
use engine::keys::{DeviceKey, NodeKey, UserKey};
use engine::log::{ChainVerifier, MemorySink};
use engine::node::{Node, SystemClock};

type TestNode = Node<MemorySink, SystemClock>;

fn now() -> u64 {
    engine::node::now_ms()
}

struct Setup {
    nitro: TestNitro,
    sigstore: TestSigstore,
    v1: Measurement,
    v2: Measurement,
    old: TestNode,
    new: TestNode,
}

fn setup() -> Setup {
    Setup {
        nitro: TestNitro::new(),
        sigstore: TestSigstore::new(),
        v1: measurement("v1.0.0", 1),
        v2: measurement("v1.1.0", 20),
        old: Node::new(NodeKey::generate(), MemorySink::new(), SystemClock),
        new: Node::new(NodeKey::generate(), MemorySink::new(), SystemClock),
    }
}

fn identity() -> WorkflowIdentity {
    WorkflowIdentity::release_workflow()
}

fn grant(node: &TestNode, owner: &str, allow_successor: bool) {
    std::thread::sleep(Duration::from_millis(2));
    let device = DeviceKey::generate();
    let mut terms = GrantTerms::new(owner, Duration::from_secs(3600));
    if !allow_successor {
        terms = terms.without_successor();
    }
    node.grant(
        &device
            .grant(&UserKey::generate(), &node.identity(), terms)
            .unwrap(),
    )
    .unwrap();
}

/// Runs the four messages; `successor_runs` is the image the successor's enclave really
/// runs, `predecessor_runs` the predecessor's.
fn run(
    s: &Setup,
    signed: &SignedStatement,
    predecessor_runs: &Measurement,
    successor_runs: &Measurement,
) -> Result<engine::node::TakenOver, Error> {
    let old = Predecessor::new(checks(&s.nitro, &s.sigstore, "v1.0.0"));
    let new = SuccessorSide::new(checks(&s.nitro, &s.sigstore, "v1.1.0"));
    let challenge = old.challenge(&s.old, now())?;
    let offer = new.offer(
        &s.new,
        &s.nitro.enclave(successor_runs),
        &challenge,
        signed,
        now(),
    )?;
    let package = old.hand_over(
        &s.old,
        &s.nitro.enclave(predecessor_runs),
        &offer,
        signed,
        now(),
    )?;
    new.take_over(&s.new, &package, signed, now())
}

#[test]
fn a_node_hands_over_to_a_signed_successor_and_one_chain_runs_across() {
    let s = setup();
    grant(&s.old, "alice", true);
    grant(&s.old, "bob", false);
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let taken = run(&s, &signed, &s.v1, &s.v2).unwrap();
    // Bob's grant stayed behind: he did not allow a successor.
    assert_eq!((taken.owners, taken.grants), (2, 1));
    assert!(s.old.is_handed_over());
    let mut verifier = ChainVerifier::new(s.old.public_key());
    for entry in s
        .old
        .with_sink(|k| k.entries().to_vec())
        .iter()
        .chain(s.new.with_sink(|k| k.entries().to_vec()).iter())
    {
        verifier.push(entry).unwrap();
    }
    assert_eq!(verifier.hand_overs(), 1);
    assert_eq!(verifier.node(), s.new.public_key());
}

#[test]
fn a_downgrade_is_refused_even_when_signed() {
    let s = setup();
    // A statement from v1.1.0 back to v1.0.0, signed at the tag of v1.0.0.
    let back = s.sigstore.statement(&identity(), &s.v2, &s.v1);
    assert!(matches!(
        verify_statement(&back, &s.sigstore.trust_root(), &identity()),
        Err(Error::Downgrade { .. })
    ));
    // The same release on both sides.
    let same = s.sigstore.statement(&identity(), &s.v1, &s.v1);
    assert!(matches!(
        verify_statement(&same, &s.sigstore.trust_root(), &identity()),
        Err(Error::Downgrade { .. })
    ));
    // A successor that runs an older image than the statement names: its measurements are
    // not listed.
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let older = measurement("v0.9.0", 9);
    assert!(matches!(
        run(&s, &signed, &s.v1, &older),
        Err(Error::Attestation(attest::Error::UnknownMeasurement))
    ));
    assert!(!s.old.is_handed_over(), "nothing was handed over");
}

#[test]
fn a_successor_with_unlisted_measurements_gets_nothing() {
    let s = setup();
    grant(&s.old, "alice", true);
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    // The operator's own build, claiming to be v1.1.0.
    let mut own = s.v2.clone();
    own.pcr2[0] ^= 1;
    assert!(matches!(
        run(&s, &signed, &s.v1, &own),
        Err(Error::Attestation(attest::Error::UnknownMeasurement))
    ));
    assert!(!s.old.is_handed_over());
    // A debug enclave (all PCRs zero).
    let mut debug = s.v2.clone();
    debug.pcr0 = [0; 48];
    debug.pcr1 = [0; 48];
    debug.pcr2 = [0; 48];
    assert!(run(&s, &signed, &s.v1, &debug).is_err());
    assert!(!s.old.is_handed_over());
    // A predecessor that is not the release the statement names: the successor refuses the
    // package, and takes nothing.
    let s = setup();
    grant(&s.old, "alice", true);
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let mut fake = s.v1.clone();
    fake.pcr0[0] ^= 1;
    assert!(matches!(
        run(&s, &signed, &fake, &s.v2),
        Err(Error::Attestation(attest::Error::UnknownMeasurement))
    ));
    assert!(s.new.with_sink(|k| k.entries().is_empty()));
}

fn refused(s: &Setup, signed: &SignedStatement) -> Error {
    match verify_statement(signed, &s.sigstore.trust_root(), &identity()) {
        Err(e) => e,
        Ok(_) => panic!("a forged statement verified"),
    }
}

#[test]
fn forged_statements_are_refused() {
    let s = setup();
    let good = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    verify_statement(&good, &s.sigstore.trust_root(), &identity()).unwrap();

    // Signed under another authority (one the node does not pin).
    let elsewhere = TestSigstore::new().statement(&identity(), &s.v1, &s.v2);
    assert!(matches!(refused(&s, &elsewhere), Error::ChainUntrusted(_)));

    // The statement changed after signing: other measurements for v1.1.0.
    let mut changed = good.clone();
    let mut other = s.v2.clone();
    other.pcr1[0] ^= 1;
    changed.statement = statement_bytes(&s.v1, &other);
    assert!(matches!(refused(&s, &changed), Error::SignatureInvalid(_)));

    // Signed by someone else than the release workflow at the tag of v1.1.0.
    let bytes = statement_bytes(&s.v1, &s.v2);
    let mut signers = Vec::new();
    let base = TestSigner::release(&identity(), "v1.1.0");
    signers.push(TestSigner {
        subject: "https://github.com/BloubHQ/credentials/.github/workflows/ci.yml@refs/tags/v1.1.0"
            .into(),
        ..base.clone()
    });
    signers.push(TestSigner {
        subject: identity().subject("v1.0.0"),
        ..base.clone()
    });
    signers.push(TestSigner {
        repository: "https://github.com/someone/credentials".into(),
        ..base.clone()
    });
    signers.push(TestSigner {
        runner: "self-hosted".into(),
        ..base.clone()
    });
    signers.push(TestSigner {
        issuer: "https://accounts.google.com".into(),
        ..base.clone()
    });
    signers.push(TestSigner {
        git_ref: "refs/heads/main".into(),
        ..base.clone()
    });
    for signer in signers {
        let forged = SignedStatement {
            statement: bytes.clone(),
            bundle: s.sigstore.sign(&bytes, &signer),
        };
        assert!(
            matches!(refused(&s, &forged), Error::IdentityMismatch(_)),
            "{signer:?}"
        );
    }

    // The log's promises: a signed entry timestamp, an inclusion proof and a checkpoint that
    // do not verify.
    let mut set = good.clone();
    let entry = &mut set.bundle.verification_material.tlog_entries[0];
    entry.integrated_time += 1;
    assert!(matches!(refused(&s, &set), Error::LogProofInvalid(_)));
    let mut proof = good.clone();
    let path = &mut proof.bundle.verification_material.tlog_entries[0]
        .inclusion_proof
        .hashes;
    path.swap(0, 1);
    assert!(matches!(refused(&s, &proof), Error::LogProofInvalid(_)));
    let mut note = good.clone();
    let envelope = &mut note.bundle.verification_material.tlog_entries[0]
        .inclusion_proof
        .checkpoint
        .envelope;
    *envelope = envelope.replacen("\n7\n", "\n8\n", 1);
    assert!(matches!(refused(&s, &note), Error::LogProofInvalid(_)));
    // A checkpoint signed by another log.
    let other_log = TestSigstore::new().statement(&identity(), &s.v1, &s.v2);
    let mut swapped = good.clone();
    swapped.bundle.verification_material.tlog_entries[0]
        .inclusion_proof
        .checkpoint = other_log.bundle.verification_material.tlog_entries[0]
        .inclusion_proof
        .checkpoint
        .clone();
    assert!(matches!(refused(&s, &swapped), Error::LogProofInvalid(_)));

    // The log entry of another signature.
    let mut entry = good.clone();
    let another = s
        .sigstore
        .statement(&identity(), &s.v1, &measurement("v1.2.0", 30));
    entry.bundle.verification_material.tlog_entries =
        another.bundle.verification_material.tlog_entries.clone();
    assert!(matches!(
        refused(&s, &entry),
        Error::LogEntryMismatch(_) | Error::ChainUntrusted(_)
    ));

    // No pinned root at all: nothing verifies.
    assert!(matches!(
        verify_statement(&good, &TrustRoot::default(), &identity()),
        Err(Error::TrustRootEmpty)
    ));
    // The trusted_root.json form of the same root verifies the same.
    let json = TrustRoot::from_json(s.sigstore.trusted_root_json().as_bytes()).unwrap();
    verify_statement(&good, &json, &identity()).unwrap();
    // The bundle survives its JSON form.
    let again =
        SignedStatement::from_files(&good.statement, &serde_json::to_vec(&good.bundle).unwrap())
            .unwrap();
    verify_statement(&again, &json, &identity()).unwrap();
    assert!(sigstore::Bundle::from_json(b"{}").is_err());
}

#[test]
fn replayed_statements_and_messages_are_refused() {
    let s = setup();
    grant(&s.old, "alice", true);
    // A real statement of an earlier hand-over (v0.9.0 to v1.0.0), replayed to the v1.0.0
    // node: it does not let v1.0.0 hand over.
    let earlier = s
        .sigstore
        .statement(&identity(), &measurement("v0.9.0", 9), &s.v1);
    verify_statement(&earlier, &s.sigstore.trust_root(), &identity()).unwrap();
    let old = Predecessor::new(checks(&s.nitro, &s.sigstore, "v1.0.0"));
    let new = SuccessorSide::new(checks(&s.nitro, &s.sigstore, "v1.1.0"));
    let challenge = old.challenge(&s.old, now()).unwrap();
    assert!(matches!(
        new.offer(&s.new, &s.nitro.enclave(&s.v2), &challenge, &earlier, now()),
        Err(Error::StatementNotForThisRelease)
    ));
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let offer = new
        .offer(&s.new, &s.nitro.enclave(&s.v2), &challenge, &signed, now())
        .unwrap();
    assert!(matches!(
        old.hand_over(&s.old, &s.nitro.enclave(&s.v1), &offer, &earlier, now()),
        Err(Error::StatementNotForThisRelease)
    ));
    // The challenge was spent by that attempt: the same offer again is refused.
    assert!(matches!(
        old.hand_over(&s.old, &s.nitro.enclave(&s.v1), &offer, &signed, now()),
        Err(Error::Protocol(_))
    ));
    // An offer whose document answers an earlier challenge.
    let first = old.challenge(&s.old, now()).unwrap();
    let stale = new
        .offer(&s.new, &s.nitro.enclave(&s.v2), &first, &signed, now())
        .unwrap();
    let _second = old.challenge(&s.old, now()).unwrap();
    assert!(matches!(
        old.hand_over(&s.old, &s.nitro.enclave(&s.v1), &stale, &signed, now()),
        Err(Error::Attestation(attest::Error::NonceMismatch))
    ));
    // A challenge answered too late.
    let late = old.challenge(&s.old, now() - 6 * 60 * 1000).unwrap();
    let offer = new
        .offer(&s.new, &s.nitro.enclave(&s.v2), &late, &signed, now())
        .unwrap();
    assert!(matches!(
        old.hand_over(&s.old, &s.nitro.enclave(&s.v1), &offer, &signed, now()),
        Err(Error::Protocol(_))
    ));
    assert!(!s.old.is_handed_over());

    // A package delivered to a second successor, or twice: refused.
    let challenge = old.challenge(&s.old, now()).unwrap();
    let offer = new
        .offer(&s.new, &s.nitro.enclave(&s.v2), &challenge, &signed, now())
        .unwrap();
    let package = old
        .hand_over(&s.old, &s.nitro.enclave(&s.v1), &offer, &signed, now())
        .unwrap();
    new.take_over(&s.new, &package, &signed, now()).unwrap();
    assert!(matches!(
        new.take_over(&s.new, &package, &signed, now()),
        Err(Error::Protocol(_))
    ));
    let third: TestNode = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let other = SuccessorSide::new(checks(&s.nitro, &s.sigstore, "v1.1.0"));
    let _ = other
        .offer(&third, &s.nitro.enclave(&s.v2), &challenge, &signed, now())
        .unwrap();
    assert!(matches!(
        other.take_over(&third, &package, &signed, now()),
        Err(Error::Attestation(attest::Error::NonceMismatch))
    ));
    // The old node, handed over, hands over again to no other node.
    let challenge = old.challenge(&s.old, now()).unwrap();
    let offer = other
        .offer(&third, &s.nitro.enclave(&s.v2), &challenge, &signed, now())
        .unwrap();
    assert!(matches!(
        old.hand_over(&s.old, &s.nitro.enclave(&s.v1), &offer, &signed, now()),
        Err(Error::Engine(engine::Error::HandedOver))
    ));
}

#[test]
fn the_host_carries_the_messages_over_sockets_and_learns_nothing_it_can_use() {
    use continuity::wire::{Service, drive};
    use std::net::{TcpListener, TcpStream};

    let s = setup();
    grant(&s.old, "alice", true);
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let old = Service::new(
        &s.old,
        s.nitro.enclave(&s.v1),
        checks(&s.nitro, &s.sigstore, "v1.0.0"),
    );
    let new = Service::new(
        &s.new,
        s.nitro.enclave(&s.v2),
        checks(&s.nitro, &s.sigstore, "v1.1.0"),
    );
    let old_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let new_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (old_addr, new_addr) = (
        old_listener.local_addr().unwrap(),
        new_listener.local_addr().unwrap(),
    );
    let taken = std::thread::scope(|scope| {
        scope.spawn(|| old.serve(&mut old_listener.accept().unwrap().0).unwrap());
        scope.spawn(|| new.serve(&mut new_listener.accept().unwrap().0).unwrap());
        let mut a = TcpStream::connect(old_addr).unwrap();
        let mut b = TcpStream::connect(new_addr).unwrap();
        drive(&mut a, &mut b, &signed)
    })
    .unwrap();
    assert_eq!((taken.owners, taken.grants), (1, 1));
    assert!(s.old.is_handed_over());

    // A host that swaps the roles gets refusals, not state.
    let s = setup();
    let signed = s.sigstore.statement(&identity(), &s.v1, &s.v2);
    let old = Service::new(
        &s.old,
        s.nitro.enclave(&s.v1),
        checks(&s.nitro, &s.sigstore, "v1.0.0"),
    );
    let new = Service::new(
        &s.new,
        s.nitro.enclave(&s.v2),
        checks(&s.nitro, &s.sigstore, "v1.1.0"),
    );
    let challenge = match new.answer(continuity::wire::Request::Challenge {}, now()) {
        continuity::wire::Response::Challenge(c) => c,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        old.answer(
            continuity::wire::Request::Offer {
                challenge,
                statement: signed
            },
            now()
        ),
        continuity::wire::Response::Refused { .. }
    ));
}

#[test]
fn frames_longer_than_allowed_are_refused_before_reading() {
    use continuity::wire::{MAX_FRAME, Request, read_frame};
    let mut bytes = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(b"{}");
    assert!(read_frame::<_, Request>(&mut bytes.as_slice()).is_err());
    let mut short = 10u32.to_be_bytes().to_vec();
    short.extend_from_slice(b"{}");
    assert!(read_frame::<_, Request>(&mut short.as_slice()).is_err());
    assert!(
        read_frame::<_, Request>(&mut [].as_slice())
            .unwrap()
            .is_none()
    );
}
