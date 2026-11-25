//! Restarts a node from its log, and shows what a restart does not bring back.
//!
//! ```sh
//! cargo run -p transport --example node_restore
//! ```
//!
//! No network and no secrets from the environment: the node derives an HMAC. The steps:
//!
//! 1. a node takes a grant and runs a call; it signs a checkpoint, which the platform keeps
//!    where the operator cannot roll it back (a TEE monotonic counter or sealed storage);
//! 2. the node restarts with its key and the entries of its sink ([`Node::restore_anchored`]);
//! 3. the grant saved from before the restart is refused, and so is a call signed before it:
//!    the owner grants again;
//! 4. a log with its tail cut is refused against the checkpoint;
//! 5. the owner checks its own entries ([`owner_entries`], [`verify_owner_chain`]).

use std::time::Duration;

use engine::Error;
use engine::call::{Body, Output, SignedCall};
use engine::fields::Fields;
use engine::grant::GrantTerms;
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{LogSink, MemorySink, SignedEntry, owner_entries, verify_owner_chain};
use engine::node::{Node, SystemClock};
use engine::policy::{Caller, FieldSpec, Input, Operation, Policy, RawInput};
use engine::record::Record;
use transport::TlsTransport;

/// A sink that holds `entries`, as the durable store of a node does after a restart.
fn sink_of(entries: &[SignedEntry]) -> Result<MemorySink, Error> {
    let mut sink = MemorySink::new();
    for entry in entries {
        sink.append(entry)?;
    }
    Ok(sink)
}

type TestNode = Node<MemorySink, SystemClock>;

/// The application signs a call of `mac` on `hello`.
fn sign(app: &CallerKey, node: &TestNode, record: &Record) -> Result<SignedCall, Error> {
    let body = Body::derive(b"hello");
    app.sign_call("app", &node.public_key(), record.clone(), "mac", body)
}

/// The node runs it.
fn mac(node: &TestNode, call: &SignedCall) -> Result<String, Box<dyn std::error::Error>> {
    match node.run(call, &mut TlsTransport::new()).result? {
        Output::Derive(output) => Ok(String::from_utf8(output)?),
        _ => Err("a derive operation hands back its output".into()),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // On the owner's device.
    let device = DeviceKey::generate();
    let user_key = UserKey::generate();
    let app = CallerKey::generate();
    let policy = Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(
            Operation::derive("mac", "{{ hex(hmac_sha256(key, $input)) }}").input(Input::Raw(
                RawInput {
                    max_len: Some(64),
                    pattern: Some("[a-z]+".into()),
                },
            )),
        )
        .with_caller(Caller::new("app", app.public(), ["mac"]));
    let mut values = Fields::new();
    values.insert("key", b"an example key of 32 bytes......".to_vec())?;
    let record = Record::seal(&user_key, "mac", "me", device.sign_policy(policy)?, &values)?;

    // 1. The node, a grant, a call, a checkpoint.
    let node_key = NodeKey::generate();
    let node = Node::new(
        NodeKey::from_bytes(&mut node_key.to_bytes()),
        MemorySink::new(),
        SystemClock,
    );
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    let saved_grant = device.grant(&user_key, &node.identity(), terms)?;
    node.grant(&saved_grant)?;
    let saved_call = sign(&app, &node, &record)?;
    let first = mac(&node, &sign(&app, &node, &record)?)?;
    println!("before the restart: mac {}", first);
    let anchor = node.checkpoint()?;
    let entries = node.with_sink(|sink| sink.entries().to_vec());
    println!(
        "checkpoint: {} entries, kept where the operator cannot roll it back",
        anchor.len
    );
    drop(node);

    // 2. The restart: the same key, the entries of the sink, the checkpoint.
    let restart = |entries: &[SignedEntry]| -> Result<_, Box<dyn std::error::Error>> {
        let key = NodeKey::from_bytes(&mut node_key.to_bytes());
        let node = Node::restore_anchored(key, sink_of(entries)?, SystemClock, entries, &anchor)?;
        Ok(node)
    };
    let node = restart(&entries)?;
    println!("restarted with {} entries", entries.len());

    // 3. Nothing signed before the restart opens the restarted node.
    match node.grant(&saved_grant) {
        Err(error) => println!("the saved grant is refused: {error}"),
        Ok(()) => return Err("a saved grant opened a restarted node".into()),
    }
    // A grant issued after the restart (a millisecond later at least) is taken.
    std::thread::sleep(Duration::from_millis(2));
    let terms = GrantTerms::new("me", Duration::from_secs(600)).pin(&record);
    node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;
    match node.run(&saved_call, &mut TlsTransport::new()).result {
        Err(error) => println!("a call signed before the restart is refused: {error}"),
        Ok(_) => return Err("a call signed before the restart ran".into()),
    }
    let again = mac(&node, &sign(&app, &node, &record)?)?;
    println!("after a new grant: mac {}", again);

    // 4. The operator cuts the tail of the log: the checkpoint finds it.
    let cut = entries
        .get(..entries.len().saturating_sub(1))
        .unwrap_or(&[]);
    match restart(cut) {
        Err(error) => println!("a log cut to {} entries is refused: {error}", cut.len()),
        Ok(_) => return Err("a cut log was taken".into()),
    }

    // 5. The owner checks its own chain, from the entries the operator hands it.
    let all = node.with_sink(|sink| sink.entries().to_vec());
    let mine = owner_entries(&all, "me");
    verify_owner_chain(&mine, "me", &node.public_key())?;
    println!(
        "the owner's chain verifies: {} entries (credentials verify --owner me)",
        mine.len()
    );
    Ok(())
}
