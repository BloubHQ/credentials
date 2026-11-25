//! The verify binary on a log a node wrote.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use engine::caller::Payload;
use engine::encoding::to_b64;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Clock, Node, SystemClock};
use engine::policy::{Caller, FieldSpec, Operation, Policy};
use engine::record::Record;

struct Written {
    dir: PathBuf,
    log: PathBuf,
    node_key: String,
}

/// A node that granted, derived twice, and wrote its log and a checkpoint to files.
fn write_log(name: &str) -> Written {
    let device = DeviceKey::generate();
    let app = CallerKey::generate();
    let user_key = [3u8; 32];
    let policy = Policy {
        fields: vec![FieldSpec::secret("key")],
        callers: vec![Caller {
            name: "app".into(),
            key: app.public(),
            operations: vec!["hash".into()],
            limit: None,
        }],
        operations: vec![Operation::Derive {
            name: "hash".into(),
            template: "{{ hex(hmac_sha256(key, $input)) }}".into(),
        }],
    };
    let mut values = Fields::new();
    values.insert("key", b"0123456789abcdef".to_vec()).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec",
        "alice",
        device.sign_policy(policy).unwrap(),
        &values,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let now = SystemClock.now_ms();
    let grant = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            GrantTerms {
                owner: "alice".into(),
                expires_ms: now + 60_000,
                issued_ms: now,
                pins: vec![RecordPin {
                    record_id: "rec".into(),
                    generation: 1,
                }],
            },
        )
        .unwrap();
    node.grant(&grant).unwrap();
    for input in [b"a".as_slice(), b"b"] {
        let auth = app
            .authorize(
                "app",
                &node.public_key(),
                &record,
                "hash",
                &Payload::Derive(input),
                SystemClock.now_ms(),
            )
            .unwrap();
        node.derive(&record, "hash", &auth, input).unwrap();
    }
    let dir = std::env::temp_dir().join(format!("verify-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lines: Vec<String> = node
        .with_sink(|s| s.entries().to_vec())
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    let log = dir.join("log.jsonl");
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();
    std::fs::write(
        dir.join("head.json"),
        serde_json::to_string(&node.checkpoint().unwrap()).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("user.key"), to_b64(&user_key)).unwrap();
    Written {
        dir,
        log,
        node_key: node.public_key().to_b64(),
    }
}

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_verify"))
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn checks_a_chain_a_checkpoint_and_an_owner() {
    let w = write_log("ok");
    let log = w.log.to_str().unwrap();
    let out = verify(&[log, &w.node_key]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).starts_with("ok: 3 entries, head "));

    let head = w.dir.join("head.json");
    let out = verify(&[log, &w.node_key, "--head", head.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let key = w.dir.join("user.key");
    let out = verify(&[
        log,
        &w.node_key,
        "--owner",
        "alice",
        "--user-key",
        key.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let details: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["detail"].clone())
        .collect();
    assert_eq!(details.len(), 3, "{stdout}");
    assert!(details[0].is_null());
    assert_eq!(details[1]["t"], "derive");
    assert_eq!(details[1]["input_len"], 1);
    assert!(stdout.contains("ok: 3 entries of alice, head "), "{stdout}");
}

#[test]
fn finds_a_cut_tail_and_names_the_bad_line() {
    let w = write_log("bad");
    let log = w.log.to_str().unwrap();
    let head = w.dir.join("head.json");

    // The last entry removed: the chain still verifies, the checkpoint does not.
    let text_log = std::fs::read_to_string(&w.log).unwrap();
    let cut: Vec<&str> = text_log.lines().collect();
    std::fs::write(&w.log, cut[..cut.len() - 1].join("\n")).unwrap();
    assert!(verify(&[log, &w.node_key]).status.success());
    let out = verify(&[log, &w.node_key, "--head", head.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("signed head"),
        "{}",
        text(&out.stderr)
    );

    // A blank line, then a broken one: the error names line 3.
    std::fs::write(&w.log, format!("{}\n\nnot json\n", cut[0])).unwrap();
    let out = verify(&[log, &w.node_key]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("line 3"),
        "{}",
        text(&out.stderr)
    );

    let out = verify(&["--help"]);
    assert!(out.status.success());
    assert_eq!(verify(&["only-one"]).status.code(), Some(2));
}
