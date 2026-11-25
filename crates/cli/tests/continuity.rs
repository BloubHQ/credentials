//! `credentials verify --next`: one chain across a hand-over between two nodes.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use engine::grant::GrantTerms;
use engine::keys::{DeviceKey, NodeKey, UserKey};
use engine::log::{MemorySink, SignedEntry};
use engine::node::{Node, Successor, SystemClock, now_ms};

fn verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_credentials"))
        .arg("verify")
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write_entries(path: &Path, entries: &[SignedEntry]) {
    let lines: Vec<String> = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

fn node() -> Node<MemorySink, SystemClock> {
    Node::new(NodeKey::generate(), MemorySink::new(), SystemClock)
}

/// Two nodes: the first hands over to the second; both logs written to files, and the log of
/// a third node that took over from nobody.
fn handed_over(name: &str) -> (PathBuf, String) {
    let (old, new, stranger) = (node(), node(), node());
    let device = DeviceKey::generate();
    for n in [&old, &stranger] {
        let grant = device
            .grant(
                &UserKey::generate(),
                &n.identity(),
                GrantTerms::new("alice", Duration::from_secs(600)),
            )
            .unwrap();
        n.grant(&grant).unwrap();
    }
    let hand_over = old
        .hand_over(&Successor {
            identity: new.identity(),
            release: "v1.1.0".into(),
            statement_sha256: [7; 32],
        })
        .unwrap();
    new.take_over(&old.public_key(), &hand_over).unwrap();
    // The new node goes on with the same chain.
    std::thread::sleep(Duration::from_millis(2));
    new.revoke(&device.revoke("alice", &new.public_key(), now_ms()).unwrap())
        .unwrap();
    let dir = std::env::temp_dir().join(format!("verify-next-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_entries(
        &dir.join("old.jsonl"),
        &old.with_sink(|k| k.entries().to_vec()),
    );
    write_entries(
        &dir.join("new.jsonl"),
        &new.with_sink(|k| k.entries().to_vec()),
    );
    write_entries(
        &dir.join("stranger.jsonl"),
        &stranger.with_sink(|k| k.entries().to_vec()),
    );
    std::fs::write(
        dir.join("new-head.json"),
        serde_json::to_string(&new.checkpoint().unwrap()).unwrap(),
    )
    .unwrap();
    (dir, old.public_key().to_b64())
}

#[test]
fn one_chain_runs_across_a_hand_over() {
    let (dir, old_key) = handed_over("chain");
    let path = |file: &str| dir.join(file).to_string_lossy().into_owned();
    let out = verify(&[
        &path("old.jsonl"),
        &old_key,
        "--next",
        &path("new.jsonl"),
        "--head",
        &path("new-head.json"),
        "--json",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let summary: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(summary["valid"], true);
    assert_eq!(summary["hand_overs"][0]["release"], "v1.1.0");
    assert_eq!(
        summary["hand_overs"][0]["statement_sha256"],
        "07".repeat(32)
    );
    let plain = verify(&[&path("old.jsonl"), &old_key, "--next", &path("new.jsonl")]);
    assert!(text(&plain.stdout).contains("handed over at entry"));

    // The old log alone is valid: it ends with the hand-over.
    assert!(verify(&[&path("old.jsonl"), &old_key]).status.success());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn logs_that_do_not_continue_the_chain_are_refused() {
    let (dir, old_key) = handed_over("fork");
    let path = |file: &str| dir.join(file).to_string_lossy().into_owned();
    let code = |args: &[&str]| verify(args).status.code();
    // A log that does not continue the old one.
    assert_eq!(
        code(&[
            &path("old.jsonl"),
            &old_key,
            "--next",
            &path("stranger.jsonl")
        ]),
        Some(1)
    );
    // The new log alone, under the old key.
    assert_eq!(code(&[&path("new.jsonl"), &old_key]), Some(1));
    // A log that did not hand over, followed by another.
    assert_eq!(
        code(&[
            &path("stranger.jsonl"),
            &old_key,
            "--next",
            &path("new.jsonl")
        ]),
        Some(1)
    );
    // The new log twice: it did not hand over.
    assert_eq!(
        code(&[
            &path("old.jsonl"),
            &old_key,
            "--next",
            &path("new.jsonl"),
            "--next",
            &path("new.jsonl"),
        ]),
        Some(1)
    );
    // The old log's tail cut off (its hand-over entry): the next log does not follow.
    let old = std::fs::read_to_string(dir.join("old.jsonl")).unwrap();
    let mut lines: Vec<&str> = old.lines().collect();
    lines.pop();
    std::fs::write(dir.join("cut.jsonl"), lines.join("\n") + "\n").unwrap();
    assert_eq!(
        code(&[&path("cut.jsonl"), &old_key, "--next", &path("new.jsonl")]),
        Some(1)
    );
    // With --owner, --next is a usage error.
    assert_eq!(
        code(&[
            &path("old.jsonl"),
            &old_key,
            "--owner",
            "alice",
            "--next",
            "x"
        ]),
        Some(2)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
