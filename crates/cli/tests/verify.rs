//! `credentials verify` on a log a node wrote.
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
use engine::log::{Event, Log, MemorySink, SignedEntry, owner_entries};
use engine::node::{Clock, Node, SystemClock};
use engine::policy::{Caller, FieldSpec, Input, Operation, Policy};
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
        item: None,
        fields: vec![FieldSpec::secret("key")],
        callers: vec![Caller {
            name: "app".into(),
            key: app.public(),
            operations: vec!["hash".into()],
            limit: None,
        }],
        operations: vec![
            Operation::derive("hash", "{{ hex(hmac_sha256(key, $input)) }}").input(Input::any()),
        ],
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
                allow_successor: true,
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
    Command::new(env!("CARGO_BIN_EXE_credentials"))
        .arg("verify")
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
    assert!(text(&out.stdout).starts_with("credentials verify:"));
    assert_eq!(verify(&["only-one"]).status.code(), Some(2));
}

fn json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn options_come_in_any_order() {
    let w = write_log("order");
    let log = w.log.to_str().unwrap();
    let head = w.dir.join("head.json");
    let head = head.to_str().unwrap();
    let key = w.dir.join("user.key");
    let key = key.to_str().unwrap();
    for args in [
        vec!["--head", head, log, &w.node_key],
        vec![log, "--head", head, &w.node_key],
        vec![&format!("--head={head}"), log, &w.node_key],
    ] {
        let out = verify(&args);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        assert!(stdout.contains("signed head of 3 entries"), "{stdout}");
        assert!(stdout.trim_end().ends_with("Z)"), "{stdout}");
    }
    let out = verify(&["--user-key", key, "--owner", "alice", log, &w.node_key]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ok: 3 entries of alice"));

    // --head and --owner together.
    let out = verify(&["--owner", "alice", log, "--head", head, &w.node_key]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("of alice"));
}

#[test]
fn json_prints_one_summary() {
    let w = write_log("json");
    let log = w.log.to_str().unwrap();
    let head = w.dir.join("head.json");
    let out = verify(&["--json", log, &w.node_key, "--head", head.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let lines = json_lines(&text(&out.stdout));
    assert_eq!(lines.len(), 1);
    let summary = &lines[0];
    assert_eq!(summary["valid"], true);
    assert_eq!(summary["entries"], 3);
    assert!(summary["head"].is_string());
    assert_eq!(summary["checkpoint"]["len"], 3);
    assert!(
        summary["checkpoint"]["time"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(summary["error"].is_null());

    // With the user key: the entries as JSON lines, then the summary.
    let key = w.dir.join("user.key");
    let out = verify(&[
        log,
        &w.node_key,
        "--json",
        "--owner",
        "alice",
        "--user-key",
        key.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let lines = json_lines(&text(&out.stdout));
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[1]["detail"]["t"], "derive");
    assert_eq!(lines[3]["valid"], true);
    assert_eq!(lines[3]["owner"], "alice");

    // An invalid log: valid is false, the error is named, exit code 1.
    let text_log = std::fs::read_to_string(&w.log).unwrap();
    let cut: Vec<&str> = text_log.lines().collect();
    std::fs::write(
        &w.log,
        cut[1..].join(
            "
",
        ),
    )
    .unwrap();
    let out = verify(&[log, &w.node_key, "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let lines = json_lines(&text(&out.stdout));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["valid"], false);
    assert_eq!(lines[0]["entries"], 0);
    assert!(
        lines[0]["error"].as_str().unwrap().contains("chain broken"),
        "{}",
        lines[0]
    );
}

#[test]
fn help_lists_every_option_and_exit_code() {
    for flag in ["--help", "-h"] {
        let out = verify(&["log.jsonl", flag]);
        assert!(out.status.success());
        let help = text(&out.stdout);
        for word in [
            "--head",
            "--owner",
            "--user-key",
            "--json",
            "Examples:",
            "Exit codes:",
            "0  the log is valid",
        ] {
            assert!(help.contains(word), "{word}");
        }
    }
}

/// A log of two owners, written by a log without a node.
fn two_owners(name: &str) -> (PathBuf, Vec<SignedEntry>, String) {
    let key = NodeKey::generate();
    let node_key = key.public().to_b64();
    let mut log = Log::new(key);
    let mut sink = MemorySink::new();
    let dir = std::env::temp_dir().join(format!("verify-cli-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (time, owner) in [(1, "alice"), (2, "bob"), (3, "alice")] {
        log.commit(
            &mut sink,
            time,
            (owner, "rec", ""),
            Event::Pin { generation: 1 },
        )
        .unwrap();
        if time == 2 {
            let early = log.checkpoint(time).unwrap();
            std::fs::write(
                dir.join("early.json"),
                serde_json::to_string(&early).unwrap(),
            )
            .unwrap();
        }
    }
    std::fs::write(
        dir.join("head.json"),
        serde_json::to_string(&log.checkpoint(10).unwrap()).unwrap(),
    )
    .unwrap();
    (dir, sink.entries().to_vec(), node_key)
}

fn write_entries(path: &std::path::Path, entries: &[SignedEntry]) {
    let lines: Vec<String> = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    std::fs::write(
        path,
        lines.join(
            "
",
        ),
    )
    .unwrap();
}

#[test]
fn an_entry_of_another_owner_is_named() {
    let (dir, all, node_key) = two_owners("owners");
    let log = dir.join("all.jsonl");
    write_entries(&log, &all);
    let log = log.to_str().unwrap();
    assert!(verify(&[log, &node_key]).status.success());

    let out = verify(&[log, &node_key, "--owner", "alice"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains(r#"entry 1 (line 2) belongs to owner "bob", not "alice""#),
        "{stderr}"
    );

    // The entries a node operator hands alice verify, with the checkpoint after them.
    let mine = dir.join("alice.jsonl");
    write_entries(&mine, &owner_entries(&all, "alice"));
    let head = dir.join("head.json");
    let out = verify(&[
        mine.to_str().unwrap(),
        &node_key,
        "--owner",
        "alice",
        "--head",
        head.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("ok: 2 entries of alice"));
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );

    // alice's last entry cut from the file: the checkpoint goes past what is left, so the
    // cut cannot be seen; the verifier says so.
    let cut = dir.join("alice-cut.jsonl");
    write_entries(&cut, &owner_entries(&all, "alice")[..1]);
    let out = verify(&[
        cut.to_str().unwrap(),
        &node_key,
        "--owner",
        "alice",
        "--head",
        head.to_str().unwrap(),
        "--json",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("would not be noticed"),
        "{}",
        text(&out.stderr)
    );
    let summary: serde_json::Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    assert_eq!(summary["owner_tail_unchecked"], true);

    // A checkpoint from before alice's last entry does not cover the file.
    let early = dir.join("early.json");
    let out = verify(&[
        mine.to_str().unwrap(),
        &node_key,
        "--owner",
        "alice",
        "--head",
        early.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("before entry 2"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn exit_codes_separate_usage_from_an_invalid_log() {
    let w = write_log("codes");
    let log = w.log.to_str().unwrap();
    // Usage errors and unreadable inputs: 2.
    for args in [
        vec![],
        vec![log],
        vec![log, &w.node_key, "extra"],
        vec![log, &w.node_key, "--wat"],
        vec![log, &w.node_key, "--owner"],
        vec![log, &w.node_key, "--user-key", "k"],
        vec![log, "not-a-key"],
        vec!["missing.jsonl", &w.node_key],
        vec![log, &w.node_key, "--head", "missing.json"],
        vec![
            log,
            &w.node_key,
            "--owner",
            "alice",
            "--user-key",
            "missing.key",
        ],
    ] {
        assert_eq!(verify(&args).status.code(), Some(2), "{args:?}");
    }
    // A key of another node: the log is invalid, 1.
    let other = NodeKey::generate().public().to_b64();
    let out = verify(&[log, &other]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("is this the node's log public key?"),
        "{}",
        text(&out.stderr)
    );
    let out = verify(&[log, &other, "--owner", "alice"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("is this the node's log public key?"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(verify(&[log, &w.node_key]).status.code(), Some(0));
}
