//! End-to-end tests of the `credentials` binary: owner, node server and caller.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

const BIN: &str = env!("CARGO_BIN_EXE_credentials");

fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cli-{name}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

/// Runs the binary and requires success; returns stdout.
fn ok(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "credentials {args:?} failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A child process killed when dropped, even when the test fails.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port nothing listens on, never the same one twice in this run: tests run on threads of
/// one process, and two servers given the same port would answer for each other.
fn free_port() -> u16 {
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut given = GIVEN.lock().unwrap();
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

fn start(key: &Path, log: &Path, port: u16, anchor: Option<&Path>) -> Server {
    start_with(key, log, port, anchor, &[])
}

fn start_with(key: &Path, log: &Path, port: u16, anchor: Option<&Path>, extra: &[&str]) -> Server {
    let listen = format!("127.0.0.1:{port}");
    let mut args = vec![
        "serve",
        "--key",
        s(key),
        "--log",
        s(log),
        "--listen",
        &listen,
    ];
    if let Some(anchor) = anchor {
        args.extend(["--anchor", s(anchor)]);
    }
    args.extend(extra);
    let child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    let url = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // A server that could not listen exits: whatever answers on the port then is not it.
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "the server exited before it answered"
        );
        if run(&["node", "identity", "--url", &url]).status.success() {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "the server exited before it answered"
            );
            return server;
        }
        assert!(
            Instant::now() < deadline,
            "the server did not answer in 10 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// POSTs a JSON file to the server; returns the status and the JSON reply.
fn post(port: u16, path: &str, body: &[u8]) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

fn hmac_hex(key: &[u8], input: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(input);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn owner_node_and_caller_end_to_end() {
    let dir = temp_dir("e2e");
    let path = |name: &str| dir.join(name);

    // Keys.
    let device_pub = ok(&["keygen", "device", "--out", s(&path("device.key"))]);
    let caller_pub = ok(&["keygen", "caller", "--out", s(&path("caller.key"))]);
    let node_pub = ok(&["keygen", "node", "--out", s(&path("node.key"))]);
    ok(&["keygen", "user", "--out", s(&path("user.key"))]);
    assert_eq!(device_pub.trim().len(), 43);
    assert_eq!(
        ok(&["pubkey", "caller", "--key", s(&path("caller.key"))]),
        caller_pub
    );
    // A key file is never overwritten.
    assert!(
        !run(&["keygen", "user", "--out", s(&path("user.key"))])
            .status
            .success()
    );

    // Policy: one operation with no connection for one caller, written in the format before
    // the step language and converted.
    let old = serde_json::json!({
        "fields": [{"name": "key", "secret": true}],
        "callers": [{"name": "app", "key": caller_pub.trim(), "operations": ["sign"]}],
        "operations": [{"kind": "derive", "name": "sign",
                        "template": "{{ hex(hmac_sha256(key, $input)) }}"}],
    });
    std::fs::write(path("old.json"), old.to_string()).unwrap();
    assert!(
        !run(&["policy", "check", s(&path("old.json"))])
            .status
            .success()
    );
    let upgrade = run(&[
        "policy",
        "upgrade",
        s(&path("old.json")),
        "--out",
        s(&path("policy.json")),
    ]);
    assert!(upgrade.status.success());
    let notes = String::from_utf8_lossy(&upgrade.stderr);
    assert!(notes.contains("must be signed again"), "{notes}");
    assert!(notes.contains("declare an input schema"), "{notes}");
    let summary = ok(&["policy", "check", s(&path("policy.json"))]);
    assert!(
        summary.contains("operation sign: no connection"),
        "{summary}"
    );
    assert!(
        summary.contains("! the caller's input is any bytes"),
        "{summary}"
    );
    ok(&[
        "policy",
        "sign",
        s(&path("policy.json")),
        "--device",
        s(&path("device.key")),
        "--out",
        s(&path("signed.json")),
    ]);

    // A signed policy checks too; with --device its signature is verified.
    let summary = ok(&["policy", "check", s(&path("signed.json"))]);
    assert!(summary.contains("signature not checked"), "{summary}");
    assert!(
        summary.contains("operation sign: no connection"),
        "{summary}"
    );
    let summary = ok(&[
        "policy",
        "check",
        s(&path("signed.json")),
        "--device",
        device_pub.trim(),
    ]);
    assert!(summary.contains(device_pub.trim()), "{summary}");
    let other_device = ok(&["keygen", "device", "--out", s(&path("other.key"))]);
    let out = run(&[
        "policy",
        "check",
        s(&path("signed.json")),
        "--device",
        other_device.trim(),
    ]);
    assert_eq!(out.status.code(), Some(1));

    // Signing a signed policy, or sealing under an unsigned one, says what to do.
    let out = run(&[
        "policy",
        "sign",
        s(&path("signed.json")),
        "--device",
        s(&path("device.key")),
        "--out",
        s(&path("signed-twice.json")),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("already signed"));

    // Seal a value read from a file.
    let secret = b"0123456789abcdef0123456789abcdef";
    std::fs::write(path("hmac.key"), secret).unwrap();
    let field = format!("key=@{}", s(&path("hmac.key")));
    let seal_with = |policy: &str, field: &str| {
        run(&[
            "seal",
            "--user-key",
            s(&path("user.key")),
            "--id",
            "x",
            "--owner",
            "me",
            "--policy",
            policy,
            "--field",
            field,
            "--out",
            s(&path("x.json")),
        ])
    };
    let out = seal_with(s(&path("policy.json")), &field);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("this policy is not signed"), "{stderr}");
    assert!(stderr.contains("credentials policy sign"), "{stderr}");

    // An empty value names the field.
    std::fs::write(path("empty.key"), b"").unwrap();
    let out = seal_with(
        s(&path("signed.json")),
        &format!("key=@{}", s(&path("empty.key"))),
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("field `key` is empty"), "{stderr}");
    // A missing file is an I/O failure; a bad name a usage error.
    let out = seal_with(s(&path("signed.json")), "key=@missing.key");
    assert_eq!(out.status.code(), Some(5));
    let out = seal_with(
        s(&path("signed.json")),
        &format!("bad name=@{}", s(&path("hmac.key"))),
    );
    assert_eq!(out.status.code(), Some(2));
    ok(&[
        "seal",
        "--user-key",
        s(&path("user.key")),
        "--id",
        "signer",
        "--owner",
        "me",
        "--policy",
        s(&path("signed.json")),
        "--field",
        &field,
        "--out",
        s(&path("record.json")),
    ]);
    // A literal value is refused.
    assert!(
        !run(&[
            "seal",
            "--user-key",
            s(&path("user.key")),
            "--id",
            "x",
            "--owner",
            "me",
            "--policy",
            s(&path("signed.json")),
            "--field",
            "key=literal",
            "--out",
            s(&path("x.json")),
        ])
        .status
        .success()
    );

    // The identity, without the server.
    ok(&[
        "node",
        "identity",
        "--key",
        s(&path("node.key")),
        "--out",
        s(&path("identity.json")),
    ]);
    let identity: Value =
        serde_json::from_str(&std::fs::read_to_string(path("identity.json")).unwrap()).unwrap();
    assert_eq!(identity["log_key"], node_pub.trim());

    // Start the node; its identity over HTTP is the same.
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let log = path("log.jsonl");
    let server = start(&path("node.key"), &log, port, None);
    let served: Value = serde_json::from_str(&ok(&["node", "identity", "--url", &url])).unwrap();
    assert_eq!(served, identity);

    let grant = |name: &str| {
        ok(&[
            "grant",
            "--device",
            s(&path("device.key")),
            "--user-key",
            s(&path("user.key")),
            "--node",
            s(&path("identity.json")),
            "--owner",
            "me",
            "--valid",
            "10",
            "--pin",
            s(&path("record.json")),
            "--out",
            s(&path(name)),
            "--send",
            &url,
        ])
    };
    grant("grant1.json");

    let call_args_for = |record: &str, input: &str| -> Vec<String> {
        [
            "call",
            "derive",
            "--caller-key",
            s(&path("caller.key")),
            "--caller",
            "app",
            "--node",
            s(&path("identity.json")),
            "--record",
            s(&path(record)),
            "--operation",
            "sign",
            "--input",
            input,
        ]
        .iter()
        .map(|a| a.to_string())
        .collect()
    };
    let call_args = |input: &str| call_args_for("record.json", input);
    let send_call = |record: &str, input: &str| {
        let mut args = call_args_for(record, input);
        args.extend(["--send".to_string(), url.clone()]);
        Command::new(BIN).args(&args).output().unwrap()
    };

    // A call sent by the tool.
    let mut args = call_args("hello");
    args.extend(["--send".to_string(), url.clone()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply: Value = serde_json::from_str(&ok(&args)).unwrap();
    assert_eq!(reply["ok"]["kind"], "derive");
    assert_eq!(reply["ok"]["utf8"], hmac_hex(secret, b"hello"));
    assert!(reply["record"].is_null());

    // A call written to a file, run once, then replayed.
    let mut args = call_args("again");
    args.extend(["--out".to_string(), s(&path("old-call.json")).to_string()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ok(&args);
    let old_call = std::fs::read(path("old-call.json")).unwrap();
    let (status, reply) = post(port, "/call", &old_call);
    assert_eq!(status, 200, "{reply}");
    assert_eq!(reply["ok"]["utf8"], hmac_hex(secret, b"again"));
    let head_file = PathBuf::from(format!("{}.head.json", s(&log)));
    let head_before = std::fs::read(&head_file).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let (status, reply) = post(port, "/call", &old_call);
    assert_eq!(status, 400, "{reply}");
    assert!(
        reply["error"].as_str().unwrap().contains("caller"),
        "{reply}"
    );
    // A refused act appends nothing, so the checkpoint is not signed and written again.
    assert_eq!(std::fs::read(&head_file).unwrap(), head_before);

    // The streaming endpoint runs only operations that stream: a derivation is refused there
    // with a JSON error, before anything is logged.
    let mut args = call_args("streamed");
    args.extend([
        "--out".to_string(),
        s(&path("stream-call.json")).to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ok(&args);
    let (status, reply) = post(
        port,
        "/stream",
        &std::fs::read(path("stream-call.json")).unwrap(),
    );
    assert_eq!(status, 400, "{reply}");
    assert!(reply.get("ok").is_none(), "{reply}");
    assert_eq!(std::fs::read(&head_file).unwrap(), head_before);

    // Restart, anchored to the checkpoint the server wrote next to its log.
    drop(server);
    let head = PathBuf::from(format!("{}.head.json", s(&log)));
    let anchor = path("anchor.json");
    std::fs::copy(&head, &anchor).unwrap();
    let lines = std::fs::read_to_string(&log).unwrap().lines().count();
    assert_eq!(lines, 3, "grant and two derivations");
    let _server = start(&path("node.key"), &log, port, Some(&anchor));

    // Grants do not survive a restart, and the old grant is refused: the owner grants again.
    let (status, _) = post(port, "/grant", &std::fs::read(path("grant1.json")).unwrap());
    assert_ne!(status, 200);
    grant("grant2.json");

    // The call signed before the restart is refused; a fresh one runs.
    let (status, reply) = post(port, "/call", &old_call);
    assert_ne!(status, 200, "{reply}");
    assert!(reply.get("ok").is_none(), "{reply}");
    let mut args = call_args("after");
    args.extend(["--send".to_string(), url.clone()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let reply: Value = serde_json::from_str(&ok(&args)).unwrap();
    assert_eq!(reply["ok"]["utf8"], hmac_hex(secret, b"after"));

    // The log grew from where it was.
    let after = std::fs::read_to_string(&log).unwrap().lines().count();
    assert!(after > lines);

    // The owner rewraps the record (generation 2) and pins it: the old generation is refused.
    ok(&[
        "seal",
        "--user-key",
        s(&path("user.key")),
        "--policy",
        s(&path("signed.json")),
        "--from",
        s(&path("record.json")),
        "--out",
        s(&path("record2.json")),
    ]);
    ok(&[
        "pin",
        "--device",
        s(&path("device.key")),
        "--record",
        s(&path("record2.json")),
        "--send",
        &url,
    ]);
    let stale = send_call("record.json", "old");
    assert_eq!(stale.status.code(), Some(3), "refused by the node");
    let reply: Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert!(
        reply["error"].as_str().unwrap().contains("older"),
        "{reply}"
    );
    let fresh = send_call("record2.json", "new");
    assert!(fresh.status.success());
    let reply: Value = serde_json::from_slice(&fresh.stdout).unwrap();
    assert_eq!(reply["ok"]["utf8"], hmac_hex(secret, b"new"));

    // A second device, endorsed by the first.
    let second = ok(&["keygen", "device", "--out", s(&path("device2.key"))]);
    ok(&[
        "device",
        "endorse",
        "--device",
        s(&path("device.key")),
        "--owner",
        "me",
        "--node",
        s(&path("identity.json")),
        "--target",
        second.trim(),
        "--send",
        &url,
    ]);

    // The owner revokes: calls stop.
    ok(&[
        "revoke",
        "--device",
        s(&path("device.key")),
        "--owner",
        "me",
        "--node",
        s(&path("identity.json")),
        "--send",
        &url,
    ]);
    let revoked = send_call("record2.json", "late");
    assert_eq!(revoked.status.code(), Some(3), "refused by the node");
    // No node listening: a connection failure.
    let mut args = call_args_for("record2.json", "nobody");
    args.extend([
        "--send".to_string(),
        format!("http://127.0.0.1:{}", free_port()),
    ]);
    let out = Command::new(BIN).args(&args).output().unwrap();
    assert_eq!(out.status.code(), Some(5));
    let reply: Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert!(
        reply["error"].as_str().unwrap().contains("no grant"),
        "{reply}"
    );

    // The checkpoint endpoint matches the file written next to the log.
    let (status, _) = post(port, "/checkpoint", b"");
    assert_eq!(status, 405);
    let head: Value = serde_json::from_str(&std::fs::read_to_string(&head).unwrap()).unwrap();
    assert_eq!(
        head["len"].as_u64().unwrap() as usize,
        std::fs::read_to_string(&log).unwrap().lines().count()
    );

    drop(_server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_check_names_the_rule() {
    let dir = temp_dir("check");
    let policy = dir.join("bad.json");
    std::fs::write(
        &policy,
        r#"{"fields": [{"name": "bad name", "secret": true}],
            "callers": [],
            "operations": [{"name": "d", "steps": [{"do": "return", "template": "x"}]}]}"#,
    )
    .unwrap();
    let out = run(&["policy", "check", s(&policy)]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("fields[0].name"), "{stderr}");
    assert!(stderr.contains("name is not a token"), "{stderr}");

    std::fs::write(&policy, r#"{"fields": [], "junk": 1}"#).unwrap();
    let out = run(&["policy", "check", s(&policy)]);
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_with_a_byte_order_mark_is_read_and_utf16_names_the_fix() {
    let dir = temp_dir("bom");
    let policy = dir.join("policy.json");
    let text = r#"{"fields": [{"name": "k", "secret": true}], "callers": [],
        "operations": [{"name": "d", "steps": [{"do": "return", "template": "x"}]}]}"#;
    // UTF-8 with a byte order mark, as `Set-Content -Encoding utf8` writes it.
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(text.as_bytes());
    std::fs::write(&policy, &bom).unwrap();
    // The document is read: the check gets as far as the rules (it has no caller).
    let out = run(&["policy", "check", s(&policy)]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("policy invalid at callers"), "{stderr}");
    // UTF-16LE with its mark, as `>` writes it in Windows PowerShell 5.1.
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&policy, &utf16).unwrap();
    let out = run(&["policy", "check", s(&policy)]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("UTF-16") && stderr.contains("--out"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_errors_name_the_place_in_the_document() {
    let dir = temp_dir("where");
    let policy = dir.join("bad.json");
    let check = |text: &str| {
        std::fs::write(&policy, text).unwrap();
        let out = run(&["policy", "check", s(&policy)]);
        assert_eq!(out.status.code(), Some(1));
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    // A caller key of 4 bytes: the message names the key.
    let stderr = check(
        r#"{"fields": [], "callers": [{"name": "app", "key": "AAAAAA", "operations": ["d"]}],
            "operations": [{"name": "d", "steps": [{"do": "return", "template": "x"}]}]}"#,
    );
    assert!(stderr.contains("callers[0].key"), "{stderr}");
    // A template that does not parse: the message says where in it.
    let stderr = check(
        r#"{"fields": [{"name": "k", "secret": true}], "callers": [],
            "operations": [{"name": "d", "steps": [{"do": "return",
                                                    "template": "ab{{ hex(sha257(k)) "}]}]}"#,
    );
    assert!(stderr.contains("template syntax"), "{stderr}");
    assert!(stderr.contains("byte 2"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A GET of /identity on a raw connection; the status, or None when no answer came in time.
fn get_identity(port: u16, timeout: Duration) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    write!(
        stream,
        "GET /identity HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    text.split_whitespace().nth(1)?.parse().ok()
}

/// A client that announces a body and sends it slowly (here: never).
fn slow_client(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST /call HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5000\r\n\r\n{{"
    )
    .unwrap();
    stream
}

#[test]
fn slow_clients_do_not_block_the_server() {
    let dir = temp_dir("slow");
    let key = dir.join("node.key");
    ok(&["keygen", "node", "--out", s(&key)]);
    let port = free_port();
    let _server = start(&key, &dir.join("log.jsonl"), port, None);

    // More slow clients than worker threads: reads of the identity still answer at once.
    let slow: Vec<TcpStream> = (0..8).map(|_| slow_client(port)).collect();
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    assert_eq!(get_identity(port, Duration::from_secs(3)), Some(200));
    assert!(started.elapsed() < Duration::from_secs(2));

    // A body larger than the limit is refused before it is read.
    let mut big = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        big,
        "POST /call HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 999999999\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    big.read_to_end(&mut raw).unwrap();
    assert!(String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 413"));
    drop(slow);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connections_beyond_the_cap_are_refused() {
    let dir = temp_dir("cap");
    let key = dir.join("node.key");
    ok(&["keygen", "node", "--out", s(&key)]);
    let port = free_port();
    let _server = start_with(
        &key,
        &dir.join("log.jsonl"),
        port,
        None,
        &["--max-connections", "2"],
    );
    let slow: Vec<TcpStream> = (0..2).map(|_| slow_client(port)).collect();
    // The server counts a connection once it has accepted it; on a loaded host that can take
    // longer than a fixed pause, so the check is repeated until the cap is reached.
    // A probe waits up to 3 s for its answer (a loaded host answers late) but never past the
    // deadline, which is checked before each probe. The slow clients send nothing after their
    // head, so the server drops them after `IO_TIMEOUT` (5 s): the cap holds about that long.
    let probe = |deadline: Instant| {
        let left = deadline.saturating_duration_since(Instant::now());
        get_identity(port, left.min(Duration::from_secs(3)))
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "the cap was not reached");
        if probe(deadline) == Some(503) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(slow);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "the slots were not freed");
        if probe(deadline) == Some(200) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn grant_without_a_pin_warns() {
    let dir = temp_dir("nopin");
    let path = |name: &str| dir.join(name);
    ok(&["keygen", "device", "--out", s(&path("device.key"))]);
    ok(&["keygen", "user", "--out", s(&path("user.key"))]);
    ok(&["keygen", "node", "--out", s(&path("node.key"))]);
    ok(&[
        "node",
        "identity",
        "--key",
        s(&path("node.key")),
        "--out",
        s(&path("identity.json")),
    ]);
    let out = run(&[
        "grant",
        "--device",
        s(&path("device.key")),
        "--user-key",
        s(&path("user.key")),
        "--node",
        s(&path("identity.json")),
        "--owner",
        "me",
        "--valid",
        "10",
        "--out",
        s(&path("grant.json")),
    ]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("warning: no --pin given"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn help_lists_the_exit_codes() {
    let help = ok(&["--help"]);
    for line in ["3  refused by the node", "4  rate limited", "5  connection"] {
        assert!(help.contains(line), "{line}");
    }
    assert!(ok(&["keygen", "--help"]).contains("icacls"));
    assert_eq!(run(&["no-such-command"]).status.code(), Some(2));
}
