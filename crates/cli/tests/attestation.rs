//! `credentials attest` and `credentials grant --attestation` on a real Nitro attestation
//! document (the fixtures of the `attest` crate, see `crates/attest/tests/fixtures/README.md`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const BIN: &str = env!("CARGO_BIN_EXE_credentials");

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../attest/tests/fixtures")
        .join(name)
}

fn document() -> PathBuf {
    fixture("nitro-attestation-prerelease.cbor")
}

fn measurements() -> PathBuf {
    fixture("measurements-prerelease.json")
}

fn nonce() -> String {
    URL_SAFE_NO_PAD.encode(std::fs::read(fixture("nitro-attestation-prerelease.nonce")).unwrap())
}

fn temp_dir(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "cli-attest-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A node key and its identity file in `dir`.
fn node_identity(dir: &Path) -> PathBuf {
    let key = dir.join("node.key");
    let identity = dir.join("identity.json");
    assert!(run(&["keygen", "node", "--out", s(&key)]).status.success());
    let out = run(&["node", "identity", "--key", s(&key), "--out", s(&identity)]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    identity
}

#[test]
fn a_real_document_verifies() {
    let nonce = nonce();
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &nonce,
        "--measurements",
        s(&measurements()),
    ]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("attestation verified"), "{stdout}");
    assert!(stdout.contains("release: v1.0.0"), "{stdout}");
    assert!(
        stdout.contains("module: i-00e27c4213a488340-enc01a0f5b621ecd411"),
        "{stdout}"
    );
    assert!(stdout.contains("time: 2026-10-01T04:26:30."), "{stdout}");
    assert!(
        stdout.contains("pcr0: d11eea49deb3a47dd60db99c7017435722ea4aa13678097839054c00e330ada12c83412710f923b45167068e12aeaba7"),
        "{stdout}"
    );
    assert!(stdout.contains("binding: not checked"), "{stdout}");
}

#[test]
fn the_document_can_come_from_stdin() {
    let nonce = nonce();
    let mut child = Command::new(BIN)
        .args([
            "attest",
            "--document",
            "-",
            "--nonce",
            &nonce,
            "--measurements",
            s(&measurements()),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(document()).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("release: v1.0.0"));
}

#[test]
fn refusals_exit_3() {
    let mut wrong = std::fs::read(fixture("nitro-attestation-prerelease.nonce")).unwrap();
    wrong[0] ^= 1;
    let wrong = URL_SAFE_NO_PAD.encode(wrong);
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &wrong,
        "--measurements",
        s(&measurements()),
    ]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("attestation refused"), "{stderr}");
    assert!(stderr.contains("nonce"), "{stderr}");

    // The fixture vouches for a node of another program, not this identity.
    let dir = temp_dir("bind");
    let identity = node_identity(&dir);
    let nonce = nonce();
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &nonce,
        "--measurements",
        s(&measurements()),
        "--identity",
        s(&identity),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(
        text(&out.stderr).contains("report data"),
        "{}",
        text(&out.stderr)
    );

    // Other measurements.
    let other = dir.join("other.json");
    let changed = std::fs::read_to_string(measurements())
        .unwrap()
        .replace("\"pcr0\": \"d11e", "\"pcr0\": \"011e");
    std::fs::write(&other, changed).unwrap();
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &nonce,
        "--measurements",
        s(&other),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(text(&out.stderr).contains("accepted release"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn usage_and_file_errors() {
    let short = URL_SAFE_NO_PAD.encode([7u8; 8]);
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &short,
        "--measurements",
        s(&measurements()),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let nonce = nonce();
    let out = run(&[
        "attest",
        "--document",
        s(&document()),
        "--nonce",
        &nonce,
        "--measurements",
        s(&fixture("missing.json")),
    ]);
    assert_eq!(out.status.code(), Some(5));
    let out = run(&[
        "attest",
        "--document",
        s(&fixture("missing.cbor")),
        "--nonce",
        &nonce,
        "--measurements",
        s(&measurements()),
    ]);
    assert_eq!(out.status.code(), Some(5));
}

#[test]
fn a_grant_is_sealed_only_to_an_attested_node() {
    let dir = temp_dir("grant");
    let identity = node_identity(&dir);
    let device = dir.join("device.key");
    let user = dir.join("user.key");
    assert!(
        run(&["keygen", "device", "--out", s(&device)])
            .status
            .success()
    );
    assert!(run(&["keygen", "user", "--out", s(&user)]).status.success());
    let grant = dir.join("grant.json");
    let nonce = nonce();
    let (document, measurements) = (document(), measurements());
    let base = [
        "grant",
        "--device",
        s(&device),
        "--user-key",
        s(&user),
        "--node",
        s(&identity),
        "--owner",
        "me",
        "--valid",
        "10",
        "--out",
        s(&grant),
    ];

    // The document verifies, but vouches for another node: no grant.
    let mut args = base.to_vec();
    args.extend([
        "--attestation",
        s(&document),
        "--nonce",
        &nonce,
        "--measurements",
        s(&measurements),
    ]);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("report data"));
    assert!(!grant.exists());

    // The three options go together.
    let mut args = base.to_vec();
    args.extend(["--attestation", s(&document)]);
    assert_eq!(run(&args).status.code(), Some(2));
    let mut args = base.to_vec();
    args.extend(["--nonce", &nonce]);
    assert_eq!(run(&args).status.code(), Some(2));

    // Without them, the grant is made with a warning.
    let out = run(&base);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("warning: no --attestation given"));
    assert!(grant.exists());
    std::fs::remove_dir_all(dir).unwrap();
}
