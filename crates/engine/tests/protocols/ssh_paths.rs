//! SSH beyond commands and the shell: SFTP within path patterns (traversal and links), local
//! port forwarding to the policy's destinations only, and the key exchanges, host keys and
//! client keys the other tests leave out, with keys generated here.

use base64::Engine as _;
use engine::node::{CallerFrame, FromCaller};
use engine::policy::{FieldSpec, FrameKind};
use serde_json::{Value, json};

use super::fake_ssh::{self, HostKind, SshServer};
use super::*;

const PASSWORD: &[u8] = b"hunter2-pass";

fn host() -> HostKind {
    HostKind::Ed25519([11; 32])
}

fn open_step(host_line: String, login: Value) -> Value {
    json!({"do": "open", "connection": "ssh",
           "destinations": [{"host": "box.example.com", "port": 22}],
           "host_keys": [host_line], "login": login})
}

fn password_login() -> Value {
    json!({"user": "deploy", "password": "{{password}}"})
}

fn files_operation() -> Operation {
    operation(json!({"name": "files", "steps": [
        open_step(host().line(), password_login()),
        {"do": "return", "relay": {"commands": [
            {"name": "report", "text": "read", "channel": "sftp",
             "params": [{"pattern": "/srv/reports/[a-z0-9_./-]{1,64}"}]},
            {"name": "upload", "text": "write", "channel": "sftp",
             "params": [{"pattern": "[a-z0-9_./-]{1,32}", "template": "/srv/inbox/{{ $input }}.txt"},
                        {"max_len": 4096}]},
            {"name": "motd", "text": "read", "channel": "sftp",
             "params": [{"template": "/etc/motd"}]}
        ]}}
    ]}))
}

fn files_server() -> SshServer {
    let mut server = SshServer::new(host());
    server
        .files
        .insert("/srv/reports/may.csv".into(), b"day,total\n1,10\n".to_vec());
    server
        .files
        .insert("/srv/inbox/keep.txt".into(), b"old".to_vec());
    server
        .files
        .insert("/etc/motd".into(), b"welcome\n".to_vec());
    server
        .files
        .insert("/etc/shadow".into(), b"root:hash".to_vec());
    // A link planted under the pattern, to a file outside it.
    server
        .links
        .insert("/srv/reports/leak.csv".into(), "/etc/shadow".into());
    server
}

fn run(s: &Setup, fake: &mut Fake<SshServer>, name: &str, commands: Vec<CallerCommand>) -> Output {
    let call = sign(
        s,
        name,
        session("box.example.com", 22, commands, Vec::new()),
    );
    match s.node.run(&call, fake).result {
        Ok(out) => out,
        Err(e) => panic!("call failed: {e}"),
    }
}

fn files_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![files_operation()],
    )
}

#[test]
fn sftp_reads_and_writes_paths_within_their_patterns() {
    let s = files_setup();
    let mut fake = Fake::new(files_server());
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "files",
        vec![
            command("report", &["/srv/reports/may.csv"]),
            command("upload", &["notes", "hello"]),
            command("motd", &[]),
        ],
    )));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(out.results[0].data, b"day,total\n1,10\n");
    assert_eq!(out.results[1].status, Some(0));
    assert_eq!(fake.peer.files["/srv/inbox/notes.txt"], b"hello");
    assert_eq!(out.results[2].data, b"welcome\n");
    // Each path was checked for links before it was opened.
    let realpaths: Vec<&str> = fake
        .peer
        .sftp_seen
        .iter()
        .filter(|(kind, _)| *kind == 16)
        .map(|(_, p)| p.as_str())
        .collect();
    assert_eq!(
        realpaths,
        ["/srv/reports/may.csv", "/srv/inbox", "/etc/motd"]
    );
}

#[test]
fn sftp_traversal_is_refused_before_anything_is_logged_or_sent() {
    let s = files_setup();
    for commands in [
        vec![command("report", &["/srv/reports/../../etc/shadow.csv"])],
        vec![command("report", &["/srv/reports/./may.csv"])],
        vec![command("report", &["/srv/reports//may.csv"])],
        vec![command("upload", &["..", "x"])],
        vec![command("upload", &["../../etc/cron", "x"])],
    ] {
        let mut fake = Fake::new(files_server());
        let call = sign(
            &s,
            "files",
            session("box.example.com", 22, commands, Vec::new()),
        );
        let result = s.node.run(&call, &mut fake).result;
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty(), "nothing reached the server");
    }
}

#[test]
fn a_link_under_the_pattern_is_not_followed() {
    let s = files_setup();
    let mut fake = Fake::new(files_server());
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "files",
        vec![command("report", &["/srv/reports/leak.csv"])],
    )));
    assert!(out.results.is_empty());
    assert!(
        matches!(out.error, Some(engine::Error::RequestInvalid { .. })),
        "{:?}",
        out.error
    );
    assert!(
        !fake.peer.sftp_seen.iter().any(|(kind, _)| *kind == 3),
        "the file was never opened"
    );
}

#[test]
fn a_link_in_the_directory_of_a_write_is_not_followed() {
    let s = files_setup();
    let mut server = files_server();
    server.files.remove("/srv/inbox/keep.txt");
    server.links.insert("/srv/inbox".into(), "/etc".into());
    let mut fake = Fake::new(server);
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "files",
        vec![command("upload", &["passwd", "x"])],
    )));
    assert!(
        matches!(out.error, Some(engine::Error::RequestInvalid { .. })),
        "{:?}",
        out.error
    );
    assert!(!fake.peer.files.contains_key("/etc/passwd.txt"));
}

#[test]
fn a_secret_in_a_file_never_goes_back() {
    let s = files_setup();
    let mut server = files_server();
    server.files.insert(
        "/srv/reports/creds.csv".into(),
        b"pw,hunter2-pass\n".to_vec(),
    );
    let mut fake = Fake::new(server);
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "files",
        vec![command("report", &["/srv/reports/creds.csv"])],
    )));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn sftp_rules_are_checked_when_the_policy_is_signed() {
    let bad = [
        json!({"name": "x", "text": "chmod", "channel": "sftp", "params": [{"pattern": "/a"}]}),
        json!({"name": "x", "text": "rename", "channel": "sftp", "params": [{"pattern": "/a"}]}),
        json!({"name": "x", "text": "rmdir", "channel": "sftp", "params": [{"template": "/"}]}),
        json!({"name": "x", "text": "stat", "channel": "sftp", "params": [{"template": "/a"}, {"template": "/b"}]}),
        json!({"name": "x", "text": "read", "channel": "sftp", "params": [{"template": "/srv/../etc/shadow"}]}),
        json!({"name": "x", "text": "read", "channel": "sftp", "params": [{"template": "relative/path"}]}),
        json!({"name": "x", "text": "write", "channel": "sftp", "params": [{"pattern": "/a"}]}),
    ];
    for rule in bad {
        let op: Operation = serde_json::from_value(json!({"name": "files", "steps": [
            open_step(host().line(), password_login()),
            {"do": "return", "relay": {"commands": [rule]}}
        ]}))
        .unwrap();
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::secret("password")],
            callers: vec![],
            operations: vec![op],
        };
        assert!(policy.validate().is_err());
    }
}

fn manage_operation() -> Operation {
    operation(json!({"name": "manage", "steps": [
        open_step(host().line(), password_login()),
        {"do": "return", "relay": {"commands": [
            {"name": "ls", "text": "list", "channel": "sftp",
             "params": [{"pattern": "/srv/[a-z]{1,16}"}]},
            {"name": "stat", "text": "stat", "channel": "sftp",
             "params": [{"pattern": "/srv/[a-z0-9_./-]{1,64}"}]},
            {"name": "mv", "text": "rename", "channel": "sftp",
             "params": [{"pattern": "/srv/reports/[a-z0-9_.-]{1,32}"},
                        {"pattern": "/srv/archive/[a-z0-9_.-]{1,32}"}]},
            {"name": "rm", "text": "delete", "channel": "sftp",
             "params": [{"pattern": "/srv/[a-z0-9_./-]{1,64}"}]},
            {"name": "mk", "text": "mkdir", "channel": "sftp",
             "params": [{"pattern": "/srv/[a-z]{1,16}"}]},
            {"name": "rd", "text": "rmdir", "channel": "sftp",
             "params": [{"pattern": "/srv/[a-z]{1,16}"}]}
        ]}}
    ]}))
}

fn manage_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![manage_operation()],
    )
}

#[test]
fn sftp_lists_stats_renames_deletes_and_makes_directories() {
    let s = manage_setup();
    let mut fake = Fake::new(files_server());
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "manage",
        vec![
            command("ls", &["/srv/reports"]),
            command("stat", &["/srv/reports/may.csv"]),
            command("mk", &["/srv/archive"]),
            command("mv", &["/srv/reports/may.csv", "/srv/archive/may.csv"]),
            command("rm", &["/srv/inbox/keep.txt"]),
            command("mk", &["/srv/tmp"]),
            command("rd", &["/srv/tmp"]),
        ],
    )));
    assert!(out.error.is_none(), "{:?}", out.error);
    let listing: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    let names: Vec<&str> = listing
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    // No . or .., links shown as links and never followed.
    assert_eq!(names, ["may.csv", "leak.csv"]);
    assert_eq!(listing[0]["type"], "file");
    assert_eq!(listing[0]["size"], 15);
    assert_eq!(listing[1]["type"], "link");
    let stat: Value = serde_json::from_slice(&out.results[1].data).unwrap();
    assert_eq!(stat["type"], "file");
    assert_eq!(stat["size"], 15);
    assert!(out.results.iter().all(|r| r.status == Some(0)));
    assert!(fake.peer.files.contains_key("/srv/archive/may.csv"));
    assert!(!fake.peer.files.contains_key("/srv/reports/may.csv"));
    assert!(!fake.peer.files.contains_key("/srv/inbox/keep.txt"));
    assert!(!fake.peer.dirs.contains("/srv/tmp"));
}

#[test]
fn sftp_management_never_acts_through_a_link() {
    let s = manage_setup();
    for (commands, kind) in [
        // A link is not a file to delete, rename or stat, nor is its target.
        (vec![command("rm", &["/srv/reports/leak.csv"])], 13u8),
        (
            vec![command("mv", &["/srv/reports/leak.csv", "/srv/archive/x"])],
            18,
        ),
        (vec![command("stat", &["/srv/reports/leak.csv"])], 0),
    ] {
        let mut server = files_server();
        server.dirs.insert("/srv/archive".into());
        let mut fake = Fake::new(server);
        let out = session_output(Ok(run(&s, &mut fake, "manage", commands)));
        assert!(out.results.is_empty());
        assert!(
            matches!(out.error, Some(engine::Error::RequestInvalid { .. })),
            "{:?}",
            out.error
        );
        assert!(!fake.peer.sftp_seen.iter().any(|(k, _)| *k == kind));
        assert!(fake.peer.files.contains_key("/etc/shadow"));
    }
    // A rename onto an existing file is refused: nothing is overwritten.
    let mut server = files_server();
    server
        .files
        .insert("/srv/archive/may.csv".into(), b"keep".to_vec());
    let mut fake = Fake::new(server);
    let out = session_output(Ok(run(
        &s,
        &mut fake,
        "manage",
        vec![command(
            "mv",
            &["/srv/reports/may.csv", "/srv/archive/may.csv"],
        )],
    )));
    assert!(out.error.is_some());
    assert_eq!(fake.peer.files["/srv/archive/may.csv"], b"keep");
    // Traversal in either path never reaches the server.
    for commands in [
        vec![command("mv", &["/srv/reports/../x", "/srv/archive/y"])],
        vec![command("rm", &["/srv/../etc/shadow"])],
        vec![command("rd", &["/srv/.."])],
    ] {
        let mut fake = Fake::new(files_server());
        let call = sign(
            &s,
            "manage",
            session("box.example.com", 22, commands, Vec::new()),
        );
        let result = s.node.run(&call, &mut fake).result;
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty());
    }
}

fn forward_operation() -> Operation {
    operation(json!({"name": "tunnel", "steps": [
        open_step(host().line(), password_login()),
        {"do": "return", "relay": {"server": true,
            "frames": [{"kind": "binary", "shape": {"raw": {"pattern": "[ -~]{1,1024}"}}}],
            "commands": [
                {"name": "db", "text": "db.internal:5432", "channel": "direct-tcpip"},
                {"name": "cache", "text": "10.0.0.7:6379", "channel": "direct-tcpip"}
            ]}}
    ]}))
}

fn forward_frame(call: &SignedCall, seq: u64, data: &[u8]) -> FromCaller {
    FromCaller::Frame(CallerFrame {
        seq,
        kind: FrameKind::Binary,
        data: data.to_vec(),
        signature: caller_key().sign_frame(&call.auth, seq, true, data),
    })
}

fn forward(
    s: &Setup,
    server: SshServer,
    commands: Vec<CallerCommand>,
    frames: &[&[u8]],
) -> (Fake<SshServer>, TestCaller, engine::Result<Output>) {
    let mut fake = Fake::new(server);
    let call = sign(
        s,
        "tunnel",
        session("box.example.com", 22, commands, Vec::new()),
    );
    let mut caller = TestCaller::default();
    for (i, data) in frames.iter().enumerate() {
        caller.sends.push_back(forward_frame(&call, i as u64, data));
    }
    caller.close = true;
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    (fake, caller, result)
}

#[test]
fn a_forward_reaches_only_the_policys_destination() {
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![forward_operation()],
    );
    let mut server = SshServer::new(host());
    server.reachable = vec!["db.internal:5432".into()];
    let sent: &[u8] = &[b'p'; 800];
    let (fake, caller, result) = forward(&s, server, vec![command("db", &[])], &[sent]);
    assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
    assert_eq!(fake.peer.forwards, ["db.internal:5432"]);
    assert_eq!(fake.peer.forwarded, sent);
    // The stream search holds back a tail as long as the longest secret until more comes;
    // the caller closed first, so what came back is a prefix of the echo.
    let mut echo = b"echo:".to_vec();
    echo.extend_from_slice(sent);
    let back = caller.output();
    assert!(back.len() > 5 && echo.starts_with(&back));
}

#[test]
fn a_forward_to_an_unlisted_destination_never_opens() {
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![forward_operation()],
    );
    // A name the policy does not list, two forwards, or none: refused before the log.
    for commands in [
        vec![command("evil.example.com:22", &[])],
        vec![command("db", &[]), command("cache", &[])],
        vec![command("db", &["evil.example.com"])],
        vec![],
    ] {
        let (fake, _, result) = forward(&s, SshServer::new(host()), commands, &[]);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.peer.forwards.is_empty());
    }
    // The server refusing a listed destination ends the call.
    let (fake, _, result) = forward(&s, SshServer::new(host()), vec![command("cache", &[])], &[]);
    assert!(result.is_err());
    assert_eq!(fake.peer.forwards, ["10.0.0.7:6379"]);
}

#[test]
fn a_secret_echoed_through_a_forward_never_goes_back() {
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![forward_operation()],
    );
    let mut server = SshServer::new(host());
    server.reachable = vec!["db.internal:5432".into()];
    let (_, caller, result) = forward(&s, server, vec![command("db", &[])], &[b"hunter2-pass"]);
    assert!(
        matches!(result, Err(engine::Error::Reflection)),
        "{result:?}"
    );
    assert!(!holds(&caller.output(), b"hunter2"));
}

#[test]
fn forward_rules_are_checked_when_the_policy_is_signed() {
    let bad = [
        // A destination the caller fills.
        json!({"server": true, "commands": [{"name": "x", "text": "{{host}}:22", "channel": "direct-tcpip"}]}),
        // No port, or parameters.
        json!({"server": true, "commands": [{"name": "x", "text": "db.internal", "channel": "direct-tcpip"}]}),
        json!({"server": true, "commands": [{"name": "x", "text": "db.internal:5432", "channel": "direct-tcpip",
               "params": [{"pattern": "a"}]}]}),
        // A forward on a relay that does not stream.
        json!({"commands": [{"name": "x", "text": "db.internal:5432", "channel": "direct-tcpip"}]}),
        // A forward mixed with commands on a streaming relay.
        json!({"server": true, "commands": [
            {"name": "x", "text": "db.internal:5432", "channel": "direct-tcpip"},
            {"name": "y", "text": "id"}]}),
    ];
    for relay in bad {
        let op: Operation = serde_json::from_value(json!({"name": "tunnel", "steps": [
            open_step(host().line(), password_login()),
            {"do": "return", "relay": relay}
        ]}))
        .unwrap();
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::secret("password")],
            callers: vec![],
            operations: vec![op],
        };
        assert!(policy.validate().is_err());
    }
}

/// An operation that runs `id`, signing in with `login` to a server with `host`.
fn id_setup(host: &HostKind, fields: &[(FieldSpec, &[u8])], login: Value) -> Setup {
    setup(
        fields,
        vec![operation(json!({"name": "ssh", "steps": [
            open_step(host.line(), login),
            {"do": "return", "relay": {"commands": [{"name": "id", "text": "id"}]}}
        ]}))],
    )
}

fn id_server(host: HostKind) -> SshServer {
    let mut server = SshServer::new(host);
    server.exec = |_| (b"uid=1000\n".to_vec(), Vec::new(), 0);
    server
}

fn signs_in(s: &Setup, server: SshServer) -> Fake<SshServer> {
    let mut fake = Fake::new(server);
    let out = session_output(Ok(run(s, &mut fake, "ssh", vec![command("id", &[])])));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(out.results[0].data, b"uid=1000\n");
    fake
}

#[test]
fn p384_and_p521_key_exchanges_with_their_hashes() {
    for kex in ["ecdh-sha2-nistp384", "ecdh-sha2-nistp521"] {
        let s = id_setup(
            &host(),
            &[(FieldSpec::secret("password"), PASSWORD)],
            password_login(),
        );
        let mut server = id_server(host());
        server.kex = vec![kex];
        let fake = signs_in(&s, server);
        assert_eq!(fake.peer.agreed_kex, kex);
    }
}

#[test]
fn rsa_host_keys_with_sha2_256_and_512() {
    let der = fake_ssh::rsa_key();
    for alg in ["rsa-sha2-512", "rsa-sha2-256"] {
        let host = HostKind::Rsa(der.clone());
        let s = id_setup(
            &host,
            &[(FieldSpec::secret("password"), PASSWORD)],
            password_login(),
        );
        let mut server = id_server(host);
        server.host_algs = vec![alg];
        let fake = signs_in(&s, server);
        assert_eq!(fake.peer.agreed_host, alg);
    }
    // Another RSA key than the pinned one is refused.
    let s = id_setup(
        &HostKind::Rsa(der),
        &[(FieldSpec::secret("password"), PASSWORD)],
        password_login(),
    );
    let mut server = id_server(HostKind::Rsa(fake_ssh::rsa_key()));
    server.host_algs = vec!["rsa-sha2-512"];
    let mut fake = Fake::new(server);
    let call = sign(
        &s,
        "ssh",
        session("box.example.com", 22, vec![command("id", &[])], Vec::new()),
    );
    let result = s.node.run(&call, &mut fake).result;
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "{result:?}"
    );
    assert!(!fake.peer.signed_in);
}

fn key_setup(key: &[u8]) -> Setup {
    id_setup(
        &host(),
        &[(FieldSpec::secret("key"), key)],
        json!({"user": "deploy", "key": "{{key}}"}),
    )
}

fn key_signs_in(key: &[u8], blob: Vec<u8>) {
    let s = key_setup(key);
    let mut server = id_server(host());
    server.keys = vec![blob];
    let fake = signs_in(&s, server);
    assert_eq!(fake.peer.methods, ["publickey"]);
}

fn ecdsa_blob(name: &str, curve: &str, point: &[u8]) -> Vec<u8> {
    let mut blob = fake_ssh::string(name.as_bytes());
    blob.extend(fake_ssh::string(curve.as_bytes()));
    blob.extend(fake_ssh::string(point));
    blob
}

#[test]
fn ecdsa_client_keys_in_pkcs8() {
    use ring::signature::KeyPair as _;
    let rng = ring::rand::SystemRandom::new();
    for (alg, name, curve) in [
        (
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            "ecdsa-sha2-nistp256",
            "nistp256",
        ),
        (
            &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            "ecdsa-sha2-nistp384",
            "nistp384",
        ),
    ] {
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
        key_signs_in(
            pkcs8.as_ref(),
            ecdsa_blob(name, curve, pair.public_key().as_ref()),
        );
    }
}

#[test]
fn rsa_client_keys_in_pkcs1() {
    let der = fake_ssh::rsa_key();
    key_signs_in(&der, fake_ssh::rsa_blob(&der));
}

/// An unencrypted `openssh-key-v1` key (PROTOCOL.key) in PEM.
fn openssh_pem(public_blob: &[u8], key_type: &str, private_fields: &[u8]) -> Vec<u8> {
    let mut private = 0x1234_5678u32.to_be_bytes().to_vec();
    private.extend(0x1234_5678u32.to_be_bytes());
    private.extend(fake_ssh::string(key_type.as_bytes()));
    private.extend_from_slice(private_fields);
    private.extend(fake_ssh::string(b"test key"));
    let mut pad = 1u8;
    while !private.len().is_multiple_of(8) {
        private.push(pad);
        pad += 1;
    }
    let mut raw = b"openssh-key-v1\0".to_vec();
    raw.extend(fake_ssh::string(b"none"));
    raw.extend(fake_ssh::string(b"none"));
    raw.extend(fake_ssh::string(b""));
    raw.extend(1u32.to_be_bytes());
    raw.extend(fake_ssh::string(public_blob));
    raw.extend(fake_ssh::string(&private));
    let body = base64::engine::general_purpose::STANDARD.encode(raw);
    let mut pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n".to_string();
    for line in body.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem.into_bytes()
}

#[test]
fn openssh_format_client_keys() {
    // Ed25519.
    let seed = [21u8; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    let mut blob = fake_ssh::string(b"ssh-ed25519");
    blob.extend(fake_ssh::string(&public));
    let mut both = seed.to_vec();
    both.extend(public);
    let mut fields = fake_ssh::string(&public);
    fields.extend(fake_ssh::string(&both));
    key_signs_in(&openssh_pem(&blob, "ssh-ed25519", &fields), blob);

    // ECDSA P-256 and P-384.
    {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let secret = p256::SecretKey::from_slice(&[22u8; 32]).unwrap();
        let point = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
        let blob = ecdsa_blob("ecdsa-sha2-nistp256", "nistp256", &point);
        let mut fields = fake_ssh::string(b"nistp256");
        fields.extend(fake_ssh::string(&point));
        fields.extend(mpint(&secret.to_bytes()));
        key_signs_in(&openssh_pem(&blob, "ecdsa-sha2-nistp256", &fields), blob);
    }
    {
        use p384::elliptic_curve::sec1::ToSec1Point as _;
        let secret = p384::SecretKey::from_slice(&[23u8; 48]).unwrap();
        let point = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
        let blob = ecdsa_blob("ecdsa-sha2-nistp384", "nistp384", &point);
        let mut fields = fake_ssh::string(b"nistp384");
        fields.extend(fake_ssh::string(&point));
        fields.extend(mpint(&secret.to_bytes()));
        key_signs_in(&openssh_pem(&blob, "ecdsa-sha2-nistp384", &fields), blob);
    }
}

fn mpint(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = magnitude.iter().copied().skip_while(|b| *b == 0).collect();
    let mut body = Vec::new();
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend(trimmed);
    fake_ssh::string(&body)
}

#[test]
fn an_approved_sftp_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &files_setup(),
        "files",
        session(
            "box.example.com",
            22,
            vec![
                command("report", &["/srv/reports/may.csv"]),
                command("upload", &["notes", "hello"]),
            ],
            Vec::new(),
        ),
        || Fake::new(files_server()),
    );
}
