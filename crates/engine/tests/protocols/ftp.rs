//! FTP over TLS: implicit and explicit (AUTH TLS), PROT P, passive data connections to the
//! same server only, typed operations, paths that cannot inject a command, replies scrubbed
//! of the sign-in and bounded.

use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::fake_ftp::FtpServer;
use super::*;

const PASSWORD: &[u8] = b"ftp-pass-7Hq2";

fn ftp_operation(tls: &str) -> Operation {
    operation(json!({"name": "files", "steps": [
        {"do": "open", "connection": "ftp", "tls": tls,
         "destinations": [{"host": "files.example.com", "port": 990}],
         "login": {"user": "reports", "password": "{{password}}"}},
        {"do": "return", "relay": {"commands": [
            {"name": "ls", "text": "list", "params": [{"pattern": "/srv/[a-z]{1,16}|/"}]},
            {"name": "get", "text": "retrieve",
             "params": [{"pattern": "/srv/reports/[a-z0-9_.-]{1,32}"}]},
            {"name": "put", "text": "store",
             "params": [{"pattern": "[a-z0-9_-]{1,32}", "template": "/srv/inbox/{{ $input }}.txt"},
                        {"max_len": 4096}]},
            {"name": "rm", "text": "delete", "params": [{"pattern": "/srv/[a-z0-9/._-]{1,64}"}]},
            {"name": "mv", "text": "rename",
             "params": [{"pattern": "/srv/reports/[a-z0-9_.-]{1,32}"},
                        {"pattern": "/srv/archive/[a-z0-9_.-]{1,32}"}]},
            {"name": "mk", "text": "mkdir", "params": [{"template": "/srv/archive"}]},
            {"name": "any", "text": "retrieve", "params": [{}]}
        ]}}
    ]}))
}

fn ftp_setup(tls: &str) -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![ftp_operation(tls)],
    )
}

fn server(greet: bool) -> FtpServer {
    FtpServer::new(greet, b"reports", PASSWORD)
}

fn explicit(server: FtpServer) -> Fake<FtpServer> {
    let mut fake = Fake::new(server);
    fake.plain
        .push_back(b"220 files.example.com FTP ready\r\n".to_vec());
    fake.plain
        .push_back(b"234 Proceed with negotiation.\r\n".to_vec());
    fake
}

fn run(
    s: &Setup,
    fake: &mut Fake<FtpServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "files",
        session("files.example.com", 990, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

fn json_of(data: &[u8]) -> Value {
    serde_json::from_slice(data).unwrap()
}

#[test]
fn implicit_ftps_runs_every_typed_operation() {
    let s = ftp_setup("implicit");
    let mut fake = Fake::new(server(true));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![
            command("ls", &["/srv/reports"]),
            command("get", &["/srv/reports/a.csv"]),
            command("put", &["notes", "hello\r\nworld"]),
            command("mk", &[]),
            command("mv", &["/srv/reports/a.csv", "/srv/archive/a.csv"]),
            command("rm", &["/srv/inbox/notes.txt"]),
        ],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["tls"]);
    let listing = json_of(&out.results[0].data);
    assert_eq!(
        listing,
        json!([{"name": "a.csv", "type": "file", "size": 13, "modify": "20250101120000"}])
    );
    assert_eq!(out.results[1].data, b"id,total\n1,9\n");
    assert_eq!(json_of(&out.results[2].data)["code"], 226);
    assert_eq!(json_of(&out.results[3].data)["code"], 257);
    assert_eq!(json_of(&out.results[4].data)["code"], 250);
    assert_eq!(json_of(&out.results[5].data)["code"], 250);
    assert!(out.results.iter().all(|r| r.status == Some(0)));
    assert!(fake.peer.files.contains_key(&b"/srv/archive/a.csv"[..]));
    assert!(!fake.peer.files.contains_key(&b"/srv/inbox/notes.txt"[..]));
    // Every data connection is protected, and went to the port the server named.
    let commands = &fake.peer.commands;
    let at = |c: &str| commands.iter().position(|x| x == c).unwrap();
    assert!(at("PBSZ 0") < at("PROT P"));
    assert!(at("PROT P") < at("EPSV"));
    assert_eq!(fake.peer.opened_data, [50_000; 3]);
    assert!(commands.contains(&"STOR /srv/inbox/notes.txt".to_string()));
}

#[test]
fn explicit_ftps_writes_nothing_secret_before_tls() {
    let s = ftp_setup("starttls");
    let mut fake = explicit(server(false));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["/srv/reports/a.csv"])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["starttls"]);
    assert_eq!(fake.plain_written, b"AUTH TLS\r\n");
    assert!(
        !holds(&fake.plain_written, PASSWORD),
        "nothing secret in the clear"
    );
    assert_eq!(out.results[0].data, b"id,total\n1,9\n");
}

#[test]
fn auth_tls_refused_or_stripped_is_refused_before_any_credential() {
    let s = ftp_setup("starttls");
    // The server refuses AUTH TLS (a stripping attacker in the path answers so).
    let mut refused = Fake::new(server(false));
    refused.plain.push_back(b"220 ready\r\n".to_vec());
    refused
        .plain
        .push_back(b"530 Please login with USER and PASS\r\n".to_vec());
    let result = run(
        &s,
        &mut refused,
        vec![command("get", &["/srv/reports/a.csv"])],
    );
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(!holds(&refused.plain_written, PASSWORD));
    assert!(
        refused.peer.received.is_empty(),
        "nothing after the refusal"
    );

    // Bytes injected after the go-ahead, before the handshake.
    let mut injected = explicit(server(false));
    injected.plain_extra = b"230 Logged in\r\n".to_vec();
    let result = run(
        &s,
        &mut injected,
        vec![command("get", &["/srv/reports/a.csv"])],
    );
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(injected.peer.received.is_empty());
}

#[test]
fn plain_ftp_does_not_exist_as_a_policy() {
    // There is no plain mode: `tls` is implicit or starttls, and nothing opens a plain
    // connection for FTP.
    let bad: std::result::Result<Operation, _> = serde_json::from_value(json!({
        "name": "files", "steps": [
            {"do": "open", "connection": "ftp", "tls": "plain",
             "destinations": [{"host": "files.example.com", "port": 21}],
             "login": {"user": "reports", "password": "{{password}}"}},
            {"do": "return", "relay": {"commands": []}}]}));
    assert!(bad.is_err());
    let s = ftp_setup("implicit");
    let mut fake = Fake::new(server(true));
    let _ = run(&s, &mut fake, vec![command("get", &["/srv/reports/a.csv"])]);
    assert!(!fake.opened.contains(&"plain"));
}

#[test]
fn a_data_connection_without_prot_p_is_never_opened() {
    let s = ftp_setup("implicit");
    let mut srv = server(true);
    srv.prot_p = false;
    let mut fake = Fake::new(srv);
    let result = run(&s, &mut fake, vec![command("get", &["/srv/reports/a.csv"])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(fake.peer.opened_data.is_empty());
}

#[test]
fn a_passive_reply_naming_another_host_is_refused() {
    let s = ftp_setup("implicit");
    for (ip, port) in [
        ([10, 0, 0, 5], 50_000),
        ([127, 0, 0, 1], 50_000),
        ([192, 0, 2, 10], 25),
    ] {
        let mut srv = server(true);
        srv.epsv = false;
        srv.pasv_ip = ip;
        srv.data_port = port;
        let mut fake = Fake::new(srv);
        let out = session_output(run(
            &s,
            &mut fake,
            vec![command("get", &["/srv/reports/a.csv"])],
        ));
        assert!(
            matches!(out.error, Some(engine::Error::ServerUntrusted { .. })),
            "{ip:?}:{port} {:?}",
            out.error
        );
        assert!(
            fake.peer.opened_data.is_empty(),
            "no data connection opened"
        );
        assert!(!fake.peer.commands.iter().any(|c| c.starts_with("RETR")));
    }
    // PASV naming the control connection's own address is taken.
    let mut srv = server(true);
    srv.epsv = false;
    let mut fake = Fake::new(srv);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["/srv/reports/a.csv"])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert!(fake.peer.commands.contains(&"PASV".to_string()));
    assert_eq!(fake.peer.opened_data, [50_000]);
}

#[test]
fn crlf_and_traversal_in_a_path_are_refused_before_anything_is_sent() {
    let s = ftp_setup("implicit");
    for commands in [
        vec![command("any", &["/srv/a\r\nDELE /srv/reports/a.csv"])],
        vec![command("any", &["/srv/a\nDELE /x"])],
        vec![command("any", &["/srv/a\0"])],
        vec![command("any", &["/srv/\u{7f}"])],
        vec![command("any", &["/srv/../etc/passwd"])],
        vec![command("any", &["srv/a"])],
        vec![command("rm", &["/srv/a/../../etc"])],
        vec![command("put", &["x\r\nDELE", "data"])],
        vec![command(
            "get",
            &["/srv/reports/a.csv\r\nDELE /srv/reports/a.csv"],
        )],
    ] {
        let mut fake = Fake::new(server(true));
        let result = run(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty(), "nothing opened");
    }
}

#[test]
fn an_echoed_user_and_password_are_scrubbed_from_replies() {
    let s = ftp_setup("implicit");
    let mut srv = server(true);
    srv.echo = format!(
        "(user reports, password {})",
        String::from_utf8_lossy(PASSWORD)
    );
    let mut fake = Fake::new(srv);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("rm", &["/srv/reports/a.csv"])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    let data = &out.results[0].data;
    assert!(!holds(data, PASSWORD), "no password in what goes back");
    assert!(!holds(data, b"reports,"), "no user name either");
    assert!(holds(data, b"[redacted]"));
}

#[test]
fn a_failed_operation_comes_back_as_its_reply() {
    let s = ftp_setup("implicit");
    let mut fake = Fake::new(server(true));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["/srv/reports/none.csv"])],
    ));
    assert!(out.error.is_none());
    assert_eq!(out.results[0].status, Some(1));
    assert_eq!(json_of(&out.results[0].data)["code"], 550);
}

#[test]
fn oversized_replies_and_cut_transfers_fail_the_call() {
    let s = ftp_setup("implicit");
    // A FEAT reply of more lines than allowed.
    let mut srv = server(true);
    srv.feat_lines = 300;
    let mut fake = Fake::new(srv);
    let result = run(&s, &mut fake, vec![command("get", &["/srv/reports/a.csv"])]);
    assert!(
        matches!(result, Err(engine::Error::ResponseInvalid { .. })),
        "{result:?}"
    );

    // A data connection that ends without TLS close_notify: not taken for the whole file.
    let mut srv = server(true);
    srv.cut = true;
    let mut fake = Fake::new(srv);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["/srv/reports/a.csv"])],
    ));
    assert!(out.results.is_empty());
    assert!(
        matches!(out.error, Some(engine::Error::Transport { .. })),
        "{:?}",
        out.error
    );

    // A file larger than the connection's byte limit.
    let mut srv = server(true);
    srv.files.insert(
        b"/srv/reports/big.csv".to_vec(),
        vec![b'x'; 70 * 1024 * 1024],
    );
    let mut fake = Fake::new(srv);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["/srv/reports/big.csv"])],
    ));
    assert!(out.results.is_empty());
    assert!(out.error.is_some());
}

#[test]
fn a_wrong_password_is_refused_and_nothing_else_runs() {
    let s = ftp_setup("implicit");
    let mut fake = Fake::new(FtpServer::new(true, b"reports", b"another"));
    let result = run(&s, &mut fake, vec![command("get", &["/srv/reports/a.csv"])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert!(!fake.peer.commands.iter().any(|c| c.starts_with("PBSZ")));
}

#[test]
fn ftp_rules_are_checked_when_the_policy_is_signed() {
    let open = json!({"do": "open", "connection": "ftp",
        "destinations": [{"host": "files.example.com", "port": 990}],
        "login": {"user": "reports", "password": "{{password}}"}});
    for rule in [
        json!({"name": "x", "text": "RETR", "params": [{"template": "/a"}]}),
        json!({"name": "x", "text": "retrieve", "params": []}),
        json!({"name": "x", "text": "store", "params": [{"template": "/a"}]}),
        json!({"name": "x", "text": "retrieve", "params": [{"template": "/a/../b"}]}),
        json!({"name": "x", "text": "retrieve", "params": [{"template": "/a\r\nDELE /b"}]}),
        json!({"name": "x", "text": "delete", "params": [{"template": "/"}]}),
        json!({"name": "x", "text": "list", "params": [{"template": "/"}], "channel": "sftp"}),
    ] {
        let op: Operation = serde_json::from_value(json!({"name": "f", "steps": [
            open.clone(), {"do": "return", "relay": {"commands": [rule.clone()]}}]}))
        .unwrap();
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::secret("password")],
            callers: Vec::new(),
            operations: vec![op],
        };
        assert!(policy.validate().is_err(), "{rule}");
    }
    // Other mechanisms than USER/PASS, and a missing password, are refused.
    for login in [
        json!({"user": "u", "password": "{{password}}", "mechanism": "plain"}),
        json!({"user": "u", "token": "{{password}}"}),
        json!({"user": "", "password": "{{password}}"}),
    ] {
        let mut open = open.clone();
        open["login"] = login.clone();
        let op: Operation = serde_json::from_value(json!({"name": "f", "steps": [
            open, {"do": "return", "relay": {"commands": []}}]}))
        .unwrap();
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::secret("password")],
            callers: Vec::new(),
            operations: vec![op],
        };
        assert!(policy.validate().is_err(), "{login}");
    }
}

#[test]
fn an_approved_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &ftp_setup("implicit"),
        "files",
        session(
            "files.example.com",
            990,
            vec![
                command("ls", &["/srv/reports"]),
                command("put", &["notes", "hello"]),
            ],
            Vec::new(),
        ),
        || Fake::new(server(true)),
    );
}
