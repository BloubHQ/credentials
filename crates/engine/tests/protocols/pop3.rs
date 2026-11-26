//! POP3: implicit TLS and STLS, the mechanism the policy names and no other (USER/PASS, APOP,
//! SASL PLAIN, LOGIN, XOAUTH2), message numbers only, status lines scrubbed of the sign-in,
//! and reading a code from a message into a temp.

use engine::policy::FieldSpec;
use engine::policy::summary::FlagCode;
use serde_json::{Value, json};

use super::fake_pop3::Pop3Server;
use super::*;

const PASSWORD: &[u8] = b"pop-pass-x81k";
const TOKEN: &[u8] = b"ya29.pop-token-aa";

fn pop3_operation(tls: &str, login: Value) -> Operation {
    operation(json!({"name": "mail", "steps": [
        {"do": "open", "connection": "pop3", "tls": tls,
         "destinations": [{"host": "pop.example.com", "port": 995}],
         "login": login},
        {"do": "return", "relay": {"commands": [
            {"name": "stat", "text": "STAT"},
            {"name": "list", "text": "LIST"},
            {"name": "uidl", "text": "UIDL", "params": [{"pattern": "[0-9]{1,4}"}]},
            {"name": "read", "text": "RETR", "params": [{"pattern": "[0-9]{1,4}"}]},
            {"name": "head", "text": "TOP", "params": [{"pattern": "[0-9]{1,4}"}, {"template": "0"}]},
            {"name": "drop", "text": "DELE", "params": [{"max_len": 32}]}
        ]}}
    ]}))
}

fn password_login(mechanism: &str) -> Value {
    json!({"user": "me@example.com", "password": "{{password}}", "mechanism": mechanism})
}

fn pop3_setup(tls: &str, login: Value) -> Setup {
    setup(
        &[
            (FieldSpec::secret("password"), PASSWORD),
            (FieldSpec::secret("token"), TOKEN),
        ],
        vec![pop3_operation(tls, login)],
    )
}

fn run(
    s: &Setup,
    fake: &mut Fake<Pop3Server>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "mail",
        session("pop.example.com", 995, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

fn server(greet: bool) -> Pop3Server {
    Pop3Server::new(greet, b"me@example.com", PASSWORD)
}

#[test]
fn user_pass_over_implicit_tls_reads_messages() {
    let s = pop3_setup("implicit", password_login("user"));
    let mut fake = Fake::new(server(true));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![
            command("stat", &[]),
            command("list", &[]),
            command("read", &["2"]),
            command("head", &["1"]),
            command("drop", &["1"]),
        ],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["tls"]);
    assert!(out.results[0].data.starts_with(b"+OK 2 "));
    let sizes = format!(
        "1 {}\r\n2 {}\r\n",
        fake.peer.messages[0].len(),
        fake.peer.messages[1].len()
    );
    assert!(holds(&out.results[1].data, sizes.as_bytes()));
    // Dot-unstuffed.
    assert!(holds(&out.results[2].data, b"\r\n.starts with a dot\r\n"));
    assert!(!holds(&out.results[2].data, b"..starts"));
    assert!(holds(&out.results[3].data, b"Your code"));
    assert_eq!(out.results[4].status, Some(0));
    assert_eq!(fake.peer.deleted, [1]);
    assert!(fake.peer.commands.contains(&"TOP 1 0".to_string()));
    assert!(fake.peer.commands.last().is_some_and(|c| c == "QUIT"));
}

#[test]
fn stls_upgrades_before_anything_and_keeps_the_greeting_for_apop() {
    let s = pop3_setup("starttls", password_login("apop"));
    let mut fake = Fake::new(server(false));
    fake.plain
        .push_back(format!("+OK POP3 ready {}\r\n", super::fake_pop3::STAMP).into_bytes());
    fake.plain
        .push_back(b"+OK Begin TLS negotiation\r\n".to_vec());
    let out = session_output(run(&s, &mut fake, vec![command("stat", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["starttls"]);
    assert_eq!(fake.plain_written, b"STLS\r\n");
    assert!(fake.peer.signed_in);
    // APOP sends a digest, never the password; CAPA is asked again over TLS.
    assert!(!holds(&fake.peer.received, PASSWORD));
    assert_eq!(fake.peer.commands[0], "CAPA");
    assert!(fake.peer.commands[1].starts_with("APOP me@example.com "));
}

#[test]
fn stls_refused_or_stripped_is_refused_before_any_credential() {
    let s = pop3_setup("starttls", password_login("user"));
    let mut refused = Fake::new(server(false));
    refused.plain.push_back(b"+OK POP3 ready\r\n".to_vec());
    refused
        .plain
        .push_back(b"-ERR STLS not supported\r\n".to_vec());
    let result = run(&s, &mut refused, vec![command("stat", &[])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(!holds(&refused.plain_written, PASSWORD));
    assert!(refused.peer.received.is_empty());

    let mut injected = Fake::new(server(false));
    injected.plain.push_back(b"+OK POP3 ready\r\n".to_vec());
    injected.plain.push_back(b"+OK go ahead\r\n".to_vec());
    injected.plain_extra = b"+OK USER\r\n".to_vec();
    let result = run(&s, &mut injected, vec![command("stat", &[])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(injected.peer.received.is_empty());
}

#[test]
fn every_sasl_mechanism_signs_in() {
    for login in [
        password_login("plain"),
        password_login("login"),
        json!({"user": "me@example.com", "token": "{{token}}"}),
    ] {
        let s = pop3_setup("implicit", login.clone());
        let secret = if login.get("token").is_some() {
            TOKEN
        } else {
            PASSWORD
        };
        let mut fake = Fake::new(Pop3Server::new(true, b"me@example.com", secret));
        let out = session_output(run(&s, &mut fake, vec![command("stat", &[])]));
        assert!(out.error.is_none(), "{login}: {:?}", out.error);
        assert!(fake.peer.signed_in, "{login}");
        assert!(fake.peer.commands.iter().any(|c| c.starts_with("AUTH ")));
        assert!(!fake.peer.commands.iter().any(|c| c.starts_with("USER")));
    }
}

#[test]
fn a_mechanism_the_server_does_not_offer_is_never_replaced() {
    for (login, caps) in [
        (password_login("plain"), vec!["USER", "SASL LOGIN"]),
        (password_login("user"), vec!["SASL PLAIN"]),
        (password_login("login"), vec!["USER"]),
    ] {
        let s = pop3_setup("implicit", login.clone());
        let mut srv = server(true);
        srv.capabilities = Some(caps);
        let mut fake = Fake::new(srv);
        let result = run(&s, &mut fake, vec![command("stat", &[])]);
        assert!(
            matches!(result, Err(engine::Error::AuthRefused { .. })),
            "{login}: {result:?}"
        );
        assert!(!holds(&fake.peer.received, PASSWORD), "{login}");
        assert_eq!(fake.peer.commands, ["CAPA"], "{login}");
    }
    // APOP needs the greeting's timestamp: a greeting without one signs in with nothing.
    let s = pop3_setup("implicit", password_login("apop"));
    let call = sign(
        &s,
        "mail",
        session(
            "pop.example.com",
            995,
            vec![command("stat", &[])],
            Vec::new(),
        ),
    );
    let mut fake = Fake::new(Greets(server(false), false));
    let result = s.node.run(&call, &mut fake).result;
    assert!(
        matches!(result, Err(engine::Error::AuthRefused { .. })),
        "{result:?}"
    );
    assert!(!holds(&fake.peer.0.received, PASSWORD));
    assert!(!fake.peer.0.commands.iter().any(|c| c.starts_with("APOP")));
}

/// A server whose greeting has no APOP timestamp.
struct Greets(Pop3Server, bool);

impl Peer for Greets {
    fn feed(&mut self, bytes: &[u8]) {
        self.0.feed(bytes);
    }

    fn take(&mut self) -> Vec<u8> {
        if !self.1 {
            self.1 = true;
            return b"+OK ready\r\n".to_vec();
        }
        self.0.take()
    }

    fn closed(&self) -> bool {
        self.0.closed()
    }
}

#[test]
fn a_wrong_password_is_refused() {
    let s = pop3_setup("implicit", password_login("user"));
    let mut fake = Fake::new(Pop3Server::new(true, b"me@example.com", b"other"));
    let result = run(&s, &mut fake, vec![command("stat", &[])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert!(!fake.peer.commands.iter().any(|c| c == "STAT"));
}

#[test]
fn parameters_are_message_numbers_only() {
    let s = pop3_setup("implicit", password_login("user"));
    for params in [
        ["1\r\nDELE 2"],
        ["1 2"],
        ["x"],
        ["-1"],
        ["12345678901"],
        [""],
    ] {
        let mut fake = Fake::new(server(true));
        let result = run(&s, &mut fake, vec![command("drop", &params)]);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{params:?}: {result:?}"
        );
        assert!(fake.opened.is_empty(), "nothing opened");
    }
}

#[test]
fn an_echoed_user_and_password_are_scrubbed_from_status_lines() {
    let s = pop3_setup("implicit", password_login("user"));
    let mut srv = server(true);
    srv.echo = format!("(me@example.com / {})", String::from_utf8_lossy(PASSWORD));
    let mut fake = Fake::new(srv);
    let out = session_output(run(&s, &mut fake, vec![command("stat", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    let data = &out.results[0].data;
    assert!(!holds(data, PASSWORD), "no password in what goes back");
    assert!(!holds(data, b"me@example.com"));
    assert!(holds(data, b"[redacted]"));
}

#[test]
fn a_message_holding_the_password_never_goes_back() {
    let s = pop3_setup("implicit", password_login("user"));
    let mut srv = server(true);
    srv.messages[0] = b"Subject: leak\r\n\r\npop-pass-x81k\r\n".to_vec();
    let mut fake = Fake::new(srv);
    let out = session_output(run(&s, &mut fake, vec![command("read", &["1"])]));
    assert!(out.results.is_empty());
    assert!(
        matches!(out.error, Some(engine::Error::Reflection)),
        "{:?}",
        out.error
    );
}

#[test]
fn oversized_status_lines_fail_the_call() {
    let s = pop3_setup("implicit", password_login("user"));
    let mut srv = server(true);
    srv.echo = "x".repeat(5000);
    let mut fake = Fake::new(srv);
    // The status line of the sign-in is already too long.
    let result = run(&s, &mut fake, vec![command("stat", &[])]);
    assert!(
        matches!(result, Err(engine::Error::ResponseInvalid { .. })),
        "{result:?}"
    );
    assert!(!fake.peer.commands.iter().any(|c| c == "STAT"));
}

#[test]
fn a_code_is_read_from_a_message_into_a_temp() {
    let op = operation(json!({"name": "code", "steps": [
        {"do": "open", "connection": "pop3",
         "destinations": [{"host": "pop.example.com", "port": 995}],
         "login": {"user": "me@example.com", "password": "{{password}}"}},
        {"do": "send", "command": {"text": "RETR", "params": ["1"]}},
        {"do": "receive", "capture": [{"source": {"from": "regex", "pattern": "code: ([0-9]{6})"},
                                       "into": {"kind": "temp", "name": "code", "secret": false}}]},
        {"do": "return", "relay": {"commands": [{"name": "noop", "text": "NOOP"}]}}
    ]}));
    let s = setup(&[(FieldSpec::secret("password"), PASSWORD)], vec![op]);
    let mut fake = Fake::new(server(true));
    let call = sign(
        &s,
        "code",
        session(
            "pop.example.com",
            995,
            vec![command("noop", &[])],
            Vec::new(),
        ),
    );
    let out = session_output(s.node.run(&call, &mut fake).result);
    assert!(out.error.is_none(), "{:?}", out.error);
    assert!(fake.peer.commands.contains(&"RETR 1".to_string()));
    assert_eq!(out.results.len(), 1);
}

#[test]
fn apop_is_flagged_weak_and_user_as_handing_the_password() {
    let policy = |login: Value| Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: Vec::new(),
        operations: vec![pop3_operation("implicit", login)],
    };
    let apop = engine::policy::summary::summarize(&policy(password_login("apop")), None);
    assert!(apop.flags.iter().any(|f| f.code == FlagCode::WeakMechanism));
    assert!(
        !apop
            .flags
            .iter()
            .any(|f| f.code == FlagCode::PasswordToServer)
    );
    let user = engine::policy::summary::summarize(&policy(password_login("user")), None);
    assert!(
        user.flags
            .iter()
            .any(|f| f.code == FlagCode::PasswordToServer)
    );
    assert!(!user.flags.iter().any(|f| f.code == FlagCode::WeakMechanism));
}

#[test]
fn pop3_rules_are_checked_when_the_policy_is_signed() {
    for rule in [
        json!({"name": "x", "text": "RETR"}),
        json!({"name": "x", "text": "RETR", "params": [{"template": "1 2"}]}),
        json!({"name": "x", "text": "RETR", "params": [{"template": "1\r\nDELE 1"}]}),
        json!({"name": "x", "text": "TOP", "params": [{"template": "1"}]}),
        json!({"name": "x", "text": "QUIT"}),
        json!({"name": "x", "text": "USER", "params": [{"template": "a"}]}),
        json!({"name": "x", "text": "retr", "params": [{"template": "1"}]}),
    ] {
        let op: Operation = serde_json::from_value(json!({"name": "m", "steps": [
            {"do": "open", "connection": "pop3",
             "destinations": [{"host": "pop.example.com", "port": 995}],
             "login": {"user": "u", "password": "{{password}}"}},
            {"do": "return", "relay": {"commands": [rule.clone()]}}]}))
        .unwrap();
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::secret("password")],
            callers: Vec::new(),
            operations: vec![op],
        };
        assert!(policy.validate().is_err(), "{rule}");
    }
}
