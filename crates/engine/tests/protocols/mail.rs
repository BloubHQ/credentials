//! SMTP submission and IMAP: TLS (implicit or STARTTLS), the mechanism the policy names and
//! no other, envelopes within the mail rule, commands within their shapes, reflection.

use engine::caller::CallerMail;
use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::fake_mail::{ImapServer, SmtpServer};
use super::*;

const PASSWORD: &[u8] = b"mail-pass-9f3k";

fn smtp_operation(tls: &str, mechanism: &str) -> Operation {
    operation(json!({"name": "send", "steps": [
        {"do": "open", "connection": "smtp",
         "destinations": [{"host": "mail.example.com", "port": 587}],
         "tls": tls,
         "login": {"user": "me@example.com", "password": "{{password}}", "mechanism": mechanism}},
        {"do": "return", "relay": {"mail": {
            "senders": ["me@example\\.com"],
            "recipients": ["[a-z0-9.]{1,32}@example\\.(com|org)"],
            "max_recipients": 2
        }}}
    ]}))
}

fn smtp_setup(tls: &str, mechanism: &str) -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![smtp_operation(tls, mechanism)],
    )
}

fn starttls(server: SmtpServer) -> Fake<SmtpServer> {
    let mut fake = Fake::new(server);
    fake.plain
        .push_back(b"220 mail.example.com ESMTP\r\n".to_vec());
    fake.plain
        .push_back(b"250-mail.example.com\r\n250 STARTTLS\r\n".to_vec());
    fake.plain.push_back(b"220 2.0.0 ready\r\n".to_vec());
    fake
}

fn mail(from: &str, to: &[&str], data: &[u8]) -> CallerMail {
    CallerMail {
        from: from.into(),
        to: to.iter().map(|t| t.to_string()).collect(),
        data: data.to_vec(),
    }
}

fn send<P: Peer>(
    s: &Setup,
    fake: &mut Fake<P>,
    messages: Vec<CallerMail>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "send",
        session("mail.example.com", 587, Vec::new(), messages),
    );
    s.node.run(&call, fake).result
}

const MESSAGE: &[u8] = b"Subject: hi\r\n\r\nline one\r\n.hidden dot\r\nbye\r\n";

#[test]
fn starttls_submission_signs_in_and_sends_a_dot_stuffed_message() {
    let s = smtp_setup("starttls", "plain");
    let mut fake = starttls(SmtpServer::new(false, b"me@example.com", PASSWORD));
    let out = session_output(send(
        &s,
        &mut fake,
        vec![mail("me@example.com", &["you@example.org"], MESSAGE)],
    ));
    assert!(out.error.is_none());
    assert_eq!(fake.opened, ["starttls"]);
    assert!(
        !holds(&fake.plain_written, PASSWORD),
        "nothing secret in the clear"
    );
    // An address literal: a strict HELO check refuses `localhost`.
    assert_eq!(fake.plain_written, b"EHLO [127.0.0.1]\r\nSTARTTLS\r\n");
    let (from, to, data) = &fake.peer.messages[0];
    assert_eq!(from, b"<me@example.com>");
    assert_eq!(to, &[b"<you@example.org>".to_vec()]);
    assert_eq!(
        data,
        b"Subject: hi\r\n\r\nline one\r\n..hidden dot\r\nbye\r\n"
    );
    assert_eq!(out.results[0].name, "mail");
    assert_eq!(out.results[0].status, Some(250));
}

#[test]
fn implicit_tls_with_auth_login() {
    let s = smtp_setup("implicit", "login");
    let mut fake = Fake::new(SmtpServer::new(true, b"me@example.com", PASSWORD));
    let out = session_output(send(
        &s,
        &mut fake,
        vec![mail(
            "me@example.com",
            &["a@example.com", "b@example.com"],
            MESSAGE,
        )],
    ));
    assert!(out.error.is_none());
    assert_eq!(fake.opened, ["tls"]);
    assert_eq!(fake.peer.messages.len(), 1);
}

#[test]
fn a_mechanism_the_server_does_not_offer_is_never_replaced() {
    // The policy names XOAUTH2-free PLAIN; the server offers LOGIN only.
    let s = smtp_setup("implicit", "plain");
    let mut server = SmtpServer::new(true, b"me@example.com", PASSWORD);
    server.mechanisms = vec!["LOGIN"];
    let mut fake = Fake::new(server);
    let result = send(
        &s,
        &mut fake,
        vec![mail("me@example.com", &["a@example.com"], MESSAGE)],
    );
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert_eq!(fake.peer.auth_lines, 0, "no AUTH sent");
    assert!(!holds(&fake.peer.received, PASSWORD));
}

#[test]
fn starttls_not_offered_or_bytes_injected_before_tls_are_refused() {
    let s = smtp_setup("starttls", "plain");
    let mut no_tls = Fake::new(SmtpServer::new(false, b"me@example.com", PASSWORD));
    no_tls.plain.push_back(b"220 hi\r\n".to_vec());
    no_tls
        .plain
        .push_back(b"250-hi\r\n250 AUTH PLAIN\r\n".to_vec());
    let result = send(
        &s,
        &mut no_tls,
        vec![mail("me@example.com", &["a@example.com"], MESSAGE)],
    );
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(!holds(&no_tls.plain_written, PASSWORD));
    assert!(no_tls.peer.received.is_empty());

    let mut injected = starttls(SmtpServer::new(false, b"me@example.com", PASSWORD));
    injected.plain_extra = b"250-x\r\n250 AUTH PLAIN\r\n".to_vec();
    let result = send(
        &s,
        &mut injected,
        vec![mail("me@example.com", &["a@example.com"], MESSAGE)],
    );
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(injected.peer.received.is_empty());
}

#[test]
fn envelopes_and_messages_outside_the_mail_rule_are_refused_first() {
    let s = smtp_setup("implicit", "plain");
    for message in [
        mail("other@example.com", &["a@example.com"], MESSAGE),
        mail("me@example.com", &["a@evil.test"], MESSAGE),
        mail(
            "me@example.com",
            &["a@example.com", "b@example.com", "c@example.com"],
            MESSAGE,
        ),
        mail("me@example.com", &[], MESSAGE),
        mail(
            "me@example.com",
            &["a@example.com>\r\nRCPT TO:<x@evil.test"],
            MESSAGE,
        ),
        // Bare LF and bare CR: SMTP smuggling.
        mail(
            "me@example.com",
            &["a@example.com"],
            b"hi\n.\nMAIL FROM:<x@evil.test>\r\n",
        ),
        mail("me@example.com", &["a@example.com"], b"hi\r.\rDATA\r\n"),
    ] {
        let mut fake = Fake::new(SmtpServer::new(true, b"me@example.com", PASSWORD));
        let result = send(&s, &mut fake, vec![message]);
        assert!(matches!(result, Err(engine::Error::RequestInvalid { .. })));
        assert!(fake.opened.is_empty(), "nothing opened");
    }
}

#[test]
fn a_secret_echoed_in_a_reply_never_goes_back() {
    let s = smtp_setup("implicit", "plain");
    let mut server = SmtpServer::new(true, b"me@example.com", PASSWORD);
    server.accepted = "queued for mail-pass-9f3k";
    let mut fake = Fake::new(server);
    let out = session_output(send(
        &s,
        &mut fake,
        vec![mail("me@example.com", &["a@example.com"], MESSAGE)],
    ));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = smtp_setup("implicit", "plain");
    let mut fake = Fake::new(SmtpServer::new(true, b"me@example.com", b"other"));
    let result = send(
        &s,
        &mut fake,
        vec![mail("me@example.com", &["a@example.com"], MESSAGE)],
    );
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
}

// --- IMAP -----------------------------------------------------------------------------------

fn imap_operation(login: Value, tls: &str) -> Operation {
    operation(json!({"name": "inbox", "steps": [
        {"do": "open", "connection": "imap",
         "destinations": [{"host": "mail.example.com", "port": 993}],
         "tls": tls, "login": login},
        {"do": "send", "command": {"text": "SELECT INBOX"}},
        {"do": "send", "command": {"text": "UID FETCH 7 BODY[TEXT]"}},
        {"do": "receive", "capture": [{
            "source": {"from": "regex", "pattern": "code: ([0-9]{6})", "group": 1},
            "into": {"kind": "temp", "name": "code", "secret": true}
        }]},
        {"do": "return", "relay": {"commands": [
            {"name": "search", "text": "UID SEARCH SUBJECT", "params": [{"pattern": "[ -~]{1,64}"}]},
            {"name": "confirm", "text": "UID STORE 7 +FLAGS", "params": [{"template": "{{code}}"}]},
            {"name": "body", "text": "UID FETCH", "params": [{"pattern": "[0-9]{1,6}"}]}
        ]}}
    ]}))
}

fn imap_setup(login: Value, tls: &str) -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![imap_operation(login, tls)],
    )
}

fn imap_server(greet: bool) -> ImapServer {
    let mut server = ImapServer::new(greet, b"me", PASSWORD);
    server.answer = |command| {
        if command.starts_with(b"UID FETCH 7 ") {
            let body = b"Your code: 493817\r\n";
            let mut out =
                format!("* 1 FETCH (UID 7 BODY[TEXT] {{{}}}\r\n", body.len()).into_bytes();
            out.extend_from_slice(body);
            out.extend_from_slice(b")\r\n");
            (out, true)
        } else if command.starts_with(b"UID FETCH ") {
            let body = b"your password is mail-pass-9f3k\r\n";
            let mut out = format!("* 2 FETCH (BODY[TEXT] {{{}}}\r\n", body.len()).into_bytes();
            out.extend_from_slice(body);
            out.extend_from_slice(b")\r\n");
            (out, true)
        } else if command.starts_with(b"UID SEARCH") {
            (b"* SEARCH 3 7\r\n".to_vec(), true)
        } else {
            (Vec::new(), true)
        }
    };
    server
}

fn inbox(
    s: &Setup,
    fake: &mut Fake<ImapServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "inbox",
        session("mail.example.com", 993, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

fn login() -> Value {
    json!({"user": "me", "password": "{{password}}"})
}

#[test]
fn imap_login_reads_a_code_into_a_temp_and_uses_it() {
    let s = imap_setup(login(), "implicit");
    let mut fake = Fake::new(imap_server(true));
    let out = session_output(inbox(
        &s,
        &mut fake,
        vec![
            command("search", &["Your \"code\""]),
            command("confirm", &[]),
        ],
    ));
    assert!(out.error.is_none());
    assert_eq!(out.results[0].status, Some(0));
    assert!(holds(&out.results[0].data, b"* SEARCH 3 7"));
    let commands = &fake.peer.commands;
    assert_eq!(commands[0], b"SELECT INBOX");
    assert_eq!(commands[1], b"UID FETCH 7 BODY[TEXT]");
    // A quote in a parameter stays inside its quoted string.
    assert_eq!(commands[2], b"UID SEARCH SUBJECT \"Your \\\"code\\\"\"");
    assert_eq!(commands[3], b"UID STORE 7 +FLAGS \"493817\"");
    // The code read from the message does not go back.
    assert!(!out.results.iter().any(|r| holds(&r.data, b"493817")));
}

#[test]
fn imap_authenticate_plain_over_starttls() {
    let s = imap_setup(
        json!({"user": "me", "password": "{{password}}", "mechanism": "plain"}),
        "starttls",
    );
    let mut fake = Fake::new(imap_server(false));
    fake.plain.push_back(b"* OK ready\r\n".to_vec());
    fake.plain.push_back(b"a0 OK begin TLS\r\n".to_vec());
    let out = session_output(inbox(&s, &mut fake, vec![command("search", &["x"])]));
    assert!(out.error.is_none());
    assert_eq!(fake.plain_written, b"a0 STARTTLS\r\n");
    assert!(fake.peer.signed_in);
}

#[test]
fn imap_mechanism_downgrades_are_refused() {
    // LOGIN on a server that disables it.
    let s = imap_setup(login(), "implicit");
    let mut server = imap_server(true);
    server.capabilities = "IMAP4rev1 LOGINDISABLED AUTH=PLAIN";
    let mut fake = Fake::new(server);
    let result = inbox(&s, &mut fake, vec![command("search", &["x"])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert!(!holds(&fake.peer.received, PASSWORD));
    // PLAIN on a server that does not offer it: no fallback to LOGIN.
    let s = imap_setup(
        json!({"user": "me", "password": "{{password}}", "mechanism": "plain"}),
        "implicit",
    );
    let mut server = imap_server(true);
    server.capabilities = "IMAP4rev1";
    let mut fake = Fake::new(server);
    let result = inbox(&s, &mut fake, vec![command("search", &["x"])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert!(!holds(&fake.peer.received, PASSWORD));
}

#[test]
fn imap_commands_outside_their_shapes_are_refused_first() {
    let s = imap_setup(login(), "implicit");
    for commands in [
        vec![command("expunge", &[])],
        vec![command("search", &["x\r\na9 DELETE INBOX"])],
        vec![command("body", &["1:*"])],
        vec![command("confirm", &["123456"])],
    ] {
        let mut fake = Fake::new(imap_server(true));
        let result = inbox(&s, &mut fake, commands);
        assert!(matches!(result, Err(engine::Error::RequestInvalid { .. })));
        assert!(fake.opened.is_empty());
    }
}

#[test]
fn a_secret_in_a_mail_body_never_goes_back() {
    let s = imap_setup(login(), "implicit");
    let mut fake = Fake::new(imap_server(true));
    let out = session_output(inbox(&s, &mut fake, vec![command("body", &["9"])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn an_approved_smtp_session_sends_the_messages_it_was_signed_with() {
    same_after_approval(
        &smtp_setup("starttls", "plain"),
        "send",
        session(
            "mail.example.com",
            587,
            Vec::new(),
            vec![mail("me@example.com", &["you@example.org"], MESSAGE)],
        ),
        || starttls(SmtpServer::new(false, b"me@example.com", PASSWORD)),
    );
}

#[test]
fn an_approved_imap_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &imap_setup(login(), "implicit"),
        "inbox",
        session(
            "mail.example.com",
            993,
            vec![
                command("search", &["Your \"code\""]),
                command("confirm", &[]),
            ],
            Vec::new(),
        ),
        || Fake::new(imap_server(true)),
    );
}
