//! AMQP 1.0 over TLS: the SASL layer with the policy's mechanism, messages sent to and taken
//! from the addresses the policy fixes, with the settle mode it names, within the bounds of the
//! frame and type decoder.

use engine::policy::{Caller, FieldSpec};
use engine::proto::amqp1;
use serde_json::{Value, json};

use super::fake_amqp1::{Amqp1Broker, Misbehave, message};
use super::*;

const PASSWORD: &[u8] = b"amqp1-pass-71x";
const TOKEN: &[u8] = b"amqp1-token-5k2";

fn commands() -> Value {
    json!([
        {"name": "put", "text": "send",
         "params": [{"template": "orders"}, {"pattern": "[0-9]{1,9}", "template": "order:{{ $input }}"}]},
        {"name": "put_settled", "text": "send", "settle": "settled",
         "params": [{"template": "orders"}, {"pattern": "[0-9]{1,9}"}]},
        {"name": "put_second", "text": "send", "settle": "second",
         "params": [{"template": "orders"}, {"pattern": "[0-9]{1,9}"}]},
        {"name": "raw", "text": "send", "params": [{"template": "orders"}, {"max_len": 8192}]},
        {"name": "take", "text": "receive", "max_messages": 2, "wait_ms": 200,
         "params": [{"template": "replies"}]},
        {"name": "take_settled", "text": "receive", "max_messages": 2, "wait_ms": 200,
         "settle": "settled", "params": [{"template": "replies"}]},
        {"name": "take_second", "text": "receive", "max_messages": 2, "wait_ms": 200,
         "settle": "second", "params": [{"template": "replies"}]}
    ])
}

fn setup_with(fields: &[(FieldSpec, &[u8])], open: Value) -> Setup {
    setup(
        fields,
        vec![operation(json!({"name": "queue", "steps": [
            open,
            {"do": "return", "relay": {"commands": commands()}}
        ]}))],
    )
}

fn plain_setup() -> Setup {
    setup_with(
        &[(FieldSpec::secret("password"), PASSWORD)],
        json!({"do": "open", "connection": "amqp1",
               "destinations": [{"host": "mq.example.com", "port": 5671}],
               "login": {"user": "app", "password": "{{password}}"}}),
    )
}

fn run(
    s: &Setup,
    fake: &mut Fake<Amqp1Broker>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "queue",
        session("mq.example.com", 5671, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

fn data(out: &SessionOutput, i: usize) -> Value {
    serde_json::from_slice(&out.results[i].data).unwrap()
}

#[test]
fn plain_over_tls_then_send_and_receive() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.queues = vec![(
        "replies".into(),
        vec![
            message(b"one"),
            message(&vec![b'y'; 70_000]),
            message(b"three"),
        ],
    )];
    let mut fake = Fake::new(broker);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("put", &["1234"]), command("take", &[])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["tls"]);
    let b = &fake.peer;
    assert_eq!(b.mechanism.as_deref(), Some("PLAIN"));
    assert_eq!(b.hostname.as_deref(), Some("mq.example.com"));
    assert_eq!(
        b.received,
        [("orders".into(), b"order:1234".to_vec(), false)]
    );
    assert_eq!(data(&out, 0), json!({"outcome": "accepted"}));
    let got = data(&out, 1);
    assert_eq!(got.as_array().unwrap().len(), 2, "at most max_messages");
    assert_eq!(got[0]["payload"], json!("one"));
    assert_eq!(got[0]["subject"], json!("greeting"));
    assert_eq!(got[1]["payload"].as_str().unwrap().len(), 70_000);
    assert_eq!(b.credits, [2], "credit is the policy's count");
    // Both deliveries accepted and settled by the node (settle first).
    assert_eq!(
        b.dispositions,
        [
            (true, 0, true, amqp1::code::ACCEPTED),
            (true, 1, true, amqp1::code::ACCEPTED)
        ]
    );
}

#[test]
fn each_settle_mode_is_kept_on_send() {
    let s = plain_setup();
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![
            command("put_settled", &["1"]),
            command("put_second", &["2"]),
        ],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    let b = &fake.peer;
    // snd-settle-mode settled (1) / unsettled (0); rcv-settle-mode first (0) / second (1).
    assert_eq!(b.attaches[0].1, 1);
    assert_eq!(b.attaches[1].1, 0);
    assert_eq!(b.attaches[1].2, 1);
    assert!(b.received[0].2, "settled: sent settled");
    assert!(!b.received[1].2, "second: sent unsettled");
    assert_eq!(data(&out, 0), json!({"settled": true}));
    assert_eq!(data(&out, 1), json!({"outcome": "accepted"}));
    // Second: the node settles after the broker's unsettled outcome.
    assert_eq!(b.dispositions, [(false, 1, true, amqp1::code::ACCEPTED)]);
}

#[test]
fn each_settle_mode_is_kept_on_receive() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.queues = vec![("replies".into(), vec![message(b"a"), message(b"b")])];
    let mut fake = Fake::new(broker);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("take_settled", &[]), command("take_second", &[])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    let b = &fake.peer;
    assert_eq!((b.attaches[0].1, b.attaches[0].2), (1, 0));
    assert_eq!((b.attaches[1].1, b.attaches[1].2), (0, 1));
    assert_eq!(data(&out, 0).as_array().unwrap().len(), 2);
    assert_eq!(data(&out, 1).as_array().unwrap().len(), 0);
    // Settled deliveries get no disposition.
    assert!(b.dispositions.is_empty());

    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.queues = vec![("replies".into(), vec![message(b"c")])];
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("take_second", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(data(&out, 0)[0]["payload"], json!("c"));
    // Accepted unsettled: the broker settles first, the node after.
    assert_eq!(
        fake.peer.dispositions,
        [(true, 0, false, amqp1::code::ACCEPTED)]
    );
}

#[test]
fn a_broker_that_changes_or_breaks_the_settle_mode_is_refused() {
    for (misbehave, name) in [
        (Misbehave::ChangeSettle, "put"),
        (Misbehave::SettleFirst, "put_second"),
    ] {
        let s = plain_setup();
        let mut broker = Amqp1Broker::new(PASSWORD);
        broker.misbehave = misbehave;
        let mut fake = Fake::new(broker);
        let result = run(&s, &mut fake, vec![command(name, &["1"])]);
        let refused = match &result {
            Err(engine::Error::ServerUntrusted { .. }) => true,
            Ok(Output::Session(out)) => {
                matches!(out.error, Some(engine::Error::ServerUntrusted { .. }))
            }
            _ => false,
        };
        assert!(refused, "{misbehave:?}: {result:?}");
        if misbehave == Misbehave::ChangeSettle {
            assert!(fake.peer.received.is_empty(), "nothing sent on the link");
        }
    }
}

#[test]
fn the_receive_count_is_the_credit_however_much_the_broker_sends() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.misbehave = Misbehave::Overdeliver;
    broker.queues = vec![(
        "replies".into(),
        (0..5)
            .map(|i| message(format!("m{i}").as_bytes()))
            .collect(),
    )];
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("take", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(data(&out, 0).as_array().unwrap().len(), 2);
    assert_eq!(fake.peer.credits, [2]);
    assert_eq!(
        fake.peer.dispositions.len(),
        2,
        "only what the node took is accepted"
    );
}

#[test]
fn a_message_larger_than_the_bound_is_refused() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.misbehave = Misbehave::HugeMessage;
    let mut fake = Fake::new(broker);
    let result = run(&s, &mut fake, vec![command("take", &[])]);
    let refused = match &result {
        Err(engine::Error::Transport { .. }) => true,
        Ok(Output::Session(out)) => matches!(out.error, Some(engine::Error::Transport { .. })),
        _ => false,
    };
    assert!(refused, "{result:?}");
}

#[test]
fn oversized_frames_deep_values_and_unknown_performatives_end_the_connection() {
    for misbehave in [Misbehave::Oversized, Misbehave::Deep, Misbehave::Unknown] {
        let s = plain_setup();
        let mut broker = Amqp1Broker::new(PASSWORD);
        broker.misbehave = misbehave;
        let mut fake = Fake::new(broker);
        let result = run(&s, &mut fake, vec![command("put", &["1"])]);
        let failed = match &result {
            Err(_) => true,
            Ok(Output::Session(out)) => out.error.is_some() && out.results.is_empty(),
            _ => false,
        };
        assert!(failed, "{misbehave:?}: {result:?}");
        assert!(fake.peer.received.is_empty(), "{misbehave:?}: nothing sent");
    }
}

#[test]
fn a_server_without_the_mechanism_or_asking_for_more_gets_nothing() {
    for misbehave in [Misbehave::None, Misbehave::PlainChallenge] {
        let s = plain_setup();
        let mut broker = Amqp1Broker::new(PASSWORD);
        broker.misbehave = misbehave;
        if misbehave == Misbehave::None {
            broker.mechanisms = vec!["ANONYMOUS", "SCRAM-SHA-1"];
        }
        let mut fake = Fake::new(broker);
        let result = run(&s, &mut fake, vec![command("put", &["1"])]);
        assert!(
            matches!(result, Err(engine::Error::ServerUntrusted { .. })),
            "{misbehave:?}: {result:?}"
        );
        if misbehave == Misbehave::None {
            assert!(fake.peer.response.is_none(), "no credential sent");
        }
        assert!(!fake.peer.signed_in);
        assert!(fake.peer.received.is_empty());
    }
}

#[test]
fn a_server_that_skips_sasl_gets_nothing() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.misbehave = Misbehave::SkipSasl;
    let mut fake = Fake::new(broker);
    let result = run(&s, &mut fake, vec![command("put", &["1"])]);
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "{result:?}"
    );
    assert!(!holds(&fake.peer.written, PASSWORD), "no credential sent");
    assert_eq!(fake.peer.written, amqp1::SASL_HEADER, "only the header");
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = plain_setup();
    let mut fake = Fake::new(Amqp1Broker::new(b"other"));
    let result = run(&s, &mut fake, vec![command("put", &["1"])]);
    assert!(
        matches!(result, Err(engine::Error::AuthRefused { .. })),
        "{result:?}"
    );
}

#[test]
fn scram_signs_in_only_when_the_server_proves_the_password() {
    let scram = || {
        setup_with(
            &[(FieldSpec::secret("password"), PASSWORD)],
            json!({"do": "open", "connection": "amqp1",
                   "destinations": [{"host": "mq.example.com", "port": 5671}],
                   "login": {"user": "app", "password": "{{password}}",
                             "mechanism": "scram-sha-256", "vhost": "shop"}}),
        )
    };
    for final_in_challenge in [false, true] {
        let s = scram();
        let mut broker = Amqp1Broker::new(PASSWORD);
        broker.final_in_challenge = final_in_challenge;
        let mut fake = Fake::new(broker);
        let out = session_output(run(&s, &mut fake, vec![command("put", &["5"])]));
        assert!(out.error.is_none(), "{:?}", out.error);
        assert_eq!(fake.peer.mechanism.as_deref(), Some("SCRAM-SHA-256"));
        assert_eq!(fake.peer.hostname.as_deref(), Some("shop"), "the vhost");
        assert!(
            !holds(&fake.peer.written, PASSWORD),
            "the password never goes"
        );
        assert_eq!(fake.peer.received.len(), 1);
    }
    for misbehave in [Misbehave::BadProof, Misbehave::ScramNoProof] {
        let s = scram();
        let mut broker = Amqp1Broker::new(PASSWORD);
        broker.misbehave = misbehave;
        let mut fake = Fake::new(broker);
        let result = run(&s, &mut fake, vec![command("put", &["5"])]);
        assert!(result.is_err(), "{misbehave:?}: {result:?}");
        assert!(fake.peer.received.is_empty(), "{misbehave:?}");
    }
}

#[test]
fn xoauth2_and_external_sign_in() {
    let s = setup_with(
        &[(FieldSpec::secret("token"), TOKEN)],
        json!({"do": "open", "connection": "amqp1",
               "destinations": [{"host": "mq.example.com", "port": 5671}],
               "login": {"user": "app", "token": "{{token}}"}}),
    );
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.token = TOKEN.to_vec();
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("put", &["1"])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.mechanism.as_deref(), Some("XOAUTH2"));

    let s = setup_with(
        &[
            (FieldSpec::public("cert"), b"-----BEGIN CERTIFICATE-----"),
            (FieldSpec::secret("key"), b"-----BEGIN PRIVATE KEY-----"),
        ],
        json!({"do": "open", "connection": "amqp1",
               "destinations": [{"host": "mq.example.com", "port": 5671}],
               "identity": {"cert": "{{cert}}", "key": "{{key}}"},
               "login": {"user": "", "mechanism": "external"}}),
    );
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    let out = session_output(run(&s, &mut fake, vec![command("put", &["1"])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.mechanism.as_deref(), Some("EXTERNAL"));
    assert_eq!(fake.peer.response.as_deref(), Some(&b""[..]), "no authzid");
}

#[test]
fn the_tls_header_comes_first_and_a_plain_answer_is_refused() {
    let starttls = || {
        setup_with(
            &[(FieldSpec::secret("password"), PASSWORD)],
            json!({"do": "open", "connection": "amqp1", "tls": "starttls",
                   "destinations": [{"host": "mq.example.com", "port": 5672}],
                   "login": {"user": "app", "password": "{{password}}"}}),
        )
    };
    let go = |s: &Setup, fake: &mut Fake<Amqp1Broker>| {
        let call = sign(
            s,
            "queue",
            session(
                "mq.example.com",
                5672,
                vec![command("put", &["1"])],
                Vec::new(),
            ),
        );
        s.node.run(&call, fake).result
    };
    let s = starttls();
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    fake.plain.push_back(amqp1::TLS_HEADER.to_vec());
    let out = session_output(go(&s, &mut fake));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["starttls"]);
    assert_eq!(
        fake.plain_written,
        amqp1::TLS_HEADER,
        "only the header in the clear"
    );
    assert_eq!(fake.peer.received.len(), 1);

    // A server that answers in the clear (the SASL or AMQP header) gets nothing more.
    for answer in [amqp1::SASL_HEADER, amqp1::AMQP_HEADER] {
        let s = starttls();
        let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
        fake.plain.push_back(answer.to_vec());
        let result = go(&s, &mut fake);
        assert!(result.is_err(), "{result:?}");
        assert_eq!(fake.plain_written, amqp1::TLS_HEADER);
        assert!(fake.peer.written.is_empty(), "nothing after the refusal");
    }
    // Bytes after the server's header, before the handshake, are an injection.
    let s = starttls();
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    fake.plain.push_back(amqp1::TLS_HEADER.to_vec());
    fake.plain_extra = amqp1::SASL_HEADER.to_vec();
    let result = go(&s, &mut fake);
    assert!(result.is_err(), "{result:?}");
    assert!(fake.peer.written.is_empty());
}

#[test]
fn a_secret_echoed_in_a_rejection_is_scrubbed() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    broker.reject = Some(format!(
        "user app with password {} may not send",
        String::from_utf8_lossy(PASSWORD)
    ));
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("put", &["1"])]));
    assert_eq!(out.results[0].status, Some(1));
    assert!(
        !holds(&out.results[0].data, PASSWORD),
        "the password is scrubbed"
    );
    let rejected = data(&out, 0);
    assert_eq!(rejected["outcome"], json!("rejected"));
    assert_eq!(
        rejected["error"]["condition"],
        json!("amqp:unauthorized-access")
    );
}

#[test]
fn a_secret_in_a_message_never_goes_back() {
    let s = plain_setup();
    let mut broker = Amqp1Broker::new(PASSWORD);
    let mut leak = b"reply ".to_vec();
    leak.extend_from_slice(PASSWORD);
    broker.queues = vec![("replies".into(), vec![message(&leak)])];
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("take", &[])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn the_payload_is_one_body_whatever_it_holds() {
    let s = plain_setup();
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    let evil = "x\u{0}\u{53}\u{10}AMQP\u{3}";
    let out = session_output(run(&s, &mut fake, vec![command("raw", &[evil])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.received[0].1, evil.as_bytes());
}

#[test]
fn addresses_and_bounds_are_the_policys() {
    let s = plain_setup();
    for commands in [
        vec![command("put", &["x"])],
        vec![command("put", &["1", "other"])],
        vec![command("take", &["other-queue"])],
        vec![command("purge", &[])],
    ] {
        let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
        let result = run(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty());
    }
    let policy = |open: Value, rule: Value| Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: vec!["queue".into()],
            limit: None,
        }],
        operations: vec![operation(json!({"name": "queue", "steps": [
            open,
            {"do": "return", "relay": {"commands": [rule]}}
        ]}))],
    };
    let open = json!({"do": "open", "connection": "amqp1",
                      "destinations": [{"host": "mq.example.com", "port": 5671}],
                      "login": {"user": "app", "password": "{{password}}"}});
    let ok = policy(
        open.clone(),
        json!({"name": "x", "text": "send", "params": [{"template": "q"}, {"max_len": 10}]}),
    )
    .validate();
    assert!(ok.is_ok(), "{ok:?}");
    for rule in [
        // The caller picks the address.
        json!({"name": "x", "text": "send", "params": [{"pattern": "[a-z]{1,8}"}, {"max_len": 10}]}),
        json!({"name": "x", "text": "receive", "params": [{"pattern": "[a-z]{1,8}"}]}),
        // Counts and waits out of bounds.
        json!({"name": "x", "text": "receive", "max_messages": 257, "params": [{"template": "q"}]}),
        json!({"name": "x", "text": "receive", "wait_ms": 60_001, "params": [{"template": "q"}]}),
        // Another verb, a forward's flag.
        json!({"name": "x", "text": "publish", "params": [{"template": "q"}, {"max_len": 10}]}),
        json!({"name": "x", "text": "send", "wildcard_bind": true,
               "params": [{"template": "q"}, {"max_len": 10}]}),
    ] {
        assert!(
            policy(open.clone(), rule.clone()).validate().is_err(),
            "{rule}"
        );
    }
    // External needs a client certificate; a settle mode is for AMQP 1.0 only.
    let external = json!({"do": "open", "connection": "amqp1",
                          "destinations": [{"host": "mq.example.com", "port": 5671}],
                          "login": {"user": "", "mechanism": "external"}});
    let rule = json!({"name": "x", "text": "send", "params": [{"template": "q"}, {"max_len": 10}]});
    assert!(policy(external, rule).validate().is_err());
    let amqp = json!({"do": "open", "connection": "amqp",
                      "destinations": [{"host": "mq.example.com", "port": 5671}],
                      "login": {"user": "app", "password": "{{password}}"}});
    let settle = json!({"name": "x", "text": "publish", "settle": "first",
                        "params": [{"template": "e"}, {"template": "k"}, {"max_len": 10}]});
    assert!(policy(amqp, settle).validate().is_err());
}

#[test]
fn the_summary_names_the_mode_and_the_tls_header() {
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: vec!["queue".into()],
            limit: None,
        }],
        operations: vec![operation(json!({"name": "queue", "steps": [
            {"do": "open", "connection": "amqp1", "tls": "starttls",
             "destinations": [{"host": "mq.example.com", "port": 5672}],
             "login": {"user": "app", "password": "{{password}}"}},
            {"do": "return", "relay": {"commands": commands()}}
        ]}))],
    };
    let valid = policy.validate();
    assert!(valid.is_ok(), "{valid:?}");
    let lines = policy.summary().join(
        "
",
    );
    assert!(lines.contains("AMQP TLS header"), "{lines}");
    assert!(lines.contains("settle second"), "{lines}");
    let flags = engine::policy::summary::summarize(&policy, None).flags;
    assert!(
        flags
            .iter()
            .any(|f| f.code == engine::policy::summary::FlagCode::PasswordToServer),
        "PLAIN hands the server the password"
    );
    // A changed settle mode is a wider policy (at most once instead of once confirmed).
    let mut settled = policy.clone();
    let text = serde_json::to_string(&settled.operations).unwrap();
    settled.operations = serde_json::from_str(&text.replace("\"second\"", "\"settled\"")).unwrap();
    assert!(settled.validate().is_ok());
    let flags = engine::policy::summary::summarize(&settled, Some(&policy)).flags;
    assert!(
        flags
            .iter()
            .any(|f| f.code == engine::policy::summary::FlagCode::Wider
                && f.detail.contains("put_second")),
        "{flags:?}"
    );
}

#[test]
fn a_send_step_of_the_policy_runs_before_the_callers_commands() {
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "queue", "steps": [
            {"do": "open", "connection": "amqp1",
             "destinations": [{"host": "mq.example.com", "port": 5671}],
             "login": {"user": "app", "password": "{{password}}"}},
            {"do": "send", "command": {"text": "send", "params": ["audit", "opened"]}},
            {"do": "return", "relay": {"commands": commands()}}
        ]}))],
    );
    let mut fake = Fake::new(Amqp1Broker::new(PASSWORD));
    let out = session_output(run(&s, &mut fake, vec![command("put", &["9"])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(
        fake.peer.received,
        [
            ("audit".into(), b"opened".to_vec(), false),
            ("orders".into(), b"order:9".to_vec(), false)
        ]
    );
}

#[test]
fn an_approved_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &plain_setup(),
        "queue",
        session(
            "mq.example.com",
            5671,
            vec![command("put", &["1234"]), command("take", &[])],
            Vec::new(),
        ),
        || {
            let mut broker = Amqp1Broker::new(PASSWORD);
            broker.queues = vec![("replies".into(), vec![message(b"one")])];
            Fake::new(broker)
        },
    );
}
