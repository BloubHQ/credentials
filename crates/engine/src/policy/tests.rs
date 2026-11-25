#![allow(clippy::expect_used)]

use super::*;
use crate::keys::CallerKey;

fn caller() -> Caller {
    Caller::new(
        "app",
        CallerKey::from_bytes(&mut [5u8; 32]).public(),
        ["op"],
    )
}

fn one(fields: Vec<FieldSpec>, operation: Operation) -> Policy {
    Policy {
        item: None,
        fields,
        callers: vec![caller()],
        operations: vec![operation],
    }
}

fn rule_of(policy: &Policy) -> Option<(String, &'static str)> {
    match policy.validate() {
        Ok(()) => None,
        Err(Error::PolicyInvalid { at, rule }) => Some((at, rule)),
        Err(other) => panic!("{other:?}"),
    }
}

fn api() -> Destination {
    Destination::https("api.example.com")
}

fn caller_send() -> Send {
    Send::caller(CallerRequest::new([Method::Get]).paths(["/v1/**"]))
}

#[test]
fn json_reads_the_step_language() {
    let json = r#"{
      "fields": [{"name": "token", "secret": true}],
      "callers": [],
      "operations": [{
        "name": "op",
        "steps": [
          {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
          {"do": "send", "request": {"from": "caller", "methods": ["GET"], "paths": ["/v1/**"],
                                     "query": [{"name": "page", "max": "100"}]},
           "inject": [{"target": {"kind": "header", "name": "Authorization"}, "template": "Bearer {{token}}"}]},
          {"do": "return", "response": {"headers": ["ETag"], "body": {"json": ["/items/*/id"]}}}
        ]
      }]
    }"#;
    let mut policy: Policy = serde_json::from_str(json).unwrap();
    policy.callers = vec![caller()];
    policy.validate().unwrap();
    let text = serde_json::to_string(&policy).unwrap();
    assert_eq!(serde_json::from_str::<Policy>(&text).unwrap(), policy);
    // Unknown members are refused at every level, the fixed request included.
    for bad in [
        json.replace(r#""do": "open","#, r#""do": "open", "extra": 1,"#),
        json.replace(r#""from": "caller","#, r#""from": "caller", "extra": 1,"#),
        json.replace(r#""max": "100""#, r#""max": "100", "extra": 1"#),
    ] {
        assert!(serde_json::from_str::<Policy>(&bad).is_err(), "{bad}");
    }
    let fixed = r#"{"from": "fixed", "method": "GET", "path": "/x", "extra": 1}"#;
    assert!(serde_json::from_str::<StepRequest>(fixed).is_err());
}

#[test]
fn the_shape_of_an_operation_is_checked() {
    let fields = || vec![FieldSpec::secret("token")];
    // `open` comes first, once.
    let late_open = Operation {
        name: "op".into(),
        input: None,
        steps: vec![
            Step::Return(Return::output("x")),
            Step::Open(Open {
                connection: Connection::Https,
                destinations: vec![api()],
                identity: None,
            }),
        ],
        payment: None,
        approval: false,
    };
    assert!(rule_of(&one(fields(), late_open)).is_some());
    // An operation ends with `return`.
    let no_return = Operation::https("op", api()).then(caller_send());
    assert!(rule_of(&one(fields(), no_return)).is_some());
    // An HTTPS `receive` follows its `send`.
    let orphan = Operation::https("op", api())
        .then(Receive::response())
        .then(caller_send())
        .then(Return::status());
    assert!(rule_of(&one(fields(), orphan)).is_some());
    // A TLS `receive` names its delimiters.
    let endless = Operation::tls("op", Destination::new("imap.example.com", 993))
        .then(Receive::response())
        .then(Return::status());
    assert!(rule_of(&one(fields(), endless)).is_some());
    // A return of the wrong kind for the connection.
    let mixed = Operation::https("op", api())
        .then(caller_send())
        .then(Return::relay(["NOOP\r\n"]));
    assert!(rule_of(&one(fields(), mixed)).is_some());
    // The same operation, well formed.
    let good = Operation::https("op", api())
        .then(caller_send())
        .then(Return::status());
    assert_eq!(rule_of(&one(fields(), good)), None);
}

#[test]
fn loops_and_branches_are_syntax_for_now() {
    let json = r#"{"do": "repeat", "times": 3, "steps": [{"do": "compute", "into": "t", "template": "x"}]}"#;
    let repeat: Step = serde_json::from_str(json).unwrap();
    let json = r#"{"do": "if", "name": "status", "equals": "OK", "then": [], "else": []}"#;
    let branch: Step = serde_json::from_str(json).unwrap();
    for step in [repeat, branch] {
        let operation = Operation {
            name: "op".into(),
            input: None,
            steps: vec![step, Step::Return(Return::output("x"))],
            payment: None,
            approval: false,
        };
        let (_, rule) = rule_of(&one(vec![FieldSpec::secret("key")], operation)).expect("refused");
        assert!(rule.contains("not run yet"), "{rule}");
    }
}

#[test]
fn a_computed_value_has_the_properties_of_its_template() {
    let fields = || vec![FieldSpec::secret("key"), FieldSpec::guessable("pin")];
    let local = |steps: Vec<(&str, &str)>, out: &str| {
        let mut operation = Operation::local("op").input(Input::any());
        for (into, template) in steps {
            operation = operation.compute(into, template);
        }
        one(fields(), operation.then(Return::output(out)))
    };
    // A computed secret is as tainted as the secret, through any number of steps.
    for policy in [
        local(vec![("t", "{{key}}")], "{{t}}"),
        local(
            vec![("t", "{{hex(key)}}"), ("u", "{{t + $input}}")],
            "{{u}}",
        ),
        // An oracle through a computed value is still an oracle.
        local(vec![("t", "{{key}}")], r#"{{ slice(t, $input, "1") }}"#),
        // A computed check of a guessable field is a guess check.
        local(vec![("t", "{{ hex(sha256(pin)) }}")], "{{t}}"),
        // The hash of a secret alone is as good as the secret.
        local(vec![("t", "{{key}}")], "{{ hex(sha256(t)) }}"),
    ] {
        assert!(rule_of(&policy).is_some(), "{policy:?}");
    }
    // What the same templates allow inline, they allow through a computed value.
    for policy in [
        local(
            vec![("t", "{{ hmac_sha256(key, $input) }}")],
            "{{ hex(t) }}",
        ),
        local(vec![("t", "{{ len(pin) }}")], "{{t}}"),
    ] {
        assert_eq!(rule_of(&policy), None, "{policy:?}");
    }
    // A computed name may not shadow a field, a temporary value or another computed value.
    assert!(rule_of(&local(vec![("key", "x")], "x")).is_some());
    assert!(rule_of(&local(vec![("t", "x"), ("t", "y")], "{{t}}")).is_some());
    // And is read only after it is computed.
    assert!(rule_of(&local(vec![], "{{t}}")).is_some());
}

#[test]
fn the_input_is_declared_where_it_is_read() {
    let fields = || vec![FieldSpec::secret("key")];
    let undeclared = Operation::derive("op", "{{ hex(hmac_sha256(key, $input)) }}");
    assert!(rule_of(&one(fields(), undeclared.clone())).is_some());
    assert_eq!(
        rule_of(&one(fields(), undeclared.input(Input::any()))),
        None
    );
    // An input only for an operation with no connection.
    let https = Operation {
        input: Some(Input::any()),
        ..Operation::https("op", api())
            .then(caller_send())
            .then(Return::status())
    };
    assert!(rule_of(&one(fields(), https)).is_some());
}

#[test]
fn contracts_are_checked_at_signing() {
    let fields = || vec![FieldSpec::secret("token")];
    let with = |contract: CallerRequest, inject: Vec<Injection>| {
        let mut send = Send::caller(contract);
        send.inject = inject;
        one(
            fields(),
            Operation::https("op", api())
                .then(send)
                .then(Return::status()),
        )
    };
    let get = || CallerRequest::new([Method::Get]);
    for bad in [
        with(get(), vec![]),
        with(get().paths(["v1"]), vec![]),
        with(get().paths(["/v1/**/x"]), vec![]),
        with(get().paths(["/v1/a{id}"]), vec![]),
        with(get().paths(["/v1?x=1"]), vec![]),
        with(get().paths(["/v1/%2e%2e"]), vec![]),
        with(
            get().paths(["/v1/**"]).headers(["Authorization"]),
            vec![Injection::header("Authorization", "Bearer {{token}}")],
        ),
        with(
            get()
                .paths(["/v1/**"])
                .query(QueryRule::any("a"))
                .query(QueryRule::any("A")),
            vec![],
        ),
        with(
            get().paths(["/v1/**"]).query(QueryRule {
                min: Some("x".into()),
                ..QueryRule::any("n")
            }),
            vec![],
        ),
        // A path parameter without its whole segment in every template.
        with(
            get().paths(["/v1/{id}", "/v2/x"]),
            vec![Injection::path_param("id", "{{token}}")],
        ),
    ] {
        assert!(rule_of(&bad).is_some(), "{bad:?}");
    }
    assert_eq!(
        rule_of(&with(
            get().paths(["/v1/{id}/x", "/v2/{id}"]),
            vec![Injection::path_param("id", "{{token}}")],
        )),
        None
    );
}

#[test]
fn projections_and_relays_are_checked() {
    let fields = || vec![FieldSpec::secret("token")];
    let https = |ret: Return| {
        one(
            fields(),
            Operation::https("op", api()).then(caller_send()).then(ret),
        )
    };
    assert_eq!(
        rule_of(&https(Return::status().json("/a/*/b").header("ETag"))),
        None
    );
    assert!(rule_of(&https(Return::status().json("a"))).is_some());
    assert!(rule_of(&https(Return::status().header("bad header"))).is_some());
    let tls = |ret: Return| {
        one(
            fields(),
            Operation::tls("op", Destination::new("imap.example.com", 993))
                .then(Receive::until(["\r\n"]))
                .then(ret),
        )
    };
    assert_eq!(rule_of(&tls(Return::relay([r"a[0-9]+ NOOP\r\n"]))), None);
    assert!(rule_of(&tls(Return::relay(Vec::<String>::new()))).is_some());
    assert!(rule_of(&tls(Return::relay(["(unclosed"]))).is_some());
}

#[test]
fn the_summary_flags_what_widens_the_caller() {
    let policy = one(
        vec![FieldSpec::secret("token")],
        Operation::https("op", api())
            .then(Send::caller(
                CallerRequest::new([Method::Get])
                    .paths(["/v1/**"])
                    .query(QueryRule::any("q"))
                    .encoded_percent(true),
            ))
            .then(Return::status().body()),
    );
    let summary = policy.summary().join("\n");
    assert!(
        summary.contains("operation op: HTTPS to api.example.com:443"),
        "{summary}"
    );
    assert!(
        summary.contains("! the caller's path may hold %25"),
        "{summary}"
    );
    assert!(
        summary.contains("! some query parameters take any value"),
        "{summary}"
    );
    assert!(summary.contains('!'), "{summary}");
    let local = one(
        vec![FieldSpec::secret("key")],
        Operation::derive("op", "{{ hex(hmac_sha256(key, $input)) }}").input(Input::any()),
    );
    let summary = local.summary().join("\n");
    assert!(summary.contains("operation op: no connection"), "{summary}");
    assert!(
        summary.contains("! the caller's input is any bytes"),
        "{summary}"
    );
}

fn code_login(challenge: Challenge) -> Operation {
    Operation::https("op", api())
        .then(Send::fixed(Method::Post, "/login").inject(Injection::body("pw={{token}}")))
        .then(challenge)
        .then(Send::fixed(Method::Post, "/otp").inject(Injection::body("otp={{otp}}")))
        .then(Return::status())
}

fn sms() -> Challenge {
    Challenge::code(ChallengeKind::Sms, "The code your bank texts you", "otp")
}

fn status_poll() -> Poll {
    Poll {
        send: Send::fixed(Method::Get, "/status"),
        success: Condition {
            source: Source::json("/state"),
            one_of: vec!["approved".into()],
        },
        failure: None,
        every_ms: 2000,
    }
}

#[test]
fn awaits_are_checked_at_signing() {
    let fields = || vec![FieldSpec::secret("token")];
    let refused = |operation: Operation| rule_of(&one(fields(), operation)).is_some();
    assert_eq!(rule_of(&one(fields(), code_login(sms()))), None);
    // The code is a secret temporary value: the analysis knows it.
    let policy = one(fields(), code_login(sms()));
    let operation = policy.operation("op").expect("op");
    assert!(policy.is_secret_in(operation, "otp"));

    let mut no_into = sms();
    no_into.into = None;
    let mut taken = sms();
    taken.into = Some("token".into());
    let mut bad_pattern = sms();
    bad_pattern.pattern = Some("(".into());
    let mut with_poll = sms();
    with_poll.poll = Some(status_poll());
    for (what, challenge) in [
        ("a code without into", no_into),
        ("into a name already used", taken),
        ("a pattern that does not compile", bad_pattern),
        ("a code that polls", with_poll),
        (
            "an empty hint",
            Challenge::code(ChallengeKind::App, "", "otp"),
        ),
        (
            "a hint with a control character",
            Challenge::code(ChallengeKind::App, "a\nb", "otp"),
        ),
        ("waiting too long", sms().waiting_at_most(300_001)),
        ("waiting too short", sms().waiting_at_most(999)),
    ] {
        assert!(refused(code_login(challenge)), "{what}");
    }

    // External: polled with a fixed HTTPS request, no more often than once a second.
    let external = |poll: Poll| {
        Operation::https("op", api())
            .then(Send::fixed(Method::Post, "/start").inject(Injection::body("{{token}}")))
            .then(Challenge::external("Approve in the app", poll))
            .then(Return::status())
    };
    assert_eq!(rule_of(&one(fields(), external(status_poll()))), None);
    let mut fast = status_poll();
    fast.every_ms = 999;
    let mut from_caller = status_poll();
    from_caller.send = caller_send();
    let mut no_values = status_poll();
    no_values.success.one_of.clear();
    for (what, poll) in [
        ("polled too often", fast),
        ("a poll of the caller's request", from_caller),
        ("a condition with no value", no_values),
    ] {
        assert!(refused(external(poll)), "{what}");
    }
    let mut external_into = Challenge::external("Approve in the app", status_poll());
    external_into.into = Some("otp".into());
    assert!(refused(
        Operation::https("op", api())
            .then(Send::fixed(Method::Get, "/start"))
            .then(external_into)
            .then(Return::status())
    ));

    // Not on TLS; at most four per operation.
    assert!(refused(
        Operation::tls("op", Destination::new("imap.example.com", 993))
            .then(sms())
            .then(Send::write("a1 {{otp}}\r\n"))
            .then(Return::status())
    ));
    let mut many = Operation::https("op", api()).then(Send::fixed(Method::Get, "/a"));
    for i in 0..=MAX_AWAITS {
        many = many.then(Challenge::code(
            ChallengeKind::Sms,
            "code",
            &format!("otp{i}"),
        ));
    }
    assert!(refused(many.then(Return::status())));

    // JSON: the step reads and writes back, and junk is refused.
    let json = r#"{"do": "await", "challenge": {"kind": "3ds", "hint": "Confirm in your bank app", "into": "otp"}}"#;
    let step: Step = serde_json::from_str(json).expect("an await");
    assert_eq!(
        serde_json::from_str::<Step>(&serde_json::to_string(&step).expect("json")).expect("again"),
        step
    );
    let junk = json.replace(r#""into": "otp""#, r#""into": "otp", "junk": 1"#);
    assert!(serde_json::from_str::<Step>(&junk).is_err());
}

fn charge(payment: Payment, max: &str) -> Operation {
    let contract = CallerRequest::new([Method::Post])
        .paths(["/v1/charge"])
        .query(QueryRule {
            name: "amount".into(),
            required: true,
            min: Some("0".into()),
            max: Some(max.into()),
            ..QueryRule::default()
        });
    Operation::https("op", api())
        .then(Send::caller(contract).inject(Injection::header("Authorization", "Bearer {{token}}")))
        .then(Return::status())
        .pays(payment)
}

fn eur(amount: AmountSource) -> Payment {
    Payment {
        amount,
        currency: "EUR".into(),
        exponent: 2,
    }
}

#[test]
fn a_payment_reads_its_amount_only_from_a_checked_number() {
    let fields = || vec![FieldSpec::secret("token")];
    let query = || AmountSource::Query {
        name: "amount".into(),
    };
    assert_eq!(
        rule_of(&one(fields(), charge(eur(query()), "1000000"))),
        None
    );
    let fixed = |value: &str| AmountSource::Fixed {
        value: value.into(),
    };
    assert_eq!(
        rule_of(&one(fields(), charge(eur(fixed("500")), "1"))),
        None
    );
    let mut lower = eur(query());
    lower.currency = "eur".into();
    let mut wide = eur(query());
    wide.exponent = 9;
    for (what, operation) in [
        (
            "a parameter no rule bounds",
            charge(
                eur(AmountSource::Query {
                    name: "other".into(),
                }),
                "1000",
            ),
        ),
        (
            "a bound above 10^18",
            charge(eur(query()), "10000000000000000000"),
        ),
        (
            "a fixed amount with a fraction",
            charge(eur(fixed("1.5")), "1"),
        ),
        ("a currency in lower case", charge(lower, "1000")),
        ("more than 8 decimals", charge(wide, "1000")),
        (
            "an input amount without an input",
            charge(
                eur(AmountSource::Input {
                    pointer: "/amount".into(),
                }),
                "1000",
            ),
        ),
    ] {
        assert!(rule_of(&one(fields(), operation)).is_some(), "{what}");
    }

    // From the checked JSON input of a derivation: a required, bounded number.
    let input = |member: &str| -> Input {
        serde_json::from_str(&format!(r#"{{"json": {{"members": [{member}]}}}}"#)).expect("input")
    };
    let derive = |member: &str| {
        Operation::derive("op", "{{ hex(hmac_sha256(token, $input)) }}")
            .input(input(member))
            .pays(eur(AmountSource::Input {
                pointer: "/amount".into(),
            }))
    };
    let good = r#"{"pointer": "/amount", "type": "number", "min": "0", "max": "100000"}"#;
    assert_eq!(rule_of(&one(fields(), derive(good))), None);
    for bad in [
        r#"{"pointer": "/amount", "type": "number", "min": "0", "max": "100000", "optional": true}"#,
        r#"{"pointer": "/amount", "type": "string", "min": "0", "max": "100000"}"#,
        r#"{"pointer": "/amount", "type": "number", "max": "100000"}"#,
    ] {
        assert!(rule_of(&one(fields(), derive(bad))).is_some(), "{bad}");
    }
}

fn session_policy(rule: SessionRule, login: Operation) -> Policy {
    Policy {
        item: None,
        fields: vec![
            FieldSpec::secret("password"),
            FieldSpec::secret("session").optional().session(rule),
            FieldSpec::public("session_expires").optional(),
        ],
        callers: vec![caller()],
        operations: vec![
            Operation::https("op", api())
                .then(
                    Send::fixed(Method::Get, "/data")
                        .inject(Injection::header("Cookie", "sid={{session}}")),
                )
                .then(Return::status()),
            login,
        ],
    }
}

fn login() -> Operation {
    Operation::https("login", api())
        .then(Send::fixed(Method::Post, "/login").inject(Injection::body("pw={{password}}")))
        .then(
            Receive::response()
                .capture(Capture::new(Source::cookie("sid"), Store::field("session"))),
        )
        .then(Return::status())
}

fn hourly(renew: Renew) -> SessionRule {
    SessionRule {
        lifetime_ms: 3_600_000,
        expires: "session_expires".into(),
        renew,
    }
}

#[test]
fn sessions_are_checked_at_signing() {
    let by_login = || Renew::Operation {
        name: "login".into(),
    };
    assert_eq!(rule_of(&session_policy(hourly(by_login()), login())), None);
    assert_eq!(
        rule_of(&session_policy(hourly(Renew::Owner {}), login())),
        None
    );
    let mut forever = hourly(by_login());
    forever.lifetime_ms = MAX_SESSION_MS + 1;
    let mut nowhere = hourly(by_login());
    nowhere.expires = "missing".into();
    let mut into_secret = hourly(by_login());
    into_secret.expires = "password".into();
    for (what, rule) in [
        ("a lifetime above 30 days", forever),
        ("an expiry field the policy lacks", nowhere),
        ("an expiry into a secret field", into_secret),
        (
            "a renewal by an operation the policy lacks",
            hourly(Renew::Operation {
                name: "absent".into(),
            }),
        ),
    ] {
        assert!(rule_of(&session_policy(rule, login())).is_some(), "{what}");
    }
    // The renewal fills the session and does not read it.
    let reads_it = Operation::https("login", api())
        .then(Send::fixed(Method::Post, "/login").inject(Injection::body("{{session}}")))
        .then(
            Receive::response()
                .capture(Capture::new(Source::cookie("sid"), Store::field("session"))),
        )
        .then(Return::status());
    assert!(rule_of(&session_policy(hourly(by_login()), reads_it)).is_some());
    let fills_nothing = Operation::https("login", api())
        .then(Send::fixed(Method::Post, "/login").inject(Injection::body("pw={{password}}")))
        .then(Return::status());
    assert!(rule_of(&session_policy(hourly(by_login()), fills_nothing)).is_some());
    // A session is a secret field.
    let mut public = session_policy(hourly(by_login()), login());
    public.fields[1].secret = false;
    assert!(rule_of(&public).is_some());
}

#[test]
fn payments_approvals_and_sessions_widen_when_loosened() {
    let fields = || vec![FieldSpec::secret("token")];
    let query = || AmountSource::Query {
        name: "amount".into(),
    };
    let narrow = one(fields(), charge(eur(query()), "1000").approved_each_time());
    let wider = |policy: &Policy| {
        summary::summarize(policy, Some(&narrow))
            .flags
            .iter()
            .any(|f| f.code == summary::FlagCode::Wider)
    };
    assert!(!wider(&narrow));
    let no_approval = one(fields(), charge(eur(query()), "1000"));
    assert!(wider(&no_approval));
    let mut yen = eur(query());
    yen.currency = "JPY".into();
    let other_currency = one(fields(), charge(yen, "1000").approved_each_time());
    assert!(wider(&other_currency));
    let summary = narrow.summary().join("\n");
    assert!(summary.contains("EUR"), "{summary}");
    assert!(summary.contains("approval"), "{summary}");
}
