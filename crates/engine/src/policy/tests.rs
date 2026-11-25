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
