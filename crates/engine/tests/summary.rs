//! `summarize`: where each secret can go and in what form, what returns to the caller, and
//! each risk flag, including what a new version widens.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use engine::item::ItemBinding;
use engine::keys::CallerKey;
use engine::policy::summary::{FlagCode, Form, Place, Summary};
use engine::policy::{
    Caller, CallerRequest, Destination, FieldSpec, Injection, Input, Method, Operation, Policy,
    QueryRule, RawInput, Receive, Return, Send, summarize,
};

fn caller(ops: &[&str]) -> Caller {
    Caller::new(
        "agent",
        CallerKey::from_bytes(&mut [4u8; 32]).public(),
        ops.iter().copied(),
    )
}

fn codes(summary: &Summary) -> Vec<FlagCode> {
    summary.flags.iter().map(|f| f.code).collect()
}

fn has(summary: &Summary, code: FlagCode) -> bool {
    codes(summary).contains(&code)
}

fn https(host: &str) -> Place {
    Place {
        scheme: "https".into(),
        host: host.into(),
        port: 443,
    }
}

/// An API policy: a bearer token in a header, a caller contract with a query allow-list.
fn api() -> Policy {
    Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_field(FieldSpec::public("account"))
        .with_operation(
            Operation::https("call", Destination::https("api.example"))
                .then(
                    Send::caller(
                        CallerRequest::new([Method::Get])
                            .paths(["/v1/items", "/v1/items/*"])
                            .headers(["Accept"])
                            .query(QueryRule {
                                name: "page".into(),
                                required: false,
                                equals: None,
                                one_of: Vec::new(),
                                pattern: None,
                                min: Some("1".into()),
                                max: Some("100".into()),
                            }),
                    )
                    .inject(Injection::header("Authorization", "Bearer {{token}}")),
                )
                .then(Return::status().header("ETag").json("/items/*/id")),
        )
        .with_caller(caller(&["call"]))
}

#[test]
fn each_secret_lists_where_it_goes_and_in_what_form() {
    let s = summarize(&api(), None);
    assert!(s.flags.is_empty(), "{:?}", s.flags);
    assert_eq!(s.secrets.len(), 1);
    let token = &s.secrets[0];
    assert_eq!(token.field, "token");
    assert_eq!(token.uses.len(), 1);
    assert_eq!(
        token.uses[0].form,
        Form::Header {
            name: "Authorization".into()
        }
    );
    assert_eq!(token.uses[0].destinations, [https("api.example")]);
    let op = &s.operations[0];
    assert_eq!(op.connection, "https");
    assert_eq!(op.destinations, [https("api.example")]);
    let request = &op.requests[0];
    assert_eq!(request.from, "caller");
    assert_eq!(request.methods, ["GET"]);
    assert_eq!(request.paths, ["/v1/items", "/v1/items/*"]);
    assert_eq!(request.headers, ["Accept"]);
    assert_eq!(request.query[0].name, "page");
    assert_eq!(request.injects, ["header Authorization"]);
    assert!(op.returns.status);
    assert_eq!(op.returns.headers, ["ETag"]);
    assert_eq!(op.returns.body, "json");
    assert_eq!(op.returns.json, ["/items/*/id"]);
    assert_eq!(s.callers[0].operations, ["call"]);
    assert!(!s.lines.is_empty());
    // It is JSON, as the client hands it out.
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["secrets"][0]["uses"][0]["form"]["in"], "header");
}

#[test]
fn uses_are_followed_through_computed_values_identities_and_streams() {
    let policy = Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_field(FieldSpec::secret("cert"))
        .with_field(FieldSpec::secret("password"))
        .with_operation(
            Operation::https("sign", Destination::https("api.example"))
                .identity("{{cert}}", "{{key}}")
                .compute("mac", "{{ hex(hmac_sha256(key, $unix)) }}")
                .then(
                    Send::fixed(Method::Post, "/v1/{id}")
                        .inject(Injection::query("sig", "{{mac}}"))
                        .inject(Injection::path_param("id", "{{mac}}")),
                )
                .then(Return::status()),
        )
        .with_operation(
            Operation::tls("mail", Destination::new("mail.example", 993))
                .then(Send::write("a1 LOGIN me {{password}}\r\n"))
                .then(Receive::until(["a1 OK"]))
                .then(Return::status()),
        )
        .with_caller(caller(&["sign", "mail"]));
    policy.validate().unwrap();
    let s = summarize(&policy, None);
    let forms = |field: &str| -> Vec<Form> {
        s.secrets
            .iter()
            .find(|x| x.field == field)
            .unwrap()
            .uses
            .iter()
            .map(|u| u.form.clone())
            .collect()
    };
    assert_eq!(
        forms("key"),
        [
            Form::Identity,
            Form::Query { name: "sig".into() },
            Form::PathParam { name: "id".into() }
        ]
    );
    assert_eq!(forms("cert"), [Form::Identity]);
    assert_eq!(forms("password"), [Form::StreamSend]);
    let mail = s.secrets.iter().find(|x| x.field == "password").unwrap();
    assert_eq!(
        mail.uses[0].destinations,
        [Place {
            scheme: "tls".into(),
            host: "mail.example".into(),
            port: 993
        }]
    );
    assert!(has(&s, FlagCode::ClientCertificate));
}

#[test]
fn the_risk_flags() {
    // A wildcard, the whole body, any query value, %25 and method overrides.
    let wide = Policy::new()
        .with_field(FieldSpec::secret("token"))
        .with_operation(
            Operation::https("call", Destination::https("*.api.example"))
                .then(
                    Send::caller(
                        CallerRequest::new([Method::Get])
                            .paths(["/v1/**"])
                            .query(QueryRule {
                                name: "q".into(),
                                required: false,
                                equals: None,
                                one_of: Vec::new(),
                                pattern: None,
                                min: None,
                                max: None,
                            })
                            .encoded_percent(true)
                            .override_params(true),
                    )
                    .inject(Injection::header("Authorization", "Bearer {{token}}")),
                )
                .then(Return::status().body()),
        )
        .with_caller(caller(&["call"]));
    wide.validate().unwrap();
    let s = summarize(&wide, None);
    for code in [
        FlagCode::Wildcard,
        FlagCode::ResponseAll,
        FlagCode::QueryAny,
        FlagCode::EncodedPercent,
        FlagCode::OverrideParams,
    ] {
        assert!(has(&s, code), "{code:?}: {:?}", s.flags);
    }

    // A derivation of any bytes, whose output is an encryption: not one-way.
    let oracle = Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(
            Operation::derive(
                "seal",
                "{{ b64(aes_gcm_encrypt(key, hexdecode(\"000000000000000000000000\"), $input)) }}",
            )
            .input(Input::Raw(RawInput {
                max_len: None,
                pattern: None,
            })),
        )
        .with_operation(Operation::derive(
            "mac",
            "{{ hex(hmac_sha256(key, \"aes_gcm_encrypt(\")) }}",
        ))
        .with_caller(caller(&["seal", "mac"]));
    oracle.validate().unwrap();
    let s = summarize(&oracle, None);
    assert!(has(&s, FlagCode::RawInput));
    let reversible: Vec<&str> = s
        .flags
        .iter()
        .filter(|f| f.code == FlagCode::DeriveReversible)
        .map(|f| f.at.as_str())
        .collect();
    // The name of a function inside a string literal is not a call.
    assert_eq!(reversible, ["operation seal"]);
    let key = &s.secrets[0];
    assert_eq!(key.uses[0].form, Form::Output { one_way: false });
    assert_eq!(key.uses[1].form, Form::Output { one_way: true });
    // Through a computed value too.
    let computed = Policy::new()
        .with_field(FieldSpec::secret("key"))
        .with_operation(
            Operation::local("seal")
                .compute(
                    "box",
                    "{{ aes_gcm_encrypt(key, hexdecode(\"000000000000000000000000\"), \"x\") }}",
                )
                .then(Return::output("{{ b64(box) }}")),
        )
        .with_caller(caller(&["seal"]));
    computed.validate().unwrap();
    assert!(has(&summarize(&computed, None), FlagCode::DeriveReversible));

    // A relay, and a broad one.
    let relay = Policy::new()
        .with_field(FieldSpec::secret("password"))
        .with_operation(
            Operation::tls("mail", Destination::new("mail.example", 993))
                .then(Send::write("a1 LOGIN me {{password}}\r\n"))
                .then(Receive::until(["a1 OK"]))
                .then(Return::relay(["a[0-9]+ NOOP\\r\\n", "a[0-9]+ .*\\r\\n"])),
        )
        .with_caller(caller(&["mail"]));
    relay.validate().unwrap();
    let s = summarize(&relay, None);
    assert!(has(&s, FlagCode::Relay));
    let broad: Vec<&str> = s
        .flags
        .iter()
        .filter(|f| f.code == FlagCode::RelayBroad)
        .map(|f| f.detail.as_str())
        .collect();
    assert_eq!(broad.len(), 1, "{broad:?}");
    assert!(broad[0].contains(".*"));
}

fn oauth(api_host: &str) -> Policy {
    Policy::new()
        .with_item(ItemBinding::reviewed("oauth").pin("provider", "https://auth.example"))
        .with_field(FieldSpec::public("provider"))
        .with_field(FieldSpec::public("client_id"))
        .with_field(FieldSpec::secret("access_token").optional())
        .with_operation(
            Operation::https("call", Destination::https(api_host))
                .then(
                    Send::caller(CallerRequest::new([Method::Get]).paths(["/v1/me"])).inject(
                        Injection::header("Authorization", "Bearer {{access_token}}"),
                    ),
                )
                .then(Return::status().json("/name")),
        )
        .with_caller(caller(&["call"]))
}

#[test]
fn a_destination_outside_the_items_origin_is_flagged() {
    let inside = oauth("api.auth.example");
    inside.validate().unwrap();
    let s = summarize(&inside, None);
    assert!(!has(&s, FlagCode::OutsideOrigin), "{:?}", s.flags);
    assert_eq!(
        s.item.as_ref().unwrap().origin.as_deref(),
        Some("https://auth.example")
    );
    // The secret's disclosure in the kind is part of the summary.
    assert!(s.secrets[0].disclosure.is_some());
    for host in ["api.other.example", "auth.example.evil", "xauth.example"] {
        let outside = oauth(host);
        outside.validate().unwrap();
        assert!(
            has(&summarize(&outside, None), FlagCode::OutsideOrigin),
            "{host}"
        );
    }
}

#[test]
fn plain_text_signoffs_are_flagged() {
    let login = Policy::new()
        .with_item(
            ItemBinding::reviewed("login")
                .pin("origin", "http://intranet.example")
                .sign_off("plain_http"),
        )
        .with_field(FieldSpec::public("origin"))
        .with_field(FieldSpec::secret("username"))
        .with_field(FieldSpec::guessable("password"))
        .with_operation(
            Operation::https("login", Destination::new("intranet.example", 80))
                .then(
                    Send::fixed(Method::Post, "/login")
                        .inject(Injection::body("{{username}}:{{password}}")),
                )
                .then(Return::status()),
        )
        .with_caller(caller(&["login"]));
    login.validate().unwrap();
    assert!(has(&summarize(&login, None), FlagCode::PlainHttp));

    let database = Policy::new()
        .with_item(
            ItemBinding::reviewed("database")
                .pin("host", "db.example")
                .pin("port", "6380")
                .pin("tls", "disable")
                .sign_off("plain"),
        )
        .with_field(FieldSpec::public("engine"))
        .with_field(FieldSpec::public("host"))
        .with_field(FieldSpec::public("port"))
        .with_field(FieldSpec::public("user"))
        .with_field(FieldSpec::guessable("password"))
        .with_field(FieldSpec::public("tls"))
        .with_operation(
            Operation::tls("auth", Destination::new("db.example", 6380))
                .then(Send::write("AUTH {{user}} {{password}}\r\n"))
                .then(Return::status()),
        )
        .with_caller(caller(&["auth"]));
    database.validate().unwrap();
    assert!(has(&summarize(&database, None), FlagCode::PlainSignoff));
}

fn wider(previous: &Policy, current: &Policy) -> Vec<String> {
    summarize(current, Some(previous))
        .flags
        .into_iter()
        .filter(|f| f.code == FlagCode::Wider)
        .map(|f| f.detail)
        .collect()
}

#[test]
fn the_same_policy_is_not_wider() {
    let s = summarize(&api(), Some(&api()));
    assert!(s.flags.is_empty(), "{:?}", s.flags);
    assert!(s.changes.is_empty());
}

#[test]
fn every_widening_against_the_previous_version_is_flagged() {
    type Edit = Box<dyn Fn(&mut Policy)>;
    fn contract(p: &mut Policy) -> &mut CallerRequest {
        match &mut p.operations[0].steps[1] {
            engine::policy::Step::Send(send) => match send.request.as_mut().unwrap() {
                engine::policy::StepRequest::Caller(c) => c,
                _ => panic!("caller"),
            },
            _ => panic!("send"),
        }
    }
    let cases: Vec<(&str, Edit)> = vec![
        (
            "new destination",
            Box::new(|p| {
                p.operations[0] = p.operations[0]
                    .clone()
                    .destination(Destination::https("collect.example"));
            }),
        ),
        (
            "may now use POST",
            Box::new(|p| contract(p).methods.push(Method::Post)),
        ),
        (
            "may now reach /v1/**",
            Box::new(|p| contract(p).paths.push("/v1/**".into())),
        ),
        (
            "may now set header X-Debug",
            Box::new(|p| contract(p).headers.push("X-Debug".into())),
        ),
        (
            "query parameter page is new or looser",
            Box::new(|p| contract(p).query[0].max = Some("1000".into())),
        ),
        (
            "path may now hold %25",
            Box::new(|p| contract(p).encoded_percent = true),
        ),
        (
            "a value now also goes in query t",
            Box::new(|p| {
                if let engine::policy::Step::Send(send) = &mut p.operations[0].steps[1] {
                    send.inject.push(Injection::query("t", "{{token}}"));
                }
            }),
        ),
        (
            "more of the response body goes back",
            Box::new(|p| {
                p.operations[0].steps[2] = engine::policy::Step::Return(Return::status().body());
            }),
        ),
        (
            "the JSON member /items/*/secret now goes back",
            Box::new(|p| {
                p.operations[0].steps[2] = engine::policy::Step::Return(
                    Return::status()
                        .header("ETag")
                        .json("/items/*/id")
                        .json("/items/*/secret"),
                );
            }),
        ),
        (
            "the response header set-cookie now goes back",
            Box::new(|p| {
                p.operations[0].steps[2] = engine::policy::Step::Return(
                    Return::status()
                        .header("ETag")
                        .header("Set-Cookie")
                        .json("/items/*/id"),
                );
            }),
        ),
        (
            "operation other added",
            Box::new(|p| {
                p.operations
                    .push(Operation::derive("other", "{{ len(token) }}"));
            }),
        ),
        (
            "caller second added",
            Box::new(|p| {
                p.callers.push(Caller::new(
                    "second",
                    CallerKey::generate().public(),
                    ["call"],
                ));
            }),
        ),
        (
            "caller agent: another key",
            Box::new(|p| p.callers[0].key = CallerKey::generate().public()),
        ),
        (
            "field account: now public",
            Box::new(|p| p.fields[1].secret = false),
        ),
    ];
    for (expected, edit) in cases {
        let mut previous = api();
        if expected.starts_with("field account") {
            previous.fields[1].secret = true;
        }
        let mut current = previous.clone();
        edit(&mut current);
        let found = wider(&previous, &current);
        assert!(
            found.iter().any(|w| w.contains(expected)),
            "{expected}: {found:?}"
        );
    }
    // A new destination is also flagged as first seen.
    let mut current = api();
    current.operations[0] = current.operations[0]
        .clone()
        .destination(Destination::https("collect.example"));
    assert!(has(
        &summarize(&current, Some(&api())),
        FlagCode::NewDestination
    ));
}

#[test]
fn rate_limits_and_sign_offs_widen_too() {
    let mut limited = api();
    limited.callers[0] = limited.callers[0].clone().limit(10, 60_000);
    let mut none = limited.clone();
    none.callers[0].limit = None;
    assert!(
        wider(&limited, &none)
            .iter()
            .any(|w| w.contains("no rate limit"))
    );
    let mut faster = limited.clone();
    faster.callers[0] = faster.callers[0].clone().limit(10, 1_000);
    assert!(
        wider(&limited, &faster)
            .iter()
            .any(|w| w.contains("higher rate limit"))
    );
    let mut slower = limited.clone();
    slower.callers[0] = slower.callers[0].clone().limit(5, 60_000);
    assert!(wider(&limited, &slower).is_empty());

    let before = oauth("api.auth.example");
    let mut after = before.clone();
    after.item = None;
    assert!(
        wider(&before, &after)
            .iter()
            .any(|w| w.contains("no longer bound"))
    );
}

#[test]
fn narrowing_is_a_change_not_a_widening() {
    let mut previous = api();
    previous
        .operations
        .push(Operation::derive("other", "{{ len(token) }}"));
    previous.callers[0].operations.push("other".into());
    let s = summarize(&api(), Some(&previous));
    assert!(
        s.flags.iter().all(|f| f.code != FlagCode::Wider),
        "{:?}",
        s.flags
    );
    assert!(s.changes.iter().any(|c| c == "operation other removed"));
}
