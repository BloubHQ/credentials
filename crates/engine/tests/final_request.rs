//! Signatures over the request as it is sent (`docs/policy.md`, Injection order): a template
//! of an injection reads the request with every other injection in place (path parameters
//! filled, query parameters appended, headers set, the body replaced), never its own target.
//! The injections render in dependency order and a cycle is refused at signing; a value the
//! policy injects carries its taint into every variable that holds it.
//!
//! The schemes whose signatures could not cover what the policy fills run again here: RFC
//! 9421 appendix B.2.6 and B.2.5 byte for byte with the covered headers and the query set by
//! the policy, and a ring-verified signature over an injected query parameter, header and
//! body; AWS Signature Version 4 over an injected path segment (and presigned, over injected
//! query parameters), verified by a signer written in the test; RFC 5849 section 1.2 byte for
//! byte with every `oauth_*` parameter injected into the query, and a signature over an
//! injected form parameter verified from the wire; the Hawk specification's MAC byte for byte
//! with its query and `ext` injected.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Clock, Node, Outcome, Response};
use engine::policy::summary::Form;
use engine::policy::{Caller, Destination, FieldSpec, Method, Operation, Policy, summarize};
use engine::record::Record;
use engine::request::Request;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde_json::{Value, json};
use sha2::Digest as _;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

/// Rule 2 of the analysis (`docs/policy.md`, The analysis).
const RULE_2: &str = "a secret and a chosen value meet in a function that compares or cuts them";
const CYCLE: &str = "injections read each other's components in a cycle";
const OWN: &str = "a template reads the header or query parameter its own injection sets";

/// The Ed25519 key `test-key-ed25519` of RFC 9421 appendix B.1.4 (PKCS#8 PEM).
const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n";
/// Its public key, RFC 9421 appendix B.1.4 (SubjectPublicKeyInfo, base64).
const ED25519_PUBLIC_SPKI: &str = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
/// The shared key `test-shared-secret` of RFC 9421 appendix B.1.5 (base64).
const HMAC_SHARED: &str =
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==";

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(0) };
}

struct TestClock;

impl TestClock {
    fn at(ms: u64) -> Self {
        TIME.with(|t| t.set(ms));
        TestClock
    }
}

fn now() -> u64 {
    TIME.with(Cell::get)
}

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        now()
    }
}

/// A fake server: records each request and answers 200, with the value of the request header
/// `echo` as its body when one is named (a server that reflects what it was sent).
#[derive(Default)]
struct FakeServer {
    echo: Option<&'static str>,
    sent: Vec<Vec<u8>>,
}

impl FakeServer {
    fn request(&self, n: usize) -> Sent {
        parse(&self.sent[n])
    }
}

impl Transport for FakeServer {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        let body = self
            .echo
            .map(|name| parse(wire).field(name))
            .unwrap_or_default();
        Ok(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes())
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        Err(Error::transport(TransportKind::Unsupported, false))
    }
}

/// One request as the server read it.
struct Sent {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Sent {
    /// A header as RFC 9421 section 2.1 reads a field: the value without leading and
    /// trailing whitespace; empty when absent.
    fn field(&self, name: &str) -> String {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim_matches([' ', '\t']).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn path(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }

    fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    /// The header names in the order they were sent.
    fn names(&self) -> Vec<&str> {
        self.headers.iter().map(|(n, _)| n.as_str()).collect()
    }
}

fn parse(wire: &[u8]) -> Sent {
    let split = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&wire[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap().split(' ');
    let method = request_line.next().unwrap().to_string();
    let target = request_line.next().unwrap().to_string();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_string(), value.to_string())
        })
        .collect();
    Sent {
        method,
        target,
        headers,
        body: wire[split + 4..].to_vec(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 percent-encoding of everything but the unreserved characters, written here.
fn rfc3986(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// `application/x-www-form-urlencoded` decoding (`+` is a space), written here.
fn form_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// The pairs of form-encoded lists, decoded, encoded again (RFC 3986), sorted and joined:
/// RFC 5849 section 3.4.1.3.2 and the canonical query of AWS Signature Version 4.
fn normalized(lists: &[&str]) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for list in lists {
        for pair in list.split('&').filter(|p| !p.is_empty()) {
            let (n, v) = pair.split_once('=').unwrap_or((pair, ""));
            pairs.push((rfc3986(&form_decode(n)), rfc3986(&form_decode(v))));
        }
    }
    pairs.sort();
    pairs
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The JSON text of the operation `name` in `docs/policy.md`.
fn doc(name: &str) -> Operation {
    let text = POLICY_MD.replace("\r\n", "\n");
    let mut rest = text.as_str();
    while let Some(start) = rest.find("```json\n") {
        let body = &rest[start + 8..];
        let end = body.find("```").unwrap();
        let value = serde_json::from_str::<Value>(&body[..end]).unwrap_or(Value::Null);
        if value.get("steps").is_some() && value.get("name").and_then(Value::as_str) == Some(name) {
            return operation(value);
        }
        rest = &body[end + 3..];
    }
    panic!("docs/policy.md shows no operation {name}")
}

fn operation(value: Value) -> Operation {
    let text = value.to_string();
    serde_json::from_value(value).unwrap_or_else(|e| panic!("{e}\n{text}"))
}

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

/// A policy of `fields` (and an optional public `label`, so there is always one) and
/// `operations`, all open to one caller.
fn policy(fields: Vec<FieldSpec>, operations: Vec<Operation>) -> Policy {
    let names: Vec<String> = operations.iter().map(|o| o.name().to_string()).collect();
    let mut fields = fields;
    fields.push(FieldSpec::public("label").optional());
    Policy {
        item: None,
        fields,
        callers: vec![Caller::new("app", caller_key().public(), names)],
        operations,
    }
}

/// Signs the policy; the rule it breaks when signing refuses it.
fn refused(fields: Vec<FieldSpec>, operations: Vec<Operation>) -> &'static str {
    match DeviceKey::generate().sign_policy(policy(fields, operations)) {
        Err(Error::PolicyInvalid { rule, .. }) => rule,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("signed"),
    }
}

/// True when the policy signs.
fn signs(fields: Vec<FieldSpec>, operations: Vec<Operation>) -> bool {
    DeviceKey::generate()
        .sign_policy(policy(fields, operations))
        .is_ok()
}

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

struct Setup<'c> {
    node: TestNode<'c>,
    record: Record,
}

/// A node that holds one record of `fields` with `values` under a signed policy of
/// `operations`; signing runs the template analysis and the order of the injections.
fn setup<'c>(
    clock: &'c TestClock,
    fields: Vec<FieldSpec>,
    operations: Vec<Operation>,
    values: &[(&str, &[u8])],
) -> Setup<'c> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device
        .sign_policy(policy(fields, operations))
        .unwrap_or_else(|e| panic!("the policy does not sign: {e}"));
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
        allow_successor: true,
        expires_ms: now() + DAY,
        issued_ms: now(),
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

fn call(
    s: &Setup<'_>,
    operation: &str,
    request: Option<&Request>,
    server: &mut FakeServer,
) -> Outcome<Response> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            operation,
            &Payload::Http(request),
            now(),
        )
        .unwrap();
    s.node.http(&s.record, operation, &auth, request, server)
}

fn request(
    method: Method,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Request {
    Request {
        method,
        destination: Destination::new(host, port),
        path: path.into(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        body: body.to_vec(),
    }
}

/// An injection of `template` into a header.
fn header(name: &str, template: &str) -> Value {
    json!({"target": {"kind": "header", "name": name}, "template": template})
}

/// An injection of `template` into a query parameter.
fn query(name: &str, template: &str) -> Value {
    json!({"target": {"kind": "query", "name": name}, "template": template})
}

/// An injection of `template` into a path parameter.
fn path_param(name: &str, template: &str) -> Value {
    json!({"target": {"kind": "path_param", "name": name}, "template": template})
}

/// An injection of `template` as the body.
fn body(template: &str) -> Value {
    json!({"target": {"kind": "body"}, "template": template})
}

/// An HTTPS operation to `host:port` whose `send` takes the caller's request under
/// `contract` with the injections `inject`, and returns the response body.
fn caller_op(name: &str, host: &str, port: u16, contract: Value, inject: Vec<Value>) -> Operation {
    let mut contract = contract;
    contract["from"] = json!("caller");
    operation(json!({"name": name, "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": host, "port": port}]},
        {"do": "send", "request": contract, "inject": inject},
        {"do": "return", "response": {"body": "all"}}
    ]}))
}

/// [`caller_op`] to `example.com` with a caller POST or GET to `/v1/{p}` when the
/// injections fill `p`, else to `/v1/x`.
fn op(inject: Vec<Value>) -> Operation {
    let path = if inject.iter().any(|i| i["target"]["kind"] == "path_param") {
        "/v1/{p}"
    } else {
        "/v1/x"
    };
    caller_op(
        "o",
        "example.com",
        443,
        json!({"methods": ["GET", "POST"], "paths": [path], "query": [{"name": "x"}]}),
        inject,
    )
}

// ---------------------------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------------------------

/// Each template reads the request as it is sent but for its own target: a query parameter
/// that reads `$query` sees the caller's query and the injected parameters before it in
/// dependency order, not itself; a header that reads `$query` sees both; a path parameter
/// that reads `$path` sees the whole query and keeps its own placeholder. The values go on
/// the wire in the order the policy lists them, whatever order they render in.
#[test]
fn a_template_reads_the_request_as_sent_but_its_own_target() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![],
        vec![op(vec![
            header("X-Q", "{{ $query }}"),
            path_param("p", "{{ $path }}"),
            query("b", "{{ $query }}"),
            query("a", "1"),
            header("X-Uri", "{{ $target_uri }}"),
        ])],
        &[],
    );
    let mut server = FakeServer::default();
    let req = request(Method::Get, "example.com", 443, "/v1/{p}?x=0", &[], b"");
    call(&s, "o", Some(&req), &mut server).result.unwrap();
    let sent = server.request(0);
    // `b` reads the caller's `x` and the injected `a`; it renders after `a`, though listed
    // first, and goes on the wire first.
    let b = "x%3D0%26a%3D1";
    assert_eq!(sent.query(), format!("x=0&b={b}&a=1"));
    assert_eq!(sent.field("X-Q"), format!("x=0&b={b}&a=1"));
    // `p` sees the whole query and its own placeholder, as written.
    let p = sent.path().strip_prefix("/v1/").unwrap().to_string();
    assert_eq!(
        String::from_utf8(form_decode(&p)).unwrap(),
        format!("/v1/{{p}}?x=0&b={b}&a=1")
    );
    assert_eq!(
        sent.field("X-Uri"),
        format!("https://example.com{}", sent.target)
    );
    assert_eq!(sent.names()[..3], ["Host", "X-Q", "X-Uri"]);
}

/// `$body` in the body's own injection is the caller's body; anywhere else it is the body
/// as it is sent. An injected header is readable by name, in a caller request or a fixed one.
#[test]
fn body_and_injected_headers_are_read_as_sent() {
    let clock = TestClock::at(NOW);
    let fixed = operation(json!({"name": "fixed", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/token"},
         "inject": [
            header("X-Sum", r#"{{ hex(sha256($header("date") + "|" + $body)) }}"#),
            body(r#"{"at":"{{ $header("date") }}"}"#),
            header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")]},
        {"do": "return", "response": {"body": "all"}}
    ]}));
    let s = setup(
        &clock,
        vec![],
        vec![
            op(vec![
                header("X-Len", "{{ len($body) }}"),
                body(r#"{{ $body + "!" }}"#),
            ]),
            fixed,
        ],
        &[],
    );
    let mut server = FakeServer::default();
    let req = request(Method::Post, "example.com", 443, "/v1/x", &[], b"abc");
    call(&s, "o", Some(&req), &mut server).result.unwrap();
    let sent = server.request(0);
    assert_eq!(sent.body, b"abc!");
    assert_eq!(sent.field("X-Len"), "4");

    call(&s, "fixed", None, &mut server).result.unwrap();
    let sent = server.request(1);
    assert_eq!(sent.body, br#"{"at":"Tue, 20 Apr 2021 02:07:55 GMT"}"#);
    let expected = hex(&sha2::Sha256::digest(
        [b"Tue, 20 Apr 2021 02:07:55 GMT|".as_slice(), &sent.body].concat(),
    ));
    assert_eq!(sent.field("X-Sum"), expected);
}

/// Injections that read each other's components, directly or through others, have no order
/// and are refused at signing; so is a template that reads the header or query parameter it
/// sets itself. A header neither injected nor in the contract stays refused, and a fixed
/// request still has no caller headers.
#[test]
fn cycles_and_own_targets_are_refused_at_signing() {
    let cases: Vec<(Vec<Value>, &str)> = vec![
        (
            vec![
                header("A", r#"{{ $header("b") }}"#),
                header("B", r#"{{ $header("a") }}"#),
            ],
            CYCLE,
        ),
        // Each query parameter sees the other through `$query`.
        (
            vec![query("a", "{{ $query }}"), query("b", "{{ $query }}")],
            CYCLE,
        ),
        (
            vec![
                path_param("p", "{{ $query }}"),
                query("q", "{{ $pathname }}"),
            ],
            CYCLE,
        ),
        (
            vec![
                body(r#"{{ $header("x-d") }}"#),
                header("X-D", "{{ $body }}"),
            ],
            CYCLE,
        ),
        // Three long: A reads B, B reads the query, the query reads A.
        (
            vec![
                header("A", r#"{{ $header("b") }}"#),
                header("B", "{{ $target_uri }}"),
                query("q", r#"{{ $header("a") }}"#),
            ],
            CYCLE,
        ),
        (vec![header("A", r#"{{ $header("a") }}"#)], OWN),
        (vec![query("sig", r#"{{ $query_param("sig") }}"#)], OWN),
        (vec![query("sig", r#"{{ $query_param("SIG") }}"#)], OWN),
        (
            vec![header("A", r#"{{ $header("x-other") }}"#)],
            "a template reads a header the caller contract does not allow",
        ),
    ];
    for (inject, rule) in cases {
        assert_eq!(refused(vec![], vec![op(inject)]), rule);
    }
    let fixed = |inject: Vec<Value>| {
        operation(json!({"name": "o", "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "example.com", "port": 443}]},
            {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/"},
             "inject": inject},
            {"do": "return"}
        ]}))
    };
    assert_eq!(
        refused(
            vec![],
            vec![fixed(vec![header("A", r#"{{ $header("date") }}"#)])]
        ),
        "a fixed request has no caller headers or query parameters to read"
    );
    assert!(signs(
        vec![],
        vec![fixed(vec![
            header("A", r#"{{ $header("date") + $query_param("q") }}"#),
            header("Date", "x"),
            query("q", "1"),
        ])]
    ));
    // A chain is not a cycle.
    assert!(signs(
        vec![],
        vec![op(vec![
            header("A", r#"{{ $header("b") }}"#),
            header("B", r#"{{ $header("c") }}"#),
            header("C", "{{ $path }}"),
            query("q", "1"),
        ])]
    ));
}

// ---------------------------------------------------------------------------------------
// Taint
// ---------------------------------------------------------------------------------------

/// A secret the policy puts in the path or the query taints every variable that holds it:
/// the analysis applies each rule to `$path`, `$query`, `$target_uri` and `$query_param`
/// exactly as to the secret written there, and the same templates over a public value sign.
#[test]
fn a_secret_injected_into_the_path_or_query_taints_the_variables_that_hold_it() {
    let fields = || vec![FieldSpec::secret("token"), FieldSpec::public("id")];
    for (inject, reader) in [
        (path_param("p", "{{ token }}"), "$path"),
        (path_param("p", "{{ token }}"), "$pathname"),
        (path_param("p", "{{ token }}"), "$target_uri"),
        (query("t", "{{ token }}"), "$query"),
        (query("t", "{{ token }}"), "$path"),
        (
            query("t", "{{ token }}"),
            r#"$query_param("t") + $query_param("x")"#,
        ),
    ] {
        let cut = header("X-Cut", &format!(r#"{{{{ slice({reader}, "0", "4") }}}}"#));
        assert_eq!(
            refused(fields(), vec![op(vec![inject.clone(), cut.clone()])]),
            RULE_2,
            "{reader}"
        );
        let public =
            serde_json::from_str::<Value>(&inject.to_string().replace("token", "id")).unwrap();
        assert!(signs(fields(), vec![op(vec![public, cut])]), "{reader}");
    }
    // An injected parameter read alone is exactly its value: tainted, not chosen, so a cut of
    // it signs as `slice(pct(token), ...)` does (and its output is a tainted value).
    for template in [
        r#"{{ slice($query_param("t"), "0", "4") }}"#,
        r#"{{ slice(pct(token), "0", "4") }}"#,
    ] {
        assert!(signs(
            fields(),
            vec![op(vec![
                query("t", "{{ token }}"),
                header("X-Cut", template)
            ])]
        ));
    }
    // The same rule as the secret written in place of the variable.
    assert_eq!(
        refused(
            fields(),
            vec![op(vec![header(
                "X-Cut",
                r#"{{ slice($pathname + pct(token), "0", "4") }}"#
            )])]
        ),
        RULE_2
    );
    // Through an injected header: `$header` of a header that holds a secret is that secret.
    assert_eq!(
        refused(
            fields(),
            vec![op(vec![
                header("X-Key", "{{ token }}"),
                header(
                    "X-Cut",
                    r#"{{ slice($header("x-key") + $body, "0", "4") }}"#
                ),
            ])]
        ),
        RULE_2
    );
    // Taint follows a chain: the body holds a header that holds the path.
    assert_eq!(
        refused(
            fields(),
            vec![op(vec![
                path_param("p", "{{ token }}"),
                header("X-P", "{{ b64($path) }}"),
                body(r#"{{ $header("x-p") }}"#),
                header("X-Cut", r#"{{ slice($body, "0", "4") }}"#),
            ])]
        ),
        RULE_2
    );
    // A MAC over the tainted path is one-way, as over the secret itself.
    assert!(signs(
        fields(),
        vec![op(vec![
            path_param("p", "{{ token }}"),
            header("X-Mac", "{{ hex(hmac_sha256(token, $path)) }}"),
        ])]
    ));
}

/// A secret injected into the query, read back through `$query` in an encoding that does not
/// line up with the secret's own (so the search for the secret field alone would not find
/// it), is never returned: the header that holds it is a tainted rendered value, and a server
/// that echoes it gets the response dropped. With a public value in its place the same
/// policy returns the echo, so the taint is what refuses it.
#[test]
fn a_secret_in_the_query_never_leaks_through_a_request_variable() {
    let clock = TestClock::at(NOW);
    let secret: &[u8] = b"sk-live-0123456789abcdef";
    let leak = || {
        op(vec![
            query("api_key", "{{ key }}"),
            header("X-Q", "{{ b64($query) }}"),
        ])
    };
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![leak()],
        &[("key", secret)],
    );
    let mut server = FakeServer {
        echo: Some("X-Q"),
        ..FakeServer::default()
    };
    let req = request(Method::Get, "example.com", 443, "/v1/x", &[], b"");
    let outcome = call(&s, "o", Some(&req), &mut server);
    let echoed = server.request(0).field("X-Q");
    let decoded = STANDARD.decode(&echoed).unwrap();
    assert!(
        decoded.windows(secret.len()).any(|w| w == secret),
        "the echoed value holds the secret"
    );
    assert!(
        !echoed.contains(&STANDARD.encode(secret)[..8]),
        "the echo is not aligned with the secret's own base64"
    );
    assert!(
        matches!(outcome.result, Err(Error::Reflection)),
        "the echo is refused"
    );

    let s = setup(
        &clock,
        vec![FieldSpec::public("key")],
        vec![leak()],
        &[("key", secret)],
    );
    let mut server = FakeServer {
        echo: Some("X-Q"),
        ..FakeServer::default()
    };
    let response = call(&s, "o", Some(&req), &mut server).result.unwrap();
    assert!(
        response.body() == server.request(0).field("X-Q").as_bytes(),
        "the echo of a public value is returned"
    );

    // Raw, through the target URI and a path parameter, the same.
    for (path, inject) in [
        (
            "/v1/x",
            vec![
                query("api_key", "{{ key }}"),
                header("X-Q", "{{ $target_uri }}"),
            ],
        ),
        (
            "/v1/{p}",
            vec![
                path_param("p", "{{ key }}"),
                header("X-Q", "{{ b64($pathname) }}"),
            ],
        ),
    ] {
        let s = setup(
            &clock,
            vec![FieldSpec::secret("key")],
            vec![op(inject)],
            &[("key", secret)],
        );
        let mut server = FakeServer {
            echo: Some("X-Q"),
            ..FakeServer::default()
        };
        let req = request(Method::Get, "example.com", 443, path, &[], b"");
        let outcome = call(&s, "o", Some(&req), &mut server);
        assert!(
            matches!(outcome.result, Err(Error::Reflection)),
            "the echo is refused"
        );
    }
}

/// The summary follows the same edges: a secret that reaches a header through `$path` is
/// listed as going in that header.
#[test]
fn the_summary_lists_a_secret_read_through_a_request_variable() {
    let policy = policy(
        vec![FieldSpec::secret("token")],
        vec![op(vec![
            path_param("p", "{{ token }}"),
            header("X-Echo", "{{ $path }}"),
        ])],
    );
    let summary = summarize(&policy, None);
    let token = summary.secrets.iter().find(|s| s.field == "token").unwrap();
    let forms: Vec<&Form> = token.uses.iter().map(|u| &u.form).collect();
    assert!(forms.contains(&&Form::PathParam { name: "p".into() }));
    assert!(forms.contains(&&Form::Header {
        name: "X-Echo".into()
    }));
}

// ---------------------------------------------------------------------------------------
// HTTP Message Signatures (RFC 9421)
// ---------------------------------------------------------------------------------------

/// RFC 9421 appendix B.2.6 (Ed25519) and B.2.5 (HMAC-SHA256) with `date` and `content-type`
/// set by the policy and the query of the example (`param=Value&Pet=dog`) injected too; the
/// signature is listed before the headers it covers. The signatures the RFC publishes, byte
/// for byte, and the request line the example sends.
#[test]
fn rfc9421_b26_and_b25_cover_policy_injected_headers() {
    const CREATED: u64 = 1_618_884_473_000;
    let clock = TestClock::at(CREATED);
    let rfc = |label: &str, params: &str, signature: &str| {
        operation(json!({"name": "rfc9421", "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "example.com", "port": 443}]},
            {"do": "compute", "into": "sig_params", "template": params},
            {"do": "send",
             "request": {"from": "caller", "methods": ["POST"], "paths": ["/foo"]},
             "inject": [
                header("Signature-Input", &format!("{label}={{{{ sig_params }}}}")),
                header("Signature", signature),
                header("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
                header("Content-Type", "application/json"),
                query("param", "Value"),
                query("Pet", "dog")]},
            {"do": "return"}
        ]}))
    };
    let b26 = rfc(
        "sig-b26",
        r#"("date" "@method" "@path" "@authority" "content-type" "content-length");created={{ $unix }};keyid="test-key-ed25519""#,
        r#"sig-b26=:{{ b64(ed25519_sign(pem(key), "\"date\": " + $header("date") + "\n\"@method\": " + $method + "\n\"@path\": " + $pathname + "\n\"@authority\": " + $authority + "\n\"content-type\": " + $header("content-type") + "\n\"content-length\": " + len($body) + "\n\"@signature-params\": " + sig_params)) }}:"#,
    );
    let req = request(
        Method::Post,
        "example.com",
        443,
        "/foo",
        &[],
        br#"{"hello": "world"}"#,
    );
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![b26],
        &[("key", ED25519_PEM.as_bytes())],
    );
    let mut server = FakeServer::default();
    call(&s, "rfc9421", Some(&req), &mut server).result.unwrap();
    let sent = server.request(0);
    assert_eq!(sent.target, "/foo?param=Value&Pet=dog");
    assert_eq!(sent.field("Date"), "Tue, 20 Apr 2021 02:07:55 GMT");
    assert_eq!(
        sent.field("Signature"),
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
    );

    let b25 = rfc(
        "sig-b25",
        r#"("date" "@authority" "content-type");created={{ $unix }};keyid="test-shared-secret""#,
        r#"sig-b25=:{{ b64(hmac_sha256(b64decode(key), "\"date\": " + $header("date") + "\n\"@authority\": " + $authority + "\n\"content-type\": " + $header("content-type") + "\n\"@signature-params\": " + sig_params)) }}:"#,
    );
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![b25],
        &[("key", HMAC_SHARED.as_bytes())],
    );
    let mut server = FakeServer::default();
    call(&s, "rfc9421", Some(&req), &mut server).result.unwrap();
    assert_eq!(
        server.request(0).field("Signature"),
        "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
    );
}

/// An RFC 9421 signature over a query parameter, a header and a body the policy injects
/// (`@query-param` of an injected `client_id`, an injected `x-tenant`, `content-digest` of an
/// injected body, `@target-uri` with both): ring verifies it over the base a verifier
/// rebuilds from the wire, for a POST and a PUT.
#[test]
fn rfc9421_covers_an_injected_query_parameter_header_and_body() {
    use ring::signature::{ED25519, UnparsedPublicKey};
    let clock = TestClock::at(NOW);
    let params = r#"("@method" "@target-uri" "@query-param";name="client_id" "x-tenant" "content-digest");created={{ $unix }};keyid="k1""#;
    let base = r#""\"@method\": " + $method + "\n\"@target-uri\": " + $target_uri + "\n\"@query-param\";name=\"client_id\": " + $query_param("client_id") + "\n\"x-tenant\": " + $header("x-tenant") + "\n\"content-digest\": " + $header("content-digest") + "\n\"@signature-params\": " + sig_params"#;
    let signed = operation(json!({"name": "signed", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 8443}]},
        {"do": "compute", "into": "sig_params", "template": params},
        {"do": "send",
         "request": {"from": "caller", "methods": ["POST", "PUT"], "paths": ["/v1/items"],
                     "query": [{"name": "page"}]},
         "inject": [
            header("Signature", &format!("sig1=:{{{{ b64(ed25519_sign(key, {base})) }}}}:")),
            header("Signature-Input", "sig1={{ sig_params }}"),
            header("Content-Digest", "sha-256=:{{ b64(sha256($body)) }}:"),
            body(r#"{{ json_set($body, "tenant", tenant) }}"#),
            header("X-Tenant", "{{ tenant }}"),
            query("client_id", "{{ client }}")]},
        {"do": "return"}
    ]}));
    let s = setup(
        &clock,
        vec![
            FieldSpec::secret("key"),
            FieldSpec::public("tenant"),
            FieldSpec::public("client"),
        ],
        vec![signed],
        &[
            ("key", &pem_body(ED25519_PEM)),
            ("tenant", b"acme"),
            ("client", b"app 7/x"),
        ],
    );
    let public = STANDARD.decode(ED25519_PUBLIC_SPKI).unwrap()[12..].to_vec();
    let mut verified = 0;
    for (method, body) in [(Method::Post, &br#"{"n":1}"#[..]), (Method::Put, b"{}")] {
        let req = request(
            method,
            "api.example.com",
            8443,
            "/v1/items?page=2",
            &[],
            body,
        );
        let mut server = FakeServer::default();
        call(&s, "signed", Some(&req), &mut server).result.unwrap();
        let sent = server.request(0);
        assert!(sent.query().ends_with("&client_id=app%207%2Fx"));
        let tenant: Value = serde_json::from_slice(&sent.body).unwrap();
        assert_eq!(tenant["tenant"], "acme");
        // The verifier: the digest of the body received, the parameter as RFC 9421 section
        // 2.2.8 encodes it, the target URI as sent.
        let digest = format!(
            "sha-256=:{}:",
            STANDARD.encode(sha2::Sha256::digest(&sent.body))
        );
        assert_eq!(sent.field("Content-Digest"), digest);
        let client_id = sent
            .query()
            .split('&')
            .find_map(|p| p.strip_prefix("client_id="))
            .unwrap();
        let client_id = rfc3986(&form_decode(client_id));
        let sig_params = sent.field("Signature-Input");
        let sig_params = sig_params.strip_prefix("sig1=").unwrap();
        let base = format!(
            "\"@method\": {}\n\"@target-uri\": https://api.example.com:8443{}\n\"@query-param\";name=\"client_id\": {client_id}\n\"x-tenant\": {}\n\"content-digest\": {digest}\n\"@signature-params\": {sig_params}",
            sent.method,
            sent.target,
            sent.field("X-Tenant"),
        );
        let signature = sent.field("Signature");
        let signature = signature
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        UnparsedPublicKey::new(&ED25519, &public)
            .verify(base.as_bytes(), &STANDARD.decode(signature).unwrap())
            .expect("the signature over the injected components verifies");
        verified += 1;
    }
    assert_eq!(verified, 2);
}

// ---------------------------------------------------------------------------------------
// AWS Signature Version 4
// ---------------------------------------------------------------------------------------

const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

/// The SigV4 signing key and signature of `string_to_sign`, written here with `hmac`.
fn sigv4_signature(date: &str, scope: &str, string_to_sign: &str) -> String {
    let mut key = hmac_sha256(
        format!("AWS4{SECRET_ACCESS_KEY}").as_bytes(),
        date.as_bytes(),
    );
    for part in scope.split('/') {
        key = hmac_sha256(&key, part.as_bytes());
    }
    hex(&hmac_sha256(&key, string_to_sign.as_bytes()))
}

/// SigV4 with the bucket the policy fills into the path (`{bucket}`, a value with a space)
/// and the `X-Amz-Date` it injects read back with `$header`: a verifier written here rebuilds
/// the canonical request from the wire (the path as sent, the sorted query, the headers, the
/// payload hash) and recomputes the signature. Then presigned: every `X-Amz-*` parameter
/// injected into the query and the signature over the query as sent without itself.
#[test]
fn sigv4_signs_a_policy_injected_path_segment() {
    let clock = TestClock::at(1_440_938_160_000);
    let stamp = r#"time($unix, "%Y%m%dT%H%M%SZ")"#;
    let date = r#"time($unix, "%Y%m%d")"#;
    let key = format!(
        r#"hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256("AWS4" + secret_key, {date}), "us-east-1"), "s3"), "aws4_request")"#
    );
    let canonical = r#"$method + "\n" + $pathname + "\n" + canonical_query($query) + "\nhost:" + $host + "\nx-amz-date:" + $header("x-amz-date") + "\n\nhost;x-amz-date\n" + hex(sha256($body))"#;
    let to_sign = format!(
        r#""AWS4-HMAC-SHA256\n" + $header("x-amz-date") + "\n" + {date} + "/us-east-1/s3/aws4_request\n" + hex(sha256({canonical}))"#
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={{{{ access_key }}}}/{{{{ {date} }}}}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={{{{ hex(hmac_sha256({key}, {to_sign})) }}}}"
    );
    let header_op = caller_op(
        "get",
        "s3.example.com",
        443,
        json!({"methods": ["GET"], "paths": ["/{bucket}/**"], "query": [{"name": "list-type"}]}),
        vec![
            header("Authorization", &authorization),
            path_param("bucket", "{{ bucket }}"),
            header("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
        ],
    );
    let presigned_canonical = r#"$method + "\n" + $pathname + "\n" + canonical_query($query) + "\nhost:" + $host + "\n\nhost\nUNSIGNED-PAYLOAD""#;
    let presigned_to_sign = format!(
        r#""AWS4-HMAC-SHA256\n" + $query_param("X-Amz-Date") + "\n" + {date} + "/us-east-1/s3/aws4_request\n" + hex(sha256({presigned_canonical}))"#
    );
    let presigned = caller_op(
        "presign",
        "s3.example.com",
        443,
        json!({"methods": ["GET"], "paths": ["/{bucket}/**"]}),
        vec![
            query(
                "X-Amz-Signature",
                &format!("{{{{ hex(hmac_sha256({key}, {presigned_to_sign})) }}}}"),
            ),
            path_param("bucket", "{{ bucket }}"),
            query("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            query(
                "X-Amz-Credential",
                &format!("{{{{ access_key }}}}/{{{{ {date} }}}}/us-east-1/s3/aws4_request"),
            ),
            query("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
            query("X-Amz-Expires", "300"),
            query("X-Amz-SignedHeaders", "host"),
        ],
    );
    let s = setup(
        &clock,
        vec![
            FieldSpec::public("access_key"),
            FieldSpec::secret("secret_key"),
            FieldSpec::public("bucket"),
        ],
        vec![header_op, presigned],
        &[
            ("access_key", ACCESS_KEY_ID.as_bytes()),
            ("secret_key", SECRET_ACCESS_KEY.as_bytes()),
            ("bucket", b"my bucket"),
        ],
    );
    let scope = "20150830/us-east-1/s3/aws4_request";
    let mut server = FakeServer::default();
    let req = request(
        Method::Get,
        "s3.example.com",
        443,
        "/{bucket}/photos/a.jpg?list-type=2",
        &[],
        b"",
    );
    call(&s, "get", Some(&req), &mut server).result.unwrap();
    let sent = server.request(0);
    assert_eq!(sent.path(), "/my%20bucket/photos/a.jpg");
    assert_eq!(sent.field("X-Amz-Date"), "20150830T123600Z");
    let canonical = format!(
        "GET\n{}\n{}\nhost:s3.example.com\nx-amz-date:{}\n\nhost;x-amz-date\n{}",
        sent.path(),
        normalized(&[sent.query()]),
        sent.field("X-Amz-Date"),
        hex(&sha2::Sha256::digest(&sent.body)),
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        sent.field("X-Amz-Date"),
        hex(&sha2::Sha256::digest(canonical.as_bytes()))
    );
    assert_eq!(
        sent.field("Authorization"),
        format!(
            "AWS4-HMAC-SHA256 Credential={ACCESS_KEY_ID}/{scope}, SignedHeaders=host;x-amz-date, Signature={}",
            sigv4_signature("20150830", "us-east-1/s3/aws4_request", &to_sign)
        )
    );

    let req = request(
        Method::Get,
        "s3.example.com",
        443,
        "/{bucket}/photos/a.jpg",
        &[],
        b"",
    );
    call(&s, "presign", Some(&req), &mut server).result.unwrap();
    let sent = server.request(1);
    let (signature, rest): (Vec<&str>, Vec<&str>) = sent
        .query()
        .split('&')
        .partition(|p| p.starts_with("X-Amz-Signature="));
    assert!(sent.query().starts_with("X-Amz-Signature="));
    let canonical = format!(
        "GET\n{}\n{}\nhost:s3.example.com\n\nhost\nUNSIGNED-PAYLOAD",
        sent.path(),
        normalized(&[&rest.join("&")]),
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n20150830T123600Z\n{scope}\n{}",
        hex(&sha2::Sha256::digest(canonical.as_bytes()))
    );
    assert_eq!(
        signature,
        [format!(
            "X-Amz-Signature={}",
            sigv4_signature("20150830", "us-east-1/s3/aws4_request", &to_sign)
        )
        .as_str()]
    );
}

// ---------------------------------------------------------------------------------------
// OAuth 1.0a (RFC 5849)
// ---------------------------------------------------------------------------------------

const CONSUMER_SECRET: &[u8] = b"kd94hf93k423kf44";
const TOKEN_SECRET: &[u8] = b"pfkkdhi9sl3r4s00";

fn oauth_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::public("consumer_key"),
        FieldSpec::secret("consumer_secret"),
        FieldSpec::public("token"),
        FieldSpec::secret("token_secret"),
    ]
}

fn oauth_values() -> [(&'static str, &'static [u8]); 4] {
    [
        ("consumer_key", b"dpf43f3p2l4k3l03"),
        ("consumer_secret", CONSUMER_SECRET),
        ("token", b"nnch734d00sl2jdk"),
        ("token_secret", TOKEN_SECRET),
    ]
}

/// RFC 5849 section 1.2 (the photo request; section 3.5.3, the protocol parameters in the
/// query): every `oauth_*` parameter injected into the query by the policy and the signature
/// over the query as sent (without itself), listed first. The signature the RFC gives, byte
/// for byte, on the wire.
#[test]
fn oauth1_rfc5849_vector_with_injected_query_parameters() {
    let clock = TestClock::at(NOW);
    let op = caller_op(
        "photos",
        "photos.example.net",
        443,
        json!({"methods": ["GET"], "paths": ["/photos"],
               "query": [{"name": "file"}, {"name": "size"}]}),
        vec![
            query(
                "oauth_signature",
                r#"{{ b64(hmac_sha1(pct(consumer_secret) + "&" + pct(token_secret), "GET&" + pct("http://photos.example.net/photos") + "&" + pct(sorted_params($query)))) }}"#,
            ),
            query("oauth_consumer_key", "{{ consumer_key }}"),
            query("oauth_token", "{{ token }}"),
            query("oauth_signature_method", "HMAC-SHA1"),
            query("oauth_timestamp", "137131202"),
            query("oauth_nonce", "chapoH"),
        ],
    );
    let s = setup(&clock, oauth_fields(), vec![op], &oauth_values());
    let mut server = FakeServer::default();
    let req = request(
        Method::Get,
        "photos.example.net",
        443,
        "/photos?file=vacation.jpg&size=original",
        &[],
        b"",
    );
    call(&s, "photos", Some(&req), &mut server).result.unwrap();
    assert_eq!(
        server.request(0).target,
        "/photos?file=vacation.jpg&size=original&oauth_signature=MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131202&oauth_nonce=chapoH"
    );
}

/// The `oauth1-query` operation of `docs/policy.md`: every protocol parameter injected into
/// the query with a fresh nonce and the clock's timestamp; a verifier rebuilds the base string
/// from the query as sent (without `oauth_signature`) and recomputes the HMAC-SHA1.
#[test]
fn oauth1_query_example_of_policy_md_verifies() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        oauth_fields(),
        vec![doc("oauth1-query")],
        &oauth_values(),
    );
    let mut server = FakeServer::default();
    let req = request(
        Method::Get,
        "photos.example.net",
        443,
        "/photos?file=vacation.jpg&size=original",
        &[],
        b"",
    );
    call(&s, "oauth1-query", Some(&req), &mut server)
        .result
        .unwrap();
    let sent = server.request(0);
    let (signature, rest): (Vec<&str>, Vec<&str>) = sent
        .query()
        .split('&')
        .partition(|p| p.starts_with("oauth_signature="));
    assert!(rest.contains(&"oauth_timestamp=1800000000"));
    let base = format!(
        "GET&{}&{}",
        rfc3986(b"https://photos.example.net/photos"),
        rfc3986(normalized(&[&rest.join("&")]).as_bytes())
    );
    let mut key = rfc3986(CONSUMER_SECRET);
    key.push('&');
    key.push_str(&rfc3986(TOKEN_SECRET));
    let expected = STANDARD.encode(hmac_sha1(key.as_bytes(), base.as_bytes()));
    let got = signature[0].strip_prefix("oauth_signature=").unwrap();
    assert!(
        form_decode(got) == expected.as_bytes(),
        "the OAuth signature verifies"
    );
}

/// An `oauth_nonce` the policy appends to the caller's form body and an `oauth_version` it
/// appends to the query are covered by the signature in the `Authorization` header, which
/// reads both as sent; a verifier rebuilds the base string from the wire (query, body and
/// header parameters) and recomputes the HMAC-SHA1. Two calls, two fresh nonces.
#[test]
fn oauth1_signs_injected_form_and_query_parameters() {
    let clock = TestClock::at(NOW);
    let protocol = r#""oauth_consumer_key=" + pct(consumer_key) + "&oauth_token=" + pct(token) + "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=" + $unix"#;
    let signature = format!(
        r#"b64(hmac_sha1(pct(consumer_secret) + "&" + pct(token_secret), $method + "&" + pct("https://" + $host + $pathname) + "&" + pct(sorted_params($query, $body, {protocol}))))"#
    );
    let op = caller_op(
        "update",
        "api.example.com",
        443,
        json!({"methods": ["POST"], "paths": ["/1.1/statuses/update"],
               "query": [{"name": "count"}]}),
        vec![
            header(
                "Authorization",
                &format!(
                    r#"OAuth oauth_consumer_key="{{{{ pct(consumer_key) }}}}", oauth_token="{{{{ pct(token) }}}}", oauth_signature_method="HMAC-SHA1", oauth_timestamp="{{{{ $unix }}}}", oauth_signature="{{{{ pct({signature}) }}}}""#
                ),
            ),
            header("Content-Type", "application/x-www-form-urlencoded"),
            body(r#"{{ $body + "&oauth_nonce=" + $nonce }}"#),
            query("oauth_version", "1.0"),
        ],
    );
    let s = setup(&clock, oauth_fields(), vec![op], &oauth_values());
    let mut server = FakeServer::default();
    let req = request(
        Method::Post,
        "api.example.com",
        443,
        "/1.1/statuses/update?count=20",
        &[],
        b"status=Hello+Ladies+%2B+Gentlemen%2C+caf%C3%A9",
    );
    for _ in 0..2 {
        call(&s, "update", Some(&req), &mut server).result.unwrap();
    }
    let mut nonces = Vec::new();
    for n in 0..2 {
        let sent = server.request(n);
        let header = sent.field("Authorization");
        let params: Vec<(String, String)> = header
            .strip_prefix("OAuth ")
            .unwrap()
            .split(", ")
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                let v = v.trim_matches('"');
                (k.to_string(), String::from_utf8(form_decode(v)).unwrap())
            })
            .collect();
        let protocol: Vec<String> = params
            .iter()
            .filter(|(k, _)| k != "oauth_signature")
            .map(|(k, v)| format!("{}={}", rfc3986(k.as_bytes()), rfc3986(v.as_bytes())))
            .collect();
        let body = std::str::from_utf8(&sent.body).unwrap();
        let nonce = body.split("&oauth_nonce=").nth(1).unwrap().to_string();
        assert_eq!(nonce.len(), 32);
        nonces.push(nonce);
        assert!(sent.query().ends_with("&oauth_version=1.0"));
        let base = format!(
            "POST&{}&{}",
            rfc3986(format!("https://api.example.com{}", sent.path()).as_bytes()),
            rfc3986(normalized(&[sent.query(), body, &protocol.join("&")]).as_bytes())
        );
        assert!(base.contains("oauth_nonce%3D"));
        assert!(base.contains("oauth_version%3D1.0"));
        let mut key = rfc3986(CONSUMER_SECRET);
        key.push('&');
        key.push_str(&rfc3986(TOKEN_SECRET));
        let expected = STANDARD.encode(hmac_sha1(key.as_bytes(), base.as_bytes()));
        let got = &params
            .iter()
            .find(|(k, _)| k == "oauth_signature")
            .unwrap()
            .1;
        assert!(got == &expected, "the OAuth signature verifies");
    }
    assert_ne!(nonces[0], nonces[1]);
}

// ---------------------------------------------------------------------------------------
// Hawk
// ---------------------------------------------------------------------------------------

/// The Hawk specification's GET example (its README: port 8000, `/resource/1?b=1&a=2`,
/// `ext="some-app-ext-data"`, its fixed nonce): the query injected by the policy and `ext`
/// taken from a header the policy injects, both read as sent. The MAC the specification
/// publishes, byte for byte.
#[test]
fn hawk_specification_example_with_injected_query_and_ext() {
    let clock = TestClock::at(1_353_832_234_000);
    let mac = r#"b64(hmac_sha256(secret, "hawk.1.header\n" + $unix + "\nj4h3g2\n" + $method + "\n" + $path + "\n" + $host + "\n" + $port + "\n\n" + $header("x-app-ext") + "\n"))"#;
    let op = caller_op(
        "get",
        "example.com",
        8000,
        json!({"methods": ["GET"], "paths": ["/resource/1"]}),
        vec![
            header(
                "Authorization",
                &format!(
                    r#"Hawk id="{{{{ user }}}}", ts="{{{{ $unix }}}}", nonce="j4h3g2", ext="{{{{ $header("x-app-ext") }}}}", mac="{{{{ {mac} }}}}""#
                ),
            ),
            query("b", "1"),
            query("a", "2"),
            header("X-App-Ext", "some-app-ext-data"),
        ],
    );
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::secret("secret")],
        vec![op],
        &[
            ("user", b"dh37fgj492je"),
            ("secret", b"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"),
        ],
    );
    let mut server = FakeServer::default();
    let req = request(Method::Get, "example.com", 8000, "/resource/1", &[], b"");
    call(&s, "get", Some(&req), &mut server).result.unwrap();
    let sent = server.request(0);
    assert_eq!(sent.target, "/resource/1?b=1&a=2");
    assert_eq!(
        sent.field("Authorization"),
        r#"Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=""#
    );
}
