//! The generic capabilities the scheme tests of `crates/engine/tests/schemes.rs` found
//! missing, each a whole family: the caller's request components as template variables
//! (`$header`, `$query_param`, `$port`, `$authority`, `$target_uri`, `$scheme`), the parts of an
//! AEAD output (`aead_ciphertext`, `aead_tag`) and public keys from private keys
//! (`ed25519_public`, `ed448_public`, `ecdsa_public`, `rsa_public`). The schemes that worked
//! with caveats, or not at all, for these reasons run again here, checked against published
//! vectors (RFC 9421 appendix B.2, the Hawk specification, RFC 7516 appendix A, RFC 8032,
//! RFC 8037, RFC 6979) or a verifier written in the test over crates that are not the engine's
//! code path for that value; and every guarantee has its attack.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Clock, Node, Outcome, Response};
use engine::policy::{Caller, Destination, FieldSpec, Method, Operation, Policy};
use engine::record::Record;
use engine::request::Request;
use serde_json::{Value, json};
use sha2::Digest as _;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

/// Rule 2 of the analysis (`docs/policy.md`, The analysis).
const RULE_2: &str = "a secret and a chosen value meet in a function that compares or cuts them";
/// Rule 1.
const RULE_1: &str = "a secret mixed with a chosen value reaches a decoder, number or key";
/// Rule 9.
const RULE_9: &str = "a length must not depend on a secret";
/// Rule 6.
const RULE_6: &str = "a hash or curve name must be fixed by the policy";
/// Rule 7.
const RULE_7: &str =
    "an encryption key must come from the policy or the destination, not the caller";
/// Rule 5, tainted output.
const RULE_5: &str = "a derivation would hand a secret back";
const AEAD_IN_PLACE: &str =
    "aead_ciphertext and aead_tag take an AEAD encryption call written in place";

/// The Ed25519 key `test-key-ed25519` of RFC 9421 appendix B.1.4 (PKCS#8 PEM).
const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n";
/// Its public key, RFC 9421 appendix B.1.4 (SubjectPublicKeyInfo, base64).
const ED25519_PUBLIC_SPKI: &str = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
/// The shared key `test-shared-secret` of RFC 9421 appendix B.1.5 (base64).
const HMAC_SHARED: &str =
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==";
/// RFC 8032 section 7.1, TEST 1: the Ed25519 secret and public key (also RFC 8037 A.1, A.2).
const ED25519_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// RFC 8032 section 7.4, the first Ed448 test ("Blank"): secret and public key.
const ED448_SECRET: &str = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
const ED448_PUBLIC: &str = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
/// RFC 6979 appendix A.2.5 (P-256): the private key and `Ux || Uy`.
const P256_SECRET: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_PUBLIC: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
/// RFC 6979 appendix A.2.6 (P-384): the private key and `Ux || Uy`.
const P384_SECRET: &str = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5";
const P384_PUBLIC: &str = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
/// secp256k1: the private key 1 has the generator as its public key (SEC 2, section 2.4.1).
const K256_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const K256_G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
/// Private keys for the curves without a published key pair here (not published values).
const P521_SECRET: &str = "00fb26d7b0a6a7cc1aa4b4e6e4d3bd5bd8efa1d66e4bb2a5a2f1e0d19a07b8c3f41a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a";
const BP256_SECRET: &str = "1f2e3d4c5b6a79880f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778";
const BP384_SECRET: &str = "1f2e3d4c5b6a79880f1e2d3c4b5a69788796a5b4c3d2e1f0011223344556677812345678123456781234567812345678";
const SM2_SECRET: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";

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

/// A fake server: answers from `replies` in order and records each request.
#[derive(Default)]
struct FakeServer {
    replies: VecDeque<Vec<u8>>,
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
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()))
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

    fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
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

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unb64url(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

/// The JSON text of the operation `name` in `docs/policy.md`.
fn doc(name: &str) -> Operation {
    let text = POLICY_MD.replace("\r\n", "\n");
    let mut rest = text.as_str();
    while let Some(start) = rest.find("```json\n") {
        let body = &rest[start + 8..];
        let end = body.find("```").unwrap();
        let block = &body[..end];
        let value = serde_json::from_str::<Value>(block).unwrap_or(Value::Null);
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

fn policy(fields: Vec<FieldSpec>, operations: Vec<Operation>) -> Policy {
    let names: Vec<String> = operations.iter().map(|o| o.name().to_string()).collect();
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

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

struct Setup<'c> {
    node: TestNode<'c>,
    record: Record,
}

/// A node that holds one record of `fields` with `values` under a signed policy of
/// `operations`; signing runs the template analysis.
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

fn derive(s: &Setup<'_>, operation: &str, input: &[u8]) -> Vec<u8> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            operation,
            &Payload::Derive(input),
            now(),
        )
        .unwrap();
    s.node.derive(&s.record, operation, &auth, input).unwrap()
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

/// An operation with no connection that returns `template` over a raw `$input`.
fn derivation(name: &str, template: &str) -> Operation {
    operation(json!({"name": name, "input": {"raw": {}},
        "steps": [{"do": "return", "template": template}]}))
}

/// An HTTPS operation to `example.com` whose caller request (POST `/v1/x`, the headers and
/// query parameters given) gets one header `X-Out` of `template`.
fn https_with(name: &str, headers: &[&str], query: &[&str], template: &str) -> Operation {
    let query: Vec<Value> = query.iter().map(|q| json!({"name": q})).collect();
    operation(json!({"name": name, "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "send",
         "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/x"],
                     "headers": headers, "query": query},
         "inject": [{"target": {"kind": "header", "name": "X-Out"}, "template": template}]},
        {"do": "return"}
    ]}))
}

// ---------------------------------------------------------------------------------------
// Request components: RFC 9421 and Hawk over what the caller sends
// ---------------------------------------------------------------------------------------

/// An RFC 9421 appendix B.2 operation for `example.com`: the caller's `POST /foo` with
/// `Date` and `Content-Type` among the headers it may set, and the signature headers.
fn rfc9421_caller_headers(label: &str, params: &str, signature: &str) -> Operation {
    operation(json!({"name": "rfc9421", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "compute", "into": "sig_params", "template": params},
        {"do": "send",
         "request": {"from": "caller", "methods": ["POST"], "paths": ["/foo"],
                     "headers": ["Date", "Content-Type"],
                     "query": [{"name": "param"}, {"name": "Pet"}]},
         "inject": [
            {"target": {"kind": "header", "name": "Signature-Input"},
             "template": format!("{label}={{{{ sig_params }}}}")},
            {"target": {"kind": "header", "name": "Signature"}, "template": signature}]},
        {"do": "return"}
    ]}))
}

/// The request of RFC 9421 appendix B.2, with `Date` and `Content-Type` set by the caller.
fn rfc9421_request() -> Request {
    request(
        Method::Post,
        "example.com",
        443,
        "/foo?param=Value&Pet=dog",
        &[
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
        ],
        br#"{"hello": "world"}"#,
    )
}

/// RFC 9421 appendix B.2.6 (Ed25519) and B.2.5 (HMAC-SHA256) with the `date` and
/// `content-type` fields the caller sent and `@authority` from `$authority`: the signatures the
/// RFC publishes, byte for byte. (Before `$header`, the policy had to fix both fields itself.)
#[test]
fn rfc9421_b26_and_b25_cover_the_callers_headers() {
    const CREATED: u64 = 1_618_884_473_000;
    let clock = TestClock::at(CREATED);
    let b26 = rfc9421_caller_headers(
        "sig-b26",
        r#"("date" "@method" "@path" "@authority" "content-type" "content-length");created={{ $unix }};keyid="test-key-ed25519""#,
        r#"sig-b26=:{{ b64(ed25519_sign(pem(key), "\"date\": " + $header("date") + "\n\"@method\": " + $method + "\n\"@path\": " + $pathname + "\n\"@authority\": " + $authority + "\n\"content-type\": " + $header("content-type") + "\n\"content-length\": " + len($body) + "\n\"@signature-params\": " + sig_params)) }}:"#,
    );
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![b26],
        &[("key", ED25519_PEM.as_bytes())],
    );
    let mut server = FakeServer::default();
    call(&s, "rfc9421", Some(&rfc9421_request()), &mut server)
        .result
        .unwrap();
    let sent = server.request(0);
    assert_eq!(sent.field("Date"), "Tue, 20 Apr 2021 02:07:55 GMT");
    assert_eq!(
        sent.field("Signature"),
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
    );

    let b25 = rfc9421_caller_headers(
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
    call(&s, "rfc9421", Some(&rfc9421_request()), &mut server)
        .result
        .unwrap();
    assert_eq!(
        server.request(0).field("Signature"),
        "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
    );
}

/// `@query-param` (RFC 9421 section 2.2.8, `$query_param`): the section's examples `var`,
/// `bar`, `qux` and `baz`, value for value (`+` read as a space, values encoded again as
/// `%20` and `%0A`, an empty value). Its third example names `fa%C3%A7ade%22%3A%20`, which a
/// contract cannot list (a query name is visible ASCII), so a name with `~` and `"` stands in
/// for it: written encoded (`%7E`, `%22`), with a value holding `*` (kept) and UTF-8 (`%C3%A7`).
#[test]
fn query_param_follows_rfc9421_section_2_2_8() {
    let clock = TestClock::at(NOW);
    let op = https_with(
        "qp",
        &[],
        &["var", "bar", "a~b\"", "qux", "baz"],
        r#"{{ $query_param("var") + "|" + $query_param("bar") + "|" + $query_param("a%7Eb%22") + "|" + $query_param("qux") + "|" + $query_param("baz") }}"#,
    );
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        vec![op],
        &[],
    );
    let mut server = FakeServer::default();
    let req = request(
        Method::Post,
        "example.com",
        443,
        "/v1/x?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&a~b%22=x*y%C3%A7&qux=&baz=batman",
        &[],
        b"",
    );
    call(&s, "qp", Some(&req), &mut server).result.unwrap();
    assert_eq!(
        server.request(0).field("X-Out"),
        "this%20is%20a%20big%0Amultiline%20value|with%20plus%20whitespace|x*y%C3%A7||batman"
    );
}

/// Rebuilds the signature base of the `signed-call-headers` operation from the request as
/// the server read it, as an RFC 9421 verifier does (section 2.5).
fn signed_call_base(sent: &Sent, params: &str) -> String {
    let digest = format!(
        "sha-256=:{}:",
        STANDARD.encode(sha2::Sha256::digest(&sent.body))
    );
    assert_eq!(sent.field("Content-Digest"), digest);
    let authority = sent.field("Host").to_ascii_lowercase();
    let page = sent
        .query()
        .split('&')
        .find_map(|p| p.strip_prefix("page="))
        .unwrap_or("");
    format!(
        "\"@method\": {}\n\"@target-uri\": https://{authority}{}\n\"@authority\": {authority}\n\"@query-param\";name=\"page\": {page}\n\"content-type\": {}\n\"content-digest\": {digest}\n\"idempotency-key\": {}\n\"@signature-params\": {params}",
        sent.method,
        sent.target,
        sent.field("Content-Type"),
        sent.field("Idempotency-Key"),
    )
}

/// The `signed-call-headers` operation of `docs/policy.md`: the caller's `Content-Type` and
/// `Idempotency-Key` (sent with whitespace around it, absent on the GET), a query parameter,
/// the target URI and an authority with port 8443 are covered; ring verifies each signature
/// over the base an independent verifier rebuilds from the wire.
#[test]
fn signed_call_headers_verifies() {
    use ring::signature::{ED25519, UnparsedPublicKey};
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![doc("signed-call-headers")],
        &[("key", &pem_body(ED25519_PEM))],
    );
    let public = STANDARD.decode(ED25519_PUBLIC_SPKI).unwrap()[12..].to_vec();
    let requests = [
        request(
            Method::Post,
            "api.example.com",
            8443,
            "/v1/items?page=7",
            &[
                ("Content-Type", "application/json"),
                ("Idempotency-Key", " \tk-0001 "),
            ],
            br#"{"name":"x"}"#,
        ),
        request(
            Method::Get,
            "api.example.com",
            8443,
            "/v1/items/9?page=12",
            &[("content-type", "text/plain")],
            b"",
        ),
    ];
    let mut verified = 0;
    for req in &requests {
        let mut server = FakeServer::default();
        call(&s, "signed-call-headers", Some(req), &mut server)
            .result
            .unwrap();
        let sent = server.request(0);
        let params = sent
            .field("Signature-Input")
            .strip_prefix("sig1=")
            .unwrap()
            .to_string();
        let base = signed_call_base(&sent, &params);
        assert!(base.contains("\"@authority\": api.example.com:8443\n"));
        let signature = STANDARD
            .decode(
                sent.field("Signature")
                    .strip_prefix("sig1=:")
                    .unwrap()
                    .strip_suffix(':')
                    .unwrap(),
            )
            .unwrap();
        UnparsedPublicKey::new(&ED25519, &public)
            .verify(base.as_bytes(), &signature)
            .expect("the signature over the caller's headers verifies");
        verified += 1;
    }
    assert_eq!(verified, 2);
}

/// The Hawk specification's POST example (its README: port 8000, `text/plain`, payload
/// "Thank you for flying Hawk", `ext`) with the content type the caller sends (with a
/// parameter and in mixed case, which Hawk normalizes away) and the port from `$port`; its
/// fixed nonce in place of `$nonce`: the payload hash and the MAC it publishes, byte for byte.
/// And its GET example with the port from `$port`.
#[test]
fn hawk_specification_examples_with_the_callers_content_type_and_port() {
    let clock = TestClock::at(1_353_832_234_000);
    let payload = r#"b64(sha256("hawk.1.payload\n" + lower(trim(between($header("content-type") + ";", "", ";"))) + "\n" + $body + "\n"))"#;
    let mac = |hash: &str| {
        format!(
            r#"b64(hmac_sha256(secret, "hawk.1.header\n" + $unix + "\nj4h3g2\n" + $method + "\n" + $path + "\n" + $host + "\n" + $port + "\n" + {hash} + "\nsome-app-ext-data\n"))"#
        )
    };
    let post = format!(
        r#"Hawk id="{{{{ user }}}}", ts="{{{{ $unix }}}}", nonce="j4h3g2", hash="{{{{ {payload} }}}}", ext="some-app-ext-data", mac="{{{{ {} }}}}""#,
        mac(payload)
    );
    let get = format!(
        r#"Hawk id="{{{{ user }}}}", ts="{{{{ $unix }}}}", nonce="j4h3g2", ext="some-app-ext-data", mac="{{{{ {} }}}}""#,
        mac("\"\"")
    );
    let op = |name: &str, method: &str, template: &str| {
        operation(json!({"name": name, "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "example.com", "port": 8000}]},
            {"do": "send",
             "request": {"from": "caller", "methods": [method], "paths": ["/resource/1"],
                         "headers": ["Content-Type"],
                         "query": [{"name": "b"}, {"name": "a"}]},
             "inject": [{"target": {"kind": "header", "name": "Authorization"},
                         "template": template}]},
            {"do": "return"}
        ]}))
    };
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::secret("secret")],
        vec![op("get", "GET", &get), op("post", "POST", &post)],
        &[
            ("user", b"dh37fgj492je"),
            ("secret", b"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"),
        ],
    );
    let mut server = FakeServer::default();
    let req = request(
        Method::Get,
        "example.com",
        8000,
        "/resource/1?b=1&a=2",
        &[],
        b"",
    );
    call(&s, "get", Some(&req), &mut server).result.unwrap();
    assert_eq!(
        server.request(0).field("Authorization"),
        r#"Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=""#
    );
    let req = request(
        Method::Post,
        "example.com",
        8000,
        "/resource/1?b=1&a=2",
        &[("Content-Type", "Text/Plain; charset=utf-8")],
        b"Thank you for flying Hawk",
    );
    call(&s, "post", Some(&req), &mut server).result.unwrap();
    let sent = server.request(1);
    assert_eq!(sent.field("Content-Type"), "Text/Plain; charset=utf-8");
    assert_eq!(
        sent.field("Authorization"),
        r#"Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=""#
    );
}

/// The `hawk-call-headers` operation of `docs/policy.md`: a verifier recomputes the payload
/// hash over the content type the server received and the MAC over the port it was sent to.
#[test]
fn hawk_call_headers_verifies() {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    let clock = TestClock::at(NOW);
    let key = b"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::secret("secret")],
        vec![doc("hawk-call-headers")],
        &[("user", b"dh37fgj492je"), ("secret", key)],
    );
    let mut verified = 0;
    for (method, body, content_type) in [
        (
            Method::Post,
            &br#"{"n":1}"#[..],
            "application/json; charset=utf-8",
        ),
        (Method::Get, b"", ""),
    ] {
        let headers: Vec<(&str, &str)> = if content_type.is_empty() {
            vec![]
        } else {
            vec![("Content-Type", content_type)]
        };
        let req = request(method, "api.example.com", 8000, "/v1/items", &headers, body);
        let mut server = FakeServer::default();
        call(&s, "hawk-call-headers", Some(&req), &mut server)
            .result
            .unwrap();
        let sent = server.request(0);
        let header = sent.field("Authorization");
        let attribute = |name: &str| -> String {
            header
                .strip_prefix("Hawk ")
                .unwrap()
                .split(", ")
                .find_map(|p| p.strip_prefix(&format!("{name}=\"")))
                .unwrap()
                .trim_end_matches('"')
                .to_string()
        };
        let media = sent
            .field("Content-Type")
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_ascii_lowercase();
        let hash = STANDARD.encode(sha2::Sha256::digest(
            [
                format!("hawk.1.payload\n{media}\n").as_bytes(),
                &sent.body,
                b"\n",
            ]
            .concat(),
        ));
        assert_eq!(attribute("hash"), hash);
        let normalized = format!(
            "hawk.1.header\n{}\n{}\n{}\n{}\napi.example.com\n8000\n{hash}\n\n",
            attribute("ts"),
            attribute("nonce"),
            sent.method,
            sent.target,
        );
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(normalized.as_bytes());
        mac.verify_slice(&STANDARD.decode(attribute("mac")).unwrap())
            .expect("the Hawk MAC verifies");
        verified += 1;
    }
    assert_eq!(verified, 2);
}

/// A caller cannot put a header the contract does not list into a signature base: the
/// request is refused before anything is rendered, logged or sent.
#[test]
fn a_header_outside_the_contract_never_reaches_a_signature() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![https_with(
            "sig",
            &["Content-Type"],
            &[],
            r#"{{ hex(hmac_sha256(key, $header("content-type"))) }}"#,
        )],
        &[("key", b"k-0123456789abcdef")],
    );
    for headers in [
        vec![("X-Forwarded-Host", "evil.example")],
        vec![("Content-Type", "a"), ("Authorization", "Bearer x")],
        vec![("X-Out", "forged")],
    ] {
        let mut server = FakeServer::default();
        let req = request(Method::Post, "example.com", 443, "/v1/x", &headers, b"");
        let outcome = call(&s, "sig", Some(&req), &mut server);
        assert!(
            matches!(outcome.result, Err(Error::RequestInvalid { .. })),
            "a header outside the contract is refused"
        );
        assert!(server.sent.is_empty(), "nothing is sent");
    }
}

/// Header smuggling: the same header twice (in one case or two), a folded value (obs-fold,
/// RFC 9112 section 5.2), a bare line feed, a NUL and a byte outside ASCII are refused; the
/// value a template reads is never a combination the caller chose to build.
#[test]
fn duplicate_folded_and_control_headers_are_refused() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![https_with(
            "sig",
            &["Content-Type", "Date"],
            &[],
            r#"{{ hex(hmac_sha256(key, $header("content-type") + $header("date"))) }}"#,
        )],
        &[("key", b"k-0123456789abcdef")],
    );
    let cases: [Vec<(&str, &str)>; 7] = [
        vec![("Content-Type", "a"), ("Content-Type", "b")],
        vec![("Content-Type", "a"), ("content-type", "b")],
        vec![("Content-Type", "a"), ("CONTENT-TYPE", "a")],
        vec![("Content-Type", "a\r\n b")],
        vec![("Date", "x\ny")],
        vec![("Date", "x\0y")],
        vec![("Date", "caf\u{e9}")],
    ];
    for headers in cases {
        let mut server = FakeServer::default();
        let req = request(Method::Post, "example.com", 443, "/v1/x", &headers, b"");
        let outcome = call(&s, "sig", Some(&req), &mut server);
        assert!(
            matches!(outcome.result, Err(Error::RequestInvalid { .. })),
            "a smuggling header is refused"
        );
        assert!(server.sent.is_empty(), "nothing is sent");
    }
    // A header in another case than the contract's is the same header; whitespace around the
    // value is not part of it (RFC 9110 section 5.5).
    let mut server = FakeServer::default();
    let req = request(
        Method::Post,
        "example.com",
        443,
        "/v1/x",
        &[("CONTENT-type", "\t text/plain  ")],
        b"",
    );
    call(&s, "sig", Some(&req), &mut server).result.unwrap();
    use hmac::{Hmac, KeyInit as _, Mac as _};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"k-0123456789abcdef").unwrap();
    mac.update(b"text/plain");
    assert_eq!(
        server.request(0).field("X-Out"),
        hex(&mac.finalize().into_bytes())
    );
}

/// The analysis knows every request component a template reads: a header or query parameter
/// the contract does not list, any in a fixed request, in a `compute` step or in a derivation,
/// a reserved header and a name that is not a literal are refused at signing.
#[test]
fn templates_read_only_components_the_contract_lists() {
    let key = || vec![FieldSpec::secret("key")];
    let mac = |component: &str| format!("{{{{ hex(hmac_sha256(key, {component})) }}}}");
    assert_eq!(
        refused(
            key(),
            vec![https_with(
                "o",
                &["Date"],
                &[],
                &mac(r#"$header("x-tenant")"#)
            )]
        ),
        "a template reads a header the caller contract does not allow"
    );
    assert_eq!(
        refused(
            key(),
            vec![https_with(
                "o",
                &["Content-Length"],
                &[],
                &mac(r#"$header("content-length")"#)
            )]
        ),
        "caller header must be a token and not reserved"
    );
    assert_eq!(
        refused(
            key(),
            vec![https_with(
                "o",
                &[],
                &["page"],
                &mac(r#"$query_param("limit")"#)
            )]
        ),
        "a template reads a query parameter the caller contract does not allow"
    );
    let fixed = operation(json!({"name": "o", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/"},
         "inject": [{"target": {"kind": "header", "name": "X-Out"},
                     "template": mac(r#"$header("date")"#)}]},
        {"do": "return"}
    ]}));
    assert_eq!(
        refused(key(), vec![fixed]),
        "a fixed request has no caller headers or query parameters to read"
    );
    let compute = operation(json!({"name": "o", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "compute", "into": "d", "template": r#"{{ $header("date") }}"#},
        {"do": "send",
         "request": {"from": "caller", "methods": ["GET"], "paths": ["/"], "headers": ["Date"]},
         "inject": [{"target": {"kind": "header", "name": "X-Out"}, "template": "{{ d }}"}]},
        {"do": "return"}
    ]}));
    assert_eq!(
        refused(key(), vec![compute]),
        "template reads a variable not available here"
    );
    for template in [
        mac(r#"$header("date")"#),
        mac("$port"),
        mac("$target_uri"),
        mac(r#"$query_param("a")"#),
    ] {
        assert_eq!(
            refused(key(), vec![derivation("o", &template)]),
            "template reads a variable not available here"
        );
    }
    for template in [
        mac("$header(date)"),
        mac(r#"$header("a b")"#),
        mac(r#"$header("date", "x")"#),
        mac(r#"$header(key)"#),
        mac("$header"),
        mac(r#"$query_param("")"#),
    ] {
        assert_eq!(
            refused(key(), vec![https_with("o", &["Date"], &["a"], &template)]),
            "template syntax"
        );
    }
}

/// A caller's header is chosen like `$body`, so the rules of the analysis hold for it
/// unchanged: signing it with a secret key is allowed (the normal signing case), but it may
/// not meet a secret in a cut, a decoder or a key argument, choose an encryption key or a hash.
#[test]
fn caller_headers_follow_the_rules_of_the_analysis() {
    let key = || vec![FieldSpec::secret("key")];
    let with = |t: &str| vec![https_with("o", &["X-A"], &[], t)];
    for (template, rule) in [
        (r#"{{ slice(key, $header("x-a"), "1") }}"#, RULE_2),
        (r#"{{ between(key, $header("x-a"), "") }}"#, RULE_2),
        (r#"{{ b64decode(key + $header("x-a")) }}"#, RULE_1),
        (
            r#"{{ b64(rsa_encrypt_oaep("sha256", $header("x-a"), key)) }}"#,
            RULE_7,
        ),
        (
            r#"{{ hex(pbkdf2($header("x-a"), key, "s", "1")) }}"#,
            RULE_6,
        ),
        (r#"{{ hex(random(key + $header("x-a"))) }}"#, RULE_1),
    ] {
        assert_eq!(refused(key(), with(template)), rule, "{template}");
    }
    // A caller header cannot shadow one the policy injects (and so signs).
    assert_eq!(
        refused(key(), vec![https_with("o", &["X-Out"], &[], "x")]),
        "a caller header is also injected"
    );
    DeviceKey::generate()
        .sign_policy(policy(
            key(),
            with(r#"{{ b64(hmac_sha256(key, $header("x-a") + $target_uri + $authority + $port + $scheme)) }}"#),
        ))
        .expect("signing the caller's header with a secret key is the normal case");
}

// ---------------------------------------------------------------------------------------
// AEAD parts
// ---------------------------------------------------------------------------------------

/// Every AEAD family, split: the ciphertext and the tag are the whole output cut at the tag
/// length of the algorithm (16; the CCM tag length; half the AES-CBC-HMAC key), for messages
/// of 0, 1 and 37 bytes; AES-GCM is checked against the `aes-gcm` crate's detached form and
/// AES-CCM against the `ccm` crate.
#[test]
fn aead_parts_of_every_family() {
    use aes_gcm::aead::AeadInOut as _;
    use aes_gcm::{KeyInit as _, Nonce};
    let clock = TestClock::at(NOW);
    let k16 = "0123456789abcdef";
    let k32 = "0123456789abcdef0123456789abcdef";
    let cases: Vec<(String, usize)> = vec![
        (
            format!(r#"aes_gcm_encrypt("{k16}", "000000000000", $input, "aad")"#),
            16,
        ),
        (
            format!(r#"aes_gcm_encrypt("{k32}", "000000000000", $input)"#),
            16,
        ),
        (
            format!(r#"chacha20_poly1305_encrypt("{k32}", "000000000000", $input, "aad")"#),
            16,
        ),
        (
            format!(r#"aes_cbc_hmac_encrypt("{k32}", "{k16}", $input, "aad")"#),
            16,
        ),
        (
            format!(r#"aes_cbc_hmac_encrypt("{k32}{k16}", "{k16}", $input)"#),
            24,
        ),
        (
            format!(r#"aes_cbc_hmac_encrypt("{k32}{k32}", "{k16}", $input)"#),
            32,
        ),
        (
            format!(r#"aes_ccm_encrypt("{k16}", "0123456789abc", "8", $input, "aad")"#),
            8,
        ),
        (
            format!(r#"aes_ccm_encrypt("{k16}", "0123456", "4", $input)"#),
            4,
        ),
        (
            format!(r#"aes_ccm_encrypt("{k16}", "0123456789abc", "16", $input)"#),
            16,
        ),
        (
            format!(r#"aes_eax_encrypt("{k16}", "{k16}", $input, "aad")"#),
            16,
        ),
    ];
    let ops: Vec<Operation> = cases
        .iter()
        .enumerate()
        .map(|(i, (call, _))| {
            derivation(
                &format!("aead{i}"),
                &format!(
                    "{{{{ hex(aead_ciphertext({call})) + \".\" + hex(aead_tag({call})) + \".\" + hex({call}) }}}}"
                ),
            )
        })
        .collect();
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        ops,
        &[],
    );
    let mut checked = 0;
    for (i, (call, tag_len)) in cases.iter().enumerate() {
        for message in [&b""[..], b"x", b"thirty-seven bytes of a caller's text"] {
            let out = String::from_utf8(derive(&s, &format!("aead{i}"), message)).unwrap();
            let parts: Vec<&str> = out.split('.').collect();
            let (ciphertext, tag, whole) = (unhex(parts[0]), unhex(parts[1]), unhex(parts[2]));
            assert_eq!([ciphertext.clone(), tag.clone()].concat(), whole, "{call}");
            assert_eq!(tag.len(), *tag_len, "{call}");
            if call.starts_with("aes_gcm_encrypt(\"0123456789abcdef\"") {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(k16.as_bytes()).unwrap();
                let mut buffer = message.to_vec();
                let expected = cipher
                    .encrypt_inout_detached(
                        &Nonce::try_from(&b"000000000000"[..]).unwrap(),
                        b"aad",
                        buffer.as_mut_slice().into(),
                    )
                    .unwrap();
                assert_eq!(ciphertext, buffer, "aes-gcm ciphertext");
                assert_eq!(tag, expected.to_vec(), "aes-gcm tag");
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 30);
}

/// RFC 7516 appendix A.3 (A128KW with A128CBC-HS256), the whole compact JWE byte for byte,
/// and the content of appendix A.1 (A256GCM): its ciphertext and tag. The content key and IV
/// are the RFC's, as fields.
#[test]
fn jwe_rfc7516_vectors_split_by_aead_parts() {
    let clock = TestClock::at(NOW);
    let a3_cek = [
        4u8, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212,
        45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
    ];
    let a3_iv = [
        3u8, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
    ];
    let a1_cek = [
        177u8, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110,
        91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
    ];
    let a1_iv = [227u8, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
    let a3 = r#"{{ head + "." + b64urlraw(aes_kw_wrap(kek, cek)) + "." + b64urlraw(iv) + "." + b64urlraw(aead_ciphertext(aes_cbc_hmac_encrypt(cek, iv, "Live long and prosper.", head))) + "." + b64urlraw(aead_tag(aes_cbc_hmac_encrypt(cek, iv, "Live long and prosper.", head))) }}"#;
    let a1 = r#"{{ b64urlraw(aead_ciphertext(aes_gcm_encrypt(cek1, iv1, "The true sign of intelligence is not knowledge but imagination.", head1))) + "." + b64urlraw(aead_tag(aes_gcm_encrypt(cek1, iv1, "The true sign of intelligence is not knowledge but imagination.", head1))) }}"#;
    let op = operation(json!({"name": "jwe", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "compute", "into": "head",
         "template": "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"},
        {"do": "compute", "into": "head1",
         "template": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/jwe"},
         "inject": [
            {"target": {"kind": "header", "name": "X-A1"}, "template": a1},
            {"target": {"kind": "body"}, "template": a3}]},
        {"do": "return"}
    ]}));
    let s = setup(
        &clock,
        vec![
            FieldSpec::secret("kek"),
            FieldSpec::secret("cek"),
            FieldSpec::public("iv"),
            FieldSpec::secret("cek1"),
            FieldSpec::public("iv1"),
        ],
        vec![op],
        &[
            ("kek", &unb64url("GawgguFyGrWKav7AX4VKUg")),
            ("cek", &a3_cek),
            ("iv", &a3_iv),
            ("cek1", &a1_cek),
            ("iv1", &a1_iv),
        ],
    );
    let mut server = FakeServer::default();
    call(&s, "jwe", None, &mut server).result.unwrap();
    let sent = server.request(0);
    assert_eq!(
        std::str::from_utf8(&sent.body).unwrap(),
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ"
    );
    assert_eq!(
        sent.field("X-A1"),
        "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    );
}

/// The server's RSA key of the JWE tests: the public half of the test fixture, as PEM.
fn server_public_pem() -> (rsa::PrivateKey, String) {
    use rsa::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _, LineEnding};
    let private =
        rsa::PrivateKey::from_pkcs8_der(&pem_body(include_str!("fixtures/rsa2048.pem"))).unwrap();
    let public = private
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    (private, public)
}

/// The `jwe-mixed` operation of `docs/policy.md`: the caller's JSON with a card number added
/// from the record, sealed with RSA-OAEP-256 and A256GCM. Before `aead_ciphertext`, this
/// policy was refused (rule 2: the ciphertext of a value that mixes the caller's bytes and a
/// secret cannot be cut by `slice`). The test opens each JWE: the content key with `rsa`, the
/// content with `aes-gcm`, the encoded header as AAD; a fresh key and IV each call.
#[test]
fn jwe_of_caller_bytes_and_a_secret_opens() {
    use aes_gcm::aead::Aead as _;
    use aes_gcm::{KeyInit as _, Nonce};
    let clock = TestClock::at(NOW);
    let (private, public_pem) = server_public_pem();
    let s = setup(
        &clock,
        vec![
            FieldSpec::secret("card_number"),
            FieldSpec::public("server_key"),
        ],
        vec![doc("jwe-mixed")],
        &[
            ("card_number", b"4111111111111111"),
            ("server_key", public_pem.as_bytes()),
        ],
    );
    let mut keys = Vec::new();
    for body in [
        &br#"{"amount":"12.00"}"#[..],
        br#"{"amount":"9.99","note":"x"}"#,
    ] {
        let mut server = FakeServer::default();
        let req = request(
            Method::Post,
            "api.example.com",
            443,
            "/v1/payments",
            &[],
            body,
        );
        call(&s, "jwe-mixed", Some(&req), &mut server)
            .result
            .unwrap();
        let sent = server.request(0);
        let compact = String::from_utf8(sent.body.clone()).unwrap();
        let parts: Vec<&str> = compact.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(
            json_of(&unb64url(parts[0])),
            json!({"alg": "RSA-OAEP-256", "enc": "A256GCM"})
        );
        let cek = private
            .decrypt(rsa::Oaep::<sha2::Sha256>::new(), &unb64url(parts[1]))
            .unwrap();
        let iv = unb64url(parts[2]);
        assert_eq!((cek.len(), iv.len()), (32, 12));
        let tag = unb64url(parts[4]);
        assert_eq!(tag.len(), 16);
        let sealed = [unb64url(parts[3]), tag].concat();
        let plaintext = aes_gcm::Aes256Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt(
                &Nonce::try_from(iv.as_slice()).unwrap(),
                aes_gcm::aead::Payload {
                    msg: &sealed,
                    aad: parts[0].as_bytes(),
                },
            )
            .expect("the JWE opens");
        let mut expected = json_of(body);
        expected["card"] = json!("4111111111111111");
        assert_eq!(json_of(&plaintext), expected);
        keys.push(cek);
    }
    assert_ne!(keys[0], keys[1], "a fresh content key each call");
}

/// `aead_ciphertext` and `aead_tag` take only an AEAD call written in place: a name, a
/// literal, a non-AEAD encryption, a nested cut or a missing argument is refused, so the cut
/// always falls where the algorithm puts the tag.
#[test]
fn aead_parts_take_only_an_aead_call_in_place() {
    let fields = || vec![FieldSpec::secret("key")];
    for template in [
        r#"{{ hex(aead_tag("0123456789abcdef0123")) }}"#,
        r#"{{ hex(aead_tag(key)) }}"#,
        r#"{{ hex(aead_tag($input)) }}"#,
        r#"{{ hex(aead_ciphertext(aes_cbc_encrypt("0123456789abcdef", "0123456789abcdef", $input))) }}"#,
        r#"{{ hex(aead_tag(aes_cts_encrypt("0123456789abcdef", "0123456789abcdef", $input))) }}"#,
        r#"{{ hex(aead_tag(aes_kw_wrap("0123456789abcdef", $input))) }}"#,
        r#"{{ hex(aead_tag(slice(aes_gcm_encrypt("0123456789abcdef", "000000000000", $input), "0", "16"))) }}"#,
        r#"{{ hex(aead_tag(aead_ciphertext(aes_gcm_encrypt("0123456789abcdef", "000000000000", $input)))) }}"#,
        r#"{{ hex(aead_tag(aes_gcm_encrypt("0123456789abcdef", "000000000000", $input) + "x")) }}"#,
    ] {
        assert_eq!(
            refused(fields(), vec![derivation("o", template)]),
            AEAD_IN_PLACE,
            "{template}"
        );
    }
    let computed = operation(json!({"name": "o", "input": {"raw": {}}, "steps": [
        {"do": "compute", "into": "sealed",
         "template": r#"{{ aes_gcm_encrypt("0123456789abcdef", "000000000000", $input) }}"#},
        {"do": "return", "template": "{{ hex(aead_tag(sealed)) }}"}
    ]}));
    assert_eq!(refused(fields(), vec![computed]), AEAD_IN_PLACE);
    assert_eq!(
        refused(fields(), vec![derivation("o", "{{ hex(aead_tag()) }}")]),
        "template syntax"
    );
}

/// Each part has exactly the properties of the encryption it comes from: under a secret key
/// with a message the caller chooses it can be handed back; with a secret in the message, or
/// under a key that is not a secret key, it stays tainted; a part of a mixed message is mixed,
/// so it cannot be cut or decoded either; and rule 9 still refuses every length that depends
/// on a secret, including the cut `slice` would need without the parts.
#[test]
fn aead_parts_keep_the_taint_of_the_encryption() {
    let fields = || {
        vec![
            FieldSpec::secret("key"),
            FieldSpec::secret("card_number"),
            FieldSpec::guessable("pin"),
        ]
    };
    let nonce = r#"slice(hexdecode($nonce), "0", "12")"#;
    for template in [
        format!(r#"{{{{ hex(aead_tag(aes_gcm_encrypt(key, {nonce}, $input))) }}}}"#),
        format!(r#"{{{{ hex(aead_ciphertext(aes_gcm_encrypt(key, {nonce}, $input))) }}}}"#),
        format!(r#"{{{{ hex(aead_tag(chacha20_poly1305_encrypt(key, {nonce}, $input, "a"))) }}}}"#),
    ] {
        DeviceKey::generate()
            .sign_policy(policy(fields(), vec![derivation("o", &template)]))
            .unwrap_or_else(|e| panic!("{template}: {e}"));
    }
    for template in [
        format!(r#"{{{{ hex(aead_tag(aes_gcm_encrypt(key, {nonce}, card_number))) }}}}"#),
        format!(
            r#"{{{{ hex(aead_ciphertext(aes_gcm_encrypt(key, {nonce}, $input, card_number))) }}}}"#
        ),
        r#"{{ hex(aead_tag(aes_gcm_encrypt("0123456789abcdef", "000000000000", card_number))) }}"#
            .to_string(),
        r#"{{ hex(aead_ciphertext(aes_eax_encrypt(sha256(key), "0123456789abcdef", key))) }}"#
            .to_string(),
    ] {
        assert_eq!(
            refused(fields(), vec![derivation("o", &template)]),
            RULE_5,
            "{template}"
        );
    }
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "o",
                &format!(r#"{{{{ hex(aead_tag(aes_gcm_encrypt(key, {nonce}, pin))) }}}}"#)
            )]
        ),
        RULE_5,
        "a guessable field is tainted too"
    );
    // A part of a mixed message is mixed: no cut, no decoder.
    let mixed = r#"aes_gcm_encrypt(cek, iv, json_set($body, "card", card_number))"#;
    let jwe = |body: &str| {
        operation(json!({"name": "o", "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "example.com", "port": 443}]},
            {"do": "compute", "into": "cek", "template": r#"{{ random("32") }}"#},
            {"do": "compute", "into": "iv", "template": r#"{{ random("12") }}"#},
            {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/"]},
             "inject": [{"target": {"kind": "body"}, "template": body}]},
            {"do": "return"}
        ]}))
    };
    for (body, rule) in [
        (
            format!(r#"{{{{ slice(aead_ciphertext({mixed}), "0", "1") }}}}"#),
            RULE_2,
        ),
        (format!(r#"{{{{ b64decode(aead_tag({mixed})) }}}}"#), RULE_1),
        // What the scheme needed before: cutting the whole output at a length the caller's
        // bytes set. Still refused.
        (
            format!(r#"{{{{ slice({mixed}, "0", len(json_set($body, "card", card_number))) }}}}"#),
            RULE_2,
        ),
    ] {
        assert_eq!(refused(fields(), vec![jwe(&body)]), rule, "{body}");
    }
    // Rule 9: a cut or a length that depends on a secret.
    for template in [
        r#"{{ hex(sha256(slice(aead_ciphertext(aes_gcm_encrypt("0123456789abcdef", "000000000000", "public text")), "0", key))) }}"#,
        r#"{{ hex(aead_tag(aes_ccm_encrypt("0123456789abcdef", "0123456789abc", key, $input))) }}"#,
        r#"{{ hex(sha256(random(key))) }}"#,
    ] {
        assert_eq!(
            refused(fields(), vec![derivation("o", template)]),
            RULE_9,
            "{template}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Public keys from private keys
// ---------------------------------------------------------------------------------------

/// `ed25519_public`, `ed448_public`, `ecdsa_public` and `rsa_public` against published key
/// pairs: RFC 8032 (Ed25519 TEST 1, Ed448 "Blank"), RFC 9421 B.1.4 (an Ed25519 key in
/// PKCS#8), RFC 6979 A.2.5 and A.2.6 (P-256, P-384), the secp256k1 generator, and the RSA test
/// key's modulus, exponent and encodings read by the `rsa` crate.
#[test]
fn public_keys_match_published_key_pairs() {
    use rsa::pkcs1::EncodeRsaPublicKey as _;
    use rsa::pkcs8::EncodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;
    let clock = TestClock::at(NOW);
    let names = ["ed", "edpk8", "ed448", "p256", "p384", "k256", "rsa"];
    let template = r#"{{ hex(ed25519_public(ed)) + "." + hex(ed25519_public(pem(edpk8))) + "." + hex(ed448_public(ed448)) + "." + hex(ecdsa_public("p256", p256)) + "." + hex(ecdsa_public("p384", p384)) + "." + hex(ecdsa_public("k256", k256)) + "." + hex(rsa_public("n", pem(rsa))) + "." + hex(rsa_public("e", pem(rsa))) + "." + hex(rsa_public("spki", pem(rsa))) + "." + hex(rsa_public("pkcs1", pem(rsa))) }}"#;
    let rsa_pem = include_str!("fixtures/rsa2048.pem");
    let s = setup(
        &clock,
        names.iter().map(|n| FieldSpec::secret(n)).collect(),
        vec![derivation("pk", template)],
        &[
            ("ed", &unhex(ED25519_SECRET)),
            ("edpk8", ED25519_PEM.as_bytes()),
            ("ed448", &unhex(ED448_SECRET)),
            ("p256", &unhex(P256_SECRET)),
            ("p384", &unhex(P384_SECRET)),
            ("k256", &unhex(K256_ONE)),
            ("rsa", rsa_pem.as_bytes()),
        ],
    );
    let out = String::from_utf8(derive(&s, "pk", b"")).unwrap();
    let parts: Vec<&str> = out.split('.').collect();
    let (private, _) = server_public_pem();
    let public = private.to_public_key();
    let strip = |bytes: Vec<u8>| {
        let first = bytes.iter().position(|b| *b != 0).unwrap();
        bytes[first..].to_vec()
    };
    let expected = [
        ED25519_PUBLIC.to_string(),
        hex(&STANDARD.decode(ED25519_PUBLIC_SPKI).unwrap()[12..]),
        ED448_PUBLIC.to_string(),
        format!("04{P256_PUBLIC}"),
        format!("04{P384_PUBLIC}"),
        format!("04{K256_G}"),
        hex(&strip(public.n().to_be_bytes().to_vec())),
        hex(&strip(public.e().to_be_bytes().to_vec())),
        hex(public.to_public_key_der().unwrap().as_bytes()),
        hex(public.to_pkcs1_der().unwrap().as_bytes()),
    ];
    assert_eq!(parts.len(), expected.len());
    for (i, (got, want)) in parts.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "public key {i}");
    }
    assert_eq!(parts[7], "010001");
}

/// On the curves with no published key pair here, the derived key verifies a signature the
/// engine makes with the private key: P-521 and brainpool by the `ecdsa` crate's verifier,
/// SM2 by the `sm2` crate's, PKCS#8 input included.
#[test]
fn public_keys_verify_signatures_on_every_curve() {
    use ecdsa::signature::Verifier as _;
    use ecdsa::signature::hazmat::PrehashVerifier as _;
    let clock = TestClock::at(NOW);
    let template = r#"{{ hex(ecdsa_public("p521", p521)) + "." + hex(ecdsa_sign_prehash("p521", p521, sha512("m"))) + "." + hex(ecdsa_public("bp256", bp256)) + "." + hex(ecdsa_sign_prehash("bp256", bp256, sha256("m"))) + "." + hex(ecdsa_public("bp384", bp384)) + "." + hex(ecdsa_sign_prehash("bp384", bp384, sha384("m"))) + "." + hex(ecdsa_public("sm2", sm2)) + "." + hex(sm2_sign(sm2, "m")) }}"#;
    let s = setup(
        &clock,
        ["p521", "bp256", "bp384", "sm2"]
            .iter()
            .map(|n| FieldSpec::secret(n))
            .collect(),
        vec![derivation("pk", template)],
        &[
            ("p521", &unhex(P521_SECRET)),
            ("bp256", &unhex(BP256_SECRET)),
            ("bp384", &unhex(BP384_SECRET)),
            ("sm2", &unhex(SM2_SECRET)),
        ],
    );
    let out = String::from_utf8(derive(&s, "pk", b"")).unwrap();
    let p: Vec<Vec<u8>> = out.split('.').map(unhex).collect();
    assert_eq!(
        (p[0].len(), p[2].len(), p[4].len(), p[6].len()),
        (133, 65, 97, 65)
    );
    let p521 = p521::ecdsa::VerifyingKey::from_sec1_bytes(&p[0]).unwrap();
    p521.verify_prehash(
        &sha2::Sha512::digest(b"m"),
        &p521::ecdsa::Signature::from_slice(&p[1]).unwrap(),
    )
    .expect("P-521 verifies under the derived key");
    let bp256 = ecdsa::VerifyingKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(&p[2]).unwrap();
    bp256
        .verify_prehash(
            &sha2::Sha256::digest(b"m"),
            &ecdsa::Signature::from_slice(&p[3]).unwrap(),
        )
        .expect("brainpoolP256r1 verifies under the derived key");
    let bp384 = ecdsa::VerifyingKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(&p[4]).unwrap();
    bp384
        .verify_prehash(
            &sha2::Sha384::digest(b"m"),
            &ecdsa::Signature::from_slice(&p[5]).unwrap(),
        )
        .expect("brainpoolP384r1 verifies under the derived key");
    let sm2 = sm2::dsa::VerifyingKey::from_sec1_bytes("1234567812345678", &p[6]).unwrap();
    sm2.verify(
        b"m",
        &sm2::dsa::Signature::try_from(p[7].as_slice()).unwrap(),
    )
    .expect("SM2 verifies under the derived key");
}

/// The `jws-eddsa-jwk` operation of `docs/policy.md` with the key of RFC 8037 appendix A.1:
/// the header's `x` is the public key that appendix publishes, and ring verifies the JWS
/// under the key the header names. (Before `ed25519_public`, the JWK needed a public field.)
#[test]
fn jws_with_the_jwk_of_its_own_ed25519_key() {
    use ring::signature::{ED25519, UnparsedPublicKey};
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![doc("jws-eddsa-jwk")],
        &[("key", &unhex(ED25519_SECRET))],
    );
    let jws =
        String::from_utf8(derive(&s, "jws-eddsa-jwk", b"Example of Ed25519 signing")).unwrap();
    let parts: Vec<&str> = jws.split('.').collect();
    let header = json_of(&unb64url(parts[0]));
    assert_eq!(
        header["jwk"]["x"],
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
    assert_eq!(unb64url(parts[1]), b"Example of Ed25519 signing");
    let x = unb64url(header["jwk"]["x"].as_str().unwrap());
    UnparsedPublicKey::new(&ED25519, &x)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &unb64url(parts[2]),
        )
        .expect("the JWS verifies under its own jwk");
}

/// An RS256 JWS whose header carries the RSA JWK of the signing key (`n` and `e` from
/// `rsa_public`); ring verifies it from those two members alone.
#[test]
fn jws_with_the_jwk_of_its_own_rsa_key() {
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
    let clock = TestClock::at(NOW);
    let op = operation(json!({"name": "rs256", "input": {"raw": {}}, "steps": [
        {"do": "compute", "into": "header",
         "template": r#"{"alg":"RS256","jwk":{"kty":"RSA","n":"{{ b64urlraw(rsa_public("n", pem(key))) }}","e":"{{ b64urlraw(rsa_public("e", pem(key))) }}"}}"#},
        {"do": "compute", "into": "head", "template": "{{ b64urlraw(header) }}"},
        {"do": "return",
         "template": r#"{{ head + "." + b64urlraw($input) + "." + b64urlraw(rsa_sign_pkcs1("sha256", pem(key), head + "." + b64urlraw($input))) }}"#}
    ]}));
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![op],
        &[("key", include_str!("fixtures/rsa2048.pem").as_bytes())],
    );
    let jws = String::from_utf8(derive(&s, "rs256", br#"{"sub":"x"}"#)).unwrap();
    let parts: Vec<&str> = jws.split('.').collect();
    let header = json_of(&unb64url(parts[0]));
    assert_eq!(header["jwk"]["e"], "AQAB");
    let n = unb64url(header["jwk"]["n"].as_str().unwrap());
    assert_eq!(
        n.len(),
        256,
        "the modulus of a 2048-bit key, no leading zero"
    );
    RsaPublicKeyComponents {
        n: &n,
        e: &unb64url("AQAB"),
    }
    .verify(
        &RSA_PKCS1_2048_8192_SHA256,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &unb64url(parts[2]),
    )
    .expect("RS256 verifies under the jwk");
}

/// The public key functions follow the rules: one-way (a derivation may hand back the public
/// key of a secret), the curve and form fixed by the policy (rule 6), the key never mixed with
/// a chosen value (rule 1), and a public key of a guessable field still lets guesses be
/// checked.
#[test]
fn public_key_functions_follow_the_rules() {
    let fields = || vec![FieldSpec::secret("key"), FieldSpec::guessable("pin")];
    for template in [
        r#"{{ hex(ed25519_public(key)) }}"#,
        r#"{{ hex(ed448_public(key)) }}"#,
        r#"{{ hex(ecdsa_public("p256", key)) }}"#,
        r#"{{ hex(rsa_public("n", key)) }}"#,
    ] {
        DeviceKey::generate()
            .sign_policy(policy(fields(), vec![derivation("o", template)]))
            .unwrap_or_else(|e| panic!("{template}: {e}"));
    }
    for (template, rule) in [
        (r#"{{ hex(ecdsa_public($input, key)) }}"#, RULE_6),
        (r#"{{ hex(rsa_public($input, key)) }}"#, RULE_6),
        (r#"{{ hex(ecdsa_public(key, key)) }}"#, RULE_6),
        (r#"{{ hex(ed25519_public(key + $input)) }}"#, RULE_1),
        (r#"{{ hex(ed448_public(key + $input)) }}"#, RULE_1),
        (r#"{{ hex(ecdsa_public("p256", key + $input)) }}"#, RULE_1),
        (r#"{{ hex(rsa_public("n", key + $input)) }}"#, RULE_1),
        (
            r#"{{ hex(ed25519_public(pin)) }}"#,
            "a derivation would hand back a check for guesses of a guessable field",
        ),
    ] {
        assert_eq!(
            refused(fields(), vec![derivation("o", template)]),
            rule,
            "{template}"
        );
    }
}
