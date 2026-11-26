//! The schemes `docs/design.md` section 11 listed as needing primitives the engine lacked, each
//! with the standard family it needed: OAuth 1.0a (RFC 5849) over `sorted_params`; the
//! ECDSA P-256 key of AWS Signature Version 4A, derived by `kbkdf_ec_key` (NIST SP 800-108
//! counter mode and the rejection sampling of FIPS 186-5 appendix A.2.2); NTLMv2 (MS-NLMP)
//! over HTTP on one TLS connection, with `utf16le`, `uint_le` and the weak `md4`.
//!
//! The policies are the operations of `docs/policy.md` (Parameter lists, derived EC keys and
//! binary messages), read from that file. Each scheme is checked against the published
//! vectors (RFC 5849 sections 1.2 and 3.4.1, MS-NLMP section 4.2.4) and by a verifier written
//! here over crates that are not the engine's code path for that value (`hmac`, `md4`,
//! `md-5`, `p256`, `ring`, `rsa`), and every guarantee has its attack.
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
use base64::engine::general_purpose::STANDARD;
use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Clock, Node, Outcome, Response, StreamOutput};
use engine::policy::summary::{FlagCode, summarize};
use engine::policy::{Caller, Destination, FieldSpec, Method, Operation, Policy};
use engine::record::Record;
use engine::request::Request;
use hmac::{KeyInit as _, Mac as _};
use serde_json::{Value, json};
use sha2::Digest as _;

const OWNER: &str = "user-1";
/// 2027-01-15T08:00:00Z.
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

const RULE_1: &str = "a secret mixed with a chosen value reaches a decoder, number or key";
const RULE_2: &str = "a secret and a chosen value meet in a function that compares or cuts them";
const RULE_5: &str = "a derivation would hand a secret back";
const RULE_5_GUESS: &str = "a derivation would hand back a check for guesses of a guessable field";
const RULE_6: &str = "a hash or curve name must be fixed by the policy";
const RULE_9: &str = "a length must not depend on a secret";

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

/// A fake server: HTTPS requests are answered from `replies` in order and recorded; a TLS
/// connection answers each read from `reads` and records each write.
#[derive(Default)]
struct FakeServer {
    replies: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    reads: VecDeque<Vec<u8>>,
    written: Vec<Vec<u8>>,
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
        Ok(Box::new(FakeStream(self)))
    }
}

struct FakeStream<'a>(&'a mut FakeServer);

impl Stream for FakeStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.written.push(bytes.to_vec());
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        self.0
            .reads
            .pop_front()
            .ok_or(Error::transport(TransportKind::Closed, false))
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
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
            .unwrap_or_else(|| panic!("no header {name}"))
    }

    fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map_or(self.target.as_str(), |(p, _)| p)
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
    let clean: String = text.split_whitespace().collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

/// The operation `name` of `docs/policy.md`.
fn doc(name: &str) -> Operation {
    operation(doc_value(name))
}

fn doc_value(name: &str) -> Value {
    let text = POLICY_MD.replace("\r\n", "\n");
    let mut rest = text.as_str();
    while let Some(start) = rest.find("```json\n") {
        let body = &rest[start + 8..];
        let end = body.find("```").unwrap();
        let value = serde_json::from_str::<Value>(&body[..end]).unwrap_or(Value::Null);
        if value.get("steps").is_some() && value.get("name").and_then(Value::as_str) == Some(name) {
            return value;
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

fn call_stream(
    s: &Setup<'_>,
    operation: &str,
    destination: &Destination,
    exchanges: &[CallerExchange],
    server: &mut FakeServer,
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
            operation,
            &payload,
            now(),
        )
        .unwrap();
    s.node
        .stream(&s.record, operation, &auth, destination, exchanges, server)
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
    s.node
        .derive(&s.record, operation, &auth, input)
        .unwrap_or_else(|e| panic!("{operation}: {e}"))
}

/// An operation with no connection that returns `template` over a raw `$input`.
fn derivation(name: &str, template: &str) -> Operation {
    operation(json!({"name": name, "input": {"raw": {}},
        "steps": [{"do": "return", "template": template}]}))
}

/// Renders `template` as a derivation with the record `values` (all secret fields).
fn render(template: &str, values: &[(&str, &[u8])]) -> Vec<u8> {
    let clock = TestClock::at(NOW);
    // A policy has at least one field.
    let mut values = values.to_vec();
    values.push(("unused", b"-"));
    let fields = values.iter().map(|(n, _)| FieldSpec::secret(n)).collect();
    let s = setup(&clock, fields, vec![derivation("d", template)], &values);
    derive(&s, "d", b"")
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_md5(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(key).unwrap();
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------------------
// OAuth 1.0a (RFC 5849)
// ---------------------------------------------------------------------------------------

/// RFC 3986 percent-encoding of everything but the unreserved characters, written here (RFC
/// 5849 section 3.6).
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

/// `application/x-www-form-urlencoded` decoding (`+` is a space).
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

/// The normalized parameters of RFC 5849 section 3.4.1.3.2, written here.
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

/// The parameters of an `Authorization: OAuth ...` header, values decoded.
fn oauth_params(header: &str) -> Vec<(String, String)> {
    header
        .strip_prefix("OAuth ")
        .unwrap()
        .split(", ")
        .map(|p| {
            let (n, v) = p.split_once('=').unwrap();
            let v = v.strip_prefix('"').unwrap().strip_suffix('"').unwrap();
            (n.to_string(), String::from_utf8(form_decode(v)).unwrap())
        })
        .collect()
}

/// The signature base string of RFC 5849 section 3.4.1 of a request as the server read it:
/// the method, the base string URI and every parameter but `oauth_signature`.
fn base_string(sent: &Sent, host: &str) -> (String, Vec<(String, String)>) {
    let params = oauth_params(sent.header("Authorization"));
    let protocol: Vec<String> = params
        .iter()
        .filter(|(n, _)| n != "oauth_signature")
        .map(|(n, v)| format!("{}={}", rfc3986(n.as_bytes()), rfc3986(v.as_bytes())))
        .collect();
    let protocol = protocol.join("&");
    let body = std::str::from_utf8(&sent.body).unwrap();
    let base = format!(
        "{}&{}&{}",
        sent.method,
        rfc3986(format!("https://{host}{}", sent.path()).as_bytes()),
        rfc3986(normalized(&[sent.query(), body, &protocol]).as_bytes())
    );
    (base, params)
}

fn param<'p>(params: &'p [(String, String)], name: &str) -> &'p str {
    &params.iter().find(|(n, _)| n == name).unwrap().1
}

const CONSUMER_SECRET: &[u8] = b"kd94hf93k423kf44";
const TOKEN_SECRET: &[u8] = b"pfkkdhi9sl3r4s00";

fn oauth_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::public("consumer_key"),
        FieldSpec::secret("consumer_secret"),
        FieldSpec::public("token"),
        FieldSpec::secret("token_secret"),
        FieldSpec::secret("key"),
    ]
}

fn oauth_values() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("consumer_key", b"dpf43f3p2l4k3l03".to_vec()),
        ("consumer_secret", CONSUMER_SECRET.to_vec()),
        ("token", b"nnch734d00sl2jdk".to_vec()),
        ("token_secret", TOKEN_SECRET.to_vec()),
        (
            "key",
            include_str!("fixtures/rsa2048.pem").as_bytes().to_vec(),
        ),
    ]
}

fn oauth_setup<'c>(clock: &'c TestClock, operations: Vec<Operation>) -> Setup<'c> {
    let values = oauth_values();
    let refs: Vec<(&str, &[u8])> = values.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    setup(clock, oauth_fields(), operations, &refs)
}

/// The caller's request: a POST with a query and a form body whose values hold a space, a
/// `+`, a reserved character and non-ASCII text.
fn oauth_request() -> Request {
    Request {
        method: Method::Post,
        destination: Destination::new("api.example.com", 443),
        path: "/1.1/statuses/update?count=20&q=tea%20and%20cake".into(),
        headers: Vec::new(),
        body: b"status=Hello+Ladies+%2B+Gentlemen%2C+a+signed+OAuth+request%21+caf%C3%A9&include_entities=true"
            .to_vec(),
    }
}

/// RFC 5849 section 1.2 (the photo example; the RFC gives the secrets) and section 3.4.1.1
/// (the base string of the request of section 3.4.1, of which the RFC gives no secrets):
/// the signature and the base string, byte for byte, as templates write them.
#[test]
fn oauth1_rfc5849_vectors() {
    let signature = render(
        r#"{{ b64(hmac_sha1(pct(consumer_secret) + "&" + pct(token_secret), "GET&" + pct("http://photos.example.net/photos") + "&" + pct(sorted_params("file=vacation.jpg&size=original", "oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131202&oauth_nonce=chapoH")))) }}"#,
        &[
            ("consumer_secret", CONSUMER_SECRET),
            ("token_secret", TOKEN_SECRET),
        ],
    );
    assert_eq!(signature, b"MdpQcU8iPSUjWoN/UDMsK2sui9I=");

    let base = render(
        r#"{{ "POST&" + pct("http://example.com/request") + "&" + pct(sorted_params("b5=%3D%253D&a3=a&c%40=&a2=r%20b", "c2&a3=2+q", "oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a")) }}"#,
        &[],
    );
    assert_eq!(
        String::from_utf8(base).unwrap(),
        "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
    );
}

/// The `oauth1-hmac-sha1` operation of `docs/policy.md` signs the caller's request: the base
/// string rebuilt from the wire with the normalization written in this test, the HMAC-SHA1
/// recomputed with the `hmac` crate. Two calls: fresh nonces, both verify.
#[test]
fn oauth1_hmac_sha1_signs_the_callers_query_and_form_body() {
    let clock = TestClock::at(NOW);
    let s = oauth_setup(&clock, vec![doc("oauth1-hmac-sha1")]);
    let mut server = FakeServer::default();
    for _ in 0..2 {
        call(&s, "oauth1-hmac-sha1", Some(&oauth_request()), &mut server)
            .result
            .unwrap();
    }
    let mut nonces = Vec::new();
    for wire in &server.sent {
        let sent = parse(wire);
        assert_eq!(
            sent.header("Content-Type"),
            "application/x-www-form-urlencoded"
        );
        let (base, params) = base_string(&sent, "api.example.com");
        assert_eq!(param(&params, "oauth_signature_method"), "HMAC-SHA1");
        assert_eq!(param(&params, "oauth_consumer_key"), "dpf43f3p2l4k3l03");
        assert_eq!(param(&params, "oauth_timestamp"), "1800000000");
        assert_eq!(param(&params, "oauth_version"), "1.0");
        nonces.push(param(&params, "oauth_nonce").to_string());
        let mut key = rfc3986(CONSUMER_SECRET);
        key.push('&');
        key.push_str(&rfc3986(TOKEN_SECRET));
        let expected = STANDARD.encode(hmac_sha1(key.as_bytes(), base.as_bytes()));
        assert_eq!(param(&params, "oauth_signature"), expected);
        assert!(base.contains("q%3Dtea%2520and%2520cake"));
        assert!(base.contains("request%2521%2520caf%25C3%25A9"));
        assert!(base.contains("status%3DHello%2520Ladies%2520%252B%2520Gentlemen"));
    }
    assert_ne!(nonces[0], nonces[1]);
}

/// The `oauth1-rsa-sha1` operation: the same base string signed with RSASSA-PKCS1-v1_5 and
/// SHA-1 (RFC 5849 section 3.4.3), verified by the `rsa` crate; and PLAINTEXT (section
/// 3.4.4), the two secrets encoded, sent over TLS only.
#[test]
fn oauth1_rsa_sha1_and_plaintext() {
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::signature::Verifier as _;
    let plaintext = operation(json!({"name": "oauth1-plaintext", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/oauth/request_token"},
         "inject": [{"target": {"kind": "header", "name": "Authorization"},
                     "template": "OAuth oauth_consumer_key=\"{{ pct(consumer_key) }}\", oauth_signature_method=\"PLAINTEXT\", oauth_signature=\"{{ pct(pct(consumer_secret) + \"&\" + pct(token_secret)) }}\""}]},
        {"do": "return", "response": {"body": "all"}}
    ]}));
    let clock = TestClock::at(NOW);
    let s = oauth_setup(&clock, vec![doc("oauth1-rsa-sha1"), plaintext]);
    let mut server = FakeServer::default();
    call(&s, "oauth1-rsa-sha1", Some(&oauth_request()), &mut server)
        .result
        .unwrap();
    call(&s, "oauth1-plaintext", None, &mut server)
        .result
        .unwrap();

    let sent = parse(&server.sent[0]);
    let (base, params) = base_string(&sent, "api.example.com");
    assert_eq!(param(&params, "oauth_signature_method"), "RSA-SHA1");
    let private =
        rsa::PrivateKey::from_pkcs8_der(&pem_body(include_str!("fixtures/rsa2048.pem"))).unwrap();
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(private.to_public_key());
    let signature = STANDARD.decode(param(&params, "oauth_signature")).unwrap();
    let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
    assert!(verifier.verify(base.as_bytes(), &signature).is_ok());

    let sent = parse(&server.sent[1]);
    let params = oauth_params(sent.header("Authorization"));
    let mut expected = rfc3986(CONSUMER_SECRET);
    expected.push('&');
    expected.push_str(&rfc3986(TOKEN_SECRET));
    assert!(
        param(&params, "oauth_signature") == expected,
        "the PLAINTEXT signature is not the encoded secrets"
    );
}

/// What `sorted_params` holds to: a secret and the caller's parameters may not meet in it
/// (sorting compares them: rule 2), a secret mixed into one list with chosen bytes is refused
/// too (rule 2), a sorted list of a secret is not handed back (rule 5), and a list that is not
/// well formed fails before anything is sent.
#[test]
fn oauth1_parameter_lists_refuse_secrets_beside_chosen_values() {
    let fields = || vec![FieldSpec::secret("secret")];
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                "{{ hex(sha256(sorted_params($input, \"k=\" + secret))) }}"
            )]
        ),
        RULE_2
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                "{{ hex(sha256(sorted_params($input + secret))) }}"
            )]
        ),
        RULE_2
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation("d", "{{ sorted_params(\"k=\" + secret) }}")]
        ),
        RULE_5
    );

    // A body that is not a well-formed form list (a lone `%`) is refused at rendering; the
    // request is never sent.
    let clock = TestClock::at(NOW);
    let s = oauth_setup(&clock, vec![doc("oauth1-hmac-sha1")]);
    let mut server = FakeServer::default();
    let mut bad = oauth_request();
    bad.body = b"status=100%".to_vec();
    let result = call(&s, "oauth1-hmac-sha1", Some(&bad), &mut server).result;
    assert!(result.is_err());
    assert!(server.sent.is_empty());
}

// ---------------------------------------------------------------------------------------
// The ECDSA key of AWS Signature Version 4A
// ---------------------------------------------------------------------------------------

/// The example credentials of the AWS documentation (test values, not a real key).
const ACCESS_KEY_ID: &str = "AKIDEXAMPLE";
const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

/// The SigV4A private key derived here with `hmac` and byte arithmetic, not the engine: NIST
/// SP 800-108 counter mode with `i = 1` and `L = 256` over the fixed input
/// `"AWS4-ECDSA-P256-SHA256" || 0x00 || access key id || counter`, the first candidate
/// `c <= n - 2` giving `d = c + 1` (both 32 big-endian bytes, so the comparison is the
/// comparison of the byte strings).
fn sigv4a_key() -> Vec<u8> {
    let mut n_minus_2 = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    n_minus_2[31] -= 2;
    let key = format!("AWS4A{SECRET_ACCESS_KEY}");
    for counter in 1u8..=254 {
        let mut fixed = 1u32.to_be_bytes().to_vec();
        fixed.extend_from_slice(b"AWS4-ECDSA-P256-SHA256\0");
        fixed.extend_from_slice(ACCESS_KEY_ID.as_bytes());
        fixed.push(counter);
        fixed.extend_from_slice(&256u32.to_be_bytes());
        let mut c = hmac_sha256(key.as_bytes(), &fixed);
        if c <= n_minus_2 {
            for byte in c.iter_mut().rev() {
                let (sum, carry) = byte.overflowing_add(1);
                *byte = sum;
                if !carry {
                    break;
                }
            }
            return c;
        }
    }
    panic!("no candidate")
}

/// SigV4 canonical query (sorted, RFC 3986 encoded), written here.
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, v) = p.split_once('=').unwrap_or((p, ""));
            (
                rfc3986(&form_decode(&n.replace('+', "%2B"))),
                rfc3986(&form_decode(&v.replace('+', "%2B"))),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The `sigv4a` operation of `docs/policy.md`: the key `kbkdf_ec_key` derives equals the one
/// derived here; the ECDSA P-256 signature of each request (DER, SHA-256) verifies with ring
/// under that key's public key, over a string to sign rebuilt from the wire.
#[test]
fn sigv4a_key_derivation_and_signature_verify() {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    let expected_key = sigv4a_key();
    let public = {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        p256::SecretKey::from_slice(&expected_key)
            .unwrap()
            .public_key()
            .as_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    };

    // The derived key's public key, as a derivation may hand it back (one-way).
    let clock = TestClock::at(NOW);
    let fields = vec![
        FieldSpec::public("access_key_id"),
        FieldSpec::secret("secret_access_key"),
    ];
    let public_of = derivation(
        "sigv4a-public",
        "{{ hex(ecdsa_public(\"p256\", kbkdf_ec_key(\"p256\", \"sha256\", \"AWS4A\" + secret_access_key, \"AWS4-ECDSA-P256-SHA256\\0\" + access_key_id, be32(\"256\")))) }}",
    );
    let values: [(&str, &[u8]); 2] = [
        ("access_key_id", ACCESS_KEY_ID.as_bytes()),
        ("secret_access_key", SECRET_ACCESS_KEY.as_bytes()),
    ];
    let s = setup(&clock, fields, vec![doc("sigv4a"), public_of], &values);
    assert_eq!(derive(&s, "sigv4a-public", b""), hex(&public).into_bytes());

    let mut server = FakeServer::default();
    for (method, path, body) in [
        (
            Method::Get,
            "/bucket/photos/a.jpg?versionId=3&list-type=2",
            &b""[..],
        ),
        (Method::Put, "/bucket/notes/b.txt", &b"some bytes"[..]),
    ] {
        let request = Request {
            method,
            destination: Destination::new("s3.example.com", 443),
            path: path.into(),
            headers: Vec::new(),
            body: body.to_vec(),
        };
        call(&s, "sigv4a", Some(&request), &mut server)
            .result
            .unwrap();
    }
    for wire in &server.sent {
        let sent = parse(wire);
        let date = sent.header("X-Amz-Date");
        assert_eq!(date, "20270115T080000Z");
        assert_eq!(sent.header("X-Amz-Region-Set"), "*");
        let payload = hex(&sha2::Sha256::digest(&sent.body));
        assert_eq!(sent.header("X-Amz-Content-Sha256"), payload);
        let canonical = format!(
            "{}\n{}\n{}\nhost:s3.example.com\nx-amz-content-sha256:{payload}\nx-amz-date:{date}\nx-amz-region-set:*\n\nhost;x-amz-content-sha256;x-amz-date;x-amz-region-set\n{payload}",
            sent.method,
            sent.path(),
            canonical_query(sent.query()),
        );
        let to_sign = format!(
            "AWS4-ECDSA-P256-SHA256\n{date}\n20270115/s3/aws4_request\n{}",
            hex(&sha2::Sha256::digest(canonical.as_bytes()))
        );
        let authorization = sent.header("Authorization");
        assert!(authorization.starts_with(
            "AWS4-ECDSA-P256-SHA256 Credential=AKIDEXAMPLE/20270115/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, Signature="
        ));
        let signature = unhex(authorization.rsplit_once("Signature=").unwrap().1);
        assert!(
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                .verify(to_sign.as_bytes(), &signature)
                .is_ok()
        );
    }
}

/// The derived key is a secret (rule 8): a derivation cannot hand it back, and the curve and
/// hash are the policy's (rule 6).
#[test]
fn sigv4a_derived_key_stays_in_the_node() {
    let fields = || vec![FieldSpec::secret("secret")];
    let derived = "kbkdf_ec_key(\"p256\", \"sha256\", secret, \"label\\0\", be32(\"256\"))";
    assert_eq!(
        refused(
            fields(),
            vec![derivation("d", &format!("{{{{ hex({derived}) }}}}"))]
        ),
        RULE_5
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                &format!("{{{{ hex(sha256({derived})) }}}}")
            )]
        ),
        RULE_5
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                "{{ hex(kbkdf_ec_key($input, \"sha256\", secret, \"l\", \"\")) }}"
            )]
        ),
        RULE_6
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                "{{ hex(kbkdf_ec_key(\"p256\", $input, secret, \"l\", \"\")) }}"
            )]
        ),
        RULE_6
    );
    // A signature with it is one-way, as with any key.
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        fields(),
        vec![derivation(
            "d",
            &format!("{{{{ hex(p256_sign({derived}, $input)) }}}}"),
        )],
        &[("secret", b"0123456789abcdef0123456789abcdef")],
    );
    assert_eq!(derive(&s, "d", b"message").len(), 128);
}

// ---------------------------------------------------------------------------------------
// NTLMv2 (MS-NLMP) over HTTP
// ---------------------------------------------------------------------------------------

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn md4(bytes: &[u8]) -> Vec<u8> {
    md4::Md4::digest(bytes).to_vec()
}

/// MS-NLMP section 4.2.4 (NTLMv2 authentication): NTOWFv2 (4.2.4.1.1), the LMv2 response
/// (4.2.4.2.1), NTProofStr and the session base key (4.2.4.2.2, 4.1.? the `temp` of section
/// 3.3.2 with the AV pairs of the challenge of 4.2.4.3), as templates compute them, byte for
/// byte. The encrypted random session key of 4.2.4.2.3 needs RC4, which is not offered.
#[test]
fn ntlmv2_ms_nlmp_vectors() {
    let ntowf = "hmac_md5(md4(utf16le(\"Password\")), utf16le(upper(\"User\") + \"Domain\"))";
    let temp = "hexdecode(\"0101000000000000\") + hexdecode(\"0000000000000000\") + hexdecode(\"aaaaaaaaaaaaaaaa\") + hexdecode(\"00000000\") + le16(\"2\") + le16(len(utf16le(\"Domain\"))) + utf16le(\"Domain\") + le16(\"1\") + le16(len(utf16le(\"Server\"))) + utf16le(\"Server\") + hexdecode(\"00000000\") + hexdecode(\"00000000\")";
    let challenge = "hexdecode(\"0123456789abcdef\")";
    let template = format!(
        "{{{{ hex({ntowf}) + \",\" + hex(hmac_md5({ntowf}, {challenge} + hexdecode(\"aaaaaaaaaaaaaaaa\")) + hexdecode(\"aaaaaaaaaaaaaaaa\")) + \",\" + hex(hmac_md5({ntowf}, {challenge} + {temp})) + \",\" + hex(hmac_md5({ntowf}, hmac_md5({ntowf}, {challenge} + {temp}))) }}}}"
    );
    let out = String::from_utf8(render(&template, &[])).unwrap();
    assert_eq!(
        out.split(',').collect::<Vec<_>>(),
        [
            "0c868a403bfd7a93a3001ef22ef02e3f",
            "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa",
            "68cd0ab851e51c96aabc927bebef6a1c",
            "8de40ccadbc14a82f15cb0ad0de95ca3",
        ]
    );
}

const NTLM_FLAGS: u32 = 0xa289_8205;
const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const SERVER_TIME: [u8; 8] = [0x00, 0x80, 0x3e, 0xd5, 0xde, 0xb1, 0x9d, 0x01];

fn av(id: u16, value: &[u8]) -> Vec<u8> {
    let mut out = id.to_le_bytes().to_vec();
    out.extend((value.len() as u16).to_le_bytes());
    out.extend(value);
    out
}

/// The server's target information: names, a timestamp (so the client must send a MIC,
/// MS-NLMP 3.1.5.1.2), the end.
fn target_info() -> Vec<u8> {
    let mut out = av(2, &utf16("CORP"));
    out.extend(av(1, &utf16("WEB01")));
    out.extend(av(4, &utf16("corp.example.com")));
    out.extend(av(7, &SERVER_TIME));
    out.extend(av(0, &[]));
    out
}

/// A CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) built here.
fn challenge_message() -> Vec<u8> {
    let name = utf16("CORP");
    let info = target_info();
    let mut out = b"NTLMSSP\0".to_vec();
    out.extend(2u32.to_le_bytes());
    out.extend((name.len() as u16).to_le_bytes());
    out.extend((name.len() as u16).to_le_bytes());
    out.extend(56u32.to_le_bytes());
    out.extend(NTLM_FLAGS.to_le_bytes());
    out.extend(SERVER_CHALLENGE);
    out.extend([0u8; 8]);
    out.extend((info.len() as u16).to_le_bytes());
    out.extend((info.len() as u16).to_le_bytes());
    out.extend(((56 + name.len()) as u32).to_le_bytes());
    out.extend(unhex("0a00614a0000000f"));
    out.extend(name);
    out.extend(info);
    out
}

fn field(message: &[u8], at: usize) -> &[u8] {
    let len = u16::from_le_bytes([message[at], message[at + 1]]) as usize;
    let offset = u32::from_le_bytes(message[at + 4..at + 8].try_into().unwrap()) as usize;
    &message[offset..offset + len]
}

fn ntlm_token(written: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(written).unwrap();
    let start = text.find("Authorization: NTLM ").unwrap() + "Authorization: NTLM ".len();
    let end = start + text[start..].find("\r\n").unwrap();
    STANDARD.decode(&text[start..end]).unwrap()
}

fn ntlm_setup<'c>(clock: &'c TestClock) -> Setup<'c> {
    setup(
        clock,
        vec![
            FieldSpec::public("user"),
            FieldSpec::public("domain"),
            FieldSpec::guessable("password"),
        ],
        vec![doc("ntlm-http")],
        &[
            ("user", b"svc-reports"),
            ("domain", b"CORP"),
            ("password", b"Winter2027!"),
        ],
    )
}

/// The `ntlm-http` operation of `docs/policy.md` on one TLS connection: NEGOTIATE, the
/// server's 401 with its CHALLENGE, then AUTHENTICATE with the request, then the caller's
/// requests on the authenticated connection. The AUTHENTICATE message is read back here:
/// NTProofStr recomputed with the `md4` and `hmac` crates, the server's timestamp in the
/// blob, `MsvAvFlags` announcing the MIC, and the MIC itself over the three messages.
#[test]
fn ntlmv2_over_one_tls_connection_verifies() {
    let clock = TestClock::at(NOW);
    let s = ntlm_setup(&clock);
    let mut server = FakeServer::default();
    let challenge = challenge_message();
    server.reads.extend([
        format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\n\r\n",
            STANDARD.encode(&challenge)
        )
        .into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]".to_vec(),
    ]);
    let exchanges = [CallerExchange {
        send: b"GET /api/reports/today HTTP/1.1\r\nHost: intranet.example.com\r\n\r\n".to_vec(),
        until: vec![b"\r\n\r\n".to_vec()],
    }];
    let out = call_stream(
        &s,
        "ntlm-http",
        &Destination::new("intranet.example.com", 443),
        &exchanges,
        &mut server,
    )
    .result
    .unwrap();
    assert_eq!(out.reads.len(), 1);
    assert_eq!(server.written.len(), 3);

    let negotiate = ntlm_token(&server.written[0]);
    assert_eq!(&negotiate[..12], b"NTLMSSP\0\x01\0\0\0");
    let auth = ntlm_token(&server.written[1]);
    assert_eq!(&auth[..12], b"NTLMSSP\0\x03\0\0\0");
    assert_eq!(field(&auth, 28), utf16("CORP"));
    assert_eq!(field(&auth, 36), utf16("svc-reports"));
    assert_eq!(field(&auth, 12), [0u8; 24], "LmChallengeResponse is Z(24)");
    assert_eq!(
        u32::from_le_bytes(auth[60..64].try_into().unwrap()),
        NTLM_FLAGS
    );

    let nt = field(&auth, 20);
    let (proof, blob) = nt.split_at(16);
    let ntowf = hmac_md5(&md4(&utf16("Winter2027!")), &utf16("SVC-REPORTSCORP"));
    let mut challenged = SERVER_CHALLENGE.to_vec();
    challenged.extend(blob);
    assert!(hmac_md5(&ntowf, &challenged) == proof, "NTProofStr differs");
    assert_eq!(&blob[..8], unhex("0101000000000000"));
    assert_eq!(&blob[8..16], SERVER_TIME);
    // The server's pairs, then MsvAvFlags with the MIC bit, then the end.
    let info = target_info();
    let pairs = &blob[28..blob.len() - 4];
    assert_eq!(&pairs[..info.len() - 4], &info[..info.len() - 4]);
    assert_eq!(
        &pairs[info.len() - 4..info.len() + 4],
        av(6, &2u32.to_le_bytes()).as_slice()
    );
    assert_eq!(&pairs[info.len() + 4..], [0u8; 4]);

    let session = hmac_md5(&ntowf, proof);
    let mut zeroed = auth.clone();
    zeroed[72..88].fill(0);
    let mut messages = negotiate.clone();
    messages.extend(&challenge);
    messages.extend(&zeroed);
    assert!(hmac_md5(&session, &messages) == auth[72..88], "MIC differs");

    // A second call has a fresh client challenge.
    let mut again = FakeServer::default();
    again.reads.extend([
        format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\n\r\n",
            STANDARD.encode(&challenge)
        )
        .into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]);
    call_stream(
        &s,
        "ntlm-http",
        &Destination::new("intranet.example.com", 443),
        &[],
        &mut again,
    )
    .result
    .unwrap();
    let second = ntlm_token(&again.written[1]);
    assert_ne!(field(&second, 20)[32..40], blob[16..24]);
}

/// MD4 is flagged weak in the summary; NTOWFv2 of a guessable password cannot be handed
/// back; `utf16le` of a mixed value and `uint_le` of a secret are refused; a challenge
/// without a timestamp, and one that is not base64, fail before AUTHENTICATE is written.
#[test]
fn ntlm_weak_flag_and_refusals() {
    let fields = vec![
        FieldSpec::public("user"),
        FieldSpec::public("domain"),
        FieldSpec::guessable("password"),
    ];
    let summary = summarize(&policy(fields.clone(), vec![doc("ntlm-http")]), None);
    let weak: Vec<_> = summary
        .flags
        .iter()
        .filter(|f| f.code == FlagCode::WeakMechanism)
        .collect();
    assert_eq!(weak.len(), 1);
    assert!(weak[0].detail.contains("MD4"));
    let hmac_only = summarize(&policy(oauth_fields(), vec![doc("oauth1-hmac-sha1")]), None);
    assert!(
        !hmac_only
            .flags
            .iter()
            .any(|f| f.code == FlagCode::WeakMechanism)
    );

    assert_eq!(
        refused(
            fields.clone(),
            vec![derivation(
                "d",
                "{{ hex(hmac_md5(md4(utf16le(password)), utf16le(upper(user) + domain))) }}"
            )]
        ),
        RULE_5_GUESS
    );
    assert_eq!(
        refused(
            fields.clone(),
            vec![derivation(
                "d",
                "{{ hex(md4(utf16le(password + $input))) }}"
            )]
        ),
        RULE_1
    );
    assert_eq!(
        refused(
            vec![FieldSpec::secret("secret")],
            vec![derivation(
                "d",
                "{{ hex(sha256(uint_le(slice(secret, \"0\", \"2\")))) }}"
            )]
        ),
        RULE_9
    );

    for challenge in [
        // No MsvAvTimestamp: `between` finds no pair 7.
        {
            let mut c = challenge_message();
            let at = c.len() - 16;
            c.drain(at..at + 12);
            c[40] -= 12;
            c[42] -= 12;
            STANDARD.encode(c)
        },
        "not-base64!".to_string(),
    ] {
        let clock = TestClock::at(NOW);
        let s = ntlm_setup(&clock);
        let mut server = FakeServer::default();
        server.reads.push_back(
            format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {challenge}\r\n\r\n")
                .into_bytes(),
        );
        let result = call_stream(
            &s,
            "ntlm-http",
            &Destination::new("intranet.example.com", 443),
            &[],
            &mut server,
        )
        .result;
        assert!(result.is_err());
        assert_eq!(server.written.len(), 1, "only NEGOTIATE was written");
    }
}
