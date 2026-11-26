//! The schemes of `docs/design.md` section 11 that were "expressible with templates but
//! untested": DPoP, HTTP Message Signatures, Hawk, ACME and JWS, JWE, client authentication
//! by JWT and a SAML login through forms. Each policy is the operation `docs/policy.md` shows
//! (read from that file, so the reference cannot drift from what runs), signed with the
//! analysis unchanged, run in-process against a fake server, and checked against the scheme's
//! published examples or a verifier written here over crates that are not the engine's
//! signing code path where one exists (ring verifies what RustCrypto signs, `rsa` verifies
//! what ring signs).
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
/// The rule of the analysis that refuses a secret and a chosen value in one function that
/// compares or cuts (`docs/policy.md`, The analysis, rule 2).
const RULE_2: &str = "a secret and a chosen value meet in a function that compares or cuts them";
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

/// A P-256 private key for the tests: the scalar of RFC 6979 appendix A.2.5.
const P256_KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
/// The Ed25519 key `test-key-ed25519` of RFC 9421 appendix B.1.4 (PKCS#8 PEM).
const ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n";
/// Its public key, RFC 9421 appendix B.1.4 (SubjectPublicKeyInfo, base64).
const ED25519_PUBLIC_SPKI: &str = "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
/// The recipient's P-256 key in the JWE tests (not a published value).
const RECIPIENT_KEY: &str = "0f6e1d2c3b4a59687766554433221100ffeeddccbbaa99887766554433221101";

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

/// A fake server: answers from `replies` in order, records each request and its destination.
#[derive(Default)]
struct FakeServer {
    replies: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    hosts: Vec<String>,
}

impl FakeServer {
    fn new(replies: &[Vec<u8>]) -> Self {
        Self {
            replies: replies.iter().cloned().collect(),
            ..Self::default()
        }
    }

    fn request(&self, n: usize) -> Sent {
        parse(&self.sent[n])
    }
}

impl Transport for FakeServer {
    fn send(
        &mut self,
        destination: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        self.hosts.push(destination.host.clone());
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| reply("200 OK", &[], "")))
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        Err(Error::transport(TransportKind::Unsupported, false))
    }
}

fn reply(status: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    out.into_bytes()
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
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("no header {name}"))
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    }

    fn pathname(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }

    fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    fn body_text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }

    /// A member of a form body, percent-decoded.
    fn form(&self, name: &str) -> String {
        let value = self
            .body_text()
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no form member {name}"));
        pct_decode(value)
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
            let (name, value) = line.split_once(": ").unwrap();
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

fn pct_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn unb64url(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// The JSON text of the operation `name` in `docs/policy.md`.
fn doc_operation(name: &str) -> String {
    let text = POLICY_MD.replace("\r\n", "\n");
    let mut rest = text.as_str();
    while let Some(start) = rest.find("```json\n") {
        let body = &rest[start + 8..];
        let end = body.find("```").unwrap();
        let block = &body[..end];
        let value = serde_json::from_str::<Value>(block).unwrap_or(Value::Null);
        if value.get("steps").is_some() && value.get("name").and_then(Value::as_str) == Some(name) {
            return block.to_string();
        }
        rest = &body[end + 3..];
    }
    panic!("docs/policy.md shows no operation {name}")
}

fn operation(json: &str) -> Operation {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}\n{json}"))
}

fn doc(name: &str) -> Operation {
    operation(&doc_operation(name))
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

/// Signs the policy; the rule it breaks when the analysis refuses it.
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
/// `operations`; signing runs the template analysis unchanged.
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

fn derive(s: &Setup<'_>, operation: &str) -> Vec<u8> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            operation,
            &Payload::Derive(b""),
            now(),
        )
        .unwrap();
    s.node.derive(&s.record, operation, &auth, b"").unwrap()
}

fn request(method: Method, host: &str, port: u16, path: &str, body: &[u8]) -> Request {
    Request {
        method,
        destination: Destination::new(host, port),
        path: path.into(),
        headers: vec![],
        body: body.to_vec(),
    }
}

/// The uncompressed SEC1 public key of a raw P-256 scalar, computed with the `p256` crate.
fn p256_public(scalar_hex: &str) -> Vec<u8> {
    p256::SecretKey::from_slice(&unhex(scalar_hex))
        .unwrap()
        .public_key()
        .to_sec1_bytes()
        .to_vec()
}

/// Verifies a compact JWS with ES256 by ring; its header and payload.
fn verify_es256(compact: &str, public: &[u8]) -> (Value, Vec<u8>) {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 3, "a compact JWS has three parts");
    let signed = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(signed.as_bytes(), &unb64url(parts[2]))
        .expect("the ES256 signature verifies");
    (json_of(&unb64url(parts[0])), unb64url(parts[1]))
}

/// The SEC1 public key a JWK of kind EC P-256 names.
fn jwk_public(jwk: &Value) -> Vec<u8> {
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    let mut out = vec![4u8];
    out.extend(unb64url(jwk["x"].as_str().unwrap()));
    out.extend(unb64url(jwk["y"].as_str().unwrap()));
    out
}

// ---------------------------------------------------------------------------------------
// DPoP (RFC 9449)
// ---------------------------------------------------------------------------------------

fn dpop_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::secret("key"),
        FieldSpec::secret("refresh_token"),
        FieldSpec::secret("access_token").optional(),
        FieldSpec::public("client_id"),
    ]
}

/// Checks a DPoP proof (RFC 9449 section 4.3): its header, its signature by the key its
/// `jwk` names, and the claims; returns the claims.
fn check_dpop(proof: &str, method: &str, htu: &str) -> Value {
    let header = json_of(&unb64url(proof.split('.').next().unwrap()));
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    let public = jwk_public(&header["jwk"]);
    assert_eq!(
        public,
        p256_public(P256_KEY),
        "the jwk is the key's public key"
    );
    let (_, claims) = verify_es256(proof, &public);
    let claims = json_of(&claims);
    let jti = claims["jti"].as_str().unwrap();
    assert!(
        jti.len() == 32 && jti.bytes().all(|b| b.is_ascii_hexdigit()),
        "jti is 32 hex characters"
    );
    assert_eq!(claims["htm"], method);
    assert_eq!(claims["htu"], htu);
    assert_eq!(claims["iat"], NOW / 1000);
    claims
}

/// The token refresh of `docs/policy.md` meets an authorization server that asks for a
/// nonce (RFC 9449 section 8): the first proof has none, the retry carries the server's, each
/// has its own `jti`; the new tokens are sealed and the next resource request proves
/// possession with `ath` over the new access token and the resource server's nonce.
#[test]
fn dpop_token_refresh_and_resource_request() {
    let clock = TestClock::at(NOW);
    let mut s = setup(
        &clock,
        dpop_fields(),
        vec![doc("dpop-token"), doc("dpop-call")],
        &[
            ("key", &unhex(P256_KEY)),
            ("refresh_token", b"rt-first-0123456789"),
            ("client_id", b"client-1"),
        ],
    );
    let mut server = FakeServer::new(&[
        reply(
            "400 Bad Request",
            &[("DPoP-Nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v")],
            r#"{"error":"use_dpop_nonce"}"#,
        ),
        reply(
            "200 OK",
            &[("Content-Type", "application/json")],
            r#"{"access_token":"at-new-abcdefghijkl","token_type":"DPoP","expires_in":3600,"refresh_token":"rt-second-987654321"}"#,
        ),
    ]);
    let outcome = call(&s, "dpop-token", None, &mut server);
    let response = outcome.result.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        json_of(response.body()),
        json!({"/token_type": "DPoP", "/expires_in": 3600})
    );
    assert_eq!(server.sent.len(), 2);
    let mut jtis = Vec::new();
    for (n, nonce) in [(0, None), (1, Some("eyJ7S_zG.eyJH0-Z.HX4w-7v"))] {
        let sent = server.request(n);
        assert_eq!(sent.method, "POST");
        assert_eq!(sent.target, "/token");
        assert_eq!(sent.form("refresh_token"), "rt-first-0123456789");
        let claims = check_dpop(
            sent.header("DPoP"),
            "POST",
            "https://auth.example.com/token",
        );
        assert_eq!(claims["nonce"].as_str(), nonce);
        assert!(claims.get("ath").is_none());
        jtis.push(claims["jti"].as_str().unwrap().to_string());
    }
    assert_ne!(jtis[0], jtis[1], "every proof has its own jti");

    s.record = outcome.record.expect("the new tokens are sealed");
    let mut server = FakeServer::new(&[
        reply(
            "401 Unauthorized",
            &[
                ("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""),
                ("DPoP-Nonce", "rs-nonce-42"),
            ],
            "",
        ),
        reply("200 OK", &[], r#"{"id":7}"#),
    ]);
    let get = request(Method::Get, "api.example.com", 443, "/v1/items/7", b"");
    let response = call(&s, "dpop-call", Some(&get), &mut server)
        .result
        .unwrap();
    assert_eq!(response.body(), br#"{"id":7}"#);
    let ath = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(b"at-new-abcdefghijkl"));
    for (n, nonce) in [(0, None), (1, Some("rs-nonce-42"))] {
        let sent = server.request(n);
        assert_eq!(sent.target, "/v1/items/7");
        assert_eq!(sent.header("Authorization"), "DPoP at-new-abcdefghijkl");
        let claims = check_dpop(
            sent.header("DPoP"),
            "GET",
            "https://api.example.com/v1/items/7",
        );
        assert_eq!(claims["nonce"].as_str(), nonce);
        assert_eq!(
            claims["ath"],
            ath.as_str(),
            "ath is the hash of the new token"
        );
    }
}

/// Without `if`, the retry is unconditional: a resource server that accepts the first proof
/// and sends no nonce makes the capture, and so the call, fail after one request.
#[test]
fn dpop_retry_needs_a_server_nonce() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        dpop_fields(),
        vec![doc("dpop-call")],
        &[
            ("key", &unhex(P256_KEY)),
            ("refresh_token", b"rt-first-0123456789"),
            ("access_token", b"at-first-abcdefghij"),
            ("client_id", b"client-1"),
        ],
    );
    let mut server = FakeServer::new(&[reply("200 OK", &[], r#"{"id":7}"#)]);
    let get = request(Method::Get, "api.example.com", 443, "/v1/items/7", b"");
    let outcome = call(&s, "dpop-call", Some(&get), &mut server);
    assert!(outcome.result.is_err(), "the call fails without a nonce");
    assert_eq!(server.sent.len(), 1);
}

/// `ath` is a hash of the token alone, so it stays tainted; written before the server's
/// nonce, the tainted object meets a controlled value in `json_set` and the analysis
/// refuses it, which is why the policy writes `ath` last.
#[test]
fn dpop_ath_before_the_nonce_is_refused() {
    let op = json!({"name": "proof", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "caller", "methods": ["GET"], "paths": ["/v1/**"]}},
        {"do": "receive", "capture": [{"source": {"from": "header", "name": "DPoP-Nonce"},
            "into": {"kind": "temp", "name": "dpop_nonce", "secret": false}}]},
        {"do": "send", "request": {"from": "caller", "methods": ["GET"], "paths": ["/v1/**"]},
         "inject": [{"target": {"kind": "header", "name": "DPoP"},
            "template": r#"{{ b64urlraw(json_set(json_set("{}", "ath", b64urlraw(sha256(access_token))), "nonce", dpop_nonce)) }}"#}]},
        {"do": "return"}
    ]});
    let rule = refused(dpop_fields(), vec![serde_json::from_value(op).unwrap()]);
    assert_eq!(rule, RULE_2);
}

// ---------------------------------------------------------------------------------------
// HTTP Message Signatures (RFC 9421)
// ---------------------------------------------------------------------------------------

/// The signature base of RFC 9421 section 2.5 for the components the policy covers, rebuilt
/// from the request as the server read it.
fn signature_base(sent: &Sent, params: &str) -> String {
    let digest = format!(
        "sha-256=:{}:",
        STANDARD.encode(sha2::Sha256::digest(&sent.body))
    );
    assert_eq!(sent.header("Content-Digest"), digest);
    let authority = sent.header("Host").to_ascii_lowercase();
    format!(
        "\"@method\": {}\n\"@authority\": {authority}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {digest}\n\"@signature-params\": {params}",
        sent.method,
        sent.pathname(),
        sent.query(),
    )
}

/// The label's value of a dictionary header with one member, `sig1=...`.
fn member<'a>(value: &'a str, label: &str) -> &'a str {
    value.strip_prefix(&format!("{label}=")).unwrap()
}

fn signature_bytes(sent: &Sent) -> Vec<u8> {
    let value = member(sent.header("Signature"), "sig1");
    STANDARD
        .decode(value.strip_prefix(':').unwrap().strip_suffix(':').unwrap())
        .unwrap()
}

/// The signed-call policy of `docs/policy.md` with each algorithm of RFC 9421 section 3.3
/// the task names; a server-side verifier rebuilds the base from the wire and checks the
/// signature (ring for Ed25519 and ECDSA, the `rsa` crate for RSA-PSS, `hmac` for HMAC).
#[test]
fn http_message_signatures_four_algorithms() {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey};
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::signature::Verifier as _;

    let base = doc_operation("signed-call");
    let rsa_pem = include_str!("fixtures/rsa2048.pem");
    let ed25519_der = pem_body(ED25519_PEM);
    let ed25519_public = STANDARD.decode(ED25519_PUBLIC_SPKI).unwrap()[12..].to_vec();
    let cases: [(&str, &str, Vec<u8>); 4] = [
        ("ed25519", "ed25519_sign(key,", ed25519_der),
        ("ecdsa-p256-sha256", "p256_sign(key,", unhex(P256_KEY)),
        (
            "rsa-pss-sha512",
            "rsa_sign_pss(\\\"sha512\\\", pem(key),",
            rsa_pem.as_bytes().to_vec(),
        ),
        (
            "hmac-sha256",
            "hmac_sha256(key,",
            b"hmac-key-0123456789abcdef".to_vec(),
        ),
    ];
    let mut verified = 0;
    for (alg, function, key) in cases {
        let json = base
            .replace("ed25519_sign(key,", function)
            .replace("alg=\\\"ed25519\\\"", &format!("alg=\\\"{alg}\\\""));
        let clock = TestClock::at(NOW);
        let s = setup(
            &clock,
            vec![FieldSpec::secret("key")],
            vec![operation(&json)],
            &[("key", &key)],
        );
        for req in [
            request(
                Method::Post,
                "api.example.com",
                443,
                "/v1/items?page=2",
                br#"{"name":"x"}"#,
            ),
            request(Method::Get, "api.example.com", 443, "/v1/items", b""),
        ] {
            let mut server = FakeServer::default();
            call(&s, "signed-call", Some(&req), &mut server)
                .result
                .unwrap();
            let sent = server.request(0);
            let params = member(sent.header("Signature-Input"), "sig1");
            assert_eq!(
                params,
                format!(
                    "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created={};keyid=\"client-1\";alg=\"{alg}\"",
                    NOW / 1000
                )
            );
            let base = signature_base(&sent, params);
            let signature = signature_bytes(&sent);
            match alg {
                "ed25519" => UnparsedPublicKey::new(&ED25519, &ed25519_public)
                    .verify(base.as_bytes(), &signature)
                    .expect("ed25519 verifies"),
                "ecdsa-p256-sha256" => {
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, p256_public(P256_KEY))
                        .verify(base.as_bytes(), &signature)
                        .expect("ecdsa-p256-sha256 verifies");
                }
                "rsa-pss-sha512" => {
                    let private = rsa::PrivateKey::from_pkcs8_der(&pem_body(rsa_pem)).unwrap();
                    rsa::pss::VerifyingKey::<sha2::Sha512>::new(private.to_public_key())
                        .verify(
                            base.as_bytes(),
                            &rsa::pss::Signature::try_from(signature.as_slice()).unwrap(),
                        )
                        .expect("rsa-pss-sha512 verifies");
                }
                _ => {
                    use hmac::{Hmac, KeyInit as _, Mac as _};
                    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
                    mac.update(base.as_bytes());
                    mac.verify_slice(&signature).expect("hmac-sha256 verifies");
                }
            }
            verified += 1;
        }
    }
    assert_eq!(verified, 8);
}

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

/// An HTTP signature test operation of RFC 9421 appendix B.2: `example.com`, the caller's
/// `POST /foo?param=Value&Pet=dog`, `Content-Type` and `Date` injected (the example's `Date`
/// is two seconds after `created`), and the `Signature-Input` and `Signature` headers.
fn rfc9421_operation(label: &str, params: &str, signature: &str) -> Operation {
    let op = json!({"name": "rfc9421", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "compute", "into": "sig_params", "template": params},
        {"do": "send",
         "request": {"from": "caller", "methods": ["POST"], "paths": ["/foo"],
                     "query": [{"name": "param"}, {"name": "Pet"}]},
         "inject": [
            {"target": {"kind": "header", "name": "Date"},
             "template": r#"{{ time(add($unix, "2"), "%a, %d %b %Y %H:%M:%S GMT") }}"#},
            {"target": {"kind": "header", "name": "Content-Type"}, "template": "application/json"},
            {"target": {"kind": "header", "name": "Signature-Input"},
             "template": format!("{label}={{{{ sig_params }}}}")},
            {"target": {"kind": "header", "name": "Signature"}, "template": signature}]},
        {"do": "return"}
    ]});
    serde_json::from_value(op).unwrap()
}

fn rfc9421_request(clock_ms: u64, s: &Setup<'_>) -> Sent {
    assert_eq!(now(), clock_ms);
    let req = request(
        Method::Post,
        "example.com",
        443,
        "/foo?param=Value&Pet=dog",
        br#"{"hello": "world"}"#,
    );
    let mut server = FakeServer::default();
    call(s, "rfc9421", Some(&req), &mut server).result.unwrap();
    server.request(0)
}

/// RFC 9421 appendix B.2.6 (Ed25519 over date, method, path, authority, content type and
/// length): the signature the RFC publishes, byte for byte. (B.2.5, HMAC, is not here: its
/// shared key could not be checked against the RFC text offline; HMAC is checked by the
/// verifier of `http_message_signatures_four_algorithms`.)
#[test]
fn http_message_signatures_rfc9421_vectors() {
    const CREATED: u64 = 1_618_884_473_000;
    let date = r#"time(add($unix, "2"), "%a, %d %b %Y %H:%M:%S GMT")"#;

    let clock = TestClock::at(CREATED);
    let b26 = rfc9421_operation(
        "sig-b26",
        r#"("date" "@method" "@path" "@authority" "content-type" "content-length");created={{ $unix }};keyid="test-key-ed25519""#,
        &format!(
            r#"sig-b26=:{{{{ b64(ed25519_sign(pem(key), "\"date\": " + {date} + "\n\"@method\": " + $method + "\n\"@path\": " + $pathname + "\n\"@authority\": " + $host + "\n\"content-type\": application/json\n\"content-length\": " + len($body) + "\n\"@signature-params\": " + sig_params)) }}}}:"#
        ),
    );
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![b26],
        &[("key", ED25519_PEM.as_bytes())],
    );
    let sent = rfc9421_request(CREATED, &s);
    assert_eq!(sent.header("Date"), "Tue, 20 Apr 2021 02:07:55 GMT");
    assert_eq!(
        sent.header("Signature-Input"),
        r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#
    );
    assert_eq!(
        sent.header("Signature"),
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
    );
}

// ---------------------------------------------------------------------------------------
// Hawk
// ---------------------------------------------------------------------------------------

/// The attributes of a `Hawk` header.
fn hawk_attributes(header: &str) -> Vec<(String, String)> {
    header
        .strip_prefix("Hawk ")
        .unwrap()
        .split(", ")
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap();
            (name.to_string(), value.trim_matches('"').to_string())
        })
        .collect()
}

fn attribute<'a>(attributes: &'a [(String, String)], name: &str) -> &'a str {
    attributes
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no attribute {name}"))
}

fn hmac_sha256_b64(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    STANDARD.encode(mac.finalize().into_bytes())
}

/// The hawk-call policy of `docs/policy.md`: a verifier recomputes the payload hash and the
/// MAC from what the server read (the Hawk specification's normalized string).
#[test]
fn hawk_header_verifies() {
    let clock = TestClock::at(NOW);
    let key = b"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn";
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::secret("secret")],
        vec![doc("hawk-call")],
        &[("user", b"dh37fgj492je"), ("secret", key)],
    );
    for req in [
        request(Method::Get, "api.example.com", 443, "/v1/resource/1", b""),
        request(
            Method::Post,
            "api.example.com",
            443,
            "/v1/items",
            br#"{"n":1}"#,
        ),
    ] {
        let mut server = FakeServer::default();
        call(&s, "hawk-call", Some(&req), &mut server)
            .result
            .unwrap();
        let sent = server.request(0);
        assert_eq!(sent.header("Content-Type"), "application/json");
        let attributes = hawk_attributes(sent.header("Authorization"));
        assert_eq!(attribute(&attributes, "id"), "dh37fgj492je");
        assert_eq!(attribute(&attributes, "ts"), (NOW / 1000).to_string());
        let hash = STANDARD.encode(sha2::Sha256::digest(
            [
                b"hawk.1.payload\napplication/json\n".as_slice(),
                &sent.body,
                b"\n",
            ]
            .concat(),
        ));
        assert_eq!(attribute(&attributes, "hash"), hash);
        let normalized = format!(
            "hawk.1.header\n{}\n{}\n{}\n{}\napi.example.com\n443\n{hash}\n\n",
            attribute(&attributes, "ts"),
            attribute(&attributes, "nonce"),
            sent.method,
            sent.target,
        );
        assert_eq!(
            attribute(&attributes, "mac"),
            hmac_sha256_b64(key, normalized.as_bytes()),
            "the mac verifies"
        );
    }
}

/// The two request examples of the Hawk specification (its README: GET without and POST
/// with a payload hash, `ext`, port 8000), with the specification's fixed nonce in place of
/// `$nonce`: the MACs and the hash it publishes.
#[test]
fn hawk_specification_examples() {
    let clock = TestClock::at(1_353_832_234_000);
    let header = |hash: &str, normalized_hash: &str| {
        format!(
            r#"Hawk id="{{{{ user }}}}", ts="{{{{ $unix }}}}", nonce="j4h3g2"{hash}, ext="some-app-ext-data", mac="{{{{ b64(hmac_sha256(secret, "hawk.1.header\n" + $unix + "\nj4h3g2\n" + $method + "\n" + $path + "\n" + $host + "\n8000\n" + {normalized_hash} + "\nsome-app-ext-data\n")) }}}}""#
        )
    };
    let payload_hash = r#"b64(sha256("hawk.1.payload\ntext/plain\n" + $body + "\n"))"#;
    let get = header("", "\"\"");
    let post = header(
        &format!(r#", hash="{{{{ {payload_hash} }}}}""#),
        payload_hash,
    );
    let op = |name: &str, method: &str, template: &str, content_type: bool| {
        let mut inject = vec![
            json!({"target": {"kind": "header", "name": "Authorization"},
                                     "template": template}),
        ];
        if content_type {
            inject.push(json!({"target": {"kind": "header", "name": "Content-Type"},
                               "template": "text/plain"}));
        }
        serde_json::from_value::<Operation>(json!({"name": name, "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "example.com", "port": 8000}]},
            {"do": "send",
             "request": {"from": "caller", "methods": [method], "paths": ["/resource/1"],
                         "query": [{"name": "b"}, {"name": "a"}]},
             "inject": inject},
            {"do": "return"}
        ]}))
        .unwrap()
    };
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::secret("secret")],
        vec![
            op("get", "GET", &get, false),
            op("post", "POST", &post, true),
        ],
        &[
            ("user", b"dh37fgj492je"),
            ("secret", b"werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"),
        ],
    );
    let mut server = FakeServer::default();
    let req = request(Method::Get, "example.com", 8000, "/resource/1?b=1&a=2", b"");
    call(&s, "get", Some(&req), &mut server).result.unwrap();
    assert_eq!(
        server.request(0).header("Authorization"),
        r#"Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=""#
    );
    let req = request(
        Method::Post,
        "example.com",
        8000,
        "/resource/1?b=1&a=2",
        b"Thank you for flying Hawk",
    );
    call(&s, "post", Some(&req), &mut server).result.unwrap();
    let attributes = hawk_attributes(server.request(1).header("Authorization"));
    assert_eq!(
        attribute(&attributes, "hash"),
        "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="
    );
    assert_eq!(
        attribute(&attributes, "mac"),
        "aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="
    );
}

// ---------------------------------------------------------------------------------------
// ACME (RFC 8555) and JWS
// ---------------------------------------------------------------------------------------

/// Checks a flattened JWS of RFC 8555 section 6.2: ES256, signed by the account key, with
/// the nonce and URL expected; its protected header and payload.
fn check_acme(sent: &Sent, nonce: &str, url: &str) -> (Value, Vec<u8>) {
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.header("Content-Type"), "application/jose+json");
    let jws = json_of(&sent.body);
    let protected = jws["protected"].as_str().unwrap();
    let payload = jws["payload"].as_str().unwrap();
    let signature = jws["signature"].as_str().unwrap();
    let (header, payload) = verify_es256(
        &format!("{protected}.{payload}.{signature}"),
        &p256_public(P256_KEY),
    );
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["nonce"], nonce);
    assert_eq!(header["url"], url);
    (header, payload)
}

/// `acme-new-account` signs the caller's payload with the account key as `jwk` and the nonce
/// of `newNonce`; `acme-call` finds the account URL by key (`onlyReturnExisting`) and signs
/// the caller's request with it as `kid`, each request with the nonce of the response before
/// it; an empty body is a POST-as-GET.
#[test]
fn acme_jws_with_jwk_kid_and_chained_nonces() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("key")],
        vec![doc("acme-new-account"), doc("acme-call")],
        &[("key", &unhex(P256_KEY))],
    );
    let account = "https://acme.example.com/acme/acct/17";
    let mut server = FakeServer::new(&[
        reply("200 OK", &[("Replay-Nonce", "nonce-A")], ""),
        reply(
            "201 Created",
            &[("Location", account), ("Replay-Nonce", "nonce-B")],
            r#"{"status":"valid"}"#,
        ),
    ]);
    let body = br#"{"termsOfServiceAgreed":true,"contact":["mailto:admin@example.org"]}"#;
    let req = request(
        Method::Post,
        "acme.example.com",
        443,
        "/acme/new-account",
        body,
    );
    let response = call(&s, "acme-new-account", Some(&req), &mut server)
        .result
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.header("Location"), Some(account.as_bytes()));
    let head = server.request(0);
    assert_eq!(
        (head.method.as_str(), head.target.as_str()),
        ("HEAD", "/acme/new-nonce")
    );
    let (header, payload) = check_acme(
        &server.request(1),
        "nonce-A",
        "https://acme.example.com/acme/new-account",
    );
    assert_eq!(jwk_public(&header["jwk"]), p256_public(P256_KEY));
    assert!(header.get("kid").is_none());
    assert_eq!(payload, body);

    let mut checked = 0;
    for (path, body) in [
        (
            "/acme/new-order",
            &br#"{"identifiers":[{"type":"dns","value":"example.org"}]}"#[..],
        ),
        ("/acme/order/9", b""),
    ] {
        let mut server = FakeServer::new(&[
            reply("200 OK", &[("Replay-Nonce", "nonce-1")], ""),
            reply(
                "200 OK",
                &[("Location", account), ("Replay-Nonce", "nonce-2")],
                r#"{"status":"valid"}"#,
            ),
            reply(
                "201 Created",
                &[("Replay-Nonce", "nonce-3")],
                r#"{"status":"pending"}"#,
            ),
        ]);
        let req = request(Method::Post, "acme.example.com", 443, path, body);
        let response = call(&s, "acme-call", Some(&req), &mut server)
            .result
            .unwrap();
        assert_eq!(response.status(), 201);
        let (header, payload) = check_acme(
            &server.request(1),
            "nonce-1",
            "https://acme.example.com/acme/new-account",
        );
        assert!(header.get("jwk").is_some());
        assert_eq!(payload, br#"{"onlyReturnExisting":true}"#);
        let (header, payload) = check_acme(
            &server.request(2),
            "nonce-2",
            &format!("https://acme.example.com{path}"),
        );
        assert_eq!(header["kid"], account);
        assert!(header.get("jwk").is_none());
        assert_eq!(payload, body);
        checked += 1;
    }
    assert_eq!(checked, 2);
}

/// JWS beyond ACME: RFC 7515 appendix A.1 (HS256, the header and payload with their CRLFs)
/// and RFC 8037 appendix A.4 (EdDSA with Ed25519), whole compact serializations byte for
/// byte, from operations with no connection.
#[test]
fn jws_rfc7515_and_rfc8037_vectors() {
    let hs256 = r#"{{ b64urlraw("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}") + "." + b64urlraw("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}") + "." + b64urlraw(hmac_sha256(secret, b64urlraw("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}") + "." + b64urlraw("{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"))) }}"#;
    let eddsa = r#"{{ b64urlraw("{\"alg\":\"EdDSA\"}") + "." + b64urlraw("Example of Ed25519 signing") + "." + b64urlraw(ed25519_sign(key, b64urlraw("{\"alg\":\"EdDSA\"}") + "." + b64urlraw("Example of Ed25519 signing"))) }}"#;
    let op = |name: &str, template: &str| {
        serde_json::from_value::<Operation>(
            json!({"name": name, "steps": [{"do": "return", "template": template}]}),
        )
        .unwrap()
    };
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::secret("secret"), FieldSpec::secret("key")],
        vec![op("hs256", hs256), op("eddsa", eddsa)],
        &[
            (
                "secret",
                &unb64url(
                    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                ),
            ),
            (
                "key",
                &unb64url("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"),
            ),
        ],
    );
    assert_eq!(
        String::from_utf8(derive(&s, "hs256")).unwrap(),
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    assert_eq!(
        String::from_utf8(derive(&s, "eddsa")).unwrap(),
        "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    );
}

// ---------------------------------------------------------------------------------------
// JWE (RFC 7516)
// ---------------------------------------------------------------------------------------

/// The five parts of the compact JWE in the `card` member of a request body.
fn jwe_parts(sent: &Sent) -> Vec<String> {
    let body = json_of(&sent.body);
    let parts: Vec<String> = body["card"]
        .as_str()
        .unwrap()
        .split('.')
        .map(String::from)
        .collect();
    assert_eq!(parts.len(), 5, "a compact JWE has five parts");
    parts
}

/// AES-GCM decryption by the `aes-gcm` crate, with the encoded header as AAD.
fn gcm_open(key: &[u8], parts: &[String]) -> Vec<u8> {
    use aes_gcm::aead::{Aead as _, KeyInit as _, Payload as AeadPayload};
    let iv = unb64url(&parts[2]);
    let mut sealed = unb64url(&parts[3]);
    let tag = unb64url(&parts[4]);
    assert_eq!(iv.len(), 12);
    assert_eq!(tag.len(), 16);
    sealed.extend_from_slice(&tag);
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(iv.as_slice()).unwrap();
    let payload = AeadPayload {
        msg: &sealed,
        aad: parts[0].as_bytes(),
    };
    match key.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(&nonce, payload),
        _ => aes_gcm::Aes256Gcm::new_from_slice(key)
            .unwrap()
            .decrypt(&nonce, payload),
    }
    .expect("the JWE decrypts")
}

fn rsa_public_pem() -> String {
    use rsa::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
    let private =
        rsa::PrivateKey::from_pkcs8_der(&pem_body(include_str!("fixtures/rsa2048.pem"))).unwrap();
    let der = private.to_public_key().to_public_key_der().unwrap();
    let b64 = STANDARD.encode(der.as_bytes());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        lines.join("\n")
    )
}

fn card_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::secret("card_number"),
        FieldSpec::public("server_key"),
        FieldSpec::public("recipient"),
    ]
}

const CARD: &[u8] = b"4111111111111111";

/// RSA-OAEP-256 with A256GCM: the server unwraps the content key with its RSA key (the
/// `rsa` crate) and decrypts the card number; a second call uses a fresh key and IV.
#[test]
fn jwe_rsa_oaep_256_a256gcm() {
    use rsa::pkcs8::DecodePrivateKey as _;
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        card_fields(),
        vec![doc("jwe-rsa")],
        &[
            ("card_number", CARD),
            ("server_key", rsa_public_pem().as_bytes()),
            ("recipient", &p256_public(RECIPIENT_KEY)),
        ],
    );
    let private =
        rsa::PrivateKey::from_pkcs8_der(&pem_body(include_str!("fixtures/rsa2048.pem"))).unwrap();
    let mut keys = Vec::new();
    for _ in 0..2 {
        let mut server = FakeServer::new(&[reply("200 OK", &[], r#"{"token":"tok_1"}"#)]);
        let response = call(&s, "jwe-rsa", None, &mut server).result.unwrap();
        assert_eq!(json_of(response.body()), json!({"/token": "tok_1"}));
        let parts = jwe_parts(&server.request(0));
        assert_eq!(
            json_of(&unb64url(&parts[0])),
            json!({"alg": "RSA-OAEP-256", "enc": "A256GCM"})
        );
        let cek = private
            .decrypt(rsa::Oaep::<sha2::Sha256>::new(), &unb64url(&parts[1]))
            .unwrap();
        assert_eq!(cek.len(), 32);
        assert_eq!(gcm_open(&cek, &parts), br#"{"number":"4111111111111111"}"#);
        keys.push((cek, parts[2].clone()));
    }
    assert_ne!(keys[0], keys[1], "a fresh content key and IV each call");
}

/// Concat KDF of RFC 7518 section 4.6.2 for a key of `bits`, computed here with `sha2`.
fn concat_kdf(z: &[u8], alg: &str, apu: &[u8], apv: &[u8], bits: u32) -> Vec<u8> {
    let mut input = 1u32.to_be_bytes().to_vec();
    input.extend_from_slice(z);
    for part in [alg.as_bytes(), apu, apv] {
        input.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        input.extend_from_slice(part);
    }
    input.extend_from_slice(&bits.to_be_bytes());
    sha2::Sha256::digest(&input)[..(bits / 8) as usize].to_vec()
}

/// ECDH-ES+A128KW with A128GCM: the recipient agrees on Z with the `epk` (the `p256`
/// crate), derives the KEK, unwraps the content key (the `aes-kw` crate) and decrypts.
#[test]
fn jwe_ecdh_es_a128kw_a128gcm() {
    use aes_kw::KeyInit as _;
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        card_fields(),
        vec![doc("jwe-ecdh")],
        &[
            ("card_number", CARD),
            ("server_key", rsa_public_pem().as_bytes()),
            ("recipient", &p256_public(RECIPIENT_KEY)),
        ],
    );
    let mut epks = Vec::new();
    for _ in 0..2 {
        let mut server = FakeServer::new(&[reply("200 OK", &[], r#"{"token":"tok_2"}"#)]);
        call(&s, "jwe-ecdh", None, &mut server).result.unwrap();
        let parts = jwe_parts(&server.request(0));
        let header = json_of(&unb64url(&parts[0]));
        assert_eq!(header["alg"], "ECDH-ES+A128KW");
        assert_eq!(header["enc"], "A128GCM");
        let epk = jwk_public(&header["epk"]);
        let z = p256::SecretKey::from_slice(&unhex(RECIPIENT_KEY))
            .unwrap()
            .diffie_hellman(&p256::PublicKey::from_sec1_bytes(&epk).unwrap())
            .raw_secret_bytes()
            .to_vec();
        let kek = concat_kdf(&z, "ECDH-ES+A128KW", b"", b"", 128);
        let mut cek = [0u8; 16];
        aes_kw::KwAes128::new_from_slice(&kek)
            .unwrap()
            .unwrap_key(&unb64url(&parts[1]), &mut cek)
            .expect("the content key unwraps");
        assert_eq!(gcm_open(&cek, &parts), br#"{"number":"4111111111111111"}"#);
        epks.push(epk);
    }
    assert_ne!(epks[0], epks[1], "an ephemeral key per operation");
}

/// RFC 7518 appendix C: direct ECDH-ES for A128GCM with `apu` "Alice" and `apv` "Bob",
/// Alice's published ephemeral key given as a static key (`ecdh` with three arguments) and
/// Bob's public key. The content the operation encrypts opens under the key the RFC
/// publishes, `VqqN6vgjbSBcIijNcacQGg`, so the composed Concat KDF input is the RFC's.
#[test]
fn jwe_ecdh_es_rfc7518_appendix_c() {
    let op = json!({"name": "vector", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "compute", "into": "cek",
         "template": r#"{{ concat_kdf("sha256", ecdh("p256", recipient, eph), be32("7") + "A128GCM" + be32("5") + "Alice" + be32("3") + "Bob" + be32("128"), "16") }}"#},
        {"do": "compute", "into": "head", "template": r#"{{ b64urlraw(json_set(json_set("{}", "alg", "ECDH-ES"), "enc", "A128GCM")) }}"#},
        {"do": "compute", "into": "iv", "template": r#"{{ random("12") }}"#},
        {"do": "compute", "into": "sealed", "template": r#"{{ aes_gcm_encrypt(cek, iv, card_number, head) }}"#},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/v1/cards"},
         "inject": [{"target": {"kind": "body"},
            "template": r#"{"card":"{{ head + ".." + b64urlraw(iv) + "." + b64urlraw(slice(sealed, "0", len(card_number))) + "." + b64urlraw(slice(sealed, len(card_number), "16")) }}"}"#}]},
        {"do": "return"}
    ]});
    let clock = TestClock::at(NOW);
    let bob = concat!(
        "04",
        "c1e349cb61ec70248ce801034c3834e1b88ebe1161cb25af38741f785fcfc4c4",
        "7bc96708ef80952b53f8d2555fe72b841ed04588628b1d378a594939500ec9c9",
    );
    let alice = "d3f3716913d4310a0026de741b3f18893afc8114f0c84682ba677e313a13988a";
    let s = setup(
        &clock,
        vec![
            FieldSpec::secret("card_number"),
            FieldSpec::secret("eph"),
            FieldSpec::public("recipient"),
        ],
        vec![serde_json::from_value(op).unwrap()],
        &[
            ("card_number", CARD),
            ("eph", &unhex(alice)),
            ("recipient", &unhex(bob)),
        ],
    );
    let mut server = FakeServer::default();
    call(&s, "vector", None, &mut server).result.unwrap();
    let parts = jwe_parts(&server.request(0));
    let key = unb64url("VqqN6vgjbSBcIijNcacQGg");
    assert_eq!(
        key,
        concat_kdf(
            &unhex(&ecdh_z(alice, bob)),
            "A128GCM",
            b"Alice",
            b"Bob",
            128
        )
    );
    assert_eq!(gcm_open(&key, &parts), CARD);
}

/// Z of a static P-256 key and a SEC1 public key, both hex, by the `p256` crate.
fn ecdh_z(private: &str, public: &str) -> String {
    let z = p256::SecretKey::from_slice(&unhex(private))
        .unwrap()
        .diffie_hellman(&p256::PublicKey::from_sec1_bytes(&unhex(public)).unwrap())
        .raw_secret_bytes()
        .to_vec();
    z.iter().map(|b| format!("{b:02x}")).collect()
}

/// `dir` with A256GCM over the caller's body under a shared key: the server decrypts with
/// that key; the IV is the request's `$nonce`, so it differs between requests.
#[test]
fn jwe_dir_a256gcm_over_the_callers_body() {
    let clock = TestClock::at(NOW);
    let key = [0x5au8; 32];
    let s = setup(
        &clock,
        vec![FieldSpec::secret("secret")],
        vec![doc("jwe-dir")],
        &[("secret", &key)],
    );
    let mut ivs = Vec::new();
    for body in [&br#"{"to":"ops","text":"hi"}"#[..], b"x"] {
        let mut server = FakeServer::default();
        let req = request(Method::Post, "api.example.com", 443, "/v1/messages", body);
        call(&s, "jwe-dir", Some(&req), &mut server).result.unwrap();
        let sent = server.request(0);
        assert_eq!(sent.header("Content-Type"), "application/jose");
        let parts: Vec<String> = sent.body_text().split('.').map(String::from).collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(
            json_of(&unb64url(&parts[0])),
            json!({"alg": "dir", "enc": "A256GCM"})
        );
        assert!(parts[1].is_empty(), "dir has no encrypted key");
        assert_eq!(gcm_open(&key, &parts), body);
        ivs.push(parts[2].clone());
    }
    assert_ne!(ivs[0], ivs[1]);
}

/// A plaintext that mixes the caller's body with a secret: its length is controlled and the
/// ciphertext tainted, and `slice` refuses them together (rule 2), so the split into
/// ciphertext and tag cannot be written.
#[test]
fn jwe_of_caller_bytes_and_a_secret_is_refused() {
    let op = json!({"name": "mixed", "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "compute", "into": "cek", "template": r#"{{ random("32") }}"#},
        {"do": "compute", "into": "iv", "template": r#"{{ random("12") }}"#},
        {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/cards"]},
         "inject": [{"target": {"kind": "body"},
            "template": r#"{{ b64urlraw(slice(aes_gcm_encrypt(cek, iv, json_set($body, "number", card_number), "h"), "0", len(json_set($body, "number", card_number)))) }}"#}]},
        {"do": "return"}
    ]});
    let rule = refused(card_fields(), vec![serde_json::from_value(op).unwrap()]);
    assert_eq!(rule, RULE_2);
}

// ---------------------------------------------------------------------------------------
// Client authentication by JWT (RFC 7523)
// ---------------------------------------------------------------------------------------

fn client_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::secret("key"),
        FieldSpec::secret("secret"),
        FieldSpec::public("client_id"),
        FieldSpec::secret("access_token").optional(),
    ]
}

/// Checks the assertion's claims (RFC 7523 section 3); its compact form.
fn check_assertion(sent: &Sent, alg: &str) -> String {
    assert_eq!(sent.target, "/oauth2/token");
    assert_eq!(sent.form("grant_type"), "client_credentials");
    assert_eq!(
        sent.form("client_assertion_type"),
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    let assertion = sent.form("client_assertion");
    let parts: Vec<&str> = assertion.split('.').collect();
    assert_eq!(
        json_of(&unb64url(parts[0])),
        json!({"alg": alg, "typ": "JWT"})
    );
    let claims = json_of(&unb64url(parts[1]));
    assert_eq!(claims["iss"], "client-1");
    assert_eq!(claims["sub"], "client-1");
    assert_eq!(claims["aud"], "https://auth.example.com/oauth2/token");
    assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
    assert_eq!(claims["iat"], NOW / 1000);
    assert_eq!(claims["exp"], NOW / 1000 + 300);
    assertion
}

/// `private_key_jwt` (RS256, verified by ring) and `client_secret_jwt` (HS256, the same
/// operation with the signature function changed, verified by `hmac`): the access token is
/// sealed into the record and the caller gets only the token type and lifetime.
#[test]
fn client_assertions_private_key_jwt_and_client_secret_jwt() {
    use ring::signature::{
        KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey,
    };
    let pem = include_str!("fixtures/rsa2048.pem");
    let public = RsaKeyPair::from_pkcs8(&pem_body(pem))
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let secret = b"client-secret-0123456789abcdef01";
    let rs256 = doc_operation("client-assertion");
    let hs256 = rs256.replace("\\\"RS256\\\"", "\\\"HS256\\\"").replace(
        "rsa_sign_pkcs1(\\\"sha256\\\", pem(key),",
        "hmac_sha256(secret,",
    );
    for (alg, json) in [("RS256", rs256), ("HS256", hs256)] {
        let clock = TestClock::at(NOW);
        let s = setup(
            &clock,
            client_fields(),
            vec![operation(&json)],
            &[
                ("key", pem.as_bytes()),
                ("secret", secret),
                ("client_id", b"client-1"),
            ],
        );
        let mut server = FakeServer::new(&[reply(
            "200 OK",
            &[],
            r#"{"access_token":"at-minted-0123456789","token_type":"Bearer","expires_in":3600}"#,
        )]);
        let outcome = call(&s, "client-assertion", None, &mut server);
        let response = outcome.result.unwrap();
        assert_eq!(
            json_of(response.body()),
            json!({"/token_type": "Bearer", "/expires_in": 3600})
        );
        assert!(outcome.record.is_some(), "the access token is sealed");
        let assertion = check_assertion(&server.request(0), alg);
        let (signed, signature) = assertion.rsplit_once('.').unwrap();
        if alg == "RS256" {
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
                .verify(signed.as_bytes(), &unb64url(signature))
                .expect("RS256 verifies");
        } else {
            assert_eq!(
                URL_SAFE_NO_PAD.encode(
                    STANDARD
                        .decode(hmac_sha256_b64(secret, signed.as_bytes()))
                        .unwrap()
                ),
                signature,
                "HS256 verifies"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// SAML login through forms
// ---------------------------------------------------------------------------------------

/// The saml-login policy: the redirect's `SAMLRequest` and `RelayState` reach the identity
/// provider unchanged, the CSRF token and cookie of its form go back with the credentials,
/// the `SAMLResponse` of the auto-posting form (with an entity in it) reaches the service
/// provider's ACS, and the session cookie is sealed; the caller gets the status only.
#[test]
fn saml_login_through_forms() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![
            FieldSpec::public("user"),
            FieldSpec::secret("password"),
            FieldSpec::secret("web_session").optional(),
        ],
        vec![doc("saml-login")],
        &[
            ("user", b"alice@example.org"),
            ("password", b"correct horse battery"),
        ],
    );
    let saml_request = "fZJNT8MwDIb%2FSpX7mrbrNhStlcZ2YNKAiRYOXFDaeqwiTVLHFfDvSRkfQ0ic";
    let assertion = "PHNhbWxwOlJlc3BvbnNlIElEPSJfOGU4ZGM1ZjY5YSI+PC9zYW1scDpSZXNwb25zZT4=";
    let mut server = FakeServer::new(&[
        reply(
            "302 Found",
            &[(
                "Location",
                &format!("https://idp.example.com/sso?SAMLRequest={saml_request}&RelayState=s1"),
            )],
            "",
        ),
        reply(
            "200 OK",
            &[("Set-Cookie", "idp=idp-cookie-31415; Secure; HttpOnly")],
            r#"<html><form method="post" action="/login"><input type="hidden" name="csrf" value="csrf-2718"><input name="username"><input type="password" name="password"></form></html>"#,
        ),
        reply(
            "200 OK",
            &[],
            &format!(
                r#"<html><body onload="document.forms[0].submit()"><form method="post" action="https://sp.example.com/acs"><input type="hidden" name="SAMLResponse" value="{}"><input type="hidden" name="RelayState" value="s1"></form></body></html>"#,
                assertion.replace('+', "&#43;")
            ),
        ),
        reply(
            "302 Found",
            &[
                (
                    "Set-Cookie",
                    "sp_session=sp-session-161803; Secure; HttpOnly",
                ),
                ("Location", "/"),
            ],
            "",
        ),
    ]);
    let outcome = call(&s, "saml-login", None, &mut server);
    let response = outcome.result.unwrap();
    assert_eq!(response.status(), 302);
    assert!(response.body().is_empty());
    assert!(outcome.record.is_some(), "the session is sealed");
    assert_eq!(
        server.hosts,
        [
            "sp.example.com",
            "idp.example.com",
            "idp.example.com",
            "sp.example.com"
        ]
    );
    let sso = server.request(1);
    assert_eq!(sso.pathname(), "/sso");
    assert_eq!(
        sso.query(),
        format!("SAMLRequest={saml_request}&RelayState=s1")
    );
    let login = server.request(2);
    assert_eq!(login.header("Cookie"), "idp=idp-cookie-31415");
    assert_eq!(login.form("username"), "alice@example.org");
    assert_eq!(login.form("password"), "correct horse battery");
    assert_eq!(login.form("csrf"), "csrf-2718");
    let acs = server.request(3);
    assert_eq!(acs.target, "/acs");
    assert_eq!(acs.form("SAMLResponse"), assertion);
    assert_eq!(acs.form("RelayState"), "s1");
    assert!(!acs.has_header("Cookie"));
}
