//! The two schemes the tables of `docs/design.md` section 11 left for want of a primitive:
//! SRP-6a (RFC 2945, RFC 5054), as a login in two requests against a server written here, and
//! OpenPGP detached signatures (RFC 9580: version 4 with RSA and with EdDSA as GnuPG writes
//! it, version 6 with Ed25519), with ASCII armor.
//!
//! The policies are the operations of `docs/policy.md` (SRP-6a and OpenPGP), read from that
//! file. The SRP server computes `B`, checks `M1` and writes `M2` with `num-bigint`, not the
//! engine's `crypto-bigint`; RFC 5054 appendix B is checked byte for byte in
//! `crates/engine/src/primitives/srp.rs`. Each OpenPGP signature is parsed here from the
//! armor, its hashed data rebuilt from RFC 9580, and its signature checked by ring (Ed25519)
//! and the `rsa` crate. Every guarantee has its attack.
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
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy};
use engine::record::Record;
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::Digest as _;

const OWNER: &str = "user-1";
/// 2027-01-15T08:00:00Z.
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

const RULE_1: &str = "a secret mixed with a chosen value reaches a decoder, number or key";
const RULE_5: &str = "a derivation would hand a secret back";
const RULE_6: &str = "a hash or curve name must be fixed by the policy";
const RULE_10_MPI: &str = "a secret may not be an OpenPGP integer: the length would tell it";
const RULE_11_PRIVATE: &str =
    "an SRP private value must not be chosen by the caller or a server: random or a field";
const RULE_11_SERVER: &str =
    "an SRP server value or proof must come from the policy or the destination, not the caller";

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

fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(body).unwrap()
}

fn sha1(bytes: &[u8]) -> Vec<u8> {
    use sha1::Digest as _;
    sha1::Sha1::digest(bytes).to_vec()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = sha2::Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().to_vec()
}

/// The operation `name` of `docs/policy.md`.
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

fn call(s: &Setup<'_>, operation: &str, server: &mut SrpServer) -> Outcome<Response> {
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            operation,
            &Payload::Http(None),
            now(),
        )
        .unwrap();
    s.node.http(&s.record, operation, &auth, None, server)
}

fn derive(s: &Setup<'_>, operation: &str, input: &[u8]) -> engine::Result<Vec<u8>> {
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
    s.node.derive(&s.record, operation, &auth, input)
}

/// An operation with no connection that returns `template` over a raw `$input`, after the
/// `compute` steps given.
fn derivation(name: &str, computes: &[(&str, &str)], template: &str) -> Operation {
    let mut steps: Vec<Value> = computes
        .iter()
        .map(|(into, t)| json!({"do": "compute", "into": into, "template": t}))
        .collect();
    steps.push(json!({"do": "return", "template": template}));
    operation(json!({"name": name, "input": {"raw": {}}, "steps": steps}))
}

/// When `CREDENTIALS_INTEROP_DIR` is set, writes `bytes` there, so tools outside this test
/// (GnuPG) can check what the engine produced.
fn keep(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("CREDENTIALS_INTEROP_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

/// The body of an HTTP request as written on the wire.
fn request_body(wire: &[u8]) -> (String, Value) {
    let split = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&wire[..split]).unwrap();
    let target = head.split(' ').nth(1).unwrap().to_string();
    (target, serde_json::from_slice(&wire[split + 4..]).unwrap())
}

// ---------------------------------------------------------------------------------------
// SRP-6a
// ---------------------------------------------------------------------------------------

/// RFC 5054 appendix A, the 2048-bit group, written here apart from the engine's copy.
const N_2048: &str = "AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050
    A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 E8083969 EDB767B0
    CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
    7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A
    5B9D32E6 88F87748 544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6
    AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6 94B5C803 D89F7AE4
    35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73";
const LEN: usize = 256;

fn pad(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = vec![0u8; LEN - bytes.len()];
    out.extend(bytes);
    out
}

/// How the server answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// As RFC 5054 says.
    Honest,
    /// Sends this `B` instead of its own.
    BadB(&'static str),
    /// Accepts any `M1` and proves nothing: it does not know the verifier.
    Impostor,
}

/// The server side of SRP-6a with SHA-256 over the 2048-bit group, on `num-bigint`. It keeps
/// only the verifier `v = g^x`, as a server does.
struct SrpServer {
    mode: Mode,
    n: BigUint,
    g: BigUint,
    user: &'static str,
    salt: Vec<u8>,
    v: BigUint,
    b: BigUint,
    big_b: BigUint,
    big_a: Option<BigUint>,
    sent: Vec<Vec<u8>>,
    accepted: usize,
}

impl SrpServer {
    fn new(user: &'static str, password: &str, mode: Mode) -> Self {
        let n = BigUint::from_bytes_be(&unhex(N_2048));
        let g = BigUint::from(2u32);
        let salt = unhex("5f2c3e4d6a7b8c9d0e1f20314253647586");
        let x = BigUint::from_bytes_be(&sha256(&[
            &salt,
            &sha256(&[format!("{user}:{password}").as_bytes()]),
        ]));
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&sha256(&[&pad(&n), &pad(&g)]));
        let b = BigUint::from_bytes_be(&unhex(
            "7c9a8b6d5e4f30211203f4e5d6c7b8a99a8b7c6d5e4f30211203f4e5d6c7b8a9",
        ));
        let big_b = (&k * &v + g.modpow(&b, &n)) % &n;
        Self {
            mode,
            n,
            g,
            user,
            salt,
            v,
            b,
            big_b,
            big_a: None,
            sent: Vec::new(),
            accepted: 0,
        }
    }

    /// `M1` and the session key for the client's `A`, from the verifier alone.
    fn expected(&self, big_a: &BigUint) -> (Vec<u8>, Vec<u8>) {
        let (pa, pb) = (pad(big_a), pad(&self.big_b));
        let u = BigUint::from_bytes_be(&sha256(&[&pa, &pb]));
        let s = (big_a * self.v.modpow(&u, &self.n)).modpow(&self.b, &self.n);
        let key = sha256(&[&pad(&s)]);
        let hn = sha256(&[&self.n.to_bytes_be()]);
        let hg = sha256(&[&self.g.to_bytes_be()]);
        let xor: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
        let m1 = sha256(&[
            &xor,
            &sha256(&[self.user.as_bytes()]),
            &self.salt,
            &pa,
            &pb,
            &key,
        ]);
        (m1, key)
    }

    fn reply(&mut self, wire: &[u8]) -> String {
        let (target, body) = request_body(wire);
        match target.as_str() {
            "/srp/init" => {
                assert_eq!(body["user"], self.user);
                let big_a = BigUint::from_bytes_be(&unhex(body["A"].as_str().unwrap()));
                assert_eq!(body["A"].as_str().unwrap().len(), 2 * LEN, "A padded to N");
                assert!(
                    big_a.clone() % &self.n != BigUint::from(0u32),
                    "A mod N is not zero"
                );
                self.big_a = Some(big_a);
                let b = match self.mode {
                    Mode::BadB(b) => b.to_string(),
                    _ => hex(&pad(&self.big_b)),
                };
                format!("{{\"salt\":\"{}\",\"B\":\"{b}\"}}", hex(&self.salt))
            }
            "/srp/verify" => {
                let big_a = self.big_a.clone().unwrap();
                let (m1, key) = self.expected(&big_a);
                let got = unhex(body["M1"].as_str().unwrap());
                match self.mode {
                    Mode::Impostor => {
                        format!("{{\"M2\":\"{}\",\"session\":\"s-1\"}}", hex(&[0x42; 32]))
                    }
                    _ if got == m1 => {
                        self.accepted += 1;
                        let m2 = sha256(&[&pad(&big_a), &m1, &key]);
                        format!("{{\"M2\":\"{}\",\"session\":\"s-1\"}}", hex(&m2))
                    }
                    _ => "{\"error\":\"bad proof\"}".to_string(),
                }
            }
            other => panic!("unexpected request to {other}"),
        }
    }
}

impl Transport for SrpServer {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        let body = self.reply(wire);
        Ok(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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

fn srp_fields() -> Vec<FieldSpec> {
    vec![FieldSpec::public("user"), FieldSpec::guessable("password")]
}

fn srp_setup<'c>(clock: &'c TestClock, password: &str) -> Setup<'c> {
    setup(
        clock,
        srp_fields(),
        vec![doc("srp-login")],
        &[("user", b"alice"), ("password", password.as_bytes())],
    )
}

/// The `srp-login` operation of `docs/policy.md`: the node sends `A`, reads the salt and `B`,
/// proves the password with `M1`, which the server recomputes from the verifier, and checks
/// the server's `M2` before it returns the session. Each call has a fresh private value.
#[test]
fn srp_login_against_an_independent_server() {
    let clock = TestClock::at(NOW);
    let s = srp_setup(&clock, "correct horse battery staple");
    let mut seen = Vec::new();
    for _ in 0..3 {
        let mut server = SrpServer::new("alice", "correct horse battery staple", Mode::Honest);
        let response = call(&s, "srp-login", &mut server).result.unwrap();
        assert_eq!(server.sent.len(), 2);
        assert_eq!(server.accepted, 1, "the server accepts M1");
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["/session"], "s-1");
        seen.push(server.big_a.unwrap());
    }
    assert!(
        seen[0] != seen[1] && seen[1] != seen[2],
        "a fresh A each call"
    );
}

/// A wrong password: the server refuses `M1` and sends no `M2`, so the operation fails at the
/// capture. A server that does not know the verifier (it accepts any `M1`) cannot prove
/// itself: `srp_verify` fails the operation and nothing is returned. A `B` of zero, `N` or
/// longer than `N` fails before `M1` is sent.
#[test]
fn srp_login_refuses_a_wrong_password_an_impostor_and_bad_server_values() {
    let clock = TestClock::at(NOW);
    let wrong = srp_setup(&clock, "Tr0ub4dor&3");
    let mut server = SrpServer::new("alice", "correct horse battery staple", Mode::Honest);
    assert!(call(&wrong, "srp-login", &mut server).result.is_err());
    assert_eq!((server.sent.len(), server.accepted), (2, 0));

    let s = srp_setup(&clock, "correct horse battery staple");
    let mut server = SrpServer::new("alice", "correct horse battery staple", Mode::Impostor);
    match call(&s, "srp-login", &mut server).result {
        Err(Error::TemplateInvalid { rule }) => {
            assert_eq!(rule, "the SRP server proof M2 does not match");
        }
        Err(other) => panic!("failed for another reason: {other}"),
        Ok(_) => panic!("an impostor's session was returned"),
    }

    let zero: &'static str = Box::leak("00".repeat(LEN).into_boxed_str());
    let n: &'static str = Box::leak(hex(&unhex(N_2048)).into_boxed_str());
    let long: &'static str = Box::leak(format!("01{}", "00".repeat(LEN)).into_boxed_str());
    for b in [zero, "00", n, long] {
        let mut server = SrpServer::new("alice", "correct horse battery staple", Mode::BadB(b));
        assert!(call(&s, "srp-login", &mut server).result.is_err());
        assert_eq!(server.sent.len(), 1, "M1 is never sent after a bad B");
    }
}

fn srp_refused(computes: &[(&str, &str)], template: &str) -> &'static str {
    refused(
        vec![
            FieldSpec::public("user"),
            FieldSpec::secret("password"),
            FieldSpec::secret("a_field"),
        ],
        vec![derivation("d", computes, template)],
    )
}

fn srp_signs(fields: Vec<FieldSpec>, computes: &[(&str, &str)], template: &str) -> bool {
    signs(fields, vec![derivation("d", computes, template)])
}

const G: &str = "\"rfc5054_2048\"";
const B_LIT: &str = "hexdecode(\"0102\")";

/// What the analysis refuses in the SRP functions, each measured at signing.
#[test]
fn srp_functions_keep_the_secret_in_the_node() {
    let a = ("a", "{{ random(\"32\") }}");
    let x = ("x", "{{ srp_x(\"sha256\", \"salt\", user, password) }}");
    let pre = |b: &str| format!("srp_premaster({G}, \"sha256\", x, a, {b})");
    // Rule 11: the private value is the node's, B and the proofs are the destination's.
    for template in [
        format!("{{{{ hex(srp_public({G}, $input)) }}}}"),
        format!("{{{{ hex(srp_public({G}, hexdecode($input))) }}}}"),
    ] {
        assert_eq!(srp_refused(&[], &template), RULE_11_PRIVATE, "{template}");
    }
    let template = format!(
        "{{{{ hex(sha256(srp_premaster({G}, \"sha256\", x, $input, {B_LIT}) + $input)) }}}}"
    );
    assert_eq!(srp_refused(&[x], &template), RULE_11_PRIVATE);
    let template = format!("{{{{ hex(sha256({} + $input)) }}}}", pre("$input"));
    assert_eq!(srp_refused(&[a, x], &template), RULE_11_SERVER);
    let template = "{{ srp_verify(\"sha256\", \"A\", \"M1\", \"K\", $input) }}";
    assert_eq!(srp_refused(&[], template), RULE_11_SERVER);
    // Rule 6: the group and the hash are the policy's.
    for template in [
        "{{ hex(srp_public($input, a)) }}".to_string(),
        "{{ hex(sha256(srp_x($input, \"s\", user, password) + $input)) }}".to_string(),
        format!("{{{{ hex(srp_u({G}, $input, \"A\", \"B\")) }}}}"),
        format!("{{{{ hex(srp_m1({G}, $input, user, \"s\", \"A\", \"B\", \"K\")) }}}}"),
    ] {
        assert_eq!(srp_refused(&[a], &template), RULE_6, "{template}");
    }
    // Rule 1: padding fails on a value longer than N, so a mixed value may not reach it.
    let template = format!("{{{{ hex(srp_u({G}, \"sha256\", password + $input, \"B\")) }}}}");
    assert_eq!(srp_refused(&[], &template), RULE_1);
    // Rule 5: x, the premaster secret and the session key stay secrets.
    for template in [
        "{{ hex(x) }}".to_string(),
        format!("{{{{ hex({}) }}}}", pre(B_LIT)),
        format!("{{{{ hex(sha256({})) }}}}", pre(B_LIT)),
        // M1 over values the policy fixes alone is a hash of the secret alone (rule 3).
        format!(
            "{{{{ hex(srp_m1({G}, \"sha256\", user, \"s\", srp_public({G}, a), {B_LIT}, sha256({}))) }}}}",
            pre(B_LIT)
        ),
    ] {
        assert_eq!(srp_refused(&[a, x], &template), RULE_5, "{template}");
    }
    // M1 over a chosen salt hides the key; with a guessable password it still lets a guess be
    // checked, which rule 5 refuses.
    let m1 = format!(
        "{{{{ hex(srp_m1({G}, \"sha256\", user, $input, srp_public({G}, a), {B_LIT}, sha256({}))) }}}}",
        pre(B_LIT)
    );
    let fields = |password: FieldSpec| vec![FieldSpec::public("user"), password];
    assert!(srp_signs(
        fields(FieldSpec::secret("password")),
        &[a, x],
        &m1
    ));
    assert!(!srp_signs(
        fields(FieldSpec::guessable("password")),
        &[a, x],
        &m1
    ));
    // `A` and the verifier are one-way: a derivation may hand them back.
    assert!(srp_signs(
        fields(FieldSpec::secret("password")),
        &[a],
        &format!("{{{{ hex(srp_public({G}, a)) }}}}")
    ));
    // The documented login signs (it is set up in the tests above) with a secret password
    // too.
    assert!(signs(
        vec![FieldSpec::public("user"), FieldSpec::secret("password")],
        vec![doc("srp-login")]
    ));
}

// ---------------------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------------------

/// RFC 8032 section 7.1, test 1.
const ED25519_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const KEY_CREATED: u32 = 1_700_000_000;
const SIGNED_AT: u32 = 1_800_000_000;
const DATA: &[u8] = b"release-1.4.2.tar.gz sha256 9f86d081884c7d659a2feaa0c55ad015\n";

/// A packet in the OpenPGP format with the length as RFC 9580 section 4.2.1.1 writes it.
fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | tag];
    let len = body.len();
    if len < 192 {
        out.push(len as u8);
    } else if len < 8384 {
        out.extend([((len - 192) >> 8) as u8 + 192, ((len - 192) & 0xff) as u8]);
    } else {
        out.push(0xff);
        out.extend((len as u32).to_be_bytes());
    }
    out.extend(body);
    out
}

fn mpi(value: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
    let bits = trimmed.first().map_or(0, |top| {
        (trimmed.len() - 1) * 8 + (8 - top.leading_zeros() as usize)
    });
    let mut out = (bits as u16).to_be_bytes().to_vec();
    out.extend(trimmed);
    out
}

/// The binary form of armored text, its CRC-24 line checked when present.
fn dearmor(text: &[u8], crc: bool) -> Vec<u8> {
    let text = std::str::from_utf8(text).unwrap();
    let mut lines = text.split('\n');
    assert_eq!(lines.next(), Some("-----BEGIN PGP SIGNATURE-----"));
    assert_eq!(lines.next(), Some(""), "no armor header");
    let mut b64 = String::new();
    let mut checksum = None;
    for line in lines.by_ref() {
        if line.starts_with("-----END PGP SIGNATURE-----") {
            break;
        }
        if let Some(sum) = line.strip_prefix('=') {
            checksum = Some(STANDARD.decode(sum).unwrap());
        } else {
            assert!(line.len() <= 64, "lines of at most 64 characters");
            b64.push_str(line);
        }
    }
    assert!(text.ends_with("-----END PGP SIGNATURE-----\n"));
    let data = STANDARD.decode(b64).unwrap();
    assert_eq!(checksum.is_some(), crc);
    if let Some(sum) = checksum {
        // RFC 9580 section 6.1.1, written here bit by bit.
        let mut c: u32 = 0xb704ce;
        for &b in &data {
            c ^= u32::from(b) << 16;
            for _ in 0..8 {
                c <<= 1;
                if c & 0x100_0000 != 0 {
                    c ^= 0x186_4cfb;
                }
            }
        }
        assert_eq!(sum, (c & 0xff_ffff).to_be_bytes()[1..]);
    }
    data
}

/// A signature packet parsed by RFC 9580 section 5.2.3.
struct Signature {
    version: u8,
    algorithm: u8,
    hashed_part: Vec<u8>,
    hashed_subpackets: Vec<u8>,
    unhashed: Vec<u8>,
    left16: Vec<u8>,
    salt: Vec<u8>,
    material: Vec<u8>,
}

fn parse_signature(bytes: &[u8]) -> Signature {
    assert_eq!(bytes[0], 0xc2, "a signature packet, OpenPGP format");
    let (len, body) = match bytes[1] {
        l @ 0..=191 => (usize::from(l), &bytes[2..]),
        l @ 192..=223 => (
            ((usize::from(l) - 192) << 8) + usize::from(bytes[2]) + 192,
            &bytes[3..],
        ),
        0xff => (
            u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize,
            &bytes[6..],
        ),
        _ => panic!("a partial length"),
    };
    assert_eq!(body.len(), len, "one packet");
    let version = body[0];
    assert_eq!(body[1], 0x00, "a binary signature");
    assert_eq!(body[3], 8, "SHA-256");
    // Subpacket area lengths: two octets in v4, four in v6.
    let width = if version == 6 { 4 } else { 2 };
    let area = |at: usize| -> usize {
        body[at..at + width]
            .iter()
            .fold(0usize, |n, b| (n << 8) | usize::from(*b))
    };
    let hashed_len = area(4);
    let hashed_end = 4 + width + hashed_len;
    let unhashed_len = area(hashed_end);
    let mut rest = &body[hashed_end + width + unhashed_len..];
    let left16 = rest[..2].to_vec();
    rest = &rest[2..];
    let salt = if version == 6 {
        let n = usize::from(rest[0]);
        let salt = rest[1..1 + n].to_vec();
        rest = &rest[1 + n..];
        salt
    } else {
        Vec::new()
    };
    Signature {
        version,
        algorithm: body[2],
        hashed_part: body[..hashed_end].to_vec(),
        hashed_subpackets: body[4 + width..hashed_end].to_vec(),
        unhashed: body[hashed_end + width..hashed_end + width + unhashed_len].to_vec(),
        left16,
        salt,
        material: rest.to_vec(),
    }
}

/// What a signature hashes (RFC 9580 section 5.2.4): the salt (v6), the data, the hashed part
/// and the trailer.
fn hashed_input(data: &[u8], sig: &Signature) -> Vec<u8> {
    let mut out = sig.salt.clone();
    out.extend(data);
    out.extend(&sig.hashed_part);
    out.extend([sig.version, 0xff]);
    out.extend((sig.hashed_part.len() as u32).to_be_bytes());
    out
}

fn v4_fingerprint(key_body: &[u8]) -> Vec<u8> {
    let mut framed = vec![0x99];
    framed.extend((key_body.len() as u16).to_be_bytes());
    framed.extend(key_body);
    sha1(&framed)
}

fn v6_fingerprint(key_body: &[u8]) -> Vec<u8> {
    sha256(&[&[0x9b], &(key_body.len() as u32).to_be_bytes(), key_body])
}

fn eddsa_legacy_key_body() -> Vec<u8> {
    let mut body = vec![4];
    body.extend(KEY_CREATED.to_be_bytes());
    body.push(22);
    body.extend(unhex("092b06010401da470f01"));
    let mut point = vec![0x40];
    point.extend(unhex(ED25519_PUBLIC));
    body.extend(mpi(&point));
    body
}

fn v6_key_body() -> Vec<u8> {
    let mut body = vec![6];
    body.extend(KEY_CREATED.to_be_bytes());
    body.push(27);
    body.extend(32u32.to_be_bytes());
    body.extend(unhex(ED25519_PUBLIC));
    body
}

fn rsa_key_body(public: &rsa::PublicKey) -> Vec<u8> {
    use rsa::traits::PublicKeyParts as _;
    let mut body = vec![4];
    body.extend(KEY_CREATED.to_be_bytes());
    body.push(1);
    body.extend(mpi(&public.n_bytes()));
    body.extend(mpi(&public.e_bytes()));
    body
}

/// The subpackets: creation time and issuer fingerprint hashed, and in v4 the issuer key ID
/// unhashed.
fn check_subpackets(sig: &Signature, fingerprint: &[u8]) {
    let mut expected = vec![5, 2];
    expected.extend(SIGNED_AT.to_be_bytes());
    expected.extend([fingerprint.len() as u8 + 2, 33, sig.version]);
    expected.extend(fingerprint);
    assert_eq!(sig.hashed_subpackets, expected);
    if sig.version == 4 {
        let mut issuer = vec![9, 16];
        issuer.extend(&fingerprint[12..]);
        assert_eq!(sig.unhashed, issuer);
    } else {
        assert!(sig.unhashed.is_empty());
    }
}

fn rsa_private() -> rsa::PrivateKey {
    use rsa::pkcs8::DecodePrivateKey as _;
    rsa::PrivateKey::from_pkcs8_der(&pem_body(include_str!("fixtures/rsa2048.pem"))).unwrap()
}

fn openpgp_setup(clock: &TestClock) -> Setup<'_> {
    let pem = include_str!("fixtures/rsa2048.pem");
    setup(
        clock,
        vec![
            FieldSpec::secret("ed_key"),
            FieldSpec::secret("rsa_key"),
            FieldSpec::public("key_created"),
        ],
        vec![
            doc("openpgp-rsa"),
            doc("openpgp-eddsa-legacy"),
            doc("openpgp-v6-ed25519"),
        ],
        &[
            ("ed_key", &unhex(ED25519_SECRET)),
            ("rsa_key", pem.as_bytes()),
            ("key_created", KEY_CREATED.to_string().as_bytes()),
        ],
    )
}

fn ed25519_verifies(message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, unhex(ED25519_PUBLIC))
        .verify(message, signature)
        .is_ok()
}

/// The three signing operations of `docs/policy.md`. Each armored signature is read here,
/// its packet parsed, its fingerprint and key ID checked against a key packet built here,
/// its hash rebuilt, and its signature verified: RSA by the `rsa` crate over the hashed data,
/// Ed25519 by ring over the digest (RFC 9580 section 5.2.3.4).
#[test]
fn openpgp_detached_signatures_verify() {
    use rsa::signature::Verifier as _;
    let clock = TestClock::at(u64::from(SIGNED_AT) * 1000);
    let s = openpgp_setup(&clock);
    keep("data.txt", DATA);

    // Version 4, RSA, armor with the CRC-24.
    let armored = derive(&s, "openpgp-rsa", DATA).unwrap();
    keep("rsa.asc", &armored);
    let sig = parse_signature(&dearmor(&armored, true));
    assert_eq!((sig.version, sig.algorithm), (4, 1));
    let private = rsa_private();
    let public = private.to_public_key();
    check_subpackets(&sig, &v4_fingerprint(&rsa_key_body(&public)));
    let input = hashed_input(DATA, &sig);
    assert_eq!(sig.left16, sha256(&[&input])[..2]);
    let bits = usize::from(u16::from_be_bytes([sig.material[0], sig.material[1]]));
    let value = &sig.material[2..];
    assert_eq!(value.len(), bits.div_ceil(8), "one MPI, nothing after it");
    assert_ne!(value[0], 0, "an MPI has no leading zero octet");
    let mut padded = vec![0u8; 256 - value.len()];
    padded.extend(value);
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public);
    let signature = rsa::pkcs1v15::Signature::try_from(padded.as_slice()).unwrap();
    assert!(verifier.verify(&input, &signature).is_ok());
    assert!(verifier.verify(b"other data", &signature).is_err());

    // Version 4, EdDSALegacy: r and s as two MPIs.
    let armored = derive(&s, "openpgp-eddsa-legacy", DATA).unwrap();
    keep("eddsa.asc", &armored);
    let sig = parse_signature(&dearmor(&armored, true));
    assert_eq!((sig.version, sig.algorithm), (4, 22));
    check_subpackets(&sig, &v4_fingerprint(&eddsa_legacy_key_body()));
    let digest = sha256(&[&hashed_input(DATA, &sig)]);
    assert_eq!(sig.left16, digest[..2]);
    let r_bits = usize::from(u16::from_be_bytes([sig.material[0], sig.material[1]]));
    let r = &sig.material[2..2 + r_bits.div_ceil(8)];
    let rest = &sig.material[2 + r.len()..];
    let s_bits = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    let s_value = &rest[2..];
    assert_eq!(
        s_value.len(),
        s_bits.div_ceil(8),
        "two MPIs, nothing after them"
    );
    let mut rs = vec![0u8; 32 - r.len()];
    rs.extend(r);
    rs.extend(vec![0u8; 32 - s_value.len()]);
    rs.extend(s_value);
    assert!(ed25519_verifies(&digest, &rs));
    assert!(!ed25519_verifies(&sha256(&[b"other"]), &rs));

    // Version 6, Ed25519: a fresh salt each call, armor without the CRC-24.
    let first = derive(&s, "openpgp-v6-ed25519", DATA).unwrap();
    keep("v6.asc", &first);
    let second = derive(&s, "openpgp-v6-ed25519", DATA).unwrap();
    let mut salts = Vec::new();
    for armored in [&first, &second] {
        let sig = parse_signature(&dearmor(armored, false));
        assert_eq!((sig.version, sig.algorithm), (6, 27));
        assert_eq!(sig.salt.len(), 16, "the salt size of SHA-256");
        check_subpackets(&sig, &v6_fingerprint(&v6_key_body()));
        let digest = sha256(&[&hashed_input(DATA, &sig)]);
        assert_eq!(sig.left16, digest[..2]);
        assert_eq!(sig.material.len(), 64, "the native Ed25519 signature");
        assert!(ed25519_verifies(&digest, &sig.material));
        // Without the salt the hash is another.
        let unsalted = Signature {
            salt: Vec::new(),
            ..parse_signature(&dearmor(armored, false))
        };
        assert!(!ed25519_verifies(
            &sha256(&[&hashed_input(DATA, &unsalted)]),
            &sig.material
        ));
        salts.push(sig.salt);
    }
    assert_ne!(salts[0], salts[1]);

    // Certificates for GnuPG, which the test does not run (`--import`, then `--verify`).
    keep("rsa.pub", &rsa_certificate(&private));
    keep("eddsa.pub", &eddsa_certificate());
}

/// The framing functions against RFC 9580 directly: the three length forms, the critical
/// bit, MPIs of zero and of a value with leading zeros, the CRC-24 of the armor.
#[test]
fn openpgp_framing_follows_rfc9580() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::public("p")],
        vec![
            derivation("packet", &[], "{{ hex(pgp_packet(\"11\", $input)) }}"),
            derivation("sub", &[], "{{ hex(pgp_subpacket(\"130\", $input)) }}"),
            derivation("mpi", &[], "{{ hex(pgp_mpi($input)) }}"),
            derivation(
                "armor",
                &[],
                "{{ pgp_armor(\"SIGNATURE\", $input, \"crc24\") }}",
            ),
            derivation("bad_type", &[], "{{ hex(pgp_packet(\"64\", $input)) }}"),
        ],
        &[("p", b"x")],
    );
    for n in [0usize, 1, 191, 192, 8383, 8384, 10_000] {
        let input = vec![0x5a; n];
        let out = unhex(std::str::from_utf8(&derive(&s, "packet", &input).unwrap()).unwrap());
        assert_eq!(out, packet(11, &input), "a packet of {n} bytes");
        let out = unhex(std::str::from_utf8(&derive(&s, "sub", &input).unwrap()).unwrap());
        // A subpacket's length covers its type octet.
        let mut body = vec![130u8];
        body.extend(&input);
        assert_eq!(out, packet(0, &body)[1..], "a subpacket of {n} bytes");
    }
    for (value, expected) in [
        (&b""[..], "0000"),
        (b"\x00\x00", "0000"),
        (b"\x01", "000101"),
        (b"\x00\x7f\xff", "000f7fff"),
        (b"\x80\x00", "00108000"),
    ] {
        assert_eq!(derive(&s, "mpi", value).unwrap(), expected.as_bytes());
    }
    let armored = derive(&s, "armor", b"\x01\x02\x03").unwrap();
    // `dearmor` checks the CRC-24 line against the definition, written there bit by bit.
    assert_eq!(dearmor(&armored, true), b"\x01\x02\x03");
    assert!(derive(&s, "bad_type", b"x").is_err());
}

/// What the analysis refuses in the OpenPGP functions, measured at signing.
#[test]
fn openpgp_functions_keep_the_secret_in_the_node() {
    let fields = || vec![FieldSpec::secret("ed_key"), FieldSpec::public("p")];
    let refused_with = |template: &str| refused(fields(), vec![derivation("d", &[], template)]);
    // Rule 10: an MPI's length tells the leading zeros of its value.
    assert_eq!(refused_with("{{ hex(pgp_mpi(ed_key)) }}"), RULE_10_MPI);
    assert_eq!(refused_with("{{ len(pgp_mpi(ed_key)) }}"), RULE_10_MPI);
    // Rule 6: the label and the checksum are the policy's.
    assert_eq!(refused_with("{{ pgp_armor($input, \"x\") }}"), RULE_6);
    assert_eq!(
        refused_with("{{ pgp_armor(\"MESSAGE\", \"x\", $input) }}"),
        RULE_6
    );
    // Rule 1: a packet type is a number argument.
    assert_eq!(
        refused_with("{{ hex(pgp_packet(ed_key + $input, \"x\")) }}"),
        RULE_1
    );
    // Rule 5: framing and armor keep the taint of what they frame.
    for template in [
        "{{ pgp_armor(\"PRIVATE KEY BLOCK\", ed_key) }}",
        "{{ hex(pgp_packet(\"5\", ed_key)) }}",
        "{{ hex(pgp_subpacket(\"2\", ed_key + $input)) }}",
    ] {
        assert_eq!(refused_with(template), RULE_5, "{template}");
    }
    // The public key and a signature are not secrets.
    assert!(signs(
        fields(),
        vec![derivation(
            "d",
            &[],
            "{{ hex(pgp_mpi(ed25519_public(ed_key)) + pgp_mpi(ed25519_sign(ed_key, $input))) }}"
        )]
    ));
}

/// A transferable public key for `gpg --import` (RFC 9580 section 10.1): the key packet, a
/// user ID and a positive self-certification (type 0x13) signed by `sign` over the hashed
/// data.
fn certificate(body: &[u8], algorithm: u8, sign: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let fingerprint = v4_fingerprint(body);
    let uid = b"Release signing (test) <release@example.com>";
    let mut sub = vec![5, 2];
    sub.extend(KEY_CREATED.to_be_bytes());
    sub.extend([2, 27, 0x03]);
    sub.extend([22, 33, 4]);
    sub.extend(&fingerprint);
    let mut hashed = vec![4, 0x13, algorithm, 8];
    hashed.extend((sub.len() as u16).to_be_bytes());
    hashed.extend(&sub);
    let mut input = vec![0x99];
    input.extend((body.len() as u16).to_be_bytes());
    input.extend(body);
    input.push(0xb4);
    input.extend((uid.len() as u32).to_be_bytes());
    input.extend(uid);
    input.extend(&hashed);
    input.extend([0x04, 0xff]);
    input.extend((hashed.len() as u32).to_be_bytes());
    let mut sig = hashed;
    sig.extend([0, 10, 9, 16]);
    sig.extend(&fingerprint[12..]);
    sig.extend(&sha256(&[&input])[..2]);
    sig.extend(sign(&input));
    let mut out = packet(6, body);
    out.extend(packet(13, uid));
    out.extend(packet(2, &sig));
    out
}

fn rsa_certificate(private: &rsa::PrivateKey) -> Vec<u8> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private.clone());
    certificate(&rsa_key_body(&private.to_public_key()), 1, |input| {
        mpi(&signer.sign(input).to_vec())
    })
}

fn eddsa_certificate() -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&unhex(ED25519_SECRET).try_into().unwrap());
    certificate(&eddsa_legacy_key_body(), 22, |input| {
        let signature = key.sign(&sha256(&[input])).to_bytes();
        let mut out = mpi(&signature[..32]);
        out.extend(mpi(&signature[32..]));
        out
    })
}
