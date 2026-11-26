//! The two families the scheme tables of `docs/design.md` section 11 found missing, DEFLATE
//! (RFC 1951, with the zlib and gzip framings of RFC 1950 and RFC 1952) and XML
//! canonicalization (Canonical XML 1.0 and 1.1, Exclusive XML Canonicalization 1.0), and the
//! schemes they unblock: the SAML 2.0 HTTP-Redirect binding signed with RSA-SHA256 and ECDSA,
//! the HTTP-POST binding with an enveloped XML signature, and WS-Security (a UsernameToken
//! digest, a signature over the timestamp and the body with a BinarySecurityToken).
//!
//! The policies are the operations of `docs/policy.md` (Compression and XML), read from that
//! file. Each signature is checked by a verifier written here over the `rsa` and `ring`
//! crates, against canonical forms written out by hand from the specifications, and each
//! DEFLATE stream the engine writes is inflated by a decoder written here (not the engine's
//! `miniz_oxide`); the streams the engine reads come from the zlib C library
//! (`fixtures/deflate/deflate-zlib.json`). Every guarantee has its attack.
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
use engine::node::{Clock, Node, Outcome, Response};
use engine::policy::{Caller, Destination, FieldSpec, Method, Operation, Policy};
use engine::record::Record;
use engine::request::Request;
use serde_json::{Value, json};
use sha2::Digest as _;

const OWNER: &str = "user-1";
/// 2027-01-15T08:00:00Z.
const NOW: u64 = 1_800_000_000_000;
const INSTANT: &str = "2027-01-15T08:00:00Z";
const DAY: u64 = 24 * 60 * 60 * 1000;
const POLICY_MD: &str = include_str!("../../../docs/policy.md");

const RULE_1: &str = "a secret mixed with a chosen value reaches a decoder, number or key";
const RULE_2: &str = "a secret and a chosen value meet in a function that compares or cuts them";
const RULE_5: &str = "a derivation would hand a secret back";
const RULE_6: &str = "a hash or curve name must be fixed by the policy";
const RULE_9: &str = "a length must not depend on a secret";
const RULE_10: &str = "a secret may not be compressed: the length would tell it";

const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSU: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";

/// The service provider's entity ID: the `&` checks `xml_escape` on the way into the XML.
const ENTITY_ID: &str = "https://sp.example.com/metadata?tenant=a&b";
const ENTITY_ID_XML: &str = "https://sp.example.com/metadata?tenant=a&amp;b";
const RELAY_STATE: &str = "/after login?x=1";
/// RFC 6979 appendix A.2.5 (P-256): the private key and `Ux || Uy`.
const P256_SECRET: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
const P256_PUBLIC: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

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
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    }

    /// The query parameters as sent: name and value, each still percent-encoded.
    fn query(&self) -> Vec<(String, String)> {
        let query = self.target.split_once('?').map_or("", |(_, q)| q);
        pairs(query)
    }
}

fn pairs(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, v) = p.split_once('=').unwrap_or((p, ""));
            (n.to_string(), v.to_string())
        })
        .collect()
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

/// Percent-decoding as `application/x-www-form-urlencoded` reads it (`+` is a space).
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

fn unhex(text: &str) -> Vec<u8> {
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

/// The text between `start` and the next `end` in `text`.
fn between<'t>(text: &'t str, start: &str, end: &str) -> &'t str {
    let from = text.find(start).unwrap() + start.len();
    let to = from + text[from..].find(end).unwrap();
    &text[from..to]
}

/// The operation `name` of `docs/policy.md`.
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

fn try_derive(s: &Setup<'_>, operation: &str, input: &[u8]) -> engine::Result<Vec<u8>> {
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

/// The rule a rendering broke.
fn render_refusal(result: engine::Result<Vec<u8>>) -> &'static str {
    match result {
        Err(Error::TemplateInvalid { rule }) => rule,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("rendered"),
    }
}

/// An operation with no connection that returns `template` over a raw `$input`.
fn derivation(name: &str, template: &str) -> Operation {
    operation(json!({"name": name, "input": {"raw": {}},
        "steps": [{"do": "return", "template": template}]}))
}

/// An HTTPS operation to `example.com` whose fixed request gets one header `X-Out`.
fn https_header(name: &str, template: &str) -> Operation {
    operation(json!({"name": name, "steps": [
        {"do": "open", "connection": "https",
         "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/x"},
         "inject": [{"target": {"kind": "header", "name": "X-Out"}, "template": template}]},
        {"do": "return"}
    ]}))
}

/// The SP's RSA key (the test fixture) and its public half.
fn rsa_key() -> (String, rsa::PublicKey) {
    use rsa::pkcs8::DecodePrivateKey as _;
    let pem = include_str!("fixtures/rsa2048.pem").to_string();
    let private = rsa::PrivateKey::from_pkcs8_der(&pem_body(&pem)).unwrap();
    (pem, private.to_public_key())
}

fn rsa_sha256_verifies(public: &rsa::PublicKey, message: &[u8], signature: &[u8]) -> bool {
    use rsa::signature::Verifier as _;
    let key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public.clone());
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn p256_verifies(message: &[u8], signature: &[u8]) -> bool {
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let mut public = vec![4u8];
    public.extend(unhex(P256_PUBLIC));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(message, signature)
        .is_ok()
}

fn b64_sha256(bytes: &[u8]) -> String {
    STANDARD.encode(sha2::Sha256::digest(bytes))
}

/// When `CREDENTIALS_INTEROP_DIR` is set, writes `bytes` there, so tools outside this test
/// (`fixtures/xml/interop/`) can check what the engine produced.
fn keep(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("CREDENTIALS_INTEROP_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

// ---------------------------------------------------------------------------------------
// An independent DEFLATE decoder (RFC 1951), to read what the engine writes
// ---------------------------------------------------------------------------------------

mod puff {
    //! RFC 1951 decoding in the shape of zlib's `contrib/puff`, written for this test.

    struct Bits<'a> {
        data: &'a [u8],
        pos: usize,
        buf: u32,
        count: u32,
    }

    impl Bits<'_> {
        fn bits(&mut self, n: u32) -> Option<u32> {
            while self.count < n {
                self.buf |= u32::from(*self.data.get(self.pos)?) << self.count;
                self.pos += 1;
                self.count += 8;
            }
            let v = self.buf & ((1u32 << n) - 1);
            self.buf = if n == 32 { 0 } else { self.buf >> n };
            self.count -= n;
            Some(v)
        }
    }

    struct Huffman {
        count: [u16; 16],
        symbol: Vec<u16>,
    }

    impl Huffman {
        fn new(lengths: &[u8]) -> Self {
            let mut count = [0u16; 16];
            for &l in lengths {
                count[usize::from(l)] += 1;
            }
            // The first code of each length; codes of length 0 are absent.
            let mut offs = [0u16; 16];
            for len in 2..16 {
                offs[len] = offs[len - 1] + count[len - 1];
            }
            let mut symbol = vec![0u16; lengths.len()];
            for (s, &l) in lengths.iter().enumerate() {
                if l != 0 {
                    symbol[usize::from(offs[usize::from(l)])] = s as u16;
                    offs[usize::from(l)] += 1;
                }
            }
            Huffman { count, symbol }
        }

        fn decode(&self, bits: &mut Bits<'_>) -> Option<u16> {
            let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
            for len in 1..16 {
                code |= bits.bits(1)? as i32;
                let count = i32::from(self.count[len]);
                if code - count < first {
                    return self.symbol.get((index + code - first) as usize).copied();
                }
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            None
        }
    }

    const LBASE: [u16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LEXT: [u32; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DBASE: [u16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DEXT: [u32; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    fn codes(bits: &mut Bits<'_>, out: &mut Vec<u8>, lit: &Huffman, dist: &Huffman) -> Option<()> {
        loop {
            let symbol = lit.decode(bits)?;
            match symbol {
                0..=255 => out.push(symbol as u8),
                256 => return Some(()),
                _ => {
                    let i = usize::from(symbol - 257);
                    let len = usize::from(*LBASE.get(i)?) + bits.bits(*LEXT.get(i)?)? as usize;
                    let d = usize::from(dist.decode(bits)?);
                    let back = usize::from(*DBASE.get(d)?) + bits.bits(*DEXT.get(d)?)? as usize;
                    let start = out.len().checked_sub(back)?;
                    for k in 0..len {
                        out.push(out[start + k]);
                    }
                }
            }
        }
    }

    /// The inflated bytes and the input bytes read, or `None` for a damaged stream.
    pub fn inflate(data: &[u8]) -> Option<(Vec<u8>, usize)> {
        let mut bits = Bits {
            data,
            pos: 0,
            buf: 0,
            count: 0,
        };
        let mut out = Vec::new();
        loop {
            let last = bits.bits(1)?;
            match bits.bits(2)? {
                0 => {
                    bits.buf = 0;
                    bits.count = 0;
                    let len = usize::from(u16::from_le_bytes([
                        *data.get(bits.pos)?,
                        *data.get(bits.pos + 1)?,
                    ]));
                    let nlen =
                        u16::from_le_bytes([*data.get(bits.pos + 2)?, *data.get(bits.pos + 3)?]);
                    if nlen != !(len as u16) {
                        return None;
                    }
                    bits.pos += 4;
                    out.extend_from_slice(data.get(bits.pos..bits.pos + len)?);
                    bits.pos += len;
                }
                1 => {
                    let mut lengths = [0u8; 288];
                    lengths[..144].fill(8);
                    lengths[144..256].fill(9);
                    lengths[256..280].fill(7);
                    lengths[280..].fill(8);
                    codes(
                        &mut bits,
                        &mut out,
                        &Huffman::new(&lengths),
                        &Huffman::new(&[5u8; 30]),
                    )?;
                }
                2 => {
                    let nlen = bits.bits(5)? as usize + 257;
                    let ndist = bits.bits(5)? as usize + 1;
                    let ncode = bits.bits(4)? as usize + 4;
                    const ORDER: [usize; 19] = [
                        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                    ];
                    let mut code_lengths = [0u8; 19];
                    for &o in ORDER.iter().take(ncode) {
                        code_lengths[o] = bits.bits(3)? as u8;
                    }
                    let code = Huffman::new(&code_lengths);
                    let mut lengths = Vec::new();
                    while lengths.len() < nlen + ndist {
                        let symbol = code.decode(&mut bits)?;
                        let (value, repeat) = match symbol {
                            0..=15 => (symbol as u8, 1),
                            16 => (*lengths.last()?, 3 + bits.bits(2)? as usize),
                            17 => (0, 3 + bits.bits(3)? as usize),
                            _ => (0, 11 + bits.bits(7)? as usize),
                        };
                        lengths.extend(std::iter::repeat_n(value, repeat));
                    }
                    if lengths.len() != nlen + ndist {
                        return None;
                    }
                    let lit = Huffman::new(&lengths[..nlen]);
                    let dist = Huffman::new(&lengths[nlen..]);
                    codes(&mut bits, &mut out, &lit, &dist)?;
                }
                _ => return None,
            }
            if last == 1 {
                return Some((out, bits.pos));
            }
        }
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// CRC-32 bit by bit (the engine's is table-driven).
fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &x in data {
        c ^= u32::from(x);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Reads a zlib stream with the decoder above: the header checks of RFC 1950 and the
/// Adler-32.
fn read_zlib(stream: &[u8]) -> Vec<u8> {
    let (cmf, flg) = (stream[0], stream[1]);
    assert_eq!(cmf & 0x0f, 8, "CM is not DEFLATE");
    assert!(cmf >> 4 <= 7, "window over 32 KiB");
    assert_eq!((u16::from(cmf) * 256 + u16::from(flg)) % 31, 0, "FCHECK");
    assert_eq!(flg & 0x20, 0, "a preset dictionary");
    let (out, used) = puff::inflate(&stream[2..]).unwrap();
    assert_eq!(stream.len(), 2 + used + 4, "trailer");
    assert_eq!(stream[2 + used..], adler32(&out).to_be_bytes());
    out
}

/// Reads a gzip member written with no optional fields.
fn read_gzip(stream: &[u8]) -> Vec<u8> {
    assert_eq!(stream[..4], [0x1f, 0x8b, 8, 0], "ID, CM, no flags");
    let (out, used) = puff::inflate(&stream[10..]).unwrap();
    let trailer = &stream[10 + used..];
    assert_eq!(trailer.len(), 8);
    assert_eq!(trailer[..4], crc32(&out).to_le_bytes());
    assert_eq!(trailer[4..], (out.len() as u32).to_le_bytes());
    out
}

// ---------------------------------------------------------------------------------------
// DEFLATE, zlib and gzip
// ---------------------------------------------------------------------------------------

#[test]
fn the_test_decoders_agree_with_published_values() {
    // CRC-32/ISO-HDLC and Adler-32 check values.
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    // zlib's compression of "a" (RFC 1950 header 78 9c, one fixed Huffman block).
    assert_eq!(read_zlib(&unhex("789c4b040000620062")), b"a");
}

/// Every stream of `fixtures/deflate/deflate-zlib.json` (written by the zlib library): the
/// good ones inflate to the bytes zlib compressed, the damaged ones, the bombs and the
/// stream one byte over the cap are refused.
#[test]
fn inflate_reads_what_zlib_writes_and_refuses_the_rest() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/deflate/deflate-zlib.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 60);
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        vec![
            derivation("raw", "{{ hex(sha256(inflate($input))) }}"),
            derivation("zlib", "{{ hex(sha256(zlib_inflate($input))) }}"),
            derivation("gzip", "{{ hex(sha256(gzip_inflate($input))) }}"),
        ],
        &[],
    );
    let (mut good, mut bad) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let framing = case["framing"].as_str().unwrap();
        let stream = unhex(case["stream"].as_str().unwrap());
        let result = try_derive(&s, framing, &stream);
        let expected = match (&case["output"], case.get("zeros")) {
            (Value::String(h), _) => Some(unhex(h)),
            (_, Some(n)) => Some(vec![0u8; n.as_u64().unwrap() as usize]),
            _ => None,
        };
        match expected {
            Some(bytes) => {
                good += 1;
                let out = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(
                    out,
                    hex(&sha2::Sha256::digest(&bytes)).into_bytes(),
                    "{name}"
                );
            }
            None => {
                bad += 1;
                let rule = render_refusal(result);
                if name.contains("bomb") || name.contains("over-the-cap") {
                    assert_eq!(rule, "an inflated value over the size limit", "{name}");
                }
            }
        }
    }
    assert_eq!((good, bad), (41, 19));
}

/// What the engine compresses, the decoder of this test reads back: raw, zlib (header and
/// Adler-32 checked) and gzip (header, CRC-32 and length checked), for inputs that compress
/// well and inputs that do not; and the engine's own inflation reads it too.
#[test]
fn deflate_writes_streams_an_independent_decoder_reads() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        vec![
            derivation("raw", "{{ hex(deflate($input)) }}"),
            derivation("zlib", "{{ hex(zlib_deflate($input)) }}"),
            derivation("gzip", "{{ hex(gzip_deflate($input)) }}"),
            derivation(
                "round",
                "{{ inflate(deflate($input)) + zlib_inflate(zlib_deflate($input)) + gzip_inflate(gzip_deflate($input)) }}",
            ),
        ],
        &[],
    );
    let pseudo_random: Vec<u8> = (0u32..70_000)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let inputs: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("one", b"a".to_vec()),
        ("text", b"<samlp:AuthnRequest/>".repeat(500)),
        ("noise", pseudo_random),
    ];
    for (name, input) in &inputs {
        let raw = unhex(std::str::from_utf8(&try_derive(&s, "raw", input).unwrap()).unwrap());
        let (out, used) = puff::inflate(&raw).unwrap();
        assert_eq!(&out, input, "{name}");
        assert_eq!(used, raw.len(), "{name}");
        let zlib = unhex(std::str::from_utf8(&try_derive(&s, "zlib", input).unwrap()).unwrap());
        assert_eq!(&read_zlib(&zlib), input, "{name}");
        let gzip = unhex(std::str::from_utf8(&try_derive(&s, "gzip", input).unwrap()).unwrap());
        assert_eq!(&read_gzip(&gzip), input, "{name}");
        assert_eq!(
            gzip[4..10],
            [0, 0, 0, 0, 0, 0xff],
            "MTIME 0, XFL 0, OS unknown"
        );
        assert_eq!(
            try_derive(&s, "round", input).unwrap(),
            input.repeat(3),
            "{name}"
        );
        keep(&format!("deflate-{name}.raw"), &raw);
        keep(&format!("deflate-{name}.zlib"), &zlib);
        keep(&format!("deflate-{name}.gz"), &gzip);
        keep(&format!("deflate-{name}.in"), input);
        if *name == "text" {
            assert!(raw.len() < input.len() / 20, "{} bytes", raw.len());
        }
    }
}

/// Rule 10: no compression of a secret, alone or with chosen bytes (CRIME), in a request or
/// a derivation, and not through `len`; a public value compresses anywhere.
#[test]
fn compression_of_a_secret_is_refused() {
    let fields = || {
        vec![
            FieldSpec::secret("key"),
            FieldSpec::guessable("password"),
            FieldSpec::public("user"),
        ]
    };
    for template in [
        "{{ hex(deflate(key)) }}",
        "{{ len(deflate(key)) }}",
        "{{ len(zlib_deflate(password)) }}",
        "{{ hex(sha256(gzip_deflate(user + key))) }}",
        "{{ len(deflate(key + $input)) }}",
        "{{ len(deflate(b64(key))) }}",
    ] {
        assert_eq!(
            refused(fields(), vec![derivation("d", template)]),
            RULE_10,
            "{template}"
        );
    }
    for template in [
        "{{ b64(deflate(key)) }}",
        "{{ b64(gzip_deflate(\"user=\" + user + \"&pin=\" + password)) }}",
    ] {
        assert_eq!(
            refused(fields(), vec![https_header("h", template)]),
            RULE_10,
            "{template}"
        );
    }
    // A secret captured from a response is a secret too.
    let captured = operation(json!({"name": "c", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/a"}},
        {"do": "receive", "capture": [{"source": {"from": "header", "name": "X-Token"},
            "into": {"kind": "temp", "name": "token", "secret": true}}]},
        {"do": "send", "request": {"from": "fixed", "method": "POST", "path": "/b"},
         "inject": [{"target": {"kind": "body"}, "template": "{{ deflate(token) }}"}]},
        {"do": "return"}
    ]}));
    assert_eq!(refused(fields(), vec![captured]), RULE_10);
    // Public values and chosen bytes compress.
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        fields(),
        vec![derivation("ok", "{{ len(deflate(user + $input)) }}")],
        &[("key", b"k"), ("password", b"p"), ("user", b"u")],
    );
    assert!(try_derive(&s, "ok", b"abc").is_ok());
}

/// Inflation reads a secret (the output stays one) but not a secret mixed with chosen bytes,
/// whose failing or not would tell about the secret (rule 1).
#[test]
fn inflate_follows_the_rules() {
    let fields = || vec![FieldSpec::secret("key"), FieldSpec::public("user")];
    assert_eq!(
        refused(
            fields(),
            vec![derivation("d", "{{ hex(inflate(key + $input)) }}")]
        ),
        RULE_1
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation(
                "d",
                "{{ len(gzip_inflate(b64decode(key) + $input)) }}"
            )]
        ),
        RULE_1
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation("d", "{{ hex(zlib_inflate(key)) }}")]
        ),
        RULE_5
    );
    assert_eq!(
        refused(
            fields(),
            vec![derivation("d", "{{ xml_escape(key + $input) }}")]
        ),
        RULE_1
    );
    // A secret inflated into a request is allowed, like a decoded one.
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        fields(),
        vec![https_header("h", "{{ b64(inflate(key)) }}")],
        &[("key", &unhex("4b0400")[..]), ("user", b"u")],
    );
    let mut server = FakeServer::default();
    call(&s, "h", None, &mut server).result.unwrap();
    assert_eq!(parse(&server.sent[0]).header("X-Out"), Some("YQ=="));
}

/// A bomb is refused at the cap of one inflation, and inflations count against the 128 MiB
/// an operation may render: 130 inflations of 1 MiB each fail on the budget.
#[test]
fn inflation_counts_against_the_budget() {
    let clock = TestClock::at(NOW);
    let many = vec!["inflate(z)"; 130].join(" + ");
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        vec![
            operation(json!({"name": "many", "input": {"raw": {}}, "steps": [
                {"do": "compute", "into": "z", "template": "{{ $input }}"},
                {"do": "return", "template": format!("{{{{ len({many}) }}}}")}
            ]})),
            derivation("one", "{{ len(inflate($input)) }}"),
        ],
        &[],
    );
    // 1 MiB of zeros, as zlib's compressor at level 9 writes them (raw).
    let mib = unhex(
        serde_json::from_str::<Value>(include_str!("fixtures/deflate/deflate-zlib.json")).unwrap()
            ["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "raw-at-the-cap")
            .unwrap()["stream"]
            .as_str()
            .unwrap(),
    );
    assert!(mib.len() < 2_000, "{} bytes", mib.len());
    assert_eq!(try_derive(&s, "one", &mib).unwrap(), b"1048576");
    match try_derive(&s, "many", &mib) {
        Err(Error::Budget { what }) => assert_eq!(what, "bytes"),
        other => panic!("not refused on the budget: {:?}", other.map(|v| v.len())),
    }
}

// ---------------------------------------------------------------------------------------
// XML canonicalization through templates
// ---------------------------------------------------------------------------------------

/// What reaches `xml_c14n` from outside is parsed under the same refusals as any document:
/// DTDs (so XXE and entity expansion), deep nesting, too many nodes, a canonical form over the
/// budget. Each is a refusal at rendering, before anything is sent or returned.
#[test]
fn hostile_documents_are_refused_in_templates() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::public("label").optional()],
        vec![derivation(
            "c14n",
            "{{ hex(sha256(xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", $input))) }}",
        )],
        &[],
    );
    let dtd = "an XML document type declaration (DTDs and entities are refused)";
    let xxe = b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";
    assert_eq!(render_refusal(try_derive(&s, "c14n", xxe)), dtd);
    let laughs = b"<!DOCTYPE l [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><l>&b;</l>";
    assert_eq!(render_refusal(try_derive(&s, "c14n", laughs)), dtd);
    assert_eq!(
        render_refusal(try_derive(&s, "c14n", b"<r>&a;</r>")),
        "an XML entity reference no DTD declares"
    );
    let deep = "<a>".repeat(65) + &"</a>".repeat(65);
    assert_eq!(
        render_refusal(try_derive(&s, "c14n", deep.as_bytes())),
        "an XML document nested too deeply"
    );
    let wide = "<r>".to_string() + &"<a/>".repeat(70_000) + "</r>";
    assert_eq!(
        render_refusal(try_derive(&s, "c14n", wide.as_bytes())),
        "an XML document with too many nodes"
    );
    // 1,000 elements that each use a 1,000-byte namespace name the root declares: 7 kB in,
    // 1 MB out under the exclusive form. Within the limits it renders; 9 times as many
    // (9 MB out) pass the 8 MiB cap of one canonical form and are refused.
    let uri = "urn:".to_string() + &"x".repeat(1000);
    let amplify = |n: usize| format!("<r xmlns:p=\"{uri}\">{}</r>", "<p:a/>".repeat(n));
    assert!(try_derive(&s, "c14n", amplify(1000).as_bytes()).is_ok());
    assert_eq!(
        render_refusal(try_derive(&s, "c14n", amplify(9000).as_bytes())),
        "a canonical XML form over the size limit"
    );
}

/// The rules of the analysis around `xml_c14n` and `xml_escape`: the algorithm is the
/// policy's (rule 6); a secret and a chosen value do not meet in it (rule 2), since the
/// output sorts and selects what it is given; the prefix list sets which declarations come
/// out (rule 9); a canonical secret stays a secret (rule 5).
#[test]
fn xml_functions_follow_the_rules() {
    let fields = || vec![FieldSpec::secret("key"), FieldSpec::public("user")];
    let cases = [
        ("{{ hex(sha256(xml_c14n($input, \"<r/>\"))) }}", RULE_6),
        (
            "{{ hex(sha256(xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", \"<r>\" + key + $input + \"</r>\"))) }}",
            RULE_2,
        ),
        (
            "{{ hex(sha256(xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", \"<r>\" + key + \"</r>\", $input))) }}",
            RULE_2,
        ),
        (
            "{{ hex(sha256(xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", \"<r/>\", key))) }}",
            RULE_9,
        ),
        // Beside a chosen document, a secret prefix list is first a mixing (rule 2).
        (
            "{{ hex(sha256(xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", $input, key))) }}",
            RULE_2,
        ),
        (
            "{{ xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", \"<r>\" + xml_escape(key) + \"</r>\") }}",
            RULE_5,
        ),
        ("{{ xml_escape(key) }}", RULE_5),
    ];
    for (template, rule) in cases {
        assert_eq!(
            refused(fields(), vec![derivation("d", template)]),
            rule,
            "{template}"
        );
    }
    // A secret in a document the policy writes is canonicalized and signed, and a canonical
    // form of chosen bytes is returned.
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        fields(),
        vec![
            derivation(
                "mac",
                "{{ hex(hmac_sha256(key, xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", \"<r>\" + xml_escape(key) + \"</r>\"))) }}",
            ),
            derivation(
                "echo",
                "{{ xml_c14n(\"http://www.w3.org/2001/10/xml-exc-c14n#\", $input) }}",
            ),
        ],
        &[("key", b"a<b"), ("user", b"u")],
    );
    let mac = try_derive(&s, "mac", b"").unwrap();
    let expected = {
        use hmac::{KeyInit as _, Mac as _};
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"a<b").unwrap();
        m.update(b"<r>a&lt;b</r>");
        hex(&m.finalize().into_bytes())
    };
    assert_eq!(mac, expected.into_bytes());
    assert_eq!(
        try_derive(&s, "echo", b"<x b='2' a=\"1\"/>").unwrap(),
        b"<x a=\"1\" b=\"2\"></x>"
    );
}

// ---------------------------------------------------------------------------------------
// SAML 2.0, service provider side
// ---------------------------------------------------------------------------------------

/// The AuthnRequest the `saml-*` policies write, with its ID; and its exclusive canonical
/// form, written out by hand from Exclusive XML Canonicalization 1.0: the namespace of
/// `saml:` moves to the element that uses it, attributes sorted, empty elements as start and
/// end tags.
fn authn_request(id: &str) -> (String, String) {
    let written = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{SAMLP}\" xmlns:saml=\"{SAML}\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{INSTANT}\" Destination=\"https://idp.example.com/sso\" AssertionConsumerServiceURL=\"https://sp.example.com/acs\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"><saml:Issuer>{ENTITY_ID_XML}</saml:Issuer><samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" AllowCreate=\"true\"/></samlp:AuthnRequest>"
    );
    let canonical = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{SAMLP}\" AssertionConsumerServiceURL=\"https://sp.example.com/acs\" Destination=\"https://idp.example.com/sso\" ID=\"{id}\" IssueInstant=\"{INSTANT}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"{SAML}\">{ENTITY_ID_XML}</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"></samlp:NameIDPolicy></samlp:AuthnRequest>"
    );
    (written, canonical)
}

fn saml_fields() -> Vec<FieldSpec> {
    vec![
        FieldSpec::secret("key"),
        FieldSpec::secret("ec_key"),
        FieldSpec::public("sp_entity_id"),
        FieldSpec::public("relay_state"),
        FieldSpec::public("certificate"),
    ]
}

fn saml_setup<'c>(clock: &'c TestClock, operations: Vec<Operation>) -> Setup<'c> {
    let (pem, _) = rsa_key();
    let cert = include_str!("fixtures/rsa2048-cert.pem");
    setup(
        clock,
        saml_fields(),
        operations,
        &[
            ("key", pem.as_bytes()),
            ("ec_key", &unhex(P256_SECRET)),
            ("sp_entity_id", ENTITY_ID.as_bytes()),
            ("relay_state", RELAY_STATE.as_bytes()),
            ("certificate", cert.as_bytes()),
        ],
    )
}

/// Checks one HTTP-Redirect request (SAML 2.0 Bindings section 3.4.4.1): the parameters in
/// order, the signature over `SAMLRequest=..&RelayState=..&SigAlg=..` as sent (still
/// URL-encoded), and the message inflated by the decoder of this test. Returns the request ID.
fn check_redirect(sent: &Sent, sig_alg: &str, verifies: &dyn Fn(&[u8], &[u8]) -> bool) -> String {
    assert_eq!(sent.method, "GET");
    assert!(sent.target.starts_with("/sso?"));
    let query = sent.query();
    let names: Vec<&str> = query.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["SAMLRequest", "RelayState", "SigAlg", "Signature"]);
    let signed = format!(
        "SAMLRequest={}&RelayState={}&SigAlg={}",
        query[0].1, query[1].1, query[2].1
    );
    assert_eq!(form_decode(&query[1].1), RELAY_STATE.as_bytes());
    assert_eq!(form_decode(&query[2].1), sig_alg.as_bytes());
    let signature = STANDARD.decode(form_decode(&query[3].1)).unwrap();
    assert!(
        verifies(signed.as_bytes(), &signature),
        "the signature does not verify"
    );
    // A changed parameter breaks it.
    let tampered = signed.replace("RelayState=%2F", "RelayState=%2E");
    assert!(!verifies(tampered.as_bytes(), &signature));
    let deflated = STANDARD.decode(form_decode(&query[0].1)).unwrap();
    let (xml, used) = puff::inflate(&deflated).unwrap();
    assert_eq!(used, deflated.len());
    let xml = String::from_utf8(xml).unwrap();
    let id = between(&xml, "ID=\"", "\"").to_string();
    assert_eq!(id.len(), 33);
    assert!(id.starts_with('_') && id[1..].bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(xml, authn_request(&id).0);
    keep(
        &format!("redirect-{}.query", sig_alg.rsplit('#').next().unwrap()),
        sent.target.as_bytes(),
    );
    id
}

/// The `saml-redirect` operation of `docs/policy.md`: an AuthnRequest DEFLATEd, base64- and
/// URL-encoded, signed with RSA-SHA256 over the query as SAML 2.0 Bindings section 3.4.4.1
/// says, verified with the `rsa` crate; a fresh ID each call.
#[test]
fn saml_redirect_binding_rsa_sha256_verifies() {
    let clock = TestClock::at(NOW);
    let s = saml_setup(&clock, vec![doc("saml-redirect")]);
    let (_, public) = rsa_key();
    let mut server = FakeServer::default();
    for _ in 0..2 {
        call(&s, "saml-redirect", None, &mut server).result.unwrap();
    }
    let verifies = |m: &[u8], sig: &[u8]| rsa_sha256_verifies(&public, m, sig);
    let first = check_redirect(&parse(&server.sent[0]), RSA_SHA256, &verifies);
    let second = check_redirect(&parse(&server.sent[1]), RSA_SHA256, &verifies);
    assert_ne!(first, second);
}

/// The same binding with ECDSA P-256 (`ecdsa-sha256`, the signature as `r || s`, XML
/// Signature 1.1 section 6.4.3), verified by ring with the public key of RFC 6979 A.2.5.
#[test]
fn saml_redirect_binding_ecdsa_p256_verifies() {
    let clock = TestClock::at(NOW);
    let s = saml_setup(&clock, vec![doc("saml-redirect-ecdsa")]);
    let mut server = FakeServer::default();
    call(&s, "saml-redirect-ecdsa", None, &mut server)
        .result
        .unwrap();
    check_redirect(&parse(&server.sent[0]), ECDSA_SHA256, &p256_verifies);
}

/// The `saml-post` operation of `docs/policy.md`: the AuthnRequest with an enveloped XML
/// signature (XML Signature 1.1; SAML 2.0 Core section 5) in a form post. The verifier here
/// follows the reference: the element whose ID the URI names, the Signature element removed
/// (enveloped-signature), the exclusive canonical form written out by hand, its SHA-256
/// against `DigestValue`; then `SignedInfo` canonicalized by hand and the RSA-SHA256
/// signature verified with the `rsa` crate.
#[test]
fn saml_post_binding_enveloped_signature_verifies() {
    let clock = TestClock::at(NOW);
    let s = saml_setup(&clock, vec![doc("saml-post")]);
    let (_, public) = rsa_key();
    let mut server = FakeServer::default();
    call(&s, "saml-post", None, &mut server).result.unwrap();
    let sent = parse(&server.sent[0]);
    assert_eq!(sent.method, "POST");
    assert_eq!(
        sent.header("Content-Type"),
        Some("application/x-www-form-urlencoded")
    );
    let form = pairs(std::str::from_utf8(&sent.body).unwrap());
    assert_eq!(form[0].0, "SAMLRequest");
    assert_eq!(
        form[1],
        (
            "RelayState".to_string(),
            "%2Fafter%20login%3Fx%3D1".to_string()
        )
    );
    let xml = String::from_utf8(STANDARD.decode(form_decode(&form[0].1)).unwrap()).unwrap();
    keep("post-authn-request.xml", xml.as_bytes());

    // The Signature element sits right after the Issuer (SAML 2.0 Core section 3.2.1).
    let start = xml.find("<ds:Signature ").unwrap();
    let end = xml.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    assert!(xml[..start].ends_with("</saml:Issuer>"));
    let signature = &xml[start..end];
    let enveloping = format!("{}{}", &xml[..start], &xml[end..]);
    let id = between(&xml, "ID=\"", "\"");
    let (written, canonical) = authn_request(id);
    assert_eq!(enveloping, written);
    let reference = between(signature, "<ds:Reference ", ">");
    assert_eq!(reference, format!("URI=\"#{id}\""));
    assert_eq!(
        between(signature, "<ds:DigestValue>", "</ds:DigestValue>"),
        b64_sha256(canonical.as_bytes())
    );

    // SignedInfo as sent, and its exclusive canonical form: the redundant declaration of
    // `ds:` it carries is the one the form keeps (the apex uses the prefix), the empty
    // elements are written out.
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\">{}</ds:SignedInfo>",
        between(
            signature,
            &format!("<ds:SignedInfo xmlns:ds=\"{DS}\">"),
            "</ds:SignedInfo>"
        )
    );
    let canonical_signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"></ds:SignatureMethod><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"{EXC}\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        b64_sha256(canonical.as_bytes())
    );
    assert_eq!(
        signed_info,
        canonical_signed_info
            .replace("></ds:CanonicalizationMethod>", "/>")
            .replace("></ds:SignatureMethod>", "/>")
            .replace("></ds:Transform>", "/>")
            .replace("></ds:DigestMethod>", "/>")
    );
    assert!(signature.starts_with(&format!("<ds:Signature xmlns:ds=\"{DS}\"><ds:SignedInfo ")));
    let value = STANDARD
        .decode(between(
            signature,
            "<ds:SignatureValue>",
            "</ds:SignatureValue>",
        ))
        .unwrap();
    assert!(rsa_sha256_verifies(
        &public,
        canonical_signed_info.as_bytes(),
        &value
    ));
    // The signature is over the canonical form, not the text as sent.
    assert!(!rsa_sha256_verifies(
        &public,
        signed_info.as_bytes(),
        &value
    ));
}

// ---------------------------------------------------------------------------------------
// WS-Security
// ---------------------------------------------------------------------------------------

/// The `wss-username-token` operation of `docs/policy.md`: a UsernameToken with
/// `PasswordDigest` = base64(SHA-1(nonce + created + password)) (UsernameToken Profile 1.1
/// section 3.1), recomputed here from the nonce and time the request carries.
#[test]
fn ws_security_username_token_digest() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        vec![FieldSpec::public("user"), FieldSpec::guessable("password")],
        vec![doc("wss-username-token")],
        &[("user", b"alice&co"), ("password", b"p<ss w&rd")],
    );
    let mut server = FakeServer::default();
    call(&s, "wss-username-token", None, &mut server)
        .result
        .unwrap();
    let body = String::from_utf8(parse(&server.sent[0]).body).unwrap();
    assert_eq!(
        between(&body, "<wsse:Username>", "</wsse:Username>"),
        "alice&amp;co"
    );
    let nonce = STANDARD
        .decode(between(&body, "EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">", "</wsse:Nonce>"))
        .unwrap();
    assert_eq!(nonce.len(), 16);
    let created = between(&body, "<wsu:Created>", "</wsu:Created>");
    assert_eq!(created, INSTANT);
    let mut digest = sha1::Sha1::new();
    digest.update(&nonce);
    digest.update(created.as_bytes());
    digest.update(b"p<ss w&rd");
    assert_eq!(
        between(&body, "#PasswordDigest\">", "</wsse:Password>"),
        STANDARD.encode(digest.finalize())
    );
    assert!(!body.contains("p<ss"));
}

/// The `wss-signed` operation of `docs/policy.md`: the caller's SOAP body, signed with the
/// timestamp under WS-Security 1.1 (X.509 Token Profile: a BinarySecurityToken, a
/// SecurityTokenReference to it), each reference over the exclusive canonical form. The
/// caller's body is written unsorted and with an empty element on purpose; the canonical
/// forms below are written out by hand; the signature is verified with the `rsa` crate and
/// the token is the certificate of the record.
#[test]
fn ws_security_binary_security_token_signature_verifies() {
    let clock = TestClock::at(NOW);
    let s = saml_setup(&clock, vec![doc("wss-signed")]);
    let (_, public) = rsa_key();
    let mut server = FakeServer::default();
    let body =
        b"<m:GetPrice xmlns:m=\"urn:example:m\" item=\"tea\" currency='EUR'><m:Note/></m:GetPrice>";
    let request = Request {
        method: Method::Post,
        destination: Destination::new("ws.example.com", 443),
        path: "/service".into(),
        headers: vec![],
        body: body.to_vec(),
    };
    call(&s, "wss-signed", Some(&request), &mut server)
        .result
        .unwrap();
    let sent = parse(&server.sent[0]);
    assert_eq!(sent.header("Content-Type"), Some("text/xml; charset=utf-8"));
    let envelope = String::from_utf8(sent.body).unwrap();
    keep("wss-envelope.xml", envelope.as_bytes());

    let token = between(&envelope, "wsu:Id=\"cert\">", "</wsse:BinarySecurityToken>");
    assert_eq!(
        STANDARD.decode(token).unwrap(),
        pem_body(include_str!("fixtures/rsa2048-cert.pem"))
    );
    let expires = "2027-01-15T08:05:00Z";
    let timestamp = format!(
        "<wsu:Timestamp xmlns:wsu=\"{WSU}\" wsu:Id=\"ts\"><wsu:Created>{INSTANT}</wsu:Created><wsu:Expires>{expires}</wsu:Expires></wsu:Timestamp>"
    );
    assert!(envelope.contains(&timestamp));
    let body_canonical = format!(
        "<soap:Body xmlns:soap=\"{SOAP}\" xmlns:wsu=\"{WSU}\" wsu:Id=\"body\"><m:GetPrice xmlns:m=\"urn:example:m\" currency=\"EUR\" item=\"tea\"><m:Note></m:Note></m:GetPrice></soap:Body>"
    );
    let digests: Vec<&str> = envelope
        .match_indices("<ds:DigestValue>")
        .map(|(at, _)| between(&envelope[at..], "<ds:DigestValue>", "</ds:DigestValue>"))
        .collect();
    assert_eq!(
        digests,
        [
            b64_sha256(timestamp.as_bytes()),
            b64_sha256(body_canonical.as_bytes())
        ]
    );
    let t = |alg: &str| {
        format!("<ds:Transforms><ds:Transform Algorithm=\"{alg}\"></ds:Transform></ds:Transforms>")
    };
    let canonical_signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC}\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"></ds:SignatureMethod><ds:Reference URI=\"#ts\">{tr}<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference><ds:Reference URI=\"#body\">{tr}<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        digests[0],
        digests[1],
        tr = t(EXC)
    );
    let value = STANDARD
        .decode(between(
            &envelope,
            "<ds:SignatureValue>",
            "</ds:SignatureValue>",
        ))
        .unwrap();
    assert!(rsa_sha256_verifies(
        &public,
        canonical_signed_info.as_bytes(),
        &value
    ));
    // The body went out as the caller wrote it, inside the Body element the digest covers.
    let sent_body = between(&envelope, "wsu:Id=\"body\">", "</soap:Body>");
    assert_eq!(sent_body.as_bytes(), body);
    assert!(envelope.contains("<wsse:SecurityTokenReference><wsse:Reference URI=\"#cert\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wsse:SecurityTokenReference>"));
    let _ = WSSE;

    // A body that is not one well-formed piece of XML cannot reach a signature: the Body
    // element would not close where the policy closes it (an attempt to add a second Body
    // or a DTD), so the canonicalization refuses it and nothing is sent.
    for hostile in [
        &b"</soap:Body><soap:Body xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"[..],
        b"<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>",
        b"<x>",
    ] {
        let mut server = FakeServer::default();
        let request = Request {
            body: hostile.to_vec(),
            ..request.clone()
        };
        let outcome = call(&s, "wss-signed", Some(&request), &mut server);
        assert!(
            matches!(outcome.result, Err(Error::TemplateInvalid { .. })),
            "{}",
            String::from_utf8_lossy(hostile)
        );
        assert!(server.sent.is_empty());
    }
}
