//! End-to-end behaviour of a node. Every way of using a credential below is policy data only;
//! no test needs code that knows a kind of credential.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;

use engine::Error;
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::fields::Fields;
use engine::keys::{DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink, verify_chain};
use engine::node::{CallerExchange, Clock, Node, Response};
use engine::policy::{
    Capture, Destination, Exchange, FieldSpec, Identity, Injection, Method, Operation, Policy,
    Source, Step, StepRequest, Store, Target,
};
use engine::record::Record;
use engine::request::Request;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const TOKEN: &[u8] = b"tok_live_9f8e7d6c5b4a";

struct TestClock(Cell<u64>);

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

/// Records what it is given; answers from `replies` in order, then with `reply`.
#[derive(Default)]
struct FakeTransport {
    sent: Vec<Vec<u8>>,
    reply: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    identities: Vec<(Vec<u8>, Vec<u8>)>,
    written: Vec<Vec<u8>>,
}

impl Transport for FakeTransport {
    fn send(
        &mut self,
        _: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        if let Some(identity) = identity {
            self.identities
                .push((identity.cert().to_vec(), identity.key().to_vec()));
        }
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| self.reply.clone()))
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        Ok(Box::new(FakeStream(self)))
    }
}

struct FakeStream<'a>(&'a mut FakeTransport);

impl Stream for FakeStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.written.push(bytes.to_vec());
        Ok(())
    }

    fn read_until(&mut self, _: &[u8], _: usize) -> engine::Result<Vec<u8>> {
        self.0.replies.pop_front().ok_or(Error::Transport)
    }
}

fn host() -> Destination {
    Destination::https("api.example.com")
}

fn secret(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        secret: true,
        optional: false,
    }
}

fn public(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        secret: false,
        optional: false,
    }
}

fn later(name: &str) -> FieldSpec {
    FieldSpec {
        name: name.into(),
        secret: true,
        optional: true,
    }
}

fn header(name: &str, template: &str) -> Injection {
    Injection {
        target: Target::Header { name: name.into() },
        template: template.into(),
    }
}

fn inject(target: Target, template: &str) -> Injection {
    Injection {
        target,
        template: template.into(),
    }
}

fn caller_step(inject: Vec<Injection>) -> Step {
    Step {
        request: StepRequest::Caller,
        inject,
        capture: vec![],
    }
}

fn capture(source: Source, into: Store) -> Capture {
    Capture {
        source,
        into,
        optional: false,
    }
}

fn temp(name: &str, secret: bool) -> Store {
    Store::Temp {
        name: name.into(),
        secret,
    }
}

fn http(name: &str, destination: Destination, steps: Vec<Step>) -> Operation {
    let has_caller = steps.iter().any(|s| s.request == StepRequest::Caller);
    Operation::Http {
        name: name.into(),
        destinations: vec![destination],
        methods: if has_caller {
            vec![Method::Get, Method::Post]
        } else {
            vec![]
        },
        identity: None,
        steps,
    }
}

fn request_policy(fields: Vec<FieldSpec>, inject: Vec<Injection>) -> Policy {
    Policy {
        fields,
        operations: vec![http("call", host(), vec![caller_step(inject)])],
    }
}

fn derive_policy(fields: Vec<FieldSpec>, derive: &str) -> Policy {
    Policy {
        fields,
        operations: vec![Operation::Derive {
            name: "derive".into(),
            template: derive.into(),
        }],
    }
}

fn steps_of(policy: &mut Policy) -> &mut Vec<Step> {
    match &mut policy.operations[0] {
        Operation::Http { steps, .. } => steps,
        other => panic!("not http: {other:?}"),
    }
}

fn destinations_of(policy: &mut Policy) -> &mut Vec<Destination> {
    match &mut policy.operations[0] {
        Operation::Http { destinations, .. } => destinations,
        other => panic!("not http: {other:?}"),
    }
}

fn forward(
    node: &mut Node<MemorySink, &TestClock>,
    record: &Record,
    request: &Request,
    transport: &mut FakeTransport,
) -> engine::Result<Response> {
    let outcome = node.http(record, "call", Some(request), transport);
    assert!(outcome.record.is_none());
    outcome.result
}

fn fields(values: &[(&str, &[u8])]) -> Fields {
    let mut f = Fields::new();
    for (name, value) in values {
        f.insert(name, value.to_vec()).unwrap();
    }
    f
}

struct Setup<'c> {
    node: Node<MemorySink, &'c TestClock>,
    record: Record,
    device: DeviceKey,
}

fn setup<'c>(clock: &'c TestClock, policy: Policy, values: &[(&str, &[u8])]) -> Setup<'c> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(policy).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        OWNER,
        signed,
        &fields(values),
    )
    .unwrap();
    let mut node = Node::new(NodeKey::generate(), MemorySink::new(), clock);
    node.grant(
        OWNER,
        UserKey::from_bytes(&mut user_key.clone()),
        device.public(),
        NOW + DAY,
    )
    .unwrap();
    Setup {
        node,
        record,
        device,
    }
}

fn get(path: &str) -> Request {
    Request {
        method: Method::Get,
        destination: host(),
        path: path.into(),
        headers: vec![],
        body: vec![],
    }
}

fn post(path: &str, body: &[u8]) -> Request {
    Request {
        method: Method::Post,
        destination: host(),
        path: path.into(),
        headers: vec![],
        body: body.to_vec(),
    }
}

fn send(s: &mut Setup<'_>, request: &Request) -> Vec<u8> {
    let mut transport = FakeTransport {
        reply: b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(),
        ..Default::default()
    };
    forward(&mut s.node, &s.record, request, &mut transport).unwrap();
    transport.sent.pop().unwrap()
}

fn text(wire: &[u8]) -> String {
    String::from_utf8_lossy(wire).into_owned()
}

fn body_of(wire: &[u8]) -> &[u8] {
    &wire[wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..]
}

fn assert_length(wire: &[u8]) {
    let t = text(wire);
    let length: usize = t
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(body_of(wire).len(), length);
}

#[test]
fn every_usage_is_policy_data() {
    let clock = TestClock(Cell::new(NOW));
    let token = secret("token");
    let cases: Vec<(Policy, Vec<(&str, &[u8])>, Request, &str)> = vec![
        (
            request_policy(
                vec![token.clone()],
                vec![header("Authorization", "Bearer {{token}}")],
            ),
            vec![("token", TOKEN)],
            get("/v1/me"),
            "Authorization: Bearer tok_live_9f8e7d6c5b4a\r\n",
        ),
        (
            request_policy(
                vec![public("user"), secret("password")],
                vec![header(
                    "Authorization",
                    r#"Basic {{ b64(user + ":" + password) }}"#,
                )],
            ),
            vec![("user", b"bot"), ("password", TOKEN)],
            get("/"),
            "Authorization: Basic Ym90OnRva19saXZlXzlmOGU3ZDZjNWI0YQ==\r\n",
        ),
        (
            request_policy(
                vec![token.clone()],
                vec![inject(Target::Query { name: "key".into() }, "{{token}}")],
            ),
            vec![("token", TOKEN)],
            get("/q?x=1"),
            "GET /q?x=1&key=tok_live_9f8e7d6c5b4a HTTP/1.1",
        ),
        (
            request_policy(
                vec![token.clone()],
                vec![header("Cookie", "sid={{token}}; theme=dark")],
            ),
            vec![("token", TOKEN)],
            get("/"),
            "Cookie: sid=tok_live_9f8e7d6c5b4a; theme=dark\r\n",
        ),
        (
            request_policy(
                vec![token.clone()],
                vec![inject(
                    Target::PathParam {
                        name: "token".into(),
                    },
                    "{{token}}",
                )],
            ),
            vec![("token", TOKEN)],
            get("/bot{token}/getMe"),
            "GET /bottok_live_9f8e7d6c5b4a/getMe HTTP/1.1",
        ),
        (
            request_policy(
                vec![token.clone()],
                vec![
                    inject(Target::Body, "{{$body}}&api_key={{pct(token)}}"),
                    header("Content-Type", "application/x-www-form-urlencoded"),
                ],
            ),
            vec![("token", TOKEN)],
            post("/f", b"a=1"),
            "\r\n\r\na=1&api_key=tok_live_9f8e7d6c5b4a",
        ),
        (
            request_policy(
                vec![token.clone()],
                vec![
                    inject(Target::Body, r#"{{ json_set($body, "api_key", token) }}"#),
                    header("Content-Type", "application/json"),
                ],
            ),
            vec![("token", TOKEN)],
            post("/j", br#"{"a":1}"#),
            "\r\n\r\n{\"a\":1,\"api_key\":\"tok_live_9f8e7d6c5b4a\"}",
        ),
        (
            request_policy(
                vec![secret("api_key"), secret("api_secret")],
                vec![
                    header("X-MBX-APIKEY", "{{api_key}}"),
                    inject(
                        Target::Query {
                            name: "signature".into(),
                        },
                        "{{ hex(hmac_sha256(api_secret, $query)) }}",
                    ),
                ],
            ),
            vec![
                ("api_key", b"key-0123456789"),
                (
                    "api_secret",
                    b"NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j",
                ),
            ],
            get(
                "/api/v3/order?symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559",
            ),
            // The example signature of the Binance API documentation.
            "&signature=c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71 HTTP/1.1",
        ),
    ];
    for (policy, values, request, expected) in cases {
        let mut s = setup(&clock, policy.clone(), &values);
        let wire = send(&mut s, &request);
        assert!(
            text(&wire).contains(expected),
            "{policy:?}\n{}",
            text(&wire)
        );
        assert_length(&wire);
    }
}

#[test]
fn json_body_stays_valid_json() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![public("user"), secret("password")],
        vec![inject(
            Target::Body,
            r#"{"user":"{{json(user)}}","password":"{{json(password)}}"}"#,
        )],
    );
    let mut s = setup(
        &clock,
        policy,
        &[("user", b"kim"), ("password", br#"pa"ss\word-123"#)],
    );
    let wire = send(&mut s, &post("/login", b""));
    let parsed: serde_json::Value = serde_json::from_slice(body_of(&wire)).unwrap();
    assert_eq!(parsed["user"], "kim");
    assert_eq!(parsed["password"], r#"pa"ss\word-123"#);
}

#[test]
fn binary_values_go_in_bodies_and_parts() {
    let clock = TestClock(Cell::new(NOW));
    let image: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();

    let policy = request_policy(
        vec![secret("image")],
        vec![
            inject(Target::Body, "{{image}}"),
            header("Content-Type", "image/png"),
        ],
    );
    let mut s = setup(&clock, policy, &[("image", &image)]);
    let wire = send(&mut s, &post("/upload", b""));
    assert_eq!(body_of(&wire), image.as_slice());
    assert_length(&wire);

    let multipart = "--{{$boundary}}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sign.png\"\r\nContent-Type: image/png\r\n\r\n{{image}}\r\n--{{$boundary}}--\r\n";
    let policy = request_policy(
        vec![secret("image")],
        vec![
            inject(Target::Body, multipart),
            header(
                "Content-Type",
                "multipart/form-data; boundary={{$boundary}}",
            ),
        ],
    );
    let mut s = setup(&clock, policy, &[("image", &image)]);
    let wire = send(&mut s, &post("/upload", b""));
    let head = text(&wire[..300]);
    let boundary = head
        .split("boundary=")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
        .to_string();
    let tail = format!("\r\n--{boundary}--\r\n");
    assert!(wire.ends_with(tail.as_bytes()));
    let end = wire.len() - tail.len();
    assert_eq!(&wire[end - image.len()..end], image.as_slice());
    assert_length(&wire);
}

#[test]
fn requests_outside_the_policy_are_refused_before_the_log() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let mut s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();

    let mut other_host = get("/");
    other_host.destination = Destination::https("evil.example.net");
    let mut delete = get("/");
    delete.method = Method::Delete;
    let mut own_header = get("/");
    own_header.headers.push(("x-api-key".into(), "mine".into()));
    let mut host_header = get("/");
    host_header
        .headers
        .push(("Host".into(), "evil.example.net".into()));

    for (request, error) in [
        (other_host, Error::DestinationDenied),
        (delete, Error::MethodDenied),
        (own_header, Error::RequestInvalid),
        (host_header, Error::RequestInvalid),
        (get("no-slash"), Error::RequestInvalid),
    ] {
        assert_eq!(
            forward(&mut s.node, &s.record, &request, &mut transport),
            Err(error)
        );
    }
    assert!(transport.sent.is_empty());
    assert_eq!(s.node.sink().entries().len(), 1, "only the grant entry");
}

#[test]
fn a_policy_cannot_be_widened_or_swapped() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let mut s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let mut to_evil = get("/");
    to_evil.destination = Destination::https("evil.example.net");

    let mut widened = s.record.clone();
    destinations_of(&mut widened.policy.policy).push(Destination::https("evil.example.net"));
    assert_eq!(
        forward(&mut s.node, &widened, &to_evil, &mut transport),
        Err(Error::PolicySignature)
    );

    let mut leaky = s.record.clone();
    steps_of(&mut leaky.policy.policy)[0]
        .inject
        .push(header("X-Echo", "{{token}}"));
    assert_eq!(
        forward(&mut s.node, &leaky, &get("/"), &mut transport),
        Err(Error::PolicySignature)
    );

    let mut wide = policy;
    destinations_of(&mut wide).push(Destination::https("evil.example.net"));
    let mut swapped = s.record.clone();
    swapped.policy = s.device.sign_policy(wide).unwrap();
    assert_eq!(
        forward(&mut s.node, &swapped, &to_evil, &mut transport),
        Err(Error::RecordOpen)
    );

    let mut wrong_owner = s.record.clone();
    wrong_owner.owner = "user-2".into();
    assert_eq!(
        forward(&mut s.node, &wrong_owner, &get("/"), &mut transport),
        Err(Error::NoGrant)
    );
    assert!(transport.sent.is_empty());
}

#[test]
fn nothing_is_sent_without_a_confirmed_entry() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let mut s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    s.node.sink_mut().set_failing(true);
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::LogUnconfirmed)
    );
    s.node.sink_mut().set_failing(false);
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::LogHalted)
    );
    assert!(transport.sent.is_empty());
}

#[test]
fn grants_end_and_revokes_erase() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let mut s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();

    clock.0.set(NOW + DAY);
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::GrantExpired)
    );
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::NoGrant)
    );

    clock.0.set(NOW);
    let mut s = setup(&clock, policy, &[("token", TOKEN)]);
    s.node.revoke(OWNER).unwrap();
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::NoGrant)
    );
    assert!(transport.sent.is_empty());

    s.node
        .grant(
            OWNER,
            UserKey::from_bytes(&mut [1u8; 32]),
            s.device.public(),
            NOW + 365 * DAY,
        )
        .unwrap();
    match &s.node.sink().entries().last().unwrap().entry.event {
        Event::Grant { expires_ms } => assert_eq!(*expires_ms, NOW + 30 * DAY),
        other => panic!("unexpected event {other:?}"),
    }
}

#[test]
fn responses_that_echo_a_secret_are_dropped() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![public("user"), secret("password")],
        vec![header(
            "Authorization",
            r#"Basic {{ b64(user + ":" + password) }}"#,
        )],
    );
    let replies: [(&[u8], bool); 5] = [
        (b"{\"you_sent\":\"tok_live_9f8e7d6c5b4a\"}", true),
        (b"debug: dG9rX2xpdmVfOWY4ZTdkNmM1YjRh", true),
        (b"auth=Basic Ym90OnRva19saXZlXzlmOGU3ZDZjNWI0YQ==", true),
        (b"hex 746f6b5f6c6976655f396638653764366335623461", true),
        (b"{\"user\":\"bot\"}", false),
    ];
    for (reply, dropped) in replies {
        let mut s = setup(
            &clock,
            policy.clone(),
            &[("user", b"bot"), ("password", TOKEN)],
        );
        let mut transport = FakeTransport {
            reply: reply.to_vec(),
            ..Default::default()
        };
        let result = forward(&mut s.node, &s.record, &get("/"), &mut transport);
        if dropped {
            assert_eq!(result, Err(Error::Reflection), "{}", text(reply));
        } else {
            assert_eq!(
                result.unwrap().bytes,
                reply,
                "a public field is not a secret"
            );
        }
    }
}

#[test]
fn derivations_hand_back_only_one_way_outputs() {
    let clock = TestClock(Cell::new(1_111_111_109_000));
    let mut transport = FakeTransport::default();

    let mut s = setup(
        &clock,
        derive_policy(vec![secret("seed")], "{{ totp(b32decode(seed)) }}"),
        &[("seed", b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")],
    );
    assert_eq!(s.node.derive(&s.record, "derive", b"").unwrap(), b"081804");
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/"), &mut transport),
        Err(Error::OperationUnknown)
    );

    use hmac::{Hmac, Mac};
    let key = b"exchange-secret-key-0123456789";
    let mut s = setup(
        &clock,
        derive_policy(vec![secret("key")], "{{ hex(hmac_sha256(key, $input)) }}"),
        &[("key", key)],
    );
    let tag = s
        .node
        .derive(&s.record, "derive", b"GET\n/api/v3/order\nts=1")
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(b"GET\n/api/v3/order\nts=1");
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tag, expected.as_bytes());
    match &s.node.sink().entries().last().unwrap().entry.event {
        Event::Derive { .. } => {}
        other => panic!("unexpected event {other:?}"),
    }

    let device = DeviceKey::generate();
    for leaky in ["{{key}}", "{{ b64(key) }}", "{{ hexdecode(hex(key)) }}"] {
        let policy = derive_policy(vec![secret("key")], leaky);
        assert_eq!(
            device.sign_policy(policy),
            Err(Error::PolicyInvalid),
            "{leaky}"
        );
    }
    assert!(transport.sent.is_empty());
}

#[test]
fn private_keys_in_pem_sign_without_leaving() {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let clock = TestClock(Cell::new(NOW));
    let message = b"contract v1";

    let ed = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let ed_pem = ed.to_pkcs8_pem(Default::default()).unwrap();
    let policy = derive_policy(vec![secret("key")], "{{ ed25519_sign(pem(key), $input) }}");
    let mut s = setup(&clock, policy, &[("key", ed_pem.as_bytes())]);
    let signature = s.node.derive(&s.record, "derive", message).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    ed.verifying_key()
        .verify_strict(message, &signature)
        .unwrap();

    let ec = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let ec_pem = ec.to_pkcs8_pem(Default::default()).unwrap();
    let policy = derive_policy(vec![secret("key")], "{{ p256_sign_der(pem(key), $input) }}");
    let mut s = setup(&clock, policy, &[("key", ec_pem.as_bytes())]);
    let der = s.node.derive(&s.record, "derive", message).unwrap();
    let signature = p256::ecdsa::Signature::from_der(&der).unwrap();
    use p256::ecdsa::signature::Verifier as _;
    ec.verifying_key().verify(message, &signature).unwrap();
}

#[test]
fn a_tampered_chain_is_found() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let mut s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    for path in ["/a", "/b", "/c"] {
        forward(&mut s.node, &s.record, &get(path), &mut transport).unwrap();
    }
    let key = s.node.public_key();
    let entries = s.node.sink().entries().to_vec();
    verify_chain(&entries, &key).unwrap();
    let logged = serde_json::to_string(&entries).unwrap();
    assert!(
        !logged.contains("tok_live"),
        "the log must not hold a secret"
    );

    let mut edited = entries.clone();
    if let Event::Use { path, .. } = &mut edited[2].entry.event {
        *path = "/innocent".into();
    }
    assert_eq!(
        verify_chain(&edited, &key),
        Err(Error::EntrySignature { seq: 2 })
    );

    let mut dropped = entries.clone();
    dropped.remove(1);
    assert_eq!(
        verify_chain(&dropped, &key),
        Err(Error::ChainBroken { seq: 1 })
    );
}

#[test]
fn records_round_trip_as_json_without_their_values() {
    let clock = TestClock(Cell::new(NOW));
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let json = serde_json::to_string(&s.record).unwrap();
    assert!(!json.contains("tok_live"));
    let back: Record = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s.record);
}

// ---- multi-step flows, streams, client certificates and the new primitives ----

fn reply(head: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {head}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn oauth_refresh_writes_the_new_tokens_into_a_new_record() {
    let clock = TestClock(Cell::new(NOW));
    let auth = Destination::https("auth.example.com");
    let refresh = Step {
        request: StepRequest::Fixed {
            method: Method::Post,
            path: "/oauth/token".into(),
            destination: None,
        },
        inject: vec![
            header("Content-Type", "application/x-www-form-urlencoded"),
            inject(
                Target::Body,
                "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}&client_id={{pct(client_id)}}&client_secret={{pct(client_secret)}}",
            ),
        ],
        capture: vec![
            capture(
                Source::Json {
                    pointer: "/access_token".into(),
                },
                Store::Field {
                    name: "access_token".into(),
                },
            ),
            Capture {
                optional: true,
                ..capture(
                    Source::Json {
                        pointer: "/refresh_token".into(),
                    },
                    Store::Field {
                        name: "refresh_token".into(),
                    },
                )
            },
        ],
    };
    let policy = Policy {
        fields: vec![
            public("client_id"),
            secret("client_secret"),
            secret("refresh_token"),
            later("access_token"),
        ],
        operations: vec![
            http("refresh", auth, vec![refresh]),
            http(
                "call",
                host(),
                vec![caller_step(vec![header(
                    "Authorization",
                    "Bearer {{access_token}}",
                )])],
            ),
        ],
    };
    let mut s = setup(
        &clock,
        policy,
        &[
            ("client_id", b"app-1"),
            ("client_secret", b"cs_0123456789abcdef"),
            ("refresh_token", b"rt_first_0123456789"),
        ],
    );
    let mut transport = FakeTransport::default();

    // No access token yet: the template fails before anything is logged or sent.
    assert_eq!(
        forward(&mut s.node, &s.record, &get("/me"), &mut transport),
        Err(Error::FieldMissing)
    );
    assert!(transport.sent.is_empty());

    transport.replies.push_back(reply(
        "200 OK",
        r#"{"access_token":"at_new_abcdefghijkl","refresh_token":"rt_second_987654321","expires_in":3600}"#,
    ));
    let outcome = s.node.http(&s.record, "refresh", None, &mut transport);
    let response = outcome.result.unwrap();
    assert_eq!(
        text(body_of(&response.bytes)),
        r#"{"access_token":"[redacted]","refresh_token":"[redacted]","expires_in":3600}"#
    );
    let wire = text(&transport.sent.pop().unwrap());
    assert!(wire.starts_with("POST /oauth/token HTTP/1.1\r\nHost: auth.example.com\r\n"));
    assert!(wire.ends_with(
        "grant_type=refresh_token&refresh_token=rt_first_0123456789&client_id=app-1&client_secret=cs_0123456789abcdef"
    ));
    let renewed = outcome.record.unwrap();
    assert_ne!(renewed.ct, s.record.ct);
    match &s.node.sink().entries().last().unwrap().entry.event {
        Event::Update { operation, fields } => {
            assert_eq!(operation, "refresh");
            assert_eq!(fields, &["access_token", "refresh_token"]);
        }
        other => panic!("unexpected event {other:?}"),
    }

    s.record = renewed;
    transport.reply = reply("200 OK", "{}");
    forward(&mut s.node, &s.record, &get("/me"), &mut transport).unwrap();
    assert!(
        text(&transport.sent.pop().unwrap())
            .contains("Authorization: Bearer at_new_abcdefghijkl\r\n")
    );

    // The next refresh sends the rotated refresh token.
    transport
        .replies
        .push_back(reply("200 OK", r#"{"access_token":"at_third_abcdefghij"}"#));
    let outcome = s.node.http(&s.record, "refresh", None, &mut transport);
    outcome.result.unwrap();
    assert!(outcome.record.is_some());
    assert!(text(&transport.sent.pop().unwrap()).contains("refresh_token=rt_second_987654321&"));

    // A refresh that returns no token fails and changes nothing.
    transport
        .replies
        .push_back(reply("400 Bad Request", r#"{"error":"invalid_grant"}"#));
    let outcome = s.node.http(&s.record, "refresh", None, &mut transport);
    assert_eq!(outcome.result, Err(Error::CaptureMissing));
    assert!(outcome.record.is_none());

    let logged = serde_json::to_string(s.node.sink().entries()).unwrap();
    for value in ["at_new", "rt_first", "rt_second", "cs_0123"] {
        assert!(!logged.contains(value), "{value}");
    }
}

#[test]
fn a_session_login_feeds_a_cookie_to_the_caller_request() {
    let clock = TestClock(Cell::new(NOW));
    let login = Step {
        request: StepRequest::Fixed {
            method: Method::Post,
            path: "/login".into(),
            destination: None,
        },
        inject: vec![
            header("Content-Type", "application/json"),
            inject(
                Target::Body,
                r#"{"user":"{{json(user)}}","password":"{{json(password)}}"}"#,
            ),
        ],
        capture: vec![capture(
            Source::Cookie { name: "sid".into() },
            temp("session", true),
        )],
    };
    let policy = Policy {
        fields: vec![public("user"), secret("password")],
        operations: vec![http(
            "call",
            host(),
            vec![
                login,
                caller_step(vec![header("Cookie", "sid={{session}}")]),
            ],
        )],
    };
    let mut s = setup(&clock, policy, &[("user", b"kim"), ("password", TOKEN)]);
    let mut transport = FakeTransport::default();
    transport.replies.push_back(
        b"HTTP/1.1 302 Found\r\nSet-Cookie: sid=sess_0123456789abcdef; HttpOnly\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    );
    transport.replies.push_back(reply(
        "200 OK",
        r#"{"orders":[],"echo":"sess_0123456789abcdef"}"#,
    ));
    let response = forward(&mut s.node, &s.record, &get("/orders"), &mut transport).unwrap();
    assert_eq!(
        text(body_of(&response.bytes)),
        r#"{"orders":[],"echo":"[redacted]"}"#
    );
    assert!(text(&transport.sent[0]).starts_with("POST /login HTTP/1.1\r\n"));
    let second = text(&transport.sent[1]);
    assert!(second.starts_with("GET /orders HTTP/1.1\r\n"));
    assert!(second.contains("Cookie: sid=sess_0123456789abcdef\r\n"));
    let uses = s
        .node
        .sink()
        .entries()
        .iter()
        .filter(|e| matches!(e.entry.event, Event::Use { .. }))
        .count();
    assert_eq!(uses, 2, "one entry per request");
}

#[test]
fn digest_authentication_answers_the_challenge() {
    // RFC 2617, section 3.5.
    let clock = TestClock(Cell::new(NOW));
    let param = |p: &str| Source::HeaderParam {
        name: "WWW-Authenticate".into(),
        param: p.into(),
    };
    let challenge = Step {
        request: StepRequest::Caller,
        inject: vec![],
        capture: vec![
            capture(param("realm"), temp("realm", false)),
            capture(param("nonce"), temp("nonce", false)),
            capture(param("opaque"), temp("opaque", false)),
        ],
    };
    let answer = caller_step(vec![header(
        "Authorization",
        concat!(
            r#"Digest username="{{username}}", realm="{{realm}}", nonce="{{nonce}}", uri="{{$path}}", qop=auth, nc=00000001, cnonce="0a4f113b", "#,
            r#"response="{{ hex(md5(hex(md5(username + ":" + realm + ":" + password)) + ":" + nonce + ":00000001:0a4f113b:auth:" + hex(md5($method + ":" + $path)))) }}", opaque="{{opaque}}""#,
        ),
    )]);
    let policy = Policy {
        fields: vec![public("username"), secret("password")],
        operations: vec![http("call", host(), vec![challenge, answer])],
    };
    let mut s = setup(
        &clock,
        policy,
        &[("username", b"Mufasa"), ("password", b"Circle Of Life")],
    );
    let mut transport = FakeTransport::default();
    transport.replies.push_back(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\nContent-Length: 0\r\n\r\n".to_vec());
    transport.reply = reply("200 OK", "ok");
    forward(
        &mut s.node,
        &s.record,
        &get("/dir/index.html"),
        &mut transport,
    )
    .unwrap();
    assert!(!text(&transport.sent[0]).contains("Authorization"));
    let wire = text(&transport.sent[1]);
    assert!(
        wire.contains(r#"response="6629fae49393a05397450978507c4ef1""#),
        "{wire}"
    );
    assert!(wire.contains(r#"opaque="5ccc069c403ebaf9f0171e9517f40e41""#));
}

#[test]
fn aws_signature_v4_is_a_template() {
    // The get-vanilla case of the AWS Signature Version 4 test suite.
    let clock = TestClock(Cell::new(1_440_938_160_000));
    let date = r#"time($unix, "%Y%m%d")"#;
    let stamp = r#"time($unix, "%Y%m%dT%H%M%SZ")"#;
    let key = format!(
        r#"hmac_sha256(hmac_sha256(hmac_sha256(hmac_sha256("AWS4" + secret_key, {date}), "us-east-1"), "service"), "aws4_request")"#
    );
    let canonical = format!(
        r#"$method + "\n" + $pathname + "\n" + canonical_query($query) + "\nhost:" + $host + "\nx-amz-date:" + {stamp} + "\n\nhost;x-amz-date\n" + hex(sha256($body))"#
    );
    let to_sign = format!(
        r#""AWS4-HMAC-SHA256\n" + {stamp} + "\n" + {date} + "/us-east-1/service/aws4_request\n" + hex(sha256({canonical}))"#
    );
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={{{{access_key}}}}/{{{{ {date} }}}}/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature={{{{ hex(hmac_sha256({key}, {to_sign})) }}}}"
    );
    let destination = Destination::https("example.amazonaws.com");
    let policy = Policy {
        fields: vec![public("access_key"), secret("secret_key")],
        operations: vec![http(
            "call",
            destination.clone(),
            vec![caller_step(vec![
                header("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
                header("Authorization", &authorization),
            ])],
        )],
    };
    let mut s = setup(
        &clock,
        policy,
        &[
            ("access_key", b"AKIDEXAMPLE"),
            ("secret_key", b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        ],
    );
    let mut transport = FakeTransport {
        reply: reply("200 OK", ""),
        ..Default::default()
    };
    let mut request = get("/");
    request.destination = destination;
    forward(&mut s.node, &s.record, &request, &mut transport).unwrap();
    let wire = text(&transport.sent[0]);
    assert!(wire.contains("X-Amz-Date: 20150830T123600Z\r\n"));
    assert!(
        wire.contains(
            "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31\r\n"
        ),
        "{wire}"
    );
}

#[test]
fn rsa_keys_sign_jwts() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ring::signature::{
        KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256, RsaKeyPair,
        UnparsedPublicKey,
    };

    let pem = include_str!("fixtures/rsa2048.pem");
    let der: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(der).unwrap();
    let public = RsaKeyPair::from_pkcs8(&der)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();

    let clock = TestClock(Cell::new(NOW));
    let head = r#"b64urlraw("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "." + b64urlraw($input)"#;
    let jwt =
        format!("{{{{ {head} + \".\" + b64urlraw(rsa_sign_pkcs1_sha256(pem(key), {head})) }}}}");
    let mut s = setup(
        &clock,
        derive_policy(vec![secret("key")], &jwt),
        &[("key", pem.as_bytes())],
    );
    let claims =
        br#"{"iss":"svc@example.iam","aud":"https://oauth2.example.com/token","exp":1800000600}"#;
    let token = String::from_utf8(s.node.derive(&s.record, "derive", claims).unwrap()).unwrap();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(signed.split('.').nth(1).unwrap())
            .unwrap(),
        claims
    );
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
        .verify(
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
        )
        .unwrap();

    let pss = derive_policy(
        vec![secret("key")],
        "{{ rsa_sign_pss_sha256(pem(key), $input) }}",
    );
    let mut s = setup(&clock, pss, &[("key", pem.as_bytes())]);
    let signature = s.node.derive(&s.record, "derive", b"message").unwrap();
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &public)
        .verify(b"message", &signature)
        .unwrap();
}

#[test]
fn secp256k1_keys_sign_and_recover() {
    use k256::ecdsa::signature::Verifier as _;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
    use sha3::Digest as _;

    let clock = TestClock(Cell::new(NOW));
    let secret_key = [0x11u8; 32];
    let key = SigningKey::from_slice(&secret_key).unwrap();
    let policy = Policy {
        fields: vec![secret("key")],
        operations: vec![
            Operation::Derive {
                name: "derive".into(),
                template: "{{ k256_sign(key, $input) }}".into(),
            },
            Operation::Derive {
                name: "eth".into(),
                template: "{{ k256_sign_recoverable(key, keccak256($input)) }}".into(),
            },
        ],
    };
    let mut s = setup(&clock, policy, &[("key", &secret_key)]);

    let signature = s.node.derive(&s.record, "derive", b"order 42").unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    key.verifying_key().verify(b"order 42", &signature).unwrap();

    let out = s.node.derive(&s.record, "eth", b"transfer 1 eth").unwrap();
    assert_eq!(out.len(), 65);
    let digest = sha3::Keccak256::digest(b"transfer 1 eth");
    let recovered = VerifyingKey::recover_from_prehash(
        &digest,
        &Signature::from_slice(&out[..64]).unwrap(),
        RecoveryId::from_byte(out[64] - 27).unwrap(),
    )
    .unwrap();
    assert_eq!(&recovered, key.verifying_key());
}

#[test]
fn aes_encrypts_only_under_a_secret_key() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let clock = TestClock(Cell::new(NOW));
    let key = [0x42u8; 32];
    let policy = derive_policy(
        vec![secret("key")],
        r#"{{ aes_gcm_encrypt(key, hexdecode("000102030405060708090a0b"), $input, "v1") }}"#,
    );
    let mut s = setup(&clock, policy, &[("key", &key)]);
    let sealed = s.node.derive(&s.record, "derive", b"card 4111").unwrap();
    let nonce: Vec<u8> = (0u8..12).collect();
    let plain = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed,
                aad: b"v1",
            },
        )
        .unwrap();
    assert_eq!(plain, b"card 4111");

    // Encrypting the secret under a key anyone reads would hand the secret back.
    let leaky = derive_policy(
        vec![secret("key")],
        r#"{{ aes_gcm_encrypt("0123456789abcdef", "000000000000", key) }}"#,
    );
    assert_eq!(
        DeviceKey::generate().sign_policy(leaky),
        Err(Error::PolicyInvalid)
    );
}

fn imap_policy() -> Policy {
    Policy {
        fields: vec![public("user"), secret("password")],
        operations: vec![Operation::Stream {
            name: "imap".into(),
            destinations: vec![Destination::new("imap.example.com", 993)],
            identity: None,
            script: vec![
                Exchange::Expect {
                    until: "\r\n".into(),
                    capture: vec![],
                },
                Exchange::Send {
                    template: "a1 LOGIN {{user}} {{password}}\r\n".into(),
                },
                Exchange::Expect {
                    until: "\r\n".into(),
                    capture: vec![capture(
                        Source::Between {
                            start: "a1 ".into(),
                            end: " ".into(),
                        },
                        temp("status", false),
                    )],
                },
            ],
        }],
    }
}

#[test]
fn a_stream_logs_in_then_carries_the_caller() {
    let clock = TestClock(Cell::new(NOW));
    let mut s = setup(
        &clock,
        imap_policy(),
        &[("user", b"bot"), ("password", b"p4ssw0rd-imap")],
    );
    let imap = Destination::new("imap.example.com", 993);
    let mut transport = FakeTransport::default();
    transport.replies.extend([
        b"* OK IMAP ready\r\n".to_vec(),
        b"a1 OK LOGIN completed\r\n".to_vec(),
        b"* 3 EXISTS\r\na2 OK SELECT completed\r\n".to_vec(),
    ]);
    let exchanges = [CallerExchange {
        send: b"a2 SELECT INBOX\r\n".to_vec(),
        until: b"a2 OK".to_vec(),
    }];
    let outcome = s
        .node
        .stream(&s.record, "imap", &imap, &exchanges, &mut transport);
    assert!(outcome.record.is_none());
    assert_eq!(
        outcome.result.unwrap(),
        vec![b"* 3 EXISTS\r\na2 OK SELECT completed\r\n".to_vec()]
    );
    assert_eq!(
        transport.written,
        vec![
            b"a1 LOGIN bot p4ssw0rd-imap\r\n".to_vec(),
            b"a2 SELECT INBOX\r\n".to_vec()
        ]
    );
    match &s.node.sink().entries().last().unwrap().entry.event {
        Event::Stream { host, port, .. } => {
            assert_eq!((host.as_str(), *port), ("imap.example.com", 993));
        }
        other => panic!("unexpected event {other:?}"),
    }

    // A server that echoes the password: the read is dropped.
    let mut transport = FakeTransport::default();
    transport.replies.extend([
        b"* OK\r\n".to_vec(),
        b"a1 OK done\r\n".to_vec(),
        b"a2 BAD p4ssw0rd-imap\r\n".to_vec(),
    ]);
    let outcome = s
        .node
        .stream(&s.record, "imap", &imap, &exchanges, &mut transport);
    assert_eq!(outcome.result, Err(Error::Reflection));

    // Another host is refused before the log.
    let before = s.node.sink().entries().len();
    let outcome = s.node.stream(
        &s.record,
        "imap",
        &Destination::new("evil.example.net", 993),
        &exchanges,
        &mut FakeTransport::default(),
    );
    assert_eq!(outcome.result, Err(Error::DestinationDenied));
    assert_eq!(s.node.sink().entries().len(), before);
}

#[test]
fn client_certificates_reach_only_the_transport() {
    let clock = TestClock(Cell::new(NOW));
    let cert = b"-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n";
    let key = b"-----BEGIN PRIVATE KEY-----\nMIIBkey-0123456789\n-----END PRIVATE KEY-----\n";
    let policy = Policy {
        fields: vec![public("cert"), secret("key")],
        operations: vec![Operation::Http {
            name: "call".into(),
            destinations: vec![host()],
            methods: vec![Method::Get],
            identity: Some(Identity {
                cert: "{{cert}}".into(),
                key: "{{key}}".into(),
            }),
            steps: vec![caller_step(vec![])],
        }],
    };
    let mut s = setup(&clock, policy, &[("cert", cert), ("key", key)]);
    let mut transport = FakeTransport {
        reply: reply("200 OK", "{}"),
        ..Default::default()
    };
    forward(&mut s.node, &s.record, &get("/"), &mut transport).unwrap();
    assert_eq!(transport.identities, vec![(cert.to_vec(), key.to_vec())]);
    assert!(!text(&transport.sent[0]).contains("PRIVATE KEY"));
    let logged = serde_json::to_string(s.node.sink().entries()).unwrap();
    assert!(!logged.contains("MIIBkey"));
}
