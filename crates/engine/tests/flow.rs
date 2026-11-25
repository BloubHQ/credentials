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
use engine::caller::{Authorization, BAD_SIGNATURE, Payload};
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Detail, Event, LogSink, MemorySink, SignedEntry, verify_chain};
use engine::node::{CallerExchange, Clock, Node, Outcome, Response, StreamOutput};
use engine::policy::{
    Caller, CallerRequest, Capture, Destination, FieldSpec, Injection, Input, Method, Operation,
    Policy, QueryRule, Receive, Return, Send, Source, Step as IrStep, StepRequest as IrRequest,
    Store, Target,
};
use engine::record::Record;
use engine::request::Request;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const TOKEN: &[u8] = b"tok_live_9f8e7d6c5b4a";

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(0) };
}

/// The time of the test thread; callers sign with it too.
struct TestClock;

impl TestClock {
    fn at(ms: u64) -> Self {
        TIME.with(|t| t.set(ms));
        TestClock
    }

    fn set(&self, ms: u64) {
        TIME.with(|t| t.set(ms));
    }
}

fn now() -> u64 {
    TIME.with(Cell::get)
}

thread_local! {
    static ISSUED: Cell<u64> = const { Cell::new(0) };
}

/// An issue time for a grant or revocation: now, and later than the one before.
fn issued() -> u64 {
    ISSUED.with(|i| {
        let next = now().max(i.get() + 1);
        i.set(next);
        next
    })
}

/// Grants `node` the user key `key` of `OWNER` from `device`, pinning `pins`.
fn grant_on<S: LogSink, C: Clock>(
    node: &Node<S, C>,
    device: &DeviceKey,
    key: [u8; 32],
    expires_ms: u64,
    pins: &[(&str, u64)],
) -> engine::Result<()> {
    let terms = GrantTerms {
        owner: OWNER.into(),
        expires_ms,
        issued_ms: issued(),
        pins: pins
            .iter()
            .map(|(id, generation)| RecordPin {
                record_id: (*id).into(),
                generation: *generation,
            })
            .collect(),
    };
    let sealed = device.grant(
        &UserKey::from_bytes(&mut key.clone()),
        &node.identity(),
        terms,
    )?;
    node.grant(&sealed)
}

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        now()
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
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        if let Some(identity) = identity {
            self.identities
                .push((identity.cert().to_vec(), identity.key().to_vec()));
        }
        Ok(self.replies.pop_front().unwrap_or_else(|| {
            if self.reply.is_empty() {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
            } else {
                self.reply.clone()
            }
        }))
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

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        self.0
            .replies
            .pop_front()
            .ok_or(Error::transport(TransportKind::Closed, false))
    }
}

fn host() -> Destination {
    Destination::https("api.example.com")
}

fn secret(name: &str) -> FieldSpec {
    FieldSpec::secret(name)
}

fn public(name: &str) -> FieldSpec {
    FieldSpec::public(name)
}

fn later(name: &str) -> FieldSpec {
    FieldSpec::secret(name).optional()
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

/// What one request of an HTTPS test operation sends.
#[derive(Clone, Debug, PartialEq)]
enum StepRequest {
    /// The caller's request, within [`contract`].
    Caller,
    /// A request the policy fixes.
    Fixed {
        method: Method,
        path: String,
        destination: Option<Destination>,
    },
}

/// One request of an HTTPS test operation: a `send` and, when it captures, the `receive`
/// of its response.
#[derive(Clone, Debug)]
struct Step {
    request: StepRequest,
    inject: Vec<Injection>,
    capture: Vec<Capture>,
}

/// The contract of the caller in these tests: GET and POST on any path, no header, the query
/// parameters `x` and `full`.
fn contract() -> CallerRequest {
    CallerRequest::new([Method::Get, Method::Post])
        .paths(["/", "/**"])
        .query(QueryRule::any("x"))
        .query(QueryRule::any("full"))
}

fn caller_step(inject: Vec<Injection>) -> Step {
    Step {
        request: StepRequest::Caller,
        inject,
        capture: vec![],
    }
}

/// The IR of `steps` after an `open`, with a `return` of `ret`.
fn steps_to_ir(steps: Vec<Step>, contract: &CallerRequest, ret: Return) -> Vec<IrStep> {
    let mut out = Vec::new();
    for step in steps {
        let request = match step.request {
            StepRequest::Caller => IrRequest::Caller(contract.clone()),
            StepRequest::Fixed {
                method,
                path,
                destination,
            } => IrRequest::Fixed {
                method,
                path,
                destination,
            },
        };
        out.push(IrStep::Send(Send {
            request: Some(request),
            inject: step.inject,
            template: None,
        }));
        if !step.capture.is_empty() {
            out.push(IrStep::Receive(Receive {
                until: vec![],
                capture: step.capture,
            }));
        }
    }
    out.push(IrStep::Return(ret));
    out
}

/// The `return` of the HTTPS test operations: the status, the body and the headers the
/// tests read.
fn everything() -> Return {
    Return::status()
        .header("Content-Type")
        .header("Set-Cookie")
        .header("X-Echo")
        .header("Location")
        .body()
}

fn http(name: &str, destination: Destination, steps: Vec<Step>) -> Operation {
    let mut operation = Operation::https(name, destination);
    operation
        .steps
        .extend(steps_to_ir(steps, &contract(), everything()));
    operation
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

fn request_policy(fields: Vec<FieldSpec>, inject: Vec<Injection>) -> Policy {
    Policy {
        item: None,
        fields,
        callers: vec![],
        operations: vec![http("call", host(), vec![caller_step(inject)])],
    }
}

fn derive_policy(fields: Vec<FieldSpec>, derive: &str) -> Policy {
    Policy {
        item: None,
        fields,
        callers: vec![],
        operations: vec![derive_op("derive", derive)],
    }
}

/// An operation with no connection that renders `template`; it takes any input.
fn derive_op(name: &str, template: &str) -> Operation {
    let operation = Operation::derive(name, template);
    if template.contains("$input") {
        operation.input(Input::any())
    } else {
        operation
    }
}

/// The `n`-th `send` of the first operation.
fn send_of(policy: &mut Policy, n: usize) -> &mut Send {
    policy.operations[0]
        .steps
        .iter_mut()
        .filter_map(|s| match s {
            IrStep::Send(send) => Some(send),
            _ => None,
        })
        .nth(n)
        .expect("a send")
}

/// The contract of the first `send` of the first operation that takes the caller's request.
fn contract_of(policy: &mut Policy) -> &mut CallerRequest {
    policy.operations[0]
        .steps
        .iter_mut()
        .find_map(|s| match s {
            IrStep::Send(Send {
                request: Some(IrRequest::Caller(contract)),
                ..
            }) => Some(contract),
            _ => None,
        })
        .expect("a caller send")
}

fn destinations_of(policy: &mut Policy) -> &mut Vec<Destination> {
    match &mut policy.operations[0].steps[0] {
        IrStep::Open(open) => &mut open.destinations,
        other => panic!("not open: {other:?}"),
    }
}

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

/// The key of the caller every test policy lists as `app`.
fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

fn authorize(
    node: &TestNode<'_>,
    record: &Record,
    operation: &str,
    payload: &Payload<'_>,
) -> Authorization {
    caller_key()
        .authorize("app", &node.public_key(), record, operation, payload, now())
        .unwrap()
}

fn call_http(
    node: &TestNode<'_>,
    record: &Record,
    operation: &str,
    request: Option<&Request>,
    transport: &mut FakeTransport,
) -> Outcome<Response> {
    let auth = authorize(node, record, operation, &Payload::Http(request));
    node.http(record, operation, &auth, request, transport)
}

fn call_stream(
    node: &TestNode<'_>,
    record: &Record,
    operation: &str,
    destination: &Destination,
    exchanges: &[CallerExchange],
    transport: &mut FakeTransport,
) -> Outcome<StreamOutput> {
    let payload = Payload::Stream {
        destination,
        exchanges,
    };
    let auth = authorize(node, record, operation, &payload);
    node.stream(record, operation, &auth, destination, exchanges, transport)
}

fn call_derive(
    node: &TestNode<'_>,
    record: &Record,
    operation: &str,
    input: &[u8],
) -> engine::Result<Vec<u8>> {
    let auth = authorize(node, record, operation, &Payload::Derive(input));
    node.derive(record, operation, &auth, input)
}

fn log_of(node: &TestNode<'_>) -> Vec<SignedEntry> {
    node.with_sink(|sink| sink.entries().to_vec())
}

/// The last logged event `keep` accepts.
fn last_event(node: &TestNode<'_>, keep: fn(&Event) -> bool) -> Event {
    log_of(node)
        .into_iter()
        .rev()
        .map(|e| e.entry.event)
        .find(keep)
        .unwrap()
}

fn forward(
    node: &TestNode<'_>,
    record: &Record,
    request: &Request,
    transport: &mut FakeTransport,
) -> engine::Result<Response> {
    let outcome = call_http(node, record, "call", Some(request), transport);
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
    node: TestNode<'c>,
    record: Record,
    device: DeviceKey,
}

/// Lists the caller `app` for every operation, when the policy lists no caller.
fn with_caller(mut policy: Policy) -> Policy {
    if policy.callers.is_empty() {
        policy.callers.push(Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: policy
                .operations
                .iter()
                .map(|o| o.name().to_string())
                .collect(),
            limit: None,
        });
    }
    policy
}

fn setup<'c>(clock: &'c TestClock, policy: Policy, values: &[(&str, &[u8])]) -> Setup<'c> {
    let policy = with_caller(policy);
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
    let node = Node::new(NodeKey::generate(), MemorySink::new(), clock);
    grant_on(&node, &device, user_key, NOW + DAY, &[("rec-1", 1)]).unwrap();
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
    forward(&s.node, &s.record, request, &mut transport).unwrap();
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
    let clock = TestClock::at(NOW);
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
            {
                let mut policy = request_policy(
                    vec![token.clone()],
                    vec![inject(
                        Target::PathParam {
                            name: "token".into(),
                        },
                        "{{token}}",
                    )],
                );
                contract_of(&mut policy).paths = vec!["/{token}/getMe".into()];
                policy
            },
            vec![("token", TOKEN)],
            get("/{token}/getMe"),
            "GET /tok_live_9f8e7d6c5b4a/getMe HTTP/1.1",
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
            {
                let mut policy = request_policy(
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
                );
                let contract = contract_of(&mut policy);
                contract.query = ["symbol", "type", "timeInForce", "price", "timestamp"]
                    .into_iter()
                    .map(QueryRule::any)
                    .collect();
                contract.query.push(QueryRule {
                    one_of: vec!["BUY".into(), "SELL".into()],
                    ..QueryRule::any("side")
                });
                contract.query.push(QueryRule {
                    max: Some("10".into()),
                    ..QueryRule::any("quantity")
                });
                contract.query.push(QueryRule {
                    max: Some("60000".into()),
                    ..QueryRule::any("recvWindow")
                });
                policy
            },
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
    let clock = TestClock::at(NOW);
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
    let clock = TestClock::at(NOW);
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
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
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
        (
            other_host,
            Error::DestinationDenied {
                host: "evil.example.net:443".into(),
            },
        ),
        (
            delete,
            Error::MethodDenied {
                method: "DELETE".into(),
            },
        ),
        (
            own_header,
            Error::RequestInvalid {
                rule: "header not allowed by the operation",
            },
        ),
        (
            host_header,
            Error::RequestInvalid {
                rule: "header name or value malformed or reserved",
            },
        ),
        (
            get("no-slash"),
            Error::RequestInvalid {
                rule: "path must start with /",
            },
        ),
        (
            get("/a/../b"),
            Error::RequestInvalid {
                rule: "path holds a dot segment or separator, as sent, after ; parameters or after decoding",
            },
        ),
    ] {
        assert_eq!(
            forward(&s.node, &s.record, &request, &mut transport),
            Err(error)
        );
    }
    assert!(transport.sent.is_empty());
    assert_eq!(log_of(&s.node).len(), 1, "only the grant entry");
}

#[test]
fn a_policy_cannot_be_widened_or_swapped() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let mut to_evil = get("/");
    to_evil.destination = Destination::https("evil.example.net");

    let mut widened = s.record.clone();
    destinations_of(&mut widened.policy.policy).push(Destination::https("evil.example.net"));
    assert_eq!(
        forward(&s.node, &widened, &to_evil, &mut transport),
        Err(Error::PolicySignature)
    );

    let mut leaky = s.record.clone();
    send_of(&mut leaky.policy.policy, 0)
        .inject
        .push(header("X-Echo", "{{token}}"));
    assert_eq!(
        forward(&s.node, &leaky, &get("/"), &mut transport),
        Err(Error::PolicySignature)
    );

    let mut wide = policy;
    destinations_of(&mut wide).push(Destination::https("evil.example.net"));
    let mut swapped = s.record.clone();
    swapped.policy = s.device.sign_policy(with_caller(wide)).unwrap();
    assert_eq!(
        forward(&s.node, &swapped, &to_evil, &mut transport),
        Err(Error::RecordOpen)
    );

    let mut wrong_owner = s.record.clone();
    wrong_owner.owner = "user-2".into();
    // The node knows no device of user-2, so the policy does not verify; it says nothing
    // about grants before a signature checks.
    assert_eq!(
        forward(&s.node, &wrong_owner, &get("/"), &mut transport),
        Err(Error::PolicySignature)
    );
    assert!(transport.sent.is_empty());
}

#[test]
fn nothing_is_sent_without_a_confirmed_entry() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    s.node.with_sink(|k| k.set_failing(true));
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::LogUnconfirmed)
    );
    s.node.with_sink(|k| k.set_failing(false));
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::LogHalted)
    );
    assert!(transport.sent.is_empty());
}

#[test]
fn grants_end_and_revokes_erase() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();

    clock.set(NOW + DAY);
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::GrantExpired)
    );
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::NoGrant)
    );

    clock.set(NOW);
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let revocation = s
        .device
        .revoke(OWNER, &s.node.public_key(), issued())
        .unwrap();
    s.node.revoke(&revocation).unwrap();
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::NoGrant)
    );
    assert!(transport.sent.is_empty());

    grant_on(&s.node, &s.device, [1u8; 32], NOW + 365 * DAY, &[]).unwrap();
    match &log_of(&s.node).last().unwrap().entry.event {
        Event::Grant { expires_ms, .. } => assert_eq!(*expires_ms, NOW + 30 * DAY),
        other => panic!("unexpected event {other:?}"),
    }
}

#[test]
fn responses_that_echo_a_secret_are_dropped() {
    let clock = TestClock::at(NOW);
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
        let s = setup(
            &clock,
            policy.clone(),
            &[("user", b"bot"), ("password", TOKEN)],
        );
        let mut wire = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        wire.extend_from_slice(reply);
        let mut transport = FakeTransport {
            reply: wire,
            ..Default::default()
        };
        let result = forward(&s.node, &s.record, &get("/"), &mut transport);
        if dropped {
            assert_eq!(result, Err(Error::Reflection), "{}", text(reply));
        } else {
            assert_eq!(
                result.unwrap().body(),
                reply,
                "a public field is not a secret"
            );
        }
    }
}

#[test]
fn derivations_hand_back_only_one_way_outputs() {
    let clock = TestClock::at(1_111_111_109_000);
    let mut transport = FakeTransport::default();

    let s = setup(
        &clock,
        derive_policy(vec![secret("seed")], "{{ totp(b32decode(seed)) }}"),
        &[("seed", b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")],
    );
    assert_eq!(
        call_derive(&s.node, &s.record, "derive", b"").unwrap(),
        b"081804"
    );
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport),
        Err(Error::OperationUnknown {
            name: "call".into()
        })
    );

    use hmac::{Hmac, KeyInit, Mac};
    let key = b"exchange-secret-key-0123456789";
    let s = setup(
        &clock,
        derive_policy(vec![secret("key")], "{{ hex(hmac_sha256(key, $input)) }}"),
        &[("key", key)],
    );
    let tag = call_derive(&s.node, &s.record, "derive", b"GET\n/api/v3/order\nts=1").unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(b"GET\n/api/v3/order\nts=1");
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tag, expected.as_bytes());
    match &log_of(&s.node).last().unwrap().entry.event {
        Event::Derive { .. } => {}
        other => panic!("unexpected event {other:?}"),
    }

    let device = DeviceKey::generate();
    for leaky in ["{{key}}", "{{ b64(key) }}", "{{ hexdecode(hex(key)) }}"] {
        let policy = derive_policy(vec![secret("key")], leaky);
        assert!(
            matches!(device.sign_policy(policy), Err(Error::PolicyInvalid { .. })),
            "{leaky}"
        );
    }
    assert!(transport.sent.is_empty());
}

#[test]
fn private_keys_in_pem_sign_without_leaving() {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let clock = TestClock::at(NOW);
    let message = b"contract v1";

    let ed = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let ed_pem = ed.to_pkcs8_pem(Default::default()).unwrap();
    let policy = derive_policy(vec![secret("key")], "{{ ed25519_sign(pem(key), $input) }}");
    let s = setup(&clock, policy, &[("key", ed_pem.as_bytes())]);
    let signature = call_derive(&s.node, &s.record, "derive", message).unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    ed.verifying_key()
        .verify_strict(message, &signature)
        .unwrap();

    let ec = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let ec_pem = p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(&ec, Default::default()).unwrap();
    let policy = derive_policy(vec![secret("key")], "{{ p256_sign_der(pem(key), $input) }}");
    let s = setup(&clock, policy, &[("key", ec_pem.as_bytes())]);
    let der = call_derive(&s.node, &s.record, "derive", message).unwrap();
    let signature = p256::ecdsa::Signature::from_der(&der).unwrap();
    use p256::ecdsa::signature::Verifier as _;
    ec.verifying_key().verify(message, &signature).unwrap();
}

#[test]
fn a_tampered_chain_is_found() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    for path in ["/a", "/b", "/c"] {
        forward(&s.node, &s.record, &get(path), &mut transport).unwrap();
    }
    let key = s.node.public_key();
    let entries = log_of(&s.node).to_vec();
    verify_chain(&entries, &key).unwrap();
    let logged = serde_json::to_string(&entries).unwrap();
    assert!(
        !logged.contains("tok_live"),
        "the log must not hold a secret"
    );

    // Entries: grant, then a use and its done for each request.
    let mut edited = entries.clone();
    match &mut edited[3].entry.event {
        Event::Use { operation, .. } => *operation = "innocent".into(),
        other => panic!("unexpected event {other:?}"),
    }
    assert_eq!(
        verify_chain(&edited, &key),
        Err(Error::EntrySignature { seq: 3 })
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
    let clock = TestClock::at(NOW);
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
    let clock = TestClock::at(NOW);
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
        item: None,
        fields: vec![
            public("client_id"),
            secret("client_secret"),
            secret("refresh_token"),
            later("access_token"),
        ],
        callers: vec![],
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
        forward(&s.node, &s.record, &get("/me"), &mut transport),
        Err(Error::FieldMissing {
            field: "access_token".into()
        })
    );
    assert!(transport.sent.is_empty());

    transport.replies.push_back(reply(
        "200 OK",
        r#"{"access_token":"at_new_abcdefghijkl","refresh_token":"rt_second_987654321","expires_in":3600}"#,
    ));
    let outcome = call_http(&s.node, &s.record, "refresh", None, &mut transport);
    let response = outcome.result.unwrap();
    assert_eq!(
        text(response.body()),
        r#"{"access_token":"[redacted]","refresh_token":"[redacted]","expires_in":3600}"#
    );
    let wire = text(&transport.sent.pop().unwrap());
    assert!(wire.starts_with("POST /oauth/token HTTP/1.1\r\nHost: auth.example.com\r\n"));
    assert!(wire.ends_with(
        "grant_type=refresh_token&refresh_token=rt_first_0123456789&client_id=app-1&client_secret=cs_0123456789abcdef"
    ));
    let renewed = outcome.record.unwrap();
    assert_ne!(renewed.ct, s.record.ct);
    match last_event(&s.node, |e| matches!(e, Event::Update { .. })) {
        Event::Update {
            operation, fields, ..
        } => {
            assert_eq!(operation, "refresh");
            assert_eq!(fields, &["access_token", "refresh_token"]);
        }
        other => panic!("unexpected event {other:?}"),
    }

    s.record = renewed;
    transport.reply = reply("200 OK", "{}");
    forward(&s.node, &s.record, &get("/me"), &mut transport).unwrap();
    assert!(
        text(&transport.sent.pop().unwrap())
            .contains("Authorization: Bearer at_new_abcdefghijkl\r\n")
    );

    // The next refresh sends the rotated refresh token.
    transport
        .replies
        .push_back(reply("200 OK", r#"{"access_token":"at_third_abcdefghij"}"#));
    let outcome = call_http(&s.node, &s.record, "refresh", None, &mut transport);
    outcome.result.unwrap();
    assert!(text(&transport.sent.pop().unwrap()).contains("refresh_token=rt_second_987654321&"));

    // The record it replaces is refused from now on: an operator cannot roll it back.
    let newest = outcome.record.unwrap();
    assert_eq!(newest.generation, s.record.generation + 1);
    let outcome = call_http(&s.node, &s.record, "refresh", None, &mut transport);
    assert_eq!(
        outcome.result,
        Err(Error::RecordStale {
            have: s.record.generation,
            need: newest.generation
        })
    );
    s.record = newest;

    // A refresh that returns no token fails and changes nothing.
    transport
        .replies
        .push_back(reply("400 Bad Request", r#"{"error":"invalid_grant"}"#));
    let outcome = call_http(&s.node, &s.record, "refresh", None, &mut transport);
    assert_eq!(outcome.result, Err(Error::CaptureMissing));
    assert!(outcome.record.is_none());

    let logged = serde_json::to_string(&log_of(&s.node)).unwrap();
    for value in ["at_new", "rt_first", "rt_second", "cs_0123"] {
        assert!(!logged.contains(value), "{value}");
    }
}

#[test]
fn a_session_login_feeds_a_cookie_to_the_caller_request() {
    let clock = TestClock::at(NOW);
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
        item: None,
        fields: vec![public("user"), secret("password")],
        callers: vec![],
        operations: vec![http(
            "call",
            host(),
            vec![
                login,
                caller_step(vec![header("Cookie", "sid={{session}}")]),
            ],
        )],
    };
    let s = setup(&clock, policy, &[("user", b"kim"), ("password", TOKEN)]);
    let mut transport = FakeTransport::default();
    transport.replies.push_back(
        b"HTTP/1.1 302 Found\r\nSet-Cookie: sid=sess_0123456789abcdef; HttpOnly\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    );
    transport.replies.push_back(reply(
        "200 OK",
        r#"{"orders":[],"echo":"sess_0123456789abcdef"}"#,
    ));
    let response = forward(&s.node, &s.record, &get("/orders"), &mut transport).unwrap();
    assert_eq!(
        text(response.body()),
        r#"{"orders":[],"echo":"[redacted]"}"#
    );
    assert!(text(&transport.sent[0]).starts_with("POST /login HTTP/1.1\r\n"));
    let second = text(&transport.sent[1]);
    assert!(second.starts_with("GET /orders HTTP/1.1\r\n"));
    assert!(second.contains("Cookie: sid=sess_0123456789abcdef\r\n"));
    let uses = log_of(&s.node)
        .iter()
        .filter(|e| matches!(e.entry.event, Event::Use { .. }))
        .count();
    assert_eq!(uses, 2, "one entry per request");
}

#[test]
fn digest_authentication_answers_the_challenge() {
    // RFC 2617, section 3.5.
    let clock = TestClock::at(NOW);
    let param = |p: &str| Source::HeaderParam {
        name: "WWW-Authenticate".into(),
        param: p.into(),
        scheme: None,
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
        item: None,
        fields: vec![public("username"), secret("password")],
        callers: vec![],
        operations: vec![http("call", host(), vec![challenge, answer])],
    };
    let s = setup(
        &clock,
        policy,
        &[("username", b"Mufasa"), ("password", b"Circle Of Life")],
    );
    let mut transport = FakeTransport::default();
    transport.replies.push_back(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\nContent-Length: 0\r\n\r\n".to_vec());
    transport.reply = reply("200 OK", "ok");
    forward(&s.node, &s.record, &get("/dir/index.html"), &mut transport).unwrap();
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
    let clock = TestClock::at(1_440_938_160_000);
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
        item: None,
        fields: vec![public("access_key"), secret("secret_key")],
        callers: vec![],
        operations: vec![http(
            "call",
            destination.clone(),
            vec![caller_step(vec![
                header("X-Amz-Date", &format!("{{{{ {stamp} }}}}")),
                header("Authorization", &authorization),
            ])],
        )],
    };
    let s = setup(
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
    forward(&s.node, &s.record, &request, &mut transport).unwrap();
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

    let clock = TestClock::at(NOW);
    let head = r#"b64urlraw("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "." + b64urlraw($input)"#;
    let jwt =
        format!("{{{{ {head} + \".\" + b64urlraw(rsa_sign_pkcs1_sha256(pem(key), {head})) }}}}");
    let s = setup(
        &clock,
        derive_policy(vec![secret("key")], &jwt),
        &[("key", pem.as_bytes())],
    );
    let claims =
        br#"{"iss":"svc@example.iam","aud":"https://oauth2.example.com/token","exp":1800000600}"#;
    let token =
        String::from_utf8(call_derive(&s.node, &s.record, "derive", claims).unwrap()).unwrap();
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
    let s = setup(&clock, pss, &[("key", pem.as_bytes())]);
    let signature = call_derive(&s.node, &s.record, "derive", b"message").unwrap();
    UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, &public)
        .verify(b"message", &signature)
        .unwrap();
}

#[test]
fn secp256k1_keys_sign_and_recover() {
    use k256::ecdsa::signature::Verifier as _;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
    use sha3::Digest as _;

    let clock = TestClock::at(NOW);
    let secret_key = [0x11u8; 32];
    let key = SigningKey::from_slice(&secret_key).unwrap();
    let policy = Policy {
        item: None,
        fields: vec![secret("key")],
        callers: vec![],
        operations: vec![
            derive_op("derive", "{{ k256_sign(key, $input) }}"),
            derive_op("eth", "{{ k256_sign_recoverable(key, keccak256($input)) }}"),
        ],
    };
    let s = setup(&clock, policy, &[("key", &secret_key)]);

    let signature = call_derive(&s.node, &s.record, "derive", b"order 42").unwrap();
    let signature = Signature::from_slice(&signature).unwrap();
    key.verifying_key().verify(b"order 42", &signature).unwrap();

    let out = call_derive(&s.node, &s.record, "eth", b"transfer 1 eth").unwrap();
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

    let clock = TestClock::at(NOW);
    let key = [0x42u8; 32];
    let policy = derive_policy(
        vec![secret("key")],
        r#"{{ aes_gcm_encrypt(key, hexdecode("000102030405060708090a0b"), $input, "v1") }}"#,
    );
    let s = setup(&clock, policy, &[("key", &key)]);
    let sealed = call_derive(&s.node, &s.record, "derive", b"card 4111").unwrap();
    let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let plain = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            &Nonce::from(nonce),
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
    assert!(matches!(
        DeviceKey::generate().sign_policy(leaky),
        Err(Error::PolicyInvalid { .. })
    ));
}

fn imap_policy() -> Policy {
    Policy {
        item: None,
        fields: vec![public("user"), secret("password")],
        callers: vec![],
        operations: vec![
            Operation::tls("imap", Destination::new("imap.example.com", 993))
                .then(Receive::until(["\r\n"]))
                .then(Send::write("a1 LOGIN {{user}} {{password}}\r\n"))
                .then(Receive::until(["\r\n"]).capture(capture(
                    Source::Between {
                        start: "a1 ".into(),
                        end: " ".into(),
                    },
                    temp("status", false),
                )))
                .then(Return::relay([r"a[0-9]+ (SELECT INBOX|NOOP|LOGOUT)\r\n"])),
        ],
    }
}

#[test]
fn a_stream_logs_in_then_carries_the_caller() {
    let clock = TestClock::at(NOW);
    let s = setup(
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
        until: vec![b"a2 OK".to_vec()],
    }];
    let outcome = call_stream(
        &s.node,
        &s.record,
        "imap",
        &imap,
        &exchanges,
        &mut transport,
    );
    assert!(outcome.record.is_none());
    assert_eq!(
        outcome.result.unwrap(),
        StreamOutput {
            reads: vec![b"* 3 EXISTS\r\na2 OK SELECT completed\r\n".to_vec()],
            error: None,
        }
    );
    assert_eq!(
        transport.written,
        vec![
            b"a1 LOGIN bot p4ssw0rd-imap\r\n".to_vec(),
            b"a2 SELECT INBOX\r\n".to_vec()
        ]
    );
    let entries = log_of(&s.node);
    let stream = entries
        .iter()
        .rev()
        .find(|e| matches!(e.entry.event, Event::Stream { .. }))
        .unwrap();
    assert!(
        !serde_json::to_string(stream)
            .unwrap()
            .contains("imap.example.com")
    );
    match engine::log::open_detail(&user_key(), &stream.entry).unwrap() {
        Some(Detail::Stream { host, port, .. }) => {
            assert_eq!((host.as_str(), port), ("imap.example.com", 993));
        }
        other => panic!("unexpected detail {other:?}"),
    }

    // A server that echoes the password: the read is dropped.
    let mut transport = FakeTransport::default();
    transport.replies.extend([
        b"* OK\r\n".to_vec(),
        b"a1 OK done\r\n".to_vec(),
        b"a2 BAD p4ssw0rd-imap\r\n".to_vec(),
    ]);
    let outcome = call_stream(
        &s.node,
        &s.record,
        "imap",
        &imap,
        &exchanges,
        &mut transport,
    );
    assert_eq!(
        outcome.result,
        Ok(StreamOutput {
            reads: vec![],
            error: Some(Error::Reflection),
        })
    );

    // Another host is refused before the log.
    let before = log_of(&s.node).len();
    let outcome = call_stream(
        &s.node,
        &s.record,
        "imap",
        &Destination::new("evil.example.net", 993),
        &exchanges,
        &mut FakeTransport::default(),
    );
    assert_eq!(
        outcome.result,
        Err(Error::DestinationDenied {
            host: "evil.example.net:993".into()
        })
    );
    assert_eq!(log_of(&s.node).len(), before);
}

#[test]
fn client_certificates_reach_only_the_transport() {
    let clock = TestClock::at(NOW);
    let cert = b"-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n";
    let key = b"-----BEGIN PRIVATE KEY-----\nMIIBkey-0123456789\n-----END PRIVATE KEY-----\n";
    let policy = Policy {
        item: None,
        fields: vec![public("cert"), secret("key")],
        callers: vec![],
        operations: vec![
            http("call", host(), vec![caller_step(vec![])]).identity("{{cert}}", "{{key}}"),
        ],
    };
    let s = setup(&clock, policy, &[("cert", cert), ("key", key)]);
    let mut transport = FakeTransport {
        reply: reply("200 OK", "{}"),
        ..Default::default()
    };
    forward(&s.node, &s.record, &get("/"), &mut transport).unwrap();
    assert_eq!(transport.identities, vec![(cert.to_vec(), key.to_vec())]);
    assert!(!text(&transport.sent[0]).contains("PRIVATE KEY"));
    let logged = serde_json::to_string(&log_of(&s.node)).unwrap();
    assert!(!logged.contains("MIIBkey"));
}

// ---- regressions: what the review (code user, owner, bug hunter, hacker) found ----

fn user_key() -> UserKey {
    UserKey::from_bytes(&mut [7u8; 32])
}

fn refresh_policy() -> Policy {
    let step = Step {
        request: StepRequest::Fixed {
            method: Method::Post,
            path: "/oauth/token".into(),
            destination: None,
        },
        inject: vec![inject(Target::Body, "rt={{pct(refresh_token)}}")],
        capture: vec![capture(
            Source::Json {
                pointer: "/access_token".into(),
            },
            Store::Field {
                name: "access_token".into(),
            },
        )],
    };
    Policy {
        item: None,
        fields: vec![secret("refresh_token"), later("access_token")],
        callers: vec![],
        operations: vec![http("refresh", host(), vec![step])],
    }
}

fn run_refresh(response: Vec<u8>) -> engine::Result<Response> {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        refresh_policy(),
        &[("refresh_token", b"rt_first_0123456789")],
    );
    let mut transport = FakeTransport::default();
    transport.replies.push_back(response);
    call_http(&s.node, &s.record, "refresh", None, &mut transport).result
}

#[test]
fn a_captured_secret_split_over_chunks_is_redacted() {
    let first = "{\"access_token\":\"at_new_abcd";
    let second = "efghijkl\"}";
    let wire = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
        first.len(),
        second.len()
    );
    let response = run_refresh(wire.into_bytes()).unwrap();
    assert_eq!(response.body(), br#"{"access_token":"[redacted]"}"#);
    assert!(response.header("transfer-encoding").is_none());
}

#[test]
fn a_captured_secret_written_with_json_escapes_is_redacted() {
    let body = format!(
        r#"{{"access_token":"{}u0061t_new_abcdefghijkl"}}"#,
        char::from(0x5c)
    );
    let response = run_refresh(reply("200 OK", &body)).unwrap();
    assert_eq!(response.body(), br#"{"access_token":"[redacted]"}"#);
}

#[test]
fn short_captured_secrets_are_redacted_or_dropped() {
    let response = run_refresh(reply("200 OK", r#"{"access_token":"at_x7k"}"#)).unwrap();
    assert_eq!(response.body(), br#"{"access_token":"[redacted]"}"#);
    // Too short to redact without breaking the response: it is dropped.
    assert_eq!(
        run_refresh(reply("200 OK", r#"{"access_token":"a7k"}"#)).map(|_| ()),
        Err(Error::Reflection)
    );
}

#[test]
fn short_secret_fields_are_searched() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(vec![secret("pin")], vec![header("X-Pin", "{{pin}}")]);
    let s = setup(&clock, policy, &[("pin", b"483920")]);
    let mut transport = FakeTransport {
        reply: reply("200 OK", "your pin is 483920"),
        ..Default::default()
    };
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::Reflection)
    );
}

#[test]
fn an_echo_split_over_chunks_is_caught_and_framing_headers_are_refused() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let (first, second) = ("Bearer tok_", "live_9f8e7d6c5b4a");
    let mut transport = FakeTransport {
        reply: format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\n\r\n",
            first.len(),
            second.len()
        )
        .into_bytes(),
        ..Default::default()
    };
    assert_eq!(
        forward(&s.node, &s.record, &get("/echo"), &mut transport).map(|_| ()),
        Err(Error::Reflection)
    );
    let sent = text(&transport.sent[0]);
    assert!(sent.contains("Accept-Encoding: identity\r\n"), "{sent}");
    for name in [
        "Accept-Encoding",
        "X-HTTP-Method-Override",
        "Range",
        "TE",
        "Expect",
    ] {
        let mut request = get("/echo");
        request.headers.push((name.into(), "x".into()));
        assert_eq!(
            forward(&s.node, &s.record, &request, &mut transport).map(|_| ()),
            Err(Error::RequestInvalid {
                rule: "header name or value malformed or reserved"
            }),
            "{name}"
        );
    }
    // A compressed body cannot be searched: it is refused.
    transport.reply = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nxx".to_vec();
    assert_eq!(
        forward(&s.node, &s.record, &get("/echo"), &mut transport).map(|_| ()),
        Err(Error::ResponseInvalid {
            rule: "encoded body"
        })
    );
}

#[test]
fn a_stream_keeps_its_captured_field_when_an_exchange_fails() {
    let clock = TestClock::at(NOW);
    let policy = Policy {
        item: None,
        fields: vec![secret("password"), later("session")],
        callers: vec![],
        operations: vec![
            Operation::tls("s", Destination::new("imap.example.com", 993))
                .then(Send::write("LOGIN {{password}}\r\n"))
                .then(Receive::until(["\r\n"]).capture(capture(
                    Source::Between {
                        start: "SESSION ".into(),
                        end: "\r\n".into(),
                    },
                    Store::Field {
                        name: "session".into(),
                    },
                )))
                .then(Return::relay([r"NOOP\r\n"])),
        ],
    };
    let s = setup(&clock, policy, &[("password", b"p4ssw0rd-imap")]);
    let mut transport = FakeTransport::default();
    transport
        .replies
        .push_back(b"SESSION sess_rotated_0123456789\r\n".to_vec());
    let exchanges = [CallerExchange {
        send: b"NOOP\r\n".to_vec(),
        until: vec![b"\r\n".to_vec()],
    }];
    let imap = Destination::new("imap.example.com", 993);
    let outcome = call_stream(&s.node, &s.record, "s", &imap, &exchanges, &mut transport);
    assert_eq!(
        outcome.result,
        Ok(StreamOutput {
            reads: vec![],
            error: Some(Error::transport(TransportKind::Closed, false)),
        })
    );
    assert_eq!(outcome.record.unwrap().generation, 2);
}

#[test]
fn derivations_that_are_oracles_are_refused() {
    let device = DeviceKey::generate();
    for template in [
        // xor(key, key) is all zeros: not a secret key.
        r#"{{ aes_gcm_encrypt(xor(key, key), "000000000000", key) }}"#,
        // The length tells whether the input is a part of the key.
        r#"{{ len(replace(key, $input, "")) }}"#,
        // Whether decoding fails tells about the key.
        r#"{{ sha256(b64decode(key + $input)) }}"#,
    ] {
        let policy = with_caller(derive_policy(vec![secret("key")], template));
        assert!(
            matches!(device.sign_policy(policy), Err(Error::PolicyInvalid { .. })),
            "{template}"
        );
    }
}

#[test]
fn templates_read_every_token_name_and_end_with_braces() {
    let clock = TestClock::at(NOW);
    for name in ["api-key", "2fa"] {
        let policy = request_policy(
            vec![secret(name)],
            vec![inject(
                Target::Body,
                &format!(r#"{{"outer":{{"token":"{{{{{name}}}}}"}}}}"#),
            )],
        );
        let s = setup(&clock, policy, &[(name, TOKEN)]);
        let mut transport = FakeTransport::default();
        forward(&s.node, &s.record, &post("/", b""), &mut transport).unwrap();
        assert_eq!(
            body_of(&transport.sent[0]),
            br#"{"outer":{"token":"tok_live_9f8e7d6c5b4a"}}"#
        );
    }
}

#[test]
fn a_clock_that_goes_back_keeps_the_chain_valid() {
    let clock = TestClock::at(NOW);
    let policy = derive_policy(vec![secret("key")], "{{ hex(hmac_sha256(key, $input)) }}");
    let s = setup(&clock, policy, &[("key", b"0123456789abcdef")]);
    clock.set(NOW + 5000);
    call_derive(&s.node, &s.record, "derive", b"x").unwrap();
    clock.set(NOW + 4000);
    call_derive(&s.node, &s.record, "derive", b"x").unwrap();
    let entries = log_of(&s.node);
    verify_chain(&entries, &s.node.public_key()).unwrap();
    assert_eq!(entries.last().unwrap().entry.time_ms, NOW + 5000);
    // Behind the time the node started, nothing signed is accepted.
    clock.set(NOW - 1000);
    assert!(matches!(
        call_derive(&s.node, &s.record, "derive", b"x"),
        Err(Error::CallerInvalid { .. })
    ));
}

#[test]
fn a_capture_into_a_public_field_is_refused() {
    let mut step = Step {
        request: StepRequest::Fixed {
            method: Method::Get,
            path: "/me".into(),
            destination: None,
        },
        inject: vec![header("Authorization", "Bearer {{token}}")],
        capture: vec![],
    };
    step.capture.push(capture(
        Source::Json {
            pointer: "/name".into(),
        },
        Store::Field {
            name: "display_name".into(),
        },
    ));
    let policy = with_caller(Policy {
        item: None,
        fields: vec![secret("token"), public("display_name")],
        callers: vec![],
        operations: vec![
            http("call", host(), vec![step]),
            derive_op("name", "{{display_name}}"),
        ],
    });
    assert_eq!(
        DeviceKey::generate().sign_policy(policy),
        Err(Error::PolicyInvalid {
            at: "operations[0].steps[2].capture[0]".into(),
            rule: "capture into a public field (a derivation could hand it back)"
        })
    );
}

#[test]
fn an_older_record_is_refused_after_a_newer_one_or_a_pin() {
    let clock = TestClock::at(NOW);
    let wide = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, wide.clone(), &[("token", TOKEN)]);
    let old = s.record.clone();
    let mut transport = FakeTransport::default();

    // The owner narrows the policy on the device: same values, one generation later.
    let mut narrow = with_caller(wide);
    contract_of(&mut narrow).methods = vec![Method::Get];
    let narrow = old
        .rewrap(&user_key(), s.device.sign_policy(narrow).unwrap())
        .unwrap();
    assert_eq!(narrow.generation, 2);

    // Until the node sees the new record or a pin, the old one still works.
    forward(&s.node, &old, &post("/x", b""), &mut transport).unwrap();
    s.node.pin(&s.device.pin(&narrow).unwrap()).unwrap();
    assert_eq!(
        forward(&s.node, &old, &post("/x", b""), &mut transport).map(|_| ()),
        Err(Error::RecordStale { have: 1, need: 2 })
    );
    assert_eq!(
        forward(&s.node, &narrow, &post("/x", b""), &mut transport).map(|_| ()),
        Err(Error::MethodDenied {
            method: "POST".into()
        })
    );
    forward(&s.node, &narrow, &get("/x"), &mut transport).unwrap();

    // A pin signed by a key that is not a device of the owner is refused.
    let stranger = DeviceKey::generate().pin(&narrow).unwrap();
    assert_eq!(s.node.pin(&stranger), Err(Error::PolicySignature));
}

#[test]
fn a_second_device_is_added_not_swapped() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let seal = |device: &DeviceKey| {
        Record::seal(
            &user_key(),
            "rec-1",
            OWNER,
            device.sign_policy(with_caller(policy.clone())).unwrap(),
            &fields(&[("token", TOKEN)]),
        )
        .unwrap()
    };

    // A laptop with the same user key but no endorsement is no device of the owner: the user
    // key alone would let a retired or stolen device come back under a fresh key.
    let laptop = DeviceKey::generate();
    assert_eq!(
        grant_on(&s.node, &laptop, [7u8; 32], NOW + DAY, &[("rec-2", 1)]),
        Err(Error::GrantDenied)
    );
    forward(&s.node, &s.record, &get("/"), &mut transport).unwrap();
    assert_eq!(
        forward(&s.node, &seal(&laptop), &get("/"), &mut transport).map(|_| ()),
        Err(Error::PolicySignature)
    );

    // A tablet the phone endorses.
    let tablet = DeviceKey::generate();
    let record = seal(&tablet);
    assert_eq!(
        forward(&s.node, &record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::PolicySignature)
    );
    s.node
        .add_device(
            &s.device
                .endorse(OWNER, &s.node.public_key(), &tablet.public(), issued())
                .unwrap(),
        )
        .unwrap();
    forward(&s.node, &record, &get("/"), &mut transport).unwrap();

    // An endorsement by a stranger is refused.
    let stranger = DeviceKey::generate();
    assert_eq!(
        s.node.add_device(
            &stranger
                .endorse(OWNER, &s.node.public_key(), &stranger.public(), issued())
                .unwrap()
        ),
        Err(Error::PolicySignature)
    );

    // A stranger cannot take the owner over with another user key.
    assert_eq!(
        grant_on(&s.node, &stranger, [8u8; 32], NOW + DAY, &[]),
        Err(Error::GrantDenied)
    );
    forward(&s.node, &s.record, &get("/"), &mut transport).unwrap();
}

#[test]
fn calls_need_a_listed_caller_and_a_fresh_signature() {
    let clock = TestClock::at(NOW);
    let mut policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    policy
        .operations
        .push(derive_op("hash", "{{ hex(hmac_sha256(token, $input)) }}"));
    let reader = CallerKey::from_bytes(&mut [6u8; 32]);
    policy.callers = vec![
        Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: vec!["call".into(), "hash".into()],
            limit: None,
        },
        Caller {
            name: "reader".into(),
            key: reader.public(),
            operations: vec!["hash".into()],
            limit: None,
        },
    ];
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let request = get("/a");
    let payload = Payload::Http(Some(&request));
    let sign = |key: &CallerKey, name: &str, payload: &Payload<'_>, time: u64| {
        key.authorize(name, &s.node.public_key(), &s.record, "call", payload, time)
            .unwrap()
    };
    let run = |auth: &Authorization, request: &Request, transport: &mut FakeTransport| {
        s.node
            .http(&s.record, "call", auth, Some(request), transport)
            .result
            .map(|_| ())
    };

    let cases = [
        (
            sign(&caller_key(), "nobody", &payload, NOW),
            Error::CallerDenied {
                caller: "nobody".into(),
                operation: String::new(),
            },
        ),
        (
            sign(&reader, "reader", &payload, NOW),
            Error::CallerDenied {
                caller: "reader".into(),
                operation: "call".into(),
            },
        ),
        (
            sign(&reader, "app", &payload, NOW),
            Error::CallerInvalid {
                rule: BAD_SIGNATURE,
            },
        ),
        (
            sign(&caller_key(), "app", &payload, NOW - 6 * 60 * 1000),
            Error::CallerInvalid {
                rule: "authorization too old or from the future",
            },
        ),
        (
            sign(&caller_key(), "app", &Payload::Http(Some(&get("/b"))), NOW),
            Error::CallerInvalid {
                rule: BAD_SIGNATURE,
            },
        ),
    ];
    for (auth, error) in cases {
        assert_eq!(run(&auth, &request, &mut transport), Err(error));
    }
    assert!(transport.sent.is_empty());
    assert_eq!(log_of(&s.node).len(), 1, "only the grant entry");

    let auth = sign(&caller_key(), "app", &payload, NOW);
    run(&auth, &request, &mut transport).unwrap();
    assert_eq!(
        run(&auth, &request, &mut transport),
        Err(Error::CallerInvalid {
            rule: "authorization used before"
        })
    );
    let callers: Vec<String> = log_of(&s.node)
        .iter()
        .map(|e| e.entry.caller.clone())
        .collect();
    assert_eq!(callers, ["", "app", "app"]);

    // The reader may use its own operation.
    let auth = reader
        .authorize(
            "reader",
            &s.node.public_key(),
            &s.record,
            "hash",
            &Payload::Derive(b""),
            NOW,
        )
        .unwrap();
    s.node.derive(&s.record, "hash", &auth, b"").unwrap();
}

#[test]
fn a_caller_is_held_to_its_limit() {
    let clock = TestClock::at(NOW);
    let mut policy = with_caller(derive_policy(
        vec![secret("key")],
        "{{ hex(hmac_sha256(key, $input)) }}",
    ));
    policy.callers[0].limit = Some(engine::policy::Limit {
        count: 2,
        window_ms: 1000,
    });
    let s = setup(&clock, policy, &[("key", b"0123456789abcdef")]);
    call_derive(&s.node, &s.record, "derive", b"").unwrap();
    call_derive(&s.node, &s.record, "derive", b"").unwrap();
    assert_eq!(
        call_derive(&s.node, &s.record, "derive", b""),
        Err(Error::RateLimited)
    );
    clock.set(NOW + 1000);
    call_derive(&s.node, &s.record, "derive", b"").unwrap();
}

#[test]
fn a_call_of_the_wrong_kind_spends_no_limit() {
    let clock = TestClock::at(NOW);
    let mut policy = with_caller(derive_policy(
        vec![secret("key")],
        "{{ hex(hmac_sha256(key, $input)) }}",
    ));
    policy.callers[0].limit = Some(engine::policy::Limit {
        count: 1,
        window_ms: 1000,
    });
    let s = setup(&clock, policy, &[("key", b"0123456789abcdef")]);
    let unknown = Error::OperationUnknown {
        name: "derive".into(),
    };
    for _ in 0..3 {
        let auth = authorize(&s.node, &s.record, "derive", &Payload::Http(None));
        let result = s
            .node
            .http(
                &s.record,
                "derive",
                &auth,
                None,
                &mut FakeTransport::default(),
            )
            .result
            .map(|_| ());
        assert_eq!(result, Err(unknown.clone()));
    }
    call_derive(&s.node, &s.record, "derive", b"").unwrap();
}

#[test]
fn caller_paths_and_headers_are_allowlisted() {
    let clock = TestClock::at(NOW);
    let mut policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let contract = contract_of(&mut policy);
    contract.paths = vec!["/v1/**".into(), "/health".into()];
    contract.headers = vec!["Accept".into()];
    contract.query = vec![QueryRule::any("full")];
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let mut accept = get("/v1/repos");
    accept
        .headers
        .push(("accept".into(), "application/json".into()));
    for request in [
        accept,
        get("/health"),
        get("/health?full=1"),
        get("/v1/a.b"),
    ] {
        forward(&s.node, &s.record, &request, &mut transport).unwrap();
    }
    let mut other = get("/v1/x");
    other.headers.push(("X-Other".into(), "1".into()));
    let denied = |path: &str| Error::PathDenied { path: path.into() };
    let dot_rule = Error::RequestInvalid {
        rule: "path holds a dot segment or separator, as sent, after ; parameters or after decoding",
    };
    let encoded_rule = Error::RequestInvalid {
        rule: "path holds an encoded /, \\ or .",
    };
    for (request, error) in [
        (get("/v2/x"), denied("/v2/x")),
        (get("/healthz"), denied("/healthz")),
        (get("/v1"), denied("/v1")),
        (get("/v1/../admin"), dot_rule),
        (get("/v1/%2e%2e/admin"), encoded_rule.clone()),
        (get("/v1%2Fadmin"), encoded_rule),
        (
            other,
            Error::RequestInvalid {
                rule: "header not allowed by the operation",
            },
        ),
    ] {
        assert_eq!(
            forward(&s.node, &s.record, &request, &mut transport).map(|_| ()),
            Err(error)
        );
    }
}

#[test]
fn a_wildcard_destination_matches_one_label() {
    let clock = TestClock::at(NOW);
    let mut policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    *destinations_of(&mut policy) = vec![Destination::https("*.example.com")];
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let to = |host: &str| {
        let mut request = get("/");
        request.destination = Destination::https(host);
        request
    };
    forward(&s.node, &s.record, &to("eu.example.com"), &mut transport).unwrap();
    assert!(text(&transport.sent[0]).contains("Host: eu.example.com\r\n"));
    for host in ["example.com", "a.b.example.com", "evil-example.com"] {
        assert_eq!(
            forward(&s.node, &s.record, &to(host), &mut transport).map(|_| ()),
            Err(Error::DestinationDenied {
                host: format!("{host}:443")
            }),
            "{host}"
        );
    }
}

#[test]
fn a_restarted_node_continues_its_chain_and_its_floors() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        refresh_policy(),
        &[("refresh_token", b"rt_first_0123456789")],
    );
    let device = s.device;
    let node_key = [9u8; 32];
    let node = Node::new(
        NodeKey::from_bytes(&mut node_key.clone()),
        MemorySink::new(),
        &clock,
    );
    grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
    let mut transport = FakeTransport::default();
    transport
        .replies
        .push_back(reply("200 OK", r#"{"access_token":"at_new_abcdefghijkl"}"#));
    let renewed = call_http(&node, &s.record, "refresh", None, &mut transport)
        .record
        .unwrap();
    let before = log_of(&node);
    drop(node);

    let mut sink = MemorySink::new();
    for entry in &before {
        engine::log::LogSink::append(&mut sink, entry).unwrap();
    }
    let node = Node::restore(
        NodeKey::from_bytes(&mut node_key.clone()),
        sink,
        &clock,
        &before,
    )
    .unwrap();
    clock.set(now() + 2);
    grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
    assert_eq!(
        call_http(&node, &s.record, "refresh", None, &mut transport)
            .result
            .map(|_| ()),
        Err(Error::RecordStale { have: 1, need: 2 })
    );
    transport
        .replies
        .push_back(reply("200 OK", r#"{"access_token":"at_third_abcdefghij"}"#));
    call_http(&node, &renewed, "refresh", None, &mut transport)
        .result
        .unwrap();
    let after = log_of(&node);
    assert!(after.len() > before.len());
    verify_chain(&after, &node.public_key()).unwrap();
    engine::log::verify_owner_chain(&after, OWNER, &node.public_key()).unwrap();
}

#[test]
fn a_lost_acknowledgement_halts_until_reconciled() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    s.node.with_sink(|k| k.set_store_then_fail(true));
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::LogUnconfirmed)
    );
    s.node.with_sink(|k| k.set_store_then_fail(false));
    assert!(s.node.is_halted());
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::LogHalted)
    );
    assert!(transport.sent.is_empty());
    let stored = log_of(&s.node);
    s.node.reconcile(stored.last()).unwrap();
    forward(&s.node, &s.record, &get("/"), &mut transport).unwrap();
    verify_chain(&log_of(&s.node), &s.node.public_key()).unwrap();
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

#[test]
fn one_node_serves_many_threads() {
    let _clock = TestClock::at(NOW);
    let device = DeviceKey::generate();
    let policy = with_caller(derive_policy(
        vec![secret("key")],
        "{{ hex(hmac_sha256(key, $input)) }}",
    ));
    let record = Record::seal(
        &user_key(),
        "rec-1",
        OWNER,
        device.sign_policy(policy).unwrap(),
        &fields(&[("key", b"0123456789abcdef")]),
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), FixedClock(NOW));
    grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
    std::thread::scope(|scope| {
        for t in 0..8u8 {
            let (node, record) = (&node, &record);
            scope.spawn(move || {
                for i in 0..10u8 {
                    let input = [t, i];
                    let auth = caller_key()
                        .authorize(
                            "app",
                            &node.public_key(),
                            record,
                            "derive",
                            &Payload::Derive(&input),
                            NOW,
                        )
                        .unwrap();
                    node.derive(record, "derive", &auth, &input).unwrap();
                }
            });
        }
    });
    let entries = node.with_sink(|k| k.entries().to_vec());
    assert_eq!(entries.len(), 1 + 80);
    verify_chain(&entries, &node.public_key()).unwrap();
}

#[test]
fn renderings_and_responses_have_budgets() {
    let clock = TestClock::at(NOW);
    let blowup = format!(
        "{{{{ len({}$input{}) }}}}",
        "hex(".repeat(16),
        ")".repeat(16)
    );
    let s = setup(
        &clock,
        derive_policy(vec![secret("k")], &blowup),
        &[("k", b"0123456789")],
    );
    let started = std::time::Instant::now();
    assert_eq!(
        call_derive(&s.node, &s.record, "derive", &[b'/'; 1024]),
        Err(Error::Budget { what: "bytes" })
    );
    assert!(started.elapsed().as_secs() < 10);

    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport {
        reply: vec![b'z'; engine::response::MAX_RESPONSE + 1],
        ..Default::default()
    };
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    let many = "X: 1\r\n".repeat(200);
    transport.reply = format!("HTTP/1.1 200 OK\r\n{many}\r\n").into_bytes();
    assert_eq!(
        forward(&s.node, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::ResponseInvalid {
            rule: "too many headers"
        })
    );
}

#[test]
fn p384_keys_sign() {
    use ring::signature::{
        ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
        UnparsedPublicKey,
    };
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        derive_policy(vec![secret("key")], "{{ p384_sign(key, $input) }}"),
        &[("key", pkcs8.as_ref())],
    );
    let signature = call_derive(&s.node, &s.record, "derive", b"message").unwrap();
    assert_eq!(signature.len(), 96);
    UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &public)
        .verify(b"message", &signature)
        .unwrap();
}

// ---- grants, revocations, pins, log privacy, guessable fields ----

#[test]
fn a_grant_opens_only_on_its_node_and_only_once() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let terms = || GrantTerms {
        owner: OWNER.into(),
        expires_ms: NOW + DAY,
        issued_ms: issued(),
        pins: vec![],
    };

    // Sealed to another node: this node cannot open it.
    let other = Node::new(NodeKey::generate(), MemorySink::new(), &clock);
    let elsewhere = s
        .device
        .grant(&user_key(), &other.identity(), terms())
        .unwrap();
    assert_eq!(
        s.node.grant(&elsewhere),
        Err(Error::GrantInvalid {
            rule: "not sealed to this node"
        })
    );

    // A grant replayed after a newer grant or revocation is refused.
    let first = s
        .device
        .grant(&user_key(), &s.node.identity(), terms())
        .unwrap();
    s.node.grant(&first).unwrap();
    let revocation = s
        .device
        .revoke(OWNER, &s.node.public_key(), issued())
        .unwrap();
    s.node.revoke(&revocation).unwrap();
    let stale = Err(Error::GrantInvalid {
        rule: "issued before the last grant or revocation of the owner",
    });
    assert_eq!(s.node.grant(&first), stale);
    assert_eq!(s.node.revoke(&revocation), stale);

    // A grant made long ago is refused.
    let mut old = terms();
    old.issued_ms = NOW - 6 * 60 * 1000;
    let old = s
        .device
        .grant(&user_key(), &s.node.identity(), old)
        .unwrap();
    assert_eq!(
        s.node.grant(&old),
        Err(Error::GrantInvalid {
            rule: "issued too long ago or in the future"
        })
    );

    // A changed byte of the sealed grant is refused.
    let mut bent = s
        .device
        .grant(&user_key(), &s.node.identity(), terms())
        .unwrap();
    let last = bent.ciphertext.len() - 1;
    bent.ciphertext[last] ^= 1;
    assert_eq!(
        s.node.grant(&bent),
        Err(Error::GrantInvalid {
            rule: "not sealed to this node"
        })
    );

    // The sealed grant does not hold the user key in the clear.
    let json = serde_json::to_string(&first).unwrap();
    assert!(!json.contains(&engine::encoding::to_b64(&[7u8; 32])));
}

#[test]
fn only_a_known_device_revokes() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let stranger = DeviceKey::generate();
    let forged = stranger
        .revoke(OWNER, &s.node.public_key(), issued())
        .unwrap();
    assert_eq!(s.node.revoke(&forged), Err(Error::GrantDenied));
    let mut swapped = s
        .device
        .revoke(OWNER, &s.node.public_key(), issued())
        .unwrap();
    swapped.owner = "user-2".into();
    assert_eq!(
        s.node.revoke(&swapped),
        Err(Error::GrantInvalid {
            rule: "revocation signature does not verify"
        })
    );
    forward(&s.node, &s.record, &get("/"), &mut transport).unwrap();
    assert_eq!(log_of(&s.node).len(), 3, "grant, use, done: no revoke");
}

#[test]
fn a_record_its_owner_never_pinned_is_refused() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    let unpinned = Record::seal(
        &user_key(),
        "rec-9",
        OWNER,
        s.device.sign_policy(with_caller(policy)).unwrap(),
        &fields(&[("token", TOKEN)]),
    )
    .unwrap();
    assert_eq!(
        forward(&s.node, &unpinned, &get("/"), &mut transport).map(|_| ()),
        Err(Error::RecordUnpinned)
    );
    assert!(transport.sent.is_empty());
    s.node.pin(&s.device.pin(&unpinned).unwrap()).unwrap();
    forward(&s.node, &unpinned, &get("/"), &mut transport).unwrap();
}

#[test]
fn a_fresh_node_refuses_an_old_record_the_grant_pinned_past() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy.clone(), &[("token", TOKEN)]);
    let newer = s
        .record
        .rewrap(
            &user_key(),
            s.device.sign_policy(with_caller(policy)).unwrap(),
        )
        .unwrap();
    // The operator starts a node that never saw the newer record; the grant pins it.
    let fresh = Node::new(NodeKey::generate(), MemorySink::new(), &clock);
    grant_on(
        &fresh,
        &s.device,
        [7u8; 32],
        NOW + DAY,
        &[("rec-1", newer.generation)],
    )
    .unwrap();
    let mut transport = FakeTransport::default();
    assert_eq!(
        forward(&fresh, &s.record, &get("/"), &mut transport).map(|_| ()),
        Err(Error::RecordStale { have: 1, need: 2 })
    );
    forward(&fresh, &newer, &get("/"), &mut transport).unwrap();
}

#[test]
fn the_log_store_cannot_read_where_a_value_went() {
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("Authorization", "Bearer {{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let mut transport = FakeTransport::default();
    forward(
        &s.node,
        &s.record,
        &post("/v1/patients/8812?full=1", br#"{"q":1}"#),
        &mut transport,
    )
    .unwrap();
    let entries = log_of(&s.node);
    let json = serde_json::to_string(&entries).unwrap();
    assert!(!json.contains("patients"), "{json}");
    assert!(!json.contains("api.example.com"), "{json}");
    let used = entries
        .iter()
        .find(|e| matches!(e.entry.event, Event::Use { .. }))
        .unwrap();
    match engine::log::open_detail(&user_key(), &used.entry).unwrap() {
        Some(Detail::Use {
            path,
            host,
            body_len,
            ..
        }) => {
            assert_eq!(path, "/v1/patients/8812?full=1");
            assert_eq!(host, "api.example.com");
            assert_eq!(body_len, 7);
        }
        other => panic!("unexpected detail {other:?}"),
    }
    assert_eq!(
        engine::log::open_detail(&UserKey::from_bytes(&mut [9u8; 32]), &used.entry),
        Err(Error::RecordOpen)
    );
}

#[test]
fn guessable_fields_give_back_no_check_for_guesses() {
    let device = DeviceKey::generate();
    let sign = |template: &str| {
        let policy = Policy {
            item: None,
            fields: vec![FieldSpec::guessable("pin"), secret("key")],
            callers: vec![],
            operations: vec![derive_op("derive", template)],
        };
        device.sign_policy(with_caller(policy)).map(|_| ())
    };
    for refused in [
        "{{ hex(sha256(pin)) }}",
        r#"{{ hex(pbkdf2_sha256(pin, "salt", "100000", "32")) }}"#,
        "{{ hex(hmac_sha256(pin, $input)) }}",
        "{{ ed25519_sign(key, pin) }}",
        "{{ hex(hmac_sha256(sha256(pin), $input)) }}",
        // A keyed MAC does not hide it either: another operation could compute the same MAC on
        // chosen input, which checks a guess.
        "{{ hex(hmac_sha256(key, pin)) }}",
    ] {
        assert!(
            matches!(sign(refused), Err(Error::PolicyInvalid { .. })),
            "{refused}"
        );
    }
    for allowed in ["{{ len(pin) }}", "{{ hex(hmac_sha256(key, $input)) }}"] {
        sign(allowed).unwrap_or_else(|e| panic!("{allowed}: {e}"));
    }
    let public = Policy {
        item: None,
        fields: vec![FieldSpec {
            guessable: true,
            ..public("user")
        }],
        callers: vec![],
        operations: vec![derive_op("derive", "{{ len(user) }}")],
    };
    assert!(matches!(
        device.sign_policy(with_caller(public)),
        Err(Error::PolicyInvalid { .. })
    ));
}

// ---- regressions: the second review ----

fn signed_record(policy: Policy, values: &[(&str, &[u8])]) -> (DeviceKey, Record) {
    let device = DeviceKey::generate();
    let signed = device.sign_policy(with_caller(policy)).unwrap();
    let record = Record::seal(&user_key(), "rec-1", OWNER, signed, &fields(values)).unwrap();
    (device, record)
}

fn hmac_record() -> (DeviceKey, Record) {
    signed_record(
        derive_policy(vec![secret("key")], "{{ hex(hmac_sha256(key, $input)) }}"),
        &[("key", b"0123456789abcdef")],
    )
}

fn sink_of(entries: &[SignedEntry]) -> MemorySink {
    let mut sink = MemorySink::new();
    for entry in entries {
        sink.append(entry).unwrap();
    }
    sink
}

#[test]
fn a_derivation_cannot_hand_back_a_key_and_what_it_encrypts() {
    let device = DeviceKey::generate();
    for template in [
        // The key and a ciphertext under it.
        r#"{{ hex(sha256(key)) }}.{{ hex(aes_gcm_encrypt(sha256(key), "000000000000", msg)) }}"#,
        // A nonce that only looks fresh: a constant.
        r#"{{ aes_gcm_encrypt(key, "0000000000" + len($nonce), $input + msg) }}"#,
        // A fresh nonce: another operation could still encrypt chosen bytes under it.
        r#"{{ aes_gcm_encrypt(key, hexdecode(replace($nonce, "00000000", "")), msg) }}"#,
    ] {
        let policy = derive_policy(vec![secret("key"), secret("msg")], template);
        assert!(
            matches!(
                device.sign_policy(with_caller(policy)),
                Err(Error::PolicyInvalid { .. })
            ),
            "{template}"
        );
    }
}

#[test]
fn a_saved_grant_does_not_open_a_restarted_node() {
    let clock = TestClock::at(NOW);
    let (device, record) = hmac_record();
    let node_key = [9u8; 32];
    let node = Node::new(
        NodeKey::from_bytes(&mut node_key.clone()),
        MemorySink::new(),
        &clock,
    );
    let terms = GrantTerms {
        owner: OWNER.into(),
        expires_ms: NOW + DAY,
        issued_ms: issued(),
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
    };
    let sealed = device.grant(&user_key(), &node.identity(), terms).unwrap();
    node.grant(&sealed).unwrap();
    let auth = authorize(&node, &record, "derive", &Payload::Derive(b"x"));
    clock.set(NOW + 1000);
    node.revoke(&device.revoke(OWNER, &node.public_key(), issued()).unwrap())
        .unwrap();
    let full = log_of(&node);
    drop(node);

    // The operator restarts with the log cut before the grant, or with all of it.
    clock.set(NOW + 2000);
    for cut in [0, full.len()] {
        let node = Node::restore(
            NodeKey::from_bytes(&mut node_key.clone()),
            sink_of(&full[..cut]),
            &clock,
            &full[..cut],
        )
        .unwrap();
        assert!(
            matches!(node.grant(&sealed), Err(Error::GrantInvalid { .. })),
            "cut {cut}"
        );
        // A call authorized before the restart is refused too: its nonce is forgotten.
        clock.set(now() + 2);
        grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
        assert!(matches!(
            node.derive(&record, "derive", &auth, b"x"),
            Err(Error::CallerInvalid { .. })
        ));
    }
}

#[test]
fn an_anchored_restore_refuses_a_cut_log() {
    let clock = TestClock::at(NOW);
    let (device, record) = hmac_record();
    let node_key = [9u8; 32];
    let key = || NodeKey::from_bytes(&mut node_key.clone());
    let node = Node::new(key(), MemorySink::new(), &clock);
    grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
    call_derive(&node, &record, "derive", b"x").unwrap();
    let anchor = node.checkpoint().unwrap();
    let full = log_of(&node);
    let restore = |entries: &[SignedEntry], anchor| {
        Node::restore_anchored(key(), sink_of(entries), &clock, entries, anchor).map(|_| ())
    };
    restore(&full, &anchor).unwrap();
    let len = full.len() as u64;
    assert_eq!(
        restore(&full[..full.len() - 1], &anchor),
        Err(Error::LogBehindAnchor {
            len: len - 1,
            anchor: len
        })
    );
    assert_eq!(
        restore(&[], &anchor),
        Err(Error::LogBehindAnchor {
            len: 0,
            anchor: len
        })
    );
    // A checkpoint of another node is no anchor.
    let other = Node::new(NodeKey::generate(), MemorySink::new(), &clock)
        .checkpoint()
        .unwrap();
    assert!(restore(&full, &other).is_err());
}

#[test]
fn a_retired_device_signs_nothing_more() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        request_policy(
            vec![secret("token")],
            vec![header("X-Api-Key", "{{token}}")],
        ),
        &[("token", TOKEN)],
    );
    let node = s.node.public_key();
    let tablet = DeviceKey::generate();
    s.node
        .add_device(
            &s.device
                .endorse(OWNER, &node, &tablet.public(), issued())
                .unwrap(),
        )
        .unwrap();
    // An endorsement for another node, or an old one, is refused.
    let elsewhere = s
        .device
        .endorse(
            OWNER,
            &NodeKey::generate().public(),
            &tablet.public(),
            issued(),
        )
        .unwrap();
    assert!(matches!(
        s.node.add_device(&elsewhere),
        Err(Error::GrantInvalid { .. })
    ));
    let old = s
        .device
        .endorse(OWNER, &node, &DeviceKey::generate().public(), NOW - 1)
        .unwrap();
    assert!(matches!(
        s.node.add_device(&old),
        Err(Error::GrantInvalid { .. })
    ));

    // A device cannot retire itself; another device can.
    assert_eq!(
        s.node.retire_device(
            &tablet
                .retire(OWNER, &node, &tablet.public(), issued())
                .unwrap()
        ),
        Err(Error::PolicySignature)
    );
    s.node
        .retire_device(
            &s.device
                .retire(OWNER, &node, &tablet.public(), issued())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        grant_on(&s.node, &tablet, [7u8; 32], NOW + DAY, &[]),
        Err(Error::GrantDenied)
    );
    assert!(matches!(
        last_event(&s.node, |e| matches!(e, Event::Retire { .. })),
        Event::Retire { device, .. } if device == tablet.public()
    ));
}

#[test]
fn one_caller_cannot_fill_the_replay_cache() {
    let clock = TestClock::at(NOW);
    let (device, record) = hmac_record();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), &clock);
    grant_on(&node, &device, [7u8; 32], NOW + DAY, &[("rec-1", 1)]).unwrap();
    // Dated far ahead, an authorization would stay in the cache longer: refused.
    let ahead = caller_key()
        .authorize(
            "app",
            &node.public_key(),
            &record,
            "derive",
            &Payload::Derive(b"x"),
            NOW + engine::node::MAX_FUTURE_MS + 1,
        )
        .unwrap();
    assert!(matches!(
        node.derive(&record, "derive", &ahead, b"x"),
        Err(Error::CallerInvalid { .. })
    ));
    let mut refused = None;
    for i in 0..=engine::node::MAX_NONCES_PER_CALLER {
        if let Err(e) = call_derive(&node, &record, "derive", b"x") {
            refused = Some((i, e));
            break;
        }
    }
    assert_eq!(
        refused,
        Some((engine::node::MAX_NONCES_PER_CALLER, Error::RateLimited))
    );
    // Once the window has passed, the caller may call again.
    clock.set(NOW + 5 * 60 * 1000 + 1);
    call_derive(&node, &record, "derive", b"x").unwrap();
}

#[test]
fn a_user_key_round_trips_through_base64() {
    let key = UserKey::generate();
    let text = key.to_b64();
    assert_eq!(text.len(), 43);
    let back = UserKey::from_b64(&text).unwrap();
    assert_eq!(*back.to_bytes(), *key.to_bytes());
    let longer = format!("{}AAAA", text.as_str());
    for bad in ["", "AAAA", longer.as_str(), "!!!"] {
        assert!(UserKey::from_b64(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_signed_call_travels_as_json_and_runs() {
    use engine::call::{Body, Output, SignedCall};
    let clock = TestClock::at(NOW);
    let policy = request_policy(
        vec![secret("token")],
        vec![header("X-Api-Key", "{{token}}")],
    );
    let s = setup(&clock, policy, &[("token", TOKEN)]);
    let call = caller_key()
        .sign_call_at(
            "app",
            &s.node.public_key(),
            s.record.clone(),
            "call",
            Body::http(get("/")),
            NOW,
        )
        .unwrap();
    // Over the wire and back.
    let json = serde_json::to_string(&call).unwrap();
    let call: SignedCall = serde_json::from_str(&json).unwrap();
    let mut transport = FakeTransport::default();
    transport.replies.push_back(reply("200 OK", "hello"));
    let outcome = s.node.run(&call, &mut transport);
    assert!(outcome.record.is_none());
    let Ok(Output::Http(response)) = outcome.result else {
        panic!("{:?}", outcome.result);
    };
    assert_eq!(response.body(), b"hello");
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains(std::str::from_utf8(TOKEN).unwrap()));

    // A changed request no longer matches the signature.
    let mut changed = call.clone();
    changed.body = Body::http(get("/other"));
    assert!(matches!(
        s.node.run(&changed, &mut transport).result,
        Err(Error::CallerInvalid { .. })
    ));
}

#[test]
fn grant_terms_take_a_duration_and_pin_records() {
    let clock = TestClock::at(NOW);
    let (device, record) = hmac_record();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), &clock);
    let terms = GrantTerms::at(OWNER, issued(), std::time::Duration::from_secs(600)).pin(&record);
    assert_eq!(terms.expires_ms, terms.issued_ms + 600_000);
    node.grant(&device.grant(&user_key(), &node.identity(), terms).unwrap())
        .unwrap();
    call_derive(&node, &record, "derive", b"x").unwrap();
}

fn derives(fields: Vec<FieldSpec>, ops: &[(&str, &str)]) -> Policy {
    with_caller(Policy {
        item: None,
        fields,
        callers: vec![],
        operations: ops
            .iter()
            .map(|(name, template)| derive_op(name, template))
            .collect(),
    })
}

#[test]
fn a_hash_of_a_secret_alone_is_not_handed_back() {
    // An HMAC key longer than its block is hashed first: its SHA-256 is the key.
    let refused = derives(
        vec![secret("k")],
        &[
            ("fp", "{{ hex(sha256(k)) }}"),
            ("mac", "{{ hex(hmac_sha256(k, $input)) }}"),
        ],
    );
    assert!(matches!(
        refused.validate(),
        Err(Error::PolicyInvalid { .. })
    ));
    for template in ["{{ hex(sha512(trim(k))) }}", "{{ hex(md5(b64decode(k))) }}"] {
        assert!(
            derives(vec![secret("k")], &[("fp", template)])
                .validate()
                .is_err(),
            "{template}"
        );
    }
    // A hash that covers chosen bytes too hides the secret.
    derives(vec![secret("k")], &[("h", "{{ hex(sha256(k + $input)) }}")])
        .validate()
        .unwrap();
}

#[test]
fn a_chosen_time_format_cannot_pick_digits_of_a_secret() {
    let policy = derives(
        vec![secret("acct")],
        &[("t", "{{ hex(sha256(time(acct, $input))) }}")],
    );
    assert!(matches!(
        policy.validate(),
        Err(Error::PolicyInvalid { .. })
    ));
}

#[test]
fn a_retired_device_cannot_return_under_a_fresh_key() {
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        request_policy(
            vec![secret("token")],
            vec![header("X-Api-Key", "{{token}}")],
        ),
        &[("token", TOKEN)],
    );
    let node = s.node.public_key();
    let tablet = DeviceKey::generate();
    s.node
        .add_device(
            &s.device
                .endorse(OWNER, &node, &tablet.public(), issued())
                .unwrap(),
        )
        .unwrap();
    s.node
        .retire_device(
            &s.device
                .retire(OWNER, &node, &tablet.public(), issued())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        grant_on(&s.node, &tablet, [7u8; 32], NOW + DAY, &[]),
        Err(Error::GrantDenied)
    );
    // Whoever holds the tablet's user key makes a fresh device key: still no way in.
    let fresh = DeviceKey::generate();
    assert_eq!(
        grant_on(&s.node, &fresh, [7u8; 32], NOW + DAY, &[("rec-1", 1)]),
        Err(Error::GrantDenied)
    );
    assert!(
        s.node
            .retire_device(
                &fresh
                    .retire(OWNER, &node, &s.device.public(), issued())
                    .unwrap()
            )
            .is_err()
    );
}

#[test]
fn a_clock_stepped_back_after_a_restart_opens_nothing_old() {
    let clock = TestClock::at(NOW);
    let (device, record) = hmac_record();
    let node = Node::new(
        NodeKey::from_bytes(&mut [9u8; 32]),
        MemorySink::new(),
        &clock,
    );
    let terms = GrantTerms {
        owner: OWNER.into(),
        expires_ms: NOW + DAY,
        issued_ms: NOW,
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
    };
    let saved = device.grant(&user_key(), &node.identity(), terms).unwrap();
    node.grant(&saved).unwrap();
    let auth = authorize(&node, &record, "derive", &Payload::Derive(b"x"));
    node.derive(&record, "derive", &auth, b"x").unwrap();
    clock.set(NOW + 1000);
    node.revoke(
        &device
            .revoke(OWNER, &node.public_key(), NOW + 1000)
            .unwrap(),
    )
    .unwrap();
    // The operator restarts with an empty log, then steps the clock back.
    clock.set(NOW + 2000);
    let node = Node::restore(
        NodeKey::from_bytes(&mut [9u8; 32]),
        MemorySink::new(),
        &clock,
        &[],
    )
    .unwrap();
    clock.set(NOW);
    assert!(matches!(
        node.grant(&saved),
        Err(Error::GrantInvalid { .. })
    ));
    assert!(node.derive(&record, "derive", &auth, b"x").is_err());
}

fn fixed(method: Method, path: &str, inject: Vec<Injection>, capture: Vec<Capture>) -> Step {
    Step {
        request: StepRequest::Fixed {
            method,
            path: path.into(),
            destination: None,
        },
        inject,
        capture,
    }
}

fn unhex(text: &[u8]) -> Vec<u8> {
    text.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A password envelope built from generic primitives: the server hands out a session key and
/// a P-256 public key; the node makes an ephemeral key pair, derives an AES-256 key as
/// SHA-256 of the hex of the shared secret, encrypts length-prefixed fields under a fresh IV,
/// and sends `b64(ciphertext),b64(iv),hex(ephemeral public key),session`. The test plays the
/// server and decrypts.
#[test]
fn ephemeral_ecdh_password_envelope() {
    use base64::Engine as _;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
    use sha2::Digest as _;

    let clock = TestClock::at(NOW);
    let server = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let server_public = {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        lower_hex(
            server
                .public_key()
                .as_affine()
                .to_sec1_point(false)
                .as_bytes(),
        )
    };
    let keys = fixed(
        Method::Get,
        "/keys/current",
        vec![],
        vec![
            capture(Source::All, temp("keys", false)),
            capture(
                Source::Regex {
                    pattern: "^([^,]+),".into(),
                    group: None,
                },
                temp("session", false),
            ),
        ],
    );
    let envelope = concat!(
        "{{ b64(aes_cbc_encrypt(",
        "sha256(hex(ecdh(\"p256\", hexdecode(between(keys, \",\", \"\"))))), ",
        "hexdecode($nonce), ",
        "u8(len(session)) + session + u8(len(user)) + user + u8(len(password)) + password",
        ")) + \",\" + b64(hexdecode($nonce)) + \",\" + hex(ecdh_public(\"p256\")) + \",\" + session }}",
    );
    let login = fixed(
        Method::Post,
        "/login",
        vec![
            header("Content-Type", "text/plain"),
            inject(Target::Body, envelope),
        ],
        vec![],
    );
    let policy = Policy {
        item: None,
        fields: vec![public("user"), FieldSpec::guessable("password")],
        callers: vec![],
        operations: vec![http("login", host(), vec![keys, login])],
    };
    let password = b"hunter2-correct-horse";
    let s = setup(&clock, policy, &[("user", b"kim"), ("password", password)]);
    let mut transport = FakeTransport::default();
    let session = "sk_5f2a9c";
    transport
        .replies
        .push_back(reply("200 OK", &format!("{session},{server_public}")));
    transport
        .replies
        .push_back(reply("200 OK", r#"{"ok":true}"#));
    let outcome = call_http(&s.node, &s.record, "login", None, &mut transport);
    assert_eq!(outcome.result.unwrap().body(), br#"{"ok":true}"#);

    let body = body_of(&transport.sent[1]).to_vec();
    let parts: Vec<&[u8]> = body.split(|b| *b == b',').collect();
    assert_eq!(parts.len(), 4);
    let b64 = base64::engine::general_purpose::STANDARD;
    let ciphertext = b64.decode(parts[0]).unwrap();
    let iv = b64.decode(parts[1]).unwrap();
    assert_eq!(iv.len(), 16);
    assert_eq!(parts[2].len(), 130, "uncompressed P-256 point in hex");
    assert_eq!(parts[3], session.as_bytes());
    let ephemeral = p256::PublicKey::from_sec1_bytes(&unhex(parts[2])).unwrap();
    let shared = server.diffie_hellman(&ephemeral);
    let key = sha2::Sha256::digest(lower_hex(shared.raw_secret_bytes()).as_bytes());
    let plain = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(&ciphertext)
        .unwrap();
    let mut expected = vec![u8::try_from(session.len()).unwrap()];
    expected.extend_from_slice(session.as_bytes());
    expected.extend_from_slice(&[3]);
    expected.extend_from_slice(b"kim");
    expected.push(u8::try_from(password.len()).unwrap());
    expected.extend_from_slice(password);
    assert_eq!(plain, expected);
    // The password itself never went out.
    assert!(
        !transport
            .sent
            .iter()
            .any(|w| w.windows(password.len()).any(|x| x == password))
    );
    // A second login uses a new ephemeral key.
    transport
        .replies
        .push_back(reply("200 OK", &format!("{session},{server_public}")));
    transport.replies.push_back(reply("200 OK", "{}"));
    call_http(&s.node, &s.record, "login", None, &mut transport)
        .result
        .unwrap();
    let again = body_of(&transport.sent[3]).to_vec();
    let again: Vec<&[u8]> = again.split(|b| *b == b',').collect();
    assert_ne!(again[2], parts[2]);
}

/// A JWT whose `iat` and `exp` the node sets itself (`$unix`, `add`, `json_set_number`),
/// signed with RS512: the caller passes only the audience, so the policy bounds the lifetime.
#[test]
fn jwt_claims_get_their_times_from_the_node() {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ring::signature::{
        KeyPair as _, RSA_PKCS1_2048_8192_SHA512, RsaKeyPair, UnparsedPublicKey,
    };

    let pem = include_str!("fixtures/rsa2048.pem");
    let der: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(der).unwrap();
    let verifying = RsaKeyPair::from_pkcs8(&der)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let claims = concat!(
        "json_set_number(json_set_number(json_set(json_set(\"{}\", \"iss\", client_id), ",
        "\"aud\", $input), \"iat\", $unix), \"exp\", add($unix, \"300\"))",
    );
    let head = format!(r#"b64urlraw("{{\"alg\":\"RS512\"}}") + "." + b64urlraw({claims})"#);
    let jwt = format!(
        "{{{{ {head} + \".\" + b64urlraw(rsa_sign_pkcs1(\"sha512\", pem(key), {head})) }}}}"
    );
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        derive_policy(vec![secret("key"), public("client_id")], &jwt),
        &[("key", pem.as_bytes()), ("client_id", b"svc-1")],
    );
    let token = call_derive(&s.node, &s.record, "derive", b"https://auth.example.com").unwrap();
    let token = String::from_utf8(token).unwrap();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let payload = URL_SAFE_NO_PAD
        .decode(signed.split('.').nth(1).unwrap())
        .unwrap();
    let iat = NOW / 1000;
    assert_eq!(
        String::from_utf8(payload).unwrap(),
        format!(
            r#"{{"iss":"svc-1","aud":"https://auth.example.com","iat":{iat},"exp":{}}}"#,
            iat + 300
        )
    );
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, &verifying)
        .verify(
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(signature).unwrap(),
        )
        .unwrap();
}

/// A CSRF token read from an HTML form (`html` capture) and a value cut from a captured
/// text (`slice`) feed the next request.
#[test]
fn html_and_regex_captures_feed_later_steps() {
    let clock = TestClock::at(NOW);
    let page = fixed(
        Method::Get,
        "/login",
        vec![],
        vec![
            capture(
                Source::Html {
                    selector: "input[name=_csrf]".into(),
                    attribute: Some("value".into()),
                },
                temp("csrf", false),
            ),
            capture(
                Source::Regex {
                    pattern: r"build-([0-9a-f]{12})".into(),
                    group: None,
                },
                temp("build", false),
            ),
        ],
    );
    let login = fixed(
        Method::Post,
        "/login",
        vec![
            header("X-Build", "{{ slice(build, \"0\", \"6\") }}"),
            inject(
                Target::Body,
                "_csrf={{pct(csrf)}}&user={{pct(user)}}&password={{pct(password)}}",
            ),
        ],
        vec![],
    );
    let policy = Policy {
        item: None,
        fields: vec![public("user"), secret("password")],
        callers: vec![],
        operations: vec![http("login", host(), vec![page, login])],
    };
    let s = setup(&clock, policy, &[("user", b"kim"), ("password", TOKEN)]);
    let mut transport = FakeTransport::default();
    transport.replies.push_back(reply(
        "200 OK",
        r#"<html><!-- build-0123456789ab --><form><input type="hidden" name="_csrf" value="a+b&amp;c"></form></html>"#,
    ));
    transport.replies.push_back(reply("200 OK", "ok"));
    call_http(&s.node, &s.record, "login", None, &mut transport)
        .result
        .unwrap();
    let sent = text(&transport.sent[1]);
    assert!(sent.contains("X-Build: 012345\r\n"), "{sent}");
    assert!(sent.ends_with(&format!(
        "_csrf=a%2Bb%26c&user=kim&password={}",
        text(TOKEN)
    )));
}

/// Every new function, used to hand a secret back from a derivation or to let the caller
/// steer which part of it comes out, is refused when the policy is signed.
#[test]
fn new_functions_cannot_exfiltrate_a_secret() {
    let device = DeviceKey::generate();
    let fields = || vec![secret("key"), public("pub")];
    let refused = [
        // Cutting: the output is the secret, or the caller picks the part.
        r#"{{ slice(key, "0", "4") }}"#,
        r#"{{ slice(key, $input, "1") }}"#,
        r#"{{ hex(slice(key, len($input), "1")) }}"#,
        r#"{{ between(key, "", "-") }}"#,
        r#"{{ between(key, $input, "") }}"#,
        r#"{{ between($input, key, "") }}"#,
        // Arithmetic and fixed-width encodings keep the secret readable.
        r#"{{ add(key, "0") }}"#,
        r#"{{ add(key, $input) }}"#,
        r#"{{ u8(key) }}"#,
        r#"{{ be64(key) }}"#,
        r#"{{ le16(key) }}"#,
        r#"{{ json_set_number("{}", "n", key) }}"#,
        r#"{{ json_set_number("{}", $input, key) }}"#,
        // A hash of the secret alone is as good as the secret.
        r#"{{ hex(sha384(key)) }}"#,
        r#"{{ hex(sha512_256(key)) }}"#,
        r#"{{ hex(md4(key)) }}"#,
        // Algorithm names are fixed by the policy.
        r#"{{ hex(pbkdf2($input, key, "salt", "1")) }}"#,
        r#"{{ b64(rsa_sign_pkcs1($input, key, "m")) }}"#,
        r#"{{ b64(rsa_sign_pss($input, key, "m")) }}"#,
        r#"{{ hex(ecdh_public($input)) }}"#,
        r#"{{ pbkdf2("sha256", "p", "s", key + $input) }}"#,
        // Public-key encryption: the key may not come from the caller, and a secret in the
        // message stays tainted.
        r#"{{ b64(rsa_encrypt_pkcs1($input, "x")) }}"#,
        r#"{{ b64(rsa_encrypt_oaep("sha256", $input, "x")) }}"#,
        r#"{{ b64(rsa_encrypt_oaep("sha256", pub, key)) }}"#,
        r#"{{ b64(rsa_encrypt_pkcs1(pub, key)) }}"#,
        // A shared secret is a secret, and so is a plain hash of it.
        r#"{{ hex(ecdh("p256", $input)) }}"#,
        r#"{{ hex(sha256(hex(ecdh("x25519", $input)))) }}"#,
        r#"{{ hex(ecdh("p256", pub, key)) }}"#,
        r#"{{ hex(ecdh("p256", key + $input)) }}"#,
        // Symmetric encryption under a known key.
        r#"{{ chacha20_poly1305_encrypt("0123456789abcdef0123456789abcdef", "000000000000", key) }}"#,
        r#"{{ aes_gcm_encrypt("0123456789abcdef01234567", "000000000000", key) }}"#,
        // A random length steered by the secret and the caller.
        r#"{{ random(key + $input) }}"#,
    ];
    for template in refused {
        let policy = with_caller(derive_policy(fields(), template));
        assert!(
            matches!(device.sign_policy(policy), Err(Error::PolicyInvalid { at, .. }) if at.starts_with("operations[0].steps[0].template")),
            "{template}"
        );
    }
    let allowed = [
        r#"{{ hex(ecdh_public("p256")) }}"#,
        r#"{{ hex(random("16")) }}"#,
        r#"{{ add($unix, "300") }}"#,
        r#"{{ hex(u8(len(key))) + hex(be64($unix)) }}"#,
        r#"{{ hex(hmac_sha384(key, $input)) + hex(hmac_md5(key, $input)) }}"#,
        r#"{{ hex(pbkdf2("sha512", key, $input, "1000")) }}"#,
        r#"{{ hex(sha384(key + $input)) }}"#,
        r#"{{ slice($input, "0", "4") + between($input, "a", "") }}"#,
        r#"{{ json_set_number("{}", "n", add($unix, $input)) }}"#,
        r#"{{ b64(rsa_encrypt_oaep("sha256", pub, $input)) }}"#,
    ];
    for template in allowed {
        let policy = with_caller(derive_policy(fields(), template));
        let signed = device.sign_policy(policy);
        assert!(signed.is_ok(), "{template} {:?}", signed.err());
    }
}

/// The new captures and functions in a request: a secret temp captured by `html` or `regex`
/// is redacted in the response, and a tainted header value cut by `slice` is searched for.
#[test]
fn new_captures_are_redacted_and_cut_secrets_are_searched() {
    let clock = TestClock::at(NOW);
    let page = fixed(
        Method::Get,
        "/session",
        vec![],
        vec![
            capture(
                Source::Html {
                    selector: "meta[name=token]".into(),
                    attribute: Some("content".into()),
                },
                temp("token", true),
            ),
            capture(
                Source::Regex {
                    pattern: "sid=([a-z0-9]+)".into(),
                    group: Some(1),
                },
                temp("sid", true),
            ),
        ],
    );
    let use_it = fixed(
        Method::Get,
        "/me",
        vec![
            header("Authorization", "Bearer {{token}}"),
            header("X-Key-Part", "{{ slice(key, \"0\", \"12\") }}"),
            header("X-Sid", "{{sid}}"),
        ],
        vec![],
    );
    let policy = Policy {
        item: None,
        fields: vec![secret("key")],
        callers: vec![],
        operations: vec![http("op", host(), vec![page, use_it])],
    };
    let key = b"key_0123456789abcdef";
    let s = setup(&clock, policy, &[("key", key)]);
    let session = r#"<meta name="token" content="tok_abcdefgh12345678"> sid=s0s1s2s3s4"#;
    // The response echoes both captured secrets: they are redacted.
    let mut transport = FakeTransport::default();
    transport.replies.push_back(reply("200 OK", session));
    transport.replies.push_back(reply(
        "200 OK",
        r#"{"t":"tok_abcdefgh12345678","s":"s0s1s2s3s4"}"#,
    ));
    let response = call_http(&s.node, &s.record, "op", None, &mut transport)
        .result
        .unwrap();
    assert_eq!(
        text(response.body()),
        r#"{"t":"[redacted]","s":"[redacted]"}"#
    );
    // The response echoes the part of the key the policy cut: dropped.
    let mut transport = FakeTransport::default();
    transport.replies.push_back(reply("200 OK", session));
    transport
        .replies
        .push_back(reply("200 OK", r#"{"echo":"key_01234567"}"#));
    assert_eq!(
        call_http(&s.node, &s.record, "op", None, &mut transport)
            .result
            .map(|_| ()),
        Err(Error::Reflection)
    );
}

/// Every function of the second group of families (KDFs, key wrapping, AES modes and MACs,
/// Ed448, prehashed ECDSA, DSA, X448, SHA-3 and SHAKE, CBOR, Kerberos n-fold and DK), used
/// to hand a secret back from a derivation or to let the caller steer how it comes out, is
/// refused when the policy is signed; the same functions used as intended are accepted.
#[test]
fn families_cannot_exfiltrate_a_secret() {
    let device = DeviceKey::generate();
    let fields = || vec![secret("key"), public("pub")];
    let refused = [
        // A key derived from a secret is a secret, and so is a plain hash of it.
        r#"{{ hex(hkdf("sha256", key, "", "", "32")) }}"#,
        r#"{{ hex(hkdf("sha256", key, $input, "info", "32")) }}"#,
        r#"{{ hex(sha256(hkdf("sha256", key, $input, "", "32"))) }}"#,
        r#"{{ hex(hkdf_expand("sha384", key, "info", "48")) }}"#,
        r#"{{ hex(concat_kdf("sha256", ecdh("p256", pub), $input, "16")) }}"#,
        r#"{{ hex(kbkdf_counter("sha512", key, $input, "64")) }}"#,
        r#"{{ hex(kerberos_dk(key, "kerberos")) }}"#,
        // Hash names are fixed by the policy, and no length depends on a secret.
        r#"{{ hex(hkdf($input, key, "", "", "32")) }}"#,
        r#"{{ hex(concat_kdf($input, key, "", "16")) }}"#,
        r#"{{ hex(kbkdf_counter($input, key, "", "16")) }}"#,
        r#"{{ hex(hkdf_expand($input, key, "", "32")) }}"#,
        r#"{{ len(hkdf("sha256", $input, "", "", key)) }}"#,
        r#"{{ len(shake256($input, key)) }}"#,
        r#"{{ len(nfold($input, key)) }}"#,
        r#"{{ len(aes_ccm_encrypt("0123456789abcdef", "0123456", key, $input)) }}"#,
        // A plain hash of the secret alone.
        r#"{{ hex(sha3_224(key)) }}"#,
        r#"{{ hex(sha3_256(key)) }}"#,
        r#"{{ hex(sha3_384(key)) }}"#,
        r#"{{ hex(sha3_512(key)) }}"#,
        r#"{{ hex(shake128(key, "32")) }}"#,
        r#"{{ hex(shake256(key, "64")) }}"#,
        // A block-cipher MAC under a known key can be decrypted; a chosen key is an oracle.
        r#"{{ hex(aes_cmac("0123456789abcdef", key)) }}"#,
        r#"{{ hex(aes_cbc_mac(pub, key)) }}"#,
        r#"{{ hex(aes_cmac(key + $input, "m")) }}"#,
        r#"{{ hex(aes_cbc_mac(key + $input, "m")) }}"#,
        // Encryption and wrapping under a known key, or of a secret under any key.
        r#"{{ b64(aes_kw_wrap("0123456789abcdef", key)) }}"#,
        r#"{{ b64(aes_kwp_wrap(pub, key)) }}"#,
        r#"{{ b64(aes_kw_wrap(key, key)) }}"#,
        r#"{{ b64(aes_cbc_hmac_encrypt("0123456789abcdef0123456789abcdef", "0123456789abcdef", key)) }}"#,
        r#"{{ b64(aes_ccm_encrypt("0123456789abcdef", "0123456", "8", key)) }}"#,
        r#"{{ b64(aes_eax_encrypt(pub, $input, key)) }}"#,
        r#"{{ b64(aes_cts_encrypt("0123456789abcdef", "0123456789abcdef", key)) }}"#,
        r#"{{ b64(aes_ccm_encrypt(key, "0123456", "8", "m", key)) }}"#,
        r#"{{ b64(aes_eax_encrypt(key, key + $input, "m")) }}"#,
        r#"{{ b64(aes_kw_wrap(key + $input, "0123456789abcdef")) }}"#,
        // n-fold keeps the secret readable; DK under a chosen key is an oracle.
        r#"{{ hex(nfold(key, "128")) }}"#,
        r#"{{ hex(kerberos_dk(key + $input, "kerberos")) }}"#,
        // Signatures: the algorithm is fixed, the key is not mixed with chosen bytes.
        r#"{{ hex(ecdsa_sign_prehash($input, key, "0123456789abcdef0123456789abcdef")) }}"#,
        r#"{{ hex(dsa_sign($input, key, "m")) }}"#,
        r#"{{ hex(dsa_sign_der(pub + $input, key, "m")) }}"#,
        r#"{{ hex(ed448_sign(key + $input, "m")) }}"#,
        r#"{{ hex(ecdsa_sign_prehash("p256", key + $input, "0123456789abcdef")) }}"#,
        r#"{{ hex(dsa_sign("sha256", key + $input, "m")) }}"#,
        // X448 shared secrets are secrets.
        r#"{{ hex(ecdh("x448", $input)) }}"#,
        r#"{{ hex(sha3_256(hex(ecdh("x448", pub)))) }}"#,
        // CBOR keeps the secret readable, and its checks and key order are oracles.
        r#"{{ hex(cbor_bytes(key)) }}"#,
        r#"{{ hex(cbor_array(cbor_text("a"), cbor_bytes(key))) }}"#,
        r#"{{ len(cbor_array(key + $input)) }}"#,
        r#"{{ len(cbor_int(key + $input)) }}"#,
        r#"{{ len(cbor_text(key + $input)) }}"#,
        r#"{{ len(cbor_tag(key + $input, "\0")) }}"#,
        r#"{{ len(cbor_map(cbor_bytes(key), cbor_int("1"), cbor_bytes($input), cbor_int("2"))) }}"#,
    ];
    for template in refused {
        // Refused by the analysis, not by the parser.
        assert!(
            engine::template::Template::parse(template).is_ok(),
            "{template}"
        );
        let policy = with_caller(derive_policy(fields(), template));
        assert!(
            matches!(device.sign_policy(policy), Err(Error::PolicyInvalid { at, .. }) if at.starts_with("operations[0].steps[0].template")),
            "{template}"
        );
    }
    let allowed = [
        // One-way functions of a derived key, and derivations from nothing secret.
        r#"{{ hex(hmac_sha256(hkdf("sha256", key, $input, "", "32"), $input)) }}"#,
        r#"{{ hex(hkdf("sha256", $input, "", "", "32")) + hex(nfold($input, "128")) }}"#,
        r#"{{ hex(sha3_512(key + $input)) + hex(shake256(key + $input, "64")) }}"#,
        // Under a secret key: MACs, and a fresh content key wrapped.
        r#"{{ hex(aes_cmac(key, $input)) + hex(aes_cbc_mac(key, $input)) }}"#,
        r#"{{ b64(aes_kw_wrap(key, random("16"))) + b64(aes_kwp_wrap(key, random("20"))) }}"#,
        // Under a secret key, with the node's nonce, a chosen message.
        r#"{{ b64(aes_ccm_encrypt(key, slice(hexdecode($nonce), "0", "13"), "16", $input, "aad")) }}"#,
        r#"{{ b64(aes_eax_encrypt(key, hexdecode($nonce), $input)) }}"#,
        r#"{{ b64(aes_cts_encrypt(key, hexdecode($nonce), $input)) }}"#,
        r#"{{ b64(aes_cbc_hmac_encrypt(key, hexdecode($nonce), $input, "aad")) }}"#,
        // Signatures and the public half of a key agreement.
        r#"{{ hex(ed448_sign(key, $input, "ctx")) + hex(ecdsa_sign_prehash("p384", key, sha384($input))) }}"#,
        r#"{{ hex(dsa_sign("sha256", key, $input)) + hex(dsa_sign_der("sha1", key, $input)) }}"#,
        r#"{{ hex(ecdh_public("x448")) }}"#,
        // A COSE_Sign1 (EdDSA) over the caller's payload.
        concat!(
            r#"{{ b64urlraw(cbor_tag("18", cbor_array(cbor_bytes(cbor_map(cbor_int("1"), cbor_int("-8"))), "#,
            r#"cbor_map(), cbor_bytes($input), cbor_bytes(ed448_sign(key, cbor_array(cbor_text("Signature1"), "#,
            r#"cbor_bytes(cbor_map(cbor_int("1"), cbor_int("-8"))), cbor_bytes(""), cbor_bytes($input))))))) }}"#,
        ),
        r#"{{ hex(cbor_map(cbor_text("k"), cbor_bytes($input), cbor_int("1"), cbor_bytes(hex(sha3_256(key + $input))))) }}"#,
    ];
    for template in allowed {
        let policy = with_caller(derive_policy(fields(), template));
        let signed = device.sign_policy(policy);
        assert!(signed.is_ok(), "{template} {:?}", signed.err());
    }
}

/// A `COSE_Sign1` (RFC 9052) with Ed448, built by a derivation over the caller's payload,
/// verifies with the public key: the structure, the `Sig_structure` signed, the signature.
#[test]
fn a_derivation_builds_a_cose_sign1_with_ed448() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed448_goldilocks::signature::Verifier as _;

    // RFC 8032 section 7.4, the blank-message key.
    let secret_key = [
        0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e,
        0xbf, 0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3,
        0x48, 0xa3, 0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc, 0x5b, 0x94,
        0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b,
    ];
    let protected = r#"cbor_map(cbor_int("1"), cbor_int("-8"))"#;
    let template = format!(
        concat!(
            "{{{{ b64urlraw(cbor_tag(\"18\", cbor_array(cbor_bytes({p}), cbor_map(), ",
            "cbor_bytes($input), cbor_bytes(ed448_sign(key, cbor_array(cbor_text(\"Signature1\"), ",
            "cbor_bytes({p}), cbor_bytes(\"\"), cbor_bytes($input))))))) }}}}"
        ),
        p = protected
    );
    let clock = TestClock::at(NOW);
    let s = setup(
        &clock,
        derive_policy(vec![secret("key")], &template),
        &[("key", &secret_key)],
    );
    let payload = b"This is the content.";
    let out = call_derive(&s.node, &s.record, "derive", payload).unwrap();
    let cose = URL_SAFE_NO_PAD.decode(out).unwrap();
    // Tag 18, array of 4: bstr(3) {1: -8}, {}, bstr payload, bstr(114) signature.
    let mut head = vec![0xd2, 0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x54];
    head.extend_from_slice(payload);
    head.extend_from_slice(&[0x58, 0x72]);
    assert_eq!(&cose[..head.len()], head.as_slice());
    let signature = &cose[head.len()..];
    assert_eq!(signature.len(), 114);
    let mut to_be_signed = b"\x84\x6aSignature1\x43\xa1\x01\x27\x40\x54".to_vec();
    to_be_signed.extend_from_slice(payload);
    let key = ed448_goldilocks::SigningKey::try_from(&secret_key[..]).unwrap();
    let signature = ed448_goldilocks::Signature::try_from(signature).unwrap();
    key.verifying_key()
        .verify(&to_be_signed, &signature)
        .unwrap();
}
