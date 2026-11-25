//! Connections that stay open: streamed responses, WebSockets, gRPC and pinned HTTP
//! versions, end to end through a node with scripted servers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::VecDeque;
use std::time::Duration;

use engine::Error;
use engine::call::{Body, Output, SignedCall};
use engine::egress::{Arrived, ClientIdentity, Stream, Transport, Version, Versions};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink};
use engine::node::{
    CallerFrame, Closed, FromCaller, MAX_STREAMS_PER_CALLER, Node, Part, Relay, SystemClock,
};
use engine::policy::{Caller, Destination, FieldSpec, FrameKind, Operation, Policy};
use engine::reflection::forms;
use serde_json::json;

const TOKEN: &[u8] = b"tok/live+9f8e=7d6c\"5b4a";

type TestNode = Node<MemorySink, SystemClock>;

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

struct Setup {
    node: TestNode,
    record: engine::record::Record,
}

fn operation(value: serde_json::Value) -> Operation {
    serde_json::from_value(value).unwrap()
}

fn setup(operations: Vec<Operation>) -> Setup {
    let names = operations.iter().map(|o| o.name().to_string()).collect();
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("token")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: names,
            limit: None,
        }],
        operations,
    };
    policy.validate().unwrap();
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let mut fields = Fields::new();
    fields.insert("token", TOKEN.to_vec()).unwrap();
    let record = engine::record::Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        "user-1",
        device.sign_policy(policy).unwrap(),
        &fields,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms {
        owner: "user-1".into(),
        expires_ms: engine::node::now_ms() + 3_600_000,
        issued_ms: engine::node::now_ms(),
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
        allow_successor: true,
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

fn sign(s: &Setup, operation: &str, body: Body) -> SignedCall {
    caller_key()
        .sign_call(
            "app",
            &s.node.public_key(),
            s.record.clone(),
            operation,
            body,
        )
        .unwrap()
}

/// A server: what it sends in order (each read gets one item); `None` in the queue is a read
/// that finds nothing yet. With `echo`, every message the node writes is answered by the
/// same bytes as a text message.
#[derive(Default)]
struct Server {
    script: VecDeque<Option<Vec<u8>>>,
    /// When the script is done: true ends the connection, false waits forever.
    end: bool,
    echo: bool,
    written: Vec<u8>,
    /// The HTTP version the server agrees to.
    version: Option<Version>,
    exchanges: usize,
}

impl Transport for Server {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.written.extend_from_slice(wire);
        Ok(self.script.drain(..).flatten().flatten().collect())
    }

    fn exchange(
        &mut self,
        destination: &Destination,
        identity: Option<&ClientIdentity>,
        wire: &[u8],
        max: usize,
        versions: Versions,
    ) -> engine::Result<(Vec<u8>, Version)> {
        self.exchanges += 1;
        let version = self.version.unwrap_or(Version::Http1);
        if !versions.allows(version) {
            return Err(Error::transport(TransportKind::Downgrade, false));
        }
        let bytes = self.send(destination, identity, wire, max)?;
        Ok((bytes, version))
    }

    fn exchange_streamed(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        versions: Versions,
    ) -> engine::Result<(Box<dyn Stream + '_>, Version)> {
        let version = self.version.unwrap_or(Version::Http1);
        if !versions.allows(version) {
            return Err(Error::transport(TransportKind::Downgrade, false));
        }
        self.written.extend_from_slice(wire);
        Ok((Box::new(Script(self)), version))
    }
}

struct Script<'a>(&'a mut Server);

/// The payloads of the masked client frames in `bytes`.
fn client_frames(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while bytes.len() >= 6 {
        let opcode = bytes[0] & 0x0f;
        let (len, at) = match bytes[1] & 0x7f {
            126 => (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, 4),
            127 => (
                u64::from_be_bytes(bytes[2..10].try_into().unwrap()) as usize,
                10,
            ),
            n => (n as usize, 2),
        };
        let mask = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        let payload: Vec<u8> = bytes[at + 4..at + 4 + len]
            .iter()
            .zip(mask.iter().cycle())
            .map(|(b, m)| b ^ m)
            .collect();
        out.push((opcode, payload));
        bytes = &bytes[at + 4 + len..];
    }
    out
}

/// A server message (unmasked, `FIN`).
fn message(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

impl Stream for Script<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.0.written.extend_from_slice(bytes);
        if self.0.echo {
            for (opcode, payload) in client_frames(bytes) {
                if opcode == 1 || opcode == 2 {
                    self.0.script.push_back(Some(message(opcode, &payload)));
                }
            }
        }
        Ok(())
    }

    fn read_until(&mut self, delimiters: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        // The scripted handshake answer is one item.
        let _ = delimiters;
        match self.0.script.pop_front() {
            Some(Some(bytes)) => Ok(bytes),
            _ => Err(Error::transport(TransportKind::Closed, false)),
        }
    }

    fn read_some(&mut self, _: usize, wait: Duration) -> engine::Result<Arrived> {
        match self.0.script.pop_front() {
            Some(Some(bytes)) => Ok(Arrived::Bytes(bytes)),
            Some(None) => Ok(Arrived::Nothing),
            None if self.0.end => Ok(Arrived::End),
            None => {
                std::thread::sleep(wait);
                Ok(Arrived::Nothing)
            }
        }
    }
}

/// The caller: what it was handed, and what it sends (one item per wait).
#[derive(Default)]
struct TestCaller {
    parts: Vec<Part>,
    sends: VecDeque<FromCaller>,
    /// Close once the sends are done (else wait for the server).
    close: bool,
}

impl Relay for TestCaller {
    fn deliver(&mut self, part: Part) -> engine::Result<()> {
        self.parts.push(part);
        Ok(())
    }

    fn next(&mut self, _: Duration) -> engine::Result<Option<FromCaller>> {
        match self.sends.pop_front() {
            Some(sent) => Ok(Some(sent)),
            None if self.close => Ok(Some(FromCaller::Close)),
            None => Ok(None),
        }
    }
}

impl TestCaller {
    fn body(&self) -> Vec<u8> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Body(b) => Some(b.to_vec()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn messages(&self) -> Vec<Vec<u8>> {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Text(b) | Part::Binary(b) => Some(b.to_vec()),
                _ => None,
            })
            .collect()
    }
}

fn closed(output: engine::Result<Output>) -> Closed {
    match output {
        Ok(Output::Closed(closed)) => closed,
        Ok(other) => panic!("not closed: {other:?}"),
        Err(e) => panic!("failed: {e}"),
    }
}

fn events(s: &Setup) -> Vec<Event> {
    s.node.with_sink(|sink| {
        sink.entries()
            .iter()
            .map(|e| e.entry.event.clone())
            .collect()
    })
}

fn last_closed(s: &Setup) -> (bool, String, (u64, u64), (u64, u64)) {
    match events(s)
        .into_iter()
        .rev()
        .find(|e| matches!(e, Event::Closed { .. }))
    {
        Some(Event::Closed {
            ok,
            reason,
            to_server,
            to_caller,
            ..
        }) => (ok, reason, to_server, to_caller),
        _ => panic!("no closed entry"),
    }
}

// --- Streamed responses -------------------------------------------------------------------

fn sse(limits: serde_json::Value) -> Operation {
    operation(json!({
        "name": "events",
        "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "api.example.com", "port": 443}], "limits": limits},
            {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/events"},
             "inject": [{"target": {"kind": "header", "name": "Authorization"},
                         "template": "Bearer {{token}}"}]},
            {"do": "return", "response": {"headers": ["content-type"], "body": "stream",
                                          "trailers": ["x-sum"]}}
        ]
    }))
}

const SSE_HEAD: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";

fn chunk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

#[test]
fn a_streamed_body_arrives_in_parts_with_its_trailers() {
    let s = setup(vec![sse(json!({}))]);
    let body: Vec<u8> = (0..200)
        .flat_map(|i| format!("data: {{\"n\":{i}}}\n\n").into_bytes())
        .collect();
    let mut server = Server {
        end: true,
        ..Server::default()
    };
    server.script.push_back(Some(SSE_HEAD.to_vec()));
    for part in body.chunks(97) {
        server.script.push_back(Some(chunk(part)));
        server.script.push_back(None);
    }
    server
        .script
        .push_back(Some(b"0\r\nX-Sum: 42\r\nX-Other: no\r\n\r\n".to_vec()));
    let mut caller = TestCaller::default();
    let call = sign(&s, "events", Body::http_fixed());
    let outcome = s.node.relay(&call, &mut server, &mut caller);
    let end = closed(outcome.result);
    assert_eq!(end.reason, "server");
    assert_eq!(end.status, Some(200));
    assert_eq!(end.trailers, vec![("X-Sum".to_string(), b"42".to_vec())]);
    assert_eq!(caller.body(), body);
    assert!(caller.parts.len() > 3, "the body came in parts");
    match &caller.parts[0] {
        Part::Head(head) => {
            assert_eq!(head.status(), 200);
            assert_eq!(head.header("content-type"), Some(&b"text/event-stream"[..]));
        }
        other => panic!("first part {other:?}"),
    }
    let written = String::from_utf8_lossy(&server.written).to_string();
    assert!(
        written.contains("Authorization: Bearer "),
        "the token was injected"
    );
    // One entry when it opened, one when it closed.
    let kinds: Vec<&str> = events(&s)
        .iter()
        .filter_map(|e| match e {
            Event::Use { .. } => Some("use"),
            Event::Closed { .. } => Some("closed"),
            Event::Done { .. } => Some("done"),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, ["use", "closed"]);
    let (ok, reason, _, to_caller) = last_closed(&s);
    assert!(ok);
    assert_eq!(reason, "server");
    assert_eq!(to_caller.1, body.len() as u64);
}

#[test]
fn a_secret_split_across_chunks_in_any_form_is_caught() {
    let s = setup(vec![sse(json!({}))]);
    for (f, form) in forms(TOKEN).unwrap().iter().enumerate() {
        for split in 1..form.len() {
            let mut server = Server {
                end: true,
                ..Server::default()
            };
            server.script.push_back(Some(SSE_HEAD.to_vec()));
            let mut first = b"data: {\"echo\":\"".to_vec();
            first.extend_from_slice(&form[..split]);
            let mut second = form[split..].to_vec();
            second.extend_from_slice(b"\"}\n\n");
            server.script.push_back(Some(chunk(&first)));
            server.script.push_back(Some(chunk(&second)));
            server.script.push_back(Some(b"0\r\n\r\n".to_vec()));
            let mut caller = TestCaller::default();
            let call = sign(&s, "events", Body::http_fixed());
            let outcome = s.node.relay(&call, &mut server, &mut caller);
            assert_eq!(
                outcome.result.err(),
                Some(Error::Reflection),
                "form {f} split at {split} not caught"
            );
            let seen = caller.body();
            assert!(
                memchr::memmem::find(&seen, form).is_none(),
                "form {f} split at {split} reached the caller"
            );
            assert!(
                seen.len() <= b"data: {\"echo\":\"".len(),
                "form {f}: bytes of the secret were released"
            );
        }
    }
    let (ok, reason, _, _) = last_closed(&s);
    assert!(!ok);
    assert_eq!(reason, "reflection");
}

#[test]
fn a_plain_call_gets_a_streamed_body_whole() {
    let s = setup(vec![sse(json!({}))]);
    let mut server = Server::default();
    server.script.push_back(Some(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
    ));
    let call = sign(&s, "events", Body::http_fixed());
    match s.node.run(&call, &mut server).result {
        Ok(Output::Http(response)) => assert_eq!(response.body(), b"hello"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn each_limit_ends_a_streamed_response() {
    // Bytes.
    let s = setup(vec![sse(json!({"bytes": 300}))]);
    let mut server = Server::default();
    server.script.push_back(Some(SSE_HEAD.to_vec()));
    for _ in 0..10 {
        server.script.push_back(Some(chunk(&[b'x'; 100])));
    }
    let mut caller = TestCaller::default();
    let call = sign(&s, "events", Body::http_fixed());
    let end = closed(s.node.relay(&call, &mut server, &mut caller).result);
    assert_eq!(end.reason, "bytes");
    assert!(caller.body().len() <= 300);
    assert_eq!(last_closed(&s).1, "bytes");

    // Idle: the server goes quiet.
    let s = setup(vec![sse(json!({"idle_ms": 60}))]);
    let mut server = Server::default();
    server.script.push_back(Some(SSE_HEAD.to_vec()));
    let mut caller = TestCaller::default();
    let call = sign(&s, "events", Body::http_fixed());
    let end = closed(s.node.relay(&call, &mut server, &mut caller).result);
    assert_eq!(end.reason, "idle");

    // Duration: the server keeps sending.
    let s = setup(vec![sse(json!({"duration_ms": 80}))]);
    let mut server = Server::default();
    server.script.push_back(Some(SSE_HEAD.to_vec()));
    for _ in 0..100_000 {
        server.script.push_back(Some(chunk(b"data: x\n\n")));
    }
    let mut caller = TestCaller::default();
    let call = sign(&s, "events", Body::http_fixed());
    let end = closed(s.node.relay(&call, &mut server, &mut caller).result);
    assert_eq!(end.reason, "duration");
    assert!(end.duration_ms >= 80);
}

#[test]
fn a_streaming_call_needs_an_operation_that_streams() {
    let plain = operation(json!({
        "name": "plain",
        "steps": [
            {"do": "open", "connection": "https",
             "destinations": [{"host": "api.example.com", "port": 443}]},
            {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/"}},
            {"do": "return"}
        ]
    }));
    let s = setup(vec![plain]);
    let call = sign(&s, "plain", Body::http_fixed());
    let outcome = s
        .node
        .relay(&call, &mut Server::default(), &mut TestCaller::default());
    assert!(matches!(outcome.result, Err(Error::RequestInvalid { .. })));
}

// --- WebSocket ------------------------------------------------------------------------------

fn socket(relay: serde_json::Value, limits: serde_json::Value) -> Operation {
    operation(json!({
        "name": "live",
        "steps": [
            {"do": "open", "connection": "websocket",
             "destinations": [{"host": "api.example.com", "port": 443}], "limits": limits},
            {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/ws"},
             "inject": [{"target": {"kind": "query", "name": "v"}, "template": "1"}]},
            {"do": "send", "frame": "text", "template": "{\"auth\":\"{{token}}\"}"},
            {"do": "receive", "capture": [{"source": {"from": "all"},
                                           "into": {"kind": "temp", "name": "hello", "secret": false}}]},
            {"do": "return", "relay": relay}
        ]
    }))
}

fn rules(server: bool) -> serde_json::Value {
    json!({
        "server": server,
        "frames": [{
            "kind": "text",
            "shape": {"json": {"members": [
                {"pointer": "/op", "equals": "sub"},
                {"pointer": "/channel", "type": "string", "pattern": "[a-z]{1,16}"}
            ]}}
        }]
    })
}

/// The server's answer to the handshake in the written bytes.
fn handshake_answer(written: &[u8], extra: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(written).to_string();
    let key = text
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap()
        .trim()
        .to_string();
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{extra}\r\n",
        engine::websocket::accept(&key)
    )
    .into_bytes()
}

/// A server that answers the handshake (the key is known only once the node wrote it).
struct WsServer {
    inner: Server,
    extra: &'static str,
    status: &'static str,
}

impl Transport for WsServer {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        _: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        Err(Error::transport(TransportKind::Unsupported, false))
    }

    fn exchange_streamed(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        versions: Versions,
    ) -> engine::Result<(Box<dyn Stream + '_>, Version)> {
        assert_eq!(versions, Versions::Http1, "a handshake is HTTP/1.1");
        self.inner.written.extend_from_slice(wire);
        let mut answer = handshake_answer(wire, self.extra);
        if !self.status.is_empty() {
            answer = format!("HTTP/1.1 {}\r\nContent-Length: 0\r\n\r\n", self.status).into_bytes();
        }
        self.inner.script.push_front(Some(answer));
        Ok((Box::new(Script(&mut self.inner)), Version::Http1))
    }
}

fn ws(script: Vec<Option<Vec<u8>>>, echo: bool) -> WsServer {
    WsServer {
        inner: Server {
            script: script.into(),
            echo,
            ..Server::default()
        },
        extra: "",
        status: "",
    }
}

fn frame(call: &SignedCall, seq: u64, data: &[u8]) -> FromCaller {
    FromCaller::Frame(CallerFrame {
        seq,
        kind: FrameKind::Text,
        data: data.to_vec(),
        signature: caller_key().sign_frame(&call.auth, seq, false, data),
    })
}

#[test]
fn a_websocket_authenticates_then_relays_frames_within_their_shapes() {
    let s = setup(vec![socket(rules(true), json!({}))]);
    let call = sign(&s, "live", Body::Socket { request: None });
    let mut server = ws(
        vec![
            Some(message(1, b"{\"hello\":1}")),
            Some(message(1, b"welcome")),
        ],
        false,
    );
    let mut caller = TestCaller {
        sends: vec![
            frame(&call, 0, br#"{"op":"sub","channel":"news"}"#),
            frame(&call, 1, br#"{"op":"sub","channel":"sport"}"#),
        ]
        .into(),
        close: true,
        ..TestCaller::default()
    };
    let outcome = s.node.relay(&call, &mut server, &mut caller);
    let end = closed(outcome.result);
    assert_eq!(end.reason, "caller");
    assert_eq!(end.status, Some(101));
    let sent = client_frames(
        &server.inner.written[server
            .inner
            .written
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4..],
    );
    // The first message carries the token (first-message auth), then the caller's frames.
    assert_eq!(
        sent[0].1,
        [b"{\"auth\":\"".as_slice(), TOKEN, b"\"}"].concat()
    );
    assert_eq!(sent[1].1, br#"{"op":"sub","channel":"news"}"#);
    assert_eq!(sent[2].1, br#"{"op":"sub","channel":"sport"}"#);
    assert_eq!(
        sent[3],
        (8, 1000u16.to_be_bytes().to_vec()),
        "a close frame"
    );
    let handshake = String::from_utf8_lossy(&server.inner.written).to_string();
    assert!(handshake.starts_with("GET /ws?v=1 HTTP/1.1\r\n"));
    assert!(handshake.contains("Upgrade: websocket\r\n"));
    assert!(handshake.contains("Sec-WebSocket-Version: 13\r\n"));
    assert_eq!(caller.messages(), vec![b"welcome".to_vec()]);
    assert_eq!(end.to_server, (3, (11 + TOKEN.len() + 29 + 30) as u64));
    let kinds: Vec<&str> = events(&s)
        .iter()
        .filter_map(|e| match e {
            Event::Use { .. } => Some("use"),
            Event::Closed { .. } => Some("closed"),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, ["use", "closed"]);
}

#[test]
fn a_server_echoing_a_secret_ends_the_websocket() {
    let s = setup(vec![socket(rules(true), json!({}))]);
    let call = sign(&s, "live", Body::Socket { request: None });
    let mut server = ws(
        vec![
            Some(message(1, b"{\"hello\":1}")),
            Some(message(1, b"fine")),
            Some(message(1, &[b"leak ".as_slice(), TOKEN].concat())),
        ],
        false,
    );
    let mut caller = TestCaller::default();
    let outcome = s.node.relay(&call, &mut server, &mut caller);
    assert_eq!(outcome.result.err(), Some(Error::Reflection));
    assert_eq!(caller.messages(), vec![b"fine".to_vec()]);
    assert_eq!(last_closed(&s).1, "reflection");

    // Split across two messages: found when the second arrives.
    for (f, form) in forms(TOKEN).unwrap().iter().enumerate() {
        for split in [1, form.len() / 2, form.len() - 1] {
            let mut server = ws(
                vec![
                    Some(message(1, b"{\"hello\":1}")),
                    Some(message(1, &form[..split])),
                    Some(message(1, &form[split..])),
                ],
                false,
            );
            let mut caller = TestCaller::default();
            let outcome = s.node.relay(&call_again(&s), &mut server, &mut caller);
            assert_eq!(
                outcome.result.err(),
                Some(Error::Reflection),
                "form {f} split at {split} not caught"
            );
            assert!(
                caller.messages().len() <= 1,
                "form {f}: the second part went out"
            );
        }
    }
}

fn call_again(s: &Setup) -> SignedCall {
    sign(s, "live", Body::Socket { request: None })
}

type MakeFrame = Box<dyn Fn(&SignedCall) -> FromCaller>;

#[test]
fn caller_frames_outside_the_rules_are_refused() {
    let s = setup(vec![socket(rules(false), json!({}))]);
    let cases: Vec<(&str, MakeFrame)> = vec![
        (
            "outside the shape",
            Box::new(|c| frame(c, 0, br#"{"op":"unsub","channel":"news"}"#)),
        ),
        (
            "an extra member",
            Box::new(|c| frame(c, 0, br#"{"op":"sub","channel":"news","x":1}"#)),
        ),
        (
            "binary where only text is relayed",
            Box::new(|c| {
                let data = br#"{"op":"sub","channel":"news"}"#;
                FromCaller::Frame(CallerFrame {
                    seq: 0,
                    kind: FrameKind::Binary,
                    data: data.to_vec(),
                    signature: caller_key().sign_frame(&c.auth, 0, true, data),
                })
            }),
        ),
        (
            "a bad signature",
            Box::new(|c| {
                let FromCaller::Frame(mut f) = frame(c, 0, br#"{"op":"sub","channel":"news"}"#)
                else {
                    unreachable!()
                };
                f.data = br#"{"op":"sub","channel":"evil"}"#.to_vec();
                FromCaller::Frame(f)
            }),
        ),
        (
            "out of sequence",
            Box::new(|c| frame(c, 1, br#"{"op":"sub","channel":"news"}"#)),
        ),
        (
            "signed for another call",
            Box::new(|_| {
                let other = sign_other();
                frame(&other, 0, br#"{"op":"sub","channel":"news"}"#)
            }),
        ),
    ];
    for (name, make) in cases {
        let call = call_again(&s);
        let mut server = ws(vec![Some(message(1, b"{\"hello\":1}"))], false);
        let mut caller = TestCaller {
            sends: vec![make(&call)].into(),
            ..TestCaller::default()
        };
        let outcome = s.node.relay(&call, &mut server, &mut caller);
        assert!(
            matches!(outcome.result, Err(Error::FrameRefused { .. })),
            "{name}: {:?}",
            outcome.result
        );
        let after = &server.inner.written[server
            .inner
            .written
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4..];
        let sent = client_frames(after);
        assert_eq!(
            sent.len(),
            1,
            "{name}: only the policy's first message went out"
        );
        assert_eq!(last_closed(&s).1, "refused", "{name}");
    }
}

fn sign_other() -> SignedCall {
    let s = setup(vec![socket(rules(false), json!({}))]);
    call_again(&s)
}

#[test]
fn server_messages_go_back_only_when_the_policy_says() {
    let s = setup(vec![socket(rules(false), json!({}))]);
    let mut server = ws(
        vec![
            Some(message(1, b"{\"hello\":1}")),
            Some(message(1, b"news")),
        ],
        false,
    );
    server.inner.end = true;
    let mut caller = TestCaller::default();
    let end = closed(
        s.node
            .relay(&call_again(&s), &mut server, &mut caller)
            .result,
    );
    assert_eq!(end.reason, "server");
    assert!(caller.messages().is_empty());
}

#[test]
fn each_limit_ends_a_websocket() {
    for (limits, reason) in [
        (json!({"idle_ms": 50}), "idle"),
        (json!({"duration_ms": 80}), "duration"),
        (json!({"bytes": 400}), "bytes"),
    ] {
        let s = setup(vec![socket(rules(true), limits)]);
        let mut script = vec![Some(message(1, b"{\"hello\":1}"))];
        if reason != "idle" {
            script.extend((0..50_000).map(|_| Some(message(1, b"tick"))));
        }
        let mut server = ws(script, false);
        let mut caller = TestCaller::default();
        let end = closed(
            s.node
                .relay(&call_again(&s), &mut server, &mut caller)
                .result,
        );
        assert_eq!(end.reason, reason);
        let (ok, logged, to_server, to_caller) = last_closed(&s);
        assert!(!ok);
        assert_eq!(logged, reason);
        assert_eq!(to_server.0, 1, "the policy's first message");
        assert_eq!(to_caller.0, caller.messages().len() as u64);
    }
}

#[test]
fn the_handshake_answer_is_checked() {
    let s = setup(vec![socket(rules(true), json!({}))]);
    for (extra, status, rule) in [
        (
            "",
            "200 OK",
            "WebSocket handshake refused (status other than 101)",
        ),
        (
            "Sec-WebSocket-Extensions: permessage-deflate\r\n",
            "",
            "WebSocket extension the node did not offer",
        ),
        (
            "Sec-WebSocket-Protocol: chat\r\n",
            "",
            "WebSocket subprotocol the request did not offer",
        ),
    ] {
        let mut server = ws(vec![], false);
        server.extra = extra;
        server.status = status;
        let outcome = s
            .node
            .relay(&call_again(&s), &mut server, &mut TestCaller::default());
        assert_eq!(outcome.result.err(), Some(Error::ResponseInvalid { rule }));
    }
    // A wrong accept value.
    struct Wrong(Server);
    impl Transport for Wrong {
        fn send(
            &mut self,
            _: &Destination,
            _: Option<&ClientIdentity>,
            _: &[u8],
            _: usize,
        ) -> engine::Result<Vec<u8>> {
            Err(Error::transport(TransportKind::Unsupported, false))
        }
        fn exchange_streamed(
            &mut self,
            _: &Destination,
            _: Option<&ClientIdentity>,
            _: &[u8],
            _: Versions,
        ) -> engine::Result<(Box<dyn Stream + '_>, Version)> {
            self.0.script.push_back(Some(
                b"HTTP/1.1 101 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAA\r\n\r\n".to_vec(),
            ));
            Ok((Box::new(Script(&mut self.0)), Version::Http1))
        }
    }
    let outcome = s.node.relay(
        &call_again(&s),
        &mut Wrong(Server::default()),
        &mut TestCaller::default(),
    );
    assert_eq!(
        outcome.result.err(),
        Some(Error::ResponseInvalid {
            rule: "WebSocket handshake with a wrong Sec-WebSocket-Accept"
        })
    );
}

#[test]
fn a_websocket_runs_only_on_a_streaming_call() {
    let s = setup(vec![socket(rules(true), json!({}))]);
    let outcome = s.node.run(&call_again(&s), &mut ws(vec![], false));
    assert!(matches!(outcome.result, Err(Error::RequestInvalid { .. })));
}

#[test]
fn open_connections_are_bounded_per_caller() {
    // A caller holds at most MAX_STREAMS_PER_CALLER at once: the relays below each wait on
    // a barrier inside the connection, so they are all open together.
    use std::sync::{Arc, Barrier};
    let s = Arc::new(setup(vec![sse(json!({"idle_ms": 2000}))]));
    let barrier = Arc::new(Barrier::new(MAX_STREAMS_PER_CALLER + 1));
    let mut handles = Vec::new();
    for _ in 0..MAX_STREAMS_PER_CALLER {
        let (s, barrier) = (Arc::clone(&s), Arc::clone(&barrier));
        let call = sign(&s, "events", Body::http_fixed());
        handles.push(std::thread::spawn(move || {
            struct Held(Arc<Barrier>, bool);
            impl Relay for Held {
                fn deliver(&mut self, _: Part) -> engine::Result<()> {
                    if !self.1 {
                        self.1 = true;
                        self.0.wait();
                        self.0.wait();
                    }
                    Ok(())
                }
                fn next(&mut self, _: Duration) -> engine::Result<Option<FromCaller>> {
                    Ok(Some(FromCaller::Close))
                }
            }
            let mut server = Server::default();
            server.script.push_back(Some(SSE_HEAD.to_vec()));
            s.node
                .relay(&call, &mut server, &mut Held(barrier, false))
                .result
                .map(|_| ())
        }));
    }
    barrier.wait();
    let call = sign(&s, "events", Body::http_fixed());
    let outcome = s
        .node
        .relay(&call, &mut Server::default(), &mut TestCaller::default());
    assert_eq!(
        outcome.result.err(),
        Some(Error::StreamsFull { who: "caller" })
    );
    barrier.wait();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    // Freed: one more fits now.
    let mut server = Server {
        end: true,
        ..Server::default()
    };
    server.script.push_back(Some(SSE_HEAD.to_vec()));
    server.script.push_back(Some(b"0\r\n\r\n".to_vec()));
    let call = sign(&s, "events", Body::http_fixed());
    assert!(
        s.node
            .relay(&call, &mut server, &mut TestCaller::default())
            .result
            .is_ok()
    );
}

// --- gRPC and HTTP versions ------------------------------------------------------------------

fn grpc(protocol: &str) -> Operation {
    operation(json!({
        "name": "rpc",
        "steps": [
            {"do": "open", "connection": "https", "protocol": protocol,
             "destinations": [{"host": "api.example.com", "port": 443}]},
            {"do": "send", "grpc": true,
             "request": {"from": "fixed", "method": "POST", "path": "/pkg.Service/Get"},
             "inject": [{"target": {"kind": "header", "name": "authorization"},
                         "template": "Bearer {{token}}"},
                        {"target": {"kind": "body"}, "template": "abc"}]},
            {"do": "return", "response": {"body": "all", "trailers": ["grpc-status", "grpc-message"]}}
        ]
    }))
}

#[test]
fn a_unary_grpc_call_frames_its_message_and_reads_trailers() {
    let s = setup(vec![grpc("h2")]);
    let mut server = Server {
        version: Some(Version::Http2),
        ..Server::default()
    };
    // The transport writes an HTTP/2 answer in HTTP/1.1 form: chunked, trailers after.
    let mut answer =
        b"HTTP/1.1 200 OK\r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    answer.extend(chunk(b"\x00\x00\x00\x00\x03\x08\x96\x01"));
    answer.extend_from_slice(b"0\r\ngrpc-status: 0\r\ngrpc-message: fine\r\n\r\n");
    server.script.push_back(Some(answer));
    let call = sign(&s, "rpc", Body::http_fixed());
    let response = match s.node.run(&call, &mut server).result {
        Ok(Output::Http(response)) => response,
        other => panic!("{other:?}"),
    };
    assert_eq!(response.body(), b"\x08\x96\x01");
    assert_eq!(response.trailer("grpc-status"), Some(&b"0"[..]));
    assert_eq!(response.trailer("grpc-message"), Some(&b"fine"[..]));
    let wire = String::from_utf8_lossy(&server.written).to_string();
    assert!(wire.contains("Content-Type: application/grpc\r\nTE: trailers\r\n"));
    assert!(wire.ends_with("\r\n\r\n\x00\x00\x00\x00\x03abc"));
}

#[test]
fn a_grpc_send_needs_http2_pinned() {
    let mut policy_op = grpc("h2");
    if let engine::policy::Step::Open(open) = &mut policy_op.steps[0] {
        open.protocol = None;
    }
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("token")],
        callers: vec![],
        operations: vec![policy_op],
    };
    assert!(policy.validate().is_err());
}

#[test]
fn a_pinned_http2_is_not_downgraded() {
    let s = setup(vec![grpc("h2")]);
    // The server only agrees to HTTP/1.1: nothing is read, the request fails.
    let mut server = Server {
        version: Some(Version::Http1),
        ..Server::default()
    };
    let call = sign(&s, "rpc", Body::http_fixed());
    let outcome = s.node.run(&call, &mut server);
    assert_eq!(
        outcome.result.err(),
        Some(Error::transport(TransportKind::Downgrade, false))
    );
    assert!(server.written.is_empty(), "nothing was sent");
    // A transport that would answer over HTTP/1.1 anyway is caught by the engine too.
    struct Liar;
    impl Transport for Liar {
        fn send(
            &mut self,
            _: &Destination,
            _: Option<&ClientIdentity>,
            _: &[u8],
            _: usize,
        ) -> engine::Result<Vec<u8>> {
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        }
        fn exchange(
            &mut self,
            d: &Destination,
            i: Option<&ClientIdentity>,
            w: &[u8],
            m: usize,
            _: Versions,
        ) -> engine::Result<(Vec<u8>, Version)> {
            self.send(d, i, w, m).map(|b| (b, Version::Http1))
        }
    }
    let call = sign(&s, "rpc", Body::http_fixed());
    let outcome = s.node.run(&call, &mut Liar);
    assert_eq!(
        outcome.result.err(),
        Some(Error::transport(TransportKind::Downgrade, true))
    );
}

/// A caller whose node hands over to a successor while the connection is open.
struct HandingOver<'a> {
    node: &'a TestNode,
    sends: VecDeque<FromCaller>,
    handed: bool,
}

impl Relay for HandingOver<'_> {
    fn deliver(&mut self, _: Part) -> engine::Result<()> {
        Ok(())
    }

    fn next(&mut self, _: Duration) -> engine::Result<Option<FromCaller>> {
        // The first frame goes out before the hand-over; the second is sent after it.
        if self.sends.len() == 1 && !self.handed {
            self.handed = true;
            let successor = engine::node::Successor {
                identity: Node::new(NodeKey::generate(), MemorySink::new(), SystemClock).identity(),
                release: "v9.9.9".into(),
                statement_sha256: [7; 32],
            };
            self.node.hand_over(&successor)?;
        }
        Ok(self.sends.pop_front())
    }
}

#[test]
fn a_hand_over_ends_open_connections_before_another_frame_is_written() {
    let s = setup(vec![socket(rules(true), json!({}))]);
    let call = sign(&s, "live", Body::Socket { request: None });
    let mut server = ws(vec![Some(message(1, b"{\"hello\":1}"))], false);
    let mut caller = HandingOver {
        node: &s.node,
        sends: vec![
            frame(&call, 0, br#"{"op":"sub","channel":"news"}"#),
            frame(&call, 1, br#"{"op":"sub","channel":"sport"}"#),
        ]
        .into(),
        handed: false,
    };
    let outcome = s.node.relay(&call, &mut server, &mut caller);
    assert!(caller.handed);
    assert!(
        matches!(outcome.result, Err(Error::HandedOver)),
        "the old node logs nothing after its hand-over"
    );
    let written = &server.inner.written;
    let start = written.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let sent = client_frames(&written[start..]);
    let data: Vec<&[u8]> = sent.iter().map(|(_, d)| d.as_slice()).collect();
    assert!(data.contains(&br#"{"op":"sub","channel":"news"}"#.as_slice()));
    assert!(
        !data.contains(&br#"{"op":"sub","channel":"sport"}"#.as_slice()),
        "a frame was written after the hand-over"
    );
    assert_eq!(
        sent.last().unwrap(),
        &(8, 1001u16.to_be_bytes().to_vec()),
        "a close frame (going away)"
    );
}
