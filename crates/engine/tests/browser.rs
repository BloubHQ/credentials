//! Browser fills over CDP, end to end through a node, against an in-process fake CDP
//! endpoint (no real browser): every attack of `docs/threat-model.md` on fills has a test
//! here, and every limit.
//!
//! The fake models what the node reads: targets, a frame tree with loaders, isolated worlds,
//! remote objects bound to the document they were found in (a navigation makes them
//! unknown), and the checks the node's page functions make (`location.origin`,
//! `location.ancestorOrigins`). Hooks make it navigate, swap frames, flood, stall, forge or
//! echo at chosen moments. Assertion messages never print a secret.
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
use engine::cdp::{self, WebOrigin};
use engine::egress::{Arrived, ClientIdentity, Stream, Transport, Version, Versions};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink};
use engine::node::{Filled, MAX_CDP_EVENTS, Node, SystemClock};
use engine::policy::summary::{FlagCode, Form};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy};
use serde_json::{Value, json};

const USER: &str = "alice@example.com";
const PASSWORD: &str = "pw-\"S3cret\"\\ü<9>";
const PAGE: &str = "https://login.example.com";
const FRAME: &str = "https://pay.example.org";

type TestNode = Node<MemorySink, SystemClock>;

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [6u8; 32])
}

struct Setup {
    node: TestNode,
    record: engine::record::Record,
}

fn op(value: Value) -> Operation {
    serde_json::from_value(value).unwrap()
}

fn policy_of(operations: Vec<Operation>) -> Policy {
    let names = operations.iter().map(|o| o.name().to_string()).collect();
    Policy {
        item: None,
        fields: vec![
            FieldSpec::public("username"),
            FieldSpec::guessable("password"),
            FieldSpec::secret("token"),
        ],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: names,
            limit: None,
        }],
        operations,
    }
}

fn setup_with(operations: Vec<Operation>, password: &[u8]) -> Setup {
    let policy = policy_of(operations);
    policy.validate().unwrap();
    let device = DeviceKey::generate();
    let user_key = [8u8; 32];
    let mut fields = Fields::new();
    fields.insert("username", USER.as_bytes().to_vec()).unwrap();
    fields.insert("password", password.to_vec()).unwrap();
    fields
        .insert("token", b"browser-token-0123456789".to_vec())
        .unwrap();
    let record = engine::record::Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-b",
        "user-b",
        device.sign_policy(policy).unwrap(),
        &fields,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let terms = GrantTerms {
        owner: "user-b".into(),
        expires_ms: engine::node::now_ms() + 3_600_000,
        issued_ms: engine::node::now_ms(),
        pins: vec![RecordPin {
            record_id: "rec-b".into(),
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

fn setup(operations: Vec<Operation>) -> Setup {
    setup_with(operations, PASSWORD.as_bytes())
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

fn fill_value(fill: Value) -> Value {
    json!({"name": "login", "steps": [
        {"do": "open", "connection": "browser",
         "destinations": [{"host": "cdp.browser.test", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/devtools/browser/b1"},
         "inject": [{"target": {"kind": "header", "name": "Authorization"},
                     "template": "Bearer {{token}}"}]},
        {"do": "send", "fill": fill},
        {"do": "return"}
    ]})
}

fn login_fill() -> Value {
    json!({"origin": PAGE,
           "fields": [{"selector": "#id", "template": "{{username}}"},
                      {"selector": "#pw", "template": "{{password}}"}],
           "submit": {"selector": "form#login"},
           "wait_ms": 300})
}

fn login() -> Operation {
    op(fill_value(login_fill()))
}

fn with_limits(mut value: Value, limits: Value) -> Value {
    value["steps"][0]["limits"] = limits;
    value
}

// ---------------------------------------------------------------- the fake CDP endpoint

#[derive(Clone)]
struct El {
    selector: String,
    kind: &'static str,
    value: String,
}

#[derive(Clone)]
struct Fr {
    id: String,
    parent: Option<String>,
    loader: u32,
    url: String,
    /// What the browser reports as `securityOrigin`, when it differs from the URL's.
    security_origin: Option<String>,
    /// The origin the page code sees (`location.origin`), when it differs from the URL's (a
    /// browser that lies in the frame tree).
    real_origin: Option<String>,
    elements: Vec<El>,
}

#[derive(Default)]
struct Hooks {
    /// After a lookup of this selector, navigate the top frame to this URL.
    navigate_after_find: Option<(String, String)>,
    /// After the fill of this selector is answered, navigate the top frame (same URL, new
    /// document).
    navigate_after_fill: Option<String>,
    /// After a lookup of this selector, replace its frame with a new one (new id, same URL).
    swap_after_find: Option<String>,
    /// The submit navigates the top frame.
    submit_navigates: bool,
    /// Every command is echoed back as an event, params included.
    echo_events: bool,
    /// Events sent before each answer.
    flood: usize,
    /// Commands answered before the endpoint stops answering.
    stall_after: Option<usize>,
    /// While stalled, an event on every read (the connection is never idle).
    stall_chatty: bool,
    /// A message of this many bytes before the first answer.
    huge: Option<usize>,
    /// Forge the answer to the command of this method (the n-th of it, from 1).
    forge: Option<(String, usize, Forge)>,
    /// The endpoint does not let the node attach to an OOPIF frame's page session.
    oopif: Option<String>,
    /// After answering the n-th frame-tree read, forget every remote object.
    forget_objects_at_tree: Option<usize>,
}

#[derive(Clone, Copy)]
enum Forge {
    WrongId,
    OtherSession,
    Duplicate,
    Binary,
    NotJson,
    NotOk,
    ErrorEcho,
}

#[derive(Default)]
struct Browser {
    targets: Vec<(String, String, String, bool)>,
    frames: Vec<Fr>,
    sessions: Vec<(String, String)>,
    contexts: Vec<(i64, String, u32)>,
    objects: Vec<(String, String, u32, String)>,
    next: u64,
    hooks: Hooks,
    /// Server bytes waiting to be read.
    out: VecDeque<Vec<u8>>,
    /// The methods the node issued, in order.
    methods: Vec<String>,
    /// Count of each method, for forging.
    counts: Vec<(String, usize)>,
    answered: usize,
    stalled: bool,
    handshake: Vec<u8>,
}

fn element(selector: &str, kind: &'static str) -> El {
    El {
        selector: selector.into(),
        kind,
        value: String::new(),
    }
}

fn frame(id: &str, parent: Option<&str>, url: &str, elements: Vec<El>) -> Fr {
    Fr {
        id: id.into(),
        parent: parent.map(str::to_string),
        loader: 1,
        url: url.into(),
        security_origin: None,
        real_origin: None,
        elements,
    }
}

impl Browser {
    /// One tab at the login page with a form of two fields.
    fn login_page() -> Self {
        let mut b = Browser::default();
        b.targets.push((
            "page-1".into(),
            "page".into(),
            format!("{PAGE}/signin"),
            false,
        ));
        b.frames.push(frame(
            "page-1",
            None,
            &format!("{PAGE}/signin"),
            vec![
                element("#id", "input"),
                element("#pw", "input"),
                element("form#login", "form"),
            ],
        ));
        b
    }

    fn value_of(&self, selector: &str) -> Option<String> {
        self.frames
            .iter()
            .flat_map(|f| f.elements.iter())
            .find(|e| e.selector == selector)
            .map(|e| e.value.clone())
    }

    /// True when any element anywhere holds the secret.
    fn holds_password(&self) -> bool {
        self.frames
            .iter()
            .flat_map(|f| f.elements.iter())
            .any(|e| e.value.contains(PASSWORD))
    }

    fn origin_of(&self, frame: &Fr) -> String {
        frame.real_origin.clone().unwrap_or_else(|| {
            WebOrigin::of_url(&frame.url)
                .map(|o| o.serialize())
                .unwrap_or_else(|| "null".into())
        })
    }

    fn ancestors_of(&self, frame: &Fr) -> Vec<String> {
        let mut out = Vec::new();
        let mut parent = frame.parent.clone();
        while let Some(p) = parent {
            let f = self.frames.iter().find(|f| f.id == p).unwrap();
            out.push(self.origin_of(f));
            parent = f.parent.clone();
        }
        out
    }

    fn navigate_top(&mut self, url: &str) {
        let top = self.frames.iter_mut().find(|f| f.parent.is_none()).unwrap();
        top.loader += 1;
        top.url = url.into();
        top.real_origin = None;
        for e in &mut top.elements {
            e.value.clear();
        }
        let id = top.id.clone();
        // A new document: its child frames are gone.
        self.frames.retain(|f| f.parent.as_deref() != Some(&id));
        if let Some(t) = self.targets.iter_mut().find(|t| t.0 == id) {
            t.2 = url.into();
        }
    }

    fn tree(&self, id: &str) -> Value {
        let f = self.frames.iter().find(|f| f.id == id).unwrap();
        let mut frame = json!({"id": f.id, "loaderId": format!("L{}-{}", f.id, f.loader),
                               "url": f.url});
        if let Some(p) = &f.parent {
            frame["parentId"] = json!(p);
        }
        if let Some(s) = &f.security_origin {
            frame["securityOrigin"] = json!(s);
        }
        let children: Vec<Value> = self
            .frames
            .iter()
            .filter(|c| c.parent.as_deref() == Some(id))
            .map(|c| self.tree(&c.id))
            .collect();
        if children.is_empty() {
            json!({"frame": frame})
        } else {
            json!({"frame": frame, "childFrames": children})
        }
    }

    fn queue(&mut self, payload: &[u8]) {
        self.out.push_back(server_message(0x1, payload));
    }

    fn answer(&mut self, id: u64, session: Option<&str>, result: Result<Value, String>) {
        let mut message = match result {
            Ok(result) => json!({"id": id, "result": result}),
            Err(message) => json!({"id": id, "error": {"code": -32000, "message": message}}),
        };
        if let Some(s) = session {
            message["sessionId"] = json!(s);
        }
        self.queue(message.to_string().as_bytes());
    }

    fn text(value: &str) -> Value {
        json!({"result": {"type": "string", "value": value}})
    }

    /// The page code's origin checks, as the node's functions make them.
    fn in_page_check(&self, frame: &Fr, origin: &Value, ancestors: &Value) -> Option<&'static str> {
        if origin.as_str() != Some(self.origin_of(frame).as_str()) {
            return Some("origin");
        }
        let expected: Vec<Value> = self
            .ancestors_of(frame)
            .into_iter()
            .map(Value::String)
            .collect();
        if ancestors.as_array() != Some(&expected) {
            return Some("ancestors");
        }
        None
    }

    fn handle(&mut self, command: &Value) {
        let id = command["id"].as_u64().unwrap();
        let method = command["method"].as_str().unwrap().to_string();
        let session = command["sessionId"].as_str().map(str::to_string);
        let params = &command["params"];
        self.methods.push(method.clone());
        let n = match self.counts.iter_mut().find(|(m, _)| *m == method) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                self.counts.push((method.clone(), 1));
                1
            }
        };
        if self.hooks.echo_events {
            let echo = json!({"method": "Debug.echo", "params": command});
            self.queue(echo.to_string().as_bytes());
        }
        for i in 0..self.hooks.flood {
            let event = json!({"method": "Page.lifecycleEvent", "params": {"i": i}});
            self.queue(event.to_string().as_bytes());
        }
        if let Some(size) = self.hooks.huge.take() {
            let padding = "x".repeat(size);
            let event = json!({"method": "Page.big", "params": {"p": padding}});
            self.queue(event.to_string().as_bytes());
        }
        if let Some(limit) = self.hooks.stall_after
            && self.answered >= limit
        {
            self.stalled = true;
            return;
        }
        self.answered += 1;
        if let Some((m, at, forge)) = self.hooks.forge.clone()
            && m == method
            && at == n
        {
            match forge {
                Forge::WrongId => return self.answer(id + 7, session.as_deref(), Ok(json!({}))),
                Forge::OtherSession => {
                    return self.answer(id, Some("SOMEONE-ELSE"), Ok(json!({})));
                }
                Forge::Duplicate => {
                    self.respond(id, &method, session.as_deref(), params);
                    return self.respond(id, &method, session.as_deref(), params);
                }
                Forge::Binary => {
                    self.out.push_back(server_message(0x2, b"{}"));
                    return;
                }
                Forge::NotJson => return self.queue(b"{\"id\":"),
                Forge::NotOk => return self.answer(id, session.as_deref(), Ok(Self::text("yes"))),
                Forge::ErrorEcho => {
                    let echoed = params.to_string();
                    return self.answer(id, session.as_deref(), Err(echoed));
                }
            }
        }
        self.respond(id, &method, session.as_deref(), params);
        if method == "Page.getFrameTree" && self.hooks.forget_objects_at_tree == Some(n) {
            self.objects.clear();
        }
    }

    fn respond(&mut self, id: u64, method: &str, session: Option<&str>, params: &Value) {
        let result: Result<Value, String> = match method {
            "Target.getTargets" => Ok(json!({"targetInfos": self.targets.iter().map(|t| json!({
                "targetId": t.0, "type": t.1, "url": t.2, "attached": t.3, "title": "t"
            })).collect::<Vec<_>>()})),
            "Target.attachToTarget" => {
                let target = params["targetId"].as_str().unwrap().to_string();
                assert_eq!(params["flatten"], json!(true));
                self.next += 1;
                let s = format!("S{}", self.next);
                self.sessions.push((s.clone(), target.clone()));
                if let Some(t) = self.targets.iter_mut().find(|t| t.0 == target) {
                    t.3 = true;
                }
                Ok(json!({"sessionId": s}))
            }
            "Target.detachFromTarget" => Ok(json!({})),
            "Runtime.releaseObjectGroup" => Ok(json!({})),
            "Page.getFrameTree" => {
                let top = self
                    .frames
                    .iter()
                    .find(|f| f.parent.is_none())
                    .unwrap()
                    .id
                    .clone();
                Ok(json!({"frameTree": self.tree(&top)}))
            }
            "Page.navigate" => {
                let url = params["url"].as_str().unwrap().to_string();
                self.navigate_top(&url);
                let top = self.frames.iter().find(|f| f.parent.is_none()).unwrap();
                Ok(json!({"frameId": top.id, "loaderId": format!("L{}-{}", top.id, top.loader)}))
            }
            "Page.createIsolatedWorld" => {
                let frame_id = params["frameId"].as_str().unwrap().to_string();
                assert_eq!(params["worldName"], json!(cdp::WORLD));
                let session_target = self
                    .sessions
                    .iter()
                    .find(|(s, _)| Some(s.as_str()) == session)
                    .map(|(_, t)| t.clone());
                let oopif_refused = self.hooks.oopif.as_deref() == Some(frame_id.as_str())
                    && session_target.as_deref() != Some(frame_id.as_str());
                match self.frames.iter().find(|f| f.id == frame_id) {
                    Some(f) if !oopif_refused => {
                        self.next += 1;
                        let ctx = self.next as i64;
                        self.contexts.push((ctx, f.id.clone(), f.loader));
                        Ok(json!({"executionContextId": ctx}))
                    }
                    _ => Err("No frame for given id found".into()),
                }
            }
            "Runtime.callFunctionOn" => self.call(params),
            _ => Err("method not found".into()),
        };
        self.answer(id, session, result);
    }

    fn call(&mut self, params: &Value) -> Result<Value, String> {
        let function = params["functionDeclaration"].as_str().unwrap();
        let args: Vec<Value> = params["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["value"].clone())
            .collect();
        if function == cdp::FIND {
            let ctx = params["executionContextId"].as_i64().unwrap();
            let (_, frame_id, loader) = self
                .contexts
                .iter()
                .find(|c| c.0 == ctx)
                .cloned()
                .ok_or("Cannot find context with specified id")?;
            let f = self
                .frames
                .iter()
                .find(|f| f.id == frame_id && f.loader == loader)
                .cloned()
                .ok_or("Cannot find context with specified id")?;
            if let Some(reason) = self.in_page_check(&f, &args[1], &args[2]) {
                return Ok(Self::text(reason));
            }
            let selector = args[0].as_str().unwrap().to_string();
            let matches = f.elements.iter().filter(|e| e.selector == selector).count();
            let result = match matches {
                0 => Ok(json!({"result": {"type": "object", "subtype": "null", "value": null}})),
                1 => {
                    self.next += 1;
                    let object = format!("obj-{}", self.next);
                    self.objects
                        .push((object.clone(), f.id.clone(), f.loader, selector.clone()));
                    Ok(json!({"result": {"type": "object", "subtype": "node", "objectId": object}}))
                }
                _ => Ok(Self::text("many")),
            };
            if let Some((sel, url)) = self.hooks.navigate_after_find.clone()
                && sel == selector
            {
                self.hooks.navigate_after_find = None;
                self.navigate_top(&url);
            }
            if self.hooks.swap_after_find.as_deref() == Some(selector.as_str()) {
                self.hooks.swap_after_find = None;
                let old = self.frames.iter_mut().find(|f| f.id == frame_id).unwrap();
                old.id = format!("{}-swapped", old.id);
                old.loader += 1;
            }
            return result;
        }
        let object = params["objectId"].as_str().unwrap();
        let (_, frame_id, loader, selector) = self
            .objects
            .iter()
            .find(|o| o.0 == object)
            .cloned()
            .ok_or("Could not find object with given id")?;
        let f = self
            .frames
            .iter()
            .find(|f| f.id == frame_id && f.loader == loader)
            .cloned()
            .ok_or("Cannot find context with specified id")?;
        let (origin, ancestors) = if function == cdp::FILL {
            (&args[1], &args[2])
        } else {
            (&args[0], &args[1])
        };
        if let Some(reason) = self.in_page_check(&f, origin, ancestors) {
            return Ok(Self::text(reason));
        }
        let el = f.elements.iter().find(|e| e.selector == selector).unwrap();
        let kind = el.kind;
        let set = |b: &mut Browser, value: String| {
            let fr = b.frames.iter_mut().find(|x| x.id == frame_id).unwrap();
            fr.elements
                .iter_mut()
                .find(|e| e.selector == selector)
                .unwrap()
                .value = value;
        };
        if function == cdp::FILL {
            if kind != "input" && kind != "textarea" {
                return Ok(Self::text("kind"));
            }
            set(self, args[0].as_str().unwrap().to_string());
            if self.hooks.navigate_after_fill.as_deref() == Some(selector.as_str()) {
                self.hooks.navigate_after_fill = None;
                let url = self
                    .frames
                    .iter()
                    .find(|f| f.parent.is_none())
                    .unwrap()
                    .url
                    .clone();
                // The page navigates just after taking the value (as a script could).
                let top = self.frames.iter_mut().find(|f| f.parent.is_none()).unwrap();
                top.loader += 1;
                top.url = url;
            }
            Ok(Self::text("ok"))
        } else if function == cdp::SUBMIT {
            if self.hooks.submit_navigates {
                self.navigate_top(&format!("{PAGE}/home"));
            }
            Ok(Self::text("ok"))
        } else if function == cdp::CLEAR {
            set(self, String::new());
            Ok(Self::text("ok"))
        } else {
            panic!("a function the node does not have");
        }
    }
}

/// An unmasked server message, `FIN`.
fn server_message(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else if payload.len() <= 0xffff {
        out.push(126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

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

impl Transport for Browser {
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
        destination: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        versions: Versions,
    ) -> engine::Result<(Box<dyn Stream + '_>, Version)> {
        assert_eq!(destination.host, "cdp.browser.test");
        assert!(versions.allows(Version::Http1));
        self.handshake = wire.to_vec();
        let text = String::from_utf8(wire.to_vec()).unwrap();
        let key = text
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim()
            .to_string();
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            engine::websocket::accept(&key)
        );
        self.out.push_back(head.into_bytes());
        Ok((Box::new(Wire(self)), Version::Http1))
    }
}

struct Wire<'a>(&'a mut Browser);

impl Stream for Wire<'_> {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        for (opcode, payload) in client_frames(bytes) {
            if opcode == 0x1 {
                let command: Value = serde_json::from_slice(&payload).unwrap();
                self.0.handle(&command);
            }
        }
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        self.0
            .out
            .pop_front()
            .ok_or(Error::transport(TransportKind::Closed, false))
    }

    fn read_some(&mut self, _: usize, wait: Duration) -> engine::Result<Arrived> {
        if let Some(bytes) = self.0.out.pop_front() {
            return Ok(Arrived::Bytes(bytes));
        }
        if self.0.stalled && self.0.hooks.stall_chatty {
            std::thread::sleep(wait);
            let event = json!({"method": "Page.lifecycleEvent", "params": {}});
            return Ok(Arrived::Bytes(server_message(
                0x1,
                event.to_string().as_bytes(),
            )));
        }
        std::thread::sleep(wait);
        Ok(Arrived::Nothing)
    }
}

// ---------------------------------------------------------------- helpers

fn run(s: &Setup, browser: &mut Browser) -> engine::Result<Filled> {
    let call = sign(s, "login", Body::http_fixed());
    match s.node.run(&call, browser).result {
        Ok(Output::Fill(filled)) => Ok(filled),
        Ok(other) => panic!("not a fill: {:?}", core::mem::discriminant(&other)),
        Err(e) => Err(e),
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

/// The `closed` entry of the fill: its reason and whether it ended well.
fn closed_entry(s: &Setup) -> (String, bool) {
    events(s)
        .into_iter()
        .find_map(|e| match e {
            Event::Closed { reason, ok, .. } => Some((reason, ok)),
            _ => None,
        })
        .expect("a closed entry")
}

const ALLOWED: [&str; 8] = [
    "Target.getTargets",
    "Target.attachToTarget",
    "Target.detachFromTarget",
    "Page.navigate",
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Runtime.callFunctionOn",
    "Runtime.releaseObjectGroup",
];

fn only_allowed_methods(browser: &Browser) {
    for m in &browser.methods {
        assert!(ALLOWED.contains(&m.as_str()), "the node issued {m}");
    }
    assert!(!browser.methods.iter().any(|m| m == "Runtime.evaluate"));
}

/// Nothing the caller gets, nor the log, holds the secret.
fn no_secret_out(s: &Setup, result: &engine::Result<Filled>) {
    let shown = match result {
        Ok(filled) => serde_json::to_string(filled).unwrap(),
        Err(e) => e.to_string(),
    };
    assert!(
        !shown.contains(PASSWORD) && !shown.contains("S3cret"),
        "the secret reached what the caller gets"
    );
    let log = serde_json::to_string(&events(s)).unwrap();
    assert!(!log.contains("S3cret"), "the secret reached the log");
}

fn refused_with(result: &engine::Result<Filled>, rule: &str) {
    match result {
        Err(Error::FillRefused { rule: r }) => assert_eq!(*r, rule),
        Err(other) => panic!("refused otherwise: {other}"),
        Ok(_) => panic!("not refused"),
    }
}

// ---------------------------------------------------------------- the fill itself

#[test]
fn the_node_fills_submits_and_hands_back_only_the_outcome() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.submit_navigates = true;
    let result = run(&s, &mut browser);
    let filled = result.as_ref().unwrap();
    assert_eq!(filled.outcome, "navigated");
    assert_eq!(filled.origin, PAGE);
    assert_eq!(filled.fields, 2);
    only_allowed_methods(&browser);
    no_secret_out(&s, &result);
    // The handshake carried the token the policy injects, to the endpoint the policy fixes.
    let handshake = String::from_utf8(browser.handshake.clone()).unwrap();
    assert!(handshake.starts_with("GET /devtools/browser/b1 HTTP/1.1\r\n"));
    assert!(handshake.contains("Authorization: Bearer browser-token-0123456789\r\n"));
    // Logs: the use (the handshake) and how it closed.
    let events = events(&s);
    assert!(matches!(events[1], Event::Use { .. }), "{events:?}");
    assert_eq!(closed_entry(&s), ("navigated".into(), true));
    assert_eq!(filled.log_seqs.len(), 1);
}

#[test]
fn the_values_go_into_the_fields_the_policy_names() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.submit_navigates = false;
    // Look at the values before the node blanks them: stop right before the clear.
    browser.hooks.forge = Some(("Runtime.callFunctionOn".into(), 7, Forge::NotOk));
    let _ = run(&s, &mut browser);
    assert_eq!(browser.value_of("#id").as_deref(), Some(USER));
    assert!(
        browser.value_of("#pw").as_deref() == Some(PASSWORD),
        "the password field does not hold the password"
    );
}

#[test]
fn a_page_that_stays_is_blanked() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    let result = run(&s, &mut browser);
    let filled = result.as_ref().unwrap();
    assert_eq!(filled.outcome, "submitted");
    assert_eq!(browser.value_of("#id").as_deref(), Some(""));
    assert_eq!(browser.value_of("#pw").as_deref(), Some(""));
    assert!(
        !browser.holds_password(),
        "the page still holds the password"
    );
    assert_eq!(closed_entry(&s), ("submitted".into(), true));
}

#[test]
fn navigate_loads_the_page_first() {
    let mut fill = login_fill();
    fill["navigate"] = json!("/signin?fresh=1");
    let s = setup(vec![op(fill_value(fill))]);
    let mut browser = Browser::login_page();
    let filled = run(&s, &mut browser).unwrap();
    assert_eq!(filled.outcome, "submitted");
    assert!(browser.methods.iter().any(|m| m == "Page.navigate"));
    assert_eq!(
        browser.frames[0].url,
        format!("{PAGE}/signin?fresh=1"),
        "the page was loaded at the policy's path"
    );
}

fn request(path: &str) -> engine::request::Request {
    engine::request::Request {
        method: engine::policy::Method::Get,
        destination: Destination {
            host: "cdp.browser.test".into(),
            port: 443,
        },
        path: path.into(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

#[test]
fn a_caller_chosen_session_path_stays_within_the_contract() {
    let mut value = fill_value(login_fill());
    value["steps"][1] = json!({"do": "send",
        "request": {"from": "caller", "methods": ["GET"], "paths": ["/devtools/browser"],
                    "query": [{"name": "session", "pattern": "[0-9a-f]{8,32}", "required": true}]},
        "inject": [{"target": {"kind": "header", "name": "Authorization"},
                    "template": "Bearer {{token}}"}]});
    let s = setup(vec![op(value)]);
    let ok = request("/devtools/browser?session=0123abcd");
    let mut browser = Browser::login_page();
    let call = sign(&s, "login", Body::http(ok));
    assert!(matches!(
        s.node.run(&call, &mut browser).result,
        Ok(Output::Fill(_))
    ));
    let other = request("/json/new");
    let mut browser = Browser::login_page();
    let call = sign(&s, "login", Body::http(other));
    assert!(s.node.run(&call, &mut browser).result.is_err());
    assert!(browser.methods.is_empty(), "nothing reached the endpoint");
}

// ---------------------------------------------------------------- origin binding

#[test]
fn a_page_at_another_origin_gets_nothing() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.targets[0].2 = "https://login.example.com.evil.test/signin".into();
    browser.frames[0].url = "https://login.example.com.evil.test/signin".into();
    let result = run(&s, &mut browser);
    refused_with(&result, "no page of the browser is at the policy's origin");
    assert!(
        !browser
            .methods
            .iter()
            .any(|m| m == "Runtime.callFunctionOn")
    );
    assert!(!browser.holds_password());
    assert_eq!(closed_entry(&s), ("refused".into(), false));
    no_secret_out(&s, &result);
}

#[test]
fn a_plain_http_page_or_a_lying_frame_tree_gets_nothing() {
    // The target is listed at the origin but the top frame is not.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0].url = "http://login.example.com/signin".into();
    refused_with(
        &run(&s, &mut browser),
        "the page is not at the policy's origin",
    );
    assert!(!browser.holds_password());
    // The URL says the origin, the security origin another.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0].security_origin = Some("https://evil.example.net".into());
    refused_with(
        &run(&s, &mut browser),
        "the page is not at the policy's origin",
    );
    assert!(!browser.holds_password());
    // The frame tree says the origin; the page itself (location.origin) says otherwise.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0].real_origin = Some("https://evil.example.net".into());
    refused_with(
        &run(&s, &mut browser),
        "the frame is not at the policy's origin",
    );
    assert!(!browser.holds_password());
}

#[test]
fn another_client_or_a_second_tab_stops_the_fill() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.targets[0].3 = true;
    refused_with(
        &run(&s, &mut browser),
        "another client is attached to the page",
    );
    assert!(!browser.methods.iter().any(|m| m == "Target.attachToTarget"));
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.targets.push((
        "page-2".into(),
        "page".into(),
        format!("{PAGE}/other"),
        false,
    ));
    refused_with(
        &run(&s, &mut browser),
        "more than one page of the browser is at the policy's origin",
    );
}

#[test]
fn a_navigation_between_the_check_and_the_fill_gets_nothing() {
    // To another origin, right after the password field was found.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.navigate_after_find = Some(("#pw".into(), "https://evil.example.net/".into()));
    let result = run(&s, &mut browser);
    refused_with(&result, "the page changed before the fill");
    assert!(!browser.holds_password(), "the password reached a page");
    no_secret_out(&s, &result);
    // Within the origin (a new document): refused the same way.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.navigate_after_find = Some(("#pw".into(), format!("{PAGE}/signin")));
    refused_with(&run(&s, &mut browser), "the page changed before the fill");
    assert!(!browser.holds_password());
}

#[test]
fn a_navigation_right_after_the_fill_is_caught_by_the_check_after_it() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.navigate_after_fill = Some("#id".into());
    let result = run(&s, &mut browser);
    refused_with(&result, "the page changed during the fill");
    // The password field comes after: it was never filled.
    assert!(!browser.holds_password());
}

#[test]
fn a_document_that_changes_after_the_last_check_makes_the_element_unknown() {
    // The frame tree still shows the same document (a lying or racing browser), but the
    // element's id belongs to a document that is gone: the fill call fails in the browser.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    // The 5th frame-tree read is the check just before the password's fill.
    browser.hooks.forget_objects_at_tree = Some(5);
    let result = run(&s, &mut browser);
    refused_with(&result, "the page changed between the check and the fill");
    assert!(!browser.holds_password());
}

#[test]
fn a_frame_swapped_between_the_check_and_the_fill_gets_nothing() {
    let mut fill = login_fill();
    fill["fields"][1]["frame"] = json!(FRAME);
    let s = setup(vec![op(fill_value(fill))]);
    let mut browser = Browser::login_page();
    browser.frames[0].elements.retain(|e| e.selector != "#pw");
    browser.frames.push(frame(
        "frame-2",
        Some("page-1"),
        &format!("{FRAME}/card"),
        vec![element("#pw", "input")],
    ));
    browser.hooks.swap_after_find = Some("#pw".into());
    let result = run(&s, &mut browser);
    refused_with(&result, "the page changed before the fill");
    assert!(!browser.holds_password());
}

#[test]
fn a_cross_origin_frame_gets_values_only_when_the_policy_names_it() {
    let page = || {
        let mut browser = Browser::login_page();
        browser.frames[0].elements.retain(|e| e.selector != "#pw");
        browser.frames.push(frame(
            "frame-2",
            Some("page-1"),
            &format!("{FRAME}/card"),
            vec![element("#pw", "input")],
        ));
        browser
    };
    // Not named: the field in the frame is never found.
    let s = setup(vec![login()]);
    let mut browser = page();
    refused_with(
        &run(&s, &mut browser),
        "no element of the page matches the selector",
    );
    assert!(!browser.holds_password());
    // Named: filled, and flagged in the summary.
    let mut fill = login_fill();
    fill["fields"][1]["frame"] = json!(FRAME);
    let operation = op(fill_value(fill.clone()));
    let s = setup(vec![operation.clone()]);
    let mut browser = page();
    browser.hooks.forge = Some(("Runtime.callFunctionOn".into(), 7, Forge::NotOk));
    let _ = run(&s, &mut browser);
    assert!(
        browser.value_of("#pw").as_deref() == Some(PASSWORD),
        "the named frame did not get the value"
    );
    let summary = engine::policy::summarize(&policy_of(vec![operation]), None);
    assert!(
        summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::FrameOrigin)
    );
    // Named, but the frame sits inside another frame: refused.
    let s = setup(vec![op(fill_value(fill.clone()))]);
    let mut browser = Browser::login_page();
    browser.frames[0].elements.retain(|e| e.selector != "#pw");
    browser.frames.push(frame(
        "frame-2",
        Some("page-1"),
        "https://ads.example.net/",
        vec![],
    ));
    browser.frames.push(frame(
        "frame-3",
        Some("frame-2"),
        &format!("{FRAME}/card"),
        vec![element("#pw", "input")],
    ));
    refused_with(
        &run(&s, &mut browser),
        "no element of the page matches the selector",
    );
    assert!(!browser.holds_password());
    // Named, in another process: the node attaches to the frame's own target.
    let s = setup(vec![op(fill_value(fill))]);
    let mut browser = page();
    browser.targets.push((
        "frame-2".into(),
        "iframe".into(),
        format!("{FRAME}/card"),
        false,
    ));
    browser.hooks.oopif = Some("frame-2".into());
    let filled = run(&s, &mut browser).unwrap();
    assert_eq!(filled.outcome, "submitted");
    assert_eq!(
        browser
            .methods
            .iter()
            .filter(|m| *m == "Target.attachToTarget")
            .count(),
        2
    );
}

#[test]
fn ambiguous_or_wrong_elements_get_nothing() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0].elements.push(element("#pw", "input"));
    refused_with(
        &run(&s, &mut browser),
        "a selector matches more than one element",
    );
    assert!(!browser.holds_password());
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0]
        .elements
        .iter_mut()
        .find(|e| e.selector == "#pw")
        .unwrap()
        .kind = "div";
    refused_with(
        &run(&s, &mut browser),
        "the element is not of the kind the step needs",
    );
    assert!(!browser.holds_password());
}

// ---------------------------------------------------------------- forged answers

#[test]
fn forged_answers_end_the_fill() {
    let cases: [(&str, usize, Forge); 6] = [
        ("Target.getTargets", 1, Forge::WrongId),
        ("Page.getFrameTree", 2, Forge::OtherSession),
        ("Page.getFrameTree", 1, Forge::Duplicate),
        ("Page.createIsolatedWorld", 1, Forge::Binary),
        ("Runtime.callFunctionOn", 1, Forge::NotJson),
        ("Runtime.callFunctionOn", 4, Forge::NotOk),
    ];
    for (method, n, forge) in cases {
        let s = setup(vec![login()]);
        let mut browser = Browser::login_page();
        browser.hooks.forge = Some((method.into(), n, forge));
        let result = run(&s, &mut browser);
        assert!(result.is_err(), "{method} #{n}");
        assert!(
            !browser.holds_password(),
            "{method} #{n}: the password reached the page"
        );
        no_secret_out(&s, &result);
        let (_, ok) = closed_entry(&s);
        assert!(!ok, "{method} #{n}");
    }
}

#[test]
fn a_browser_error_that_echoes_the_value_reaches_nobody() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    // The 4th call is the password's fill; its error message carries the params back.
    browser.hooks.forge = Some(("Runtime.callFunctionOn".into(), 4, Forge::ErrorEcho));
    let result = run(&s, &mut browser);
    refused_with(&result, "the page changed between the check and the fill");
    no_secret_out(&s, &result);
}

// ---------------------------------------------------------------- what reaches the caller

#[test]
fn events_that_carry_the_value_are_never_passed_back() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.echo_events = true;
    browser.hooks.flood = 3;
    let result = run(&s, &mut browser);
    assert!(result.is_ok());
    no_secret_out(&s, &result);
    let filled = result.unwrap();
    let text = serde_json::to_string(&filled).unwrap();
    assert!(!text.contains("Debug.echo") && !text.contains("lifecycle"));
}

#[test]
fn the_caller_cannot_issue_cdp_commands_through_the_node() {
    // A relay of the caller's frames is refused when the policy is signed.
    let mut value = fill_value(login_fill());
    value["steps"][3] =
        json!({"do": "return", "relay": {"frames": [{"kind": "text"}], "server": true}});
    let err = policy_of(vec![op(value)]).validate().unwrap_err();
    assert!(
        err.to_string().contains("a browser return takes nothing"),
        "{err}"
    );
    // So are a response projection, a receive and a template send after the handshake.
    let mut value = fill_value(login_fill());
    value["steps"][3] = json!({"do": "return", "response": {"body": "all"}});
    assert!(policy_of(vec![op(value)]).validate().is_err());
    let mut value = fill_value(login_fill());
    value["steps"].as_array_mut().unwrap().insert(
        3,
        json!({"do": "receive", "capture": [{"source": {"from": "all"},
               "into": {"kind": "temp", "name": "page", "secret": false}}]}),
    );
    assert!(policy_of(vec![op(value)]).validate().is_err());
    let mut value = fill_value(login_fill());
    value["steps"][2] = json!({"do": "send", "frame": "text",
                               "template": "{\"id\":1,\"method\":\"Runtime.evaluate\"}"});
    assert!(policy_of(vec![op(value)]).validate().is_err());
    // At run time: a streaming call, a stream call or a derivation is refused before
    // anything reaches the endpoint.
    let s = setup(vec![login()]);
    for body in [
        Body::Socket { request: None },
        Body::Stream {
            destination: Destination {
                host: "cdp.browser.test".into(),
                port: 443,
            },
            exchanges: vec![engine::node::CallerExchange {
                send: br#"{"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}"#
                    .to_vec(),
                until: vec![b"}".to_vec()],
            }],
        },
        Body::derive(b"x"),
    ] {
        let mut browser = Browser::login_page();
        let call = sign(&s, "login", body);
        assert!(s.node.run(&call, &mut browser).result.is_err());
        assert!(browser.methods.is_empty(), "a command reached the endpoint");
    }
}

#[test]
fn a_value_that_is_not_utf8_is_refused_before_the_page() {
    let s = setup_with(vec![login()], b"\xff\xfe-not-utf8");
    let mut browser = Browser::login_page();
    refused_with(&run(&s, &mut browser), "a fill value that is not UTF-8");
    let fills = browser
        .methods
        .iter()
        .filter(|m| *m == "Runtime.callFunctionOn")
        .count();
    // The username's lookup and fill, then the password's lookup; no fill of it.
    assert_eq!(fills, 3);
}

// ---------------------------------------------------------------- limits

#[test]
fn a_message_over_the_limit_ends_the_fill() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.huge = Some(cdp::MAX_MESSAGE + 10);
    let result = run(&s, &mut browser);
    assert!(
        matches!(&result, Err(Error::Transport(f)) if f.kind == TransportKind::TooLarge),
        "{:?}",
        result.as_ref().err().map(ToString::to_string)
    );
    assert!(!browser.holds_password());
}

#[test]
fn too_many_events_end_the_fill() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.flood = MAX_CDP_EVENTS + 1;
    let result = run(&s, &mut browser);
    assert!(matches!(result, Err(Error::Budget { what: "CDP events" })));
    assert!(!browser.holds_password());
    assert_eq!(closed_entry(&s), ("limit".into(), false));
}

#[test]
fn a_silent_endpoint_hits_the_idle_limit() {
    let value = with_limits(fill_value(login_fill()), json!({"idle_ms": 200}));
    let s = setup(vec![op(value)]);
    let mut browser = Browser::login_page();
    browser.hooks.stall_after = Some(2);
    let started = std::time::Instant::now();
    let result = run(&s, &mut browser);
    assert!(matches!(&result, Err(Error::Transport(f)) if f.kind == TransportKind::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(closed_entry(&s), ("idle".into(), false));
}

#[test]
fn a_chatty_endpoint_hits_the_duration_limit() {
    let value = with_limits(
        fill_value(login_fill()),
        json!({"idle_ms": 5000, "duration_ms": 400}),
    );
    let s = setup(vec![op(value)]);
    let mut browser = Browser::login_page();
    browser.hooks.stall_after = Some(2);
    browser.hooks.stall_chatty = true;
    let started = std::time::Instant::now();
    let result = run(&s, &mut browser);
    assert!(matches!(&result, Err(Error::Transport(f)) if f.kind == TransportKind::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(closed_entry(&s), ("duration".into(), false));
}

#[test]
fn the_byte_limit_ends_the_fill() {
    let value = with_limits(fill_value(login_fill()), json!({"bytes": 1500}));
    let s = setup(vec![op(value)]);
    let mut browser = Browser::login_page();
    let result = run(&s, &mut browser);
    assert!(
        matches!(result, Err(Error::Budget { .. })),
        "{:?}",
        result.as_ref().err().map(ToString::to_string)
    );
    assert_eq!(closed_entry(&s), ("bytes".into(), false));
}

#[test]
fn an_element_that_never_appears_ends_the_fill_after_the_wait() {
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.frames[0].elements.retain(|e| e.selector != "#pw");
    let started = std::time::Instant::now();
    refused_with(
        &run(&s, &mut browser),
        "no element of the page matches the selector",
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(300) && waited < Duration::from_secs(5));
}

#[test]
fn policy_bounds_of_a_fill() {
    let refuse = |fill: Value, why: &str| {
        let err = policy_of(vec![op(fill_value(fill))])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains(why), "{err}");
    };
    let mut f = login_fill();
    f["fields"] = json!(
        (0..17)
            .map(|i| json!({"selector": format!("#f{i}"), "template": "{{username}}"}))
            .collect::<Vec<_>>()
    );
    refuse(f, "1 to 16 fields");
    let mut f = login_fill();
    f["fields"][0]["selector"] = json!("a".repeat(257));
    refuse(f, "a selector is 1 to 256 bytes");
    let mut f = login_fill();
    f["fields"][0]["selector"] = json!("#id\n");
    refuse(f, "a selector is 1 to 256 bytes");
    let mut f = login_fill();
    f["wait_ms"] = json!(30_001);
    refuse(f, "wait_ms is at most 30000");
    let mut f = login_fill();
    f["origin"] = json!("http://login.example.com");
    refuse(f, "the page origin is https://host");
    let mut f = login_fill();
    f["origin"] = json!("https://login.example.com/");
    refuse(f, "the page origin is https://host");
    let mut f = login_fill();
    f["fields"][1]["frame"] = json!("https://*.example.org");
    refuse(f, "a frame origin is https://host");
    let mut f = login_fill();
    f["navigate"] = json!("/../admin");
    refuse(f, "navigate is a path");
    let mut f = login_fill();
    f["fields"][1]["selector"] = json!("#id");
    refuse(f, "each field of a fill is a different element");
    let mut f = login_fill();
    f["fields"][1]["template"] = json!("{{ tls_exporter(\"x\", \"\", 32) }}");
    refuse(f, "tls_exporter");
    let value = with_limits(fill_value(login_fill()), json!({"duration_ms": 300_001}));
    let err = policy_of(vec![op(value)]).validate().unwrap_err();
    assert!(err.to_string().contains("at most 300000 ms"), "{err}");
    let mut value = fill_value(login_fill());
    for _ in 0..8 {
        value["steps"]
            .as_array_mut()
            .unwrap()
            .insert(2, json!({"do": "send", "fill": login_fill()}));
    }
    let err = policy_of(vec![op(value)]).validate().unwrap_err();
    assert!(err.to_string().contains("at most 8 fills"), "{err}");
    // A fill on another kind of connection, and run or await on a browser.
    let value = json!({"name": "login", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "login.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/"}, "fill": login_fill()},
        {"do": "return"}]});
    assert!(policy_of(vec![op(value)]).validate().is_err());
    let mut value = fill_value(login_fill());
    value["steps"].as_array_mut().unwrap().insert(
        2,
        json!({"do": "await", "challenge": {"kind": "sms", "hint": "code", "into": "otp"}}),
    );
    assert!(policy_of(vec![op(value)]).validate().is_err());
    // A browser operation needs a fill before its return.
    let mut value = fill_value(login_fill());
    value["steps"].as_array_mut().unwrap().remove(2);
    assert!(policy_of(vec![op(value)]).validate().is_err());
}

// ---------------------------------------------------------------- summary

#[test]
fn the_summary_flags_browser_fills_and_where_the_secret_goes() {
    let policy = policy_of(vec![login()]);
    let summary = engine::policy::summarize(&policy, None);
    let flag = summary
        .flags
        .iter()
        .find(|f| f.code == FlagCode::BrowserFill)
        .expect("browser_fill");
    assert!(flag.detail.contains(PAGE) && flag.detail.contains("cdp.browser.test:443"));
    assert!(
        !summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::FrameOrigin)
    );
    let password = summary
        .secrets
        .iter()
        .find(|s| s.field == "password")
        .unwrap();
    let browser_use = password
        .uses
        .iter()
        .find(|u| matches!(u.form, Form::BrowserField { .. }))
        .expect("a browser field use");
    assert!(
        browser_use
            .destinations
            .iter()
            .any(|p| p.scheme == "https" && p.host == "login.example.com")
    );
    assert!(
        browser_use
            .destinations
            .iter()
            .any(|p| p.scheme == "wss" && p.host == "cdp.browser.test")
    );
    assert!(
        policy
            .summary()
            .iter()
            .any(|l| l.contains("fill the page at https://login.example.com"))
    );
    assert!(policy.summary().iter().any(|l| l.contains("! the browser")));
    // Against the previous version, any change of a fill is wider.
    let mut moved = login_fill();
    moved["origin"] = json!("https://login.example.net");
    let current = policy_of(vec![op(fill_value(moved))]);
    let diff = engine::policy::summarize(&current, Some(&policy));
    assert!(
        diff.flags
            .iter()
            .any(|f| f.code == FlagCode::Wider && f.detail.contains("the browser fill changed"))
    );
}
