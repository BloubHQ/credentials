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
use engine::approval::ApprovalSummary;
use engine::call::{Body, Output, SignedCall};
use engine::cdp::{self, WebOrigin};
use engine::egress::{Arrived, ClientIdentity, Stream, Transport, Version, Versions};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::item::{ItemBinding, ItemFill, KindSchema, RoleField, ShapeConnection};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink};
use engine::node::Clock;
use engine::node::{Filled, MAX_CDP_EVENTS, Node, SystemClock};
use engine::policy::Element;
use engine::policy::summary::{FlagCode, Form};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy};
use engine::session::Pending;
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
    /// A header of the handshake's answer (the endpoint's exclusive grant).
    grant: Option<(String, String)>,
    /// After the n-th command of this method, another client does something.
    during: Option<(String, usize, During)>,
    /// The browser answers the history reset but keeps the history.
    keep_history: bool,
}

/// What another client of the browser does in the middle of a fill.
#[derive(Clone)]
enum During {
    /// Attaches to the target of this id.
    Attach(String),
    /// Opens a page at this URL.
    Open(String),
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
    /// The documents the top frame left, with the values their elements held (the
    /// back/forward cache keeps a document as it was).
    history: Vec<Vec<El>>,
    /// Every value a fill set, by selector, in order.
    typed: Vec<(String, String)>,
    /// How many submits ran.
    submits: usize,
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

    /// True when a document the top frame left still holds `secret`.
    fn history_holds(&self, secret: &str) -> bool {
        self.history
            .iter()
            .flatten()
            .any(|e| !secret.is_empty() && e.value.contains(secret))
    }

    /// True when a fill typed `secret` into any element.
    fn typed_any(&self, secret: &str) -> bool {
        self.typed.iter().any(|(_, v)| v.contains(secret))
    }

    /// The value typed into `selector`, if one was.
    fn typed_into(&self, selector: &str) -> Option<String> {
        self.typed
            .iter()
            .rev()
            .find(|(s, _)| s == selector)
            .map(|(_, v)| v.clone())
    }

    fn navigate_top(&mut self, url: &str) {
        let top = self.frames.iter_mut().find(|f| f.parent.is_none()).unwrap();
        self.history.push(top.elements.clone());
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
        if let Some((m, at, during)) = self.hooks.during.clone()
            && m == method
            && at == n
        {
            self.hooks.during = None;
            match during {
                During::Attach(target) => {
                    self.targets.iter_mut().find(|t| t.0 == target).unwrap().3 = true;
                }
                During::Open(url) => {
                    self.targets
                        .push(("page-9".into(), "page".into(), url, false));
                }
            }
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
            "Page.resetNavigationHistory" => {
                if !self.hooks.keep_history {
                    self.history.clear();
                }
                Ok(json!({}))
            }
            "Page.getNavigationHistory" => {
                let mut entries: Vec<Value> = self
                    .history
                    .iter()
                    .map(|_| json!({"id": 1, "url": "https://old.example/", "title": "t"}))
                    .collect();
                entries.push(json!({"id": 2, "url": self.frames[0].url, "title": "t"}));
                Ok(json!({"currentIndex": entries.len() - 1, "entries": entries}))
            }
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
            self.typed
                .push((selector.clone(), args[0].as_str().unwrap().to_string()));
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
            self.submits += 1;
            if self.hooks.submit_navigates {
                // To another document of the page's own origin.
                let top = self.frames.iter().find(|f| f.parent.is_none()).unwrap();
                let origin = WebOrigin::of_url(&top.url).unwrap().serialize();
                self.navigate_top(&format!("{origin}/home"));
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
        let grant = self
            .hooks
            .grant
            .as_ref()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{grant}\r\n",
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

const ALLOWED: [&str; 10] = [
    "Target.getTargets",
    "Target.attachToTarget",
    "Target.detachFromTarget",
    "Page.navigate",
    "Page.getFrameTree",
    "Page.createIsolatedWorld",
    "Runtime.callFunctionOn",
    "Runtime.releaseObjectGroup",
    "Page.resetNavigationHistory",
    "Page.getNavigationHistory",
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
    // A wrong answer to the first clear: the fill fails, and blanks on its way out.
    browser.hooks.forge = Some(("Runtime.callFunctionOn".into(), 7, Forge::NotOk));
    assert!(run(&s, &mut browser).is_err());
    assert_eq!(browser.typed_into("#id").as_deref(), Some(USER));
    assert!(
        browser.typed_into("#pw").as_deref() == Some(PASSWORD),
        "the password field did not get the password"
    );
    assert!(
        !browser.holds_password(),
        "a failed fill left the password in the page"
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
        browser.typed_into("#pw").as_deref() == Some(PASSWORD),
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
    // The username's lookup and fill, then the password's lookup; no fill of it; then the
    // username field blanked again, since the fill failed after it.
    assert_eq!(fills, 4);
    assert_eq!(browser.typed_into("#id").as_deref(), Some(USER));
    assert_eq!(
        browser.value_of("#id").as_deref(),
        Some(""),
        "the field kept the user name"
    );
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

// ---------------------------------------------------------------- the agent's controller

const GRANT: (&str, &str) = ("cdp-exclusive", "granted");

fn granted_open(mut value: Value, leave: &str) -> Value {
    value["steps"][0]["browser"] =
        json!({"exclusive": {"header": GRANT.0, "value": GRANT.1}, "leave": leave});
    value
}

#[test]
fn without_the_endpoints_exclusive_grant_nothing_is_sent() {
    let s = setup(vec![op(granted_open(fill_value(login_fill()), "blank"))]);
    // No grant in the answer, a wrong value, a value with more around it, another header:
    // not one command.
    for grant in [
        None,
        Some((GRANT.0.to_string(), "denied".to_string())),
        Some((GRANT.0.to_string(), "granted, maybe".to_string())),
        Some(("cdp-shared".to_string(), GRANT.1.to_string())),
    ] {
        let mut browser = Browser::login_page();
        browser.hooks.grant = grant;
        let result = run(&s, &mut browser);
        refused_with(
            &result,
            "the endpoint did not hand the browser to the node alone",
        );
        assert!(browser.methods.is_empty(), "a command reached the endpoint");
        assert!(!browser.typed_any(PASSWORD));
        no_secret_out(&s, &result);
    }
    // The grant, its header name in any case: the fill runs.
    let mut browser = Browser::login_page();
    browser.hooks.grant = Some(("CDP-Exclusive".into(), GRANT.1.into()));
    browser.hooks.submit_navigates = true;
    assert_eq!(run(&s, &mut browser).unwrap().outcome, "navigated");
    // Without `exclusive`, the summary says the controller may still be there.
    let shared = engine::policy::summarize(&policy_of(vec![login()]), None);
    assert!(
        shared
            .flags
            .iter()
            .any(|f| f.code == FlagCode::BrowserShared)
    );
    let held_policy = policy_of(vec![op(granted_open(fill_value(login_fill()), "blank"))]);
    let held = engine::policy::summarize(&held_policy, None);
    assert!(!held.flags.iter().any(|f| f.code == FlagCode::BrowserShared));
    // Dropping the grant is wider.
    let diff = engine::policy::summarize(&policy_of(vec![login()]), Some(&held_policy));
    assert!(diff.flags.iter().any(|f| {
        f.code == FlagCode::Wider
            && f.detail
                .contains("how the browser is kept to the node changed")
    }));
}

#[test]
fn a_client_attached_anywhere_in_the_browser_stops_the_fill() {
    // A worker of the origin: it would see the request that carries the values.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.targets.push((
        "sw-1".into(),
        "service_worker".into(),
        format!("{PAGE}/sw.js"),
        true,
    ));
    refused_with(
        &run(&s, &mut browser),
        "another client is attached to the browser",
    );
    assert!(!browser.methods.iter().any(|m| m == "Target.attachToTarget"));
    assert!(browser.typed.is_empty());
}

fn with_worker(mut browser: Browser) -> Browser {
    browser.targets.push((
        "sw-1".into(),
        "service_worker".into(),
        format!("{PAGE}/sw.js"),
        false,
    ));
    browser
}

#[test]
fn a_client_that_attaches_during_the_fill_gets_no_further_value() {
    // The agent attaches to a worker of the origin right after the user name is typed (the
    // 2nd call of a function is the user name's fill).
    let s = setup(vec![login()]);
    let mut browser = with_worker(Browser::login_page());
    browser.hooks.during = Some((
        "Runtime.callFunctionOn".into(),
        2,
        During::Attach("sw-1".into()),
    ));
    let result = run(&s, &mut browser);
    refused_with(
        &result,
        "another client attached to the browser during the fill",
    );
    assert_eq!(browser.typed_into("#id").as_deref(), Some(USER));
    assert_eq!(browser.value_of("#id").as_deref(), Some(""), "not blanked");
    assert!(
        !browser.typed_any(PASSWORD),
        "the password reached the page"
    );
    no_secret_out(&s, &result);
    // It opens a second tab at the origin instead.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.during = Some((
        "Runtime.callFunctionOn".into(),
        2,
        During::Open(format!("{PAGE}/spy")),
    ));
    refused_with(
        &run(&s, &mut browser),
        "another page at the policy's origin opened during the fill",
    );
    assert!(!browser.typed_any(PASSWORD));
    // Between the last value and the submit (the 5th call is the submit's lookup): no
    // submit, and both values blanked on the way out.
    let s = setup(vec![login()]);
    let mut browser = with_worker(Browser::login_page());
    browser.hooks.during = Some((
        "Runtime.callFunctionOn".into(),
        5,
        During::Attach("sw-1".into()),
    ));
    refused_with(
        &run(&s, &mut browser),
        "another client attached to the browser during the fill",
    );
    assert!(browser.typed_any(PASSWORD), "the password was not typed");
    assert_eq!(browser.submits, 0);
    assert!(!browser.holds_password(), "the password stayed in the page");
}

#[test]
fn values_do_not_wait_in_the_page_for_the_controller() {
    // The page stays, `leave: reload`: blanked, then loaded again with a GET at the origin.
    let s = setup(vec![op(granted_open(fill_value(login_fill()), "reload"))]);
    let mut browser = Browser::login_page();
    browser.hooks.grant = Some((GRANT.0.into(), GRANT.1.into()));
    let loader = browser.frames[0].loader;
    let result = run(&s, &mut browser);
    let filled = result.as_ref().unwrap();
    assert_eq!(filled.outcome, "reloaded");
    assert_eq!(filled.origin, PAGE);
    assert_eq!(closed_entry(&s), ("reloaded".into(), true));
    assert!(
        browser.frames[0].loader > loader,
        "the document was not replaced"
    );
    assert_eq!(browser.frames[0].url, format!("{PAGE}/"));
    assert!(!browser.holds_password(), "the page holds the password");
    assert!(
        !browser.history_holds(PASSWORD),
        "the history holds the filled document"
    );
    assert!(browser.history.is_empty());
    only_allowed_methods(&browser);
    no_secret_out(&s, &result);
    // The page navigates: the document it left (with the values) leaves the history too.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.submit_navigates = true;
    let result = run(&s, &mut browser);
    assert_eq!(result.unwrap().outcome, "navigated");
    assert!(
        !browser.history_holds(PASSWORD),
        "the back/forward cache holds the filled document"
    );
    // A browser that keeps the history: refused, never reported as done.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.hooks.submit_navigates = true;
    browser.hooks.keep_history = true;
    refused_with(
        &run(&s, &mut browser),
        "the browser kept the filled page in its history",
    );
    // `leave: blank` (the default) blanks a page that stays and clears its history too.
    let s = setup(vec![login()]);
    let mut browser = Browser::login_page();
    browser.history.push(vec![element("#old", "input")]);
    assert_eq!(run(&s, &mut browser).unwrap().outcome, "submitted");
    assert!(browser.history.is_empty());
    assert!(!browser.holds_password());
}

// ---------------------------------------------------------------- typed items

#[derive(Clone, Copy)]
struct Fixed(u64);

impl Clock for Fixed {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

struct Typed {
    node: Node<MemorySink, Fixed>,
    record: engine::record::Record,
    device: DeviceKey,
    now: u64,
}

/// RFC 6238's SHA-1 key, `12345678901234567890`, in base32.
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SHOP: &str = "https://shop.example.com";
const PSP: &str = "https://pay.example.org";
const NUMBER: &str = "4242424242424242";
const CVC: &str = "737";
/// 2026-11-25T00:00:00Z.
const NOW_MS: u64 = 1_795_564_800_000;

fn typed_op(fills: Vec<Value>) -> Operation {
    let mut steps = vec![
        json!({"do": "open", "connection": "browser",
               "destinations": [{"host": "cdp.browser.test", "port": 443}],
               "browser": {"exclusive": {"header": GRANT.0, "value": GRANT.1},
                           "leave": "reload"}}),
        json!({"do": "send",
               "request": {"from": "fixed", "method": "GET", "path": "/devtools/browser/b1"}}),
    ];
    steps.extend(fills.into_iter().map(|f| json!({"do": "send", "fill": f})));
    steps.push(json!({"do": "return"}));
    op(json!({"name": "login", "steps": steps}))
}

fn login_binding() -> ItemBinding {
    ItemBinding::reviewed("login").pin("origin", PAGE)
}

fn item_fill(origin: Option<&str>, roles: &[(&str, &str, Option<&str>)], submit: &str) -> ItemFill {
    ItemFill {
        origin: origin.map(str::to_string),
        fields: roles
            .iter()
            .map(|(role, selector, frame)| RoleField {
                role: role.to_string(),
                selector: selector.to_string(),
                frame: frame.map(str::to_string),
            })
            .collect(),
        submit: Element {
            selector: submit.into(),
            frame: None,
        },
        navigate: None,
        wait_ms: Some(300),
    }
}

fn login_fill_typed(roles: &[(&str, &str)]) -> Value {
    let roles: Vec<(&str, &str, Option<&str>)> =
        roles.iter().map(|(r, s)| (*r, *s, None)).collect();
    let fill = item_fill(None, &roles, "form#login");
    serde_json::to_value(login_binding().browser_fill(&fill).unwrap()).unwrap()
}

fn typed_policy(
    binding: ItemBinding,
    fields: Vec<FieldSpec>,
    operations: Vec<Operation>,
) -> Policy {
    Policy {
        item: Some(binding),
        fields,
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: operations.iter().map(|o| o.name().to_string()).collect(),
            limit: None,
        }],
        operations,
    }
}

fn login_policy(operations: Vec<Operation>) -> Policy {
    typed_policy(
        login_binding(),
        vec![
            FieldSpec::public("origin"),
            FieldSpec::secret("username"),
            FieldSpec::guessable("password"),
            FieldSpec::secret("totp"),
        ],
        operations,
    )
}

fn card_policy(operations: Vec<Operation>) -> Policy {
    typed_policy(
        ItemBinding::reviewed("card"),
        vec![
            FieldSpec::guessable("number"),
            FieldSpec::guessable("expiry"),
            FieldSpec::guessable("cvc"),
            FieldSpec::public("holder"),
        ],
        operations,
    )
}

fn typed_setup(policy: Policy, values: &[(&str, &str)], now: u64) -> Typed {
    policy.validate().unwrap();
    let device = DeviceKey::generate();
    let user = [9u8; 32];
    let mut fields = Fields::new();
    for (name, value) in values {
        fields.insert(name, value.as_bytes().to_vec()).unwrap();
    }
    let record = engine::record::Record::seal(
        &UserKey::from_bytes(&mut user.clone()),
        "rec-t",
        "user-t",
        device.sign_policy(policy).unwrap(),
        &fields,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), Fixed(now));
    let terms = GrantTerms::at("user-t", now, Duration::from_secs(3600)).pin(&record);
    node.grant(
        &device
            .grant(
                &UserKey::from_bytes(&mut user.clone()),
                &node.identity(),
                terms,
            )
            .unwrap(),
    )
    .unwrap();
    Typed {
        node,
        record,
        device,
        now,
    }
}

fn login_setup(operations: Vec<Operation>, now: u64) -> Typed {
    typed_setup(
        login_policy(operations),
        &[
            ("origin", PAGE),
            ("username", USER),
            ("password", PASSWORD),
            ("totp", SEED),
        ],
        now,
    )
}

fn card_values() -> [(&'static str, &'static str); 4] {
    [
        ("number", NUMBER),
        ("expiry", "12/40"),
        ("cvc", CVC),
        ("holder", "Jane Doe"),
    ]
}

fn run_typed(t: &Typed, browser: &mut Browser, body: Body) -> engine::Result<Output> {
    let call = caller_key()
        .sign_call_at(
            "app",
            &t.node.public_key(),
            t.record.clone(),
            "login",
            body,
            t.now,
        )
        .unwrap();
    t.node.run(&call, browser).result
}

fn fill_of(output: engine::Result<Output>) -> engine::Result<Filled> {
    match output {
        Ok(Output::Fill(filled)) => Ok(filled),
        Ok(other) => panic!("not a fill: {:?}", core::mem::discriminant(&other)),
        Err(e) => Err(e),
    }
}

fn approval_of(output: engine::Result<Output>) -> ([u8; 16], ApprovalSummary) {
    match output {
        Ok(Output::Pending(Pending::ApprovalRequired { id, summary })) => (id, *summary),
        other => panic!("not waiting for approval: {:?}", other.err()),
    }
}

fn login_browser() -> Browser {
    let mut browser = Browser::login_page();
    browser.hooks.grant = Some((GRANT.0.into(), GRANT.1.into()));
    browser.frames[0].elements.push(element("#otp", "input"));
    browser
}

/// RFC 6238 by hand, over `ring`'s HMAC-SHA-1 (not the node's code): 6 digits, 30 s.
fn totp_by_hand(seed: &[u8], unix: u64) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let tag = ring::hmac::sign(&key, &(unix / 30).to_be_bytes());
    let h = tag.as_ref();
    let at = (h[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]) & 0x7fff_ffff;
    format!("{:06}", code % 1_000_000)
}

#[test]
fn a_login_fills_its_user_name_password_and_one_time_code() {
    // RFC 6238 appendix B, SHA-1: the last six digits of 07081804, 89005924, 69279037.
    for (unix, code) in [
        (1_111_111_109u64, "081804"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
    ] {
        assert_eq!(totp_by_hand(b"12345678901234567890", unix), code);
        let operation = typed_op(vec![login_fill_typed(&[
            ("username", "#id"),
            ("password", "#pw"),
            ("totp", "#otp"),
        ])]);
        let t = login_setup(vec![operation], unix * 1000);
        let mut browser = login_browser();
        browser.hooks.submit_navigates = true;
        let filled = fill_of(run_typed(&t, &mut browser, Body::http_fixed())).unwrap();
        assert_eq!(filled.outcome, "navigated");
        assert_eq!(filled.fields, 3);
        assert_eq!(browser.typed_into("#id").as_deref(), Some(USER));
        assert!(
            browser.typed_into("#pw").as_deref() == Some(PASSWORD),
            "the password field did not get the password"
        );
        assert!(
            browser.typed_into("#otp").as_deref() == Some(code),
            "the code is not RFC 6238's at {unix}"
        );
        assert!(!browser.history_holds(PASSWORD));
        only_allowed_methods(&browser);
        let shown = serde_json::to_string(&filled).unwrap();
        assert!(!shown.contains("S3cret") && !shown.contains(code));
    }
}

#[test]
fn a_login_fills_only_a_page_at_its_origin_exactly() {
    let operation = typed_op(vec![login_fill_typed(&[
        ("username", "#id"),
        ("password", "#pw"),
    ])]);
    for url in [
        "https://sub.login.example.com/signin",
        "https://login.example.com:8443/signin",
        "http://login.example.com/signin",
        "https://xn--lgin-qqa.example.com/signin",
        "https://login.example.com.evil.test/signin",
        "https://example.com/signin",
    ] {
        let t = login_setup(vec![operation.clone()], NOW_MS);
        let mut browser = login_browser();
        browser.targets[0].2 = url.into();
        browser.frames[0].url = url.into();
        let result = fill_of(run_typed(&t, &mut browser, Body::http_fixed()));
        refused_with(&result, "no page of the browser is at the policy's origin");
        assert!(browser.typed.is_empty(), "{url}: a value reached the page");
    }
    // A policy cannot move the fill elsewhere, even signed: the origin is the pin.
    let mut moved = login_fill_typed(&[("password", "#pw")]);
    moved["origin"] = json!("https://sub.login.example.com");
    let err = login_policy(vec![typed_op(vec![moved])])
        .validate()
        .unwrap_err();
    assert!(
        err.to_string().contains("at its pinned origin exactly"),
        "{err}"
    );
    let elsewhere = item_fill(
        Some("https://login.example.com:8443"),
        &[("password", "#pw", None)],
        "form#login",
    );
    assert!(login_binding().browser_fill(&elsewhere).is_err());
}

#[test]
fn a_login_fills_the_top_frame_only() {
    // The password field sits in a frame of another origin (an attacker's iframe), or in a
    // child frame of the same origin: the selector never resolves into either.
    for frame_url in [
        "https://evil.example.net/x",
        "https://login.example.com/inner",
    ] {
        let operation = typed_op(vec![login_fill_typed(&[
            ("username", "#id"),
            ("password", "#pw"),
        ])]);
        let t = login_setup(vec![operation], NOW_MS);
        let mut browser = login_browser();
        browser.frames[0].elements.retain(|e| e.selector != "#pw");
        browser.frames.push(frame(
            "frame-2",
            Some("page-1"),
            frame_url,
            vec![element("#pw", "input")],
        ));
        let result = fill_of(run_typed(&t, &mut browser, Body::http_fixed()));
        refused_with(&result, "no element of the page matches the selector");
        assert!(
            !browser.typed_any(PASSWORD),
            "{frame_url}: the password reached a frame"
        );
        assert!(!browser.holds_password());
    }
    // A policy that names a frame is refused for a login.
    let mut framed = login_fill_typed(&[("password", "#pw")]);
    framed["fields"][0]["frame"] = json!(PAGE);
    let err = login_policy(vec![typed_op(vec![framed])])
        .validate()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("the kind fills the top frame only"),
        "{err}"
    );
}

#[test]
fn a_typed_fill_is_the_kinds_and_nothing_else() {
    let refuse = |operation: Operation, why: &str| {
        let err = login_policy(vec![operation])
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains(why), "{err}");
    };
    // A value that is not a role's: the password with more around it, encoded, or joined.
    for template in [
        "{{password}}x",
        "{{ b64(password) }}",
        "{{username}}{{password}}",
    ] {
        let mut fill = login_fill_typed(&[("password", "#pw")]);
        fill["fields"][0]["template"] = json!(template);
        refuse(typed_op(vec![fill]), "one of the kind's role values");
    }
    // The same role twice in one fill.
    let mut twice = login_fill_typed(&[("password", "#pw"), ("username", "#id")]);
    twice["fields"][1]["template"] = json!("{{password}}");
    refuse(typed_op(vec![twice]), "each at most once");
    // Without the exclusive grant, or with `leave: blank`.
    let fill = login_fill_typed(&[("password", "#pw")]);
    let mut value = serde_json::to_value(typed_op(vec![fill.clone()])).unwrap();
    value["steps"][0]["browser"]
        .as_object_mut()
        .unwrap()
        .remove("exclusive");
    refuse(op(value), "exclusive grant and leave reload");
    let mut value = serde_json::to_value(typed_op(vec![fill.clone()])).unwrap();
    value["steps"][0]["browser"]["leave"] = json!("blank");
    refuse(op(value), "exclusive grant and leave reload");
    // The handshake carries a field of the item to the endpoint.
    let mut value = serde_json::to_value(typed_op(vec![fill])).unwrap();
    value["steps"][1]["inject"] = json!([{"target": {"kind": "header", "name": "Authorization"},
                                          "template": "Bearer {{password}}"}]);
    refuse(op(value), "carries none of its fields");
    // `browser` on another connection.
    let mut value = fill_value(login_fill());
    value["steps"][0]["connection"] = json!("websocket");
    value["steps"][0]["browser"] = json!({"leave": "reload"});
    assert!(policy_of(vec![op(value)]).validate().is_err());
    // The builder knows only the kind's roles.
    let unknown = item_fill(None, &[("session", "#s", None)], "form");
    assert!(login_binding().browser_fill(&unknown).is_err());
    // A card has no origin of its own: the owner names the merchant's.
    let nowhere = item_fill(None, &[("number", "#cc", None)], "form");
    assert!(
        ItemBinding::reviewed("card")
            .browser_fill(&nowhere)
            .is_err()
    );
    // A typed fill is summarized like any: where each secret goes, and the browser flagged.
    let policy = login_policy(vec![typed_op(vec![login_fill_typed(&[
        ("username", "#id"),
        ("password", "#pw"),
    ])])]);
    let summary = engine::policy::summarize(&policy, None);
    assert!(
        summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::BrowserFill)
    );
    assert!(
        !summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::BrowserShared)
    );
    let password = summary
        .secrets
        .iter()
        .find(|s| s.field == "password")
        .unwrap();
    assert!(
        password
            .uses
            .iter()
            .any(|u| matches!(u.form, Form::BrowserField { .. }))
    );
}

#[test]
fn kinds_hold_browser_roles_to_their_fields() {
    let rule_of = |kind: &KindSchema| match kind.validate() {
        Err(Error::KindInvalid { rule, .. }) => rule,
        other => panic!("not refused: {:?}", other.err()),
    };
    let login = engine::item::reviewed_kind("login").unwrap().clone();
    login.validate().unwrap();
    for template in ["{{ nobody }}", "plain", "{{"] {
        let mut k = login.clone();
        k.shape.browser.as_mut().unwrap().roles[0].template = template.into();
        assert_eq!(
            rule_of(&k),
            "a role's template parses and reads fields of the kind only"
        );
    }
    let mut k = login.clone();
    k.shape.browser = None;
    assert_eq!(
        rule_of(&k),
        "a kind with a browser connection names its browser roles"
    );
    let mut k = login.clone();
    k.shape
        .connections
        .retain(|c| *c != ShapeConnection::Browser);
    assert_eq!(
        rule_of(&k),
        "browser roles are for a kind with named fields and a browser connection"
    );
    let mut k = login.clone();
    k.shape.browser.as_mut().unwrap().origin = None;
    assert_eq!(
        rule_of(&k),
        "a kind whose destinations are a pinned origin fills pages at that origin only"
    );
    let mut k = login.clone();
    k.shape.browser.as_mut().unwrap().origin = Some("username".into());
    assert!(rule_of(&k).starts_with("the browser origin is a pinned field"));
    let mut k = login;
    let first = k.shape.browser.as_ref().unwrap().roles[0].clone();
    k.shape.browser.as_mut().unwrap().roles.push(first);
    assert_eq!(rule_of(&k), "1 to 16 roles of distinct names and templates");
}

fn card_browser() -> Browser {
    let mut b = Browser::default();
    b.hooks.grant = Some((GRANT.0.into(), GRANT.1.into()));
    b.targets.push((
        "page-1".into(),
        "page".into(),
        format!("{SHOP}/checkout"),
        false,
    ));
    b.frames.push(frame(
        "page-1",
        None,
        &format!("{SHOP}/checkout"),
        vec![element("#name", "input"), element("form#pay", "form")],
    ));
    b.frames.push(frame(
        "frame-2",
        Some("page-1"),
        &format!("{PSP}/card"),
        vec![
            element("#cc", "input"),
            element("#exp-m", "input"),
            element("#exp-y", "input"),
            element("#cvc", "input"),
        ],
    ));
    b.hooks.submit_navigates = true;
    b
}

fn card_fill() -> Value {
    let fill = item_fill(
        Some(SHOP),
        &[
            ("number", "#cc", Some(PSP)),
            ("expiry_month", "#exp-m", Some(PSP)),
            ("expiry_year", "#exp-y", Some(PSP)),
            ("cvc", "#cvc", Some(PSP)),
            ("holder", "#name", None),
        ],
        "form#pay",
    );
    serde_json::to_value(ItemBinding::reviewed("card").browser_fill(&fill).unwrap()).unwrap()
}

#[test]
fn every_card_fill_waits_for_the_owners_approval() {
    let t = typed_setup(
        card_policy(vec![typed_op(vec![card_fill()])]),
        &card_values(),
        NOW_MS,
    );
    let mut browser = card_browser();
    let (id, summary) = approval_of(run_typed(&t, &mut browser, Body::http_fixed()));
    // Nothing reached the endpoint before the approval: not even the handshake.
    assert!(browser.handshake.is_empty() && browser.methods.is_empty());
    // The owner sees the merchant's page and the masked card, never its secrets.
    assert_eq!(summary.origin.as_deref(), Some(SHOP));
    let text = serde_json::to_string(&summary).unwrap();
    assert!(text.contains("4242"), "the masked number is shown");
    for secret in [NUMBER, "\"737\"", "12/40"] {
        assert!(!text.contains(secret), "a secret value is in the summary");
    }
    // Not approved yet: still waiting, still nothing sent.
    approval_of(run_typed(&t, &mut browser, Body::resume(id)));
    assert!(browser.methods.is_empty());
    t.node
        .approve(&t.device.approve(&summary, t.now).unwrap())
        .unwrap();
    let filled = fill_of(run_typed(&t, &mut browser, Body::resume(id))).unwrap();
    assert_eq!(filled.outcome, "navigated");
    assert_eq!(filled.origin, SHOP);
    assert!(
        browser.typed_into("#cc").as_deref() == Some(NUMBER),
        "the number field"
    );
    assert_eq!(browser.typed_into("#exp-m").as_deref(), Some("12"));
    assert_eq!(browser.typed_into("#exp-y").as_deref(), Some("40"));
    assert!(
        browser.typed_into("#cvc").as_deref() == Some(CVC),
        "the code field"
    );
    assert_eq!(browser.typed_into("#name").as_deref(), Some("Jane Doe"));
    assert!(!browser.history_holds(NUMBER) && !browser.history_holds(CVC));
    // The approval was for that use only.
    let mut again = card_browser();
    approval_of(run_typed(&t, &mut again, Body::http_fixed()));
    assert!(again.methods.is_empty());
}

#[test]
fn a_card_goes_into_the_frame_the_policy_names_only() {
    let t = typed_setup(
        card_policy(vec![typed_op(vec![card_fill()])]),
        &card_values(),
        NOW_MS,
    );
    let mut browser = card_browser();
    browser.frames[1].url = "https://evil.example.net/card".into();
    let (id, summary) = approval_of(run_typed(&t, &mut browser, Body::http_fixed()));
    t.node
        .approve(&t.device.approve(&summary, t.now).unwrap())
        .unwrap();
    let result = fill_of(run_typed(&t, &mut browser, Body::resume(id)));
    refused_with(&result, "no element of the page matches the selector");
    assert!(!browser.typed_any(NUMBER) && !browser.typed_any(CVC));
}

#[test]
fn describe_of_a_typed_item_never_shows_a_secret() {
    let login = login_policy(vec![typed_op(vec![login_fill_typed(&[(
        "password", "#pw",
    )])])]);
    let mut fields = Fields::new();
    for (n, v) in [
        ("origin", PAGE),
        ("username", USER),
        ("password", PASSWORD),
        ("totp", SEED),
    ] {
        fields.insert(n, v.as_bytes().to_vec()).unwrap();
    }
    let text = serde_json::to_string(&engine::item::describe(&login, &fields).unwrap()).unwrap();
    assert!(text.contains("a***@example.com") && text.contains(PAGE));
    for secret in ["S3cret", SEED, USER] {
        assert!(!text.contains(secret), "a secret is in the description");
    }
    let card = card_policy(vec![typed_op(vec![card_fill()])]);
    let mut fields = Fields::new();
    for (n, v) in card_values() {
        fields.insert(n, v.as_bytes().to_vec()).unwrap();
    }
    let text = serde_json::to_string(&engine::item::describe(&card, &fields).unwrap()).unwrap();
    assert!(text.contains("4242") && text.contains("Jane Doe"));
    for secret in [NUMBER, "\"737\"", "12/40"] {
        assert!(!text.contains(secret), "a secret is in the description");
    }
}
