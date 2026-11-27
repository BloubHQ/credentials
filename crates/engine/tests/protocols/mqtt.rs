//! MQTT 3.1.1 and 5 over TLS: CONNECT with a password or a token, publications and
//! subscriptions within the policy's topics, messages back after the reflection search, and
//! the live relay of a streaming call.

use engine::call::Body;
use engine::node::Part;
use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::*;

const PASSWORD: &[u8] = b"mqtt-pass-58k";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Misbehave {
    None,
    /// Delivers a message on a topic nobody subscribed to.
    OtherTopic,
    /// Delivers a message at QoS 2.
    Qos2,
    /// Delivers the password in a message.
    Echo,
}

/// A broker: it reads packets and answers.
pub struct Broker {
    pub password: Vec<u8>,
    pub misbehave: Misbehave,
    /// Messages delivered after each SUBACK: (topic, payload).
    pub deliver: Vec<(String, Vec<u8>)>,
    /// What it saw.
    pub level: u8,
    pub client_id: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub got_password: Option<Vec<u8>>,
    pub published: Vec<(String, Vec<u8>, u8, bool)>,
    pub subscribed: Vec<(String, u8)>,
    pub unsubscribed: Vec<String>,
    pub connected: bool,
    /// The Server Keep Alive a version 5 CONNACK names, in seconds; the pings it got.
    pub server_keep_alive: Option<u16>,
    pub pings: usize,
    closed: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
}

fn string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn frame(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    let mut n = body.len();
    loop {
        let mut byte = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    out
}

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn u8(&mut self) -> u8 {
        let b = self.0[0];
        self.0 = &self.0[1..];
        b
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes([self.0[0], self.0[1]]);
        self.0 = &self.0[2..];
        v
    }
    fn string(&mut self) -> &'a [u8] {
        let n = self.u16() as usize;
        let s = &self.0[..n];
        self.0 = &self.0[n..];
        s
    }
    fn skip_props(&mut self) {
        let n = self.u8() as usize;
        assert!(n < 128);
        self.0 = &self.0[n..];
    }
}

impl Broker {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            misbehave: Misbehave::None,
            deliver: Vec::new(),
            level: 0,
            client_id: Vec::new(),
            user: None,
            got_password: None,
            published: Vec::new(),
            subscribed: Vec::new(),
            unsubscribed: Vec::new(),
            connected: false,
            server_keep_alive: None,
            pings: 0,
            closed: false,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
        }
    }

    fn publish(&mut self, topic: &str, payload: &[u8], qos: u8) {
        let mut body = Vec::new();
        string(&mut body, topic.as_bytes());
        if qos > 0 {
            body.extend_from_slice(&9u16.to_be_bytes());
        }
        if self.level == 5 {
            body.push(0);
        }
        body.extend_from_slice(payload);
        self.outbuf.extend(frame(0x30 | (qos << 1), &body));
    }

    fn handle(&mut self, first: u8, body: &[u8]) {
        let mut r = R(body);
        match first >> 4 {
            1 => {
                assert_eq!(r.string(), b"MQTT");
                self.level = r.u8();
                let flags = r.u8();
                assert_eq!(flags & 0x02, 0x02, "clean session");
                assert_eq!(flags & 0x04, 0, "no will");
                r.u16();
                if self.level == 5 {
                    r.skip_props();
                }
                self.client_id = r.string().to_vec();
                if flags & 0x80 != 0 {
                    self.user = Some(r.string().to_vec());
                }
                if flags & 0x40 != 0 {
                    self.got_password = Some(r.string().to_vec());
                }
                // [MQTT-3.1.2-22]: in 3.1.1 a password needs the user name flag.
                let ok = self.got_password.as_deref() == Some(self.password.as_slice())
                    && (self.level != 4 || flags & 0x80 != 0);
                let code = match (ok, self.level) {
                    (true, _) => 0,
                    (false, 5) => 0x86,
                    (false, _) => 4,
                };
                self.connected = ok;
                let ack = if self.level == 5 {
                    match self.server_keep_alive {
                        Some(seconds) => {
                            let [high, low] = seconds.to_be_bytes();
                            vec![0, code, 3, 0x13, high, low]
                        }
                        None => vec![0, code, 0],
                    }
                } else {
                    vec![0, code]
                };
                self.outbuf.extend(frame(0x20, &ack));
            }
            3 => {
                let qos = (first >> 1) & 3;
                let retain = first & 1 != 0;
                let topic = String::from_utf8(r.string().to_vec()).unwrap();
                let id = if qos > 0 { Some(r.u16()) } else { None };
                if self.level == 5 {
                    r.skip_props();
                }
                self.published.push((topic, r.0.to_vec(), qos, retain));
                if let Some(id) = id {
                    let mut ack = id.to_be_bytes().to_vec();
                    if self.level == 5 {
                        ack.push(0);
                    }
                    self.outbuf.extend(frame(0x40, &ack));
                }
            }
            8 => {
                let id = r.u16();
                if self.level == 5 {
                    r.skip_props();
                }
                let filter = String::from_utf8(r.string().to_vec()).unwrap();
                let qos = r.u8() & 3;
                self.subscribed.push((filter.clone(), qos));
                let mut ack = id.to_be_bytes().to_vec();
                if self.level == 5 {
                    ack.push(0);
                }
                ack.push(qos);
                self.outbuf.extend(frame(0x90, &ack));
                for (topic, payload) in self.deliver.clone() {
                    self.publish(&topic, &payload, qos);
                }
                match self.misbehave {
                    Misbehave::OtherTopic => self.publish("admin/secrets", b"x", 0),
                    Misbehave::Qos2 => self.publish(&filter.replace('+', "a"), b"x", 2),
                    Misbehave::Echo => {
                        let password = self.password.clone();
                        let mut payload = b"pw=".to_vec();
                        payload.extend(password);
                        self.publish(&filter.replace('+', "a"), &payload, 0);
                    }
                    Misbehave::None => {}
                }
            }
            10 => {
                let id = r.u16();
                if self.level == 5 {
                    r.skip_props();
                }
                self.unsubscribed
                    .push(String::from_utf8(r.string().to_vec()).unwrap());
                let mut ack = id.to_be_bytes().to_vec();
                if self.level == 5 {
                    ack.push(0);
                    ack.push(0);
                }
                self.outbuf.extend(frame(0xb0, &ack));
            }
            4 => {}
            12 => {
                self.pings += 1;
                self.outbuf.extend([0xd0, 0]);
            }
            14 => self.closed = true,
            other => panic!("packet type {other}"),
        }
    }
}

impl Peer for Broker {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        loop {
            if self.inbuf.len() < 2 {
                return;
            }
            let mut len = 0usize;
            let mut at = 1;
            loop {
                if at >= self.inbuf.len() {
                    return;
                }
                let b = self.inbuf[at];
                len |= ((b & 0x7f) as usize) << (7 * (at - 1));
                at += 1;
                if b & 0x80 == 0 {
                    break;
                }
            }
            if self.inbuf.len() < at + len {
                return;
            }
            let first = self.inbuf[0];
            let body = self.inbuf[at..at + len].to_vec();
            self.inbuf.drain(..at + len);
            self.handle(first, &body);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        self.closed
    }
}

fn mqtt_operation(version: &str) -> Operation {
    operation(json!({"name": "sensors", "steps": [
        {"do": "open", "connection": "mqtt", "version": version,
         "destinations": [{"host": "broker.example.com", "port": 8883}],
         "login": {"user": "device-7", "password": "{{password}}", "client_id": "node-7"}},
        {"do": "return", "relay": {"commands": [
            {"name": "set", "text": "publish", "qos": 1,
             "params": [{"template": "devices/7/set"},
                        {"pattern": "[0-9]{1,3}", "template": "level={{ $input }}"}]},
            {"name": "note", "text": "publish",
             "params": [{"pattern": "notes/[a-z+#]{1,8}"}, {"max_len": 64}]},
            {"name": "read", "text": "subscribe", "max_messages": 2, "wait_ms": 300,
             "params": [{"pattern": "sensors/[a-z0-9+#]{1,16}"}]},
            {"name": "all", "text": "subscribe", "wait_ms": 100,
             "params": [{"template": "sensors/+"}]}
        ]}}
    ]}))
}

fn mqtt_setup(version: &str) -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![mqtt_operation(version)],
    )
}

fn run(s: &Setup, fake: &mut Fake<Broker>, commands: Vec<CallerCommand>) -> engine::Result<Output> {
    let call = sign(
        s,
        "sensors",
        session("broker.example.com", 8883, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

#[test]
fn publish_and_subscribe_on_3_1_1() {
    let s = mqtt_setup("3.1.1");
    let mut broker = Broker::new(PASSWORD);
    broker.deliver = vec![
        ("sensors/door".into(), b"open".to_vec()),
        ("sensors/door".into(), b"closed".to_vec()),
        ("sensors/door".into(), b"open again".to_vec()),
    ];
    let mut fake = Fake::new(broker);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("set", &["42"]), command("read", &["sensors/door"])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["tls"], "TLS from the first byte");
    let b = &fake.peer;
    assert_eq!(b.level, 4);
    assert_eq!(b.client_id, b"node-7");
    assert_eq!(b.user.as_deref(), Some(&b"device-7"[..]));
    assert_eq!(
        b.published,
        [("devices/7/set".to_string(), b"level=42".to_vec(), 1, false)]
    );
    assert_eq!(b.subscribed, [("sensors/door".to_string(), 0)]);
    assert_eq!(b.unsubscribed, ["sensors/door"]);
    let set: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(set, json!({"reason": 0}));
    let read: Value = serde_json::from_slice(&out.results[1].data).unwrap();
    assert_eq!(
        read,
        json!([
            {"topic": "sensors/door", "payload": "open", "qos": 0, "retain": false},
            {"topic": "sensors/door", "payload": "closed", "qos": 0, "retain": false}
        ]),
        "at most max_messages"
    );
}

#[test]
fn version_5_with_a_token() {
    let s = setup(
        &[(FieldSpec::secret("token"), b"tok-eyJhbGciOi.x.y")],
        vec![operation(json!({"name": "sensors", "steps": [
            {"do": "open", "connection": "mqtt", "version": "5",
             "destinations": [{"host": "broker.example.com", "port": 8883}],
             "login": {"user": "", "token": "{{token}}"}},
            {"do": "return", "relay": {"commands": [
                {"name": "all", "text": "subscribe", "qos": 1, "wait_ms": 100,
                 "params": [{"template": "sensors/+"}]}
            ]}}
        ]}))],
    );
    let mut broker = Broker::new(b"tok-eyJhbGciOi.x.y");
    broker.deliver = vec![("sensors/a".into(), vec![0xff, 0x00])];
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("all", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.level, 5);
    assert_eq!(fake.peer.user, None);
    assert!(fake.peer.client_id.starts_with(b"credentials-"));
    let read: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(
        read,
        json!([{"topic": "sensors/a", "payload": {"base64": "/wA="}, "qos": 1, "retain": false}])
    );
}

#[test]
fn a_token_without_a_user_name_on_3_1_1_sends_an_empty_user_name() {
    let s = setup(
        &[(FieldSpec::secret("token"), b"tok-eyJhbGciOi.x.y")],
        vec![operation(json!({"name": "sensors", "steps": [
            {"do": "open", "connection": "mqtt", "version": "3.1.1",
             "destinations": [{"host": "broker.example.com", "port": 8883}],
             "login": {"user": "", "token": "{{token}}"}},
            {"do": "return", "relay": {"commands": [
                {"name": "all", "text": "subscribe", "wait_ms": 100,
                 "params": [{"template": "sensors/+"}]}
            ]}}
        ]}))],
    );
    let mut fake = Fake::new(Broker::new(b"tok-eyJhbGciOi.x.y"));
    let out = session_output(run(&s, &mut fake, vec![command("all", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.level, 4);
    assert_eq!(fake.peer.user, Some(Vec::new()));
}

#[test]
fn the_server_keep_alive_of_version_5_sets_the_ping_interval() {
    // The broker allows 1 second without a packet; the node pings within half of it while it
    // waits for messages, not after the 60 seconds it asked for.
    let s = setup(
        &[(FieldSpec::secret("token"), b"tok-eyJhbGciOi.x.y")],
        vec![operation(json!({"name": "sensors", "steps": [
            {"do": "open", "connection": "mqtt", "version": "5",
             "destinations": [{"host": "broker.example.com", "port": 8883}],
             "login": {"user": "", "token": "{{token}}"}},
            {"do": "return", "relay": {"commands": [
                {"name": "all", "text": "subscribe", "wait_ms": 1500,
                 "params": [{"template": "sensors/+"}]}
            ]}}
        ]}))],
    );
    let mut broker = Broker::new(b"tok-eyJhbGciOi.x.y");
    broker.server_keep_alive = Some(1);
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("all", &[])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert!(
        fake.peer.pings >= 1,
        "no ping within the server's keep-alive"
    );
}

#[test]
fn topics_outside_their_shape_or_with_wildcards_are_refused_first() {
    let s = mqtt_setup("3.1.1");
    for commands in [
        vec![command("set", &["4200"])],
        vec![command("set", &["1; drop"])],
        vec![command("read", &["admin/x"])],
        // The pattern lets these through; a caller's topic never holds a wildcard.
        vec![command("read", &["sensors/#"])],
        vec![command("read", &["sensors/+"])],
        vec![command("note", &["notes/a#", "x"])],
        vec![command("unknown", &[])],
    ] {
        let mut fake = Fake::new(Broker::new(PASSWORD));
        let result = run(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty());
    }
}

#[test]
fn messages_the_policy_did_not_subscribe_to_are_refused() {
    for misbehave in [Misbehave::OtherTopic, Misbehave::Qos2] {
        let s = mqtt_setup("3.1.1");
        let mut broker = Broker::new(PASSWORD);
        broker.misbehave = misbehave;
        let mut fake = Fake::new(broker);
        let out = session_output(run(&s, &mut fake, vec![command("all", &[])]));
        assert!(out.results.is_empty());
        assert!(
            matches!(out.error, Some(engine::Error::ServerUntrusted { .. })),
            "{misbehave:?}: {:?}",
            out.error
        );
    }
}

#[test]
fn a_secret_in_a_message_never_goes_back() {
    let s = mqtt_setup("5");
    let mut broker = Broker::new(PASSWORD);
    broker.misbehave = Misbehave::Echo;
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("all", &[])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    for version in ["3.1.1", "5"] {
        let s = mqtt_setup(version);
        let mut fake = Fake::new(Broker::new(b"other"));
        let result = run(&s, &mut fake, vec![command("set", &["1"])]);
        assert!(
            matches!(result, Err(engine::Error::AuthRefused { .. })),
            "{result:?}"
        );
        assert!(fake.peer.published.is_empty());
    }
}

#[test]
fn mqtt_takes_no_starttls_and_qos_2_is_refused_in_the_policy() {
    let mut op = serde_json::to_value(mqtt_operation("3.1.1")).unwrap();
    op["steps"][0]["tls"] = json!("starttls");
    let op: Operation = serde_json::from_value(op).unwrap();
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![],
        operations: vec![op],
    };
    assert!(policy.validate().is_err());
    let mut op = serde_json::to_value(mqtt_operation("3.1.1")).unwrap();
    op["steps"][1]["relay"]["commands"][0]["qos"] = json!(2);
    let op: Operation = serde_json::from_value(op).unwrap();
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![],
        operations: vec![op],
    };
    assert!(policy.validate().is_err());
}

fn live_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "watch", "steps": [
            {"do": "open", "connection": "mqtt",
             "destinations": [{"host": "broker.example.com", "port": 8883}],
             "login": {"user": "device-7", "password": "{{password}}"},
             "limits": {"idle_ms": 300}},
            {"do": "send", "command": {"text": "subscribe", "params": ["sensors/+"]}},
            {"do": "return", "relay": {"server": true}}
        ]}))],
    )
}

fn live(s: &Setup, broker: Broker) -> (Fake<Broker>, TestCaller, engine::Result<Output>) {
    let mut fake = Fake::new(broker);
    let call = caller_key()
        .sign_call(
            "app",
            &s.node.public_key(),
            s.record.clone(),
            "watch",
            Body::Session {
                destination: Destination::new("broker.example.com", 8883),
                commands: Vec::new(),
                mail: Vec::new(),
            },
        )
        .unwrap();
    let mut caller = TestCaller::default();
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    (fake, caller, result)
}

#[test]
fn messages_reach_a_streaming_caller_after_the_search() {
    let s = live_setup();
    let mut broker = Broker::new(PASSWORD);
    broker.deliver = vec![
        ("sensors/door".into(), b"open".to_vec()),
        ("sensors/window".into(), b"shut".to_vec()),
    ];
    let (fake, caller, result) = live(&s, broker);
    assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
    assert_eq!(fake.peer.subscribed, [("sensors/+".to_string(), 0)]);
    let texts: Vec<Value> = caller
        .parts
        .iter()
        .filter_map(|p| match p {
            Part::Text(t) => Some(serde_json::from_slice(t).unwrap()),
            _ => None,
        })
        .collect();
    assert_eq!(
        texts,
        [
            json!({"topic": "sensors/door", "payload": "open", "qos": 0, "retain": false}),
            json!({"topic": "sensors/window", "payload": "shut", "qos": 0, "retain": false}),
        ]
    );
    let (_, reason) = last_closed(&s);
    assert_eq!(reason, "idle");
}

#[test]
fn a_secret_in_a_live_message_stops_the_relay() {
    let s = live_setup();
    let mut broker = Broker::new(PASSWORD);
    broker.misbehave = Misbehave::Echo;
    let (_, caller, result) = live(&s, broker);
    assert!(
        matches!(result, Err(engine::Error::Reflection)),
        "{result:?}"
    );
    assert!(
        caller.parts.iter().all(|p| !matches!(p, Part::Text(_))),
        "nothing of the message went back"
    );
}

#[test]
fn an_approved_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &mqtt_setup("3.1.1"),
        "sensors",
        session(
            "broker.example.com",
            8883,
            vec![command("set", &["42"]), command("read", &["sensors/door"])],
            Vec::new(),
        ),
        || {
            let mut broker = Broker::new(PASSWORD);
            broker.deliver = vec![("sensors/door".into(), b"open".to_vec())];
            Fake::new(broker)
        },
    );
}
