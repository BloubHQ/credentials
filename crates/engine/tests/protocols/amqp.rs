//! AMQP 0-9-1 over TLS: PLAIN only, publications to the exchanges and routing keys the policy
//! fixes (mandatory, confirmed), messages got from the queues it fixes.

use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::*;

const PASSWORD: &[u8] = b"amqp-pass-93q";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Misbehave {
    None,
    /// Offers only AMQPLAIN.
    NoPlain,
    /// Asks for more with connection.secure.
    Secure,
    /// Returns every publication as unroutable.
    Unroutable,
}

/// A broker after TLS.
pub struct AmqpBroker {
    pub password: Vec<u8>,
    pub misbehave: Misbehave,
    /// Messages each queue holds.
    pub queues: Vec<(String, Vec<Vec<u8>>)>,
    /// What it saw.
    pub response: Option<Vec<u8>>,
    pub mechanism: Vec<u8>,
    pub vhost: Vec<u8>,
    pub published: Vec<(String, String, Vec<u8>, bool)>,
    pub acked: Vec<u64>,
    pub got: Vec<String>,
    header: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    pending: Option<(String, String, bool, u64, Vec<u8>)>,
    tag: u64,
    confirms: u64,
}

fn short(out: &mut Vec<u8>, b: &[u8]) {
    out.push(b.len() as u8);
    out.extend_from_slice(b);
}

fn long(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn frame(kind: u8, channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(0xce);
    out
}

fn method(channel: u16, class: u16, id: u16, args: &[u8]) -> Vec<u8> {
    let mut p = class.to_be_bytes().to_vec();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(args);
    frame(1, channel, &p)
}

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.0[..n];
        self.0 = &self.0[n..];
        s
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take(8).try_into().unwrap())
    }
    fn short(&mut self) -> &'a [u8] {
        let n = self.take(1)[0] as usize;
        self.take(n)
    }
    fn long(&mut self) -> &'a [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

impl AmqpBroker {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            misbehave: Misbehave::None,
            queues: Vec::new(),
            response: None,
            mechanism: Vec::new(),
            vhost: Vec::new(),
            published: Vec::new(),
            acked: Vec::new(),
            got: Vec::new(),
            header: false,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            pending: None,
            tag: 0,
            confirms: 0,
        }
    }

    fn start(&mut self) {
        let mut args = vec![0, 9];
        long(&mut args, &[]);
        let mechanisms: &[u8] = if self.misbehave == Misbehave::NoPlain {
            b"AMQPLAIN"
        } else {
            b"AMQPLAIN PLAIN"
        };
        long(&mut args, mechanisms);
        long(&mut args, b"en_US");
        self.outbuf.extend(method(0, 10, 10, &args));
    }

    fn content(&mut self, body: &[u8]) {
        let mut header = 60u16.to_be_bytes().to_vec();
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&(body.len() as u64).to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        self.outbuf.extend(frame(2, 1, &header));
        for chunk in body.chunks(4000) {
            self.outbuf.extend(frame(3, 1, chunk));
        }
    }

    fn handle(&mut self, kind: u8, channel: u16, payload: &[u8]) {
        if kind == 2 {
            let mut r = R(payload);
            r.u16();
            r.u16();
            let size = r.u64();
            if let Some(p) = self.pending.as_mut() {
                p.3 = size;
            }
            self.finish_publish();
            return;
        }
        if kind == 3 {
            if let Some(p) = self.pending.as_mut() {
                p.4.extend_from_slice(payload);
            }
            self.finish_publish();
            return;
        }
        let mut r = R(payload);
        let (class, id) = (r.u16(), r.u16());
        match (class, id) {
            (10, 11) => {
                r.long();
                self.mechanism = r.short().to_vec();
                self.response = Some(r.long().to_vec());
                if self.misbehave == Misbehave::Secure {
                    let mut args = Vec::new();
                    long(&mut args, b"challenge");
                    self.outbuf.extend(method(0, 10, 20, &args));
                    return;
                }
                let mut expected = b"\0app\0".to_vec();
                expected.extend_from_slice(&self.password);
                if self.response.as_deref() == Some(expected.as_slice()) {
                    let mut tune = 0u16.to_be_bytes().to_vec();
                    tune.extend_from_slice(&131_072u32.to_be_bytes());
                    tune.extend_from_slice(&60u16.to_be_bytes());
                    self.outbuf.extend(method(0, 10, 30, &tune));
                } else {
                    let mut close = 403u16.to_be_bytes().to_vec();
                    short(&mut close, b"ACCESS_REFUSED");
                    close.extend_from_slice(&[0, 0, 0, 0]);
                    self.outbuf.extend(method(0, 10, 50, &close));
                }
            }
            (10, 31) => {}
            (10, 40) => {
                self.vhost = r.short().to_vec();
                let mut ok = Vec::new();
                short(&mut ok, b"");
                self.outbuf.extend(method(0, 10, 41, &ok));
            }
            (20, 10) => {
                let mut ok = Vec::new();
                long(&mut ok, b"");
                self.outbuf.extend(method(channel, 20, 11, &ok));
            }
            (85, 10) => self.outbuf.extend(method(channel, 85, 11, &[])),
            (60, 40) => {
                r.u16();
                let exchange = String::from_utf8(r.short().to_vec()).unwrap();
                let key = String::from_utf8(r.short().to_vec()).unwrap();
                let mandatory = r.take(1)[0] & 1 != 0;
                self.pending = Some((exchange, key, mandatory, u64::MAX, Vec::new()));
            }
            (60, 70) => {
                r.u16();
                let queue = String::from_utf8(r.short().to_vec()).unwrap();
                self.got.push(queue.clone());
                let next = self
                    .queues
                    .iter_mut()
                    .find(|(q, _)| *q == queue)
                    .and_then(|(_, m)| (!m.is_empty()).then(|| m.remove(0)));
                match next {
                    Some(body) => {
                        self.tag += 1;
                        let mut args = self.tag.to_be_bytes().to_vec();
                        args.push(0);
                        short(&mut args, b"orders");
                        short(&mut args, b"new");
                        args.extend_from_slice(&0u32.to_be_bytes());
                        self.outbuf.extend(method(1, 60, 71, &args));
                        self.content(&body);
                    }
                    None => {
                        let mut args = Vec::new();
                        short(&mut args, b"");
                        self.outbuf.extend(method(1, 60, 72, &args));
                    }
                }
            }
            (60, 80) => self.acked.push(r.u64()),
            (10, 50) => {
                self.outbuf.extend(method(0, 10, 51, &[]));
            }
            other => panic!("method {other:?}"),
        }
    }

    fn finish_publish(&mut self) {
        let Some((exchange, key, mandatory, size, body)) = self.pending.take() else {
            return;
        };
        if (body.len() as u64) < size {
            self.pending = Some((exchange, key, mandatory, size, body));
            return;
        }
        self.confirms += 1;
        if self.misbehave == Misbehave::Unroutable {
            let mut args = 312u16.to_be_bytes().to_vec();
            short(&mut args, b"NO_ROUTE");
            short(&mut args, exchange.as_bytes());
            short(&mut args, key.as_bytes());
            self.outbuf.extend(method(1, 60, 50, &args));
            self.content(&body);
        }
        self.published.push((exchange, key, body, mandatory));
        let mut ack = self.confirms.to_be_bytes().to_vec();
        ack.push(0);
        self.outbuf.extend(method(1, 60, 80, &ack));
    }
}

impl Peer for AmqpBroker {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        if !self.header {
            if self.inbuf.len() < 8 {
                return;
            }
            assert_eq!(&self.inbuf[..8], b"AMQP\x00\x00\x09\x01");
            self.inbuf.drain(..8);
            self.header = true;
            self.start();
        }
        while self.inbuf.len() >= 8 {
            let size = u32::from_be_bytes(self.inbuf[3..7].try_into().unwrap()) as usize;
            if self.inbuf.len() < 7 + size + 1 {
                return;
            }
            let kind = self.inbuf[0];
            let channel = u16::from_be_bytes([self.inbuf[1], self.inbuf[2]]);
            assert_eq!(self.inbuf[7 + size], 0xce);
            let payload = self.inbuf[7..7 + size].to_vec();
            self.inbuf.drain(..8 + size);
            self.handle(kind, channel, &payload);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        false
    }
}

fn amqp_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "orders", "steps": [
            {"do": "open", "connection": "amqp",
             "destinations": [{"host": "mq.example.com", "port": 5671}],
             "login": {"user": "app", "password": "{{password}}", "vhost": "shop"}},
            {"do": "return", "relay": {"commands": [
                {"name": "new", "text": "publish",
                 "params": [{"template": "orders"}, {"template": "new"},
                            {"pattern": "[0-9]{1,9}", "template": "order:{{ $input }}"}]},
                {"name": "raw", "text": "publish",
                 "params": [{"template": "orders"}, {"template": "raw"}, {"max_len": 8192}]},
                {"name": "next", "text": "get", "max_messages": 2,
                 "params": [{"template": "replies"}]}
            ]}}
        ]}))],
    )
}

fn run(
    s: &Setup,
    fake: &mut Fake<AmqpBroker>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "orders",
        session("mq.example.com", 5671, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

#[test]
fn plain_over_tls_then_publish_and_get() {
    let s = amqp_setup();
    let mut broker = AmqpBroker::new(PASSWORD);
    broker.queues = vec![(
        "replies".into(),
        vec![b"one".to_vec(), vec![b'x'; 9000], b"three".to_vec()],
    )];
    let mut fake = Fake::new(broker);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("new", &["1234"]), command("next", &[])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["tls"]);
    let b = &fake.peer;
    assert_eq!(b.mechanism, b"PLAIN");
    assert_eq!(b.vhost, b"shop");
    assert_eq!(
        b.published,
        [("orders".into(), "new".into(), b"order:1234".to_vec(), true)]
    );
    assert_eq!(b.acked, [1, 2], "each message acknowledged");
    let first: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(first, json!({"confirmed": true}));
    let got: Value = serde_json::from_slice(&out.results[1].data).unwrap();
    assert_eq!(got.as_array().unwrap().len(), 2, "at most max_messages");
    assert_eq!(got[0]["payload"], json!("one"));
    assert_eq!(got[1]["payload"].as_str().unwrap().len(), 9000);
}

#[test]
fn a_server_without_plain_or_asking_for_more_gets_nothing() {
    for misbehave in [Misbehave::NoPlain, Misbehave::Secure] {
        let s = amqp_setup();
        let mut broker = AmqpBroker::new(PASSWORD);
        broker.misbehave = misbehave;
        let mut fake = Fake::new(broker);
        let result = run(&s, &mut fake, vec![command("new", &["1"])]);
        assert!(
            matches!(result, Err(engine::Error::ServerUntrusted { .. })),
            "{result:?}"
        );
        if misbehave == Misbehave::NoPlain {
            assert!(fake.peer.response.is_none(), "no credential sent");
        }
        assert!(fake.peer.published.is_empty());
    }
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = amqp_setup();
    let mut fake = Fake::new(AmqpBroker::new(b"other"));
    let result = run(&s, &mut fake, vec![command("new", &["1"])]);
    assert!(
        matches!(result, Err(engine::Error::AuthRefused { .. })),
        "{result:?}"
    );
}

#[test]
fn an_unroutable_publication_fails_its_command() {
    let s = amqp_setup();
    let mut broker = AmqpBroker::new(PASSWORD);
    broker.misbehave = Misbehave::Unroutable;
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("new", &["7"])]));
    assert_eq!(out.results[0].status, Some(1));
    let error: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(error["error"]["code"], json!(312));
}

#[test]
fn exchanges_and_routing_keys_are_the_policys() {
    let s = amqp_setup();
    for commands in [
        vec![command("new", &["x"])],
        vec![command("new", &["1", "other-key"])],
        vec![command("next", &["other-queue"])],
        vec![command("purge", &[])],
    ] {
        let mut fake = Fake::new(AmqpBroker::new(PASSWORD));
        let result = run(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty());
    }
    // A caller-chosen exchange or routing key does not validate.
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![],
        operations: vec![operation(json!({"name": "orders", "steps": [
            {"do": "open", "connection": "amqp",
             "destinations": [{"host": "mq.example.com", "port": 5671}],
             "login": {"user": "app", "password": "{{password}}"}},
            {"do": "return", "relay": {"commands": [
                {"name": "any", "text": "publish",
                 "params": [{"pattern": "[a-z]{1,8}"}, {"template": "k"}, {"max_len": 10}]}
            ]}}
        ]}))],
    };
    assert!(policy.validate().is_err());
}

#[test]
fn a_secret_in_a_message_never_goes_back() {
    let s = amqp_setup();
    let mut broker = AmqpBroker::new(PASSWORD);
    let mut leak = b"reply ".to_vec();
    leak.extend_from_slice(PASSWORD);
    broker.queues = vec![("replies".into(), vec![leak])];
    let mut fake = Fake::new(broker);
    let out = session_output(run(&s, &mut fake, vec![command("next", &[])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn the_payload_is_one_body_whatever_it_holds() {
    let s = amqp_setup();
    let mut fake = Fake::new(AmqpBroker::new(PASSWORD));
    let evil = "x\u{1}\u{ce}\r\nAMQP";
    let out = session_output(run(&s, &mut fake, vec![command("raw", &[evil])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.peer.published.len(), 1);
    assert_eq!(fake.peer.published[0].2, evil.as_bytes());
}
