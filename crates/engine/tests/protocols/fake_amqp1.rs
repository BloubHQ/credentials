//! An AMQP 1.0 broker for the tests, after TLS: the SASL layer (PLAIN, EXTERNAL, XOAUTH2 and
//! SCRAM-SHA-256 server side from the RustCrypto crates), one connection, one session, links
//! that send and receive, and ways to misbehave. It encodes with the engine's codec; what it
//! checks of the node's frames it checks itself.

use base64::Engine as _;
use engine::proto::amqp1::{self, Value, code};
use hmac::{Hmac, Mac as _};
use sha2::{Digest, Sha256};

use super::Peer;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Misbehave {
    None,
    /// Sends a challenge to PLAIN.
    PlainChallenge,
    /// SCRAM with a server signature that does not verify.
    BadProof,
    /// SCRAM: says the sign-in succeeded before its proof.
    ScramNoProof,
    /// Answers the SASL header with the AMQP header (no sign-in at all).
    SkipSasl,
    /// Answers the open with a frame larger than the node's max-frame-size.
    Oversized,
    /// Answers the begin with a value nested deeper than the decoder takes.
    Deep,
    /// Answers the attach with a performative the standard does not define.
    Unknown,
    /// Answers the attach with another receiver settle mode.
    ChangeSettle,
    /// Settles first on a link that settles second.
    SettleFirst,
    /// Sends one more delivery than the credit.
    Overdeliver,
    /// Sends a message larger than the node takes.
    HugeMessage,
}

/// The broker after TLS.
pub struct Amqp1Broker {
    pub password: Vec<u8>,
    pub token: Vec<u8>,
    pub mechanisms: Vec<&'static str>,
    pub misbehave: Misbehave,
    /// SCRAM: the server-final message in a challenge, not in the outcome.
    pub final_in_challenge: bool,
    /// Messages each address holds, encoded.
    pub queues: Vec<(String, Vec<Vec<u8>>)>,
    /// Rejects every message sent, with this description.
    pub reject: Option<String>,
    /// What it saw: the mechanism and its initial response, the open's hostname.
    pub mechanism: Option<String>,
    pub response: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub signed_in: bool,
    /// Each attach: whether the node receives, its modes, the address.
    pub attaches: Vec<(bool, u8, u8, String)>,
    /// Each message the node sent: address, body, sent settled.
    pub received: Vec<(String, Vec<u8>, bool)>,
    /// Each disposition of the node: role (true: receiver), first, settled, state code.
    pub dispositions: Vec<(bool, u32, bool, u64)>,
    /// Each credit the node gave.
    pub credits: Vec<u32>,
    /// Every byte the node wrote.
    pub written: Vec<u8>,
    stage: Stage,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    scram: Option<(String, String, Vec<u8>)>,
    scram_done: bool,
    link: Option<(bool, u8, u8, String)>,
    transfer: Vec<u8>,
    transfer_id: u32,
    transfer_settled: bool,
    next_delivery: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    SaslHeader,
    Sasl,
    AmqpHeader,
    Amqp,
    Closed,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn described(code: u64, fields: Vec<Value>) -> Value {
    Value::described(code, fields)
}

fn bytes_of(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    amqp1::encode(value, &mut out).unwrap();
    out
}

/// A message of one `data` section, with properties naming its subject.
pub fn message(body: &[u8]) -> Vec<u8> {
    let mut out = bytes_of(&described(
        code::PROPERTIES,
        vec![
            Value::String("id-1".into()),
            Value::Null,
            Value::Null,
            Value::String("greeting".into()),
        ],
    ));
    out.extend(bytes_of(&Value::Described(
        Box::new(Value::Ulong(code::DATA)),
        Box::new(Value::Binary(body.to_vec())),
    )));
    out
}

impl Amqp1Broker {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            token: Vec::new(),
            mechanisms: vec!["SCRAM-SHA-256", "PLAIN", "EXTERNAL", "XOAUTH2"],
            misbehave: Misbehave::None,
            final_in_challenge: false,
            queues: Vec::new(),
            reject: None,
            mechanism: None,
            response: None,
            hostname: None,
            signed_in: false,
            attaches: Vec::new(),
            received: Vec::new(),
            dispositions: Vec::new(),
            credits: Vec::new(),
            written: Vec::new(),
            stage: Stage::SaslHeader,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            scram: None,
            scram_done: false,
            link: None,
            transfer: Vec::new(),
            transfer_id: 0,
            transfer_settled: false,
            next_delivery: 0,
        }
    }

    fn put(&mut self, kind: u8, value: &Value, payload: &[u8]) {
        let mut body = bytes_of(value);
        body.extend_from_slice(payload);
        self.outbuf
            .extend_from_slice(&amqp1::frame(kind, 0, &body).unwrap());
    }

    fn amqp(&mut self, code: u64, fields: Vec<Value>) {
        self.put(amqp1::FRAME_AMQP, &described(code, fields), &[]);
    }

    fn sasl(&mut self, code: u64, fields: Vec<Value>) {
        self.put(amqp1::FRAME_SASL, &described(code, fields), &[]);
    }

    fn outcome(&mut self, ok: bool, data: Option<Vec<u8>>) {
        let mut fields = vec![Value::Ubyte(if ok { 0 } else { 1 })];
        if let Some(d) = data {
            fields.push(Value::Binary(d));
        }
        self.sasl(code::SASL_OUTCOME, fields);
        if ok {
            self.signed_in = true;
            self.stage = Stage::AmqpHeader;
        }
    }

    fn sasl_frame(&mut self, p: amqp1::Performative) {
        match p.code {
            code::SASL_INIT => {
                let mechanism = p.field(0).text().unwrap().to_string();
                let Value::Binary(response) = p.field(1).clone() else {
                    panic!("no initial response");
                };
                self.mechanism = Some(mechanism.clone());
                self.response = Some(response.clone());
                match mechanism.as_str() {
                    "PLAIN" if self.misbehave == Misbehave::PlainChallenge => {
                        self.sasl(code::SASL_CHALLENGE, vec![Value::Binary(b"more".to_vec())]);
                    }
                    "PLAIN" => {
                        let mut expected = b"\0app\0".to_vec();
                        expected.extend_from_slice(&self.password);
                        self.outcome(response == expected, None);
                    }
                    "EXTERNAL" => self.outcome(true, None),
                    "XOAUTH2" => {
                        let mut expected = b"user=app\x01auth=Bearer ".to_vec();
                        expected.extend_from_slice(&self.token);
                        expected.extend_from_slice(b"\x01\x01");
                        self.outcome(response == expected, None);
                    }
                    "SCRAM-SHA-256" => {
                        let first = String::from_utf8(response).unwrap();
                        let bare = first.strip_prefix("n,,").unwrap().to_string();
                        let nonce = bare.split("r=").nth(1).unwrap().to_string();
                        let salt = [9u8; 16];
                        let mut salted = [0u8; 32];
                        pbkdf2::pbkdf2_hmac::<Sha256>(&self.password, &salt, 4096, &mut salted);
                        let server_first = format!(
                            "r={nonce}BROKERNONCE,s={},i=4096",
                            base64::engine::general_purpose::STANDARD.encode(salt)
                        );
                        if self.misbehave == Misbehave::ScramNoProof {
                            self.outcome(true, None);
                            return;
                        }
                        self.sasl(
                            code::SASL_CHALLENGE,
                            vec![Value::Binary(server_first.clone().into_bytes())],
                        );
                        self.scram = Some((bare, server_first, salted.to_vec()));
                    }
                    other => panic!("mechanism {other}"),
                }
            }
            code::SASL_RESPONSE if self.scram_done => self.outcome(true, None),
            code::SASL_RESPONSE => {
                let (bare, server_first, salted) = self.scram.clone().unwrap();
                let Value::Binary(last) = p.field(0).clone() else {
                    panic!("no response");
                };
                let last = String::from_utf8(last).unwrap();
                let (without, proof) = last.rsplit_once(",p=").unwrap();
                let auth_message = format!("{bare},{server_first},{without}");
                let client_key = hmac(&salted, b"Client Key");
                let stored = Sha256::digest(&client_key);
                let signature = hmac(&stored, auth_message.as_bytes());
                let expected: Vec<u8> = client_key
                    .iter()
                    .zip(&signature)
                    .map(|(a, b)| a ^ b)
                    .collect();
                let given = base64::engine::general_purpose::STANDARD
                    .decode(proof)
                    .unwrap();
                if given != expected {
                    self.outcome(false, None);
                    return;
                }
                let server_key = hmac(&salted, b"Server Key");
                let mut server_signature = hmac(&server_key, auth_message.as_bytes());
                if self.misbehave == Misbehave::BadProof {
                    server_signature[0] ^= 1;
                }
                let v = format!(
                    "v={}",
                    base64::engine::general_purpose::STANDARD.encode(server_signature)
                )
                .into_bytes();
                if self.final_in_challenge {
                    self.scram_done = true;
                    self.sasl(code::SASL_CHALLENGE, vec![Value::Binary(v)]);
                } else {
                    self.outcome(true, Some(v));
                }
            }
            other => panic!("SASL frame {other:#x}"),
        }
    }

    fn deliver(&mut self, credit: u32) {
        let Some((_, snd, _, address)) = self.link.clone() else {
            return;
        };
        let mut count = credit;
        if self.misbehave == Misbehave::Overdeliver {
            count += 1;
        }
        for _ in 0..count {
            let next = self
                .queues
                .iter_mut()
                .find(|(q, _)| *q == address)
                .and_then(|(_, m)| (!m.is_empty()).then(|| m.remove(0)));
            let body = match (next, self.misbehave) {
                (_, Misbehave::HugeMessage) => message(&vec![b'x'; amqp1::MAX_MESSAGE + 16]),
                (Some(body), _) => body,
                (None, _) => return,
            };
            let id = self.next_delivery;
            self.next_delivery += 1;
            let settled = snd == 1;
            let chunks: Vec<&[u8]> = body.chunks(30_000).collect();
            let last = chunks.len() - 1;
            for (i, chunk) in chunks.into_iter().enumerate() {
                let transfer = described(
                    code::TRANSFER,
                    vec![
                        Value::Uint(0),
                        Value::Uint(id),
                        Value::Binary(id.to_be_bytes().to_vec()),
                        Value::Uint(0),
                        Value::Bool(settled),
                        Value::Bool(i < last),
                    ],
                );
                self.put(amqp1::FRAME_AMQP, &transfer, chunk);
            }
        }
    }

    fn amqp_frame(&mut self, p: amqp1::Performative) {
        match p.code {
            code::OPEN => {
                self.hostname = p.field(1).text().map(str::to_string);
                if self.misbehave == Misbehave::Oversized {
                    let body = vec![0x40; amqp1::MAX_FRAME as usize];
                    self.outbuf
                        .extend_from_slice(&amqp1::frame(amqp1::FRAME_AMQP, 0, &body).unwrap());
                    return;
                }
                self.amqp(
                    code::OPEN,
                    vec![
                        Value::String("broker".into()),
                        Value::Null,
                        Value::Uint(65_536),
                        Value::Ushort(0),
                    ],
                );
            }
            code::BEGIN => {
                let mut fields = vec![
                    Value::Ushort(0),
                    Value::Uint(1),
                    Value::Uint(1024),
                    Value::Uint(1024),
                ];
                if self.misbehave == Misbehave::Deep {
                    let mut deep = Value::Null;
                    for _ in 0..64 {
                        deep = Value::List(vec![deep]);
                    }
                    fields.push(deep);
                }
                self.amqp(code::BEGIN, fields);
            }
            code::ATTACH => {
                let receives = p.field(2).bool().unwrap();
                let snd = match p.field(3) {
                    Value::Ubyte(m) => *m,
                    _ => 2,
                };
                let rcv = match p.field(4) {
                    Value::Ubyte(m) => *m,
                    _ => 0,
                };
                let terminus = if receives { p.field(5) } else { p.field(6) };
                let address = match terminus.as_described_list() {
                    Some((_, fields)) => fields[0].text().unwrap().to_string(),
                    None => panic!("no terminus"),
                };
                self.attaches.push((receives, snd, rcv, address.clone()));
                self.link = Some((receives, snd, rcv, address));
                if self.misbehave == Misbehave::Unknown {
                    self.amqp(0x30, vec![Value::Uint(0)]);
                    return;
                }
                let rcv_answer = if self.misbehave == Misbehave::ChangeSettle {
                    1 - rcv
                } else {
                    rcv
                };
                self.amqp(
                    code::ATTACH,
                    vec![
                        p.field(0).clone(),
                        Value::Uint(0),
                        Value::Bool(!receives),
                        Value::Ubyte(snd),
                        Value::Ubyte(rcv_answer),
                        p.field(5).clone(),
                        p.field(6).clone(),
                        Value::Null,
                        Value::Bool(false),
                        if receives {
                            Value::Uint(0)
                        } else {
                            Value::Null
                        },
                    ],
                );
                if !receives {
                    self.amqp(
                        code::FLOW,
                        vec![
                            Value::Uint(0),
                            Value::Uint(1024),
                            Value::Uint(1),
                            Value::Uint(1024),
                            Value::Uint(0),
                            Value::Uint(0),
                            Value::Uint(10),
                        ],
                    );
                }
            }
            code::FLOW => {
                if let Some(credit) = p.field(6).uint() {
                    self.credits.push(credit);
                    self.deliver(credit);
                }
            }
            code::TRANSFER => {
                if let Some(id) = p.field(1).uint() {
                    self.transfer_id = id;
                    self.transfer_settled = p.field(4).bool().unwrap_or(false);
                }
                self.transfer.extend_from_slice(&p.payload);
                if p.field(5).bool() == Some(true) {
                    return;
                }
                let bytes = std::mem::take(&mut self.transfer);
                let body = match amqp1::decode(&bytes).unwrap() {
                    Value::Described(_, body) => match *body {
                        Value::Binary(b) => b,
                        other => panic!("body {other:?}"),
                    },
                    other => panic!("section {other:?}"),
                };
                let address = self.link.as_ref().unwrap().3.clone();
                self.received.push((address, body, self.transfer_settled));
                if self.transfer_settled {
                    return;
                }
                let rcv = self.link.as_ref().unwrap().2;
                let state = match &self.reject {
                    Some(description) => described(
                        code::REJECTED,
                        vec![described(
                            code::ERROR,
                            vec![
                                Value::Symbol("amqp:unauthorized-access".into()),
                                Value::String(description.clone()),
                            ],
                        )],
                    ),
                    None => described(code::ACCEPTED, Vec::new()),
                };
                let settled = rcv == 0 || self.misbehave == Misbehave::SettleFirst;
                self.amqp(
                    code::DISPOSITION,
                    vec![
                        Value::Bool(true),
                        Value::Uint(self.transfer_id),
                        Value::Null,
                        Value::Bool(settled),
                        state,
                    ],
                );
            }
            code::DISPOSITION => {
                let role = p.field(0).bool().unwrap();
                let first = p.field(1).uint().unwrap();
                let settled = p.field(3).bool().unwrap_or(false);
                let state = p.field(4).as_described_list().map(|(c, _)| c).unwrap_or(0);
                self.dispositions.push((role, first, settled, state));
                // The node accepted unsettled (it settles second): the broker settles.
                if role && !settled {
                    self.amqp(
                        code::DISPOSITION,
                        vec![
                            Value::Bool(false),
                            Value::Uint(first),
                            Value::Null,
                            Value::Bool(true),
                            described(code::ACCEPTED, Vec::new()),
                        ],
                    );
                }
            }
            code::DETACH => {
                self.link = None;
                self.amqp(code::DETACH, vec![Value::Uint(0), Value::Bool(true)]);
            }
            code::END => self.amqp(code::END, Vec::new()),
            code::CLOSE => {
                self.amqp(code::CLOSE, Vec::new());
                self.stage = Stage::Closed;
            }
            other => panic!("performative {other:#x}"),
        }
    }
}

impl Peer for Amqp1Broker {
    fn feed(&mut self, bytes: &[u8]) {
        self.written.extend_from_slice(bytes);
        self.inbuf.extend_from_slice(bytes);
        loop {
            match self.stage {
                Stage::SaslHeader | Stage::AmqpHeader => {
                    if self.inbuf.len() < 8 {
                        return;
                    }
                    let header: Vec<u8> = self.inbuf.drain(..8).collect();
                    if self.stage == Stage::SaslHeader {
                        assert_eq!(header, amqp1::SASL_HEADER);
                        if self.misbehave == Misbehave::SkipSasl {
                            self.outbuf.extend_from_slice(amqp1::AMQP_HEADER);
                            self.stage = Stage::Closed;
                            return;
                        }
                        self.outbuf.extend_from_slice(amqp1::SASL_HEADER);
                        let offered = Value::Array(
                            self.mechanisms
                                .iter()
                                .map(|m| Value::Symbol((*m).into()))
                                .collect(),
                        );
                        self.sasl(code::SASL_MECHANISMS, vec![offered]);
                        self.stage = Stage::Sasl;
                    } else {
                        assert_eq!(header, amqp1::AMQP_HEADER);
                        self.outbuf.extend_from_slice(amqp1::AMQP_HEADER);
                        self.stage = Stage::Amqp;
                    }
                }
                Stage::Sasl | Stage::Amqp => {
                    let Some((n, frame)) = amqp1::parse_frame(&self.inbuf, 1 << 20).unwrap() else {
                        return;
                    };
                    self.inbuf.drain(..n);
                    if frame.body.is_empty() {
                        continue;
                    }
                    let p = amqp1::performative(&frame.body).unwrap();
                    if self.stage == Stage::Sasl {
                        assert_eq!(frame.kind, amqp1::FRAME_SASL);
                        self.sasl_frame(p);
                    } else {
                        assert_eq!(frame.kind, amqp1::FRAME_AMQP);
                        self.amqp_frame(p);
                    }
                }
                Stage::Closed => return,
            }
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        false
    }
}
