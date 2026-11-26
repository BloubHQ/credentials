//! A PostgreSQL server for the tests: SCRAM-SHA-256 server side from the RustCrypto crates
//! (the client uses ring), the extended query protocol, and ways to misbehave.

use base64::Engine as _;
use hmac::{Hmac, Mac as _};
use sha2::{Digest, Sha256};

use super::Peer;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PgAuth {
    Scram,
    /// Asks for the password in the clear.
    Cleartext,
    /// Asks for an MD5 hash.
    Md5,
    /// Says the sign-in succeeded at once.
    OkFirst,
    /// SCRAM with a server signature that does not verify.
    BadSignature,
    /// SCRAM with too few iterations.
    FewIterations,
}

/// What a query returns: columns and rows, or an error (code, message).
pub type Answer = Result<(Vec<&'static str>, Vec<Vec<Option<Vec<u8>>>>), (&'static str, String)>;

pub struct PgServer {
    pub auth: PgAuth,
    pub password: Vec<u8>,
    pub answer: fn(&[u8], &[Vec<u8>]) -> Answer,
    /// What it saw: each query's text and parameters.
    pub queries: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    pub signed_in: bool,
    /// Every byte the client wrote.
    pub received: Vec<u8>,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    started: bool,
    client_first_bare: String,
    server_first: String,
    salted: Vec<u8>,
    pending: Option<(Vec<u8>, Vec<Vec<u8>>)>,
    closed: bool,
}

fn msg(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend(((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn auth(code: u32, rest: &[u8]) -> Vec<u8> {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(rest);
    msg(b'R', &body)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn cstr(bytes: &[u8]) -> (&[u8], &[u8]) {
    let at = bytes.iter().position(|b| *b == 0).unwrap();
    (&bytes[..at], &bytes[at + 1..])
}

impl PgServer {
    pub fn new(password: &[u8]) -> Self {
        Self {
            auth: PgAuth::Scram,
            password: password.to_vec(),
            answer: |_, _| Ok((vec!["one"], vec![vec![Some(b"1".to_vec())]])),
            queries: Vec::new(),
            signed_in: false,
            received: Vec::new(),
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            started: false,
            client_first_bare: String::new(),
            server_first: String::new(),
            salted: Vec::new(),
            pending: None,
            closed: false,
        }
    }

    fn ready(&mut self) {
        self.signed_in = true;
        self.outbuf.extend(auth(0, b""));
        self.outbuf.extend(msg(b'S', b"server_version\x0016.0\x00"));
        self.outbuf.extend(msg(b'Z', b"I"));
    }

    fn handle(&mut self, kind: u8, body: Vec<u8>) {
        match kind {
            b'p' if self.client_first_bare.is_empty() => {
                let (mech, rest) = cstr(&body);
                assert_eq!(mech, b"SCRAM-SHA-256");
                let first = String::from_utf8(rest[4..].to_vec()).unwrap();
                let bare = first.strip_prefix("n,,").unwrap().to_string();
                let nonce = bare.split("r=").nth(1).unwrap().to_string();
                let salt = [7u8; 16];
                let iterations = if self.auth == PgAuth::FewIterations {
                    1024
                } else {
                    4096
                };
                let mut salted = [0u8; 32];
                pbkdf2::pbkdf2_hmac::<Sha256>(&self.password, &salt, iterations, &mut salted);
                self.salted = salted.to_vec();
                self.server_first = format!(
                    "r={nonce}SERVERNONCE,s={},i={iterations}",
                    base64::engine::general_purpose::STANDARD.encode(salt)
                );
                self.client_first_bare = bare;
                let server_first = self.server_first.clone();
                self.outbuf.extend(auth(11, server_first.as_bytes()));
            }
            b'p' => {
                let last = String::from_utf8(body).unwrap();
                let (without, proof) = last.rsplit_once(",p=").unwrap();
                let auth_message = format!(
                    "{},{},{}",
                    self.client_first_bare, self.server_first, without
                );
                let client_key = hmac(&self.salted, b"Client Key");
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
                    self.outbuf.extend(msg(
                        b'E',
                        b"SFATAL\0C28P01\0Mpassword authentication failed\0\0",
                    ));
                    self.closed = true;
                    return;
                }
                let server_key = hmac(&self.salted, b"Server Key");
                let mut server_signature = hmac(&server_key, auth_message.as_bytes());
                if self.auth == PgAuth::BadSignature {
                    server_signature[0] ^= 1;
                }
                let v = format!(
                    "v={}",
                    base64::engine::general_purpose::STANDARD.encode(server_signature)
                );
                self.outbuf.extend(auth(12, v.as_bytes()));
                self.ready();
            }
            b'P' => {
                let (_, rest) = cstr(&body);
                let (sql, _) = cstr(rest);
                self.pending = Some((sql.to_vec(), Vec::new()));
                self.outbuf.extend(msg(b'1', b""));
            }
            b'B' => {
                let (_, rest) = cstr(&body);
                let (_, rest) = cstr(rest);
                let formats = u16::from_be_bytes(rest[..2].try_into().unwrap()) as usize;
                let mut at = 2 + formats * 2;
                let n = u16::from_be_bytes(rest[at..at + 2].try_into().unwrap());
                at += 2;
                let mut params = Vec::new();
                for _ in 0..n {
                    let len = u32::from_be_bytes(rest[at..at + 4].try_into().unwrap()) as usize;
                    at += 4;
                    params.push(rest[at..at + len].to_vec());
                    at += len;
                }
                if let Some(p) = &mut self.pending {
                    p.1 = params;
                }
                self.outbuf.extend(msg(b'2', b""));
            }
            b'D' => {}
            b'E' => {
                let (sql, params) = self.pending.take().unwrap();
                self.queries.push((sql.clone(), params.clone()));
                match (self.answer)(&sql, &params) {
                    Ok((columns, rows)) => {
                        let mut desc = (columns.len() as u16).to_be_bytes().to_vec();
                        for c in &columns {
                            desc.extend_from_slice(c.as_bytes());
                            desc.push(0);
                            desc.extend([0u8; 18]);
                        }
                        self.outbuf.extend(msg(b'T', &desc));
                        for row in &rows {
                            let mut data = (row.len() as u16).to_be_bytes().to_vec();
                            for v in row {
                                match v {
                                    Some(v) => {
                                        data.extend((v.len() as u32).to_be_bytes());
                                        data.extend_from_slice(v);
                                    }
                                    None => data.extend(u32::MAX.to_be_bytes()),
                                }
                            }
                            self.outbuf.extend(msg(b'D', &data));
                        }
                        let tag = format!("SELECT {}\0", rows.len());
                        self.outbuf.extend(msg(b'C', tag.as_bytes()));
                    }
                    Err((code, message)) => {
                        let body = format!("SERROR\0C{code}\0M{message}\0\0");
                        self.outbuf.extend(msg(b'E', body.as_bytes()));
                    }
                }
            }
            b'S' => self.outbuf.extend(msg(b'Z', b"I")),
            b'X' => self.closed = true,
            _ => {}
        }
    }
}

impl Peer for PgServer {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        self.received.extend_from_slice(bytes);
        if !self.started {
            if self.inbuf.len() < 4 {
                return;
            }
            let len = u32::from_be_bytes(self.inbuf[..4].try_into().unwrap()) as usize;
            if self.inbuf.len() < len {
                return;
            }
            self.inbuf.drain(..len);
            self.started = true;
            match self.auth {
                PgAuth::Cleartext => self.outbuf.extend(auth(3, b"")),
                PgAuth::Md5 => self.outbuf.extend(auth(5, b"salt")),
                PgAuth::OkFirst => self.ready(),
                _ => self
                    .outbuf
                    .extend(auth(10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0")),
            }
        }
        while self.inbuf.len() >= 5 {
            let len = u32::from_be_bytes(self.inbuf[1..5].try_into().unwrap()) as usize;
            if self.inbuf.len() < 1 + len {
                return;
            }
            let packet: Vec<u8> = self.inbuf.drain(..1 + len).collect();
            self.handle(packet[0], packet[5..].to_vec());
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        self.closed
    }
}
