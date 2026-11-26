//! A POP3 server for the tests, line by line: CAPA, USER/PASS, APOP, SASL PLAIN, LOGIN and
//! XOAUTH2, and the transaction commands over messages in memory.

use base64::Engine as _;
use md5::Digest as _;

use super::Peer;

fn b64d(text: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim_ascii())
        .unwrap_or_default()
}

fn lines(inbuf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(at) = inbuf.windows(2).position(|w| w == b"\r\n") {
        out.push(inbuf.drain(..at + 2).collect());
    }
    out
}

pub const STAMP: &str = "<1896.697170952@pop.example.com>";

pub struct Pop3Server {
    /// The lines of its CAPA answer; `None`: it does not know CAPA.
    pub capabilities: Option<Vec<&'static str>>,
    pub user: Vec<u8>,
    pub secret: Vec<u8>,
    /// The messages, by number from 1.
    pub messages: Vec<Vec<u8>>,
    /// Appended to every status line after the sign-in (an echo).
    pub echo: String,
    /// What it saw.
    pub received: Vec<u8>,
    pub commands: Vec<String>,
    pub signed_in: bool,
    pub deleted: Vec<usize>,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    user_ok: bool,
    /// A SASL exchange in progress: the mechanism and its step.
    sasl: Option<(String, u8)>,
    login_user: Vec<u8>,
    closed: bool,
}

impl Pop3Server {
    /// `greet`: the server greets first (implicit TLS); after STLS it does not.
    pub fn new(greet: bool, user: &[u8], secret: &[u8]) -> Self {
        Self {
            capabilities: Some(vec!["USER", "UIDL", "TOP", "SASL PLAIN LOGIN XOAUTH2"]),
            user: user.to_vec(),
            secret: secret.to_vec(),
            messages: vec![
                b"Subject: code\r\n\r\nYour code: 482913\r\n".to_vec(),
                b"Subject: dots\r\n\r\n.starts with a dot\r\n".to_vec(),
            ],
            echo: String::new(),
            received: Vec::new(),
            commands: Vec::new(),
            signed_in: false,
            deleted: Vec::new(),
            inbuf: Vec::new(),
            outbuf: if greet {
                format!("+OK POP3 ready {STAMP}\r\n").into_bytes()
            } else {
                Vec::new()
            },
            user_ok: false,
            sasl: None,
            login_user: Vec::new(),
            closed: false,
        }
    }

    fn status(&mut self, text: &str) {
        self.outbuf.extend_from_slice(text.as_bytes());
        if self.signed_in && !self.echo.is_empty() {
            self.outbuf.push(b' ');
            self.outbuf.extend_from_slice(self.echo.as_bytes());
        }
        self.outbuf.extend_from_slice(b"\r\n");
    }

    fn body(&mut self, body: &[u8]) {
        for line in body.split_inclusive(|b| *b == b'\n') {
            if line.starts_with(b".") {
                self.outbuf.push(b'.');
            }
            self.outbuf.extend_from_slice(line);
        }
        self.outbuf.extend_from_slice(b".\r\n");
    }

    fn sign_in(&mut self, ok: bool) {
        if ok {
            self.signed_in = true;
            self.status("+OK maildrop locked and ready");
        } else {
            self.status("-ERR authentication failed");
        }
    }

    fn message(&self, arg: &[u8]) -> Option<(usize, Vec<u8>)> {
        let n: usize = std::str::from_utf8(arg).ok()?.parse().ok()?;
        let m = self.messages.get(n.checked_sub(1)?)?;
        (!self.deleted.contains(&n)).then(|| (n, m.clone()))
    }

    fn line(&mut self, line: Vec<u8>) {
        let body = line[..line.len() - 2].to_vec();
        self.commands
            .push(String::from_utf8_lossy(&body).into_owned());
        if let Some((mechanism, step)) = self.sasl.take() {
            match (mechanism.as_str(), step) {
                ("LOGIN", 0) => {
                    self.login_user = b64d(&body);
                    self.sasl = Some((mechanism, 1));
                    self.status("+ UGFzc3dvcmQ6");
                }
                ("LOGIN", _) => {
                    let ok = self.login_user == self.user && b64d(&body) == self.secret;
                    self.sign_in(ok);
                }
                ("XOAUTH2", 1) => self.status("-ERR authentication failed"),
                (m, _) => {
                    let ok = self.sasl_ok(m, &b64d(&body));
                    self.after_sasl(m, ok);
                }
            }
            return;
        }
        let words: Vec<&[u8]> = body.split(|b| *b == b' ').collect();
        let verb = String::from_utf8_lossy(words[0]).to_ascii_uppercase();
        let arg = |i: usize| words.get(i).copied().unwrap_or_default();
        match verb.as_str() {
            "CAPA" => match self.capabilities.clone() {
                Some(caps) => {
                    self.outbuf
                        .extend_from_slice(b"+OK Capability list follows\r\n");
                    for c in caps {
                        self.outbuf.extend_from_slice(c.as_bytes());
                        self.outbuf.extend_from_slice(b"\r\n");
                    }
                    self.outbuf.extend_from_slice(b".\r\n");
                }
                None => self.status("-ERR unknown command"),
            },
            "USER" => {
                self.user_ok = arg(1) == self.user;
                self.status("+OK send PASS");
            }
            "PASS" => {
                let ok = self.user_ok && body[5..] == self.secret[..];
                self.sign_in(ok);
            }
            "APOP" => {
                let mut hasher = md5::Md5::new();
                hasher.update(STAMP.as_bytes());
                hasher.update(&self.secret);
                let digest: String = hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let ok = arg(1) == self.user && arg(2) == digest.as_bytes();
                self.sign_in(ok);
            }
            "AUTH" => {
                let mechanism = String::from_utf8_lossy(arg(1)).to_ascii_uppercase();
                let initial = words.get(2).map(|w| b64d(w));
                match (mechanism.as_str(), initial) {
                    ("LOGIN", _) => {
                        self.sasl = Some((mechanism, 0));
                        self.status("+ VXNlcm5hbWU6");
                    }
                    (m @ ("PLAIN" | "XOAUTH2"), Some(raw)) => {
                        let m = m.to_string();
                        let ok = self.sasl_ok(&m, &raw);
                        self.after_sasl(&m, ok);
                    }
                    ("PLAIN" | "XOAUTH2", None) => {
                        self.sasl = Some((mechanism, 0));
                        self.status("+ ");
                    }
                    _ => self.status("-ERR unsupported mechanism"),
                }
            }
            "STAT" if self.signed_in => {
                let total: usize = self.messages.iter().map(Vec::len).sum();
                let text = format!("+OK {} {total}", self.messages.len());
                self.status(&text);
            }
            "LIST" | "UIDL" if self.signed_in && words.len() == 1 => {
                self.status("+OK listing follows");
                let mut listing = Vec::new();
                for (i, m) in self.messages.iter().enumerate() {
                    let value = if verb == "LIST" {
                        m.len().to_string()
                    } else {
                        format!("uid-{}", i + 1)
                    };
                    listing.extend_from_slice(format!("{} {value}\r\n", i + 1).as_bytes());
                }
                self.body(&listing);
            }
            "RETR" | "TOP" if self.signed_in => match self.message(arg(1)) {
                Some((_, m)) => {
                    self.status("+OK message follows");
                    self.body(&m);
                }
                None => self.status("-ERR no such message"),
            },
            "DELE" if self.signed_in => match self.message(arg(1)) {
                Some((n, _)) => {
                    self.deleted.push(n);
                    self.status("+OK message deleted");
                }
                None => self.status("-ERR no such message"),
            },
            "NOOP" | "RSET" | "LIST" | "UIDL" if self.signed_in => self.status("+OK"),
            "QUIT" => {
                self.status("+OK bye");
                self.closed = true;
            }
            _ => self.status("-ERR not now"),
        }
    }

    fn sasl_ok(&self, mechanism: &str, raw: &[u8]) -> bool {
        match mechanism {
            "PLAIN" => {
                let mut parts = raw.split(|b| *b == 0);
                let (_, user, pass) = (parts.next(), parts.next(), parts.next());
                user == Some(&self.user[..]) && pass == Some(&self.secret[..])
            }
            _ => {
                let mut expected = b"user=".to_vec();
                expected.extend_from_slice(&self.user);
                expected.extend_from_slice(b"\x01auth=Bearer ");
                expected.extend_from_slice(&self.secret);
                expected.extend_from_slice(b"\x01\x01");
                raw == expected
            }
        }
    }

    fn after_sasl(&mut self, mechanism: &str, ok: bool) {
        if !ok && mechanism == "XOAUTH2" {
            self.sasl = Some((mechanism.to_string(), 1));
            self.status("+ eyJzdGF0dXMiOiI0MDEifQ==");
        } else {
            self.sign_in(ok);
        }
    }
}

impl Peer for Pop3Server {
    fn feed(&mut self, bytes: &[u8]) {
        self.received.extend_from_slice(bytes);
        self.inbuf.extend_from_slice(bytes);
        for line in lines(&mut self.inbuf) {
            self.line(line);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        self.closed
    }
}
