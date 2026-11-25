//! SMTP and IMAP servers for the tests, line by line.

use base64::Engine as _;

use super::Peer;

fn b64d(text: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim_ascii())
        .unwrap_or_default()
}

/// Takes whole lines (with CRLF) from `inbuf`.
fn lines(inbuf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(at) = inbuf.windows(2).position(|w| w == b"\r\n") {
        out.push(inbuf.drain(..at + 2).collect());
    }
    out
}

pub struct SmtpServer {
    /// Mechanisms in the `AUTH` capability.
    pub mechanisms: Vec<&'static str>,
    pub user: Vec<u8>,
    pub secret: Vec<u8>,
    /// Text of the reply to the end of data.
    pub accepted: &'static str,
    /// What it saw.
    pub received: Vec<u8>,
    pub signed_in: bool,
    pub auth_lines: usize,
    pub messages: Vec<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)>,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    login: Option<u8>,
    login_user: Vec<u8>,
    data: Option<Vec<u8>>,
    from: Vec<u8>,
    to: Vec<Vec<u8>>,
    closed: bool,
}

impl SmtpServer {
    /// `greet`: the server says hello first (implicit TLS); after STARTTLS it does not.
    pub fn new(greet: bool, user: &[u8], secret: &[u8]) -> Self {
        Self {
            mechanisms: vec!["PLAIN", "LOGIN"],
            user: user.to_vec(),
            secret: secret.to_vec(),
            accepted: "2.0.0 queued",
            received: Vec::new(),
            signed_in: false,
            auth_lines: 0,
            messages: Vec::new(),
            inbuf: Vec::new(),
            outbuf: if greet {
                b"220 mail.example.com ESMTP\r\n".to_vec()
            } else {
                Vec::new()
            },
            login: None,
            login_user: Vec::new(),
            data: None,
            from: Vec::new(),
            to: Vec::new(),
            closed: false,
        }
    }

    fn reply(&mut self, text: &str) {
        self.outbuf.extend_from_slice(text.as_bytes());
        self.outbuf.extend_from_slice(b"\r\n");
    }

    fn line(&mut self, line: Vec<u8>) {
        if let Some(data) = &mut self.data {
            if line == b".\r\n" {
                let data = self.data.take().unwrap();
                self.messages
                    .push((self.from.clone(), std::mem::take(&mut self.to), data));
                let text = format!("250 {}", self.accepted);
                self.reply(&text);
            } else {
                data.extend_from_slice(&line);
            }
            return;
        }
        let body = &line[..line.len() - 2];
        match self.login {
            Some(1) => {
                self.auth_lines += 1;
                self.login_user = b64d(body);
                self.login = Some(2);
                self.reply("334 UGFzc3dvcmQ6");
                return;
            }
            Some(_) => {
                self.auth_lines += 1;
                self.login = None;
                let ok = self.login_user == self.user && b64d(body) == self.secret;
                self.finish_auth(ok);
                return;
            }
            None => {}
        }
        let upper = String::from_utf8_lossy(body).to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let mut caps = String::from("250-mail.example.com\r\n250-PIPELINING\r\n");
            caps.push_str(&format!("250 AUTH {}", self.mechanisms.join(" ")));
            self.reply(&caps);
        } else if upper.starts_with("AUTH PLAIN ") {
            self.auth_lines += 1;
            let raw = b64d(&body[11..]);
            let mut parts = raw.split(|b| *b == 0);
            let (_, user, pass) = (parts.next(), parts.next(), parts.next());
            let ok = user == Some(&self.user[..]) && pass == Some(&self.secret[..]);
            self.finish_auth(ok);
        } else if upper == "AUTH LOGIN" {
            self.auth_lines += 1;
            self.login = Some(1);
            self.reply("334 VXNlcm5hbWU6");
        } else if upper.starts_with("AUTH ") {
            self.auth_lines += 1;
            self.reply("504 5.5.4 mechanism not supported");
        } else if upper.starts_with("MAIL FROM:") && self.signed_in {
            self.from = body[10..].to_vec();
            self.reply("250 2.1.0 ok");
        } else if upper.starts_with("RCPT TO:") && self.signed_in {
            self.to.push(body[8..].to_vec());
            self.reply("250 2.1.5 ok");
        } else if upper == "DATA" && self.signed_in {
            self.data = Some(Vec::new());
            self.reply("354 go ahead");
        } else if upper == "QUIT" {
            self.reply("221 bye");
            self.closed = true;
        } else if upper == "RSET" {
            self.reply("250 ok");
        } else {
            self.reply("503 5.5.1 bad sequence");
        }
    }

    fn finish_auth(&mut self, ok: bool) {
        if ok {
            self.signed_in = true;
            self.reply("235 2.7.0 accepted");
        } else {
            self.reply("535 5.7.8 rejected");
        }
    }
}

impl Peer for SmtpServer {
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

pub struct ImapServer {
    pub capabilities: &'static str,
    pub user: Vec<u8>,
    pub secret: Vec<u8>,
    /// The answer to a command other than sign-in: untagged lines (literals included) and
    /// whether it succeeds.
    pub answer: fn(&[u8]) -> (Vec<u8>, bool),
    /// What it saw.
    pub received: Vec<u8>,
    pub commands: Vec<Vec<u8>>,
    pub signed_in: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    authenticate: Option<Vec<u8>>,
    closed: bool,
}

/// The words of an IMAP line: atoms and quoted strings, unquoted.
pub fn words(line: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b' ' => i += 1,
            b'"' => {
                let mut word = Vec::new();
                i += 1;
                while line[i] != b'"' {
                    if line[i] == b'\\' {
                        i += 1;
                    }
                    word.push(line[i]);
                    i += 1;
                }
                i += 1;
                out.push(word);
            }
            _ => {
                let end = line[i..]
                    .iter()
                    .position(|b| *b == b' ')
                    .map_or(line.len(), |p| i + p);
                out.push(line[i..end].to_vec());
                i = end;
            }
        }
    }
    out
}

impl ImapServer {
    pub fn new(greet: bool, user: &[u8], secret: &[u8]) -> Self {
        Self {
            capabilities: "IMAP4rev1 AUTH=PLAIN",
            user: user.to_vec(),
            secret: secret.to_vec(),
            answer: |_| (Vec::new(), true),
            received: Vec::new(),
            commands: Vec::new(),
            signed_in: false,
            inbuf: Vec::new(),
            outbuf: if greet {
                b"* OK IMAP ready\r\n".to_vec()
            } else {
                Vec::new()
            },
            authenticate: None,
            closed: false,
        }
    }

    fn line(&mut self, line: Vec<u8>) {
        let body = line[..line.len() - 2].to_vec();
        if let Some(tag) = self.authenticate.take() {
            let raw = b64d(&body);
            let mut parts = raw.split(|b| *b == 0);
            let (_, user, pass) = (parts.next(), parts.next(), parts.next());
            let ok = user == Some(&self.user[..]) && pass == Some(&self.secret[..]);
            self.done(&tag, ok);
            return;
        }
        let w = words(&body);
        let tag = w[0].clone();
        let verb = String::from_utf8_lossy(&w[1]).to_ascii_uppercase();
        match verb.as_str() {
            "CAPABILITY" => {
                let caps = format!("* CAPABILITY {}\r\n", self.capabilities);
                self.outbuf.extend_from_slice(caps.as_bytes());
                self.tagged(&tag, "OK done");
            }
            "LOGIN" => {
                let ok = !self.capabilities.contains("LOGINDISABLED")
                    && w[2] == self.user
                    && w[3] == self.secret;
                self.done(&tag, ok);
            }
            "AUTHENTICATE" => {
                self.outbuf.extend_from_slice(b"+ \r\n");
                self.authenticate = Some(tag);
            }
            "LOGOUT" => {
                self.outbuf.extend_from_slice(b"* BYE\r\n");
                self.tagged(&tag, "OK bye");
                self.closed = true;
            }
            _ if self.signed_in => {
                let rest = body[tag.len() + 1..].to_vec();
                self.commands.push(rest.clone());
                let (untagged, ok) = (self.answer)(&rest);
                self.outbuf.extend_from_slice(&untagged);
                self.tagged(&tag, if ok { "OK done" } else { "NO failed" });
            }
            _ => self.tagged(&tag, "BAD not now"),
        }
    }

    fn done(&mut self, tag: &[u8], ok: bool) {
        self.signed_in = ok;
        self.tagged(tag, if ok { "OK signed in" } else { "NO rejected" });
    }

    fn tagged(&mut self, tag: &[u8], text: &str) {
        self.outbuf.extend_from_slice(tag);
        self.outbuf.push(b' ');
        self.outbuf.extend_from_slice(text.as_bytes());
        self.outbuf.extend_from_slice(b"\r\n");
    }
}

impl Peer for ImapServer {
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
