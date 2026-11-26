//! MySQL: TLS before the sign-in, `caching_sha2_password` only (fast and full
//! authentication), prepared statements with every parameter bound, rows after the
//! reflection search.

use engine::policy::FieldSpec;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

const PASSWORD: &[u8] = b"my-sql-pass-31z";
const NONCE: [u8; 20] = *b"0123456789abcdefghij";

const PROTOCOL_41: u32 = 0x200;
const SSL: u32 = 0x800;
const SECURE: u32 = 0x8000;
const PLUGIN_AUTH: u32 = 0x8_0000;
const DEPRECATE_EOF: u32 = 0x100_0000;
const CONNECT_WITH_DB: u32 = 0x8;
const LOCAL_FILES: u32 = 0x80;
const MULTI_STATEMENTS: u32 = 0x1_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Misbehave {
    None,
    /// Answers the sign-in with an auth switch to `mysql_native_password`.
    SwitchNative,
    /// Answers the sign-in with an auth switch to `mysql_clear_password`.
    SwitchClear,
    /// Asks for a local file instead of running the statement.
    LocalInfile,
}

/// A MySQL server after TLS: it reads the handshake response and statements.
pub struct MysqlServer {
    pub password: Vec<u8>,
    /// True when the password's hash is cached (fast authentication); else full.
    pub cached: bool,
    pub deprecate_eof: bool,
    pub misbehave: Misbehave,
    /// What it saw: the client's capabilities, the user, the database, the plugin, the
    /// cleartext password of a full authentication, the statements and their parameters.
    pub caps: u32,
    pub user: Vec<u8>,
    pub database: Option<Vec<u8>>,
    pub plugin: Vec<u8>,
    pub cleartext: Option<Vec<u8>>,
    pub prepared: Vec<Vec<u8>>,
    pub executed: Vec<Vec<Vec<u8>>>,
    pub signed_in: bool,
    state: u8,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    seq: u8,
}

/// A packet with its header.
pub fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes()[..3].to_vec();
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

/// The greeting of a server with these capabilities.
pub fn greeting(caps: u32) -> Vec<u8> {
    let mut g = vec![10];
    g.extend_from_slice(b"8.0.36-test\0");
    g.extend_from_slice(&7u32.to_le_bytes());
    g.extend_from_slice(&NONCE[..8]);
    g.push(0);
    g.extend_from_slice(&(caps as u16).to_le_bytes());
    g.push(45);
    g.extend_from_slice(&2u16.to_le_bytes());
    g.extend_from_slice(&((caps >> 16) as u16).to_le_bytes());
    g.push(21);
    g.extend_from_slice(&[0; 10]);
    g.extend_from_slice(&NONCE[8..]);
    g.push(0);
    g.extend_from_slice(b"caching_sha2_password\0");
    packet(0, &g)
}

pub const SERVER_CAPS: u32 = PROTOCOL_41 | SSL | SECURE | PLUGIN_AUTH | DEPRECATE_EOF | 0xf;

fn lenenc(out: &mut Vec<u8>, bytes: &[u8]) {
    assert!(bytes.len() < 251);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

fn column(name: &str, kind: u8, flags: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for part in ["def", "shop", "t", "t", name, name] {
        lenenc(&mut out, part.as_bytes());
    }
    out.push(0x0c);
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&255u32.to_le_bytes());
    out.push(kind);
    out.extend_from_slice(&flags.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out
}

fn ok(affected: u8) -> Vec<u8> {
    vec![0x00, affected, 0, 2, 0, 0, 0]
}

fn err(code: u16, state: &str, message: &str) -> Vec<u8> {
    let mut out = vec![0xff];
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    out.extend_from_slice(state.as_bytes());
    out.extend_from_slice(message.as_bytes());
    out
}

fn scramble(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    let one = Sha256::digest(password);
    let two = Sha256::digest(one);
    let mut h = Sha256::new();
    h.update(two);
    h.update(nonce);
    let three = h.finalize();
    one.iter().zip(three.iter()).map(|(a, b)| a ^ b).collect()
}

impl MysqlServer {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            cached: true,
            deprecate_eof: true,
            misbehave: Misbehave::None,
            caps: 0,
            user: Vec::new(),
            database: None,
            plugin: Vec::new(),
            cleartext: None,
            prepared: Vec::new(),
            executed: Vec::new(),
            signed_in: false,
            state: 0,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            seq: 0,
        }
    }

    fn send(&mut self, payload: &[u8]) {
        let framed = packet(self.seq, payload);
        self.seq = self.seq.wrapping_add(1);
        self.outbuf.extend(framed);
    }

    fn eof(&mut self) {
        if !self.deprecate_eof {
            self.send(&[0xfe, 0, 0, 2, 0]);
        }
    }

    fn handshake(&mut self, p: &[u8]) {
        self.caps = u32::from_le_bytes(p[..4].try_into().unwrap());
        let mut at = 32;
        let end = at + p[at..].iter().position(|b| *b == 0).unwrap();
        self.user = p[at..end].to_vec();
        at = end + 1;
        let n = p[at] as usize;
        let proof = p[at + 1..at + 1 + n].to_vec();
        at += 1 + n;
        if self.caps & CONNECT_WITH_DB != 0 {
            let end = at + p[at..].iter().position(|b| *b == 0).unwrap();
            self.database = Some(p[at..end].to_vec());
            at = end + 1;
        }
        let end = at + p[at..].iter().position(|b| *b == 0).unwrap();
        self.plugin = p[at..end].to_vec();
        match self.misbehave {
            Misbehave::SwitchNative => {
                let mut switch = vec![0xfe];
                switch.extend_from_slice(b"mysql_native_password\0");
                switch.extend_from_slice(&NONCE);
                switch.push(0);
                self.send(&switch);
                self.state = 9;
                return;
            }
            Misbehave::SwitchClear => {
                let mut switch = vec![0xfe];
                switch.extend_from_slice(b"mysql_clear_password\0");
                self.send(&switch);
                self.state = 9;
                return;
            }
            _ => {}
        }
        if self.cached {
            if proof == scramble(&self.password, &NONCE) {
                self.send(&[0x01, 0x03]);
                self.send(&ok(0));
                self.signed_in = true;
                self.state = 2;
            } else {
                self.send(&err(1045, "28000", "Access denied"));
                self.state = 9;
            }
        } else {
            self.send(&[0x01, 0x04]);
            self.state = 1;
        }
    }

    fn statement(&mut self, p: &[u8]) {
        match p[0] {
            0x16 => {
                let sql = p[1..].to_vec();
                let params = sql.iter().filter(|b| **b == b'?').count() as u16;
                let select = sql.starts_with(b"SELECT");
                let columns: u16 = if select { 3 } else { 0 };
                self.prepared.push(sql.clone());
                if sql.starts_with(b"BAD") {
                    self.send(&err(1064, "42000", "You have an error in your SQL syntax"));
                    return;
                }
                let mut answer = vec![0x00];
                answer.extend_from_slice(&1u32.to_le_bytes());
                answer.extend_from_slice(&columns.to_le_bytes());
                answer.extend_from_slice(&params.to_le_bytes());
                answer.extend_from_slice(&[0, 0, 0]);
                self.send(&answer);
                for _ in 0..params {
                    self.send(&column("?", 0xfd, 0));
                }
                if params > 0 {
                    self.eof();
                }
                for (name, kind) in [("id", 0x03), ("name", 0xfd), ("note", 0xfd)]
                    .into_iter()
                    .take(columns as usize)
                {
                    self.send(&column(name, kind, 0));
                }
                if columns > 0 {
                    self.eof();
                }
            }
            0x17 => {
                let sql = self.prepared.last().cloned().unwrap_or_default();
                let n = sql.iter().filter(|b| **b == b'?').count();
                let mut params = Vec::new();
                if n > 0 {
                    let mut at = 1 + 4 + 1 + 4 + n.div_ceil(8);
                    assert_eq!(p[at], 1, "types are bound");
                    at += 1;
                    for i in 0..n {
                        assert_eq!(p[at + 2 * i], 0xfe, "each parameter a string");
                    }
                    at += 2 * n;
                    for _ in 0..n {
                        let len = p[at] as usize;
                        assert!(len < 251);
                        params.push(p[at + 1..at + 1 + len].to_vec());
                        at += 1 + len;
                    }
                    assert_eq!(at, p.len());
                }
                self.executed.push(params.clone());
                if self.misbehave == Misbehave::LocalInfile {
                    let mut ask = vec![0xfb];
                    ask.extend_from_slice(b"/etc/passwd");
                    self.send(&ask);
                    return;
                }
                if !sql.starts_with(b"SELECT") {
                    self.send(&ok(3));
                    return;
                }
                self.send(&[3]);
                for (name, kind) in [("id", 0x03), ("name", 0xfd), ("note", 0xfd)] {
                    self.send(&column(name, kind, 0));
                }
                self.eof();
                let key = params.first().cloned().unwrap_or_default();
                let rows: Vec<(i32, Vec<u8>, Option<Vec<u8>>)> = if key == b"leak" {
                    vec![(1, b"ann".to_vec(), Some(self.password.clone()))]
                } else {
                    vec![
                        (1, key.clone(), Some(b"first".to_vec())),
                        (2, b"bob".to_vec(), None),
                    ]
                };
                for (id, name, note) in rows {
                    let mut row = vec![0x00];
                    // NULL bitmap: offset 2, the third column (bit 4).
                    row.push(if note.is_none() { 0b0001_0000 } else { 0 });
                    row.extend_from_slice(&id.to_le_bytes());
                    lenenc(&mut row, &name);
                    if let Some(note) = note {
                        lenenc(&mut row, &note);
                    }
                    self.send(&row);
                }
                if self.deprecate_eof {
                    self.send(&[0xfe, 0, 0, 2, 0, 0, 0]);
                } else {
                    self.send(&[0xfe, 0, 0, 2, 0]);
                }
            }
            0x19 | 0x01 => {}
            _ => self.send(&err(1047, "08S01", "Unknown command")),
        }
    }
}

impl Peer for MysqlServer {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        loop {
            if self.inbuf.len() < 4 {
                return;
            }
            let len = u32::from_le_bytes([self.inbuf[0], self.inbuf[1], self.inbuf[2], 0]) as usize;
            if self.inbuf.len() < 4 + len {
                return;
            }
            let seq = self.inbuf[3];
            let framed: Vec<u8> = self.inbuf.drain(..4 + len).collect();
            let payload = framed[4..].to_vec();
            self.seq = seq.wrapping_add(1);
            match self.state {
                0 => self.handshake(&payload),
                1 => {
                    // Full authentication: the password and a NUL.
                    self.cleartext = Some(payload.clone());
                    if payload.strip_suffix(&[0]) == Some(self.password.as_slice()) {
                        self.signed_in = true;
                        self.send(&ok(0));
                        self.state = 2;
                    } else {
                        self.send(&err(1045, "28000", "Access denied"));
                        self.state = 9;
                    }
                }
                2 => self.statement(&payload),
                _ => {}
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

fn mysql_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "orders", "steps": [
            {"do": "open", "connection": "mysql",
             "destinations": [{"host": "db.example.com", "port": 3306}],
             "login": {"user": "reporting", "password": "{{password}}", "database": "shop"}},
            {"do": "return", "relay": {"commands": [
                {"name": "find", "text": "SELECT id, name, note FROM t WHERE name = ?",
                 "params": [{"pattern": "[a-z0-9';= -]{1,40}"}], "columns": ["id", "name", "note"]},
                {"name": "names", "text": "SELECT id, name, note FROM t WHERE name = ?",
                 "params": [{"pattern": "[a-z]{1,8}"}], "columns": ["name"]},
                {"name": "touch", "text": "UPDATE t SET seen = 1 WHERE id = ?",
                 "params": [{"pattern": "[0-9]{1,6}"}]},
                {"name": "bad", "text": "BAD SQL"},
                {"name": "two", "text": "SELECT id, name, note FROM t WHERE name = ?"}
            ]}}
        ]}))],
    )
}

fn fake(server: MysqlServer, caps: u32) -> Fake<MysqlServer> {
    let mut fake = Fake::new(server);
    fake.plain.push_back(greeting(caps));
    fake
}

fn run(
    s: &Setup,
    fake: &mut Fake<MysqlServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "orders",
        session("db.example.com", 3306, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

#[test]
fn tls_then_fast_auth_then_bound_statements() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("find", &["ann"]), command("touch", &["42"])],
    ));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(fake.opened, ["starttls"]);
    // In the clear: only the SSLRequest, 32 bytes with no user name.
    assert_eq!(fake.plain_written.len(), 4 + 32);
    assert_eq!(fake.plain_written[3], 1);
    let caps = u32::from_le_bytes(fake.plain_written[4..8].try_into().unwrap());
    assert_ne!(caps & SSL, 0);
    assert!(!holds(&fake.plain_written, b"reporting"));
    let server = &fake.peer;
    assert_eq!(server.user, b"reporting");
    assert_eq!(server.database.as_deref(), Some(&b"shop"[..]));
    assert_eq!(server.plugin, b"caching_sha2_password");
    assert_eq!(server.caps & (LOCAL_FILES | MULTI_STATEMENTS), 0);
    assert!(
        server.cleartext.is_none(),
        "fast authentication sends no password"
    );
    let rows: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(
        rows,
        json!({"columns": ["id", "name", "note"],
               "rows": [["1", "ann", "first"], ["2", "bob", null]]})
    );
    assert_eq!(out.results[0].status, Some(0));
    let touched: Value = serde_json::from_slice(&out.results[1].data).unwrap();
    assert_eq!(touched["affected"], json!(3));
    assert_eq!(
        server.executed,
        [vec![b"ann".to_vec()], vec![b"42".to_vec()]]
    );
    let (ok, reason) = last_closed(&s);
    assert!(ok);
    assert_eq!(reason, "done");
}

#[test]
fn full_authentication_and_eof_packets() {
    let s = mysql_setup();
    let mut server = MysqlServer::new(PASSWORD);
    server.cached = false;
    server.deprecate_eof = false;
    let mut fake = fake(server, SERVER_CAPS & !DEPRECATE_EOF);
    let out = session_output(run(&s, &mut fake, vec![command("names", &["ann"])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    let mut expected = PASSWORD.to_vec();
    expected.push(0);
    assert!(
        fake.peer.cleartext.as_deref() == Some(expected.as_slice()),
        "the password after TLS"
    );
    assert_eq!(fake.peer.caps & DEPRECATE_EOF, 0);
    let rows: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(
        rows,
        json!({"columns": ["name"], "rows": [["ann"], ["bob"]]})
    );
}

#[test]
fn injection_through_a_parameter_stays_a_bound_value() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    let evil = "x' or '1'='1'; drop table t; --";
    let out = session_output(run(&s, &mut fake, vec![command("find", &[evil])]));
    assert!(out.error.is_none(), "{:?}", out.error);
    assert_eq!(
        fake.peer.prepared,
        [b"SELECT id, name, note FROM t WHERE name = ?".to_vec()],
        "the statement text is the rule's"
    );
    assert_eq!(fake.peer.executed, [vec![evil.as_bytes().to_vec()]]);
}

#[test]
fn a_server_without_tls_gets_nothing() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS & !SSL);
    let result = run(&s, &mut fake, vec![command("find", &["ann"])]);
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "{result:?}"
    );
    assert!(fake.plain_written.is_empty(), "not even an SSLRequest");
    assert!(fake.peer.user.is_empty());
}

#[test]
fn bytes_after_the_greeting_are_refused() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    fake.plain_extra = packet(1, &ok(0));
    let result = run(&s, &mut fake, vec![command("find", &["ann"])]);
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "{result:?}"
    );
    assert!(fake.peer.user.is_empty());
}

#[test]
fn an_auth_switch_to_a_weaker_plugin_is_refused() {
    for misbehave in [Misbehave::SwitchNative, Misbehave::SwitchClear] {
        let s = mysql_setup();
        let mut server = MysqlServer::new(PASSWORD);
        server.misbehave = misbehave;
        let mut fake = fake(server, SERVER_CAPS);
        let result = run(&s, &mut fake, vec![command("find", &["ann"])]);
        assert!(
            matches!(result, Err(engine::Error::ServerUntrusted { .. })),
            "{result:?}"
        );
        assert!(
            fake.peer.cleartext.is_none(),
            "{misbehave:?}: nothing after the switch"
        );
        assert!(fake.peer.prepared.is_empty());
    }
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(b"other"), SERVER_CAPS);
    let result = run(&s, &mut fake, vec![command("find", &["ann"])]);
    assert!(
        matches!(result, Err(engine::Error::AuthRefused { .. })),
        "{result:?}"
    );
    assert!(fake.peer.prepared.is_empty());
}

#[test]
fn a_local_file_request_is_refused() {
    let s = mysql_setup();
    let mut server = MysqlServer::new(PASSWORD);
    server.misbehave = Misbehave::LocalInfile;
    let mut fake = fake(server, SERVER_CAPS);
    let out = session_output(run(&s, &mut fake, vec![command("find", &["ann"])]));
    assert!(out.results.is_empty());
    assert!(matches!(
        out.error,
        Some(engine::Error::ServerUntrusted { .. })
    ));
}

#[test]
fn a_secret_in_a_row_never_goes_back() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    let out = session_output(run(&s, &mut fake, vec![command("find", &["leak"])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn server_errors_and_shape_errors() {
    let s = mysql_setup();
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("bad", &[]), command("two", &[])],
    ));
    let error: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(error["error"]["code"], json!("1064"));
    assert_eq!(error["error"]["state"], json!("42000"));
    assert_eq!(out.results[0].status, Some(1));
    // A statement whose placeholders the rule does not fill fails, and stops the rest.
    assert_eq!(out.results.len(), 1);
    assert!(matches!(
        out.error,
        Some(engine::Error::RequestInvalid { .. })
    ));
}

#[test]
fn commands_outside_their_shape_are_refused_first() {
    let s = mysql_setup();
    for commands in [
        vec![command("drop", &[])],
        vec![command("find", &["ANN"])],
        vec![command("touch", &["1 or 1=1"])],
        vec![command("names", &["ann", "bob"])],
    ] {
        let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
        let result = run(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.opened.is_empty());
    }
}

#[test]
fn the_connection_byte_limit_ends_it() {
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "orders", "steps": [
            {"do": "open", "connection": "mysql",
             "destinations": [{"host": "db.example.com", "port": 3306}],
             "login": {"user": "reporting", "password": "{{password}}"},
             "limits": {"bytes": 400}},
            {"do": "return", "relay": {"commands": [
                {"name": "find", "text": "SELECT id, name, note FROM t WHERE name = ?",
                 "params": [{"pattern": "[a-z]{1,8}"}]}
            ]}}
        ]}))],
    );
    let mut fake = fake(MysqlServer::new(PASSWORD), SERVER_CAPS);
    let commands = (0..8).map(|_| command("find", &["ann"])).collect();
    let out = session_output(run(&s, &mut fake, commands));
    assert!(out.results.len() < 8);
    assert!(
        matches!(out.error, Some(engine::Error::Budget { .. })),
        "{:?}",
        out.error
    );
    let (ok, reason) = last_closed(&s);
    assert!(!ok);
    assert_eq!(reason, "bytes");
}
