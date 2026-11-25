//! Redis: AUTH over TLS, commands as literal words with parameters as bulk strings, replies
//! as JSON after the reflection search.

use engine::policy::FieldSpec;
use serde_json::{Value, json};

use super::*;

const PASSWORD: &[u8] = b"redis-pass-77x";

/// A Redis server: RESP arrays in, replies out.
pub struct RedisServer {
    pub password: Vec<u8>,
    pub commands: Vec<Vec<Vec<u8>>>,
    pub signed_in: bool,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
}

impl RedisServer {
    fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            commands: Vec::new(),
            signed_in: false,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
        }
    }

    /// One whole command from the input, if there is one.
    fn command(&mut self) -> Option<Vec<Vec<u8>>> {
        let text = &self.inbuf;
        let line_end = |from: usize| {
            text[from..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| from + p)
        };
        let end = line_end(0)?;
        assert_eq!(text[0], b'*');
        let n: usize = std::str::from_utf8(&text[1..end]).unwrap().parse().unwrap();
        let mut at = end + 2;
        let mut words = Vec::new();
        for _ in 0..n {
            let end = line_end(at)?;
            assert_eq!(text[at], b'$');
            let len: usize = std::str::from_utf8(&text[at + 1..end])
                .unwrap()
                .parse()
                .unwrap();
            at = end + 2;
            if text.len() < at + len + 2 {
                return None;
            }
            words.push(text[at..at + len].to_vec());
            at += len + 2;
        }
        self.inbuf.drain(..at);
        Some(words)
    }

    fn answer(&mut self, words: Vec<Vec<u8>>) {
        let verb = String::from_utf8_lossy(&words[0]).to_ascii_uppercase();
        let reply: Vec<u8> = match verb.as_str() {
            "AUTH" => {
                if words.last() == Some(&self.password) {
                    self.signed_in = true;
                    b"+OK\r\n".to_vec()
                } else {
                    b"-WRONGPASS invalid username-password pair\r\n".to_vec()
                }
            }
            "QUIT" => b"+OK\r\n".to_vec(),
            _ if !self.signed_in => b"-NOAUTH Authentication required.\r\n".to_vec(),
            "GET" if words[1] == b"config" => {
                let value = b"requirepass redis-pass-77x";
                let mut out = format!("${}\r\n", value.len()).into_bytes();
                out.extend_from_slice(value);
                out.extend_from_slice(b"\r\n");
                out
            }
            "GET" => {
                let mut out = format!("${}\r\n", words[1].len()).into_bytes();
                out.extend_from_slice(&words[1]);
                out.extend_from_slice(b"\r\n");
                out
            }
            "HGETALL" => b"*4\r\n$4\r\nname\r\n$3\r\nann\r\n$3\r\nage\r\n:41\r\n".to_vec(),
            _ => b"-ERR unknown command\r\n".to_vec(),
        };
        self.commands.push(words);
        self.outbuf.extend(reply);
    }
}

impl Peer for RedisServer {
    fn feed(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
        while let Some(words) = self.command() {
            self.answer(words);
        }
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    fn closed(&self) -> bool {
        false
    }
}

fn redis_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![operation(json!({"name": "cache", "steps": [
            {"do": "open", "connection": "redis",
             "destinations": [{"host": "cache.example.com", "port": 6380}],
             "login": {"user": "app", "password": "{{password}}"}},
            {"do": "return", "relay": {"commands": [
                {"name": "get", "text": "GET", "params": [{"max_len": 128}]},
                {"name": "user", "text": "HGETALL", "params": [{"template": "user:1"}]}
            ]}}
        ]}))],
    )
}

fn run(
    s: &Setup,
    fake: &mut Fake<RedisServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<Output> {
    let call = sign(
        s,
        "cache",
        session("cache.example.com", 6380, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

#[test]
fn auth_then_commands_with_replies_as_json() {
    let s = redis_setup();
    let mut fake = Fake::new(RedisServer::new(PASSWORD));
    let out = session_output(run(
        &s,
        &mut fake,
        vec![command("get", &["greeting"]), command("user", &[])],
    ));
    assert!(out.error.is_none());
    assert_eq!(fake.opened, ["tls"]);
    let first: Value = serde_json::from_slice(&out.results[0].data).unwrap();
    assert_eq!(first, json!("greeting"));
    let second: Value = serde_json::from_slice(&out.results[1].data).unwrap();
    assert_eq!(second, json!(["name", "ann", "age", 41]));
    assert_eq!(fake.peer.commands[0][0], b"AUTH");
    assert_eq!(
        fake.peer.commands[2],
        [b"HGETALL".to_vec(), b"user:1".to_vec()]
    );
}

#[test]
fn command_injection_through_a_parameter_stays_one_argument() {
    let s = redis_setup();
    let mut fake = Fake::new(RedisServer::new(PASSWORD));
    let evil = "k\r\nFLUSHALL\r\n*1\r\n$8\r\nFLUSHALL";
    let out = session_output(run(&s, &mut fake, vec![command("get", &[evil])]));
    assert!(out.error.is_none());
    let verbs: Vec<&[u8]> = fake.peer.commands.iter().map(|c| c[0].as_slice()).collect();
    assert_eq!(
        verbs,
        [&b"AUTH"[..], b"GET", b"QUIT"],
        "AUTH, one GET, QUIT"
    );
    assert_eq!(
        fake.peer.commands[1],
        [b"GET".to_vec(), evil.as_bytes().to_vec()]
    );
}

#[test]
fn a_command_outside_its_shape_is_refused_first() {
    let s = redis_setup();
    for commands in [
        vec![command("flushall", &[])],
        vec![command("get", &[&"x".repeat(129)])],
        vec![command("user", &["user:2"])],
    ] {
        let mut fake = Fake::new(RedisServer::new(PASSWORD));
        let result = run(&s, &mut fake, commands);
        assert!(matches!(result, Err(engine::Error::RequestInvalid { .. })));
        assert!(fake.opened.is_empty());
    }
}

#[test]
fn a_command_text_that_is_not_literal_words_is_refused_by_the_policy() {
    let bad = operation(json!({"name": "cache", "steps": [
        {"do": "open", "connection": "redis",
         "destinations": [{"host": "cache.example.com", "port": 6380}],
         "login": {"user": "app", "password": "{{password}}"}},
        {"do": "return", "relay": {"commands": [
            {"name": "get", "text": "GET {{password}}"}
        ]}}
    ]}));
    let policy = engine::policy::Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: Vec::new(),
        operations: vec![bad],
    };
    assert!(policy.validate().is_err());
}

#[test]
fn a_secret_in_a_reply_never_goes_back() {
    let s = redis_setup();
    let mut fake = Fake::new(RedisServer::new(PASSWORD));
    let out = session_output(run(&s, &mut fake, vec![command("get", &["config"])]));
    assert!(out.results.is_empty());
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = redis_setup();
    let mut fake = Fake::new(RedisServer::new(b"other"));
    let result = run(&s, &mut fake, vec![command("get", &["x"])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert_eq!(fake.peer.commands.len(), 1, "nothing after AUTH");
}
