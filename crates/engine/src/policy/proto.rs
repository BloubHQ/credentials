//! The protocol connections of layer 1: SSH (with SFTP and port forwarding, local and
//! remote), PostgreSQL, MySQL, SMTP, IMAP, POP3, Redis, MQTT, AMQP 0-9-1, AMQP 1.0 and FTP
//! over TLS.
//!
//! Each is a standard family with one meaning for the steps:
//!
//! - `open` signs in with [`Login`] (the node renders it; the caller never sees it), and for
//!   SSH proves the server holds a pinned host key;
//! - `send` runs one [`Command`] the policy fixes: its `text` and `params` are templates;
//! - `receive` captures from the result of the command just before it;
//! - `return` relays the caller's commands, each of which must name a [`CommandRule`] and give
//!   exactly its caller parameters, each matching the rule's pattern. A caller parameter never
//!   becomes part of a command's text: it is a bound parameter (PostgreSQL, MySQL), a bulk
//!   string (Redis), a quoted string (IMAP), a single-quoted shell word (SSH), a path checked
//!   for traversal (SFTP, FTP), a message number (POP3), a topic with no wildcard or a
//!   payload (MQTT), or a message body (AMQP). SMTP relays messages within a [`MailRule`]
//!   instead, an SSH shell or forward
//!   relays signed frames, and an MQTT live relay hands back the messages of its
//!   subscriptions.

use serde::{Deserialize, Serialize};

use super::{Checked, Connection, Kinds, Open, Policy, Relay, Send, ensure, fail, is_token};
use crate::template::Var;

/// Most commands a relay names.
pub const MAX_COMMANDS: usize = 32;
/// Most parameters of one command.
pub const MAX_PARAMS: usize = 32;
/// Most pinned host keys.
pub const MAX_HOST_KEYS: usize = 16;
/// Most keyboard-interactive answers.
pub const MAX_ANSWERS: usize = 8;
/// Longest parameter of the caller, in bytes.
pub const MAX_PARAM: usize = 64 * 1024;
/// Longest message a caller relays over SMTP, in bytes.
pub const MAX_MAIL: usize = 8 * 1024 * 1024;
/// Most recipients of one message.
pub const MAX_RECIPIENTS: usize = 100;
/// Most messages one MQTT subscription or AMQP get hands back.
pub const MAX_MESSAGES: usize = 256;
/// Longest wait of an MQTT subscription for its messages, in milliseconds.
pub const MAX_MESSAGE_WAIT_MS: u64 = 60_000;
/// Default messages of a subscription or get, and default wait.
pub const DEFAULT_MESSAGES: (usize, u64) = (16, 5_000);

/// An authentication mechanism, when the policy pins one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mechanism {
    /// SSH `password`; MQTT user name and password.
    Password,
    /// SSH `publickey`.
    Publickey,
    /// SSH `keyboard-interactive`.
    KeyboardInteractive,
    /// SASL `SCRAM-SHA-256` (PostgreSQL).
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    /// SASL `PLAIN` (SMTP, IMAP `AUTHENTICATE`, AMQP, AMQP 1.0).
    Plain,
    /// SASL `EXTERNAL` (AMQP 1.0): the TLS client certificate of the `open` authenticates;
    /// `user` is the authorization identity (may be empty), and no password is sent.
    External,
    /// SMTP `AUTH LOGIN`, IMAP `LOGIN`.
    Login,
    /// SASL `XOAUTH2` (SMTP, IMAP), with a bearer token.
    Xoauth2,
    /// Redis `AUTH`.
    Auth,
    /// MySQL `caching_sha2_password`.
    #[serde(rename = "caching-sha2-password")]
    CachingSha2Password,
    /// A bearer token in the password of an MQTT `CONNECT`.
    Token,
    /// `USER` and `PASS` (FTP, POP3): the password itself goes to the server.
    User,
    /// POP3 `APOP` (RFC 1939 section 7): MD5 over the server's timestamp and the password.
    /// The password does not cross the connection, but MD5 is weak and a captured exchange
    /// can be guessed against offline; a summary flags it.
    Apop,
}

impl Mechanism {
    /// Its name.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Password => "password",
            Mechanism::Publickey => "publickey",
            Mechanism::KeyboardInteractive => "keyboard-interactive",
            Mechanism::ScramSha256 => "scram-sha-256",
            Mechanism::Plain => "plain",
            Mechanism::External => "external",
            Mechanism::Login => "login",
            Mechanism::Xoauth2 => "xoauth2",
            Mechanism::Auth => "auth",
            Mechanism::CachingSha2Password => "caching-sha2-password",
            Mechanism::Token => "token",
            Mechanism::User => "user",
            Mechanism::Apop => "apop",
        }
    }
}

/// The MQTT version of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MqttVersion {
    /// 3.1.1 (protocol level 4).
    #[default]
    #[serde(rename = "3.1.1")]
    V311,
    /// 5.0.
    #[serde(rename = "5")]
    V5,
}

/// How a delivery of AMQP 1.0 is settled (section 3.4 of the standard): the link's
/// `snd-settle-mode` and `rcv-settle-mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SettleMode {
    /// `snd-settle-mode` settled: the sender settles before the receiver says anything, so a
    /// message is delivered at most once.
    Settled,
    /// `snd-settle-mode` unsettled, `rcv-settle-mode` first: the receiver settles when it
    /// states its outcome (at least once). The default.
    #[default]
    First,
    /// `snd-settle-mode` unsettled, `rcv-settle-mode` second: the receiver states its outcome
    /// unsettled and settles only after the sender has, so neither forgets a delivery the
    /// other still holds. A broker that does not take it is refused.
    Second,
}

impl SettleMode {
    /// Its name.
    pub fn as_str(self) -> &'static str {
        match self {
            SettleMode::Settled => "settled",
            SettleMode::First => "first",
            SettleMode::Second => "second",
        }
    }
}

/// What an SSH command rule runs on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SshChannel {
    /// A command line (`exec`).
    #[default]
    Exec,
    /// The SFTP subsystem: `text` is `read` (the path), `write` (the path and the bytes),
    /// `list` (a directory), `stat` (a path), `rename` (two paths), `delete` (a file),
    /// `mkdir` or `rmdir` (a directory).
    Sftp,
    /// Local port forwarding: `text` is the `host:port` the server connects to, fixed by the
    /// policy; the caller's frames go there on a streaming call.
    DirectTcpip,
    /// Remote port forwarding (RFC 4254 section 7.1): `text` is the `address:port` the server
    /// listens on, fixed by the policy (never port 0, never chosen by the caller). One
    /// connection the server accepts there comes back on the streaming call as a
    /// `forwarded-tcpip` channel; the caller's frames go to it.
    TcpipForward,
}

/// A prompt of SSH keyboard-interactive authentication and its answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// A regular expression the whole prompt must match (linear time, at most 256 bytes).
    pub prompt: String,
    /// The answer, a template.
    pub template: String,
}

/// How the node signs in on a protocol connection. `user`, `password`, `key`, `token` and the
/// answers are templates; the node renders them, and nothing of them goes back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// The user name.
    pub user: String,
    /// A password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// An SSH private key (PEM or DER: PKCS#8, PKCS#1, or an unencrypted OpenSSH key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// An OAuth 2.0 bearer token (SMTP and IMAP `XOAUTH2`; MQTT `token`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// SSH keyboard-interactive answers, by prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<Answer>,
    /// The database (PostgreSQL, MySQL), a literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    /// The MQTT client identifier, a literal; without it, a random one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The AMQP virtual host, a literal; without it, `/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vhost: Option<String>,
    /// The mechanism, when the policy pins one; otherwise the kind's default for the
    /// credential given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<Mechanism>,
}

impl Login {
    /// The mechanism in force for `connection`.
    pub fn mechanism_for(&self, connection: Connection) -> Option<Mechanism> {
        if let Some(m) = self.mechanism {
            return Some(m);
        }
        Some(match connection {
            Connection::Ssh if self.key.is_some() => Mechanism::Publickey,
            Connection::Ssh if !self.answers.is_empty() => Mechanism::KeyboardInteractive,
            Connection::Ssh => Mechanism::Password,
            Connection::Postgres => Mechanism::ScramSha256,
            Connection::Mysql => Mechanism::CachingSha2Password,
            Connection::Smtp | Connection::Imap if self.token.is_some() => Mechanism::Xoauth2,
            Connection::Smtp => Mechanism::Plain,
            Connection::Imap => Mechanism::Login,
            Connection::Redis => Mechanism::Auth,
            Connection::Mqtt if self.token.is_some() => Mechanism::Token,
            Connection::Mqtt => Mechanism::Password,
            Connection::Amqp => Mechanism::Plain,
            Connection::Amqp1 if self.token.is_some() => Mechanism::Xoauth2,
            Connection::Amqp1 if self.password.is_some() => Mechanism::Plain,
            Connection::Amqp1 => Mechanism::External,
            Connection::Ftp => Mechanism::User,
            Connection::Pop3 if self.token.is_some() => Mechanism::Xoauth2,
            Connection::Pop3 => Mechanism::User,
            Connection::Https
            | Connection::Tls
            | Connection::Websocket
            | Connection::Udp
            | Connection::Dtls
            | Connection::Browser => {
                return None;
            }
        })
    }

    /// The templates, with what each is.
    pub fn templates(&self) -> Vec<&str> {
        let mut out = vec![self.user.as_str()];
        out.extend(self.password.as_deref());
        out.extend(self.key.as_deref());
        out.extend(self.token.as_deref());
        out.extend(self.answers.iter().map(|a| a.template.as_str()));
        out
    }
}

/// How SMTP, IMAP, POP3 and FTP reach TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS from the first byte (ports 465, 993, 995 and 990).
    #[default]
    Implicit,
    /// A plain connection upgraded before anything else: `STARTTLS` (SMTP, IMAP; ports 587
    /// and 143), `STLS` (POP3, port 110) or `AUTH TLS` (FTP, port 21). A server that does
    /// not take it is refused.
    Starttls,
}

/// A command the policy fixes: a `send` on a protocol connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// The command: an SSH command line, an SQL statement (`$1`... for PostgreSQL, `?` for
    /// MySQL), an IMAP command without its tag, a Redis command name (literal words), or the
    /// verb of MQTT (`publish`, `subscribe`) and AMQP (`publish`, `get`).
    pub text: String,
    /// Parameters, templates: bound (PostgreSQL, MySQL), bulk strings (Redis), quoted (IMAP,
    /// SSH), the topic and payload (MQTT), the exchange, routing key and body or the queue
    /// (AMQP).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    /// MQTT: the QoS, 0 (default) or 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<u8>,
}

/// A parameter of a command the caller may run: a template of the policy, the caller's value
/// under a pattern, or both (the template reads the caller's value as `$input`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamRule {
    /// A template of the policy. Alone, the caller gives nothing for it; with a pattern, it
    /// reads the caller's value as `$input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// A regular expression the caller's whole value must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The longest value of the caller, in bytes (at most 64 KiB, the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<usize>,
}

impl ParamRule {
    /// True when the caller gives this parameter.
    pub fn from_caller(&self) -> bool {
        self.template.is_none() || self.pattern.is_some()
    }

    /// True when the caller gives this parameter with no pattern.
    pub fn unpinned(&self) -> bool {
        self.template.is_none() && self.pattern.is_none()
    }

    /// True when the value is the caller's as given (no template around it).
    pub fn raw_caller(&self) -> bool {
        self.template.is_none()
    }
}

/// A command the caller may run, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRule {
    /// The name the caller gives.
    pub name: String,
    /// The command, a template that cannot read what the caller sends.
    pub text: String,
    /// Its parameters, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<ParamRule>,
    /// PostgreSQL and MySQL: the columns that go back (all when empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    /// SSH: what the command runs on (`exec` by default, `sftp`, `direct-tcpip`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<SshChannel>,
    /// MQTT: the QoS of the publication or subscription, 0 (default) or 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<u8>,
    /// MQTT `subscribe` and AMQP `get`: most messages handed back (1 to 256, default 16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_messages: Option<usize>,
    /// MQTT `subscribe` and AMQP 1.0 `receive`: how long it waits for messages, in
    /// milliseconds (1 to 60,000, default 5,000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// AMQP 1.0 `send` and `receive`: how deliveries are settled (`first` by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle: Option<SettleMode>,
    /// SSH `tcpip-forward`: true to let the server listen on every address (`0.0.0.0`, `::`,
    /// `*`), which the summary flags; without it such a bind is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcard_bind: Option<bool>,
}

impl CommandRule {
    /// What it runs on, for SSH.
    pub fn ssh_channel(&self) -> SshChannel {
        self.channel.unwrap_or_default()
    }
}

/// What messages a caller may send over SMTP.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailRule {
    /// Patterns the whole envelope sender must match (1 to 16).
    pub senders: Vec<String>,
    /// Patterns each whole recipient must match (1 to 16).
    pub recipients: Vec<String>,
    /// Most recipients of one message (default and at most 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recipients: Option<usize>,
    /// Longest message, in bytes (default and at most 8 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}

impl Connection {
    /// True for the protocol connections of this module.
    pub fn is_protocol(self) -> bool {
        matches!(
            self,
            Connection::Ssh
                | Connection::Postgres
                | Connection::Smtp
                | Connection::Imap
                | Connection::Redis
                | Connection::Mysql
                | Connection::Mqtt
                | Connection::Amqp
                | Connection::Amqp1
                | Connection::Ftp
                | Connection::Pop3
        )
    }

    /// The scheme of the connection, as summaries and logs name it.
    pub fn scheme(self) -> &'static str {
        match self {
            Connection::Https => "https",
            Connection::Tls => "tls",
            Connection::Websocket | Connection::Browser => "wss",
            Connection::Ssh => "ssh",
            Connection::Postgres => "postgres",
            Connection::Smtp => "smtp",
            Connection::Imap => "imap",
            Connection::Redis => "redis",
            Connection::Mysql => "mysql",
            Connection::Mqtt => "mqtt",
            Connection::Amqp => "amqp",
            Connection::Amqp1 => "amqp1",
            Connection::Ftp => "ftp",
            Connection::Pop3 => "pop3",
            Connection::Udp => "udp",
            Connection::Dtls => "dtls",
        }
    }
}

fn mechanisms(connection: Connection) -> &'static [Mechanism] {
    match connection {
        Connection::Ssh => &[
            Mechanism::Password,
            Mechanism::Publickey,
            Mechanism::KeyboardInteractive,
        ],
        Connection::Postgres => &[Mechanism::ScramSha256],
        Connection::Mysql => &[Mechanism::CachingSha2Password],
        Connection::Smtp => &[Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2],
        Connection::Imap => &[Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2],
        Connection::Redis => &[Mechanism::Auth],
        Connection::Mqtt => &[Mechanism::Password, Mechanism::Token],
        Connection::Amqp => &[Mechanism::Plain],
        Connection::Amqp1 => &[
            Mechanism::Plain,
            Mechanism::External,
            Mechanism::ScramSha256,
            Mechanism::Xoauth2,
        ],
        Connection::Ftp => &[Mechanism::User],
        Connection::Pop3 => &[
            Mechanism::User,
            Mechanism::Apop,
            Mechanism::Plain,
            Mechanism::Login,
            Mechanism::Xoauth2,
        ],
        Connection::Https
        | Connection::Tls
        | Connection::Websocket
        | Connection::Udp
        | Connection::Dtls
        | Connection::Browser => &[],
    }
}

/// True for literal Redis command words.
fn redis_words(text: &str) -> bool {
    !text.trim().is_empty()
        && text.split_ascii_whitespace().count() <= 4
        && text.split_ascii_whitespace().all(|w| {
            w.len() <= 32
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        })
}

/// A literal of 1 to `max` visible ASCII bytes.
fn literal_ok(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| b.is_ascii_graphic())
}

/// The `host:port` of a `direct-tcpip` rule: a host name or an address, and a port.
pub fn forward_target(text: &str) -> Option<(&str, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    host_ok.then_some((host, port))
}

/// The `address:port` of a `tcpip-forward` rule: an address or host name the server listens
/// on (or `*`), a port other than 0, and whether the address is a wildcard (`*`, `0.0.0.0`,
/// `::`), which listens on every address of the server.
pub fn bind_target(text: &str) -> Option<(&str, u16, bool)> {
    let (host, port) = text.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let wildcard = matches!(host, "*" | "0.0.0.0" | "::" | "0:0:0:0:0:0:0:0");
    let host_ok = wildcard
        || (!host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')));
    host_ok.then_some((host, port, wildcard))
}

/// True when `text` is a template with no placeholder (its value is known now).
fn is_literal(text: &str) -> bool {
    !text.contains("{{")
}

/// The shape of a verb of FTP, POP3 or SFTP: how many parameters it takes, which of them are
/// paths, and whether they are message numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerbShape {
    /// Fewest parameters.
    pub min: usize,
    /// Most parameters.
    pub max: usize,
    /// The parameters that are paths.
    pub paths: &'static [usize],
    /// True when a path may be the root `/` (a listing, a status).
    pub root: bool,
    /// True when every parameter is a message number (POP3).
    pub numbers: bool,
}

const fn verb(min: usize, max: usize, paths: &'static [usize], root: bool) -> VerbShape {
    VerbShape {
        min,
        max,
        paths,
        root,
        numbers: false,
    }
}

const fn numbers(min: usize, max: usize) -> VerbShape {
    VerbShape {
        min,
        max,
        paths: &[],
        root: false,
        numbers: true,
    }
}

/// The shape of `text` as a verb of FTP, POP3 or SFTP (`channel` for SSH), or `None` when
/// the kind has no such verb or takes free commands.
pub fn verb_shape(connection: Connection, channel: SshChannel, text: &str) -> Option<VerbShape> {
    match (connection, channel, text) {
        (Connection::Ssh, SshChannel::Sftp, "read" | "delete" | "mkdir" | "rmdir")
        | (Connection::Ftp, _, "retrieve" | "delete" | "mkdir") => Some(verb(1, 1, &[0], false)),
        (Connection::Ssh, SshChannel::Sftp, "write") | (Connection::Ftp, _, "store") => {
            Some(verb(2, 2, &[0], false))
        }
        (Connection::Ssh, SshChannel::Sftp, "list" | "stat") | (Connection::Ftp, _, "list") => {
            Some(verb(1, 1, &[0], true))
        }
        (Connection::Ssh, SshChannel::Sftp, "rename") | (Connection::Ftp, _, "rename") => {
            Some(verb(2, 2, &[0, 1], false))
        }
        (Connection::Pop3, _, "STAT" | "NOOP" | "RSET") => Some(numbers(0, 0)),
        (Connection::Pop3, _, "LIST" | "UIDL") => Some(numbers(0, 1)),
        (Connection::Pop3, _, "RETR" | "DELE") => Some(numbers(1, 1)),
        (Connection::Pop3, _, "TOP") => Some(numbers(2, 2)),
        _ => None,
    }
}

/// True when `path` may go in a command of `connection` as a path: `/` where the verb allows
/// the root, else an absolute path with no empty, `.` or `..` segment, backslash or NUL (and
/// for FTP, whose commands are lines, no control byte, `0xFF` or invalid UTF-8).
pub fn path_ok(connection: Connection, path: &[u8], root: bool) -> bool {
    (root && path == b"/")
        || match connection {
            Connection::Ftp => crate::proto::ftp::check_path(path).is_ok(),
            _ => crate::proto::sftp::normalize(path).is_ok(),
        }
}

/// The words of the verbs of `connection` and `channel`, for messages.
fn verbs_of(connection: Connection) -> &'static str {
    match connection {
        Connection::Ftp => {
            "an FTP command is list, retrieve, store, delete, rename or mkdir, with its paths"
        }
        Connection::Pop3 => {
            "a POP3 command is STAT, LIST, UIDL, RETR, TOP, DELE, NOOP or RSET, with message numbers"
        }
        _ => {
            "an SFTP rule is read, write, list, stat, rename, delete, mkdir or rmdir, with its paths"
        }
    }
}

/// How many parameters a verb of MQTT or AMQP takes, or `None` for a verb the kind lacks.
fn verb_params(connection: Connection, verb: &str) -> Option<usize> {
    match (connection, verb) {
        (Connection::Mqtt, "publish") => Some(2),
        (Connection::Mqtt, "subscribe") => Some(1),
        (Connection::Amqp, "publish") => Some(3),
        (Connection::Amqp, "get") => Some(1),
        (Connection::Amqp1, "send") => Some(2),
        (Connection::Amqp1, "receive") => Some(1),
        _ => None,
    }
}

impl Policy {
    /// Checks the members of an `open` for a protocol connection.
    pub(super) fn check_proto_open(&self, at: &str, kinds: &Kinds<'_>, open: &Open) -> Checked {
        let connection = open.connection;
        ensure(
            open.protocol.is_none(),
            || format!("{at}.protocol"),
            "protocol is for an HTTPS connection",
        )?;
        ensure(
            open.identity.is_none() || !matches!(connection, Connection::Ssh),
            || format!("{at}.identity"),
            "an SSH connection signs in with login.key, not a TLS identity",
        )?;
        ensure(
            open.tls.is_none()
                || matches!(
                    connection,
                    Connection::Smtp
                        | Connection::Imap
                        | Connection::Pop3
                        | Connection::Ftp
                        | Connection::Amqp1
                ),
            || format!("{at}.tls"),
            "tls (implicit or starttls) is for SMTP, IMAP, POP3, FTP and AMQP 1.0; the others fix how they reach TLS",
        )?;
        ensure(
            open.version.is_none() || connection == Connection::Mqtt,
            || format!("{at}.version"),
            "version is for MQTT",
        )?;
        ensure(
            (connection == Connection::Ssh)
                == (!open.host_keys.is_empty() && open.host_keys.len() <= MAX_HOST_KEYS),
            || format!("{at}.host_keys"),
            "an SSH connection pins 1 to 16 host keys; other connections take none",
        )?;
        for (i, key) in open.host_keys.iter().enumerate() {
            ensure(
                crate::proto::ssh::HostKey::parse(key).is_some(),
                || format!("{at}.host_keys[{i}]"),
                "a host key is `type base64`: ssh-ed25519, ecdsa-sha2-nistp256/384/521 or ssh-rsa",
            )?;
        }
        let Some(login) = &open.login else {
            return fail(format!("{at}.login"), "a protocol connection needs login");
        };
        let at = format!("{at}.login");
        let mechanism = login.mechanism_for(connection);
        ensure(
            mechanism.is_some_and(|m| mechanisms(connection).contains(&m)),
            || format!("{at}.mechanism"),
            "a mechanism of this kind of connection",
        )?;
        let given = (
            login.password.is_some(),
            login.key.is_some(),
            login.token.is_some(),
            !login.answers.is_empty(),
        );
        let fits = match mechanism {
            Some(
                Mechanism::Password
                | Mechanism::ScramSha256
                | Mechanism::Plain
                | Mechanism::Login
                | Mechanism::Auth
                | Mechanism::CachingSha2Password
                | Mechanism::User
                | Mechanism::Apop,
            ) => given == (true, false, false, false),
            Some(Mechanism::Publickey) => given == (false, true, false, false),
            Some(Mechanism::External) => given == (false, false, false, false),
            Some(Mechanism::KeyboardInteractive) => given == (false, false, false, true),
            Some(Mechanism::Xoauth2 | Mechanism::Token) => given == (false, false, true, false),
            None => false,
        };
        ensure(
            fits,
            || at.clone(),
            "login gives exactly the credential its mechanism uses (password, key, token or answers)",
        )?;
        ensure(
            mechanism != Some(Mechanism::External) || open.identity.is_some(),
            || format!("{at}.mechanism"),
            "external signs in with the TLS client certificate: the open needs an identity",
        )?;
        ensure(
            !login.user.is_empty()
                || matches!(connection, Connection::Redis | Connection::Mqtt)
                || mechanism == Some(Mechanism::External),
            || format!("{at}.user"),
            "login names a user",
        )?;
        ensure(
            login.database.is_none()
                || (matches!(connection, Connection::Postgres | Connection::Mysql)
                    && login.database.as_deref().is_some_and(|d| literal_ok(d, 63))),
            || format!("{at}.database"),
            "database is for PostgreSQL and MySQL: 1 to 63 visible ASCII bytes",
        )?;
        ensure(
            login.client_id.is_none()
                || (connection == Connection::Mqtt
                    && login
                        .client_id
                        .as_deref()
                        .is_some_and(|d| literal_ok(d, 64))),
            || format!("{at}.client_id"),
            "client_id is for MQTT: 1 to 64 visible ASCII bytes",
        )?;
        ensure(
            login.vhost.is_none()
                || (matches!(connection, Connection::Amqp | Connection::Amqp1)
                    && login.vhost.as_deref().is_some_and(|d| literal_ok(d, 255))),
            || format!("{at}.vhost"),
            "vhost is for AMQP and AMQP 1.0 (its open's hostname): 1 to 255 visible ASCII bytes",
        )?;
        ensure(
            login.answers.len() <= MAX_ANSWERS
                && login
                    .answers
                    .iter()
                    .all(|a| crate::extract::compile_whole(&a.prompt).is_some()),
            || format!("{at}.answers"),
            "at most 8 answers, each prompt a regular expression of at most 256 bytes",
        )?;
        for (i, template) in login.templates().into_iter().enumerate() {
            self.check_template(&format!("{at}[{i}]"), kinds, template, &[], Var::in_stream)?;
        }
        Ok(())
    }

    /// Checks a `send` on a protocol connection: a command the policy fixes.
    pub(super) fn check_proto_send(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        connection: Connection,
        send: &Send,
        known: &[&str],
    ) -> Checked {
        ensure(
            send.request.is_none()
                && send.inject.is_empty()
                && !send.grpc
                && send.frame.is_none()
                && send.template.is_none(),
            || at.to_string(),
            "a send on a protocol connection takes command only",
        )?;
        ensure(
            connection != Connection::Smtp,
            || at.to_string(),
            "an SMTP connection sends the caller's messages only (return.relay.mail)",
        )?;
        let Some(command) = &send.command else {
            return fail(at, "a send on a protocol connection needs a command");
        };
        let at = format!("{at}.command");
        self.check_command_text(&at, kinds, connection, &command.text, known)?;
        ensure(
            command.params.len() <= MAX_PARAMS,
            || format!("{at}.params"),
            "at most 32 parameters",
        )?;
        if matches!(connection, Connection::Ftp | Connection::Pop3) {
            let Some(shape) = verb_shape(connection, SshChannel::Exec, &command.text) else {
                return fail(format!("{at}.text"), verbs_of(connection));
            };
            ensure(
                (shape.min..=shape.max).contains(&command.params.len()),
                || format!("{at}.params"),
                verbs_of(connection),
            )?;
            check_verb_literals(&at, connection, shape, command.params.iter().map(Some))?;
        }
        if let Some(n) = verb_params(connection, &command.text) {
            ensure(
                command.params.len() == n,
                || format!("{at}.params"),
                "MQTT publish takes the topic and payload, subscribe the filter; AMQP publish the exchange, routing key and body, get the queue; AMQP 1.0 send the address and body, receive the address",
            )?;
            self.check_literal_params(&at, connection, &command.text, &command.params)?;
        }
        ensure(
            command.qos.is_none() || (connection == Connection::Mqtt && command.qos <= Some(1)),
            || format!("{at}.qos"),
            "qos is for MQTT: 0 or 1",
        )?;
        for (i, p) in command.params.iter().enumerate() {
            self.check_template(
                &format!("{at}.params[{i}]"),
                kinds,
                p,
                known,
                Var::in_stream,
            )?;
        }
        Ok(())
    }

    /// Checks the parameters of MQTT and AMQP whose value is known now: topics, filters and
    /// names that cannot be sent are refused when the policy is signed.
    fn check_literal_params<'p>(
        &self,
        at: &str,
        connection: Connection,
        verb: &str,
        params: impl IntoIterator<Item = &'p String>,
    ) -> Checked {
        for (i, p) in params.into_iter().enumerate() {
            if !is_literal(p) {
                continue;
            }
            let ok = match (connection, verb, i) {
                (Connection::Mqtt, "publish", 0) => crate::proto::mqtt::topic_ok(p.as_bytes()),
                (Connection::Mqtt, "subscribe", 0) => crate::proto::mqtt::filter_ok(p.as_bytes()),
                (Connection::Amqp, "publish", 0 | 1) | (Connection::Amqp, "get", 0) => {
                    crate::proto::amqp::name_ok(p.as_bytes())
                }
                (Connection::Amqp1, "send" | "receive", 0) => {
                    crate::proto::amqp1::address_ok(p.as_bytes())
                }
                _ => true,
            };
            ensure(
                ok,
                || format!("{at}.params[{i}]"),
                "an MQTT topic or filter, an AMQP name or an AMQP 1.0 address that the protocol cannot carry",
            )?;
        }
        Ok(())
    }

    fn check_command_text(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        connection: Connection,
        text: &str,
        known: &[&str],
    ) -> Checked {
        let at = format!("{at}.text");
        ensure(
            !text.is_empty() && text.len() <= 64 * 1024,
            || at.clone(),
            "a command of 1 byte to 64 KiB",
        )?;
        match connection {
            // A Redis command is words; values go in parameters, one bulk string each.
            Connection::Redis => {
                return ensure(
                    redis_words(text),
                    || at.clone(),
                    "a Redis command is 1 to 4 literal words of letters, digits, _ - .",
                );
            }
            Connection::Mqtt | Connection::Amqp | Connection::Amqp1 => {
                return ensure(
                    verb_params(connection, text).is_some(),
                    || at.clone(),
                    "an MQTT command is publish or subscribe; an AMQP command publish or get; an AMQP 1.0 command send or receive",
                );
            }
            Connection::Ftp | Connection::Pop3 => {
                return ensure(
                    verb_shape(connection, SshChannel::Exec, text).is_some(),
                    || at.clone(),
                    verbs_of(connection),
                );
            }
            _ => {}
        }
        self.check_template(&at, kinds, text, known, Var::in_stream)?;
        // A line break in an IMAP command or a NUL in any would start another command; the
        // rendered command is checked again when it runs.
        let literal_ok = !text.bytes().any(|b| match connection {
            Connection::Imap => b == b'\r' || b == b'\n' || b == 0,
            _ => b == 0,
        });
        ensure(
            literal_ok,
            || at.clone(),
            "a command holds no NUL, and an IMAP command no line break",
        )
    }

    /// Checks one command rule's text and members for its kind and channel.
    fn check_rule_shape(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        connection: Connection,
        rule: &CommandRule,
        known: &[&str],
    ) -> Checked {
        ensure(
            rule.channel.is_none() || connection == Connection::Ssh,
            || format!("{at}.channel"),
            "channel is for SSH",
        )?;
        let verb = rule.text.as_str();
        let subscribe = connection == Connection::Mqtt && verb == "subscribe";
        let get = connection == Connection::Amqp && verb == "get";
        let receive = connection == Connection::Amqp1 && verb == "receive";
        ensure(
            rule.qos.is_none() || (connection == Connection::Mqtt && rule.qos <= Some(1)),
            || format!("{at}.qos"),
            "qos is for MQTT: 0 or 1 (QoS 2 is never used)",
        )?;
        ensure(
            rule.max_messages.is_none()
                || ((subscribe || get || receive)
                    && rule
                        .max_messages
                        .is_some_and(|n| (1..=MAX_MESSAGES).contains(&n))),
            || format!("{at}.max_messages"),
            "max_messages is for MQTT subscribe, AMQP get and AMQP 1.0 receive: 1 to 256",
        )?;
        ensure(
            rule.wait_ms.is_none()
                || ((subscribe || receive)
                    && rule
                        .wait_ms
                        .is_some_and(|n| (1..=MAX_MESSAGE_WAIT_MS).contains(&n))),
            || format!("{at}.wait_ms"),
            "wait_ms is for MQTT subscribe and AMQP 1.0 receive: 1 to 60000",
        )?;
        ensure(
            rule.settle.is_none() || connection == Connection::Amqp1,
            || format!("{at}.settle"),
            "settle is for AMQP 1.0 send and receive",
        )?;
        ensure(
            rule.wildcard_bind.is_none() || rule.channel == Some(SshChannel::TcpipForward),
            || format!("{at}.wildcard_bind"),
            "wildcard_bind is for an SSH tcpip-forward rule",
        )?;
        let params = rule.params.len();
        match (connection, rule.ssh_channel()) {
            (Connection::Ssh, SshChannel::Sftp) | (Connection::Ftp | Connection::Pop3, _) => {
                let Some(shape) = verb_shape(connection, rule.ssh_channel(), verb) else {
                    return fail(format!("{at}.text"), verbs_of(connection));
                };
                ensure(
                    (shape.min..=shape.max).contains(&params),
                    || format!("{at}.params"),
                    verbs_of(connection),
                )?;
                check_verb_literals(
                    at,
                    connection,
                    shape,
                    rule.params
                        .iter()
                        .map(|p| p.template.as_ref().filter(|_| p.pattern.is_none())),
                )
            }
            (Connection::Ssh, crate::policy::SshChannel::DirectTcpip) => ensure(
                forward_target(verb).is_some() && params == 0,
                || format!("{at}.text"),
                "a direct-tcpip rule is the host:port it forwards to, with no parameters",
            ),
            (Connection::Ssh, crate::policy::SshChannel::TcpipForward) => {
                let Some((_, _, wildcard)) = bind_target(verb).filter(|_| params == 0) else {
                    return fail(
                        format!("{at}.text"),
                        "a tcpip-forward rule is the address:port the server listens on (a literal, port 1 to 65535), with no parameters",
                    );
                };
                ensure(
                    !wildcard || rule.wildcard_bind == Some(true),
                    || format!("{at}.text"),
                    "a bind on every address (*, 0.0.0.0, ::) needs wildcard_bind: true",
                )
            }
            (Connection::Mqtt | Connection::Amqp | Connection::Amqp1, _) => {
                let Some(n) = verb_params(connection, verb) else {
                    return fail(
                        format!("{at}.text"),
                        "an MQTT command is publish or subscribe; an AMQP command publish or get; an AMQP 1.0 command send or receive",
                    );
                };
                ensure(
                    params == n,
                    || format!("{at}.params"),
                    "MQTT publish takes the topic and payload, subscribe the filter; AMQP publish the exchange, routing key and body, get the queue; AMQP 1.0 send the address and body, receive the address",
                )?;
                // AMQP: the exchange, routing key and queue are the policy's; AMQP 1.0: the
                // address.
                let fixed = match (connection, verb) {
                    (Connection::Amqp, "publish") => 2,
                    (Connection::Amqp | Connection::Amqp1, _) => 1,
                    _ => 0,
                };
                ensure(
                    rule.params.iter().take(fixed).all(|p| {
                        p.template.is_some() && p.pattern.is_none() && p.max_len.is_none()
                    }),
                    || format!("{at}.params"),
                    "an AMQP exchange, routing key and queue, and an AMQP 1.0 address, are templates of the policy",
                )?;
                self.check_literal_params(
                    at,
                    connection,
                    verb,
                    rule.params
                        .iter()
                        .filter_map(|p| p.template.as_ref().filter(|_| p.pattern.is_none())),
                )
            }
            _ => self.check_command_text(at, kinds, connection, &rule.text, known),
        }
    }

    /// Checks the `relay` of a protocol connection.
    pub(super) fn check_proto_relay(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        connection: Connection,
        relay: &Relay,
        known: &[&str],
    ) -> Checked {
        let at = format!("{at}.relay");
        ensure(
            relay.sends.is_empty(),
            || format!("{at}.sends"),
            "sends are for a TLS stream",
        )?;
        let live = !relay.frames.is_empty() || relay.server;
        let forwards = relay
            .commands
            .iter()
            .filter(|c| {
                matches!(
                    c.channel,
                    Some(SshChannel::DirectTcpip | SshChannel::TcpipForward)
                )
            })
            .count();
        ensure(
            !live
                || match connection {
                    Connection::Ssh => relay.mail.is_none() && forwards == relay.commands.len(),
                    Connection::Mqtt => relay.frames.is_empty() && relay.commands.is_empty(),
                    _ => false,
                },
            || format!("{at}.frames"),
            "frames and server are for a WebSocket, an SSH shell or forward (whose only commands are direct-tcpip and tcpip-forward rules), or the live messages of MQTT (server, with no frames or commands)",
        )?;
        ensure(
            forwards == 0 || live,
            || format!("{at}.commands"),
            "a direct-tcpip or tcpip-forward rule runs on a streaming relay (frames or server)",
        )?;
        ensure(
            relay.mail.is_some() == (connection == Connection::Smtp)
                && (relay.commands.is_empty() || connection != Connection::Smtp),
            || at.clone(),
            "an SMTP connection relays mail and nothing else; mail is for SMTP",
        )?;
        ensure(
            relay.commands.len() <= MAX_COMMANDS && relay.frames.len() <= super::MAX_RELAY_PATTERNS,
            || at.clone(),
            "at most 32 commands and 16 frame rules",
        )?;
        ensure(
            super::unique(relay.commands.iter().map(|c| c.name.as_str()))
                && relay.commands.iter().all(|c| is_token(&c.name)),
            || format!("{at}.commands"),
            "command names are unique tokens",
        )?;
        for (i, rule) in relay.commands.iter().enumerate() {
            let at = format!("{at}.commands[{i}]");
            self.check_rule_shape(&at, kinds, connection, rule, known)?;
            ensure(
                rule.params.len() <= MAX_PARAMS,
                || format!("{at}.params"),
                "at most 32 parameters",
            )?;
            ensure(
                rule.columns.is_empty()
                    || (matches!(connection, Connection::Postgres | Connection::Mysql)
                        && rule.columns.len() <= super::MAX_PROJECTION
                        && super::unique(rule.columns.iter().map(String::as_str))),
                || format!("{at}.columns"),
                "columns are for PostgreSQL and MySQL: at most 32, unique",
            )?;
            for (j, p) in rule.params.iter().enumerate() {
                let at = format!("{at}.params[{j}]");
                let caller_ok = |pattern: Option<&str>, max_len: Option<usize>| {
                    max_len.is_none_or(|n| n > 0 && n <= MAX_PARAM)
                        && pattern.is_none_or(|p| crate::extract::compile_whole(p).is_some())
                };
                match (&p.template, &p.pattern, p.max_len) {
                    (Some(t), None, None) => {
                        self.check_template(&at, kinds, t, known, Var::in_stream)?;
                    }
                    (Some(t), Some(pattern), max_len) => {
                        ensure(
                            caller_ok(Some(pattern), max_len),
                            || at.clone(),
                            "a caller parameter: max_len 1 to 65536, pattern a regular expression of at most 256 bytes",
                        )?;
                        // The caller's value, checked by the pattern, as `$input`.
                        let (template, _) =
                            self.check_template(&at, kinds, t, known, Var::in_frame)?;
                        ensure(
                            template.vars().contains(&Var::Input),
                            || at.clone(),
                            "a template with a pattern reads the caller's value as $input",
                        )?;
                    }
                    (None, pattern, max_len) => {
                        ensure(
                            caller_ok(pattern.as_deref(), max_len),
                            || at.clone(),
                            "a caller parameter: max_len 1 to 65536, pattern a regular expression of at most 256 bytes",
                        )?;
                    }
                    (Some(_), None, Some(_)) => {
                        return fail(
                            at,
                            "a parameter is a template, the caller's under pattern and max_len, or a template over the caller's value under a pattern",
                        );
                    }
                }
            }
        }
        for (i, rule) in relay.frames.iter().enumerate() {
            let at = format!("{at}.frames[{i}]");
            if let Some(rule) = rule.shape.as_ref().and_then(super::Input::fault) {
                return fail(format!("{at}.shape"), rule);
            }
            if let Some(text) = &rule.template {
                let at = format!("{at}.template");
                let (template, _) = self.check_template(&at, kinds, text, known, Var::in_frame)?;
                ensure(
                    !template.vars().contains(&Var::Input) || rule.shape.is_some(),
                    || at,
                    "a frame template that reads $input needs a shape",
                )?;
            }
        }
        if let Some(mail) = &relay.mail {
            let at = format!("{at}.mail");
            let patterns_ok = |list: &[String]| {
                !list.is_empty()
                    && list.len() <= super::MAX_RELAY_PATTERNS
                    && list
                        .iter()
                        .all(|p| crate::extract::compile_whole(p).is_some())
            };
            ensure(
                patterns_ok(&mail.senders) && patterns_ok(&mail.recipients),
                || at.clone(),
                "1 to 16 sender and recipient patterns, regular expressions of at most 256 bytes",
            )?;
            ensure(
                mail.max_recipients
                    .is_none_or(|n| n > 0 && n <= MAX_RECIPIENTS)
                    && mail.max_bytes.is_none_or(|n| n > 0 && n <= MAX_MAIL),
                || at.clone(),
                "max_recipients 1 to 100, max_bytes 1 to 8 MiB",
            )?;
        }
        Ok(())
    }
}

/// Checks the parameters of a verb whose value is known now (a template with no placeholder,
/// given as `Some`): paths and message numbers that cannot be sent are refused when the
/// policy is signed.
fn check_verb_literals<'p>(
    at: &str,
    connection: Connection,
    shape: VerbShape,
    params: impl IntoIterator<Item = Option<&'p String>>,
) -> Checked {
    for (i, p) in params.into_iter().enumerate() {
        let Some(p) = p.filter(|p| is_literal(p)) else {
            continue;
        };
        let ok = if shape.numbers {
            crate::proto::pop3::number_ok(p.as_bytes())
        } else if shape.paths.contains(&i) {
            path_ok(connection, p.as_bytes(), shape.root)
        } else {
            true
        };
        ensure(
            ok,
            || format!("{at}.params[{i}]"),
            "a path: absolute, no empty, . or .. segment, no \\, NUL or (FTP) control byte; or a POP3 message number of 1 to 10 digits",
        )?;
    }
    Ok(())
}

/// The summary lines of an `open` on a protocol connection.
pub(super) fn open_lines(open: &Open, out: &mut Vec<String>) {
    if let Some(login) = &open.login {
        let mechanism = login
            .mechanism_for(open.connection)
            .map(Mechanism::as_str)
            .unwrap_or("none");
        out.push(format!(
            "  signs in as {:?} with {mechanism}{}{}",
            login.user,
            login
                .database
                .as_ref()
                .map(|d| format!(", database {d:?}"))
                .unwrap_or_default(),
            login
                .vhost
                .as_ref()
                .map(|d| format!(", virtual host {d:?}"))
                .unwrap_or_default()
        ));
    }
    for key in &open.host_keys {
        let short: String = key
            .split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        out.push(format!("  host key pinned: {short}"));
    }
    if open.tls == Some(TlsMode::Starttls) {
        out.push(match open.connection {
            Connection::Ftp => "  TLS by AUTH TLS before anything else".into(),
            Connection::Amqp1 => "  TLS by the AMQP TLS header before anything else".into(),
            Connection::Pop3 => "  TLS by STLS before anything else".into(),
            _ => "  TLS by STARTTLS before anything else".into(),
        });
    }
    if open.connection == Connection::Ftp {
        out.push(
            "  data connections only to the same server, passive, each over TLS (PROT P)".into(),
        );
    }
}

/// The summary lines of a protocol relay.
pub(super) fn relay_lines(relay: &Relay, out: &mut Vec<String>) {
    for rule in &relay.commands {
        let params: Vec<String> = rule
            .params
            .iter()
            .map(|p| match (&p.template, &p.pattern) {
                (Some(t), None) => format!("policy {t:?}"),
                (Some(t), Some(pattern)) => format!("{t:?} over caller /{pattern}/"),
                (None, Some(pattern)) => format!("caller /{pattern}/"),
                (None, None) => "caller, any value".into(),
            })
            .collect();
        let what = match rule.channel {
            Some(SshChannel::Sftp) => format!("SFTP {}", rule.text),
            Some(SshChannel::DirectTcpip) => format!("a forward to {}", rule.text),
            Some(SshChannel::TcpipForward) => {
                format!("a remote forward from the server's {}", rule.text)
            }
            _ => match rule.settle {
                Some(mode) => format!("{:?} (settle {})", rule.text, mode.as_str()),
                None => format!("{:?}", rule.text),
            },
        };
        out.push(format!(
            "  return: the caller may run {} = {what}{}{}",
            rule.name,
            if params.is_empty() {
                String::new()
            } else {
                format!(" with [{}]", params.join(", "))
            },
            if rule.columns.is_empty() {
                String::new()
            } else {
                format!(", columns [{}] back", rule.columns.join(", "))
            }
        ));
        if rule.params.iter().any(ParamRule::unpinned) {
            out.push(format!(
                "  ! {}: a parameter of the caller takes any value",
                rule.name
            ));
        }
        if rule.channel == Some(SshChannel::DirectTcpip) {
            out.push(format!(
                "  ! {}: the caller's bytes reach {} through the SSH server",
                rule.name, rule.text
            ));
        }
        if rule.channel == Some(SshChannel::TcpipForward) {
            out.push(format!(
                "  ! {}: whoever reaches {} on the SSH server opens a connection to the caller through the node",
                rule.name, rule.text
            ));
            if bind_target(&rule.text).is_some_and(|(_, _, wildcard)| wildcard) {
                out.push(format!(
                    "  ! {}: {} listens on every address of the SSH server",
                    rule.name, rule.text
                ));
            }
        }
    }
    if let Some(mail) = &relay.mail {
        out.push(format!(
            "  return: the caller may send mail from {:?} to {:?}",
            mail.senders, mail.recipients
        ));
    }
}
