//! The protocol connections of layer 1: SSH, PostgreSQL, SMTP, IMAP and Redis.
//!
//! Each is a standard family with one meaning for the steps:
//!
//! - `open` signs in with [`Login`] (the node renders it; the caller never sees it), and for
//!   SSH proves the server holds a pinned host key;
//! - `send` runs one [`Command`] the policy fixes: its `text` and `params` are templates;
//! - `receive` captures from the result of the command just before it;
//! - `return` relays the caller's commands, each of which must name a [`CommandRule`] and give
//!   exactly its caller parameters, each matching the rule's pattern. A caller parameter never
//!   becomes part of a command's text: it is a bound parameter (PostgreSQL), a bulk string
//!   (Redis), a quoted string (IMAP) or a single-quoted shell word (SSH). SMTP relays
//!   messages within a [`MailRule`] instead, and an SSH shell relays signed frames.

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

/// An authentication mechanism, when the policy pins one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mechanism {
    /// SSH `password`.
    Password,
    /// SSH `publickey`.
    Publickey,
    /// SSH `keyboard-interactive`.
    KeyboardInteractive,
    /// SASL `SCRAM-SHA-256` (PostgreSQL).
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    /// SASL `PLAIN` (SMTP, IMAP `AUTHENTICATE`).
    Plain,
    /// SMTP `AUTH LOGIN`, IMAP `LOGIN`.
    Login,
    /// SASL `XOAUTH2` (SMTP, IMAP), with a bearer token.
    Xoauth2,
    /// Redis `AUTH`.
    Auth,
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
            Mechanism::Login => "login",
            Mechanism::Xoauth2 => "xoauth2",
            Mechanism::Auth => "auth",
        }
    }
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

/// How the node signs in on a protocol connection. Every member but `database` and
/// `mechanism` is a template; the node renders them, and nothing of them goes back.
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
    /// An OAuth 2.0 bearer token (SMTP and IMAP `XOAUTH2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// SSH keyboard-interactive answers, by prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<Answer>,
    /// The database (PostgreSQL), a literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
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
            Connection::Smtp | Connection::Imap if self.token.is_some() => Mechanism::Xoauth2,
            Connection::Smtp => Mechanism::Plain,
            Connection::Imap => Mechanism::Login,
            Connection::Redis => Mechanism::Auth,
            Connection::Https | Connection::Tls | Connection::Websocket | Connection::Udp => {
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

/// How SMTP and IMAP reach TLS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS from the first byte (ports 465 and 993).
    #[default]
    Implicit,
    /// A plain connection upgraded with `STARTTLS` before anything else (ports 587 and
    /// 143). A server that does not offer it is refused.
    Starttls,
}

/// A command the policy fixes: a `send` on a protocol connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// The command: an SSH command line, an SQL statement (`$1`... for the parameters), an
    /// IMAP command without its tag, or a Redis command name (literal words).
    pub text: String,
    /// Parameters, templates: bound (PostgreSQL), bulk strings (Redis), quoted (IMAP, SSH).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
}

/// A parameter of a command the caller may run: a template of the policy, or the caller's
/// value under a pattern.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamRule {
    /// A template of the policy; the caller gives nothing for it.
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
        self.template.is_none()
    }

    /// True when the caller gives this parameter with no pattern.
    pub fn unpinned(&self) -> bool {
        self.template.is_none() && self.pattern.is_none()
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
    /// PostgreSQL: the columns that go back (all when empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
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
        )
    }

    /// The scheme of the connection, as summaries and logs name it.
    pub fn scheme(self) -> &'static str {
        match self {
            Connection::Https => "https",
            Connection::Tls => "tls",
            Connection::Websocket => "wss",
            Connection::Ssh => "ssh",
            Connection::Postgres => "postgres",
            Connection::Smtp => "smtp",
            Connection::Imap => "imap",
            Connection::Redis => "redis",
            Connection::Udp => "udp",
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
        Connection::Smtp => &[Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2],
        Connection::Imap => &[Mechanism::Plain, Mechanism::Login, Mechanism::Xoauth2],
        Connection::Redis => &[Mechanism::Auth],
        Connection::Https | Connection::Tls | Connection::Websocket | Connection::Udp => &[],
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
            open.tls.is_none() || matches!(connection, Connection::Smtp | Connection::Imap),
            || format!("{at}.tls"),
            "tls (implicit or starttls) is for SMTP and IMAP",
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
                | Mechanism::Auth,
            ) => given == (true, false, false, false),
            Some(Mechanism::Publickey) => given == (false, true, false, false),
            Some(Mechanism::KeyboardInteractive) => given == (false, false, false, true),
            Some(Mechanism::Xoauth2) => given == (false, false, true, false),
            None => false,
        };
        ensure(
            fits,
            || at.clone(),
            "login gives exactly the credential its mechanism uses (password, key, token or answers)",
        )?;
        ensure(
            !login.user.is_empty() || connection == Connection::Redis,
            || format!("{at}.user"),
            "login names a user",
        )?;
        ensure(
            login.database.is_none()
                || (connection == Connection::Postgres
                    && login.database.as_deref().is_some_and(|d| {
                        !d.is_empty() && d.len() <= 63 && d.bytes().all(|b| b.is_ascii_graphic())
                    })),
            || format!("{at}.database"),
            "database is for PostgreSQL: 1 to 63 visible ASCII bytes",
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
        if connection == Connection::Redis {
            // A Redis command is words; values go in parameters, one bulk string each.
            return ensure(
                redis_words(text),
                || at.clone(),
                "a Redis command is 1 to 4 literal words of letters, digits, _ - .",
            );
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
        let shell = !relay.frames.is_empty() || relay.server;
        ensure(
            !shell
                || (connection == Connection::Ssh
                    && relay.commands.is_empty()
                    && relay.mail.is_none()),
            || format!("{at}.frames"),
            "frames and server are for a WebSocket or an SSH shell (with no commands)",
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
            self.check_command_text(&at, kinds, connection, &rule.text, known)?;
            ensure(
                rule.params.len() <= MAX_PARAMS,
                || format!("{at}.params"),
                "at most 32 parameters",
            )?;
            ensure(
                rule.columns.is_empty()
                    || (connection == Connection::Postgres
                        && rule.columns.len() <= super::MAX_PROJECTION
                        && super::unique(rule.columns.iter().map(String::as_str))),
                || format!("{at}.columns"),
                "columns are for PostgreSQL: at most 32, unique",
            )?;
            for (j, p) in rule.params.iter().enumerate() {
                let at = format!("{at}.params[{j}]");
                match (&p.template, &p.pattern, p.max_len) {
                    (Some(t), None, None) => {
                        self.check_template(&at, kinds, t, known, Var::in_stream)?;
                    }
                    (None, pattern, max_len) => {
                        ensure(
                            max_len.is_none_or(|n| n > 0 && n <= MAX_PARAM)
                                && pattern
                                    .as_deref()
                                    .is_none_or(|p| crate::extract::compile_whole(p).is_some()),
                            || at.clone(),
                            "a caller parameter: max_len 1 to 65536, pattern a regular expression of at most 256 bytes",
                        )?;
                    }
                    _ => {
                        return fail(
                            at,
                            "a parameter is a template, or the caller's under pattern and max_len",
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

/// The summary lines of an `open` on a protocol connection.
pub(super) fn open_lines(open: &Open, out: &mut Vec<String>) {
    if let Some(login) = &open.login {
        let mechanism = login
            .mechanism_for(open.connection)
            .map(Mechanism::as_str)
            .unwrap_or("none");
        out.push(format!(
            "  signs in as {:?} with {mechanism}{}",
            login.user,
            login
                .database
                .as_ref()
                .map(|d| format!(", database {d:?}"))
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
        out.push("  TLS by STARTTLS before anything else".into());
    }
}

/// The summary lines of a protocol relay.
pub(super) fn relay_lines(relay: &Relay, out: &mut Vec<String>) {
    for rule in &relay.commands {
        let params: Vec<String> = rule
            .params
            .iter()
            .map(|p| match (&p.template, &p.pattern) {
                (Some(t), _) => format!("policy {t:?}"),
                (None, Some(pattern)) => format!("caller /{pattern}/"),
                (None, None) => "caller, any value".into(),
            })
            .collect();
        out.push(format!(
            "  return: the caller may run {} = {:?}{}{}",
            rule.name,
            rule.text,
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
    }
    if let Some(mail) = &relay.mail {
        out.push(format!(
            "  return: the caller may send mail from {:?} to {:?}",
            mail.senders, mail.recipients
        ));
    }
}
