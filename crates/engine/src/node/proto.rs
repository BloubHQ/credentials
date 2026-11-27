//! Operations on protocol connections: SSH (with SFTP and port forwarding, local and
//! remote), PostgreSQL, MySQL, SMTP, IMAP, POP3, Redis, MQTT, AMQP 0-9-1, AMQP 1.0 and FTP
//! over TLS.
//!
//! Order, as for every act: the caller's commands and messages are checked against the
//! policy before anything is logged ([`check_session`]); the node logs the use, opens the
//! connection, signs in with the rendered [`Login`], runs the steps, then the caller's
//! commands one by one, each result redacted and searched for secrets before it goes back.
//! One more entry records how the connection ended ([`Event::Closed`]). An SSH shell or
//! forward runs on a streaming call instead: the caller's signed frames go in within the
//! relay's rules, and what the server sends goes back through the stream search. So do the
//! messages of an MQTT subscription the policy keeps open, each searched whole.
//!
//! A remote forward (`tcpip-forward`) asks the server to listen on the address and port the
//! policy fixes; the one connection the server then forwards comes back as a
//! `forwarded-tcpip` channel, which the client takes only for that address and port. It takes
//! a slot of its own, as an open connection does (refused when the caller, the owner or the
//! node is full), and it is the call's relay: the caller's frames go to it, its bytes come
//! back through the stream search, and it ends with the call (a hand-over included).

use std::time::Duration;

use zeroize::Zeroizing;

use super::live::{self, End, Live, Meter, frame_bytes, reason_of};
use super::{Clock, Closed, Node, Run, compute_vars, stream_vars};
use crate::caller::{CallerCommand, CallerMail, Payload};
use crate::egress::{ClientIdentity, Opening, Stream, Transport, open_protocol};
use crate::error::TransportKind;
use crate::log::{Detail, Event, LogSink};
use crate::policy::{
    CommandRule, Connection, Destination, FrameKind, Login, MAX_PARAM, Mechanism, MqttVersion,
    Open, Operation, Relay, SettleMode, SshChannel, Step, TlsMode,
};
use crate::policy::{path_ok, verb_shape};
use crate::proto::io::{Bounds, Io};
use crate::proto::{amqp, amqp1, ftp, imap, mqtt, mysql, pop3, postgres, redis, sftp, smtp, ssh};
use crate::record::Record;
use crate::reflection::{self, Secrets};
use crate::response::MAX_RESPONSE;
use crate::template::Var;
use crate::template::{Context, Template};
use crate::{Error, Result};

/// Most commands of the caller in one call.
pub const MAX_COMMANDS_PER_CALL: usize = 64;
/// Most messages of the caller in one call.
pub const MAX_MAIL_PER_CALL: usize = 16;
/// How long one wait on the server lasts in the shell relay before the caller is looked at.
const POLL: Duration = Duration::from_millis(10);

/// What a protocol operation handed back: one result per command (or message) that ran, and
/// the error that stopped the rest, if any.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionOutput {
    /// The results, in order.
    pub results: Vec<CommandResult>,
    /// The error that ended the commands early.
    pub error: Option<Error>,
}

/// The result of one command, after redaction and the reflection search.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CommandResult {
    /// The command rule, or `mail` for a message.
    pub name: String,
    /// The exit status (SSH), the IMAP completion (0 `OK`, 1 `NO`, 2 `BAD`), or the final
    /// SMTP reply code.
    pub status: Option<i64>,
    /// What came back: the output of an SSH command, the rows of a PostgreSQL query as JSON,
    /// a Redis reply as JSON, the response of an IMAP command, the last SMTP reply.
    pub data: Vec<u8>,
    /// The error output of an SSH command.
    pub stderr: Vec<u8>,
}

fn refused(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

/// The relay of the operation, if it has one.
fn relay_of(operation: &Operation) -> Option<&Relay> {
    operation.returns().and_then(|r| r.relay.as_ref())
}

/// True for a value the caller may give for a parameter of `connection`: within its rule's
/// length and pattern, and nothing that would end the command it goes in.
fn param_ok(connection: Connection, rule: &crate::policy::ParamRule, value: &str) -> bool {
    let bytes = value.as_bytes();
    let max = rule.max_len.unwrap_or(MAX_PARAM).min(MAX_PARAM);
    let framing_ok = match connection {
        // Quoted strings of IMAP and words of a shell cannot hold these.
        Connection::Imap => !bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)),
        Connection::Ssh => !bytes.contains(&0),
        // A message number as given; one in a template is checked once rendered.
        Connection::Pop3 => !rule.raw_caller() || pop3::number_ok(bytes),
        _ => true,
    };
    bytes.len() <= max
        && framing_ok
        && rule
            .pattern
            .as_deref()
            .is_none_or(|p| crate::extract::compile_whole(p).is_some_and(|re| re.is_match(bytes)))
}

/// True when the caller's `value` for parameter `at` of `rule` keeps the command in its shape:
/// an MQTT topic or filter of the caller holds no wildcard (only the policy's may), and a
/// path of the caller (SFTP, FTP) is absolute with no `.` or `..` segment, and for FTP holds
/// no control byte that could end the command line.
fn shape_ok(connection: Connection, rule: &CommandRule, at: usize, value: &str) -> bool {
    match connection {
        Connection::Mqtt if at == 0 => !value.contains(['+', '#']),
        Connection::Ssh | Connection::Ftp => {
            let channel = rule.ssh_channel();
            if connection == Connection::Ssh && channel != SshChannel::Sftp {
                return true;
            }
            let Some(shape) = verb_shape(connection, channel, &rule.text) else {
                return true;
            };
            if !shape.paths.contains(&at) {
                return true;
            }
            let raw = rule.params.get(at).is_some_and(|p| p.raw_caller());
            // The value goes in a template, or is the path; either way it may not climb, and
            // it may not end an FTP command line.
            !value.split('/').any(|s| s == "..")
                && (connection != Connection::Ftp || !value.bytes().any(|b| b < 0x20 || b == 0x7f))
                && (!raw || path_ok(connection, value.as_bytes(), shape.root))
        }
        _ => true,
    }
}

/// An e-mail address as a mailbox of SMTP can carry it: visible ASCII, no angle brackets,
/// spaces or quotes, one `@` with something on each side.
fn address_ok(address: &str) -> bool {
    let bytes = address.as_bytes();
    (3..=254).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'"' | b'\\' | b','))
        && address
            .rsplit_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
}

/// True when every CR and LF of `data` is part of a CRLF: a bare one would let a message end
/// early on a server that takes it as a line end (SMTP smuggling).
fn crlf_only(data: &[u8]) -> bool {
    let mut previous = 0u8;
    for (i, b) in data.iter().enumerate() {
        match b {
            b'\r' if data.get(i + 1) != Some(&b'\n') => return false,
            b'\n' if previous != b'\r' => return false,
            0 => return false,
            _ => {}
        }
        previous = *b;
    }
    true
}

/// Checks the caller's side of a protocol call before anything happens: the destination,
/// each command against its rule and each message against the mail rule.
pub(super) fn check_session(
    operation: &Operation,
    destination: &Destination,
    commands: &[CallerCommand],
    mail: &[CallerMail],
) -> Result<()> {
    if !operation.allows_destination(destination) {
        return Err(destination.denied());
    }
    let connection = operation.connection().ok_or_else(|| operation.unknown())?;
    if commands.len() > MAX_COMMANDS_PER_CALL || mail.len() > MAX_MAIL_PER_CALL {
        return Err(refused("at most 64 commands and 16 messages in one call"));
    }
    let relay = relay_of(operation);
    for command in commands {
        let rule = relay
            .and_then(|r| r.commands.iter().find(|c| c.name == command.name))
            .ok_or(refused("a command the policy does not name"))?;
        let mismatch = refused("the parameters of a command do not match its rule");
        let mut values = command.params.iter();
        for (at, p) in rule.params.iter().enumerate() {
            if !p.from_caller() {
                continue;
            }
            let value = values.next().ok_or(mismatch.clone())?;
            if !param_ok(connection, p, value) {
                return Err(refused("a parameter is outside its rule"));
            }
            if !shape_ok(connection, rule, at, value) {
                return Err(refused("a parameter outside the shape of its command"));
            }
        }
        if values.next().is_some() {
            return Err(mismatch);
        }
    }
    if !mail.is_empty() {
        let rule = relay
            .and_then(|r| r.mail.as_ref())
            .ok_or(refused("the operation sends no mail of the caller"))?;
        let compile = |list: &[String]| {
            list.iter()
                .map(|p| crate::extract::compile_whole(p).ok_or_else(|| operation.unknown()))
                .collect::<Result<Vec<_>>>()
        };
        let (senders, recipients) = (compile(&rule.senders)?, compile(&rule.recipients)?);
        let max_to = rule
            .max_recipients
            .unwrap_or(crate::policy::MAX_RECIPIENTS)
            .min(crate::policy::MAX_RECIPIENTS);
        let max_bytes = rule
            .max_bytes
            .unwrap_or(crate::policy::MAX_MAIL)
            .min(crate::policy::MAX_MAIL);
        for message in mail {
            if !address_ok(&message.from)
                || !senders.iter().any(|p| p.is_match(message.from.as_bytes()))
            {
                return Err(refused("a sender outside the mail rule"));
            }
            if message.to.is_empty() || message.to.len() > max_to {
                return Err(refused("too many or no recipients"));
            }
            if !message
                .to
                .iter()
                .all(|to| address_ok(to) && recipients.iter().any(|p| p.is_match(to.as_bytes())))
            {
                return Err(refused("a recipient outside the mail rule"));
            }
            if message.data.len() > max_bytes || !crlf_only(&message.data) {
                return Err(refused(
                    "a message too long, or with a CR or LF outside a CRLF",
                ));
            }
        }
    }
    if (!commands.is_empty() || !mail.is_empty()) && relay.is_none() {
        return Err(refused("the operation relays nothing of the caller"));
    }
    Ok(())
}

/// The login, rendered.
struct Credentials {
    user: Zeroizing<Vec<u8>>,
    secret: Zeroizing<Vec<u8>>,
    answers: Vec<(regex::bytes::Regex, Zeroizing<Vec<u8>>)>,
    mechanism: Mechanism,
}

/// Renders a template of the operation; a value that holds a secret in reversible form is
/// remembered for the reflection search.
fn render(run: &mut Run<'_>, text: &str, host: &str) -> Result<Zeroizing<Vec<u8>>> {
    render_with(run, text, host, None)
}

/// [`render`] with the caller's value of a parameter as `$input`.
fn render_with(
    run: &mut Run<'_>,
    text: &str,
    host: &str,
    input: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let template = Template::parse(text)?;
    let mut vars = stream_vars(host, run.now);
    if let Some(input) = input {
        vars.insert(Var::Input, input.to_vec());
    }
    let ctx = Context {
        fields: &run.fields,
        temps: &run.captured.temps,
        vars,
        headers: &[],
        unix: run.now / 1000,
        budget: &run.budget,
    };
    let bytes = template.render(&ctx)?;
    if template.tainted(&|n| run.kinds.kind(n)) {
        run.tainted.push(bytes.clone());
    }
    Ok(bytes)
}

fn credentials(run: &mut Run<'_>, open: &Open, host: &str) -> Result<Credentials> {
    let login: &Login = open.login.as_ref().ok_or_else(|| run.operation.unknown())?;
    let mechanism = login
        .mechanism_for(open.connection)
        .ok_or_else(|| run.operation.unknown())?;
    let user = render(run, &login.user, host)?;
    let secret_text = login
        .password
        .as_deref()
        .or(login.key.as_deref())
        .or(login.token.as_deref());
    let secret = match secret_text {
        Some(text) => render(run, text, host)?,
        None => Zeroizing::new(Vec::new()),
    };
    let mut answers = Vec::new();
    for answer in &login.answers {
        let pattern =
            crate::extract::compile_whole(&answer.prompt).ok_or_else(|| run.operation.unknown())?;
        answers.push((pattern, render(run, &answer.template, host)?));
    }
    Ok(Credentials {
        user,
        secret,
        answers,
        mechanism,
    })
}

/// A command rendered: its text and its parameters, the caller's among them.
struct Rendered {
    text: Zeroizing<Vec<u8>>,
    params: Vec<Zeroizing<Vec<u8>>>,
}

fn render_rule(
    run: &mut Run<'_>,
    rule: &CommandRule,
    given: &CallerCommand,
    host: &str,
) -> Result<Rendered> {
    let text = render(run, &rule.text, host)?;
    let mut caller = given.params.iter();
    let mut params = Vec::new();
    for p in &rule.params {
        let given = if p.from_caller() {
            Some(
                caller
                    .next()
                    .ok_or(refused("the parameters of a command do not match its rule"))?
                    .as_bytes(),
            )
        } else {
            None
        };
        params.push(match (&p.template, given) {
            (Some(t), input) => render_with(run, t, host, input)?,
            (None, Some(value)) => Zeroizing::new(value.to_vec()),
            (None, None) => return Err(run.operation.unknown()),
        });
    }
    Ok(Rendered { text, params })
}

/// How one command runs, beyond its text and parameters.
#[derive(Clone, Copy)]
struct Shape<'r> {
    /// PostgreSQL and MySQL: the columns that go back.
    columns: &'r [String],
    /// SSH: what the command runs on.
    channel: SshChannel,
    /// MQTT: the QoS.
    qos: u8,
    /// MQTT subscribe and AMQP get: most messages.
    max_messages: usize,
    /// MQTT subscribe: how long it waits.
    wait: Duration,
    /// MQTT subscribe: keeps the subscription for what follows instead of collecting.
    keep: bool,
    /// AMQP 1.0: how deliveries are settled.
    settle: SettleMode,
}

impl<'r> Shape<'r> {
    /// A command of the policy (`send`): an MQTT subscription stays.
    fn fixed(command: &crate::policy::Command) -> Self {
        Shape {
            columns: &[],
            channel: SshChannel::Exec,
            qos: command.qos.unwrap_or(0),
            max_messages: crate::policy::DEFAULT_MESSAGES.0,
            wait: Duration::from_millis(crate::policy::DEFAULT_MESSAGES.1),
            keep: true,
            settle: SettleMode::First,
        }
    }

    /// A command of the caller, by its rule.
    fn of(rule: &'r CommandRule) -> Self {
        let (messages, wait) = crate::policy::DEFAULT_MESSAGES;
        Shape {
            columns: &rule.columns,
            channel: rule.ssh_channel(),
            qos: rule.qos.unwrap_or(0),
            max_messages: rule
                .max_messages
                .unwrap_or(messages)
                .min(crate::policy::MAX_MESSAGES),
            wait: Duration::from_millis(
                rule.wait_ms
                    .unwrap_or(wait)
                    .min(crate::policy::MAX_MESSAGE_WAIT_MS),
            ),
            keep: false,
            settle: rule.settle.unwrap_or_default(),
        }
    }
}

/// The parameter at `i`, or an error for a rule that names fewer.
fn param(rendered: &Rendered, i: usize) -> Result<&[u8]> {
    rendered
        .params
        .get(i)
        .map(|p| p.as_slice())
        .ok_or(refused("the parameters of a command do not match its rule"))
}

/// JSON of a value, as bytes.
fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::Encoding)
}

/// A signed-in client of one kind.
enum Session<'s> {
    Ssh(Box<ssh::Client<'s>>),
    Postgres(postgres::Client<'s>),
    Smtp(smtp::Client<'s>),
    Imap(imap::Client<'s>),
    Redis(redis::Client<'s>),
    Mysql(mysql::Client<'s>),
    Mqtt(mqtt::Client<'s>),
    Amqp(amqp::Client<'s>),
    Amqp1(amqp1::Client<'s>),
    Ftp(ftp::Client<'s>),
    Pop3(pop3::Client<'s>),
}

/// The result of one command, and every byte the server sent for it in the form it came, for
/// the reflection search (a secret inside a JSON string is escaped there).
struct Ran {
    result: CommandResult,
    raw: Zeroizing<Vec<u8>>,
}

impl<'s> Session<'s> {
    fn io(&self) -> &Io<'s> {
        match self {
            Session::Ssh(c) => c.io(),
            Session::Postgres(c) => c.io(),
            Session::Smtp(c) => c.io(),
            Session::Imap(c) => c.io(),
            Session::Redis(c) => c.io(),
            Session::Mysql(c) => c.io(),
            Session::Mqtt(c) => c.io(),
            Session::Amqp(c) => c.io(),
            Session::Amqp1(c) => c.io(),
            Session::Ftp(c) => c.io(),
            Session::Pop3(c) => c.io(),
        }
    }

    fn io_counts(&self) -> (u64, u64) {
        (self.io().written, self.io().read)
    }

    fn reached(&self) -> Option<&'static str> {
        self.io().reached()
    }

    /// Runs one command.
    fn command(&mut self, rendered: &Rendered, shape: Shape<'_>) -> Result<Ran> {
        let status = |failed: bool| Some(i64::from(failed));
        let columns = shape.columns;
        let ran = |data: Vec<u8>, failed: bool, raw: Zeroizing<Vec<u8>>| Ran {
            result: CommandResult {
                name: String::new(),
                status: status(failed),
                data,
                stderr: Vec::new(),
            },
            raw,
        };
        match self {
            Session::Ssh(client) if shape.channel == SshChannel::Sftp => {
                let mut files = sftp::Sftp::start(client)?;
                let path = param(rendered, 0)?;
                let mut raw = Zeroizing::new(Vec::new());
                let data = match rendered.text.as_slice() {
                    b"read" => files.read_file(path, MAX_RESPONSE)?,
                    b"write" => {
                        files.write_file(path, param(rendered, 1)?)?;
                        Zeroizing::new(Vec::new())
                    }
                    b"list" => {
                        let entries = files.list(path)?;
                        for e in &entries {
                            raw.extend_from_slice(&e.name);
                            raw.push(0);
                        }
                        let json = serde_json::Value::Array(
                            entries.iter().map(sftp::Entry::json).collect(),
                        );
                        Zeroizing::new(json_bytes(&json)?)
                    }
                    b"stat" => {
                        let mut out = serde_json::Map::new();
                        files.stat(path)?.json(&mut out);
                        Zeroizing::new(json_bytes(&serde_json::Value::Object(out))?)
                    }
                    b"rename" => {
                        files.rename(path, param(rendered, 1)?)?;
                        Zeroizing::new(Vec::new())
                    }
                    b"delete" => {
                        files.delete(path)?;
                        Zeroizing::new(Vec::new())
                    }
                    b"mkdir" => {
                        files.mkdir(path)?;
                        Zeroizing::new(Vec::new())
                    }
                    b"rmdir" => {
                        files.rmdir(path)?;
                        Zeroizing::new(Vec::new())
                    }
                    _ => return Err(refused("an SFTP command the policy cannot name")),
                };
                files.finish()?;
                Ok(ran(data.to_vec(), false, raw))
            }
            Session::Ssh(_)
                if matches!(
                    shape.channel,
                    SshChannel::DirectTcpip | SshChannel::TcpipForward
                ) =>
            {
                Err(refused("a forward runs on a streaming call"))
            }
            Session::Amqp1(client) => {
                let address = param(rendered, 0)?;
                let (outcome, messages) = match rendered.text.as_slice() {
                    b"send" => (
                        client.send_message(address, param(rendered, 1)?, shape.settle)?,
                        Vec::new(),
                    ),
                    b"receive" => client.receive(
                        address,
                        shape.max_messages,
                        shape.wait,
                        shape.settle,
                        MAX_RESPONSE,
                    )?,
                    _ => return Err(refused("an AMQP 1.0 command is send or receive")),
                };
                // Every message as it came, sections and properties included.
                let mut raw = Zeroizing::new(Vec::new());
                for m in &messages {
                    raw.extend_from_slice(&m.raw);
                    raw.push(0);
                    raw.extend_from_slice(&m.body);
                    raw.push(0);
                }
                Ok(ran(json_bytes(&outcome.json)?, outcome.failed, raw))
            }
            Session::Mysql(client) => {
                let rows = client.query(&rendered.text, &rendered.params, columns, MAX_RESPONSE)?;
                Ok(ran(rows.json.to_vec(), rows.failed, rows.raw))
            }
            Session::Mqtt(client) => {
                let target = param(rendered, 0)?;
                match rendered.text.as_slice() {
                    b"publish" => {
                        if !mqtt::topic_ok(target) {
                            return Err(refused("an MQTT topic with no wildcard"));
                        }
                        let code = client.publish(target, param(rendered, 1)?, shape.qos)?;
                        let json = json_bytes(&serde_json::json!({ "reason": code }))?;
                        Ok(ran(json, code >= 0x80, Zeroizing::new(Vec::new())))
                    }
                    b"subscribe" => {
                        let filter = core::str::from_utf8(target)
                            .map_err(|_| refused("an MQTT topic filter in UTF-8"))?;
                        let granted = client.subscribe(filter, shape.qos)?;
                        if shape.keep {
                            let json = json_bytes(&serde_json::json!({ "granted": granted }))?;
                            return Ok(ran(json, false, Zeroizing::new(Vec::new())));
                        }
                        let messages =
                            client.collect(shape.wait, shape.max_messages, MAX_RESPONSE)?;
                        client.unsubscribe(filter)?;
                        let mut raw = Zeroizing::new(Vec::new());
                        for m in &messages {
                            raw.extend_from_slice(m.topic.as_bytes());
                            raw.push(0);
                            raw.extend_from_slice(&m.payload);
                            raw.push(0);
                        }
                        let json = serde_json::Value::Array(
                            messages.iter().map(mqtt::Message::json).collect(),
                        );
                        Ok(ran(json_bytes(&json)?, false, raw))
                    }
                    _ => Err(refused("an MQTT command is publish or subscribe")),
                }
            }
            Session::Amqp(client) => {
                let (outcome, messages) = match rendered.text.as_slice() {
                    b"publish" => (
                        client.publish(
                            param(rendered, 0)?,
                            param(rendered, 1)?,
                            param(rendered, 2)?,
                        )?,
                        Vec::new(),
                    ),
                    b"get" => client.get(param(rendered, 0)?, shape.max_messages, MAX_RESPONSE)?,
                    _ => return Err(refused("an AMQP command is publish or get")),
                };
                let mut raw = Zeroizing::new(Vec::new());
                for m in &messages {
                    raw.extend_from_slice(&m.body);
                    raw.push(0);
                }
                Ok(ran(json_bytes(&outcome.json)?, outcome.failed, raw))
            }
            Session::Ssh(client) => {
                let mut line = Zeroizing::new(rendered.text.to_vec());
                for p in &rendered.params {
                    line.push(b' ');
                    line.extend_from_slice(&ssh::shell_quote(p)?);
                }
                let output = client.exec(&line, MAX_RESPONSE)?;
                Ok(Ran {
                    result: CommandResult {
                        name: String::new(),
                        status: output.exit.map(i64::from),
                        data: output.stdout.to_vec(),
                        stderr: output.stderr.to_vec(),
                    },
                    raw: Zeroizing::new(Vec::new()),
                })
            }
            Session::Postgres(client) => {
                let rows = client.query(&rendered.text, &rendered.params, columns, MAX_RESPONSE)?;
                Ok(Ran {
                    result: CommandResult {
                        name: String::new(),
                        status: status(rows.failed),
                        data: rows.json.to_vec(),
                        stderr: Vec::new(),
                    },
                    raw: rows.raw,
                })
            }
            Session::Redis(client) => {
                let reply = client.command(&rendered.text, &rendered.params, MAX_RESPONSE)?;
                let mut raw = Zeroizing::new(Vec::new());
                reply.raw(&mut raw);
                let json = serde_json::to_vec(&reply.json()).map_err(|_| Error::Encoding)?;
                Ok(Ran {
                    result: CommandResult {
                        name: String::new(),
                        status: status(matches!(reply, redis::Reply::Error(_))),
                        data: json,
                        stderr: Vec::new(),
                    },
                    raw,
                })
            }
            Session::Imap(client) => {
                let response = client.command(&rendered.text, &rendered.params, MAX_RESPONSE)?;
                Ok(Ran {
                    result: CommandResult {
                        name: String::new(),
                        status: Some(response.status),
                        data: response.bytes.to_vec(),
                        stderr: Vec::new(),
                    },
                    raw: Zeroizing::new(Vec::new()),
                })
            }
            Session::Ftp(client) => {
                let path = param(rendered, 0)?;
                let verb = rendered.text.as_slice();
                let outcome = match verb {
                    b"list" => client.list(path, MAX_RESPONSE)?,
                    b"retrieve" => client.retrieve(path, MAX_RESPONSE)?,
                    b"store" => client.store(path, param(rendered, 1)?)?,
                    b"delete" => client.delete(path)?,
                    b"rename" => client.rename(path, param(rendered, 1)?)?,
                    b"mkdir" => client.mkdir(path)?,
                    _ => return Err(refused("an FTP command the policy cannot name")),
                };
                match (verb, outcome.ok) {
                    (b"retrieve", true) => {
                        let data = outcome
                            .data
                            .as_ref()
                            .map(|d| d.to_vec())
                            .unwrap_or_default();
                        Ok(ran(data, false, Zeroizing::new(Vec::new())))
                    }
                    (b"list", true) => {
                        let json = serde_json::Value::Array(
                            outcome.entries.iter().map(ftp::Entry::json).collect(),
                        );
                        let raw = outcome.data.unwrap_or_default();
                        Ok(ran(json_bytes(&json)?, false, raw))
                    }
                    (_, ok) => {
                        let json = serde_json::json!({
                            "code": outcome.code,
                            "text": String::from_utf8_lossy(&outcome.text),
                        });
                        Ok(ran(json_bytes(&json)?, !ok, Zeroizing::new(Vec::new())))
                    }
                }
            }
            Session::Pop3(client) => {
                let response = client.command(&rendered.text, &rendered.params, MAX_RESPONSE)?;
                Ok(Ran {
                    result: CommandResult {
                        name: String::new(),
                        status: Some(response.status),
                        data: response.bytes.to_vec(),
                        stderr: Vec::new(),
                    },
                    raw: Zeroizing::new(Vec::new()),
                })
            }
            Session::Smtp(_) => Err(refused("SMTP runs no commands, only messages")),
        }
    }

    /// Sends one message (SMTP).
    fn mail(&mut self, message: &CallerMail) -> Result<Ran> {
        match self {
            Session::Smtp(client) => {
                let reply = client.send(&message.from, &message.to, &message.data)?;
                Ok(Ran {
                    result: CommandResult {
                        name: "mail".into(),
                        status: Some(i64::from(reply.code)),
                        data: reply.text(),
                        stderr: Vec::new(),
                    },
                    raw: Zeroizing::new(Vec::new()),
                })
            }
            _ => Err(refused("only SMTP sends messages")),
        }
    }

    fn close(&mut self) {
        match self {
            Session::Ssh(client) => client.disconnect(),
            Session::Postgres(client) => client.close(),
            Session::Smtp(client) => client.close(),
            Session::Imap(client) => client.close(),
            Session::Redis(client) => client.close(),
            Session::Mysql(client) => client.close(),
            Session::Mqtt(client) => client.close(),
            Session::Amqp(client) => client.close(),
            Session::Amqp1(client) => client.close(),
            Session::Ftp(client) => client.close(),
            Session::Pop3(client) => client.close(),
        }
    }
}

/// A client identifier for MQTT when the policy fixes none: random, so two connections of
/// the node never take over each other's session.
fn random_client_id() -> Result<Vec<u8>> {
    let mut raw = [0u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
        .map_err(|_| Error::Encoding)?;
    let mut id = b"credentials-".to_vec();
    for b in raw {
        id.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    Ok(id)
}

/// Signs in on `stream` as the operation's login says.
fn sign_in<'s>(
    stream: &'s mut dyn Stream,
    open: &Open,
    credentials: &Credentials,
    bounds: Bounds,
    greeting: Option<&Prelude>,
    host: &str,
) -> Result<Session<'s>> {
    let io = Io::new(stream, bounds);
    let login = open.login.as_ref();
    let (user, secret) = (credentials.user.as_slice(), credentials.secret.as_slice());
    let after_starttls = opening_of(open) == OpeningKind::Starttls;
    Ok(match open.connection {
        Connection::Ssh => {
            let pinned: Vec<ssh::HostKey> = open
                .host_keys
                .iter()
                .filter_map(|k| ssh::HostKey::parse(k))
                .collect();
            let mut client = ssh::Client::connect(io, &pinned)?;
            let key;
            let auth = match credentials.mechanism {
                Mechanism::Publickey => {
                    key = ssh::ClientKey::parse(secret)?;
                    ssh::Auth::Key(&key)
                }
                Mechanism::KeyboardInteractive => ssh::Auth::Answers(&credentials.answers),
                _ => ssh::Auth::Password(secret),
            };
            client.authenticate(user, &auth)?;
            Session::Ssh(Box::new(client))
        }
        Connection::Postgres => {
            let database = open.login.as_ref().and_then(|l| l.database.as_deref());
            Session::Postgres(postgres::Client::connect(io, user, database, secret)?)
        }
        Connection::Smtp => Session::Smtp(smtp::Client::connect(
            io,
            after_starttls,
            credentials.mechanism,
            user,
            secret,
        )?),
        Connection::Imap => Session::Imap(imap::Client::connect(
            io,
            after_starttls,
            credentials.mechanism,
            user,
            secret,
        )?),
        Connection::Redis => Session::Redis(redis::Client::connect(io, user, secret)?),
        Connection::Mysql => {
            // The prelude read the greeting and asked for TLS before anything else.
            let Some(Prelude::Mysql(greeting)) = greeting else {
                return Err(Error::ServerUntrusted {
                    rule: "a MySQL connection signs in after its greeting and TLS",
                });
            };
            let database = login.and_then(|l| l.database.as_deref());
            Session::Mysql(mysql::Client::connect(
                io, greeting, user, database, secret,
            )?)
        }
        Connection::Mqtt => {
            let version = match open.version.unwrap_or_default() {
                MqttVersion::V311 => mqtt::Version::V311,
                MqttVersion::V5 => mqtt::Version::V5,
            };
            let client_id = match login.and_then(|l| l.client_id.as_deref()) {
                Some(id) => id.as_bytes().to_vec(),
                None => random_client_id()?,
            };
            Session::Mqtt(mqtt::Client::connect(
                io, version, &client_id, user, secret,
            )?)
        }
        Connection::Amqp => {
            let vhost = login.and_then(|l| l.vhost.as_deref()).unwrap_or("/");
            Session::Amqp(amqp::Client::connect(io, vhost.as_bytes(), user, secret)?)
        }
        Connection::Amqp1 => {
            // The open's hostname: the virtual host when the policy names one.
            let hostname = login.and_then(|l| l.vhost.as_deref()).unwrap_or(host);
            Session::Amqp1(amqp1::Client::connect(
                io,
                credentials.mechanism,
                user,
                secret,
                hostname.as_bytes(),
            )?)
        }
        Connection::Ftp => Session::Ftp(ftp::Client::connect(io, after_starttls, user, secret)?),
        Connection::Pop3 => {
            let greeting = match greeting {
                Some(Prelude::Pop3(g)) => Some(g),
                _ => None,
            };
            Session::Pop3(pop3::Client::connect(
                io,
                greeting,
                credentials.mechanism,
                user,
                secret,
            )?)
        }
        Connection::Https
        | Connection::Tls
        | Connection::Websocket
        | Connection::Udp
        | Connection::Dtls
        | Connection::Browser => {
            return Err(Error::transport(TransportKind::Unsupported, false));
        }
    })
}

/// How the connection of `open` is made.
fn opening_of(open: &Open) -> OpeningKind {
    match (open.connection, open.tls) {
        (Connection::Ssh, _) => OpeningKind::Plain,
        (Connection::Postgres | Connection::Mysql, _) => OpeningKind::Starttls,
        (
            Connection::Smtp
            | Connection::Imap
            | Connection::Pop3
            | Connection::Ftp
            | Connection::Amqp1,
            Some(TlsMode::Starttls),
        ) => OpeningKind::Starttls,
        _ => OpeningKind::Tls,
    }
}

/// A connection open, before the sign-in.
struct Opened<'t> {
    /// The log entry of the use.
    seq: u64,
    stream: Box<dyn Stream + 't>,
    meter: Meter,
    /// What the MySQL or POP3 prelude read.
    greeting: Option<Prelude>,
}

/// What a plain prelude read that the sign-in needs: MySQL's greeting, or the POP3 greeting
/// with its `APOP` timestamp.
enum Prelude {
    Mysql(mysql::Greeting),
    Pop3(pop3::Greeting),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpeningKind {
    Tls,
    Plain,
    Starttls,
}

/// The plain prelude before TLS of a protocol that upgrades its connection. Nothing secret is
/// written in it. MySQL's greeting comes before TLS: it is kept for the sign-in.
fn prelude(open: &Open, stream: &mut dyn Stream, bounds: Bounds) -> Result<Option<Prelude>> {
    let mut io = Io::new(stream, bounds);
    match open.connection {
        Connection::Postgres => postgres::prelude(&mut io).map(|()| None),
        Connection::Smtp => smtp::prelude(&mut io).map(|()| None),
        Connection::Imap => imap::prelude(&mut io).map(|()| None),
        Connection::Ftp => ftp::prelude(&mut io).map(|()| None),
        Connection::Amqp1 => amqp1::prelude(&mut io).map(|()| None),
        Connection::Pop3 => pop3::prelude(&mut io).map(|g| Some(Prelude::Pop3(g))),
        Connection::Mysql => {
            let database = open.login.as_ref().is_some_and(|l| l.database.is_some());
            mysql::prelude(&mut io, database).map(|g| Some(Prelude::Mysql(g)))
        }
        _ => Err(Error::transport(TransportKind::Unsupported, false)),
    }
}

impl<S: LogSink, C: Clock> Node<S, C> {
    /// Logs the use and opens the connection.
    fn open_session<'t, T: Transport>(
        &self,
        run: &mut Run<'_>,
        payload: &Payload<'_>,
        destination: &Destination,
        exchanges: usize,
        transport: &'t mut T,
    ) -> Result<Opened<'t>> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        let (now, who) = (run.now, run.who);
        let client = super::render_identity(
            open.identity.as_ref(),
            &run.fields,
            &destination.host,
            now,
            &run.budget,
        )?;
        let detail = Detail::Stream {
            host: destination.host.clone(),
            port: destination.port,
            sends_sha256: payload.sha256(),
            exchanges: u32::try_from(exchanges).unwrap_or(u32::MAX),
        };
        let event = Event::Stream {
            operation: run.name.to_string(),
            generation: run.record.generation,
            detail: detail.seal(&run.user_key, &run.record.owner, &run.record.id)?,
        };
        let (seq, confirmed) = self.lock().commit(now, who, event)?;
        run.log_seqs.push(seq);
        let meter = Meter::new(open.limits.as_ref());
        let bounds = bounds_of(open);
        let mut greeting = None;
        let mut prelude_fn = |stream: &mut dyn Stream| {
            greeting = prelude(open, stream, bounds)?;
            Ok(())
        };
        let opening = match opening_of(open) {
            OpeningKind::Tls => Opening::Tls,
            OpeningKind::Plain => Opening::Plain,
            OpeningKind::Starttls => Opening::Starttls(&mut prelude_fn),
        };
        let identity: Option<&ClientIdentity> = client.as_ref();
        let opened = open_protocol(confirmed, transport, destination, identity, opening);
        drop(client);
        match opened {
            Ok((_, stream)) => Ok(Opened {
                seq,
                stream,
                meter,
                greeting,
            }),
            Err(error) => {
                let _ = self.closed(run, seq, None, &meter, Err(("error", error.clone())));
                Err(error)
            }
        }
    }

    /// Runs the steps after sign-in: fixed commands, captures and computed values.
    fn session_steps(
        &self,
        run: &mut Run<'_>,
        session: &mut Session<'_>,
        host: &str,
        updated: &mut Option<Record>,
    ) -> Result<()> {
        let operation = run.operation;
        let now = run.now;
        let mut last: Option<Zeroizing<Vec<u8>>> = None;
        for step in &operation.steps {
            match step {
                Step::Open(_) | Step::Return(_) => {}
                Step::Send(send) => {
                    let command = send.command.as_ref().ok_or_else(|| operation.unknown())?;
                    let text = render(run, &command.text, host)?;
                    let mut params = Vec::new();
                    for p in &command.params {
                        params.push(render(run, p, host)?);
                    }
                    let ran = session.command(&Rendered { text, params }, Shape::fixed(command))?;
                    last = Some(Zeroizing::new(ran.result.data));
                }
                Step::Receive(receive) => {
                    let read = last.as_ref().ok_or_else(|| operation.unknown())?;
                    for capture in &receive.capture {
                        let value = crate::response::capture_bytes(read, &capture.source)?;
                        run.captured
                            .store(run.policy, &mut run.fields, capture, value, now)?;
                    }
                }
                Step::Compute(compute) => run.compute(compute, compute_vars(now))?,
                Step::Run(_) | Step::Repeat(_) | Step::If(_) | Step::Await(_) => {
                    return Err(operation.unknown());
                }
            }
            if let Some(reason) = session.reached() {
                return Err(limit_error(reason));
            }
        }
        self.persist(run, updated)
    }

    /// A protocol operation on a plain call: sign in, the steps, then the caller's commands
    /// or messages.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_session<T: Transport>(
        &self,
        run: &mut Run<'_>,
        payload: &Payload<'_>,
        destination: &Destination,
        commands: &[CallerCommand],
        mail: &[CallerMail],
        transport: &mut T,
        updated: &mut Option<Record>,
    ) -> Result<SessionOutput> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        let host = destination.host.clone();
        let credentials = credentials(run, open, &host)?;
        let Opened {
            seq,
            mut stream,
            mut meter,
            greeting,
        } = self.open_session(
            run,
            payload,
            destination,
            commands.len() + mail.len(),
            transport,
        )?;
        let bounds = bounds_of(open);
        let signed = sign_in(
            &mut *stream,
            open,
            &credentials,
            bounds,
            greeting.as_ref(),
            &host,
        );
        let mut session = match signed {
            Ok(session) => session,
            Err(error) => {
                let _ = stream.close();
                self.closed(
                    run,
                    seq,
                    None,
                    &meter,
                    Err((reason_of(&error), error.clone())),
                )?;
                return Err(error);
            }
        };
        drop(credentials);
        if let Err(error) = self.session_steps(run, &mut session, &host, updated) {
            session.close();
            let counts = session.io_counts();
            meter.to_server = (0, counts.0);
            self.closed(
                run,
                seq,
                None,
                &meter,
                Err((reason_of(&error), error.clone())),
            )?;
            return Err(error);
        }
        let mut output = SessionOutput::default();
        let mut history = Zeroizing::new(Vec::new());
        let rules = relay_of(operation);
        let items = commands
            .iter()
            .map(Item::Command)
            .chain(mail.iter().map(Item::Mail));
        for item in items {
            match self.caller_item(run, &mut session, rules, item, &host, &mut history) {
                Ok(result) => {
                    meter.to_caller.0 += 1;
                    meter.to_caller.1 = meter
                        .to_caller
                        .1
                        .saturating_add((result.data.len() + result.stderr.len()) as u64);
                    output.results.push(result);
                }
                Err(error) => {
                    output.error = Some(error);
                    break;
                }
            }
        }
        session.close();
        let counts = session.io_counts();
        meter.to_server = ((commands.len() + mail.len()) as u64, counts.0);
        let end = End::of(reason_of_output(&output), output.error.is_none());
        self.closed(run, seq, None, &meter, Ok(end))?;
        Ok(output)
    }

    /// Runs one command or sends one message of the caller and releases its result.
    fn caller_item(
        &self,
        run: &mut Run<'_>,
        session: &mut Session<'_>,
        rules: Option<&Relay>,
        item: Item<'_>,
        host: &str,
        history: &mut Zeroizing<Vec<u8>>,
    ) -> Result<CommandResult> {
        if self.is_handed_over() {
            return Err(Error::HandedOver);
        }
        let Ran { mut result, raw } = match item {
            Item::Command(command) => {
                let rule = rules
                    .and_then(|r| r.commands.iter().find(|c| c.name == command.name))
                    .ok_or(refused("a command the policy does not name"))?;
                let rendered = render_rule(run, rule, command, host)?;
                let mut ran = session.command(&rendered, Shape::of(rule))?;
                ran.result.name = command.name.clone();
                ran
            }
            Item::Mail(message) => session.mail(message)?,
        };
        let secrets = Secrets {
            policy: run.policy,
            fields: &run.fields,
            captured: &run.captured.secrets,
            rendered: &run.tainted,
        };
        // The values as the server sent them, before they were put in JSON.
        reflection::check(&raw, &secrets)?;
        drop(raw);
        result.data = reflection::release(core::mem::take(&mut result.data), &secrets)?;
        result.stderr = reflection::release(core::mem::take(&mut result.stderr), &secrets)?;
        // Across results too: a secret split over two of them is still found.
        history.extend_from_slice(&result.data);
        history.extend_from_slice(&result.stderr);
        reflection::check(history, &secrets)?;
        if let Some(reason) = session.reached() {
            return Err(limit_error(reason));
        }
        Ok(result)
    }

    /// A protocol connection on a streaming call: sign in, the steps, then an SSH shell or
    /// forward (the caller's frames in, the server's bytes back through the stream search) or
    /// the messages of MQTT subscriptions (each searched whole before it goes back).
    pub(super) fn run_shell<T: Transport>(
        &self,
        run: &mut Run<'_>,
        payload: &Payload<'_>,
        destination: &Destination,
        transport: &mut T,
        mut live: Live<'_>,
        updated: &mut Option<Record>,
    ) -> Result<Closed> {
        let operation = run.operation;
        let open = operation.open().ok_or_else(|| operation.unknown())?;
        if !matches!(open.connection, Connection::Ssh | Connection::Mqtt) {
            return Err(operation.unknown());
        }
        let commands = match payload {
            Payload::Session { commands, .. } => *commands,
            _ => &[],
        };
        // A forward relay names the one forward rule this call opens; a shell or a live
        // subscription takes no command of the caller.
        let rules = relay_of(operation).ok_or_else(|| operation.unknown())?;
        let forward = match commands {
            [] if rules.commands.is_empty() => None,
            [one] if one.params.is_empty() => Some(
                rules
                    .commands
                    .iter()
                    .find(|c| {
                        c.name == one.name
                            && matches!(
                                c.ssh_channel(),
                                SshChannel::DirectTcpip | SshChannel::TcpipForward
                            )
                    })
                    .ok_or(refused("a forward the policy does not name"))?,
            ),
            [_] => return Err(refused("a forward takes no parameter of the caller")),
            _ => return Err(refused("a streaming call names one forward, or nothing")),
        };
        let host = destination.host.clone();
        let credentials = credentials(run, open, &host)?;
        let Opened {
            seq,
            mut stream,
            mut meter,
            greeting,
        } = self.open_session(run, payload, destination, commands.len(), transport)?;
        let bounds = bounds_of(open);
        let signed = sign_in(
            &mut *stream,
            open,
            &credentials,
            bounds,
            greeting.as_ref(),
            &host,
        );
        let end = match signed {
            Ok(mut session) => {
                drop(credentials);
                let end = self.session_steps(run, &mut session, &host, updated);
                let end = end.and_then(|()| match &mut session {
                    Session::Mqtt(client) => self.messages(run, client, &mut live, &mut meter),
                    _ => self.shell(run, &mut session, forward, &host, &mut live, &mut meter),
                });
                session.close();
                end
            }
            Err(error) => {
                drop(credentials);
                Err(error)
            }
        };
        let _ = stream.close();
        let end = end.map_err(|error| (reason_of(&error), error));
        self.closed(run, seq, None, &meter, end)
    }

    /// The messages of the subscriptions the steps made, each searched for secrets whole
    /// (its topic and payload as they came, then its JSON) before it goes back as text.
    fn messages(
        &self,
        run: &mut Run<'_>,
        client: &mut mqtt::Client<'_>,
        live: &mut Live<'_>,
        meter: &mut Meter,
    ) -> Result<End> {
        let head = crate::response::project_head(200, Vec::new(), None, run.log_seqs.clone());
        live.relay.deliver(live::Part::Head(head))?;
        loop {
            let polled = match client.poll_message(POLL) {
                Ok(polled) => polled,
                // A bound of the connection ends the relay, as for the other relays.
                Err(error) => match client.io().reached() {
                    Some(reason) => return Ok(End::of(reason, false)),
                    None => return Err(error),
                },
            };
            if let Some(message) = polled {
                let secrets = Secrets {
                    policy: run.policy,
                    fields: &run.fields,
                    captured: &run.captured.secrets,
                    rendered: &run.tainted,
                };
                let mut raw = Zeroizing::new(message.topic.as_bytes().to_vec());
                raw.push(0);
                raw.extend_from_slice(&message.payload);
                reflection::check(&raw, &secrets)?;
                let json = json_bytes(&message.json())?;
                let released = Zeroizing::new(reflection::release(json, &secrets)?);
                meter.to_caller.0 += 1;
                meter.to_caller.1 = meter.to_caller.1.saturating_add(released.len() as u64);
                live.relay.deliver(live::Part::Text(released))?;
            }
            if let Some(reason) = client.io().reached() {
                return Ok(End::of(reason, false));
            }
            if self.is_handed_over() {
                return Ok(End::of("handed_over", false));
            }
            match live.relay.next(Duration::ZERO)? {
                None => {}
                Some(live::FromCaller::Close) => return Ok(End::of("caller", true)),
                Some(live::FromCaller::Frame(_)) => {
                    return Err(Error::FrameRefused {
                        rule: "an MQTT relay takes no frames",
                    });
                }
            }
        }
    }

    fn shell(
        &self,
        run: &mut Run<'_>,
        session: &mut Session<'_>,
        forward: Option<&CommandRule>,
        host: &str,
        live: &mut Live<'_>,
        meter: &mut Meter,
    ) -> Result<End> {
        let operation = run.operation;
        let rules = relay_of(operation).ok_or_else(|| operation.unknown())?;
        let Session::Ssh(client) = session else {
            return Err(operation.unknown());
        };
        // Remote: no channel until the server forwards a connection to the bind.
        let mut connected = true;
        match forward {
            // The destination and the bind are the policy's, never the caller's.
            Some(rule) if rule.ssh_channel() == SshChannel::TcpipForward => {
                let (address, port, wildcard) =
                    crate::policy::bind_target(&rule.text).ok_or_else(|| operation.unknown())?;
                if wildcard && rule.wildcard_bind != Some(true) {
                    return Err(operation.unknown());
                }
                client.tcpip_forward(address.as_bytes(), port)?;
                connected = false;
            }
            Some(rule) => {
                let (to, port) =
                    crate::policy::forward_target(&rule.text).ok_or_else(|| operation.unknown())?;
                client.direct_tcpip(to.as_bytes(), port)?;
            }
            None => client.shell()?,
        }
        let head = crate::response::project_head(200, Vec::new(), None, run.log_seqs.clone());
        live.relay.deliver(live::Part::Head(head))?;
        let mut scrubber = Self::scrubber(run)?;
        let caller_key = run.policy.caller(&live.auth.caller)?.key;
        let mut expected = 0u64;
        let mut status: Option<u32> = None;
        // The slot of the forwarded connection, held while it is open.
        let mut _forwarded: Option<live::Slot<'_>> = None;
        loop {
            match client.poll_event(POLL)? {
                Some(ssh::Event::Forwarded { originator, port }) => {
                    if self.is_handed_over() {
                        client.refuse_forwarded()?;
                        return Ok(End::of("handed_over", false));
                    }
                    let (owner, _, caller) = run.who;
                    match self.live.take(owner, caller, run.policy) {
                        Ok(slot) => {
                            client.accept_forwarded()?;
                            _forwarded = Some(slot);
                            connected = true;
                            let json = serde_json::json!({"forwarded": {
                                "originator": String::from_utf8_lossy(&originator),
                                "port": port,
                            }});
                            let secrets = Secrets {
                                policy: run.policy,
                                fields: &run.fields,
                                captured: &run.captured.secrets,
                                rendered: &run.tainted,
                            };
                            let released =
                                Zeroizing::new(reflection::release(json_bytes(&json)?, &secrets)?);
                            meter.to_caller.0 += 1;
                            meter.to_caller.1 =
                                meter.to_caller.1.saturating_add(released.len() as u64);
                            live.relay.deliver(live::Part::Text(released))?;
                        }
                        // The caller, the owner or the node holds as many connections as it
                        // may: the server is told so, and the forward waits for another.
                        Err(Error::StreamsFull { .. }) => client.refuse_forwarded()?,
                        Err(error) => return Err(error),
                    }
                }
                Some(ssh::Event::Data(data) | ssh::Event::Stderr(data)) => {
                    if rules.server {
                        let released = scrubber.push(&data)?;
                        if !released.is_empty() {
                            meter.to_caller.0 += 1;
                            meter.to_caller.1 =
                                meter.to_caller.1.saturating_add(released.len() as u64);
                            live.relay.deliver(live::Part::Binary(released))?;
                        }
                    }
                }
                Some(ssh::Event::Exit(code)) => status = Some(code),
                Some(ssh::Event::Closed) => break,
                None => {}
            }
            if let Some(reason) = client.io().reached() {
                return Ok(End::of(reason, false));
            }
            if self.is_handed_over() {
                return Ok(End::of("handed_over", false));
            }
            match live.relay.next(Duration::ZERO)? {
                None => {}
                Some(live::FromCaller::Close) => return Ok(End::of("caller", true)),
                Some(live::FromCaller::Frame(frame)) => {
                    if frame.seq != expected {
                        return Err(Error::FrameRefused {
                            rule: "frame out of sequence",
                        });
                    }
                    live.auth.verify_frame(
                        &caller_key,
                        frame.seq,
                        frame.kind == FrameKind::Binary,
                        &frame.data,
                        &frame.signature,
                    )?;
                    expected += 1;
                    if self.is_handed_over() {
                        return Ok(End::of("handed_over", false));
                    }
                    if !connected {
                        return Err(Error::FrameRefused {
                            rule: "no forwarded connection is open yet",
                        });
                    }
                    let bytes = frame_bytes(run, rules, &frame, host, &mut scrubber)?;
                    client.write_data(&bytes)?;
                    meter.to_server.0 += 1;
                    meter.to_server.1 = meter.to_server.1.saturating_add(bytes.len() as u64);
                }
            }
        }
        let tail = scrubber.finish();
        if !tail.is_empty() {
            meter.to_caller.0 += 1;
            meter.to_caller.1 = meter.to_caller.1.saturating_add(tail.len() as u64);
            live.relay.deliver(live::Part::Binary(tail))?;
        }
        Ok(End::of("server", status.is_none_or(|s| s == 0)))
    }
}

/// One thing the caller asked for.
#[derive(Clone, Copy)]
enum Item<'a> {
    Command(&'a CallerCommand),
    Mail(&'a CallerMail),
}

fn reason_of_output(output: &SessionOutput) -> &'static str {
    match &output.error {
        // The connection's byte limit, as the live relays name it.
        Some(Error::Budget {
            what: "connection bytes",
        }) => "bytes",
        Some(error) => reason_of(error),
        None => "done",
    }
}

fn limit_error(reason: &str) -> Error {
    if reason == "bytes" {
        Error::Budget {
            what: "connection bytes",
        }
    } else {
        Error::transport(TransportKind::Timeout, true)
    }
}

fn bounds_of(open: &Open) -> Bounds {
    let (idle, duration, bytes) = open.limits.unwrap_or_default().effective();
    Bounds::new(idle, duration, bytes)
}
