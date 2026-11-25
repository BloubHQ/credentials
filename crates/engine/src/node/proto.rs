//! Operations on protocol connections: SSH, PostgreSQL, SMTP, IMAP and Redis.
//!
//! Order, as for every act: the caller's commands and messages are checked against the
//! policy before anything is logged ([`check_session`]); the node logs the use, opens the
//! connection, signs in with the rendered [`Login`], runs the steps, then the caller's
//! commands one by one, each result redacted and searched for secrets before it goes back.
//! One more entry records how the connection ended ([`Event::Closed`]). An SSH shell runs on
//! a streaming call instead: the caller's signed frames go in within the relay's rules, and
//! what the server prints goes back through the stream search.

use std::time::Duration;

use zeroize::Zeroizing;

use super::live::{self, End, Live, Meter, frame_bytes, reason_of};
use super::{Clock, Closed, Node, Run, compute_vars, stream_vars};
use crate::caller::{CallerCommand, CallerMail, Payload};
use crate::egress::{ClientIdentity, Opening, Stream, Transport, open_protocol};
use crate::error::TransportKind;
use crate::log::{Detail, Event, LogSink};
use crate::policy::{
    CommandRule, Connection, Destination, FrameKind, Login, MAX_PARAM, Mechanism, Open, Operation,
    Relay, Step, TlsMode,
};
use crate::proto::io::{Bounds, Io};
use crate::proto::{imap, postgres, redis, smtp, ssh};
use crate::record::Record;
use crate::reflection::{self, Secrets};
use crate::response::MAX_RESPONSE;
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
        _ => true,
    };
    bytes.len() <= max
        && framing_ok
        && rule
            .pattern
            .as_deref()
            .is_none_or(|p| crate::extract::compile_whole(p).is_some_and(|re| re.is_match(bytes)))
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
        let caller_params: Vec<_> = rule.params.iter().filter(|p| p.from_caller()).collect();
        if caller_params.len() != command.params.len() {
            return Err(refused("the parameters of a command do not match its rule"));
        }
        if !caller_params
            .iter()
            .zip(&command.params)
            .all(|(rule, value)| param_ok(connection, rule, value))
        {
            return Err(refused("a parameter is outside its rule"));
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
    let template = Template::parse(text)?;
    let ctx = Context {
        fields: &run.fields,
        temps: &run.captured.temps,
        vars: stream_vars(host, run.now),
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
        params.push(match &p.template {
            Some(t) => render(run, t, host)?,
            None => Zeroizing::new(
                caller
                    .next()
                    .ok_or(refused("the parameters of a command do not match its rule"))?
                    .as_bytes()
                    .to_vec(),
            ),
        });
    }
    Ok(Rendered { text, params })
}

/// A signed-in client of one kind.
enum Session<'s> {
    Ssh(Box<ssh::Client<'s>>),
    Postgres(postgres::Client<'s>),
    Smtp(smtp::Client<'s>),
    Imap(imap::Client<'s>),
    Redis(redis::Client<'s>),
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
        }
    }

    fn io_counts(&self) -> (u64, u64) {
        (self.io().written, self.io().read)
    }

    fn reached(&self) -> Option<&'static str> {
        self.io().reached()
    }

    /// Runs one command.
    fn command(&mut self, rendered: &Rendered, columns: &[String]) -> Result<Ran> {
        let status = |failed: bool| Some(i64::from(failed));
        match self {
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
        }
    }
}

/// Signs in on `stream` as the operation's login says.
fn sign_in<'s>(
    stream: &'s mut dyn Stream,
    open: &Open,
    credentials: &Credentials,
    bounds: Bounds,
) -> Result<Session<'s>> {
    let io = Io::new(stream, bounds);
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
        Connection::Https | Connection::Tls | Connection::Websocket => {
            return Err(Error::transport(TransportKind::Unsupported, false));
        }
    })
}

/// How the connection of `open` is made.
fn opening_of(open: &Open) -> OpeningKind {
    match (open.connection, open.tls) {
        (Connection::Ssh, _) => OpeningKind::Plain,
        (Connection::Postgres, _) => OpeningKind::Starttls,
        (Connection::Smtp | Connection::Imap, Some(TlsMode::Starttls)) => OpeningKind::Starttls,
        _ => OpeningKind::Tls,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpeningKind {
    Tls,
    Plain,
    Starttls,
}

/// The plain prelude before TLS of a protocol that upgrades its connection. Nothing secret is
/// written in it.
fn prelude(connection: Connection, stream: &mut dyn Stream, bounds: Bounds) -> Result<()> {
    let mut io = Io::new(stream, bounds);
    match connection {
        Connection::Postgres => postgres::prelude(&mut io),
        Connection::Smtp => smtp::prelude(&mut io),
        Connection::Imap => imap::prelude(&mut io),
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
    ) -> Result<(u64, Box<dyn Stream + 't>, Meter)> {
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
        let connection = open.connection;
        let mut prelude_fn = |stream: &mut dyn Stream| prelude(connection, stream, bounds);
        let opening = match opening_of(open) {
            OpeningKind::Tls => Opening::Tls,
            OpeningKind::Plain => Opening::Plain,
            OpeningKind::Starttls => Opening::Starttls(&mut prelude_fn),
        };
        let identity: Option<&ClientIdentity> = client.as_ref();
        let opened = open_protocol(confirmed, transport, destination, identity, opening);
        drop(client);
        match opened {
            Ok((_, stream)) => Ok((seq, stream, meter)),
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
                    let ran = session.command(&Rendered { text, params }, &[])?;
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
        let (seq, mut stream, mut meter) = self.open_session(
            run,
            payload,
            destination,
            commands.len() + mail.len(),
            transport,
        )?;
        let bounds = bounds_of(open);
        let mut session = match sign_in(&mut *stream, open, &credentials, bounds) {
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
                let mut ran = session.command(&rendered, &rule.columns)?;
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

    /// An SSH shell on a streaming call: sign in, the steps, then the caller's frames in and
    /// the server's output back through the stream search.
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
        if open.connection != Connection::Ssh {
            return Err(operation.unknown());
        }
        let host = destination.host.clone();
        let credentials = credentials(run, open, &host)?;
        let (seq, mut stream, mut meter) =
            self.open_session(run, payload, destination, 0, transport)?;
        let bounds = bounds_of(open);
        let end = match sign_in(&mut *stream, open, &credentials, bounds) {
            Ok(mut session) => {
                let end = self.shell(run, &mut session, &host, &mut live, &mut meter, updated);
                session.close();
                end
            }
            Err(error) => Err(error),
        };
        drop(credentials);
        let _ = stream.close();
        let end = end.map_err(|error| (reason_of(&error), error));
        self.closed(run, seq, None, &meter, end)
    }

    fn shell(
        &self,
        run: &mut Run<'_>,
        session: &mut Session<'_>,
        host: &str,
        live: &mut Live<'_>,
        meter: &mut Meter,
        updated: &mut Option<Record>,
    ) -> Result<End> {
        self.session_steps(run, session, host, updated)?;
        let operation = run.operation;
        let rules = relay_of(operation).ok_or_else(|| operation.unknown())?;
        let Session::Ssh(client) = session else {
            return Err(operation.unknown());
        };
        client.shell()?;
        let head = crate::response::project_head(200, Vec::new(), None, run.log_seqs.clone());
        live.relay.deliver(live::Part::Head(head))?;
        let mut scrubber = Self::scrubber(run)?;
        let caller_key = run.policy.caller(&live.auth.caller)?.key;
        let mut expected = 0u64;
        let mut status: Option<u32> = None;
        loop {
            match client.poll_event(POLL)? {
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
    output.error.as_ref().map(reason_of).unwrap_or("done")
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
