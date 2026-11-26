//! What an owner reads before signing a policy: for each secret, where it can go and in what
//! form; for each operation, what the caller may send and what comes back; and the risk flags,
//! including what a new version widens against the one it replaces.
//!
//! [`summarize`] is pure: the owner's device runs it on a draft (an agent's, for instance), and
//! a node can run it on any policy it holds. It never reads a value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    BodyProjection, Caller, CallerRequest, Connection, Destination, Input, Limit, Operation,
    Policy, QueryRule, Return, RunModule, Send, Step, StepRequest, Store, Target,
};
use crate::item::{Disclosure, Origin};
use crate::template::Template;

/// A place a value can reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Place {
    /// `https` or `tls`.
    pub scheme: String,
    /// The host, or a `*.` pattern.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// The form in which a secret leaves the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "in", rename_all = "snake_case", deny_unknown_fields)]
pub enum Form {
    /// A request header.
    Header {
        /// Its name.
        name: String,
    },
    /// A query parameter.
    Query {
        /// Its name.
        name: String,
    },
    /// A path segment.
    PathParam {
        /// Its placeholder.
        name: String,
    },
    /// The request body.
    Body,
    /// The client certificate or key of the TLS handshake.
    Identity,
    /// Bytes written on a TLS stream.
    StreamSend,
    /// The sign-in of a protocol connection (SSH, PostgreSQL, SMTP, IMAP, Redis).
    Login {
        /// The mechanism. `password` (SSH), `plain`, `login` and `auth` hand the server the
        /// secret itself; `scram-sha-256`, `publickey` and `xoauth2` (a token) do not hand it
        /// a password.
        mechanism: String,
    },
    /// A command or query the node writes on a protocol connection.
    Command {
        /// The command rule, or `step` for a fixed command.
        name: String,
    },
    /// An input of code run in the sandbox (a `run` step); the code's output goes only to
    /// the module's origin.
    ModuleInput {
        /// The module: its URL, or `library <name>`.
        module: String,
    },
    /// A field of a page in a browser, typed by the node over CDP: the page (or the frame)
    /// gets it, and so does the browser behind the endpoint.
    BrowserField {
        /// The selector of the field.
        selector: String,
        /// The origin of the frame it is in, when not the top frame.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frame: Option<String>,
    },
    /// The output of a derivation, handed to the caller.
    Output {
        /// False when the output is an encryption (or another reversible function) of the
        /// secret or under it, rather than a hash, MAC, signature or one-time code.
        one_way: bool,
    },
}

/// One way a secret is used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretUse {
    /// The operation.
    pub operation: String,
    /// The step, from 0.
    pub step: usize,
    /// In what form.
    pub form: Form,
    /// Where it can go (empty for a derivation: it goes to the caller, as a one-way value).
    pub destinations: Vec<Place>,
}

/// A secret field and every place it can go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSummary {
    /// The field.
    pub field: String,
    /// True for a guessable field.
    pub guessable: bool,
    /// Its disclosure in the kind, for a typed item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<Disclosure>,
    /// Where and how it is used; empty when no template reads it.
    pub uses: Vec<SecretUse>,
}

/// A request a `send` makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSummary {
    /// The step, from 0.
    pub step: usize,
    /// `caller` (the caller's request within the contract) or `fixed`.
    pub from: String,
    /// The methods.
    pub methods: Vec<String>,
    /// The path templates (or the fixed path).
    pub paths: Vec<String>,
    /// The headers the caller may set.
    pub headers: Vec<String>,
    /// The query allow-list of the caller.
    pub query: Vec<QueryRule>,
    /// Where the policy puts values: `header X`, `query y`, `path {z}`, `body`.
    pub injects: Vec<String>,
    /// The destination of a fixed request, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Place>,
}

/// A `run` step: code that computes on secret values in the sandbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    /// The step, from 0.
    pub step: usize,
    /// The module: its URL, or `library <name>`.
    pub module: String,
    /// Where the module and its output go: the module's origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Place>,
    /// The SHA-256 pin of a fetched module; `None` when it is not pinned or is a library.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// True for a module fetched without a pin: the site can change the code.
    pub unpinned: bool,
    /// The exported function called.
    pub entry: String,
    /// The templates of the inputs.
    pub inputs: Vec<String>,
    /// The name of the output.
    pub into: String,
}

/// What goes back to the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnSummary {
    /// True when the status goes back (HTTPS).
    pub status: bool,
    /// The response headers that go back.
    pub headers: Vec<String>,
    /// `none`, `json` or `all`.
    pub body: String,
    /// The JSON pointers that go back, for `json`.
    pub json: Vec<String>,
    /// The patterns of the caller's sends a stream relays.
    pub relay: Vec<String>,
    /// The template of a derivation's output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

/// One operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSummary {
    /// The name.
    pub name: String,
    /// `https`, `tls` or `none`.
    pub connection: String,
    /// Where it may connect.
    pub destinations: Vec<Place>,
    /// True when it presents a client certificate.
    pub client_certificate: bool,
    /// Its requests.
    pub requests: Vec<RequestSummary>,
    /// What responses fill: `field x`, `secret temp y`, `public temp z`.
    pub captures: Vec<String>,
    /// The code it runs in the sandbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<RunSummary>,
    /// What goes back.
    pub returns: ReturnSummary,
    /// The input schema of a derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
    /// What it waits for: `sms code into otp`, `external, polls every 2000 ms`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub challenges: Vec<String>,
    /// What it pays, and where the amount is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<super::Payment>,
    /// What it vends, and for how long.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vend: Option<super::Vend>,
    /// True when every use waits for the owner's approval.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub approval: bool,
}

/// A caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerSummary {
    /// Its name.
    pub name: String,
    /// Its public key, base64url.
    pub key: String,
    /// The operations it may call.
    pub operations: Vec<String>,
    /// Its rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

/// The kind of item and the owner's choices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSummary {
    /// The kind.
    pub kind: String,
    /// True for a custom kind.
    pub custom: bool,
    /// The item's origin, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The pinned values.
    pub pins: BTreeMap<String, String>,
    /// The owner's sign-offs.
    pub signoff: Vec<String>,
}

/// What a risk flag is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagCode {
    /// A destination not under the item's origin.
    OutsideOrigin,
    /// A destination is a `*.` pattern.
    Wildcard,
    /// The item's origin is plain HTTP, or the owner signs off plain HTTP.
    PlainHttp,
    /// The owner signs off another plain-text connection.
    PlainSignoff,
    /// A derivation takes any bytes as input (`{"raw": {}}`).
    RawInput,
    /// A derivation's output is not one-way (an encryption, a key agreement, an XOR).
    DeriveReversible,
    /// A stream relays the caller's sends after the policy's login.
    Relay,
    /// A relay pattern matches broadly (`.*`, `.+`, a negated class).
    RelayBroad,
    /// The whole response body goes back.
    ResponseAll,
    /// A query parameter of the caller takes any value.
    QueryAny,
    /// The caller's path may hold `%25`.
    EncodedPercent,
    /// The caller may send method-override parameters.
    OverrideParams,
    /// A client certificate goes to a destination.
    ClientCertificate,
    /// Code fetched from a site runs on secret values without a SHA-256 pin: the site can
    /// change it at any time.
    RunUnpinned,
    /// Wider than the previous version of the policy.
    Wider,
    /// A destination the previous version did not have.
    NewDestination,
    /// A WebSocket relays the caller's frames of a kind with no pinned shape.
    FramesUnpinned,
    /// A WebSocket hands the server's messages back to the caller.
    ServerFrames,
    /// A protocol connection signs in with a mechanism that hands the server the password
    /// itself (SSH `password`, `PLAIN`, `LOGIN`, Redis `AUTH`).
    PasswordToServer,
    /// A command parameter of the caller takes any value up to its length (no pattern).
    ParamUnpinned,
    /// The caller sends messages over SMTP as the item's account.
    MailRelay,
    /// The caller types into an SSH shell.
    ShellRelay,
    /// An operation sends UDP datagrams, without TLS: what they carry is readable on the
    /// path (and by the host of an enclave).
    PlainDatagram,
    /// The node types secrets into a page in a browser over CDP: the page and the browser
    /// get them, and the node cannot see the page's TLS through CDP, so the browser is
    /// trusted.
    BrowserFill,
    /// A fill puts values into a frame of another origin than the page's.
    FrameOrigin,
    /// An operation hands the caller a credential minted from the secret (bounded in time
    /// and scope by the policy).
    Vend,
}

/// A risk flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flag {
    /// What it is about.
    pub code: FlagCode,
    /// Where: an operation, a field, a caller, `item`.
    pub at: String,
    /// In words.
    pub detail: String,
}

/// The summary of a policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// The kind of item, for a typed item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<ItemSummary>,
    /// Each secret field and where it can go.
    pub secrets: Vec<SecretSummary>,
    /// Each operation.
    pub operations: Vec<OperationSummary>,
    /// Each caller.
    pub callers: Vec<CallerSummary>,
    /// The risk flags.
    pub flags: Vec<Flag>,
    /// Against the previous version: what changed without widening (removed operations,
    /// callers, destinations). What widens is a [`FlagCode::Wider`] flag.
    pub changes: Vec<String>,
    /// [`Policy::summary`]: one line per field, operation, step and caller.
    pub lines: Vec<String>,
}

fn place(connection: Connection, d: &Destination) -> Place {
    Place {
        scheme: connection.scheme().into(),
        host: d.host.clone(),
        port: d.port,
    }
}

fn connection_name(connection: Option<Connection>) -> &'static str {
    match connection {
        Some(Connection::Https) => "https",
        Some(Connection::Tls) => "tls",
        Some(Connection::Websocket) => "websocket",
        Some(Connection::Browser) => "browser",
        Some(c) => c.scheme(),
        None => "none",
    }
}

/// The flags of the relay of a protocol operation.
fn protocol_flags(flags: &mut Vec<Flag>, at: &str, relay: &super::Relay) {
    if !relay.frames.is_empty() || relay.server {
        flag(
            flags,
            FlagCode::ShellRelay,
            at,
            "the caller types into an SSH shell under the policy's login",
        );
        if relay.server {
            flag(
                flags,
                FlagCode::ServerFrames,
                at,
                "what the shell prints goes back to the caller (after the stream search)",
            );
        }
        for (i, rule) in relay.frames.iter().enumerate() {
            if rule.unpinned() {
                flag(
                    flags,
                    FlagCode::FramesUnpinned,
                    format!("{at}.frames[{i}]"),
                    "the caller's shell input of this kind has no pinned shape",
                );
            }
        }
    }
    for rule in &relay.commands {
        for (i, p) in rule.params.iter().enumerate() {
            if p.unpinned() {
                flag(
                    flags,
                    FlagCode::ParamUnpinned,
                    format!("{at}.commands.{}.params[{i}]", rule.name),
                    "the caller's value for this parameter has no pattern",
                );
            }
        }
    }
    if let Some(mail) = &relay.mail {
        flag(
            flags,
            FlagCode::MailRelay,
            at,
            format!(
                "the caller sends mail as the account, from {:?} to {:?}",
                mail.senders, mail.recipients
            ),
        );
    }
}

/// The names a template reads, or none when it does not parse.
fn names_of(text: &str) -> Vec<String> {
    Template::parse(text)
        .map(|t| t.names().into_iter().map(str::to_string).collect())
        .unwrap_or_default()
}

/// The function names a template calls: identifiers followed by `(` inside `{{ }}`, outside
/// string literals.
fn calls_of(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let body = rest.get(start + 2..).unwrap_or_default();
        let end = body.find("}}").unwrap_or(body.len());
        let expr = body.get(..end).unwrap_or_default();
        let mut ident = String::new();
        let mut in_string = false;
        let mut escaped = false;
        for c in expr.chars() {
            if in_string {
                match (escaped, c) {
                    (false, '\\') => escaped = true,
                    (false, '"') => in_string = false,
                    _ => escaped = false,
                }
                continue;
            }
            if c.is_ascii_alphanumeric() || c == '_' {
                ident.push(c);
                continue;
            }
            if c == '(' && !ident.is_empty() {
                out.push(core::mem::take(&mut ident));
            } else if !c.is_whitespace() {
                ident.clear();
            }
            if c == '"' {
                in_string = true;
            }
        }
        rest = body.get(end..).unwrap_or_default();
    }
    out
}

/// True for a function whose output can be turned back into its input by someone (a key
/// holder, or anyone).
fn reversible(name: &str) -> bool {
    name.contains("encrypt")
        || name == "xor"
        || name == "ecdh"
        || name == "tls_exporter"
        || (name.starts_with("hpke_") && name != "hpke_public")
}

/// The fields each name of the operation stands for: a field itself, or the fields a
/// `compute` template reads, through other computed names.
struct Reads {
    computed: Vec<(String, Vec<String>, bool)>,
}

impl Reads {
    fn new(operation: &Operation) -> Self {
        let mut reads = Reads {
            computed: Vec::new(),
        };
        for step in &operation.steps {
            match step {
                Step::Compute(c) => {
                    let fields = reads.fields_of(&c.template);
                    let rev = reads.reversible_in(&c.template);
                    reads.computed.push((c.into.clone(), fields, rev));
                }
                Step::Run(run) => {
                    // The code's output may hold its inputs in any form.
                    let fields = reads.fields_of(&run.inputs.concat());
                    reads.computed.push((run.into.clone(), fields, true));
                }
                _ => {}
            }
        }
        reads
    }

    fn fields_of(&self, template: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for name in names_of(template) {
            let expanded = match self.computed.iter().find(|(n, _, _)| *n == name) {
                Some((_, fields, _)) => fields.clone(),
                None => vec![name],
            };
            for f in expanded {
                if !out.contains(&f) {
                    out.push(f);
                }
            }
        }
        out
    }

    fn reversible_in(&self, template: &str) -> bool {
        calls_of(template).iter().any(|c| reversible(c))
            || names_of(template)
                .iter()
                .any(|name| self.computed.iter().any(|(n, _, rev)| n == name && *rev))
    }
}

fn injects(send: &Send) -> Vec<String> {
    send.inject
        .iter()
        .map(|i| match &i.target {
            Target::Header { name } => format!("header {name}"),
            Target::Query { name } => format!("query {name}"),
            Target::PathParam { name } => format!("path {{{name}}}"),
            Target::Body => "body".into(),
        })
        .collect()
}

fn request_summary(step: usize, send: &Send, connection: Connection) -> Option<RequestSummary> {
    let injects = injects(send);
    match send.request.as_ref()? {
        StepRequest::Caller(c) => Some(RequestSummary {
            step,
            from: "caller".into(),
            methods: c.methods.iter().map(|m| m.as_str().to_string()).collect(),
            paths: c.paths.clone(),
            headers: c.headers.clone(),
            query: c.query.clone(),
            injects,
            destination: None,
        }),
        StepRequest::Fixed {
            method,
            path,
            destination,
        } => Some(RequestSummary {
            step,
            from: "fixed".into(),
            methods: vec![method.as_str().to_string()],
            paths: vec![path.clone()],
            headers: Vec::new(),
            query: Vec::new(),
            injects,
            destination: destination.as_ref().map(|d| place(connection, d)),
        }),
    }
}

fn return_summary(ret: &Return, connection: Option<Connection>) -> ReturnSummary {
    let mut out = ReturnSummary {
        status: connection == Some(Connection::Https),
        body: "none".into(),
        ..ReturnSummary::default()
    };
    if let Some(p) = &ret.response {
        out.headers = p.headers.clone();
        match &p.body {
            None => {}
            Some(BodyProjection::All) => out.body = "all".into(),
            Some(BodyProjection::Stream) => out.body = "stream".into(),
            Some(BodyProjection::Json(pointers)) => {
                out.body = "json".into();
                out.json = pointers.clone();
            }
        }
    }
    if let Some(relay) = &ret.relay {
        out.relay = relay.sends.clone();
    }
    out.template = ret.template.clone();
    out
}

fn operation_summary(operation: &Operation) -> OperationSummary {
    let open = operation.open();
    let connection = operation.connection();
    let mut out = OperationSummary {
        name: operation.name.clone(),
        connection: connection_name(connection).into(),
        destinations: open
            .map(|o| {
                o.destinations
                    .iter()
                    .map(|d| place(o.connection, d))
                    .collect()
            })
            .unwrap_or_default(),
        client_certificate: open.is_some_and(|o| o.identity.is_some()),
        requests: Vec::new(),
        captures: Vec::new(),
        runs: Vec::new(),
        returns: ReturnSummary::default(),
        input: operation.input.clone(),
        challenges: Vec::new(),
        payment: operation.payment.clone(),
        vend: operation.vend.clone(),
        approval: operation.approval,
    };
    for (i, step) in operation.steps.iter().enumerate() {
        match step {
            Step::Send(send) => {
                if let Some(c) = connection {
                    out.requests.extend(request_summary(i, send, c));
                }
            }
            Step::Receive(receive) => {
                out.captures
                    .extend(receive.capture.iter().map(|c| match &c.into {
                        Store::Field { name } => format!("field {name}"),
                        Store::Temp { name, secret } => {
                            format!("{} temp {name}", if *secret { "secret" } else { "public" })
                        }
                    }));
            }
            Step::Return(ret) => out.returns = return_summary(ret, connection),
            Step::Run(run) => out.runs.push(run_summary(i, run, operation)),
            Step::Await(wait) => {
                let c = &wait.challenge;
                match (&c.into, &c.poll) {
                    (Some(into), _) => out
                        .challenges
                        .push(format!("{} code into {into}", c.kind.as_str())),
                    (None, Some(poll)) => {
                        out.challenges.push(format!(
                            "{}, polls every {} ms",
                            c.kind.as_str(),
                            poll.every_ms
                        ));
                        if let Some(c) = connection {
                            out.requests.extend(request_summary(i, &poll.send, c));
                        }
                    }
                    (None, None) => out.challenges.push(c.kind.as_str().into()),
                }
            }
            Step::Open(_) | Step::Compute(_) | Step::Repeat(_) | Step::If(_) => {}
        }
    }
    out
}

/// Every use of every field in one operation, as (field, use).
fn uses_in(operation: &Operation) -> Vec<(String, SecretUse)> {
    let reads = Reads::new(operation);
    let connection = operation.connection();
    let places: Vec<Place> = operation
        .open()
        .map(|o| {
            o.destinations
                .iter()
                .map(|d| place(o.connection, d))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut add = |step: usize, template: &str, form: Form, places: &[Place]| {
        for field in reads.fields_of(template) {
            out.push((
                field,
                SecretUse {
                    operation: operation.name.clone(),
                    step,
                    form: form.clone(),
                    destinations: places.to_vec(),
                },
            ));
        }
    };
    for (i, step) in operation.steps.iter().enumerate() {
        match step {
            Step::Open(open) => {
                if let Some(identity) = &open.identity {
                    add(i, &identity.cert, Form::Identity, &places);
                    add(i, &identity.key, Form::Identity, &places);
                }
                if let Some(login) = &open.login {
                    let mechanism = login
                        .mechanism_for(open.connection)
                        .map_or("none", |m| m.as_str());
                    for template in login.templates() {
                        let form = Form::Login {
                            mechanism: mechanism.to_string(),
                        };
                        add(i, template, form, &places);
                    }
                }
            }
            Step::Send(_) | Step::Await(_) => {
                let send = match step {
                    Step::Send(send) => send,
                    Step::Await(wait) => match &wait.challenge.poll {
                        Some(poll) => &poll.send,
                        None => continue,
                    },
                    _ => continue,
                };
                let to: Vec<Place> = match (&send.request, connection) {
                    (
                        Some(StepRequest::Fixed {
                            destination: Some(d),
                            ..
                        }),
                        Some(c),
                    ) => {
                        vec![place(c, d)]
                    }
                    _ => places.clone(),
                };
                for injection in &send.inject {
                    let form = match &injection.target {
                        Target::Header { name } => Form::Header { name: name.clone() },
                        Target::Query { name } => Form::Query { name: name.clone() },
                        Target::PathParam { name } => Form::PathParam { name: name.clone() },
                        Target::Body => Form::Body,
                    };
                    add(i, &injection.template, form, &to);
                }
                if let Some(template) = &send.template {
                    add(i, template, Form::StreamSend, &to);
                }
                if let Some(command) = &send.command {
                    let form = Form::Command {
                        name: "step".into(),
                    };
                    add(i, &command.text, form.clone(), &to);
                    for p in &command.params {
                        add(i, p, form.clone(), &to);
                    }
                }
                if let Some(fill) = &send.fill {
                    for field in &fill.fields {
                        let origin = field.frame.as_deref().unwrap_or(&fill.origin);
                        let mut to: Vec<Place> = crate::cdp::WebOrigin::parse(origin)
                            .map(|o| Place {
                                scheme: "https".into(),
                                host: o.host,
                                port: o.port,
                            })
                            .into_iter()
                            .collect();
                        to.extend(places.iter().cloned());
                        let form = Form::BrowserField {
                            selector: field.selector.clone(),
                            frame: field.frame.clone(),
                        };
                        add(i, &field.template, form, &to);
                    }
                }
            }
            Step::Return(ret) => {
                if let Some(template) = &ret.template {
                    let one_way = !reads.reversible_in(template);
                    add(i, template, Form::Output { one_way }, &[]);
                }
                for rule in ret.relay.iter().flat_map(|r| &r.commands) {
                    let form = Form::Command {
                        name: rule.name.clone(),
                    };
                    add(i, &rule.text, form.clone(), &places);
                    for t in rule.params.iter().filter_map(|p| p.template.as_deref()) {
                        add(i, t, form.clone(), &places);
                    }
                }
            }
            Step::Run(run) => {
                let to: Vec<Place> = operation
                    .open()
                    .and_then(|o| run.origin(o).map(|d| place(o.connection, &d)))
                    .into_iter()
                    .collect();
                let form = Form::ModuleInput {
                    module: run.module_name(),
                };
                for input in &run.inputs {
                    add(i, input, form.clone(), &to);
                }
            }
            Step::Receive(_) | Step::Compute(_) | Step::Repeat(_) | Step::If(_) => {}
        }
    }
    out
}

fn run_summary(step: usize, run: &RunModule, operation: &Operation) -> RunSummary {
    RunSummary {
        step,
        module: run.module_name(),
        origin: operation
            .open()
            .and_then(|o| run.origin(o).map(|d| place(o.connection, &d))),
        sha256: run.module.sha256.clone(),
        unpinned: run.unpinned(),
        entry: run.entry.clone(),
        inputs: run.inputs.clone(),
        into: run.into.clone(),
    }
}

fn flag(flags: &mut Vec<Flag>, code: FlagCode, at: impl Into<String>, detail: impl Into<String>) {
    let flag = Flag {
        code,
        at: at.into(),
        detail: detail.into(),
    };
    if !flags.contains(&flag) {
        flags.push(flag);
    }
}

/// True when the destination pattern stays under the origin: the same port, and the origin's
/// host or a name under it.
fn under(origin: &Origin, d: &Destination) -> bool {
    let host = d.host.strip_prefix("*.").unwrap_or(&d.host);
    let base = &origin.destination.host;
    d.port == origin.destination.port
        && (host == base
            || host
                .strip_suffix(base.as_str())
                .is_some_and(|h| h.ends_with('.')))
}

fn broad(pattern: &str) -> bool {
    pattern.contains(".*") || pattern.contains(".+") || pattern.contains("[^")
}

fn risk_flags(policy: &Policy, origin: Option<&Origin>, flags: &mut Vec<Flag>) {
    if let Some(binding) = &policy.item {
        if origin.is_some_and(|o| !o.https) || binding.signoff.iter().any(|s| s == "plain_http") {
            flag(
                flags,
                FlagCode::PlainHttp,
                "item",
                "the item's origin is plain HTTP",
            );
        }
        for s in binding.signoff.iter().filter(|s| *s != "plain_http") {
            flag(
                flags,
                FlagCode::PlainSignoff,
                "item",
                format!("the owner signs off `{s}`: a connection without TLS is allowed"),
            );
        }
    }
    for operation in &policy.operations {
        let at = format!("operation {}", operation.name);
        if let Some(vend) = &operation.vend {
            flag(
                flags,
                FlagCode::Vend,
                &at,
                format!(
                    "the caller gets a credential minted from the secret, valid at most {} s",
                    vend.lifetime_ms / 1000
                ),
            );
        }
        if let Some(open) = operation.open() {
            for d in &open.destinations {
                let name = format!("{}:{}", d.host, d.port);
                if d.is_wildcard() {
                    flag(
                        flags,
                        FlagCode::Wildcard,
                        &at,
                        format!("{name} matches any one label there"),
                    );
                }
                if let Some(origin) = origin
                    && !under(origin, d)
                {
                    flag(
                        flags,
                        FlagCode::OutsideOrigin,
                        &at,
                        format!("{name} is not under {}", origin.text()),
                    );
                }
            }
            if open.identity.is_some() {
                flag(
                    flags,
                    FlagCode::ClientCertificate,
                    &at,
                    "a client certificate is presented",
                );
            }
            if let Some(m) = open
                .login
                .as_ref()
                .and_then(|l| l.mechanism_for(open.connection))
                && matches!(
                    m,
                    super::Mechanism::Password
                        | super::Mechanism::Plain
                        | super::Mechanism::Login
                        | super::Mechanism::Auth
                )
            {
                flag(
                    flags,
                    FlagCode::PasswordToServer,
                    &at,
                    format!(
                        "the {} sign-in ({}) hands the server the password itself",
                        open.connection.scheme(),
                        m.as_str()
                    ),
                );
            }
        }
        if let Some(Input::Raw(raw)) = &operation.input
            && raw.max_len.is_none()
            && raw.pattern.is_none()
        {
            flag(
                flags,
                FlagCode::RawInput,
                &at,
                "the caller's input is any bytes",
            );
        }
        for (c, _) in operation.caller_sends() {
            caller_flags(c, &at, flags);
        }
        for step in &operation.steps {
            if let Step::Send(send) = step
                && let Some(fill) = &send.fill
            {
                let endpoints = operation
                    .open()
                    .map(|o| {
                        o.destinations
                            .iter()
                            .map(|d| format!("{}:{}", d.host, d.port))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                flag(
                    flags,
                    FlagCode::BrowserFill,
                    &at,
                    format!(
                        "values are typed into the page at {} in the browser behind {endpoints}: the browser sees them and the node cannot check the page's TLS through CDP",
                        fill.origin
                    ),
                );
                for frame in fill.other_frames() {
                    flag(
                        flags,
                        FlagCode::FrameOrigin,
                        &at,
                        format!(
                            "values go into a frame of {frame}, inside the page at {}",
                            fill.origin
                        ),
                    );
                }
                if let Some(origin) = origin {
                    for page in core::iter::once(&fill.origin)
                        .chain(fill.fields.iter().filter_map(|f| f.frame.as_ref()))
                    {
                        let inside = crate::cdp::WebOrigin::parse(page).is_some_and(|o| {
                            under(
                                origin,
                                &Destination {
                                    host: o.host,
                                    port: o.port,
                                },
                            )
                        });
                        if !inside {
                            flag(
                                flags,
                                FlagCode::OutsideOrigin,
                                &at,
                                format!("{page} is not under {}", origin.text()),
                            );
                        }
                    }
                }
            }
        }
        if operation.connection() == Some(Connection::Udp) {
            flag(
                flags,
                FlagCode::PlainDatagram,
                &at,
                "the operation sends UDP datagrams without TLS: what they carry is readable on the path",
            );
        }
        for step in &operation.steps {
            if let Step::Run(run) = step
                && run.unpinned()
            {
                flag(
                    flags,
                    FlagCode::RunUnpinned,
                    &at,
                    format!(
                        "the module {} runs on secret values without a sha256 pin: the site can change it",
                        run.module_name()
                    ),
                );
            }
        }
        if let Some(ret) = operation.returns() {
            if let Some(p) = &ret.response {
                if p.body == Some(BodyProjection::All) {
                    flag(
                        flags,
                        FlagCode::ResponseAll,
                        &at,
                        "the whole response body goes back to the caller",
                    );
                }
                if p.body == Some(BodyProjection::Stream) {
                    flag(
                        flags,
                        FlagCode::ResponseAll,
                        &at,
                        "the whole response body goes back to the caller, as it arrives",
                    );
                }
            }
            if let Some(relay) = &ret.relay
                && operation.connection().is_some_and(Connection::is_protocol)
            {
                protocol_flags(flags, &at, relay);
            } else if let Some(relay) = &ret.relay {
                if relay.frames.is_empty() {
                    flag(
                        flags,
                        FlagCode::Relay,
                        &at,
                        format!(
                            "the caller's sends matching {:?} run under the policy's login",
                            relay.sends
                        ),
                    );
                } else {
                    flag(
                        flags,
                        FlagCode::Relay,
                        &at,
                        format!(
                            "the caller's {} kind(s) of WebSocket frames go to the server under the policy's login",
                            relay.frames.len()
                        ),
                    );
                }
                for (i, rule) in relay.frames.iter().enumerate() {
                    if rule.unpinned() {
                        flag(
                            flags,
                            FlagCode::FramesUnpinned,
                            format!("{at}.frames[{i}]"),
                            "the caller's frames of this kind are relayed with no pinned shape (no JSON schema or pattern)",
                        );
                    }
                }
                if relay.server {
                    flag(
                        flags,
                        FlagCode::ServerFrames,
                        &at,
                        "the server's WebSocket messages go back to the caller (after the stream search)",
                    );
                }
                for p in relay.sends.iter().filter(|p| broad(p)) {
                    flag(
                        flags,
                        FlagCode::RelayBroad,
                        &at,
                        format!("the relay pattern {p:?} matches broadly"),
                    );
                }
            }
            if let Some(template) = &ret.template
                && Reads::new(operation).reversible_in(template)
            {
                flag(
                    flags,
                    FlagCode::DeriveReversible,
                    &at,
                    "the output is an encryption, key agreement or XOR, not a one-way value",
                );
            }
        }
    }
}

fn caller_flags(c: &CallerRequest, at: &str, flags: &mut Vec<Flag>) {
    for q in c.query.iter().filter(|q| q.allowed().is_any()) {
        flag(
            flags,
            FlagCode::QueryAny,
            at,
            format!("the query parameter {} takes any value", q.name),
        );
    }
    if c.encoded_percent {
        flag(
            flags,
            FlagCode::EncodedPercent,
            at,
            "the caller's path may hold %25",
        );
    }
    if c.override_params {
        flag(
            flags,
            FlagCode::OverrideParams,
            at,
            "the caller may send method-override parameters",
        );
    }
}

fn covered(previous: &[Destination], d: &Destination) -> bool {
    previous.iter().any(|p| p == d || p.matches(d))
}

fn json_of<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Compares two versions of an operation of the same name.
fn diff_operation(
    prev: &Operation,
    cur: &Operation,
    wider: &mut Vec<String>,
    changes: &mut Vec<String>,
) {
    let name = &cur.name;
    if prev.connection() != cur.connection() {
        wider.push(format!("operation {name}: the connection changed"));
    }
    let prev_open = prev.open();
    let prev_dest: &[Destination] = prev_open.map(|o| o.destinations.as_slice()).unwrap_or(&[]);
    if let Some(open) = cur.open() {
        for d in &open.destinations {
            if !covered(prev_dest, d) {
                wider.push(format!(
                    "operation {name}: new destination {}:{}",
                    d.host, d.port
                ));
            }
        }
        for d in prev_dest {
            if !open.destinations.contains(d) {
                changes.push(format!(
                    "operation {name}: destination {}:{} removed",
                    d.host, d.port
                ));
            }
        }
        if open.identity.is_some()
            && prev_open.and_then(|o| o.identity.as_ref()) != open.identity.as_ref()
        {
            wider.push(format!("operation {name}: the client certificate changed"));
        }
        let prev_login = prev_open.and_then(|o| o.login.as_ref());
        if open.login.is_some() && prev_login != open.login.as_ref() {
            wider.push(format!("operation {name}: the sign-in changed"));
        }
        let prev_keys: &[String] = prev_open.map(|o| o.host_keys.as_slice()).unwrap_or(&[]);
        for k in open.host_keys.iter().filter(|k| !prev_keys.contains(k)) {
            let kind = k.split(' ').next().unwrap_or_default();
            wider.push(format!(
                "operation {name}: a new {kind} host key is trusted"
            ));
        }
        if prev_open.and_then(|o| o.tls) != open.tls {
            wider.push(format!("operation {name}: how TLS starts changed"));
        }
        if prev_open.and_then(|o| o.limits.as_ref()) != open.limits.as_ref() {
            wider.push(format!("operation {name}: the connection limits changed"));
        }
        if prev_open.and_then(|o| o.protocol) != open.protocol {
            wider.push(format!("operation {name}: the HTTP version changed"));
        }
    }
    if prev.input != cur.input {
        wider.push(format!("operation {name}: the input schema changed"));
    }
    if prev.payment != cur.payment {
        wider.push(format!("operation {name}: what it pays changed"));
    }
    match (&prev.vend, &cur.vend) {
        (Some(p), Some(c)) if p.covers(c) => {}
        (None, None) => {}
        _ => wider.push(format!(
            "operation {name}: what it vends, or for how long, changed"
        )),
    }
    if prev.approval && !cur.approval {
        wider.push(format!(
            "operation {name}: no longer waits for the owner's approval"
        ));
    }
    if prev.steps.len() != cur.steps.len()
        || prev
            .steps
            .iter()
            .zip(&cur.steps)
            .any(|(a, b)| core::mem::discriminant(a) != core::mem::discriminant(b))
    {
        wider.push(format!("operation {name}: the steps changed"));
        return;
    }
    for (i, (a, b)) in prev.steps.iter().zip(&cur.steps).enumerate() {
        if a == b {
            continue;
        }
        let at = format!("operation {name}, step {i}");
        match (a, b) {
            (Step::Send(a), Step::Send(b)) => diff_send(&at, a, b, wider),
            (Step::Return(a), Step::Return(b)) => diff_return(&at, a, b, wider),
            (Step::Receive(a), Step::Receive(b)) => {
                let fields = |r: &super::Receive| -> Vec<String> {
                    r.capture
                        .iter()
                        .filter_map(|c| match &c.into {
                            Store::Field { name } => Some(name.clone()),
                            Store::Temp { .. } => None,
                        })
                        .collect()
                };
                let before = fields(a);
                for f in fields(b).into_iter().filter(|f| !before.contains(f)) {
                    wider.push(format!("{at}: a response now fills field {f}"));
                }
                if a.capture.iter().map(json_of).collect::<Vec<_>>()
                    != b.capture.iter().map(json_of).collect::<Vec<_>>()
                    || a.until != b.until
                {
                    wider.push(format!("{at}: the captures changed"));
                }
            }
            (Step::Open(_), Step::Open(_)) => {}
            _ => wider.push(format!("{at}: the step changed")),
        }
    }
}

fn diff_send(at: &str, a: &Send, b: &Send, wider: &mut Vec<String>) {
    let before = injects(a);
    for target in injects(b).into_iter().filter(|t| !before.contains(t)) {
        wider.push(format!("{at}: a value now also goes in {target}"));
    }
    let same_templates =
        a.inject.len() == b.inject.len() && a.inject.iter().zip(&b.inject).all(|(x, y)| x == y);
    if !same_templates {
        wider.push(format!("{at}: the injected values changed"));
    }
    if a.template != b.template {
        wider.push(format!("{at}: the bytes written changed"));
    }
    if a.command != b.command {
        wider.push(format!("{at}: the command changed"));
    }
    if a.fill != b.fill {
        // Any change of a fill (origin, frames, selectors, values, submit, wait) counts as
        // wider: it decides which page gets which value.
        wider.push(format!("{at}: the browser fill changed"));
    }
    match (&a.request, &b.request) {
        (Some(StepRequest::Caller(x)), Some(StepRequest::Caller(y))) => {
            for m in y.methods.iter().filter(|m| !x.methods.contains(m)) {
                wider.push(format!("{at}: the caller may now use {}", m.as_str()));
            }
            for p in y.paths.iter().filter(|p| !x.paths.contains(p)) {
                wider.push(format!("{at}: the caller may now reach {p}"));
            }
            for h in y.headers.iter().filter(|h| !x.headers.contains(h)) {
                wider.push(format!("{at}: the caller may now set header {h}"));
            }
            for q in y.query.iter().filter(|q| !x.query.contains(q)) {
                wider.push(format!(
                    "{at}: the query parameter {} is new or looser",
                    q.name
                ));
            }
            if y.encoded_percent && !x.encoded_percent {
                wider.push(format!("{at}: the caller's path may now hold %25"));
            }
            if y.override_params && !x.override_params {
                wider.push(format!("{at}: the caller may now send method overrides"));
            }
        }
        (x, y) if x != y => wider.push(format!("{at}: the request changed")),
        _ => {}
    }
}

fn body_rank(p: Option<&super::Projection>) -> u8 {
    match p.and_then(|p| p.body.as_ref()) {
        None => 0,
        Some(BodyProjection::Json(_)) => 1,
        Some(BodyProjection::All | BodyProjection::Stream) => 2,
    }
}

fn diff_return(at: &str, a: &Return, b: &Return, wider: &mut Vec<String>) {
    let (pa, pb) = (a.response.as_ref(), b.response.as_ref());
    let headers = |p: Option<&super::Projection>| -> Vec<String> {
        p.map(|p| p.headers.iter().map(|h| h.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    };
    let before = headers(pa);
    for h in headers(pb).into_iter().filter(|h| !before.contains(h)) {
        wider.push(format!("{at}: the response header {h} now goes back"));
    }
    if body_rank(pb) > body_rank(pa) {
        wider.push(format!("{at}: more of the response body goes back"));
    }
    if let (Some(BodyProjection::Json(x)), Some(BodyProjection::Json(y))) = (
        pa.and_then(|p| p.body.as_ref()),
        pb.and_then(|p| p.body.as_ref()),
    ) {
        for p in y.iter().filter(|p| !x.contains(p)) {
            wider.push(format!("{at}: the JSON member {p} now goes back"));
        }
    }
    let relays = |r: &Return| {
        r.relay
            .as_ref()
            .map(|r| r.sends.clone())
            .unwrap_or_default()
    };
    let before = relays(a);
    for p in relays(b).into_iter().filter(|p| !before.contains(p)) {
        wider.push(format!("{at}: the stream now relays sends matching {p:?}"));
    }
    let frames = |r: &Return| {
        r.relay
            .as_ref()
            .map(|r| r.frames.clone())
            .unwrap_or_default()
    };
    let before = frames(a);
    for (i, rule) in frames(b).iter().enumerate() {
        if !before.contains(rule) {
            wider.push(format!("{at}: the frame rule {i} is new or changed"));
        }
    }
    let commands = |r: &Return| {
        r.relay
            .as_ref()
            .map(|r| r.commands.clone())
            .unwrap_or_default()
    };
    let before = commands(a);
    for rule in commands(b).iter().filter(|c| !before.contains(c)) {
        wider.push(format!("{at}: the command {} is new or changed", rule.name));
    }
    let mail = |r: &Return| r.relay.as_ref().and_then(|r| r.mail.clone());
    if mail(b).is_some() && mail(a) != mail(b) {
        wider.push(format!("{at}: the mail rule is new or changed"));
    }
    let server = |r: &Return| r.relay.as_ref().is_some_and(|r| r.server);
    if server(b) && !server(a) {
        wider.push(format!(
            "{at}: the server's messages now go back to the caller"
        ));
    }
    let trailers = |p: Option<&super::Projection>| -> Vec<String> {
        p.map(|p| p.trailers.iter().map(|h| h.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    };
    let before = trailers(pa);
    for h in trailers(pb).into_iter().filter(|h| !before.contains(h)) {
        wider.push(format!("{at}: the response trailer {h} now goes back"));
    }
    if a.template != b.template {
        wider.push(format!("{at}: the output changed"));
    }
}

fn diff_caller(prev: &Caller, cur: &Caller, wider: &mut Vec<String>) {
    let name = &cur.name;
    if prev.key != cur.key {
        wider.push(format!("caller {name}: another key"));
    }
    for o in cur
        .operations
        .iter()
        .filter(|o| !prev.operations.contains(o))
    {
        wider.push(format!("caller {name}: may now call {o}"));
    }
    let rate = |l: &Limit| (u128::from(l.count), u128::from(l.window_ms));
    match (prev.limit, cur.limit) {
        (Some(_), None) => wider.push(format!("caller {name}: no rate limit any more")),
        (Some(p), Some(c)) => {
            let ((pc, pw), (cc, cw)) = (rate(&p), rate(&c));
            if cc.saturating_mul(pw) > pc.saturating_mul(cw) || cc > pc {
                wider.push(format!("caller {name}: a higher rate limit"));
            }
        }
        _ => {}
    }
}

/// What `current` widens against `previous`, and what changed without widening.
pub fn diff(previous: &Policy, current: &Policy) -> (Vec<String>, Vec<String>) {
    let mut wider = Vec::new();
    let mut changes = Vec::new();
    if previous.item != current.item {
        match (&previous.item, &current.item) {
            (Some(a), Some(b)) => {
                if a.kind != b.kind || a.custom != b.custom {
                    wider.push("item: the kind changed".into());
                }
                if a.pins != b.pins {
                    wider.push("item: the pinned values changed".into());
                }
                for s in b.signoff.iter().filter(|s| !a.signoff.contains(s)) {
                    wider.push(format!("item: the owner now signs off {s}"));
                }
            }
            (Some(_), None) => wider.push("item: the policy is no longer bound to a kind".into()),
            (None, Some(_)) => changes.push("item: the policy is now bound to a kind".into()),
            (None, None) => {}
        }
    }
    for f in &current.fields {
        match previous.fields.iter().find(|p| p.name == f.name) {
            Some(p) => {
                if p.secret && !f.secret {
                    wider.push(format!("field {}: now public", f.name));
                }
                if p.guessable && !f.guessable {
                    wider.push(format!("field {}: no longer guessable", f.name));
                }
                if p.session != f.session {
                    wider.push(format!("field {}: the session rule changed", f.name));
                }
            }
            None => changes.push(format!("field {} added", f.name)),
        }
    }
    for p in &previous.fields {
        if !current.fields.iter().any(|f| f.name == p.name) {
            changes.push(format!("field {} removed", p.name));
        }
    }
    for op in &current.operations {
        match previous.operations.iter().find(|p| p.name == op.name) {
            Some(prev) => diff_operation(prev, op, &mut wider, &mut changes),
            None => wider.push(format!("operation {} added", op.name)),
        }
    }
    for p in &previous.operations {
        if !current.operations.iter().any(|o| o.name == p.name) {
            changes.push(format!("operation {} removed", p.name));
        }
    }
    for c in &current.callers {
        match previous.callers.iter().find(|p| p.name == c.name) {
            Some(prev) => diff_caller(prev, c, &mut wider),
            None => wider.push(format!("caller {} added", c.name)),
        }
    }
    for p in &previous.callers {
        if !current.callers.iter().any(|c| c.name == p.name) {
            changes.push(format!("caller {} removed", p.name));
        }
    }
    (wider, changes)
}

/// The summary of `policy`, against `previous` when it replaces one. It reads only the
/// policy, never a value; a policy that does not validate is summarized as far as it can be,
/// so a draft can be shown with the error next to it.
pub fn summarize(policy: &Policy, previous: Option<&Policy>) -> Summary {
    let origin = policy.item.as_ref().and_then(|b| b.origin());
    let kind = policy.item.as_ref().and_then(|b| b.schema().ok());
    let item = policy.item.as_ref().map(|b| ItemSummary {
        kind: b.kind.clone(),
        custom: b.custom.is_some(),
        origin: origin.as_ref().map(Origin::text),
        pins: b.pins.clone(),
        signoff: b.signoff.clone(),
    });
    let uses: Vec<(String, SecretUse)> = policy.operations.iter().flat_map(uses_in).collect();
    let secrets = policy
        .fields
        .iter()
        .filter(|f| f.secret)
        .map(|f| SecretSummary {
            field: f.name.clone(),
            guessable: f.guessable,
            disclosure: kind.and_then(|k| k.field(&f.name)).map(|k| k.disclosure),
            uses: uses
                .iter()
                .filter(|(name, _)| *name == f.name)
                .map(|(_, u)| u.clone())
                .collect(),
        })
        .collect();
    let mut flags = Vec::new();
    risk_flags(policy, origin.as_ref(), &mut flags);
    let mut changes = Vec::new();
    if let Some(previous) = previous {
        let (wider, narrower) = diff(previous, policy);
        for w in wider {
            if w.contains("new destination") {
                flag(
                    &mut flags,
                    FlagCode::NewDestination,
                    "destinations",
                    w.clone(),
                );
            }
            flag(&mut flags, FlagCode::Wider, "previous version", w);
        }
        changes = narrower;
    }
    Summary {
        item,
        secrets,
        operations: policy.operations.iter().map(operation_summary).collect(),
        callers: policy
            .callers
            .iter()
            .map(|c| CallerSummary {
                name: c.name.clone(),
                key: c.key.to_b64(),
                operations: c.operations.clone(),
                limit: c.limit,
            })
            .collect(),
        flags,
        changes,
        lines: policy.summary(),
    }
}
