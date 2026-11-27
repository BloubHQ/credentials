//! Policies: which fields a record holds, who may use them, and how, as data.
//!
//! The engine knows no kind of credential and no protocol flow. A policy names the fields of
//! its record, the callers that may use it, and a list of named [`Operation`]s. Every
//! operation is one program in the same step language, over one kind of connection:
//!
//! - [`Step::Open`] opens the connection: [`Connection::Https`] (each `send` is one HTTP/1.1
//!   request, `receive` reads its response) or [`Connection::Tls`] (a byte stream: `send`
//!   writes, `receive` reads up to a delimiter). An operation without `open` has no
//!   connection: it computes from the record and the caller's input (a derivation).
//! - [`Step::Send`] puts rendered templates on the connection: the caller's request within
//!   its [`CallerRequest`] contract, or a request the policy fixes, or bytes on a stream.
//! - [`Step::Receive`] reads and [`Capture`]s values: into a secret field of the record (the
//!   node seals a new record) or into a temporary value later steps read.
//! - [`Step::Compute`] renders a template into a temporary value.
//! - [`Step::Run`] runs code from the destination's own origin, or a reviewed library, in the
//!   sandbox on rendered inputs; its output may only go into a request the policy fixes to
//!   that origin ([`run`]).
//! - [`Step::Return`] says what goes back to the caller: the declared parts of the last
//!   response ([`Projection`]), the caller's exchanges on the stream within the patterns of
//!   a [`Relay`], or the output of a template that must hand no secret back.
//!
//! - [`Step::Repeat`] runs steps a bounded number of times and [`Step::If`] one of two lists
//!   of steps, on a [`Test`] of a value no secret influences ([`flow`]).
//!
//! Every template of every step is checked by the same analysis before the policy is
//! signed. Every call names a [`Caller`] of the policy and carries its signature; a caller may
//! use only the operations it lists, at most at its [`Limit`].
//!
//! The device of the owner signs the policy, and the policy is bound to the ciphertext of its
//! record, so the operator can neither widen it nor move it to another record.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, canonical};
use crate::item::ItemBinding;
use crate::keys::{CallerPublicKey, DeviceKey, DevicePublicKey};
use crate::template::{NameKind, Props, Template, Var};
use crate::{Error, Result};

mod browser;
mod contract;
pub mod flow;
mod input;
pub mod legacy;
mod proto;
pub mod run;
mod schema;
pub mod summary;
pub mod vend;
mod wait;

pub use browser::{
    BROWSER_BYTES, BROWSER_DURATION_MS, BROWSER_IDLE_MS, BrowserControl, Element, Exclusive,
    FILL_WAIT_MS, Fill, FillField, Leave, MAX_FILL_FIELDS, MAX_FILLS, MAX_GRANT_VALUE,
    MAX_NAVIGATE, MAX_SELECTOR, browser_limits,
};
pub use schema::JSON_SCHEMA;
pub use summary::{Summary, summarize};

pub use contract::{
    BodyContract, CallerRequest, FormBody, MAX_CHECKED_BODY, MAX_FORM_FIELDS, MAX_QUERY_RULES,
    QueryRule, RESERVED_PARAMS, path_fault, template_fault, template_matches,
};
pub(crate) use contract::{parse_query, placeholders};
pub use flow::{Branch, MAX_NESTING, MAX_REPEAT, MAX_TEST_VALUE, MAX_TEST_VALUES, Repeat, Test};
pub use input::{Input, JsonInput, JsonType, Member, NodeTime, RawInput, RlpInput, RlpItem};
pub use proto::{
    Answer, Command, CommandRule, DEFAULT_MESSAGES, Login, MAX_COMMANDS, MAX_HOST_KEYS, MAX_MAIL,
    MAX_MESSAGE_WAIT_MS, MAX_MESSAGES, MAX_PARAM, MAX_PARAMS, MAX_RECIPIENTS, MailRule, Mechanism,
    MqttVersion, ParamRule, SettleMode, SshChannel, TlsMode, VerbShape, bind_target,
    forward_target, path_ok, verb_shape,
};
pub use run::{ModuleRef, ModuleSource, RunLimits, RunModule, ScriptSource};
pub use summary::diff;
pub use vend::{Expiry, MAX_VEND_MS, TimeFormat, VEND_SKEW_MS, Vend};
pub(crate) use wait::is_currency;
pub use wait::{
    AmountFormat, AmountSource, Await, Challenge, ChallengeKind, Condition, DEFAULT_CODE_PATTERN,
    MAX_AMOUNT, MAX_AWAITS, MAX_EXPONENT, MAX_HINT, MAX_JSON_NUMBER_AMOUNT, MAX_SESSION_MS,
    MAX_WAIT_MS, MIN_POLL_MS, Payment, Poll, Renew, SessionRule, read_amount,
};

const POLICY_DOMAIN: &[u8] = b"policy/v4\0";

/// Most operations of a policy.
pub const MAX_OPERATIONS: usize = 16;
/// Most callers of a policy.
pub const MAX_CALLERS: usize = 32;
/// Most destinations of a connection.
pub const MAX_DESTINATIONS: usize = 32;
/// Most path templates of a caller request.
pub const MAX_PATHS: usize = 32;
/// Most steps of an operation.
pub const MAX_STEPS: usize = 64;
/// Most requests (HTTPS sends) of an operation.
pub const MAX_REQUESTS: usize = 8;
/// Most injections of a send.
pub const MAX_INJECTIONS: usize = 16;
/// Most captures of a receive.
pub const MAX_CAPTURES: usize = 16;
/// Most delimiters of one receive on a stream.
pub const MAX_DELIMITERS: usize = 8;
/// Longest delimiter of a receive on a stream, in bytes.
pub const MAX_DELIMITER: usize = 256;
/// Most headers or JSON members of a response projection.
pub const MAX_PROJECTION: usize = 32;
/// Most caller send patterns of a relay; also the most frame rules.
pub const MAX_RELAY_PATTERNS: usize = 16;

/// Headers the engine sets itself, or that change how a server reads or answers a request;
/// neither an injection nor a caller may name them.
pub(crate) const RESERVED_HEADERS: [&str; 19] = [
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-accept",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
    "range",
    "if-range",
    "keep-alive",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

/// A field of a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    /// Field name.
    pub name: String,
    /// True for a secret value; false for a public one such as a user name. Secret values are
    /// tracked by taint and searched for in responses.
    pub secret: bool,
    /// True when the record may lack the field (one an operation fills in later).
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    /// True for a secret with few possible values, such as a PIN or a password a person
    /// chose. A derivation may not hand back anything a guess can be checked against: a hash
    /// or signature of it, unless a keyed MAC or an encryption under a strong secret key hides
    /// it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub guessable: bool,
    /// For a secret field that holds a session the node obtained: its lifetime, the field of
    /// its expiry and how it is renewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionRule>,
}

impl FieldSpec {
    /// A secret field.
    pub fn secret(name: &str) -> Self {
        Self {
            name: name.into(),
            secret: true,
            optional: false,
            guessable: false,
            session: None,
        }
    }

    /// A secret field with few possible values (a PIN, a password a person chose).
    pub fn guessable(name: &str) -> Self {
        Self {
            guessable: true,
            ..Self::secret(name)
        }
    }

    /// A public field.
    pub fn public(name: &str) -> Self {
        Self {
            name: name.into(),
            secret: false,
            optional: false,
            guessable: false,
            session: None,
        }
    }

    /// The same field, optional.
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// The same field, holding a session the node obtained.
    #[must_use]
    pub fn session(mut self, rule: SessionRule) -> Self {
        self.session = Some(rule);
        self
    }
}

/// How often a caller may use a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    /// Most calls in one window.
    pub count: u32,
    /// The window, in milliseconds.
    pub window_ms: u64,
}

/// An application or agent that may use the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    /// Its name in the log.
    pub name: String,
    /// The key that signs its calls.
    pub key: CallerPublicKey,
    /// The operations it may use.
    pub operations: Vec<String>,
    /// How often it may call, over all its operations on this record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

/// Where an injection puts its rendered template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    deny_unknown_fields,
    from = "wire::Target"
)]
pub enum Target {
    /// A header with this name.
    Header {
        /// Header name.
        name: String,
    },
    /// A query parameter with this name, percent-encoded by the engine.
    Query {
        /// Parameter name.
        name: String,
    },
    /// The placeholder `{name}` of the path, a whole path segment, percent-encoded by the
    /// engine.
    PathParam {
        /// Placeholder name.
        name: String,
    },
    /// The whole body. The body of the caller is `$body`.
    Body,
}

/// One rendered template put into a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Injection {
    /// Where it goes.
    pub target: Target,
    /// What goes there.
    pub template: String,
}

impl Injection {
    /// A header injection.
    pub fn header(name: &str, template: &str) -> Self {
        Self {
            target: Target::Header { name: name.into() },
            template: template.into(),
        }
    }

    /// A query injection.
    pub fn query(name: &str, template: &str) -> Self {
        Self {
            target: Target::Query { name: name.into() },
            template: template.into(),
        }
    }

    /// A body injection.
    pub fn body(template: &str) -> Self {
        Self {
            target: Target::Body,
            template: template.into(),
        }
    }
}

macro_rules! methods {
    ($( $variant:ident = $name:literal ),* $(,)?) => {
        /// HTTP method.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum Method {
            $( #[doc = $name] #[serde(rename = $name)] $variant, )*
        }

        impl Method {
            /// The token of the method.
            pub fn as_str(self) -> &'static str {
                match self { $( Method::$variant => $name, )* }
            }
        }
    };
}

methods! {
    Get = "GET",
    Head = "HEAD",
    Post = "POST",
    Put = "PUT",
    Patch = "PATCH",
    Delete = "DELETE",
    Options = "OPTIONS",
    Propfind = "PROPFIND",
    Report = "REPORT",
    Mkcol = "MKCOL",
    Copy = "COPY",
    Move = "MOVE",
}

/// A TLS destination: a host name and a port. In a policy the host may start with `*.`,
/// which stands for exactly one label (`*.example.com` matches `a.example.com`, not
/// `example.com` nor `a.b.example.com`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// Lowercase host name.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Destination {
    /// The error for a request to this destination where the operation allows none like it.
    pub(crate) fn denied(&self) -> Error {
        Error::DestinationDenied {
            host: format!("{}:{}", self.host, self.port),
        }
    }
}

fn is_label(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && label.first() != Some(&b'-')
        && label.last() != Some(&b'-')
}

impl Destination {
    /// A destination on port 443.
    pub fn https(host: &str) -> Self {
        Self::new(host, 443)
    }

    /// A destination on `port`. The host is lowercased.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
        }
    }

    /// True when the host is a pattern.
    pub fn is_wildcard(&self) -> bool {
        self.host.starts_with("*.")
    }

    /// True for a host name of labels (no pattern) and a port that is not 0.
    pub fn is_concrete(&self) -> bool {
        self.port != 0
            && self.host.len() <= 253
            && self.host.split('.').all(|l| is_label(l.as_bytes()))
    }

    fn is_valid_pattern(&self) -> bool {
        match self.host.strip_prefix("*.") {
            Some(rest) => {
                rest.split('.').count() >= 2 && Destination::new(rest, self.port).is_concrete()
            }
            None => self.is_concrete(),
        }
    }

    /// True when the concrete destination `other` is one this destination names.
    pub fn matches(&self, other: &Destination) -> bool {
        if !other.is_concrete() || self.port != other.port {
            return false;
        }
        match self.host.strip_prefix("*.") {
            Some(suffix) => other
                .host
                .strip_suffix(suffix)
                .and_then(|h| h.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
            None => self.host == other.host,
        }
    }
}

/// A client certificate presented in the TLS handshake (mutual TLS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Template of the certificate chain, as the transport takes it (for example PEM).
    pub cert: String,
    /// Template of the private key, as the transport takes it.
    pub key: String,
}

/// Where a capture reads in a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "from",
    rename_all = "snake_case",
    deny_unknown_fields,
    from = "wire::Source"
)]
pub enum Source {
    /// The status code, as decimal text.
    Status,
    /// The value of the first header with this name.
    Header {
        /// Header name.
        name: String,
    },
    /// A `param=value` or `param="value"` inside a header value (as in `WWW-Authenticate`).
    /// With `scheme`, only a challenge of that scheme is read.
    HeaderParam {
        /// Header name.
        name: String,
        /// Parameter name.
        param: String,
        /// Authentication scheme, such as `Digest`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    /// The value of the cookie with this name in a `Set-Cookie` header.
    Cookie {
        /// Cookie name.
        name: String,
    },
    /// A JSON value of the body, by JSON pointer (RFC 6901). Strings are taken unquoted,
    /// numbers as written.
    Json {
        /// JSON pointer, such as `/access_token`.
        pointer: String,
    },
    /// The bytes between the first `start` and the next `end`.
    Between {
        /// Text before the value.
        start: String,
        /// Text after the value.
        end: String,
    },
    /// The first element of an HTML body that a compound selector (`input[name=csrf]`,
    /// `meta[name="token"]`, `#id.class`) matches: the value of `attribute`, or its text.
    Html {
        /// The selector, at most 256 bytes.
        selector: String,
        /// The attribute read; without it, the text of the element.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attribute: Option<String>,
    },
    /// A group of the first match of a regular expression (linear time, no backreferences
    /// or look-around, ASCII classes).
    Regex {
        /// The pattern, at most 256 bytes.
        pattern: String,
        /// The group; by default 1 when the pattern has a group, else the whole match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<u8>,
    },
    /// The whole body.
    All,
    /// The value of the first trailer with this name (after a chunked or HTTP/2 body), or of
    /// the header when the answer has no trailers of that name (a gRPC answer without a
    /// message carries its status in its head).
    Trailer {
        /// Trailer name.
        name: String,
    },
}

/// The forms the tagged enums are read in. Serde ignores unknown members next to the tag of a
/// variant without fields (`{"from": "all", "junk": 1}` would read as `All`), so here every
/// such variant has an empty set of fields, which refuses them.
mod wire {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    pub(super) enum Target {
        Header { name: String },
        Query { name: String },
        PathParam { name: String },
        Body {},
    }

    impl From<Target> for super::Target {
        fn from(t: Target) -> Self {
            match t {
                Target::Header { name } => Self::Header { name },
                Target::Query { name } => Self::Query { name },
                Target::PathParam { name } => Self::PathParam { name },
                Target::Body {} => Self::Body,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
    pub(super) enum Source {
        Status {},
        Header {
            name: String,
        },
        HeaderParam {
            name: String,
            param: String,
            #[serde(default)]
            scheme: Option<String>,
        },
        Cookie {
            name: String,
        },
        Json {
            pointer: String,
        },
        Between {
            start: String,
            end: String,
        },
        Html {
            selector: String,
            #[serde(default)]
            attribute: Option<String>,
        },
        Regex {
            pattern: String,
            #[serde(default)]
            group: Option<u8>,
        },
        All {},
        Trailer {
            name: String,
        },
    }

    impl From<Source> for super::Source {
        fn from(s: Source) -> Self {
            match s {
                Source::Status {} => Self::Status,
                Source::Header { name } => Self::Header { name },
                Source::HeaderParam {
                    name,
                    param,
                    scheme,
                } => Self::HeaderParam {
                    name,
                    param,
                    scheme,
                },
                Source::Cookie { name } => Self::Cookie { name },
                Source::Json { pointer } => Self::Json { pointer },
                Source::Between { start, end } => Self::Between { start, end },
                Source::Html {
                    selector,
                    attribute,
                } => Self::Html {
                    selector,
                    attribute,
                },
                Source::Regex { pattern, group } => Self::Regex { pattern, group },
                Source::All {} => Self::All,
                Source::Trailer { name } => Self::Trailer { name },
            }
        }
    }
}

impl Source {
    fn rule(&self, stream: bool) -> Option<&'static str> {
        let http_only = "source not available on a stream";
        match self {
            Source::All => None,
            Source::Status if stream => Some(http_only),
            Source::Status => None,
            Source::Header { .. }
            | Source::Cookie { .. }
            | Source::HeaderParam { .. }
            | Source::Json { .. }
            | Source::Html { .. }
            | Source::Trailer { .. }
                if stream =>
            {
                Some(http_only)
            }
            Source::Header { name } | Source::Cookie { name } | Source::Trailer { name } => {
                (!is_token(name)).then_some("name is not a token")
            }
            Source::HeaderParam {
                name,
                param,
                scheme,
            } => (!is_token(name) || !is_token(param) || !scheme.as_deref().is_none_or(is_token))
                .then_some("name is not a token"),
            Source::Json { pointer } => (!(pointer.is_empty() || pointer.starts_with('/')))
                .then_some("JSON pointer must be empty or start with /"),
            Source::Between { start, end } => (start.is_empty()
                || end.is_empty()
                || start.len() > MAX_DELIMITER
                || end.len() > MAX_DELIMITER)
                .then_some("between needs delimiters of 1 to 256 bytes"),
            Source::Html {
                selector,
                attribute,
            } => (crate::extract::Selector::parse(selector).is_none()
                || !attribute.as_deref().is_none_or(is_token))
            .then_some("html needs a compound selector of at most 256 bytes and a token attribute"),
            Source::Regex { pattern, group } => crate::extract::compile(pattern)
                .and_then(|r| crate::extract::group_of(&r, *group))
                .is_none()
                .then_some("regex needs a pattern of at most 256 bytes within the size limits, and an existing group"),
        }
    }
}

/// Where a captured value goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Store {
    /// A secret field of the record. The node seals the record again and hands the new one
    /// back. Only a request the policy fixes, or a stream, may capture into a field.
    Field {
        /// Field name.
        name: String,
    },
    /// A value later steps of this operation read by name; it ends with the operation.
    Temp {
        /// Name.
        name: String,
        /// True when the value is secret (taint, redaction and the reflection check).
        secret: bool,
    },
}

/// One value taken from a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    /// Where it is read.
    pub source: Source,
    /// Where it goes.
    pub into: Store,
    /// True when a missing value is not an error.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
}

/// The kind of connection an operation opens. New kinds (SSH, database handshakes, a browser
/// over CDP) are added here, each with what its `send`, `receive` and `return` mean; the
/// steps and the analysis stay the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    /// HTTPS: each `send` is one request on its own TLS connection (HTTP/2 or HTTP/1.1, as
    /// ALPN agrees and `protocol` allows), and `receive` reads its response.
    Https,
    /// A TLS byte stream (IMAP, SMTP, line protocols): `send` writes, `receive` reads up to a
    /// delimiter.
    Tls,
    /// A WebSocket (RFC 6455) over TLS: the first `send` is the opening handshake, an HTTPS
    /// request under the same contracts; later sends write messages from templates, and the
    /// `return` relays the caller's frames within declared shapes.
    Websocket,
    /// SSH (RFC 4253): the server proves a pinned host key, the node signs in, `send` runs a
    /// command, and `return` relays the caller's commands or an interactive shell.
    Ssh,
    /// PostgreSQL over TLS: SCRAM-SHA-256, then queries with bound parameters.
    Postgres,
    /// SMTP submission over TLS (implicit or `STARTTLS`): the caller's messages within the
    /// sender and recipient rules of the policy.
    Smtp,
    /// IMAP over TLS (implicit or `STARTTLS`): commands fixed or shaped by the policy.
    Imap,
    /// Redis over TLS: `AUTH`, then commands with bulk-string parameters.
    Redis,
    /// MySQL: TLS before the sign-in, `caching_sha2_password`, then prepared statements with
    /// bound parameters.
    Mysql,
    /// MQTT 3.1.1 or 5 over TLS: publications and subscriptions within the policy's topics.
    Mqtt,
    /// AMQP 0-9-1 over TLS: `PLAIN`, publications to fixed exchanges and routing keys,
    /// messages got from fixed queues.
    Amqp,
    /// AMQP 1.0 (OASIS, ISO/IEC 19464) over TLS (from the first byte, or after the TLS
    /// protocol header): SASL `PLAIN`, `EXTERNAL`, `SCRAM-SHA-256` or `XOAUTH2`, then one
    /// session and one link at a time: messages sent to and received from addresses the
    /// policy fixes, each with the settle mode it names.
    Amqp1,
    /// FTP over TLS (RFC 959, RFC 4217; implicit, or explicit with `AUTH TLS`): typed file
    /// operations over passive-mode data connections to the same server, each protected
    /// by TLS.
    Ftp,
    /// POP3 over TLS (RFC 1939; implicit, or `STLS` of RFC 2595): `USER`/`PASS`, `APOP` or
    /// SASL, then commands whose parameters are message numbers.
    Pop3,
    /// UDP datagrams to one destination, for request and response protocols that protect
    /// their messages with a MAC (RADIUS, DNS with TSIG, STUN): `send` writes one datagram,
    /// `receive` reads one. There is no TLS, so a send may not hold a secret in reversible
    /// form.
    Udp,
    /// DTLS 1.2 or 1.3 (RFC 6347, RFC 9147) over UDP datagrams to one destination, for
    /// request and response protocols over DTLS (CoAP, LwM2M): the server's certificate is
    /// checked as for `tls` (and against `pins` when the policy gives them) before anything
    /// is sent; then `send` writes one record and `receive` reads one.
    Dtls,
    /// A browser, over the Chrome DevTools Protocol: a WebSocket to the CDP endpoint the
    /// policy fixes. The first `send` is the handshake, as for a WebSocket; each later one is
    /// a [`Fill`] the node runs itself. Nothing of the page goes back but the outcome and the
    /// final origin; the caller issues no CDP command.
    Browser,
}

/// The `open` step: the connection and where it may go.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    /// The kind of connection.
    pub connection: Connection,
    /// Destinations it may reach.
    pub destinations: Vec<Destination>,
    /// Client certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    /// The HTTP version an HTTPS connection must use (`h2` or `http1`); without it, the one
    /// ALPN agrees on, HTTP/2 first. A pinned version the server does not agree to fails the
    /// request before anything is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<crate::egress::Versions>,
    /// Bounds of a connection that stays open (a WebSocket, a streamed response, a protocol
    /// connection); the defaults when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<StreamLimits>,
    /// How the node signs in on a protocol connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    /// The SSH host keys the server must prove it holds one of (`type base64`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_keys: Vec<String>,
    /// The keys a DTLS server's certificate must hold one of, each `sha256/` and the
    /// base64 of the SHA-256 of its DER `SubjectPublicKeyInfo`. A self-signed certificate is
    /// accepted only with a pinned key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pins: Vec<String>,
    /// CA certificates between a DTLS server's certificate and the transport's roots, each
    /// the standard base64 of its DER, for a server issued through an intermediate (almost
    /// every public CA): the DTLS stack hands over the server's own certificate, not the
    /// chain the server sent. They widen nothing: the chain must still end at a root.
    /// Padded standard base64, unlike the unpadded URL-safe base64 of the protocol's byte
    /// fields ([`crate::encoding`]): it is the body of a PEM certificate, so one can be pasted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intermediates: Vec<String>,
    /// How SMTP and IMAP reach TLS (implicit by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsMode>,
    /// The MQTT version (`3.1.1`, the default, or `5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<MqttVersion>,
    /// How a browser connection keeps the agent's controller out while the node fills, and
    /// what it leaves in the page ([`BrowserControl`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserControl>,
}

/// Bounds of a connection that stays open: it is closed when one is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamLimits {
    /// Longest time without a byte either way, in milliseconds (default 30 s, at most 120 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_ms: Option<u64>,
    /// Longest time open, in milliseconds (default 10 minutes, at most 1 hour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Most bytes both ways together (default 64 MiB, at most 1 GiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Default and largest idle time of an open connection.
pub const STREAM_IDLE_MS: (u64, u64) = (30_000, 120_000);
/// Default and longest duration of an open connection.
pub const STREAM_DURATION_MS: (u64, u64) = (600_000, 3_600_000);
/// Default and largest byte count of an open connection.
pub const STREAM_BYTES: (u64, u64) = (64 << 20, 1 << 30);

impl StreamLimits {
    /// The limits in force: given ones, else the defaults.
    pub fn effective(&self) -> (u64, u64, u64) {
        (
            self.idle_ms.unwrap_or(STREAM_IDLE_MS.0),
            self.duration_ms.unwrap_or(STREAM_DURATION_MS.0),
            self.bytes.unwrap_or(STREAM_BYTES.0),
        )
    }

    fn fault(&self) -> Option<&'static str> {
        let within = |v: Option<u64>, max: u64| v.is_none_or(|v| v > 0 && v <= max);
        (!(within(self.idle_ms, STREAM_IDLE_MS.1)
            && within(self.duration_ms, STREAM_DURATION_MS.1)
            && within(self.bytes, STREAM_BYTES.1)))
        .then_some("limits: idle 1 ms to 120 s, duration 1 ms to 1 h, bytes 1 to 1 GiB")
    }
}

/// The kind of a WebSocket data message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    /// A text message (UTF-8).
    Text,
    /// A binary message.
    Binary,
}

/// A frame of the caller a WebSocket relays: its kind, the shape it must have, and the
/// template the node sends in its place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameRule {
    /// The kind of message.
    pub kind: FrameKind,
    /// The shape the caller's frame must have: a closed JSON schema, or bytes under a pattern
    /// (the schema language of an input). Without it, any frame of the kind is relayed; a
    /// summary flags that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<Input>,
    /// What is sent for the frame, `$input` being the frame as checked (and normalized) by the
    /// shape; without it, the frame as it came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

impl FrameRule {
    /// True when the shape leaves the frame open: no shape, or bytes with no pattern.
    pub fn unpinned(&self) -> bool {
        match &self.shape {
            None => true,
            Some(Input::Raw(raw)) => raw.pattern.is_none(),
            Some(_) => false,
        }
    }
}

/// What request an HTTPS `send` sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepRequest {
    /// The request of the caller, within its contract.
    Caller(CallerRequest),
    /// A request the policy fixes; the caller has no say in it.
    Fixed {
        /// Method.
        method: Method,
        /// Path and query, starting with `/`; a placeholder `{name}` is a whole segment.
        path: String,
        /// Destination (concrete). It may be left out only when the connection has exactly
        /// one destination and that one is concrete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<Destination>,
    },
}

/// The `send` step. On HTTPS it takes `request` and `inject`; on a TLS stream, `template`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Send {
    /// The request (HTTPS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<StepRequest>,
    /// What the request carries (HTTPS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject: Vec<Injection>,
    /// What is written (TLS), or the message sent (WebSocket, with `frame`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// The request is a unary gRPC call (HTTPS pinned to `h2`, `POST`): its body is framed as
    /// one message, with `content-type: application/grpc` and `te: trailers`; the answer's
    /// message is unframed and its `grpc-status` read from the trailers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub grpc: bool,
    /// The kind of message a WebSocket send writes (after the handshake).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameKind>,
    /// The command a protocol connection runs (SSH, PostgreSQL, IMAP, Redis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    /// A browser fill (a `browser` connection, after the handshake).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill: Option<Fill>,
}

/// The `receive` step. On HTTPS it reads the response of the `send` just before it; on a TLS
/// stream it reads up to and including the first of the delimiters `until`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receive {
    /// The delimiters that end the read (TLS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub until: Vec<String>,
    /// What is taken from what was read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture: Vec<Capture>,
}

/// The `compute` step: a template rendered into a temporary value later steps read by name.
/// The name has exactly the properties of the template for the analysis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compute {
    /// The name of the value.
    pub into: String,
    /// The template.
    pub template: String,
}

/// What goes back to the caller of an HTTPS operation, from the last response. The status
/// always goes back; headers and the body only as declared.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    /// Response headers that go back (case does not matter).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// What of the body goes back; nothing when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyProjection>,
    /// Response trailers that go back (gRPC's `grpc-status`, say).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trailers: Vec<String>,
}

/// What of a response body goes back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyProjection {
    /// The whole body. A summary flags it: whatever the server puts there reaches the caller.
    All,
    /// These JSON members, as an object from each pointer to its value. A `*` token stands
    /// for every element of an array.
    Json(Vec<String>),
    /// The whole body, forwarded as it arrives (server-sent events, chunked answers) on a
    /// streaming call, after the stream search; a plain call gets it whole, as `all`. A
    /// summary flags it like `all`.
    Stream,
}

/// The caller's exchanges a TLS operation relays after its steps, or the frames a WebSocket
/// relays.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// Regular expressions (linear time, ASCII, `.` does not match a line end); each caller
    /// send must match one of them whole (TLS).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sends: Vec<String>,
    /// The frames of the caller that are relayed (WebSocket): each must match a rule of its
    /// kind; any other is refused and ends the connection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<FrameRule>,
    /// True when the server's messages go back to the caller (WebSocket, SSH shell), after
    /// the stream search. A summary flags it: whatever the server sends reaches the caller.
    #[serde(default, skip_serializing_if = "is_false")]
    pub server: bool,
    /// The commands the caller may run on a protocol connection, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<CommandRule>,
    /// The messages the caller may send over SMTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailRule>,
}

/// The `return` step: what goes back to the caller. HTTPS takes `response`, TLS `relay`, an
/// operation with no connection `template`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Return {
    /// The parts of the last response that go back (HTTPS); without it, the status only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Projection>,
    /// The caller's exchanges relayed (TLS); without it, none are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Relay>,
    /// The output (no connection): it must hand no secret back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

/// One step of an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case")]
pub enum Step {
    /// Opens the connection.
    Open(Open),
    /// Sends.
    Send(Send),
    /// Receives and captures.
    Receive(Receive),
    /// Computes a value.
    Compute(Compute),
    /// Runs site code or a reviewed library in the sandbox.
    Run(RunModule),
    /// Says what goes back to the caller; the last step.
    Return(Return),
    /// A bounded loop.
    Repeat(Repeat),
    /// A branch.
    If(Branch),
    /// Parks the operation until a challenge is answered.
    Await(Box<Await>),
}

/// A named thing a caller may do with a record: steps over one connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Operation name.
    pub name: String,
    /// The schema of the caller's input, `$input` to the templates (operations with no
    /// connection). An operation whose templates read `$input` must declare it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
    /// The steps, in order.
    pub steps: Vec<Step>,
    /// What the operation pays, when it moves money: the node builds the approval summary
    /// from it and applies the owner's spending limits before anything is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<Payment>,
    /// True when every use needs the owner's approval, whatever the limits say.
    #[serde(default, skip_serializing_if = "is_false")]
    pub approval: bool,
    /// What the operation vends: a short-lived credential minted from the secret, with the
    /// longest it may stay valid and where its expiry is read ([`vend`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vend: Option<Vend>,
}

impl Operation {
    /// The error for a call that needs another kind of operation.
    pub(crate) fn unknown(&self) -> Error {
        Error::OperationUnknown {
            name: self.name.clone(),
        }
    }

    /// The name of the operation.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `open` step, when the operation has a connection.
    pub fn open(&self) -> Option<&Open> {
        match self.steps.first() {
            Some(Step::Open(open)) => Some(open),
            _ => None,
        }
    }

    /// The kind of connection; `None` for an operation that computes only.
    pub fn connection(&self) -> Option<Connection> {
        self.open().map(|o| o.connection)
    }

    /// The `return` step.
    pub fn returns(&self) -> Option<&Return> {
        match self.steps.last() {
            Some(Step::Return(r)) => Some(r),
            _ => None,
        }
    }

    /// The contracts of the `send` steps that send the caller's request, with their steps
    /// (inside loops and branches too).
    pub fn caller_sends(&self) -> impl Iterator<Item = (&CallerRequest, &Send)> {
        flow::walk(&self.steps).into_iter().filter_map(|s| match s {
            Step::Send(send) => match &send.request {
                Some(StepRequest::Caller(contract)) => Some((contract, send)),
                _ => None,
            },
            _ => None,
        })
    }

    /// The captures that go into temporary values, with their secrecy; the outputs of `run`
    /// steps (secret: the code may copy its inputs) and the code of a challenge are secret
    /// temporary values.
    fn temps(&self) -> Vec<(&str, bool)> {
        let steps = flow::walk(&self.steps);
        let mut out: Vec<(&str, bool)> = steps
            .iter()
            .flat_map(|s| match s {
                Step::Receive(r) => r.capture.as_slice(),
                _ => &[],
            })
            .filter_map(|c| match &c.into {
                Store::Temp { name, secret } => Some((name.as_str(), *secret)),
                Store::Field { .. } => None,
            })
            .collect();
        out.extend(steps.iter().filter_map(|s| match s {
            Step::Run(run) => Some((run.into.as_str(), true)),
            _ => None,
        }));
        out.extend(
            self.awaits()
                .filter_map(|a| a.challenge.into.as_deref())
                .map(|name| (name, true)),
        );
        out
    }

    /// The `await` steps.
    pub fn awaits(&self) -> impl Iterator<Item = &Await> {
        flow::walk(&self.steps).into_iter().filter_map(|s| match s {
            Step::Await(a) => Some(a.as_ref()),
            _ => None,
        })
    }

    /// True when a step may park the operation.
    pub fn parks(&self) -> bool {
        self.awaits().next().is_some()
    }

    /// True when the operation runs on a streaming call: a WebSocket, an SSH shell or
    /// forward, a live MQTT relay, or HTTPS whose `return` streams the body. Such an
    /// operation holds the caller's connection for the call, so it never waits.
    pub fn streams(&self) -> bool {
        match self.connection() {
            Some(Connection::Websocket) => true,
            // An SSH shell or forward: the relay takes the caller's frames. MQTT: the relay
            // hands back the messages of the subscriptions the policy keeps.
            Some(Connection::Ssh | Connection::Mqtt) => self
                .returns()
                .and_then(|r| r.relay.as_ref())
                .is_some_and(|r| !r.frames.is_empty() || r.server),
            Some(Connection::Https) => self.returns().is_some_and(|r| {
                r.response
                    .as_ref()
                    .is_some_and(|p| p.body == Some(BodyProjection::Stream))
            }),
            _ => false,
        }
    }

    /// The names of fields the templates of the operation read.
    pub(crate) fn field_reads(&self, policy: &Policy) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for text in self.templates() {
            if let Ok(template) = Template::parse(text) {
                for name in template.names() {
                    if policy.is_field(name) && !out.iter().any(|n| n == name) {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out
    }

    /// The fields a response may fill (captures into fields, inside loops and branches too).
    pub(crate) fn field_captures(&self) -> Vec<&str> {
        flow::walk(&self.steps)
            .into_iter()
            .flat_map(|s| match s {
                Step::Receive(r) => r.capture.as_slice(),
                _ => &[],
            })
            .filter_map(|c| match &c.into {
                Store::Field { name } => Some(name.as_str()),
                Store::Temp { .. } => None,
            })
            .collect()
    }

    /// True when the concrete destination is one the connection names.
    pub fn allows_destination(&self, destination: &Destination) -> bool {
        self.open()
            .is_some_and(|o| o.destinations.iter().any(|d| d.matches(destination)))
    }

    /// True when a step sends the request of the caller.
    pub fn takes_request(&self) -> bool {
        self.caller_sends().next().is_some()
    }

    fn templates(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for step in flow::walk(&self.steps) {
            match step {
                Step::Open(open) => {
                    if let Some(identity) = &open.identity {
                        out.push(identity.cert.as_str());
                        out.push(identity.key.as_str());
                    }
                    if let Some(login) = &open.login {
                        out.extend(login.templates());
                    }
                }
                Step::Send(send) => {
                    out.extend(send.inject.iter().map(|i| i.template.as_str()));
                    out.extend(send.template.as_deref());
                    if let Some(command) = &send.command {
                        out.push(command.text.as_str());
                        out.extend(command.params.iter().map(String::as_str));
                    }
                    if let Some(fill) = &send.fill {
                        out.extend(fill.fields.iter().map(|f| f.template.as_str()));
                    }
                }
                Step::Compute(c) => out.push(&c.template),
                Step::Run(run) => out.extend(run.inputs.iter().map(String::as_str)),
                Step::Return(r) => {
                    out.extend(r.template.as_deref());
                    if let Some(relay) = &r.relay {
                        for rule in &relay.commands {
                            out.push(rule.text.as_str());
                            out.extend(rule.params.iter().filter_map(|p| p.template.as_deref()));
                        }
                        out.extend(relay.frames.iter().filter_map(|f| f.template.as_deref()));
                    }
                }
                Step::Await(a) => {
                    if let Some(poll) = &a.challenge.poll {
                        out.extend(poll.send.inject.iter().map(|i| i.template.as_str()));
                    }
                }
                Step::Receive(_) | Step::Repeat(_) | Step::If(_) => {}
            }
        }
        out
    }
}

/// What each name an operation reads is, for the analysis, with the properties of the values
/// its `compute` steps define worked out once, in order.
pub struct Kinds<'p> {
    policy: &'p Policy,
    temps: Vec<(&'p str, bool)>,
    computed: Vec<(&'p str, Props)>,
}

impl<'p> Kinds<'p> {
    fn new(policy: &'p Policy, operation: &'p Operation) -> Self {
        let mut kinds = Kinds {
            policy,
            temps: operation.temps(),
            computed: Vec::new(),
        };
        for step in flow::walk(&operation.steps) {
            if let Step::Compute(c) = step {
                let props = Template::parse(&c.template)
                    .ok()
                    .and_then(|t| t.props(&|n| kinds.kind(n)).ok())
                    .unwrap_or_else(Props::unknown);
                // A name both bodies of a branch compute is whatever either makes it.
                match kinds.computed.iter_mut().find(|(n, _)| *n == c.into) {
                    Some((_, known)) => *known = known.join(props),
                    None => kinds.computed.push((&c.into, props)),
                }
            }
        }
        kinds
    }

    /// What `name` is. An unknown name counts as a secret field.
    pub fn kind(&self, name: &str) -> NameKind {
        if let Some((_, props)) = self.computed.iter().find(|(n, _)| *n == name) {
            return NameKind::Computed(*props);
        }
        if self.temps.iter().any(|(n, _)| *n == name) {
            // A name captured in both bodies of a branch, or again in a loop, is secret when
            // any capture makes it so (the check refuses captures that disagree).
            let secret = self.temps.iter().any(|(n, s)| *n == name && *s);
            return if secret {
                NameKind::SecretTemp
            } else {
                NameKind::PublicTemp
            };
        }
        let fields = &self.policy.fields;
        if fields
            .iter()
            .any(|f| f.name == name && f.secret && f.guessable)
        {
            NameKind::GuessableField
        } else if self.policy.is_secret(name) {
            NameKind::SecretField
        } else {
            NameKind::PublicField
        }
    }
}

/// The rules of one record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The kind of item the record is, with the owner's choices: the policy then stays within
    /// the shape of the kind ([`crate::item::check_policy`]). Absent for a record without a
    /// kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<ItemBinding>,
    /// The fields of the record.
    pub fields: Vec<FieldSpec>,
    /// Who may use them.
    pub callers: Vec<Caller>,
    /// What may be done with them.
    pub operations: Vec<Operation>,
}

/// The headers and query parameters a template of a `send` reads: one the `send` injects, or
/// one of the caller's request that its contract lets the caller set (only a send that takes
/// the caller's request has those). So the analysis knows each value a template reads, and a
/// caller cannot put a header the contract refuses into a signature.
fn check_components(
    at: &str,
    template: &Template,
    request: &StepRequest,
    inject: &[Injection],
) -> Checked {
    let headers: Vec<&str> = template
        .headers()
        .into_iter()
        .filter(|h| !crate::request::injects_header(inject, h))
        .collect();
    let params: Vec<&str> = template
        .query_params()
        .into_iter()
        .filter(|q| !crate::request::injects_query(inject, q))
        .collect();
    if headers.is_empty() && params.is_empty() {
        return Ok(());
    }
    let StepRequest::Caller(contract) = request else {
        return fail(
            at,
            "a fixed request has no caller headers or query parameters to read",
        );
    };
    for name in headers {
        ensure(
            contract
                .headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case(name)),
            || format!("{at} ({name})"),
            "a template reads a header the caller contract does not allow",
        )?;
    }
    for name in params {
        let decoded = crate::primitives::pct_decode(name.as_bytes()).ok();
        ensure(
            decoded.is_some_and(|d| {
                contract
                    .query
                    .iter()
                    .any(|r| r.name.as_bytes() == d.as_slice())
            }),
            || format!("{at} ({name})"),
            "a template reads a query parameter the caller contract does not allow",
        )?;
    }
    Ok(())
}

pub(crate) fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn unique<'a>(names: impl Iterator<Item = &'a str>) -> bool {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    names.windows(2).all(|w| w.first() != w.get(1))
}

type Checked = core::result::Result<(), Error>;

fn fail(at: impl Into<String>, rule: &'static str) -> Checked {
    Err(Error::policy(at, rule))
}

fn ensure(ok: bool, at: impl FnOnce() -> String, rule: &'static str) -> Checked {
    if ok { Ok(()) } else { fail(at(), rule) }
}

fn check_destinations(at: &str, destinations: &[Destination]) -> Checked {
    ensure(
        !destinations.is_empty() && destinations.len() <= MAX_DESTINATIONS,
        || format!("{at}.destinations"),
        "1 to 32 destinations",
    )?;
    for (i, d) in destinations.iter().enumerate() {
        ensure(
            d.is_valid_pattern(),
            || format!("{at}.destinations[{i}]"),
            "lowercase host name (or *. and at least two labels) and a port",
        )?;
    }
    Ok(())
}

/// Most certificate pins of one `dtls` operation.
pub const MAX_CERTIFICATE_PINS: usize = 16;
/// Most intermediate certificates of a `dtls` connection.
pub const MAX_INTERMEDIATES: usize = 8;
/// Largest DER of an intermediate certificate.
pub const MAX_INTERMEDIATE_BYTES: usize = 8 * 1024;

/// The SHA-256 of a `SubjectPublicKeyInfo` that a pin names: `sha256/` and the standard,
/// padded base64 of 32 bytes, in its one canonical spelling. `None` for anything else.
pub fn parse_pin(pin: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    let encoded = pin.strip_prefix("sha256/")?;
    if encoded.len() != 44 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let hash: [u8; 32] = bytes.try_into().ok()?;
    (base64::engine::general_purpose::STANDARD.encode(hash) == encoded).then_some(hash)
}

/// Pins are for a `dtls` connection: at most 16, each a [`parse_pin`] and none twice.
fn check_pins(at: &str, open: &Open) -> Checked {
    if open.pins.is_empty() {
        return Ok(());
    }
    ensure(
        open.connection == Connection::Dtls,
        || format!("{at}.pins"),
        "pins are for a DTLS connection",
    )?;
    ensure(
        open.pins.len() <= MAX_CERTIFICATE_PINS,
        || format!("{at}.pins"),
        "1 to 16 pins",
    )?;
    for (i, pin) in open.pins.iter().enumerate() {
        ensure(
            parse_pin(pin).is_some() && !open.pins.iter().take(i).any(|p| p == pin),
            || format!("{at}.pins[{i}]"),
            "a pin is sha256/ and the base64 of 32 bytes, each once",
        )?;
    }
    Ok(())
}

/// The DER of an intermediate certificate a policy lists: the standard, padded base64 of at
/// most [`MAX_INTERMEDIATE_BYTES`] bytes that begin a DER `SEQUENCE`, in its one canonical
/// spelling. `None` for anything else; the transport parses the certificate itself.
pub fn parse_intermediate(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()?;
    let canonical = base64::engine::general_purpose::STANDARD.encode(&der) == text;
    (canonical && der.len() <= MAX_INTERMEDIATE_BYTES && der.first() == Some(&0x30)).then_some(der)
}

/// Intermediates are for a `dtls` connection: at most 8, each a [`parse_intermediate`] and
/// none twice.
fn check_intermediates(at: &str, open: &Open) -> Checked {
    if open.intermediates.is_empty() {
        return Ok(());
    }
    ensure(
        open.connection == Connection::Dtls,
        || format!("{at}.intermediates"),
        "intermediates are for a DTLS connection",
    )?;
    ensure(
        open.intermediates.len() <= MAX_INTERMEDIATES,
        || format!("{at}.intermediates"),
        "1 to 8 intermediates",
    )?;
    for (i, cert) in open.intermediates.iter().enumerate() {
        ensure(
            parse_intermediate(cert).is_some()
                && !open.intermediates.iter().take(i).any(|c| c == cert),
            || format!("{at}.intermediates[{i}]"),
            "an intermediate is the base64 of a DER certificate of at most 8 KiB, each once",
        )?;
    }
    Ok(())
}

/// A query name a policy may list: visible ASCII without the bytes that end it.
fn is_query_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"&=#+%".contains(&b))
}

/// True when every placeholder of a fixed path is a whole path segment, outside the query.
fn whole_segment_placeholders(path: &str) -> bool {
    let (pathname, query) = path.split_once('?').unwrap_or((path, ""));
    !query.contains(['{', '}'])
        && pathname
            .split('/')
            .all(|s| !s.contains(['{', '}']) || contract::placeholder(s).is_some())
}

fn check_projection(at: &str, projection: &Projection) -> Checked {
    ensure(
        projection.headers.len() <= MAX_PROJECTION
            && projection.headers.iter().all(|h| is_token(h)),
        || format!("{at}.response.headers"),
        "at most 32 header names, each a token",
    )?;
    ensure(
        projection.trailers.len() <= MAX_PROJECTION
            && projection.trailers.iter().all(|h| is_token(h)),
        || format!("{at}.response.trailers"),
        "at most 32 trailer names, each a token",
    )?;
    if let Some(BodyProjection::Json(pointers)) = &projection.body {
        ensure(
            !pointers.is_empty()
                && pointers.len() <= MAX_PROJECTION
                && pointers.iter().all(|p| p.is_empty() || p.starts_with('/'))
                && unique(pointers.iter().map(String::as_str)),
            || format!("{at}.response.body"),
            "1 to 32 distinct JSON pointers, each empty or starting with /",
        )?;
    }
    Ok(())
}

impl Policy {
    /// True when the field is secret (an unknown field counts as secret).
    pub fn is_secret(&self, name: &str) -> bool {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .is_none_or(|f| f.secret)
    }

    /// What each name `operation` reads is.
    pub fn kinds<'p>(&'p self, operation: &'p Operation) -> Kinds<'p> {
        Kinds::new(self, operation)
    }

    /// What a name read in `operation` is. An unknown name counts as a secret field.
    pub fn name_kind(&self, operation: &Operation, name: &str) -> NameKind {
        self.kinds(operation).kind(name)
    }

    /// True when the name, a field or a temporary value of `operation`, is secret.
    pub fn is_secret_in(&self, operation: &Operation, name: &str) -> bool {
        match self.name_kind(operation, name) {
            NameKind::SecretField | NameKind::GuessableField | NameKind::SecretTemp => true,
            NameKind::Computed(props) => props.tainted(),
            NameKind::PublicField | NameKind::PublicTemp => false,
        }
    }

    fn is_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }

    /// The operation with this name.
    pub fn operation(&self, name: &str) -> Result<&Operation> {
        self.operations
            .iter()
            .find(|o| o.name == name)
            .ok_or_else(|| Error::OperationUnknown {
                name: name.to_string(),
            })
    }

    /// The caller with this name.
    pub fn caller(&self, name: &str) -> Result<&Caller> {
        self.callers
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::CallerDenied {
                caller: name.to_string(),
                operation: String::new(),
            })
    }

    /// Parses a template, checks its names and variables, and applies the analysis. Returns
    /// the template, and whether its output is tainted.
    fn check_template(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        text: &str,
        known: &[&str],
        var_ok: fn(Var) -> bool,
    ) -> Result<(Template, bool)> {
        self.check_template_in(at, kinds, text, known, var_ok, false)
    }

    /// [`Self::check_template`] for a template rendered on an open TLS connection, after its
    /// handshake (`after_handshake`), where `tls_exporter` has a value; anywhere else it is
    /// refused.
    fn check_template_in(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        text: &str,
        known: &[&str],
        var_ok: fn(Var) -> bool,
        after_handshake: bool,
    ) -> Result<(Template, bool)> {
        let template = self.template_static(at, text, known, var_ok, after_handshake)?;
        let tainted = template
            .analyze(&|name| kinds.kind(name))
            .map_err(|rule| Error::policy(at, rule))?;
        Ok((template, tainted))
    }

    /// Parses a template and checks its names and variables, without the analysis: what an
    /// injection's template needs before its order is known ([`crate::request::Plan`]).
    fn template_static(
        &self,
        at: &str,
        text: &str,
        known: &[&str],
        var_ok: fn(Var) -> bool,
        after_handshake: bool,
    ) -> Result<Template> {
        let template = Template::parse(text).map_err(|e| match e {
            Error::TemplateSyntax { offset } => {
                Error::policy(format!("{at} (byte {offset})"), "template syntax")
            }
            _ => Error::policy(at, "template syntax"),
        })?;
        if !after_handshake && template.calls(crate::template::Func::TlsExporter) {
            return Err(Error::policy(
                at,
                "tls_exporter is available only in the send of a TLS connection",
            ));
        }
        let known_name = |name: &str| self.is_field(name) || known.contains(&name);
        if let Some(name) = template.names().into_iter().find(|n| !known_name(n)) {
            return Err(Error::policy(
                format!("{at} ({name})"),
                "template reads an unknown or later name",
            ));
        }
        if !template.vars().into_iter().all(var_ok) {
            return Err(Error::policy(
                at,
                "template reads a variable not available here",
            ));
        }
        Ok(template)
    }

    fn check_captures<'a>(
        &self,
        at: &str,
        captures: &'a [Capture],
        stream: bool,
        fixed: bool,
        known: &mut Vec<&'a str>,
    ) -> Checked {
        self.check_captures_in(at, captures, stream, fixed, known, &[])
    }

    /// [`Self::check_captures`] inside a loop, where a capture may give a new value to a name
    /// of `rebind` (captured before the loop) with the same secrecy.
    fn check_captures_in<'a>(
        &self,
        at: &str,
        captures: &'a [Capture],
        stream: bool,
        fixed: bool,
        known: &mut Vec<&'a str>,
        rebind: &[(&str, bool)],
    ) -> Checked {
        ensure(
            captures.len() <= MAX_CAPTURES,
            || format!("{at}.capture"),
            "at most 16 captures",
        )?;
        for (i, capture) in captures.iter().enumerate() {
            let at = format!("{at}.capture[{i}]");
            if let Some(rule) = capture.source.rule(stream) {
                return fail(at, rule);
            }
            match &capture.into {
                Store::Field { name } => {
                    ensure(
                        self.is_field(name),
                        || at.clone(),
                        "capture into an unknown field",
                    )?;
                    ensure(
                        self.is_secret(name),
                        || at.clone(),
                        "capture into a public field (a derivation could hand it back)",
                    )?;
                    ensure(
                        fixed,
                        || at.clone(),
                        "capture into a field from a request of the caller",
                    )?;
                }
                Store::Temp { name, secret } => {
                    if rebind.iter().any(|(n, s)| n == name && s == secret) {
                        continue;
                    }
                    ensure(
                        is_token(name) && !self.is_field(name) && !known.contains(&name.as_str()),
                        || at.clone(),
                        "temporary name must be a new token",
                    )?;
                    known.push(name);
                }
            }
        }
        Ok(())
    }

    fn check_identity(&self, at: &str, kinds: &Kinds<'_>, identity: Option<&Identity>) -> Checked {
        if let Some(identity) = identity {
            self.check_template(
                &format!("{at}.identity.cert"),
                kinds,
                &identity.cert,
                &[],
                Var::in_stream,
            )?;
            self.check_template(
                &format!("{at}.identity.key"),
                kinds,
                &identity.key,
                &[],
                Var::in_stream,
            )?;
        }
        Ok(())
    }

    fn check_caller_contract(&self, at: &str, contract: &CallerRequest, send: &Send) -> Checked {
        let at = format!("{at}.request");
        ensure(
            !contract.methods.is_empty(),
            || format!("{at}.methods"),
            "a caller request lists its methods",
        )?;
        ensure(
            !contract.paths.is_empty() && contract.paths.len() <= MAX_PATHS,
            || format!("{at}.paths"),
            "a caller request lists 1 to 32 path templates",
        )?;
        let params: Vec<&str> = send
            .inject
            .iter()
            .filter_map(|i| match &i.target {
                Target::PathParam { name } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        for (i, template) in contract.paths.iter().enumerate() {
            if let Some(rule) = template_fault(template) {
                return fail(format!("{at}.paths[{i}]"), rule);
            }
            let found = placeholders(template);
            let exact = params
                .iter()
                .all(|p| found.iter().filter(|f| *f == p).count() == 1)
                && found.iter().all(|f| params.contains(f));
            ensure(
                exact,
                || format!("{at}.paths[{i}]"),
                "a path template holds each path parameter of the send once, and no other placeholder",
            )?;
        }
        let injected = |kind: fn(&Target) -> Option<&str>| -> Vec<String> {
            send.inject
                .iter()
                .filter_map(|i| kind(&i.target).map(str::to_ascii_lowercase))
                .collect()
        };
        let injected_headers = injected(|t| match t {
            Target::Header { name } => Some(name),
            _ => None,
        });
        let injected_query = injected(|t| match t {
            Target::Query { name } => Some(name),
            _ => None,
        });
        for (i, name) in contract.headers.iter().enumerate() {
            let lower = name.to_ascii_lowercase();
            ensure(
                is_token(name) && !RESERVED_HEADERS.contains(&lower.as_str()),
                || format!("{at}.headers[{i}]"),
                "caller header must be a token and not reserved",
            )?;
            ensure(
                !injected_headers.contains(&lower),
                || format!("{at}.headers[{i}]"),
                "a caller header is also injected",
            )?;
        }
        ensure(
            contract.query.len() <= MAX_QUERY_RULES
                && unique(
                    contract
                        .query
                        .iter()
                        .map(|q| q.name.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .iter()
                        .map(String::as_str),
                ),
            || format!("{at}.query"),
            "at most 32 query parameters, each named once",
        )?;
        for (i, rule) in contract.query.iter().enumerate() {
            let at = format!("{at}.query[{i}]");
            ensure(
                is_query_name(&rule.name),
                || at.clone(),
                "a query name is visible ASCII without & = # + %",
            )?;
            if let Some(fault) = rule.allowed().fault() {
                return fail(at, fault);
            }
            ensure(
                !injected_query.contains(&rule.name.to_ascii_lowercase()),
                || at.clone(),
                "a query parameter the policy injects cannot also come from the caller",
            )?;
            ensure(
                contract.override_params
                    || !RESERVED_PARAMS
                        .iter()
                        .any(|r| r.eq_ignore_ascii_case(&rule.name)),
                || at.clone(),
                "a reserved method-override parameter needs override_params",
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn check_https_send<'a>(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        open: &Open,
        send: &'a Send,
        known: &[&'a str],
    ) -> Checked {
        ensure(
            send.template.is_none(),
            || format!("{at}.template"),
            "an HTTPS send takes request and inject, not template",
        )?;
        let Some(request) = &send.request else {
            return fail(at, "an HTTPS send needs a request");
        };
        ensure(
            send.inject.len() <= MAX_INJECTIONS,
            || format!("{at}.inject"),
            "at most 16 injections",
        )?;
        ensure(
            send.frame.is_none(),
            || format!("{at}.frame"),
            "frame is for the messages of a WebSocket, after its handshake",
        )?;
        ensure(
            send.fill.is_none(),
            || format!("{at}.fill"),
            "fill is for a browser connection, after its handshake",
        )?;
        let methods: Vec<Method> = match request {
            StepRequest::Fixed { method, .. } => vec![*method],
            StepRequest::Caller(contract) => contract.methods.clone(),
        };
        let names_header = |name: &str| {
            send.inject.iter().any(
                |i| matches!(&i.target, Target::Header { name: n } if n.eq_ignore_ascii_case(name)),
            ) || matches!(request, StepRequest::Caller(c)
                if c.headers.iter().any(|h| h.eq_ignore_ascii_case(name)))
        };
        if matches!(open.connection, Connection::Websocket | Connection::Browser) {
            // The opening handshake: a GET with no body.
            ensure(
                !send.grpc
                    && methods.iter().all(|m| *m == Method::Get)
                    && !send.inject.iter().any(|i| i.target == Target::Body),
                || at.to_string(),
                "a WebSocket handshake is a GET with no body and no gRPC",
            )?;
        }
        if send.grpc {
            ensure(
                open.protocol == Some(crate::egress::Versions::Http2)
                    && methods.iter().all(|m| *m == Method::Post)
                    && !names_header("content-type"),
                || format!("{at}.grpc"),
                "a gRPC send needs protocol h2, POST, and sets content-type itself",
            )?;
        }
        match request {
            StepRequest::Fixed {
                path, destination, ..
            } => {
                ensure(
                    path_fault(path, true).is_none(),
                    || format!("{at}.request.path"),
                    "path must start with / and hold no dot segment or encoded separator",
                )?;
                ensure(
                    whole_segment_placeholders(path),
                    || format!("{at}.request.path"),
                    "a path parameter placeholder is a whole path segment, not in the query",
                )?;
                let destinations = &open.destinations;
                match destination {
                    Some(d) => ensure(
                        d.is_concrete() && destinations.iter().any(|p| p.matches(d)),
                        || format!("{at}.request.destination"),
                        "fixed destination must be concrete and one of the connection",
                    )?,
                    None => ensure(
                        destinations.len() == 1
                            && destinations.iter().all(Destination::is_concrete),
                        || format!("{at}.request.destination"),
                        "fixed request needs a destination unless the connection has one concrete destination",
                    )?,
                }
            }
            StepRequest::Caller(contract) => {
                self.check_caller_contract(at, contract, send)?;
                if let Some(body) = &contract.body {
                    let at = format!("{at}.request.body");
                    if let Some(rule) = body.fault() {
                        return fail(at, rule);
                    }
                    // The node sends the body it checked, with the content type it names: a
                    // caller's or an injected content type, an injected body or a gRPC frame
                    // would make the server read another body than the one checked.
                    ensure(
                        open.connection == Connection::Https
                            && !send.grpc
                            && !send.inject.iter().any(|i| i.target == Target::Body)
                            && !names_header("content-type")
                            && !names_header("content-encoding"),
                        || at.clone(),
                        "a body contract is for an HTTPS send that injects no body and sets no content type, content encoding or gRPC frame",
                    )?;
                }
            }
        }
        let mut headers: Vec<String> = Vec::new();
        let mut query: Vec<String> = Vec::new();
        let mut bodies = 0;
        for (i, injection) in send.inject.iter().enumerate() {
            let at = format!("{at}.inject[{i}]");
            match &injection.target {
                Target::Header { name } => {
                    let lower = name.to_ascii_lowercase();
                    ensure(
                        is_token(name)
                            && !RESERVED_HEADERS.contains(&lower.as_str())
                            && !headers.contains(&lower),
                        || at.clone(),
                        "header must be a token, not reserved, and set once",
                    )?;
                    headers.push(lower);
                }
                Target::Query { name } => {
                    let lower = name.to_ascii_lowercase();
                    ensure(
                        is_token(name) && !query.contains(&lower),
                        || at.clone(),
                        "query name must be a token, set once",
                    )?;
                    query.push(lower);
                }
                Target::PathParam { name } => {
                    let placeholder_ok = match request {
                        StepRequest::Fixed { path, .. } => {
                            placeholders(path).iter().filter(|p| **p == name).count() == 1
                        }
                        StepRequest::Caller(_) => true,
                    };
                    ensure(
                        is_token(name) && placeholder_ok,
                        || at.clone(),
                        "path parameter must be a token found once in the path, as a whole segment",
                    )?;
                }
                Target::Body => bodies += 1,
            }
            let template =
                self.template_static(&at, &injection.template, known, Var::in_request, false)?;
            check_components(&at, &template, request, &send.inject)?;
        }
        ensure(bodies <= 1, || format!("{at}.inject"), "at most one body")?;
        // The injections read the request as it is sent: they must have an order, and each is
        // analysed with every component it reads holding what the others put in it.
        let plan = crate::request::Plan::new(&send.inject).map_err(|fault| {
            Error::policy(format!("{at}.inject[{}]", fault.index()), fault.rule())
        })?;
        let props = plan.props(&send.inject, &|n| kinds.kind(n));
        for (i, props) in props.into_iter().enumerate() {
            if let Err(rule) = props {
                return fail(format!("{at}.inject[{i}]"), rule);
            }
        }
        Ok(())
    }

    fn check_return(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        connection: Option<Connection>,
        ret: &Return,
        known: &[&str],
        sent: bool,
    ) -> Checked {
        match connection {
            Some(Connection::Https) => {
                ensure(
                    ret.relay.is_none() && ret.template.is_none(),
                    || at.to_string(),
                    "an HTTPS return takes response only",
                )?;
                ensure(
                    sent,
                    || at.to_string(),
                    "return needs a request sent before it",
                )?;
                if let Some(projection) = &ret.response {
                    check_projection(at, projection)?;
                }
            }
            Some(
                c @ (Connection::Ssh
                | Connection::Postgres
                | Connection::Smtp
                | Connection::Imap
                | Connection::Redis
                | Connection::Mysql
                | Connection::Mqtt
                | Connection::Amqp
                | Connection::Amqp1
                | Connection::Ftp
                | Connection::Pop3),
            ) => {
                ensure(
                    ret.response.is_none() && ret.template.is_none(),
                    || at.to_string(),
                    "a protocol connection's return takes relay only",
                )?;
                if let Some(relay) = &ret.relay {
                    self.check_proto_relay(at, kinds, c, relay, known)?;
                }
            }
            Some(Connection::Tls | Connection::Udp | Connection::Dtls) => {
                ensure(
                    ret.response.is_none() && ret.template.is_none(),
                    || at.to_string(),
                    "a TLS or UDP return takes relay only",
                )?;
                if let Some(relay) = &ret.relay {
                    ensure(
                        relay.frames.is_empty()
                            && !relay.server
                            && relay.commands.is_empty()
                            && relay.mail.is_none(),
                        || format!("{at}.relay"),
                        "frames and server are for a WebSocket",
                    )?;
                    ensure(
                        !relay.sends.is_empty()
                            && relay.sends.len() <= MAX_RELAY_PATTERNS
                            && relay
                                .sends
                                .iter()
                                .all(|p| crate::extract::compile_whole(p).is_some()),
                        || format!("{at}.relay.sends"),
                        "1 to 16 regular expressions of at most 256 bytes within the size limits",
                    )?;
                }
            }
            Some(Connection::Browser) => {
                // The caller gets the outcome and the final origin, never anything of the
                // page, and sends no CDP command of its own.
                ensure(
                    ret.response.is_none() && ret.template.is_none() && ret.relay.is_none(),
                    || at.to_string(),
                    "a browser return takes nothing: the outcome goes back, never the page",
                )?;
                ensure(
                    sent,
                    || at.to_string(),
                    "return needs the handshake and a fill before it",
                )?;
            }
            Some(Connection::Websocket) => {
                ensure(
                    ret.response.is_none() && ret.template.is_none(),
                    || at.to_string(),
                    "a WebSocket return takes relay only",
                )?;
                ensure(
                    sent,
                    || at.to_string(),
                    "return needs the handshake before it",
                )?;
                let Some(relay) = &ret.relay else {
                    return Ok(());
                };
                ensure(
                    relay.sends.is_empty()
                        && relay.commands.is_empty()
                        && relay.mail.is_none()
                        && relay.frames.len() <= MAX_RELAY_PATTERNS,
                    || format!("{at}.relay"),
                    "a WebSocket relays frames (at most 16 rules), not sends",
                )?;
                for (i, rule) in relay.frames.iter().enumerate() {
                    let at = format!("{at}.relay.frames[{i}]");
                    if let Some(rule) = rule.shape.as_ref().and_then(Input::fault) {
                        return fail(format!("{at}.shape"), rule);
                    }
                    if let Some(text) = &rule.template {
                        let at = format!("{at}.template");
                        let (template, _) =
                            self.check_template(&at, kinds, text, known, Var::in_frame)?;
                        ensure(
                            !template.vars().contains(&Var::Input) || rule.shape.is_some(),
                            || at,
                            "a frame template that reads $input needs a shape",
                        )?;
                    }
                }
            }
            None => {
                ensure(
                    ret.response.is_none() && ret.relay.is_none(),
                    || at.to_string(),
                    "a return with no connection takes template only",
                )?;
                let Some(text) = &ret.template else {
                    return fail(at, "a return with no connection needs a template");
                };
                let at = format!("{at}.template");
                let (template, tainted) =
                    self.check_template(&at, kinds, text, known, Var::in_derive)?;
                ensure(
                    !tainted,
                    || at.clone(),
                    "a derivation would hand a secret back",
                )?;
                ensure(
                    !template.guessable(&|name| kinds.kind(name)),
                    || at,
                    "a derivation would hand back a check for guesses of a guessable field",
                )?;
            }
        }
        Ok(())
    }

    fn check_operation(&self, at: &str, operation: &Operation) -> Checked {
        ensure(
            is_token(&operation.name),
            || format!("{at}.name"),
            "name is not a token",
        )?;
        ensure(
            !operation.steps.is_empty() && operation.steps.len() <= MAX_STEPS,
            || format!("{at}.steps"),
            "1 to 64 steps",
        )?;
        let open = operation.open();
        let connection = open.map(|o| o.connection);
        if let Some(input) = &operation.input {
            ensure(
                connection.is_none(),
                || format!("{at}.input"),
                "an input schema is for an operation with no connection",
            )?;
            if let Some(rule) = input.fault() {
                return fail(format!("{at}.input"), rule);
            }
        }
        let kinds = self.kinds(operation);
        let scope = flow::Scope::new(self, &kinds, operation, open);
        let streamed = operation.returns().is_some_and(|r| {
            r.response
                .as_ref()
                .is_some_and(|p| p.body == Some(BodyProjection::Stream))
        });
        let mut known: Vec<&str> = Vec::new();
        let mut sends = 0usize;
        // The HTTPS requests every run makes before `return` (a branch may skip some).
        let mut surely = 0usize;
        let mut polls = 0usize;
        let mut awaits = 0usize;
        let mut fills = 0usize;
        let count = operation.steps.len();
        for (i, step) in operation.steps.iter().enumerate() {
            let at = format!("{at}.steps[{i}]");
            let previous = i.checked_sub(1).and_then(|p| operation.steps.get(p));
            match (step, open) {
                (Step::Open(open), _) => {
                    ensure(
                        i == 0,
                        || at.clone(),
                        "open is the first step; an operation opens one connection",
                    )?;
                    check_destinations(&at, &open.destinations)?;
                    self.check_identity(&at, &kinds, open.identity.as_ref())?;
                    ensure(
                        open.connection != Connection::Udp
                            || (open.identity.is_none()
                                && open.protocol.is_none()
                                && open.limits.is_none()),
                        || at.clone(),
                        "a UDP connection takes no identity, protocol or limits",
                    )?;
                    ensure(
                        open.connection != Connection::Dtls
                            || (open.identity.is_none()
                                && open.protocol.is_none()
                                && open.limits.is_none()),
                        || at.clone(),
                        "a DTLS connection takes no identity, protocol or limits",
                    )?;
                    check_pins(&at, open)?;
                    check_intermediates(&at, open)?;
                    ensure(
                        open.protocol.is_none() || open.connection == Connection::Https,
                        || format!("{at}.protocol"),
                        "protocol is for an HTTPS connection (a WebSocket handshake is HTTP/1.1)",
                    )?;
                    if open.connection.is_protocol() {
                        self.check_proto_open(&at, &kinds, open)?;
                    } else {
                        ensure(
                            open.login.is_none() && open.host_keys.is_empty() && open.tls.is_none(),
                            || at.clone(),
                            "login, host_keys and tls are for protocol connections",
                        )?;
                    }
                    let streams = open.connection == Connection::Websocket
                        || open.connection.is_protocol()
                        || operation.returns().is_some_and(|r| {
                            r.response
                                .as_ref()
                                .is_some_and(|p| p.body == Some(BodyProjection::Stream))
                        });
                    let streams = streams || open.connection == Connection::Browser;
                    ensure(
                        open.limits.is_none() || streams,
                        || format!("{at}.limits"),
                        "limits are for a WebSocket, a browser, a streamed response or a protocol connection",
                    )?;
                    if let Some(rule) = open.limits.as_ref().and_then(StreamLimits::fault) {
                        return fail(format!("{at}.limits"), rule);
                    }
                    browser::check_control(&at, open.connection, open.browser.as_ref())?;
                    if open.connection == Connection::Browser
                        && let Some(limits) = &open.limits
                    {
                        browser::check_browser_limits(&at, limits)?;
                    }
                }
                (Step::Send(_) | Step::Receive(_), None) => {
                    return fail(at, "send and receive need an open connection");
                }
                (Step::Send(send), Some(open)) if open.connection.is_protocol() => {
                    sends += 1;
                    ensure(sends <= MAX_REQUESTS, || at.clone(), "at most 8 sends")?;
                    self.check_proto_send(&at, &kinds, open.connection, send, &known)?;
                }
                (Step::Send(send), Some(_)) if send.command.is_some() => {
                    return fail(at, "command is for a protocol connection");
                }
                (Step::Receive(receive), Some(open)) if open.connection.is_protocol() => {
                    ensure(
                        matches!(previous, Some(Step::Send(_))),
                        || at.clone(),
                        "a receive follows the send whose result it reads",
                    )?;
                    ensure(
                        receive.until.is_empty(),
                        || format!("{at}.until"),
                        "a protocol receive reads the result of its command; until is for TLS streams",
                    )?;
                    self.check_captures(&at, &receive.capture, true, true, &mut known)?;
                }
                (Step::Send(send), Some(open)) => match open.connection {
                    Connection::Https => {
                        sends += 1;
                        surely += 1;
                        ensure(
                            sends + polls <= MAX_REQUESTS,
                            || at.clone(),
                            "at most 8 requests",
                        )?;
                        self.check_https_send(&at, &kinds, open, send, &known)?;
                    }
                    Connection::Websocket | Connection::Browser if sends == 0 => {
                        sends += 1;
                        self.check_https_send(&at, &kinds, open, send, &known)?;
                    }
                    Connection::Browser => {
                        fills += 1;
                        ensure(fills <= MAX_FILLS, || at.clone(), "at most 8 fills")?;
                        ensure(
                            send.request.is_none()
                                && send.inject.is_empty()
                                && send.template.is_none()
                                && !send.grpc
                                && send.frame.is_none(),
                            || at.clone(),
                            "a browser send after the handshake takes fill only",
                        )?;
                        let Some(fill) = &send.fill else {
                            return fail(at, "a browser send after the handshake needs a fill");
                        };
                        self.check_fill(&format!("{at}.fill"), &kinds, fill, &known)?;
                    }
                    Connection::Websocket => {
                        ensure(
                            send.request.is_none()
                                && send.inject.is_empty()
                                && !send.grpc
                                && send.fill.is_none()
                                && send.frame.is_some(),
                            || at.clone(),
                            "a WebSocket send after the handshake takes frame and template",
                        )?;
                        let Some(template) = &send.template else {
                            return fail(at, "a WebSocket send needs a template");
                        };
                        self.check_template(
                            &format!("{at}.template"),
                            &kinds,
                            template,
                            &known,
                            Var::in_stream,
                        )?;
                    }
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
                    | Connection::Pop3 => {
                        return fail(at, "a send on a protocol connection takes command only");
                    }
                    Connection::Tls => {
                        ensure(
                            send.request.is_none()
                                && send.inject.is_empty()
                                && !send.grpc
                                && send.fill.is_none()
                                && send.frame.is_none(),
                            || at.clone(),
                            "a TLS send takes template only",
                        )?;
                        let Some(template) = &send.template else {
                            return fail(at, "a TLS send needs a template");
                        };
                        self.check_template_in(
                            &format!("{at}.template"),
                            &kinds,
                            template,
                            &known,
                            Var::in_stream,
                            true,
                        )?;
                    }
                    Connection::Udp => {
                        ensure(
                            send.request.is_none()
                                && send.inject.is_empty()
                                && !send.grpc
                                && send.fill.is_none()
                                && send.frame.is_none(),
                            || at.clone(),
                            "a UDP send takes template only",
                        )?;
                        let Some(template) = &send.template else {
                            return fail(at, "a UDP send needs a template");
                        };
                        let (parsed, tainted) = self.check_template(
                            &format!("{at}.template"),
                            &kinds,
                            template,
                            &known,
                            Var::in_stream,
                        )?;
                        // A datagram crosses the network, and the host of an enclave, in
                        // clear: a secret may reach it only through a one-way function, and
                        // a guessable one not at all (a MAC of it is a test for each guess).
                        ensure(
                            !tainted,
                            || format!("{at}.template"),
                            "a UDP datagram is sent in clear: it may not hold a secret in reversible form",
                        )?;
                        ensure(
                            !parsed.guessable(&|name| kinds.kind(name)),
                            || format!("{at}.template"),
                            "a UDP datagram is sent in clear: it may not depend on a guessable secret",
                        )?;
                    }
                    Connection::Dtls => {
                        ensure(
                            send.request.is_none()
                                && send.inject.is_empty()
                                && !send.grpc
                                && send.fill.is_none()
                                && send.frame.is_none(),
                            || at.clone(),
                            "a DTLS send takes template only",
                        )?;
                        let Some(template) = &send.template else {
                            return fail(at, "a DTLS send needs a template");
                        };
                        // A record is encrypted to the server whose certificate the
                        // handshake checked, as a TLS write is; no exporter is offered.
                        self.check_template(
                            &format!("{at}.template"),
                            &kinds,
                            template,
                            &known,
                            Var::in_stream,
                        )?;
                    }
                },
                (Step::Receive(receive), Some(open)) => match open.connection {
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
                    | Connection::Pop3 => {
                        return fail(at, "a protocol receive follows its send");
                    }
                    Connection::Https => {
                        let fixed = match previous {
                            Some(Step::Send(send)) => {
                                matches!(send.request, Some(StepRequest::Fixed { .. }))
                            }
                            _ => return fail(at, "an HTTPS receive follows its send"),
                        };
                        ensure(
                            receive.until.is_empty(),
                            || format!("{at}.until"),
                            "an HTTPS receive reads the whole response; until is for streams",
                        )?;
                        self.check_captures(&at, &receive.capture, false, fixed, &mut known)?;
                    }
                    Connection::Tls => {
                        ensure(
                            !receive.until.is_empty()
                                && receive.until.len() <= MAX_DELIMITERS
                                && receive
                                    .until
                                    .iter()
                                    .all(|u| !u.is_empty() && u.len() <= MAX_DELIMITER),
                            || format!("{at}.until"),
                            "1 to 8 delimiters of 1 to 256 bytes",
                        )?;
                        self.check_captures(&at, &receive.capture, true, true, &mut known)?;
                    }
                    Connection::Udp => {
                        ensure(
                            receive.until.is_empty(),
                            || format!("{at}.until"),
                            "a UDP receive reads one datagram; until is for TLS streams",
                        )?;
                        self.check_captures(&at, &receive.capture, true, true, &mut known)?;
                    }
                    Connection::Dtls => {
                        ensure(
                            receive.until.is_empty(),
                            || format!("{at}.until"),
                            "a DTLS receive reads one record; until is for TLS streams",
                        )?;
                        self.check_captures(&at, &receive.capture, true, true, &mut known)?;
                    }
                    Connection::Browser => {
                        return fail(
                            at,
                            "a browser connection reads nothing from the page: no receive",
                        );
                    }
                    Connection::Websocket => {
                        ensure(
                            receive.until.is_empty(),
                            || format!("{at}.until"),
                            "a WebSocket receive reads one message; until is for TLS streams",
                        )?;
                        // Right after the handshake, a receive reads its answer; later, the
                        // next message.
                        let handshake = match previous {
                            Some(Step::Send(send)) if send.request.is_some() => {
                                Some(matches!(send.request, Some(StepRequest::Fixed { .. })))
                            }
                            _ => None,
                        };
                        match handshake {
                            Some(fixed) => self.check_captures(
                                &at,
                                &receive.capture,
                                false,
                                fixed,
                                &mut known,
                            )?,
                            None => {
                                ensure(
                                    sends > 0,
                                    || at.clone(),
                                    "a WebSocket receive follows the handshake",
                                )?;
                                self.check_captures(&at, &receive.capture, true, true, &mut known)?
                            }
                        }
                    }
                },
                (Step::Compute(compute), _) => {
                    ensure(
                        is_token(&compute.into)
                            && !self.is_field(&compute.into)
                            && !known.contains(&compute.into.as_str()),
                        || format!("{at}.into"),
                        "compute into a new token name",
                    )?;
                    let var_ok = if connection.is_none() {
                        Var::in_derive
                    } else {
                        Var::in_compute
                    };
                    self.check_template(
                        &format!("{at}.template"),
                        &kinds,
                        &compute.template,
                        &known,
                        var_ok,
                    )?;
                    known.push(&compute.into);
                }
                (Step::Run(run), _) => {
                    ensure(
                        connection != Some(Connection::Websocket)
                            && !connection.is_some_and(Connection::is_protocol)
                            && connection != Some(Connection::Browser),
                        || at.clone(),
                        "run is not available on a WebSocket, a protocol connection or a browser",
                    )?;
                    self.check_run(&at, &kinds, open, run, &known)?;
                    known.push(&run.into);
                }
                (Step::Return(ret), _) => {
                    ensure(i + 1 == count, || at.clone(), "return is the last step")?;
                    let sent = match connection {
                        Some(Connection::Browser) => fills > 0,
                        Some(Connection::Https) => surely > 0,
                        _ => sends > 0,
                    };
                    self.check_return(&at, &kinds, connection, ret, &known, sent)?;
                    let streamed = ret
                        .response
                        .as_ref()
                        .is_some_and(|p| p.body == Some(BodyProjection::Stream));
                    if streamed {
                        // The response streamed is the one of the send just before.
                        ensure(
                            matches!(previous, Some(Step::Send(send)) if !send.grpc),
                            || at.clone(),
                            "a streamed body comes from the send just before return (not gRPC)",
                        )?;
                    }
                }
                (Step::Repeat(_) | Step::If(_), _) => {
                    ensure(
                        matches!(connection, None | Some(Connection::Https)),
                        || at.clone(),
                        "loops and branches are for HTTPS and operations with no connection",
                    )?;
                    ensure(
                        operation.payment.is_none(),
                        || at.clone(),
                        "an operation that pays has no loop or branch: its payment goes out once, to the merchant the approval names",
                    )?;
                    ensure(
                        !streamed,
                        || at.clone(),
                        "an operation whose response streams has no loop or branch",
                    )?;
                    let requests = self.check_flow(&at, &scope, step, &mut known, &[], 1)?;
                    let most = usize::try_from(requests.most).unwrap_or(usize::MAX);
                    let least = usize::try_from(requests.least).unwrap_or(usize::MAX);
                    sends = sends.saturating_add(most);
                    surely = surely.saturating_add(least);
                    ensure(
                        sends.saturating_add(polls) <= MAX_REQUESTS,
                        || at.clone(),
                        "at most 8 requests, a loop's counted as often as it may run",
                    )?;
                }
                (Step::Await(wait), _) => {
                    awaits += 1;
                    ensure(awaits <= MAX_AWAITS, || at.clone(), "at most 4 await steps")?;
                    ensure(
                        connection != Some(Connection::Websocket)
                            && connection != Some(Connection::Browser),
                        || at.clone(),
                        "a WebSocket or a browser does not wait; await is for HTTPS and derivations",
                    )?;
                    if connection == Some(Connection::Tls) {
                        // On TLS the node connects only after the awaits that directly follow
                        // `open`: nothing reaches the site, and no connection is held, while
                        // the operation waits.
                        let leading = operation.steps.get(1..i).is_some_and(|before| {
                            before.iter().all(|s| matches!(s, Step::Await(_)))
                        });
                        ensure(
                            leading && wait.challenge.kind != ChallengeKind::External,
                            || at.clone(),
                            "on TLS, await waits for a code before the connection opens: only directly after open, before any other step",
                        )?;
                    }
                    if wait.challenge.poll.is_some() {
                        polls += 1;
                        ensure(
                            sends + polls <= MAX_REQUESTS,
                            || at.clone(),
                            "at most 8 requests",
                        )?;
                    }
                    self.check_await(&at, &kinds, open, wait, &mut known)?;
                }
            }
        }
        // One caller request goes to every send that takes it: its body is checked and written
        // again once, by the one body contract they all declare.
        let bodies: Vec<Option<&BodyContract>> = operation
            .caller_sends()
            .map(|(contract, _)| contract.body.as_ref())
            .collect();
        ensure(
            bodies.iter().all(|b| Some(b) == bodies.first()),
            || format!("{at}.steps"),
            "the sends that take the caller's request declare the same body contract, or none",
        )?;
        if operation.streams() {
            // A waiting operation is resumed by a call of its own, after the streaming call
            // that started it ended: there is no caller connection left to relay on.
            let kind_waits = self
                .item
                .as_ref()
                .and_then(|b| b.schema().ok())
                .is_some_and(|k| k.shape.approval);
            ensure(
                !operation.approval && operation.payment.is_none() && !kind_waits,
                || at.to_string(),
                "an operation that streams does not wait for the owner's approval: no approval, no payment, no item kind that waits for approval",
            )?;
        }
        if let Some(payment) = &operation.payment {
            self.check_payment(&format!("{at}.payment"), operation, payment)?;
        }
        if let Some(vend) = &operation.vend {
            vend::check(&format!("{at}.vend"), operation, vend)?;
        }
        ensure(
            operation.returns().is_some(),
            || format!("{at}.steps"),
            "an operation ends with return",
        )?;
        flow::check_definitions(at, operation)?;
        run::check_confined(at, operation)?;
        // A protocol parameter over the caller's value reads that value as `$input`, not the
        // operation's input.
        let per_value: Vec<&str> = operation
            .returns()
            .and_then(|r| r.relay.as_ref())
            .map(|r| {
                r.commands
                    .iter()
                    .flat_map(|c| c.params.iter())
                    .filter(|p| p.pattern.is_some())
                    .filter_map(|p| p.template.as_deref())
                    .collect()
            })
            .unwrap_or_default();
        let reads_input = operation
            .templates()
            .into_iter()
            .filter(|t| !per_value.iter().any(|v| core::ptr::eq(*v, *t)))
            .any(|t| Template::parse(t).is_ok_and(|t| t.vars().contains(&Var::Input)));
        ensure(
            !reads_input || operation.input.is_some(),
            || format!("{at}.input"),
            "an operation that reads $input declares its input",
        )
    }

    fn check_await<'a>(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        open: Option<&Open>,
        wait: &'a Await,
        known: &mut Vec<&'a str>,
    ) -> Checked {
        let at = format!("{at}.challenge");
        let challenge = &wait.challenge;
        ensure(
            open.is_none_or(|o| matches!(o.connection, Connection::Https | Connection::Tls)),
            || at.clone(),
            "await is for HTTPS, TLS before the connection opens, and operations with no connection: any other connection would stay open while it waits",
        )?;
        ensure(
            wait::is_plain_text(&challenge.hint, MAX_HINT),
            || format!("{at}.hint"),
            "a hint is 1 to 256 bytes without control characters",
        )?;
        ensure(
            (1000..=MAX_WAIT_MS).contains(&challenge.timeout()),
            || format!("{at}.timeout_ms"),
            "an operation waits 1 second to 5 minutes",
        )?;
        if challenge.kind == ChallengeKind::External {
            ensure(
                challenge.into.is_none() && challenge.pattern.is_none(),
                || at.clone(),
                "an external challenge carries no code: no into or pattern",
            )?;
            let (Some(open), Some(poll)) = (open, &challenge.poll) else {
                return fail(at, "an external challenge polls the site over HTTPS");
            };
            ensure(
                (MIN_POLL_MS..=challenge.timeout()).contains(&poll.every_ms),
                || format!("{at}.poll.every_ms"),
                "a poll waits at least 1 second, and at most the timeout",
            )?;
            ensure(
                poll.fixed().is_some(),
                || format!("{at}.poll.send"),
                "a poll sends a request the policy fixes",
            )?;
            self.check_https_send(&format!("{at}.poll.send"), kinds, open, &poll.send, known)?;
            if let Some(rule) = poll.success.fault() {
                return fail(format!("{at}.poll.success"), rule);
            }
            if let Some(rule) = poll.failure.as_ref().and_then(Condition::fault) {
                return fail(format!("{at}.poll.failure"), rule);
            }
            return Ok(());
        }
        ensure(
            challenge.poll.is_none(),
            || format!("{at}.poll"),
            "a code challenge does not poll",
        )?;
        let Some(into) = &challenge.into else {
            return fail(at, "a code challenge names the value it goes into");
        };
        ensure(
            is_token(into) && !self.is_field(into) && !known.contains(&into.as_str()),
            || format!("{at}.into"),
            "a code goes into a new token name",
        )?;
        ensure(
            crate::extract::compile_whole(challenge.code_pattern()).is_some(),
            || format!("{at}.pattern"),
            "a regular expression of at most 256 bytes within the size limits",
        )?;
        known.push(into);
        Ok(())
    }

    fn check_payment(&self, at: &str, operation: &Operation, payment: &Payment) -> Checked {
        ensure(
            wait::is_currency(&payment.currency),
            || format!("{at}.currency"),
            "an ISO 4217 code: three uppercase letters",
        )?;
        ensure(
            payment.exponent <= MAX_EXPONENT,
            || format!("{at}.exponent"),
            "at most 8 digits after the decimal point",
        )?;
        let limit = MAX_AMOUNT.to_string();
        let bounded = |min: Option<&str>, max: Option<&str>| {
            min.is_some_and(|m| contract::is_decimal(m) && !m.starts_with('-'))
                && max.is_some_and(|m| {
                    contract::is_decimal(m)
                        && !m.starts_with('-')
                        && contract::compare_decimal(m, &limit) != core::cmp::Ordering::Greater
                })
        };
        let at = format!("{at}.amount");
        let from_request = matches!(
            payment.amount,
            AmountSource::Query { .. } | AmountSource::Body { .. } | AmountSource::Form { .. }
        );
        if from_request {
            // The caller's request, and the amount in it, goes out once.
            ensure(
                operation.caller_sends().count() == 1,
                || at.clone(),
                "an amount read from the caller's request needs exactly one send of the caller's request",
            )?;
        }
        let body = operation
            .caller_sends()
            .next()
            .and_then(|(contract, _)| contract.body.as_ref());
        match &payment.amount {
            AmountSource::Body {
                pointer,
                format,
                currency_at,
            } => {
                let Some(BodyContract::Json(schema)) = body else {
                    return fail(
                        at,
                        "an amount from the body needs a JSON body contract on the caller's request",
                    );
                };
                let member = schema
                    .member(pointer)
                    .filter(|m| !m.optional && m.set.is_none());
                let ruled = member.is_some_and(|m| match format {
                    AmountFormat::Minor => {
                        let most = match m.kind {
                            Some(JsonType::Number) => MAX_JSON_NUMBER_AMOUNT.to_string(),
                            _ => limit.clone(),
                        };
                        matches!(m.kind, Some(JsonType::Number | JsonType::String))
                            && m.min.as_deref().is_some_and(|v| bounded(Some(v), Some(v)))
                            && m.max.as_deref().is_some_and(|v| {
                                bounded(Some(v), Some(v))
                                    && contract::compare_decimal(v, &most)
                                        != core::cmp::Ordering::Greater
                            })
                    }
                    AmountFormat::Decimal => {
                        m.kind == Some(JsonType::String) && m.allowed().is_any()
                    }
                });
                ensure(
                    ruled,
                    || at.clone(),
                    "the amount is a required member of the JSON body contract: of minor units, a number (at most 2^53 - 1) or string with min (at least 0) and max (at most 10^18); as a decimal, a string with no other rule",
                )?;
                let currency = |p: &str| {
                    schema.member(p).is_some_and(|m| {
                        !m.optional && m.equals.as_deref() == Some(payment.currency.as_str())
                    })
                };
                let mentions: Vec<&str> = schema
                    .members
                    .iter()
                    .map(|m| m.pointer.as_str())
                    .filter(|p| p.to_ascii_lowercase().contains("currency"))
                    .collect();
                self.check_body_currency(&at, currency_at.as_deref(), &mentions, currency)?;
                // No member the caller fills freely with structure: the amount read is then
                // the only one the body can carry.
                ensure(
                    !schema.members.iter().any(Member::is_open),
                    || at.clone(),
                    "a body that pays declares every member with a type or a rule, so it carries no amount but the one the node reads",
                )
            }
            AmountSource::Form {
                name,
                format,
                currency_at,
            } => {
                let Some(BodyContract::Form(form)) = body else {
                    return fail(
                        at,
                        "an amount from a form field needs a form body contract on the caller's request",
                    );
                };
                let field = form.fields.iter().find(|f| f.name == *name && f.required);
                let ruled = field.is_some_and(|f| match format {
                    AmountFormat::Minor => bounded(f.min.as_deref(), f.max.as_deref()),
                    AmountFormat::Decimal => f.allowed().is_any(),
                });
                ensure(
                    ruled,
                    || at.clone(),
                    "the amount is a required field of the form body contract: of minor units with min (at least 0) and max (at most 10^18), or as a decimal with no other rule",
                )?;
                let currency = |n: &str| {
                    form.fields.iter().any(|f| {
                        f.name == n
                            && f.required
                            && f.equals.as_deref() == Some(payment.currency.as_str())
                    })
                };
                let mentions: Vec<&str> = form
                    .fields
                    .iter()
                    .map(|f| f.name.as_str())
                    .filter(|n| n.to_ascii_lowercase().contains("currency"))
                    .collect();
                self.check_body_currency(&at, currency_at.as_deref(), &mentions, currency)
            }
            AmountSource::Query { name } => {
                let ruled = operation.caller_sends().any(|(contract, _)| {
                    contract.query.iter().any(|q| {
                        q.name == *name && q.required && bounded(q.min.as_deref(), q.max.as_deref())
                    })
                });
                ensure(
                    operation.connection() == Some(Connection::Https) && ruled,
                    || at.clone(),
                    "the amount is a required query parameter of the caller's request with min (at least 0) and max (at most 10^18)",
                )?;
                let unfixed = operation.caller_sends().any(|(contract, _)| {
                    contract.query.iter().any(|q| {
                        q.name.to_ascii_lowercase().contains("currency")
                            && !(q.required
                                && q.equals.as_deref() == Some(payment.currency.as_str()))
                    })
                });
                ensure(
                    !unfixed,
                    || at.clone(),
                    "a query parameter named for a currency is required and equals the payment's currency",
                )
            }
            AmountSource::Input { pointer } => {
                let ruled = match &operation.input {
                    Some(Input::Json(schema)) => schema.members.iter().any(|m| {
                        m.pointer == *pointer
                            && !m.optional
                            && m.set.is_none()
                            && m.kind == Some(JsonType::Number)
                            && bounded(m.min.as_deref(), m.max.as_deref())
                    }),
                    _ => false,
                };
                ensure(
                    ruled,
                    || at,
                    "the amount is a required number of the JSON input with min (at least 0) and max (at most 10^18)",
                )
            }
            AmountSource::Fixed { value } => ensure(
                bounded(Some(value), Some(value)),
                || at,
                "a fixed amount is a decimal integer from 0 to 10^18",
            ),
        }
    }

    /// The currency a paying body carries is the payment's: the member or field `currency_at`
    /// names, and every one whose name holds `currency`, is fixed to it by the contract.
    fn check_body_currency(
        &self,
        at: &str,
        currency_at: Option<&str>,
        mentions: &[&str],
        fixed: impl Fn(&str) -> bool,
    ) -> Checked {
        ensure(
            currency_at.is_none_or(&fixed) && mentions.iter().all(|m| fixed(m)),
            || at.to_string(),
            "the currency in a paying body (currency_at, and every member or field named for a currency) is required and equals the payment's currency",
        )
    }

    fn check_sessions(&self) -> Checked {
        for (i, field) in self.fields.iter().enumerate() {
            let Some(rule) = &field.session else {
                continue;
            };
            let at = format!("fields[{i}].session");
            if let Some(fault) = rule.fault() {
                return fail(at, fault);
            }
            ensure(field.secret, || at.clone(), "a session is a secret field")?;
            let expires = self.fields.iter().find(|f| f.name == rule.expires);
            ensure(
                expires.is_some_and(|e| !e.secret && e.optional && e.session.is_none()),
                || format!("{at}.expires"),
                "the expiry goes into another field of the policy, public and optional",
            )?;
            if let Renew::Operation { name } = &rule.renew {
                let at = format!("{at}.renew");
                let Ok(operation) = self.operation(name) else {
                    return fail(at, "renew names an operation of the policy");
                };
                ensure(
                    operation.connection() == Some(Connection::Https)
                        && !operation.takes_request()
                        && !operation.parks()
                        && operation.payment.is_none()
                        && !operation.approval,
                    || at.clone(),
                    "a renewal is an HTTPS operation of fixed requests, without await, payment or approval",
                )?;
                ensure(
                    flow::sure_field_captures(&operation.steps).contains(&field.name.as_str())
                        && !operation.field_reads(self).contains(&field.name),
                    || at.clone(),
                    "a renewal fills the session field from a response and does not read it",
                )?;
            }
        }
        Ok(())
    }

    fn check_callers(&self) -> Checked {
        ensure(
            !self.callers.is_empty() && self.callers.len() <= MAX_CALLERS,
            || "callers".into(),
            "1 to 32 callers",
        )?;
        ensure(
            unique(self.callers.iter().map(|c| c.name.as_str())),
            || "callers".into(),
            "caller names must be unique",
        )?;
        for (i, caller) in self.callers.iter().enumerate() {
            let at = format!("callers[{i}]");
            ensure(
                is_token(&caller.name),
                || format!("{at}.name"),
                "name is not a token",
            )?;
            let unknown = caller
                .operations
                .iter()
                .find(|o| self.operation(o).is_err());
            ensure(
                !caller.operations.is_empty()
                    && unknown.is_none()
                    && unique(caller.operations.iter().map(String::as_str)),
                || match unknown {
                    Some(name) => format!("{at}.operations ({name})"),
                    None => format!("{at}.operations"),
                },
                "operations must be names of operations, each once",
            )?;
            if let Some(limit) = caller.limit {
                ensure(
                    limit.count > 0 && limit.count <= 1_000_000 && limit.window_ms > 0,
                    || format!("{at}.limit"),
                    "limit needs a count of 1 to 1000000 and a window",
                )?;
            }
        }
        Ok(())
    }

    /// Checks the rules of the policy, including every template and the taint of derivations.
    pub fn validate(&self) -> Result<()> {
        ensure(
            !self.fields.is_empty() && self.fields.len() <= crate::fields::MAX_FIELDS,
            || "fields".into(),
            "1 to 32 fields",
        )?;
        for (i, field) in self.fields.iter().enumerate() {
            ensure(
                is_token(&field.name),
                || format!("fields[{i}].name"),
                "name is not a token",
            )?;
            ensure(
                field.secret || !field.guessable,
                || format!("fields[{i}]"),
                "only a secret field can be guessable",
            )?;
        }
        ensure(
            unique(self.fields.iter().map(|f| f.name.as_str())),
            || "fields".into(),
            "field names must be unique",
        )?;
        ensure(
            !self.operations.is_empty() && self.operations.len() <= MAX_OPERATIONS,
            || "operations".into(),
            "1 to 16 operations",
        )?;
        ensure(
            unique(self.operations.iter().map(Operation::name)),
            || "operations".into(),
            "operation names must be unique",
        )?;
        for (i, operation) in self.operations.iter().enumerate() {
            self.check_operation(&format!("operations[{i}]"), operation)?;
        }
        self.check_sessions()?;
        self.check_callers()?;
        match &self.item {
            Some(binding) => crate::item::check_policy(self, binding),
            None => Ok(()),
        }
    }

    /// What the policy allows, in plain lines, for the owner to read before signing. Lines
    /// that start with `  !` flag what widens what a caller can do or see.
    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        for field in &self.fields {
            out.push(format!(
                "field {}: {}{}{}",
                field.name,
                if field.secret { "secret" } else { "public" },
                if field.guessable { ", guessable" } else { "" },
                if field.optional { ", optional" } else { "" }
            ));
            if let Some(rule) = &field.session {
                out.push(format!(
                    "  session: lasts {} ms (expiry in {}), renewed {}",
                    rule.lifetime_ms,
                    rule.expires,
                    match &rule.renew {
                        Renew::Operation { name } => format!("by the operation {name}"),
                        Renew::Owner {} => "by the owner on the device".into(),
                    }
                ));
            }
        }
        for operation in &self.operations {
            summarize_operation(operation, &mut out);
        }
        for caller in &self.callers {
            out.push(format!(
                "caller {} ({}): {}{}",
                caller.name,
                caller.key.to_b64(),
                caller.operations.join(", "),
                caller
                    .limit
                    .map(|l| format!(", at most {} per {} ms", l.count, l.window_ms))
                    .unwrap_or_default()
            ));
        }
        out
    }
}

fn destination_names(destinations: &[Destination]) -> String {
    destinations
        .iter()
        .map(|d| format!("{}:{}", d.host, d.port))
        .collect::<Vec<_>>()
        .join(", ")
}

fn summarize_send(send: &Send, out: &mut Vec<String>) {
    if let Some(command) = &send.command {
        out.push(format!(
            "  send command {:?}{}",
            command.text,
            if command.params.is_empty() {
                String::new()
            } else {
                format!(" with parameters {:?}", command.params)
            }
        ));
        return;
    }
    let injects = send
        .inject
        .iter()
        .map(|i| match &i.target {
            Target::Header { name } => format!("header {name}"),
            Target::Query { name } => format!("query {name}"),
            Target::PathParam { name } => format!("path {{{name}}}"),
            Target::Body => "body".into(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    let injects = if injects.is_empty() {
        String::new()
    } else {
        format!("; injects {injects}")
    };
    match &send.request {
        Some(StepRequest::Fixed {
            method,
            path,
            destination,
        }) => out.push(format!(
            "  send {} {path}{}{injects}",
            method.as_str(),
            destination
                .as_ref()
                .map(|d| format!(" to {}:{}", d.host, d.port))
                .unwrap_or_default()
        )),
        Some(StepRequest::Caller(c)) => {
            let query = c
                .query
                .iter()
                .map(|q| {
                    format!(
                        "{}{} {}",
                        q.name,
                        if q.required { " (required)" } else { "" },
                        q.allowed().describe()
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            out.push(format!(
                "  send the caller's request: methods [{}], paths [{}], headers [{}], query [{}]{injects}",
                c.methods
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                c.paths.join(", "),
                c.headers.join(", "),
                query
            ));
            if c.encoded_percent {
                out.push("  ! the caller's path may hold %25".into());
            }
            if c.override_params {
                out.push("  ! the caller may send method-override parameters".into());
            }
            if c.query.iter().any(|q| q.allowed().is_any()) {
                out.push("  ! some query parameters take any value".into());
            }
            if let Some(body) = &c.body {
                out.push(format!(
                    "  the caller's body, checked and sent as {}: {}",
                    body.content_type(),
                    describe_body(body)
                ));
            }
        }
        None if send.fill.is_some() => {
            if let Some(fill) = &send.fill {
                summarize_fill(fill, out);
            }
        }
        None => out.push(format!(
            "  send {}{:?}",
            match send.frame {
                Some(FrameKind::Text) => "a text message ",
                Some(FrameKind::Binary) => "a binary message ",
                None => "",
            },
            send.template.as_deref().unwrap_or_default()
        )),
    }
    if send.grpc {
        out.push("  (a unary gRPC call over HTTP/2)".into());
    }
}

/// A body contract in words, for a summary.
pub(crate) fn describe_body(body: &BodyContract) -> String {
    match body {
        BodyContract::Json(json) => Input::Json(json.clone()).describe(),
        BodyContract::Form(form) => format!(
            "form with {}",
            form.fields
                .iter()
                .map(|f| format!(
                    "{}{} {}",
                    f.name,
                    if f.required { " (required)" } else { "" },
                    f.allowed().describe()
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
}

/// How a body amount is written, in words.
fn amount_format(format: AmountFormat) -> &'static str {
    match format {
        AmountFormat::Minor => " (in minor units)",
        AmountFormat::Decimal => " (a decimal of major units)",
    }
}

fn summarize_fill(fill: &Fill, out: &mut Vec<String>) {
    let place = |frame: &Option<String>| match frame {
        Some(frame) => format!(" in a frame of {frame}"),
        None => String::new(),
    };
    out.push(format!(
        "  fill the page at {}{}: {}; submit {:?}{}; wait {} ms",
        fill.origin,
        fill.navigate
            .as_ref()
            .map(|p| format!(" (loaded at {p} first)"))
            .unwrap_or_default(),
        fill.fields
            .iter()
            .map(|f| format!("{:?}{} <- {:?}", f.selector, place(&f.frame), f.template))
            .collect::<Vec<_>>()
            .join(", "),
        fill.submit.selector,
        place(&fill.submit.frame),
        fill.wait()
    ));
    out.push(
        "  ! the browser behind the CDP endpoint sees the values; the node cannot see the page's TLS through CDP"
            .into(),
    );
    for frame in fill.other_frames() {
        out.push(format!(
            "  ! values go into a frame of {frame}, another origin than the page"
        ));
    }
}

fn summarize_operation(operation: &Operation, out: &mut Vec<String>) {
    let name = &operation.name;
    match operation.open() {
        Some(open) => out.push(format!(
            "operation {name}: {} to {}{}",
            match open.connection {
                Connection::Https => "HTTPS",
                Connection::Tls => "TLS stream",
                Connection::Websocket => "WebSocket",
                Connection::Ssh => "SSH",
                Connection::Postgres => "PostgreSQL",
                Connection::Smtp => "SMTP",
                Connection::Imap => "IMAP",
                Connection::Redis => "Redis",
                Connection::Browser => "browser (CDP)",
                Connection::Mysql => "MySQL",
                Connection::Mqtt => "MQTT",
                Connection::Amqp => "AMQP",
                Connection::Amqp1 => "AMQP 1.0",
                Connection::Ftp => "FTP over TLS",
                Connection::Pop3 => "POP3",
                Connection::Udp => "UDP datagrams (no TLS)",
                Connection::Dtls => "DTLS records over UDP",
            },
            destination_names(&open.destinations),
            if open.identity.is_some() {
                ", with a client certificate"
            } else {
                ""
            }
        )),
        None => out.push(format!(
            "operation {name}: no connection{}",
            operation
                .input
                .as_ref()
                .map(|i| format!("; input {}", i.describe()))
                .unwrap_or_default()
        )),
    }
    if matches!(&operation.input, Some(Input::Raw(raw)) if raw.max_len.is_none() && raw.pattern.is_none())
    {
        out.push("  ! the caller's input is any bytes".into());
    }
    if let Some(payment) = &operation.payment {
        out.push(format!(
            "  pays {} (exponent {}), the amount from {}",
            payment.currency,
            payment.exponent,
            match &payment.amount {
                AmountSource::Query { name } => format!("the query parameter {name}"),
                AmountSource::Input { pointer } => format!("the input member {pointer}"),
                AmountSource::Body {
                    pointer,
                    format,
                    currency_at,
                } => format!(
                    "the body member {pointer}{}{}",
                    amount_format(*format),
                    currency_at
                        .as_deref()
                        .map(|c| format!(", the currency fixed at {c}"))
                        .unwrap_or_default()
                ),
                AmountSource::Form {
                    name,
                    format,
                    currency_at,
                } => format!(
                    "the form field {name}{}{}",
                    amount_format(*format),
                    currency_at
                        .as_deref()
                        .map(|c| format!(", the currency fixed in {c}"))
                        .unwrap_or_default()
                ),
                AmountSource::Fixed { value } => format!("the policy: {value}"),
            }
        ));
    }
    if operation.approval {
        out.push("  every use waits for the owner's approval".into());
    }
    if let Some(v) = &operation.vend {
        out.push(format!(
            "  ! vends a credential minted from the secret, valid at most {} s, its expiry read from {}",
            v.lifetime_ms / 1000,
            v.describe()
        ));
    }
    if let Some(open) = operation.open() {
        proto::open_lines(open, out);
    }
    summarize_steps(operation, &operation.steps, out);
}

/// The summary lines of `steps` of `operation`; a loop or branch encloses the lines of its
/// bodies.
fn summarize_steps(operation: &Operation, steps: &[Step], out: &mut Vec<String>) {
    for step in steps {
        match step {
            Step::Open(_) => {}
            Step::Repeat(r) => {
                out.push(format!(
                    "  repeat up to {} times{}:",
                    r.times,
                    r.until
                        .as_ref()
                        .map(|t| format!(", until {}", t.describe()))
                        .unwrap_or_default()
                ));
                summarize_steps(operation, &r.steps, out);
                out.push("  end of repeat".into());
            }
            Step::If(b) => {
                out.push(format!("  if {}:", b.when.describe()));
                summarize_steps(operation, &b.then, out);
                if !b.otherwise.is_empty() {
                    out.push("  else:".into());
                    summarize_steps(operation, &b.otherwise, out);
                }
                out.push("  end of if".into());
            }
            Step::Await(wait) => {
                let c = &wait.challenge;
                match (&c.into, &c.poll) {
                    (Some(into), _) => out.push(format!(
                        "  await a {} code from the owner's device into secret {into} ({:?})",
                        c.kind.as_str(),
                        c.hint
                    )),
                    (None, Some(poll)) => {
                        out.push(format!(
                            "  await the owner's approval in another app ({:?}); poll every {} ms:",
                            c.hint, poll.every_ms
                        ));
                        summarize_send(&poll.send, out);
                    }
                    (None, None) => out.push(format!("  await {}", c.kind.as_str())),
                }
            }
            Step::Send(send) => summarize_send(send, out),
            Step::Receive(receive) => {
                let captures = receive
                    .capture
                    .iter()
                    .map(|c| match &c.into {
                        Store::Field { name } => format!("field {name}"),
                        Store::Temp { name, secret } => {
                            format!("{} {name}", if *secret { "secret" } else { "public" })
                        }
                    })
                    .collect::<Vec<_>>();
                out.push(format!(
                    "  receive{}{}",
                    if receive.until.is_empty() {
                        String::new()
                    } else {
                        format!(" until {:?}", receive.until)
                    },
                    if captures.is_empty() {
                        String::new()
                    } else {
                        format!("; captures {}", captures.join(", "))
                    }
                ));
            }
            Step::Compute(c) => out.push(format!("  compute {} = {}", c.into, c.template)),
            Step::Run(run) => out.extend(run::summary_line(run, operation.open())),
            Step::Return(ret) => match (&ret.response, &ret.relay, &ret.template) {
                (_, _, Some(template)) => out.push(format!("  return {template}")),
                (_, Some(relay), _) if !relay.commands.is_empty() || relay.mail.is_some() => {
                    proto::relay_lines(relay, out);
                }
                (_, Some(relay), _) if relay.frames.is_empty() && !relay.server => {
                    out.push(format!(
                        "  return: relays caller sends matching {:?}",
                        relay.sends
                    ));
                }
                (_, Some(relay), _) => {
                    for rule in &relay.frames {
                        out.push(format!(
                            "  return: relays the caller's {} frames{}{}",
                            match rule.kind {
                                FrameKind::Text => "text",
                                FrameKind::Binary => "binary",
                            },
                            rule.shape
                                .as_ref()
                                .map(|s| format!(" shaped {}", s.describe()))
                                .unwrap_or_else(|| " of any shape".into()),
                            rule.template
                                .as_ref()
                                .map(|t| format!(", sent as {t:?}"))
                                .unwrap_or_default()
                        ));
                        if rule.unpinned() {
                            out.push(
                                "  ! frames of this kind are relayed with no pinned shape".into(),
                            );
                        }
                    }
                    if relay.server {
                        out.push("  ! the server's messages go back to the caller".into());
                    }
                }
                (Some(p), _, _) => {
                    out.push(format!(
                        "  return: status{}{}",
                        if p.headers.is_empty() {
                            String::new()
                        } else {
                            format!(", headers [{}]", p.headers.join(", "))
                        },
                        match &p.body {
                            None => String::new(),
                            Some(BodyProjection::All) => ", the whole body".into(),
                            Some(BodyProjection::Stream) => ", the whole body as it arrives".into(),
                            Some(BodyProjection::Json(pointers)) =>
                                format!(", body members [{}]", pointers.join(", ")),
                        }
                    ));
                    if matches!(p.body, Some(BodyProjection::All | BodyProjection::Stream)) {
                        out.push("  ! the whole response body goes back to the caller".into());
                    }
                }
                (None, None, None) => out.push(match operation.connection() {
                    Some(Connection::Tls | Connection::Udp | Connection::Dtls) => {
                        "  return: no caller exchanges".into()
                    }
                    _ => "  return: status".into(),
                }),
            },
        }
    }
}

/// A policy with the signature of a device of its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    /// The policy.
    pub policy: Policy,
    /// Ed25519 signature over the canonical bytes of the policy.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl SignedPolicy {
    /// Verifies the signature under the key of the device and the rules of the policy.
    pub fn verify(&self, device: &DevicePublicKey) -> Result<&Policy> {
        self.verify_any(core::slice::from_ref(device))
    }

    /// Verifies the signature under one of `devices` and the rules of the policy.
    pub fn verify_any(&self, devices: &[DevicePublicKey]) -> Result<&Policy> {
        let message = canonical(POLICY_DOMAIN, &self.policy)?;
        if !devices
            .iter()
            .any(|d| d.verify(&message, &self.signature).is_ok())
        {
            return Err(Error::PolicySignature);
        }
        // A custom kind is signed on its own too: a device of the same owner vouches for it.
        if let Some(custom) = self.policy.item.as_ref().and_then(|i| i.custom.as_ref()) {
            custom.verify_any(devices)?;
        }
        self.policy.validate()?;
        Ok(&self.policy)
    }
}

impl DeviceKey {
    /// Signs a policy after checking its rules. Runs on the device.
    pub fn sign_policy(&self, policy: Policy) -> Result<SignedPolicy> {
        policy.validate()?;
        let message = canonical(POLICY_DOMAIN, &policy)?;
        Ok(SignedPolicy {
            signature: self.sign(&message),
            policy,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests;
