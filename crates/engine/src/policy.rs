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
//! - [`Step::Return`] says what goes back to the caller: the declared parts of the last
//!   response ([`Projection`]), the caller's exchanges on the stream within the patterns of
//!   a [`Relay`], or the output of a template that must hand no secret back.
//!
//! Loops and branches ([`Step::Repeat`], [`Step::If`]) are part of the syntax and refused
//! when a policy is checked: they are the next part of the language.
//!
//! Every template of every step is checked by the same analysis before the policy is
//! signed. Every call names a [`Caller`] of the policy and carries its signature; a caller may
//! use only the operations it lists, at most at its [`Limit`].
//!
//! The device of the owner signs the policy, and the policy is bound to the ciphertext of its
//! record, so the operator can neither widen it nor move it to another record.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, canonical};
use crate::keys::{CallerPublicKey, DeviceKey, DevicePublicKey};
use crate::template::{NameKind, Props, Template, Var};
use crate::{Error, Result};

mod contract;
mod input;
pub mod legacy;

pub(crate) use contract::placeholders;
pub use contract::{
    CallerRequest, MAX_QUERY_RULES, QueryRule, RESERVED_PARAMS, path_fault, template_fault,
    template_matches,
};
pub use input::{Input, JsonInput, JsonType, Member, NodeTime, RawInput, RlpInput, RlpItem};

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
/// Most caller send patterns of a relay.
pub const MAX_RELAY_PATTERNS: usize = 16;

/// Headers the engine sets itself, or that change how a server reads or answers a request;
/// neither an injection nor a caller may name them.
pub(crate) const RESERVED_HEADERS: [&str; 15] = [
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
}

impl FieldSpec {
    /// A secret field.
    pub fn secret(name: &str) -> Self {
        Self {
            name: name.into(),
            secret: true,
            optional: false,
            guessable: false,
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
        }
    }

    /// The same field, optional.
    pub fn optional(mut self) -> Self {
        self.optional = true;
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
                if stream =>
            {
                Some(http_only)
            }
            Source::Header { name } | Source::Cookie { name } => {
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

/// The kind of connection an operation opens. New kinds (WebSocket, SSH, database
/// handshakes, a browser over CDP) are added here, each with what its `send`, `receive` and
/// `return` mean; the steps and the analysis stay the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    /// HTTPS: each `send` is one HTTP/1.1 request on its own TLS connection, and `receive`
    /// reads its response.
    Https,
    /// A TLS byte stream (IMAP, SMTP, line protocols): `send` writes, `receive` reads up to a
    /// delimiter.
    Tls,
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
    /// What is written (TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
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
}

/// The caller's exchanges a TLS operation relays after its steps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// Regular expressions (linear time, ASCII, `.` does not match a line end); each caller
    /// send must match one of them whole.
    pub sends: Vec<String>,
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

/// A bounded loop: the syntax of the next part of the language. Refused by
/// [`Policy::validate`] for now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repeat {
    /// Most iterations.
    pub times: u32,
    /// The steps repeated.
    pub steps: Vec<Step>,
    /// A public value whose presence ends the loop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// A branch on a captured public value: the syntax of the next part of the language. Refused
/// by [`Policy::validate`] for now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    /// The value tested (a public temporary value).
    pub name: String,
    /// The value it is compared with.
    pub equals: String,
    /// The steps when it is equal.
    #[serde(default)]
    pub then: Vec<Step>,
    /// The steps otherwise.
    #[serde(default, rename = "else")]
    pub otherwise: Vec<Step>,
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
    /// Says what goes back to the caller; the last step.
    Return(Return),
    /// A bounded loop (refused for now).
    Repeat(Repeat),
    /// A branch (refused for now).
    If(Branch),
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

    /// The contracts of the `send` steps that send the caller's request, with their steps.
    pub fn caller_sends(&self) -> impl Iterator<Item = (&CallerRequest, &Send)> {
        self.steps.iter().filter_map(|s| match s {
            Step::Send(send) => match &send.request {
                Some(StepRequest::Caller(contract)) => Some((contract, send)),
                _ => None,
            },
            _ => None,
        })
    }

    /// The captures that go into temporary values, with their secrecy.
    fn temps(&self) -> Vec<(&str, bool)> {
        self.steps
            .iter()
            .flat_map(|s| match s {
                Step::Receive(r) => r.capture.as_slice(),
                _ => &[],
            })
            .filter_map(|c| match &c.into {
                Store::Temp { name, secret } => Some((name.as_str(), *secret)),
                Store::Field { .. } => None,
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
        for step in &self.steps {
            match step {
                Step::Open(open) => {
                    if let Some(identity) = &open.identity {
                        out.push(identity.cert.as_str());
                        out.push(identity.key.as_str());
                    }
                }
                Step::Send(send) => {
                    out.extend(send.inject.iter().map(|i| i.template.as_str()));
                    out.extend(send.template.as_deref());
                }
                Step::Compute(c) => out.push(&c.template),
                Step::Return(r) => out.extend(r.template.as_deref()),
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
        for step in &operation.steps {
            if let Step::Compute(c) = step {
                let props = Template::parse(&c.template)
                    .ok()
                    .and_then(|t| t.props(&|n| kinds.kind(n)).ok())
                    .unwrap_or_else(Props::unknown);
                if kinds.computed.iter().all(|(n, _)| *n != c.into) {
                    kinds.computed.push((&c.into, props));
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
        if let Some((_, secret)) = self.temps.iter().find(|(n, _)| *n == name) {
            return if *secret {
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
    /// The fields of the record.
    pub fields: Vec<FieldSpec>,
    /// Who may use them.
    pub callers: Vec<Caller>,
    /// What may be done with them.
    pub operations: Vec<Operation>,
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
        let template = Template::parse(text).map_err(|_| Error::policy(at, "template syntax"))?;
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
        let tainted = template
            .analyze(&|name| kinds.kind(name))
            .map_err(|rule| Error::policy(at, rule))?;
        Ok((template, tainted))
    }

    fn check_captures<'a>(
        &self,
        at: &str,
        captures: &'a [Capture],
        stream: bool,
        fixed: bool,
        known: &mut Vec<&'a str>,
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
                Store::Temp { name, .. } => {
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
            StepRequest::Caller(contract) => self.check_caller_contract(at, contract, send)?,
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
            self.check_template(&at, kinds, &injection.template, known, Var::in_request)?;
        }
        ensure(bodies <= 1, || format!("{at}.inject"), "at most one body")
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
            Some(Connection::Tls) => {
                ensure(
                    ret.response.is_none() && ret.template.is_none(),
                    || at.to_string(),
                    "a TLS return takes relay only",
                )?;
                if let Some(relay) = &ret.relay {
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
        let mut known: Vec<&str> = Vec::new();
        let mut sends = 0usize;
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
                }
                (Step::Send(_) | Step::Receive(_), None) => {
                    return fail(at, "send and receive need an open connection");
                }
                (Step::Send(send), Some(open)) => match open.connection {
                    Connection::Https => {
                        sends += 1;
                        ensure(sends <= MAX_REQUESTS, || at.clone(), "at most 8 requests")?;
                        self.check_https_send(&at, &kinds, open, send, &known)?;
                    }
                    Connection::Tls => {
                        ensure(
                            send.request.is_none() && send.inject.is_empty(),
                            || at.clone(),
                            "a TLS send takes template only",
                        )?;
                        let Some(template) = &send.template else {
                            return fail(at, "a TLS send needs a template");
                        };
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
                (Step::Return(ret), _) => {
                    ensure(i + 1 == count, || at.clone(), "return is the last step")?;
                    self.check_return(&at, &kinds, connection, ret, &known, sends > 0)?;
                }
                (Step::Repeat(_) | Step::If(_), _) => {
                    return fail(
                        at,
                        "loops and branches are part of the syntax but not run yet; write the steps out",
                    );
                }
            }
        }
        ensure(
            operation.returns().is_some(),
            || format!("{at}.steps"),
            "an operation ends with return",
        )?;
        let reads_input = operation
            .templates()
            .into_iter()
            .any(|t| Template::parse(t).is_ok_and(|t| t.vars().contains(&Var::Input)));
        ensure(
            !reads_input || operation.input.is_some(),
            || format!("{at}.input"),
            "an operation that reads $input declares its input",
        )
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
        self.check_callers()
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
        }
        None => out.push(format!(
            "  send {:?}",
            send.template.as_deref().unwrap_or_default()
        )),
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
    for step in &operation.steps {
        match step {
            Step::Open(_) | Step::Repeat(_) | Step::If(_) => {}
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
            Step::Return(ret) => match (&ret.response, &ret.relay, &ret.template) {
                (_, _, Some(template)) => out.push(format!("  return {template}")),
                (_, Some(relay), _) => {
                    out.push(format!(
                        "  return: relays caller sends matching {:?}",
                        relay.sends
                    ));
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
                            Some(BodyProjection::Json(pointers)) =>
                                format!(", body members [{}]", pointers.join(", ")),
                        }
                    ));
                    if p.body == Some(BodyProjection::All) {
                        out.push("  ! the whole response body goes back to the caller".into());
                    }
                }
                (None, None, None) => out.push(match operation.connection() {
                    Some(Connection::Tls) => "  return: no caller exchanges".into(),
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
