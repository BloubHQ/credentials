//! Policies: which fields a record holds, who may use them, and how, as data.
//!
//! The engine knows no kind of credential and no protocol flow. A policy names the fields of
//! its record, the callers that may use it, and a list of named [`Operation`]s:
//!
//! - [`Operation::Http`]: one or more HTTP [`Step`]s. A step sends either the request of the
//!   caller (within the destinations, methods, paths and headers of the operation) or a
//!   request the policy fixes, puts rendered templates into it, and may capture values from
//!   its response, either into a secret field of the record (a refreshed token, which the
//!   node seals into a new record) or into a value later steps read (a session cookie, a
//!   challenge nonce). The response of the last step goes back to the caller.
//! - [`Operation::Stream`]: a script of sends and expects over one TLS connection, for
//!   protocols that are not HTTP (IMAP, SMTP, line protocols), followed by the exchanges of
//!   the caller on the authenticated connection.
//! - [`Operation::Derive`]: a template whose output goes back to the caller; it must not be
//!   tainted.
//!
//! Every call names a [`Caller`] of the policy and carries its signature; a caller may use only
//! the operations it lists, at most at its [`Limit`].
//!
//! The device of the owner signs the policy, and the policy is bound to the ciphertext of its
//! record, so the operator can neither widen it nor move it to another record.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, canonical};
use crate::keys::{CallerPublicKey, DeviceKey, DevicePublicKey};
use crate::template::{NameKind, Template, Var};
use crate::{Error, Result};

const POLICY_DOMAIN: &[u8] = b"policy/v3\0";

/// Most operations of a policy.
pub const MAX_OPERATIONS: usize = 16;
/// Most callers of a policy.
pub const MAX_CALLERS: usize = 32;
/// Most destinations of an operation.
pub const MAX_DESTINATIONS: usize = 32;
/// Most path prefixes of an operation.
pub const MAX_PATHS: usize = 32;
/// Most steps of an HTTP operation.
pub const MAX_STEPS: usize = 8;
/// Most injections of a step.
pub const MAX_INJECTIONS: usize = 16;
/// Most captures of a step or an expect.
pub const MAX_CAPTURES: usize = 16;
/// Most entries of a stream script.
pub const MAX_SCRIPT: usize = 32;
/// Most delimiters of one expect.
pub const MAX_DELIMITERS: usize = 8;
/// Longest delimiter of an expect, in bytes.
pub const MAX_DELIMITER: usize = 256;

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

fn is_false(b: &bool) -> bool {
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
    /// The placeholder `{name}` of the path, percent-encoded by the engine.
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

/// What request a step sends.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepRequest {
    /// The request of the caller.
    #[default]
    Caller,
    /// A request the policy fixes; the caller has no say in it.
    Fixed {
        /// Method.
        method: Method,
        /// Path and query, starting with `/`.
        path: String,
        /// Destination (concrete). It may be left out only when the operation has exactly one
        /// destination and that one is concrete.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        destination: Option<Destination>,
    },
}

/// Where a capture reads in a response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
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
    /// The whole body.
    All,
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
        }
    }
}

/// Where a captured value goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Store {
    /// A secret field of the record. The node seals the record again and hands the new one
    /// back. Only a request the policy fixes may capture into a field.
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

/// One request of an HTTP operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// What request is sent.
    #[serde(default)]
    pub request: StepRequest,
    /// What the request carries.
    #[serde(default)]
    pub inject: Vec<Injection>,
    /// What is taken from the response.
    #[serde(default)]
    pub capture: Vec<Capture>,
}

/// One entry of a stream script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Exchange {
    /// Writes the rendered template.
    Send {
        /// What is written.
        template: String,
    },
    /// Reads up to and including the first of the delimiters `until`.
    Expect {
        /// The delimiters that end the read.
        until: Vec<String>,
        /// What is taken from the bytes read (only `between` and `all`).
        #[serde(default)]
        capture: Vec<Capture>,
    },
}

/// A named thing a caller may do with a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// One or more HTTP requests.
    Http {
        /// Operation name.
        name: String,
        /// Destinations its requests may go to.
        destinations: Vec<Destination>,
        /// Methods a request of the caller may use.
        #[serde(default)]
        methods: Vec<Method>,
        /// Path prefixes a request of the caller may use (`/v1/` allows `/v1/x`; `/v1`
        /// allows `/v1`, `/v1/x` and `/v1?q`, not `/v10`).
        #[serde(default)]
        paths: Vec<String>,
        /// Headers a request of the caller may carry (case does not matter).
        #[serde(default)]
        caller_headers: Vec<String>,
        /// Client certificate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<Identity>,
        /// The requests, in order.
        steps: Vec<Step>,
    },
    /// A scripted exchange over one TLS connection, then the exchanges of the caller.
    Stream {
        /// Operation name.
        name: String,
        /// Destinations it may connect to.
        destinations: Vec<Destination>,
        /// Client certificate.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<Identity>,
        /// The script, in order.
        script: Vec<Exchange>,
    },
    /// A template whose output goes back to the caller; `$input` is the input of the caller.
    Derive {
        /// Operation name.
        name: String,
        /// The template.
        template: String,
    },
}

impl Operation {
    /// The name of the operation.
    pub fn name(&self) -> &str {
        match self {
            Operation::Http { name, .. }
            | Operation::Stream { name, .. }
            | Operation::Derive { name, .. } => name,
        }
    }

    /// The captures that go into temporary values, with their secrecy.
    fn temps(&self) -> Vec<(&str, bool)> {
        let captures: Vec<&Capture> = match self {
            Operation::Http { steps, .. } => steps.iter().flat_map(|s| &s.capture).collect(),
            Operation::Stream { script, .. } => script
                .iter()
                .flat_map(|e| match e {
                    Exchange::Expect { capture, .. } => capture.as_slice(),
                    Exchange::Send { .. } => &[],
                })
                .collect(),
            Operation::Derive { .. } => Vec::new(),
        };
        captures
            .into_iter()
            .filter_map(|c| match &c.into {
                Store::Temp { name, secret } => Some((name.as_str(), *secret)),
                Store::Field { .. } => None,
            })
            .collect()
    }

    /// True when the concrete destination is one the operation names.
    pub fn allows_destination(&self, destination: &Destination) -> bool {
        match self {
            Operation::Http { destinations, .. } | Operation::Stream { destinations, .. } => {
                destinations.iter().any(|d| d.matches(destination))
            }
            Operation::Derive { .. } => false,
        }
    }

    /// True when a step sends the request of the caller.
    pub fn takes_request(&self) -> bool {
        matches!(self, Operation::Http { steps, .. }
            if steps.iter().any(|s| s.request == StepRequest::Caller))
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

/// A path the engine sends: starts with `/`, visible ASCII, no fragment, no `.` or `..`
/// segment and no encoded `/`, `\` or `.`, so a server cannot read it as another path.
pub(crate) fn check_path(path: &str) -> bool {
    let pathname = path.split_once('?').map_or(path, |(p, _)| p);
    let lower = pathname.to_ascii_lowercase();
    path.starts_with('/')
        && path.len() <= crate::request::MAX_PATH
        && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
        && !pathname.contains('\\')
        && !["%2f", "%5c", "%2e"].iter().any(|e| lower.contains(e))
        && !pathname.split('/').any(|s| s == "." || s == "..")
}

/// True when `path` is under `prefix` on a segment boundary.
pub(crate) fn under(path: &str, prefix: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')
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

impl Policy {
    /// True when the field is secret (an unknown field counts as secret).
    pub fn is_secret(&self, name: &str) -> bool {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .is_none_or(|f| f.secret)
    }

    /// What a name read in `operation` is. An unknown name counts as a secret field.
    pub fn name_kind(&self, operation: &Operation, name: &str) -> NameKind {
        if let Some((_, secret)) = operation.temps().into_iter().find(|(n, _)| *n == name) {
            return if secret {
                NameKind::SecretTemp
            } else {
                NameKind::PublicTemp
            };
        }
        if self
            .fields
            .iter()
            .any(|f| f.name == name && f.secret && f.guessable)
        {
            NameKind::GuessableField
        } else if self.is_secret(name) {
            NameKind::SecretField
        } else {
            NameKind::PublicField
        }
    }

    /// True when the name, a field or a temporary value of `operation`, is secret.
    pub fn is_secret_in(&self, operation: &Operation, name: &str) -> bool {
        matches!(
            self.name_kind(operation, name),
            NameKind::SecretField | NameKind::GuessableField | NameKind::SecretTemp
        )
    }

    fn is_field(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }

    /// The operation with this name.
    pub fn operation(&self, name: &str) -> Result<&Operation> {
        self.operations
            .iter()
            .find(|o| o.name() == name)
            .ok_or(Error::OperationUnknown)
    }

    /// The caller with this name.
    pub fn caller(&self, name: &str) -> Result<&Caller> {
        self.callers
            .iter()
            .find(|c| c.name == name)
            .ok_or(Error::CallerDenied)
    }

    /// Parses a template, checks its names and variables, and applies the analysis. Returns
    /// whether its output is tainted.
    fn check_template(
        &self,
        at: &str,
        operation: &Operation,
        text: &str,
        temps: &[&str],
        var_ok: fn(Var) -> bool,
    ) -> Result<bool> {
        let template = Template::parse(text).map_err(|_| Error::policy(at, "template syntax"))?;
        let known = |name: &str| self.is_field(name) || temps.contains(&name);
        if !template.names().into_iter().all(known) {
            return Err(Error::policy(at, "template reads an unknown or later name"));
        }
        if !template.vars().into_iter().all(var_ok) {
            return Err(Error::policy(
                at,
                "template reads a variable not available here",
            ));
        }
        template
            .analyze(&|name| self.name_kind(operation, name))
            .map_err(|rule| Error::policy(at, rule))
    }

    fn check_captures<'a>(
        &self,
        at: &str,
        captures: &'a [Capture],
        stream: bool,
        fixed: bool,
        temps: &mut Vec<&'a str>,
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
                        is_token(name) && !self.is_field(name) && !temps.contains(&name.as_str()),
                        || at.clone(),
                        "temporary name must be a new token",
                    )?;
                    temps.push(name);
                }
            }
        }
        Ok(())
    }

    fn check_identity(
        &self,
        at: &str,
        operation: &Operation,
        identity: Option<&Identity>,
    ) -> Checked {
        if let Some(identity) = identity {
            self.check_template(
                &format!("{at}.identity.cert"),
                operation,
                &identity.cert,
                &[],
                Var::in_stream,
            )?;
            self.check_template(
                &format!("{at}.identity.key"),
                operation,
                &identity.key,
                &[],
                Var::in_stream,
            )?;
        }
        Ok(())
    }

    fn check_step<'a>(
        &self,
        at: &str,
        operation: &Operation,
        step: &'a Step,
        destinations: &[Destination],
        temps: &mut Vec<&'a str>,
    ) -> Checked {
        ensure(
            step.inject.len() <= MAX_INJECTIONS,
            || format!("{at}.inject"),
            "at most 16 injections",
        )?;
        if let StepRequest::Fixed {
            path, destination, ..
        } = &step.request
        {
            ensure(
                check_path(path),
                || format!("{at}.request.path"),
                "path must start with / and hold no dot segment or encoded separator",
            )?;
            match destination {
                Some(d) => ensure(
                    d.is_concrete() && destinations.iter().any(|p| p.matches(d)),
                    || format!("{at}.request.destination"),
                    "fixed destination must be concrete and one of the operation",
                )?,
                None => ensure(
                    destinations.len() == 1 && destinations.iter().all(Destination::is_concrete),
                    || format!("{at}.request.destination"),
                    "fixed request needs a destination unless the operation has one concrete destination",
                )?,
            }
        }
        let mut headers: Vec<String> = Vec::new();
        let mut bodies = 0;
        for (i, injection) in step.inject.iter().enumerate() {
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
                    ensure(is_token(name), || at.clone(), "query name is not a token")?;
                }
                Target::PathParam { name } => {
                    let placeholder_ok = match &step.request {
                        StepRequest::Fixed { path, .. } => {
                            path.matches(&format!("{{{name}}}")).count() == 1
                        }
                        StepRequest::Caller => true,
                    };
                    ensure(
                        is_token(name) && placeholder_ok,
                        || at.clone(),
                        "path parameter must be a token found once in the path",
                    )?;
                }
                Target::Body => bodies += 1,
            }
            self.check_template(&at, operation, &injection.template, temps, Var::in_request)?;
        }
        ensure(bodies <= 1, || format!("{at}.inject"), "at most one body")?;
        let fixed = matches!(step.request, StepRequest::Fixed { .. });
        self.check_captures(at, &step.capture, false, fixed, temps)
    }

    fn check_operation(&self, at: &str, operation: &Operation) -> Checked {
        ensure(
            is_token(operation.name()),
            || format!("{at}.name"),
            "name is not a token",
        )?;
        let mut temps: Vec<&str> = Vec::new();
        match operation {
            Operation::Http {
                destinations,
                methods,
                paths,
                caller_headers,
                identity,
                steps,
                ..
            } => {
                check_destinations(at, destinations)?;
                ensure(
                    !steps.is_empty() && steps.len() <= MAX_STEPS,
                    || format!("{at}.steps"),
                    "1 to 8 steps",
                )?;
                let has_caller = operation.takes_request();
                ensure(
                    has_caller != methods.is_empty(),
                    || format!("{at}.methods"),
                    "methods are needed exactly when a step sends the request of the caller",
                )?;
                ensure(
                    has_caller != paths.is_empty() && paths.len() <= MAX_PATHS,
                    || format!("{at}.paths"),
                    "paths are needed exactly when a step sends the request of the caller",
                )?;
                for (i, path) in paths.iter().enumerate() {
                    ensure(
                        check_path(path) && !path.contains('?'),
                        || format!("{at}.paths[{i}]"),
                        "path prefix must start with / and hold no query or dot segment",
                    )?;
                }
                for (i, name) in caller_headers.iter().enumerate() {
                    ensure(
                        has_caller,
                        || format!("{at}.caller_headers"),
                        "caller headers need a step that sends the request of the caller",
                    )?;
                    let lower = name.to_ascii_lowercase();
                    ensure(
                        is_token(name) && !RESERVED_HEADERS.contains(&lower.as_str()),
                        || format!("{at}.caller_headers[{i}]"),
                        "caller header must be a token and not reserved",
                    )?;
                }
                self.check_identity(at, operation, identity.as_ref())?;
                for (i, step) in steps.iter().enumerate() {
                    let at = format!("{at}.steps[{i}]");
                    self.check_step(&at, operation, step, destinations, &mut temps)?;
                    let injected = step.inject.iter().any(|inj| match &inj.target {
                        Target::Header { name } => {
                            caller_headers.iter().any(|h| h.eq_ignore_ascii_case(name))
                        }
                        _ => false,
                    });
                    ensure(
                        !(step.request == StepRequest::Caller && injected),
                        || at.clone(),
                        "a caller header is also injected",
                    )?;
                }
            }
            Operation::Stream {
                destinations,
                identity,
                script,
                ..
            } => {
                check_destinations(at, destinations)?;
                ensure(
                    !script.is_empty() && script.len() <= MAX_SCRIPT,
                    || format!("{at}.script"),
                    "1 to 32 script entries",
                )?;
                self.check_identity(at, operation, identity.as_ref())?;
                for (i, exchange) in script.iter().enumerate() {
                    let at = format!("{at}.script[{i}]");
                    match exchange {
                        Exchange::Send { template } => {
                            self.check_template(&at, operation, template, &temps, Var::in_stream)?;
                        }
                        Exchange::Expect { until, capture } => {
                            ensure(
                                !until.is_empty()
                                    && until.len() <= MAX_DELIMITERS
                                    && until
                                        .iter()
                                        .all(|u| !u.is_empty() && u.len() <= MAX_DELIMITER),
                                || format!("{at}.until"),
                                "1 to 8 delimiters of 1 to 256 bytes",
                            )?;
                            self.check_captures(&at, capture, true, true, &mut temps)?;
                        }
                    }
                }
            }
            Operation::Derive { template, .. } => {
                let at = format!("{at}.template");
                let tainted = self.check_template(&at, operation, template, &[], Var::in_derive)?;
                ensure(
                    !tainted,
                    || at.clone(),
                    "a derivation would hand a secret back",
                )?;
                let parsed =
                    Template::parse(template).map_err(|_| Error::policy(&at, "template syntax"))?;
                ensure(
                    !parsed.guessable(&|name| self.name_kind(operation, name)),
                    || at,
                    "a derivation would hand back a check for guesses of a guessable field",
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
            ensure(
                !caller.operations.is_empty()
                    && caller.operations.iter().all(|o| self.operation(o).is_ok())
                    && unique(caller.operations.iter().map(String::as_str)),
                || format!("{at}.operations"),
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

    /// What the policy allows, in plain lines, for the owner to read before signing.
    pub fn summary(&self) -> Vec<String> {
        let mut out = Vec::new();
        for field in &self.fields {
            out.push(format!(
                "field {}: {}{}",
                field.name,
                if field.secret { "secret" } else { "public" },
                if field.optional { ", optional" } else { "" }
            ));
        }
        for operation in &self.operations {
            let names = |d: &[Destination]| {
                d.iter()
                    .map(|d| format!("{}:{}", d.host, d.port))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push(match operation {
                Operation::Http {
                    name,
                    destinations,
                    methods,
                    paths,
                    steps,
                    ..
                } => format!(
                    "operation {name}: HTTP to {} ({} steps; caller methods [{}] under [{}])",
                    names(destinations),
                    steps.len(),
                    methods
                        .iter()
                        .map(|m| m.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    paths.join(", ")
                ),
                Operation::Stream {
                    name, destinations, ..
                } => format!("operation {name}: stream to {}", names(destinations)),
                Operation::Derive { name, template } => {
                    format!("operation {name}: derive {template}")
                }
            });
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
mod tests {
    use super::*;
    use crate::keys::CallerKey;

    fn caller(operations: &[&str]) -> Caller {
        Caller {
            name: "app".into(),
            key: CallerKey::generate().public(),
            operations: operations.iter().map(|o| o.to_string()).collect(),
            limit: None,
        }
    }

    fn bearer() -> Policy {
        Policy {
            fields: vec![FieldSpec::secret("token")],
            callers: vec![caller(&["call"])],
            operations: vec![Operation::Http {
                name: "call".into(),
                destinations: vec![Destination::https("api.example.com")],
                methods: vec![Method::Get],
                paths: vec!["/v1/".into()],
                caller_headers: vec![],
                identity: None,
                steps: vec![Step {
                    request: StepRequest::Caller,
                    inject: vec![Injection::header("Authorization", "Bearer {{token}}")],
                    capture: vec![],
                }],
            }],
        }
    }

    fn derive_only(template: &str) -> Policy {
        Policy {
            fields: vec![FieldSpec::secret("key")],
            callers: vec![caller(&["sign"])],
            operations: vec![Operation::Derive {
                name: "sign".into(),
                template: template.into(),
            }],
        }
    }

    fn step_of(p: &mut Policy) -> &mut Step {
        match &mut p.operations[0] {
            Operation::Http { steps, .. } => &mut steps[0],
            _ => panic!("not http"),
        }
    }

    fn rule_of(p: &Policy) -> &'static str {
        match p.validate() {
            Err(Error::PolicyInvalid { rule, .. }) => rule,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn valid_policies() {
        bearer().validate().unwrap();
        derive_only("{{ hex(hmac_sha256(key, $input)) }}")
            .validate()
            .unwrap();
    }

    #[test]
    fn derive_must_not_give_a_secret_back() {
        for template in [
            "{{key}}",
            "{{ b64(key) }}",
            "{{ hexdecode(hex(key)) }}",
            "x{{ \"a\" + key }}",
            r#"{{ aes_gcm_encrypt("0123456789abcdef", "000000000000", key) }}"#,
            r#"{{ len(replace(key, $input, "")) }}"#,
        ] {
            assert!(
                matches!(
                    derive_only(template).validate(),
                    Err(Error::PolicyInvalid { .. })
                ),
                "{template}"
            );
        }
    }

    #[test]
    fn errors_name_the_part() {
        let mut p = bearer();
        step_of(&mut p).inject[0].template = "Bearer {{other}}".into();
        assert_eq!(
            p.validate(),
            Err(Error::PolicyInvalid {
                at: "operations[0].steps[0].inject[0]".into(),
                rule: "template reads an unknown or later name"
            })
        );
    }

    #[test]
    fn destinations() {
        let pattern = Destination::https("*.example.com");
        assert!(pattern.matches(&Destination::https("a.example.com")));
        assert!(!pattern.matches(&Destination::https("example.com")));
        assert!(!pattern.matches(&Destination::https("a.b.example.com")));
        assert!(!pattern.matches(&Destination::https("aexample.com")));
        assert!(!pattern.matches(&Destination::new("a.example.com", 8443)));
        assert!(!pattern.matches(&Destination::https("*.example.com")));
        assert_eq!(
            Destination::https("API.Example.com").host,
            "api.example.com"
        );
        assert!(!Destination::https("*.com").is_valid_pattern());
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut p = bearer();
        step_of(&mut p).inject[0].target = Target::Header {
            name: "Host".into(),
        };
        assert_eq!(
            rule_of(&p),
            "header must be a token, not reserved, and set once"
        );

        let mut p = bearer();
        step_of(&mut p).inject[0].target = Target::Header {
            name: "X-HTTP-Method-Override".into(),
        };
        assert_eq!(
            rule_of(&p),
            "header must be a token, not reserved, and set once"
        );

        let mut p = bearer();
        step_of(&mut p).inject[0].template = "{{ $input }}".into();
        assert_eq!(rule_of(&p), "template reads a variable not available here");

        // A temporary value is readable only after the step that captures it.
        let mut p = bearer();
        step_of(&mut p).inject[0].template = "{{ later }}".into();
        step_of(&mut p).capture.push(Capture {
            source: Source::Header { name: "X".into() },
            into: Store::Temp {
                name: "later".into(),
                secret: false,
            },
            optional: false,
        });
        assert_eq!(rule_of(&p), "template reads an unknown or later name");

        // A capture into a field from the request of the caller.
        let mut p = bearer();
        step_of(&mut p).capture.push(Capture {
            source: Source::Json {
                pointer: "/t".into(),
            },
            into: Store::Field {
                name: "token".into(),
            },
            optional: false,
        });
        assert_eq!(
            rule_of(&p),
            "capture into a field from a request of the caller"
        );

        // An operation without path prefixes.
        let mut p = bearer();
        if let Operation::Http { paths, .. } = &mut p.operations[0] {
            paths.clear();
        }
        assert_eq!(
            rule_of(&p),
            "paths are needed exactly when a step sends the request of the caller"
        );

        // Two operations with one name.
        let mut p = bearer();
        p.operations.push(p.operations[0].clone());
        assert_eq!(rule_of(&p), "operation names must be unique");

        // A caller of an unknown operation.
        let mut p = bearer();
        p.callers[0].operations.push("nope".into());
        assert_eq!(
            rule_of(&p),
            "operations must be names of operations, each once"
        );
    }

    #[test]
    fn paths() {
        assert!(under("/v1/x", "/v1/"));
        assert!(under("/v1", "/v1"));
        assert!(under("/v1?q=1", "/v1"));
        assert!(under("/v1/x", "/v1"));
        assert!(!under("/v10", "/v1"));
        assert!(!check_path("/v1/../admin"));
        assert!(!check_path("/v1/%2e%2e/admin"));
        assert!(!check_path("/v1%2Fadmin"));
        assert!(!check_path("/v1\\admin"));
        assert!(check_path("/v1/a.b?x=..%2F"));
    }

    #[test]
    fn signature_binds_policy() {
        let device = DeviceKey::generate();
        let mut signed = device.sign_policy(bearer()).unwrap();
        signed.verify(&device.public()).unwrap();
        if let Operation::Http { destinations, .. } = &mut signed.policy.operations[0] {
            destinations.push(Destination::https("evil.example.net"));
        }
        assert_eq!(signed.verify(&device.public()), Err(Error::PolicySignature));
    }
}
