//! Policies: which fields a record holds and what may be done with them, as data.
//!
//! The engine knows no kind of credential and no protocol flow. A policy names the fields of
//! its record and a list of named [`Operation`]s:
//!
//! - [`Operation::Http`]: one or more HTTP [`Step`]s. A step sends either the request of the
//!   caller or a request the policy fixes, puts rendered templates into it, and may capture
//!   values from its response, either into a field of the record (a refreshed token, which
//!   the node seals into a new record) or into a value later steps read (a session cookie, a
//!   challenge nonce). The response of the last step goes back to the caller.
//! - [`Operation::Stream`]: a script of sends and expects over one TLS connection, for
//!   protocols that are not HTTP (IMAP, SMTP, line protocols), followed by the exchanges of
//!   the caller on the authenticated connection.
//! - [`Operation::Derive`]: a template whose output goes back to the caller; it must not be
//!   tainted.
//!
//! Http and Stream operations may present a client certificate ([`Identity`]).
//!
//! The device of the owner signs the policy, and the policy is bound to the ciphertext of its
//! record, so the operator can neither widen it nor move it to another record.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_array, canonical};
use crate::keys::{DeviceKey, DevicePublicKey};
use crate::template::{Template, Var};
use crate::{Error, Result};

const POLICY_DOMAIN: &[u8] = b"policy/v2\0";

/// Most operations of a policy.
pub const MAX_OPERATIONS: usize = 16;
/// Most destinations of an operation.
pub const MAX_DESTINATIONS: usize = 32;
/// Most steps of an HTTP operation.
pub const MAX_STEPS: usize = 8;
/// Most injections of a step.
pub const MAX_INJECTIONS: usize = 16;
/// Most captures of a step or an expect.
pub const MAX_CAPTURES: usize = 16;
/// Most entries of a stream script.
pub const MAX_SCRIPT: usize = 32;
/// Longest delimiter of an expect, in bytes.
pub const MAX_DELIMITER: usize = 256;

/// Headers the engine sets itself; neither an injection nor a caller may name them.
pub(crate) const RESERVED_HEADERS: [&str; 5] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
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

/// HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

impl Method {
    /// The token of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// A TLS destination: an exact host name and a port. No wildcard.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// Lowercase host name.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Destination {
    /// A destination on port 443.
    pub fn https(host: &str) -> Self {
        Self::new(host, 443)
    }

    /// A destination on `port`.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    fn validate(&self) -> Result<()> {
        let host = self.host.as_bytes();
        let valid_chars = host
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-');
        let edges_ok = !matches!(host.first(), Some(b'.' | b'-') | None)
            && !matches!(host.last(), Some(b'.' | b'-') | None);
        if host.len() > 253 || !valid_chars || !edges_ok || self.port == 0 {
            return Err(Error::PolicyInvalid);
        }
        Ok(())
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
        /// Destination; the first destination of the operation when absent.
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
    HeaderParam {
        /// Header name.
        name: String,
        /// Parameter name.
        param: String,
    },
    /// The value of the cookie with this name in a `Set-Cookie` header.
    Cookie {
        /// Cookie name.
        name: String,
    },
    /// A JSON value of the body, by JSON pointer (RFC 6901). Strings are taken unquoted.
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
    fn validate(&self, stream: bool) -> Result<()> {
        let ok = match self {
            Source::Status | Source::All => !stream || matches!(self, Source::All),
            Source::Header { name } | Source::Cookie { name } => !stream && is_token(name),
            Source::HeaderParam { name, param } => !stream && is_token(name) && is_token(param),
            Source::Json { pointer } => !stream && (pointer.is_empty() || pointer.starts_with('/')),
            Source::Between { start, end } => {
                !start.is_empty()
                    && !end.is_empty()
                    && start.len() <= MAX_DELIMITER
                    && end.len() <= MAX_DELIMITER
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Error::PolicyInvalid)
        }
    }
}

/// Where a captured value goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Store {
    /// A field of the record. The node seals the record again and hands the new one back.
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
    /// Reads up to and including `until`.
    Expect {
        /// The delimiter that ends the read.
        until: String,
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
        methods: Vec<Method>,
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

    /// True when the destination is one of the operation.
    pub fn allows_destination(&self, destination: &Destination) -> bool {
        match self {
            Operation::Http { destinations, .. } | Operation::Stream { destinations, .. } => {
                destinations.contains(destination)
            }
            Operation::Derive { .. } => false,
        }
    }
}

/// The rules of one record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The fields of the record.
    pub fields: Vec<FieldSpec>,
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

fn check_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= crate::request::MAX_PATH
        && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
}

fn check_destinations(destinations: &[Destination]) -> Result<()> {
    if destinations.is_empty() || destinations.len() > MAX_DESTINATIONS {
        return Err(Error::PolicyInvalid);
    }
    destinations.iter().try_for_each(Destination::validate)
}

impl Policy {
    /// True when the field is secret (an unknown field counts as secret).
    pub fn is_secret(&self, name: &str) -> bool {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .is_none_or(|f| f.secret)
    }

    /// True when the name, a field or a temporary value of `operation`, is secret. An unknown
    /// name counts as secret.
    pub fn is_secret_in(&self, operation: &Operation, name: &str) -> bool {
        match operation.temps().into_iter().find(|(n, _)| *n == name) {
            Some((_, secret)) => secret,
            None => self.is_secret(name),
        }
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

    fn check_template(
        &self,
        text: &str,
        temps: &[&str],
        var_ok: fn(Var) -> bool,
    ) -> Result<Template> {
        let template = Template::parse(text)?;
        let known = |name: &str| self.is_field(name) || temps.contains(&name);
        if !template.names().into_iter().all(known) || !template.vars().into_iter().all(var_ok) {
            return Err(Error::PolicyInvalid);
        }
        Ok(template)
    }

    fn check_captures<'a>(
        &self,
        captures: &'a [Capture],
        stream: bool,
        temps: &mut Vec<&'a str>,
    ) -> Result<()> {
        if captures.len() > MAX_CAPTURES {
            return Err(Error::PolicyInvalid);
        }
        for capture in captures {
            capture.source.validate(stream)?;
            match &capture.into {
                Store::Field { name } if self.is_field(name) => {}
                Store::Temp { name, .. }
                    if is_token(name)
                        && !self.is_field(name)
                        && !temps.contains(&name.as_str()) =>
                {
                    temps.push(name);
                }
                _ => return Err(Error::PolicyInvalid),
            }
        }
        Ok(())
    }

    fn check_identity(&self, identity: Option<&Identity>) -> Result<()> {
        if let Some(identity) = identity {
            self.check_template(&identity.cert, &[], Var::in_stream)?;
            self.check_template(&identity.key, &[], Var::in_stream)?;
        }
        Ok(())
    }

    fn check_step<'a>(
        &self,
        step: &'a Step,
        destinations: &[Destination],
        temps: &mut Vec<&'a str>,
    ) -> Result<()> {
        if step.inject.len() > MAX_INJECTIONS {
            return Err(Error::PolicyInvalid);
        }
        if let StepRequest::Fixed {
            path, destination, ..
        } = &step.request
        {
            let destination_ok = destination
                .as_ref()
                .is_none_or(|d| destinations.contains(d));
            if !check_path(path) || !destination_ok {
                return Err(Error::PolicyInvalid);
            }
        }
        let mut headers: Vec<String> = Vec::new();
        let mut bodies = 0;
        for injection in &step.inject {
            match &injection.target {
                Target::Header { name } => {
                    let lower = name.to_ascii_lowercase();
                    if !is_token(name)
                        || RESERVED_HEADERS.contains(&lower.as_str())
                        || headers.contains(&lower)
                    {
                        return Err(Error::PolicyInvalid);
                    }
                    headers.push(lower);
                }
                Target::Query { name } => {
                    if !is_token(name) {
                        return Err(Error::PolicyInvalid);
                    }
                }
                Target::PathParam { name } => {
                    let placeholder_ok = match &step.request {
                        StepRequest::Fixed { path, .. } => {
                            path.matches(&format!("{{{name}}}")).count() == 1
                        }
                        StepRequest::Caller => true,
                    };
                    if !is_token(name) || !placeholder_ok {
                        return Err(Error::PolicyInvalid);
                    }
                }
                Target::Body => bodies += 1,
            }
            self.check_template(&injection.template, temps, Var::in_request)?;
        }
        if bodies > 1 {
            return Err(Error::PolicyInvalid);
        }
        self.check_captures(&step.capture, false, temps)
    }

    fn check_operation(&self, operation: &Operation) -> Result<()> {
        if !is_token(operation.name()) {
            return Err(Error::PolicyInvalid);
        }
        let mut temps: Vec<&str> = Vec::new();
        match operation {
            Operation::Http {
                destinations,
                methods,
                identity,
                steps,
                ..
            } => {
                check_destinations(destinations)?;
                let has_caller = steps.iter().any(|s| s.request == StepRequest::Caller);
                if steps.is_empty() || steps.len() > MAX_STEPS || has_caller == methods.is_empty() {
                    return Err(Error::PolicyInvalid);
                }
                self.check_identity(identity.as_ref())?;
                for step in steps {
                    self.check_step(step, destinations, &mut temps)?;
                }
            }
            Operation::Stream {
                destinations,
                identity,
                script,
                ..
            } => {
                check_destinations(destinations)?;
                if script.is_empty() || script.len() > MAX_SCRIPT {
                    return Err(Error::PolicyInvalid);
                }
                self.check_identity(identity.as_ref())?;
                for exchange in script {
                    match exchange {
                        Exchange::Send { template } => {
                            self.check_template(template, &temps, Var::in_stream)?;
                        }
                        Exchange::Expect { until, capture } => {
                            if until.is_empty() || until.len() > MAX_DELIMITER {
                                return Err(Error::PolicyInvalid);
                            }
                            self.check_captures(capture, true, &mut temps)?;
                        }
                    }
                }
            }
            Operation::Derive { template, .. } => {
                let template = self.check_template(template, &[], Var::in_derive)?;
                if template.tainted(&|name| self.is_secret(name)) {
                    return Err(Error::PolicyInvalid);
                }
            }
        }
        Ok(())
    }

    /// Checks the rules of the policy, including every template and the taint of derivations.
    pub fn validate(&self) -> Result<()> {
        if self.fields.is_empty()
            || self.fields.len() > crate::fields::MAX_FIELDS
            || !self.fields.iter().all(|f| is_token(&f.name))
            || !unique(self.fields.iter().map(|f| f.name.as_str()))
            || self.operations.is_empty()
            || self.operations.len() > MAX_OPERATIONS
            || !unique(self.operations.iter().map(Operation::name))
        {
            return Err(Error::PolicyInvalid);
        }
        self.operations
            .iter()
            .try_for_each(|o| self.check_operation(o))
    }
}

/// A policy with the signature of the device of its owner.
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
        let message = canonical(POLICY_DOMAIN, &self.policy)?;
        device
            .verify(&message, &self.signature)
            .map_err(|_| Error::PolicySignature)?;
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

    fn secret(name: &str) -> FieldSpec {
        FieldSpec {
            name: name.into(),
            secret: true,
            optional: false,
        }
    }

    fn bearer() -> Policy {
        Policy {
            fields: vec![secret("token")],
            operations: vec![Operation::Http {
                name: "call".into(),
                destinations: vec![Destination::https("api.example.com")],
                methods: vec![Method::Get],
                identity: None,
                steps: vec![Step {
                    request: StepRequest::Caller,
                    inject: vec![Injection {
                        target: Target::Header {
                            name: "Authorization".into(),
                        },
                        template: "Bearer {{token}}".into(),
                    }],
                    capture: vec![],
                }],
            }],
        }
    }

    fn derive_only(template: &str) -> Policy {
        Policy {
            fields: vec![secret("key")],
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
        ] {
            assert_eq!(
                derive_only(template).validate(),
                Err(Error::PolicyInvalid),
                "{template}"
            );
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut p = bearer();
        if let Operation::Http { destinations, .. } = &mut p.operations[0] {
            *destinations = vec![Destination::https("*.example.com")];
        }
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

        let mut p = bearer();
        step_of(&mut p).inject[0].target = Target::Header {
            name: "Host".into(),
        };
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

        let mut p = bearer();
        step_of(&mut p).inject[0].template = "Bearer {{other}}".into();
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

        let mut p = bearer();
        step_of(&mut p).inject[0].template = "{{ $input }}".into();
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

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
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

        // A capture into an undeclared field.
        let mut p = bearer();
        step_of(&mut p).capture.push(Capture {
            source: Source::Json {
                pointer: "/t".into(),
            },
            into: Store::Field {
                name: "nope".into(),
            },
            optional: false,
        });
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));

        // Two operations with one name.
        let mut p = bearer();
        p.operations.push(p.operations[0].clone());
        assert_eq!(p.validate(), Err(Error::PolicyInvalid));
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
