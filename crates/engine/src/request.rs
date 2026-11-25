//! Building the request of one step from the caller request (or the one the policy fixes) and
//! the injections of the step.
//!
//! Every rendered value is placed by its target; the wire bytes are built in one buffer of a
//! length computed up front, so no reallocation leaves a copy of a value behind, and the buffer
//! is a [`Secret`].

use std::collections::HashMap;

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use zeroize::Zeroizing;

use crate::fields::Fields;
use crate::policy::{
    Destination, Method, Operation, Policy, RESERVED_HEADERS, Step, StepRequest, Target,
    check_path, is_token, under,
};
use crate::primitives::{hex, pct};
use crate::secret::Secret;
use crate::template::{Budget, Context, Template, Temps, Var};
use crate::{Error, Result};

/// Longest path and query, in bytes.
pub const MAX_PATH: usize = 2048;
/// Most caller headers.
pub const MAX_HEADERS: usize = 64;
/// Longest caller header value, in bytes.
pub const MAX_HEADER_VALUE: usize = 4096;
/// Longest caller body, in bytes.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

fn invalid(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

/// A request the caller asks a node to send with the values of a record. In JSON the body is
/// base64url.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Destination (a concrete host).
    pub destination: Destination,
    /// Path and query, starting with `/`; it holds `{name}` once for each path parameter.
    pub path: String,
    /// Further headers; each must be one the operation lists.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Body; `$body` to the templates.
    #[serde(default, with = "crate::encoding::b64_vec")]
    pub body: Vec<u8>,
}

impl Request {
    /// A request without headers or body.
    pub fn new(method: Method, destination: Destination, path: &str) -> Self {
        Self {
            method,
            destination,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Checks the request against an HTTP operation: destination, method, path, the path
    /// parameters its steps fill, and the headers.
    pub fn validate(&self, operation: &Operation) -> Result<()> {
        let Operation::Http {
            methods,
            paths,
            caller_headers,
            steps,
            ..
        } = operation
        else {
            return Err(operation.unknown());
        };
        if !operation.allows_destination(&self.destination) {
            return Err(self.destination.denied());
        }
        if !methods.contains(&self.method) {
            return Err(Error::MethodDenied {
                method: self.method.as_str().to_string(),
            });
        }
        if !check_path(&self.path) {
            return Err(invalid(
                "path must start with / and hold no fragment, dot segment or encoded separator",
            ));
        }
        if !paths.iter().any(|p| under(&self.path, p)) {
            return Err(Error::PathDenied {
                path: self.path.split('?').next().unwrap_or_default().to_string(),
            });
        }
        let caller_steps = || steps.iter().filter(|s| s.request == StepRequest::Caller);
        let params_ok = caller_steps()
            .flat_map(|s| &s.inject)
            .all(|i| match &i.target {
                Target::PathParam { name } => {
                    self.path.matches(&format!("{{{name}}}")).count() == 1
                }
                _ => true,
            });
        if !params_ok {
            return Err(invalid("path must hold each path parameter once"));
        }
        if self.body.len() > MAX_BODY {
            return Err(invalid("body too large"));
        }
        if self.headers.len() > MAX_HEADERS {
            return Err(invalid("too many headers"));
        }
        let mut seen: Vec<String> = Vec::with_capacity(self.headers.len());
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            let value_ok = value.len() <= MAX_HEADER_VALUE
                && value
                    .bytes()
                    .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b));
            if !is_token(name) || !value_ok || RESERVED_HEADERS.contains(&lower.as_str()) {
                return Err(invalid("header name or value malformed or reserved"));
            }
            if !caller_headers.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(invalid("header not allowed by the operation"));
            }
            if seen.contains(&lower) {
                return Err(invalid("header repeated"));
            }
            seen.push(lower);
        }
        Ok(())
    }
}

/// The request one step sends, before injections.
pub(crate) struct Outbound<'a> {
    pub method: Method,
    pub destination: &'a Destination,
    pub path: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl<'a> Outbound<'a> {
    /// The request of `step`: the caller request, or the one the policy fixes.
    pub fn of(
        step: &'a Step,
        destinations: &'a [Destination],
        caller: Option<&'a Request>,
    ) -> Result<Self> {
        Ok(match &step.request {
            StepRequest::Caller => {
                let request = caller.ok_or(invalid("the operation needs a request"))?;
                Self {
                    method: request.method,
                    destination: &request.destination,
                    path: &request.path,
                    headers: &request.headers,
                    body: &request.body,
                }
            }
            StepRequest::Fixed {
                method,
                path,
                destination,
            } => Self {
                method: *method,
                destination: match (destination, destinations) {
                    (Some(d), _) => d,
                    (None, [only]) => only,
                    _ => return Err(Error::policy("step", "fixed request without destination")),
                },
                path,
                headers: &[],
                body: &[],
            },
        })
    }

    fn vars(&self, unix_ms: u64) -> HashMap<Var, Vec<u8>> {
        let mut random = [0u8; 16];
        UnwrapErr(SysRng).fill_bytes(&mut random);
        let nonce = hex(&random).to_vec();
        UnwrapErr(SysRng).fill_bytes(&mut random);
        let boundary = format!("boundary-{}", String::from_utf8_lossy(&hex(&random)));
        let (pathname, query) = self.path.split_once('?').unwrap_or((self.path, ""));
        HashMap::from([
            (Var::Method, self.method.as_str().as_bytes().to_vec()),
            (Var::Host, self.destination.host.as_bytes().to_vec()),
            (Var::Path, self.path.as_bytes().to_vec()),
            (Var::PathName, pathname.as_bytes().to_vec()),
            (Var::Query, query.as_bytes().to_vec()),
            (Var::Body, self.body.to_vec()),
            (Var::Unix, (unix_ms / 1000).to_string().into_bytes()),
            (Var::UnixMs, unix_ms.to_string().into_bytes()),
            (Var::Boundary, boundary.into_bytes()),
            (Var::Nonce, nonce),
        ])
    }
}

/// The wire bytes and the rendered values that hold a secret in reversible form.
pub(crate) struct Built {
    pub wire: Secret<Vec<u8>>,
    pub tainted: Vec<Zeroizing<Vec<u8>>>,
}

/// What a build reads besides the step and its request.
pub(crate) struct Inputs<'a> {
    pub policy: &'a Policy,
    pub operation: &'a Operation,
    pub fields: &'a Fields,
    pub temps: &'a Temps,
    pub unix_ms: u64,
    pub budget: &'a Budget,
}

/// Renders the injections of `step` and builds the HTTP/1.1 bytes.
pub(crate) fn build(step: &Step, request: &Outbound<'_>, inputs: &Inputs<'_>) -> Result<Built> {
    let ctx = Context {
        fields: inputs.fields,
        temps: inputs.temps,
        vars: request.vars(inputs.unix_ms),
        unix: inputs.unix_ms / 1000,
        budget: inputs.budget,
    };
    let kind = |name: &str| inputs.policy.name_kind(inputs.operation, name);

    let mut headers: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut query: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut params: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut body: Option<Zeroizing<Vec<u8>>> = None;
    let mut tainted = Vec::new();

    for injection in &step.inject {
        let template = Template::parse(&injection.template)?;
        let value = template.render(&ctx)?;
        if template.tainted(&kind) && !matches!(injection.target, Target::Body) {
            tainted.push(value.clone());
        }
        match &injection.target {
            Target::Header { name } => {
                if !value
                    .iter()
                    .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
                {
                    return Err(Error::SecretInvalid);
                }
                headers.push((name, value));
            }
            Target::Query { name } => query.push((name, pct(&value))),
            Target::PathParam { name } => params.push((format!("{{{name}}}"), pct(&value))),
            Target::Body => body = Some(value),
        }
    }

    let mut path = Zeroizing::new(request.path.as_bytes().to_vec());
    for (placeholder, value) in &params {
        let text = core::str::from_utf8(&path).map_err(|_| invalid("path not UTF-8"))?;
        let (before, after) = text
            .split_once(placeholder.as_str())
            .ok_or(invalid("path parameter missing"))?;
        let mut next = Zeroizing::new(Vec::with_capacity(before.len() + value.len() + after.len()));
        next.extend_from_slice(before.as_bytes());
        next.extend_from_slice(value);
        next.extend_from_slice(after.as_bytes());
        path = next;
    }

    let body_bytes: &[u8] = body.as_deref().map_or(request.body, |b| b.as_slice());
    if body_bytes.len() > MAX_BODY {
        return Err(Error::Budget { what: "body" });
    }
    let port = if request.destination.port == 443 {
        String::new()
    } else {
        format!(":{}", request.destination.port)
    };
    let length_line = format!("Content-Length: {}\r\n", body_bytes.len());
    const FIXED: &[u8] = b"Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
    let capacity = 32
        + request.method.as_str().len()
        + path.len()
        + query
            .iter()
            .map(|(n, v)| n.len() + v.len() + 2)
            .sum::<usize>()
        + request.destination.host.len()
        + port.len()
        + headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum::<usize>()
        + request
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum::<usize>()
        + length_line.len()
        + FIXED.len()
        + body_bytes.len();

    let mut wire = Secret::new(Vec::with_capacity(capacity));
    let out = wire.expose_mut();
    out.extend_from_slice(request.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(&path);
    let mut has_query = path.contains(&b'?');
    for (name, value) in &query {
        out.push(if has_query { b'&' } else { b'?' });
        has_query = true;
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
    }
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(request.destination.host.as_bytes());
    out.extend_from_slice(port.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    for (name, value) in request.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(length_line.as_bytes());
    out.extend_from_slice(FIXED);
    out.extend_from_slice(body_bytes);
    Ok(Built { wire, tainted })
}
