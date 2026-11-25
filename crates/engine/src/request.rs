//! Building the request of one step from the caller request (or the one the policy fixes) and
//! the injections of the step.
//!
//! Every rendered value is placed by its target; the wire bytes are built in one buffer of a
//! length computed up front, so no reallocation leaves a copy of a value behind, and the buffer
//! is a [`Secret`].

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::fields::Fields;
use crate::policy::{
    Destination, Method, Operation, RESERVED_HEADERS, Step, StepRequest, Target, is_token,
};
use crate::secret::Secret;
use crate::template::{Context, Template, Temps, Var, hex, pct};
use crate::{Error, Result};

/// Longest path and query, in bytes.
pub const MAX_PATH: usize = 2048;
/// Most caller headers.
pub const MAX_HEADERS: usize = 64;
/// Longest caller header value, in bytes.
pub const MAX_HEADER_VALUE: usize = 4096;
/// Longest caller body, in bytes.
pub const MAX_BODY: usize = 1024 * 1024;

/// A request the caller asks a node to send with the values of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Destination.
    pub destination: Destination,
    /// Path and query, starting with `/`; it holds `{name}` once for each path parameter.
    pub path: String,
    /// Further headers.
    pub headers: Vec<(String, String)>,
    /// Body; `$body` to the templates.
    pub body: Vec<u8>,
}

impl Request {
    /// Checks the request against an HTTP operation: destination, method, form, the path
    /// parameters its steps fill, and no header the engine or an injection sets.
    pub fn validate(&self, operation: &Operation) -> Result<()> {
        let Operation::Http { methods, steps, .. } = operation else {
            return Err(Error::OperationUnknown);
        };
        if !operation.allows_destination(&self.destination) {
            return Err(Error::DestinationDenied);
        }
        if !methods.contains(&self.method) {
            return Err(Error::MethodDenied);
        }
        let caller_steps = || steps.iter().filter(|s| s.request == StepRequest::Caller);
        let path_ok = self.path.starts_with('/')
            && self.path.len() <= MAX_PATH
            && self.path.bytes().all(|b| b.is_ascii_graphic() && b != b'#');
        let params_ok = caller_steps()
            .flat_map(|s| &s.inject)
            .all(|i| match &i.target {
                Target::PathParam { name } => {
                    self.path.matches(&format!("{{{name}}}")).count() == 1
                }
                _ => true,
            });
        if !path_ok || !params_ok || self.body.len() > MAX_BODY || self.headers.len() > MAX_HEADERS
        {
            return Err(Error::RequestInvalid);
        }
        let injected: Vec<String> = caller_steps()
            .flat_map(|s| &s.inject)
            .filter_map(|i| match &i.target {
                Target::Header { name } => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect();
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            let value_ok = value.len() <= MAX_HEADER_VALUE
                && value
                    .bytes()
                    .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b));
            if !is_token(name)
                || RESERVED_HEADERS.contains(&lower.as_str())
                || injected.contains(&lower)
                || !value_ok
            {
                return Err(Error::RequestInvalid);
            }
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
                let request = caller.ok_or(Error::RequestInvalid)?;
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
                destination: destination
                    .as_ref()
                    .or(destinations.first())
                    .ok_or(Error::PolicyInvalid)?,
                path,
                headers: &[],
                body: &[],
            },
        })
    }

    fn vars(&self, unix_ms: u64) -> HashMap<Var, Vec<u8>> {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let nonce = hex(&random).to_vec();
        OsRng.fill_bytes(&mut random);
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

/// Renders the injections of `step` and builds the HTTP/1.1 bytes. `secret` says which names
/// are secret.
pub(crate) fn build(
    step: &Step,
    request: &Outbound<'_>,
    fields: &Fields,
    temps: &Temps,
    unix_ms: u64,
    secret: &dyn Fn(&str) -> bool,
) -> Result<Built> {
    let ctx = Context {
        fields,
        temps,
        vars: request.vars(unix_ms),
        unix: unix_ms / 1000,
    };

    let mut headers: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut query: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut params: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut body: Option<Zeroizing<Vec<u8>>> = None;
    let mut tainted = Vec::new();

    for injection in &step.inject {
        let template = Template::parse(&injection.template)?;
        let value = template.render(&ctx)?;
        if template.tainted(secret) && !matches!(injection.target, Target::Body) {
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
        let text = core::str::from_utf8(&path).map_err(|_| Error::RequestInvalid)?;
        let (before, after) = text
            .split_once(placeholder.as_str())
            .ok_or(Error::RequestInvalid)?;
        let mut next = Zeroizing::new(Vec::with_capacity(before.len() + value.len() + after.len()));
        next.extend_from_slice(before.as_bytes());
        next.extend_from_slice(value);
        next.extend_from_slice(after.as_bytes());
        path = next;
    }

    let body_bytes: &[u8] = body.as_deref().map_or(request.body, |b| b.as_slice());
    let port = if request.destination.port == 443 {
        String::new()
    } else {
        format!(":{}", request.destination.port)
    };
    let length_line = format!("Content-Length: {}\r\n", body_bytes.len());
    let capacity = 64
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
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body_bytes);
    Ok(Built { wire, tainted })
}
