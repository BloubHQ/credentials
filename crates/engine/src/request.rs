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
use crate::policy::{Destination, Kinds, Method, Operation, Send, StepRequest, Target};
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

    /// Checks the request against an HTTPS operation: the destination against its
    /// connection, and the method, path, path parameters, query, headers and body against the
    /// contract of every `send` that takes the caller's request.
    pub fn validate(&self, operation: &Operation) -> Result<()> {
        if !operation.takes_request() {
            return Err(invalid("the operation takes no request"));
        }
        if !operation.allows_destination(&self.destination) {
            return Err(self.destination.denied());
        }
        for (contract, send) in operation.caller_sends() {
            let names = |pick: fn(&Target) -> Option<&str>| -> Vec<&str> {
                send.inject.iter().filter_map(|i| pick(&i.target)).collect()
            };
            let injected = names(|t| match t {
                Target::Query { name } => Some(name),
                _ => None,
            });
            let params = names(|t| match t {
                Target::PathParam { name } => Some(name),
                _ => None,
            });
            contract.check(self, &injected, &params)?;
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
    /// The request of `send`: the caller request, or the one the policy fixes.
    pub fn of(
        send: &'a Send,
        destinations: &'a [Destination],
        caller: Option<&'a Request>,
    ) -> Result<Self> {
        Ok(match &send.request {
            Some(StepRequest::Caller(_)) => {
                let request = caller.ok_or(invalid("the operation needs a request"))?;
                Self {
                    method: request.method,
                    destination: &request.destination,
                    path: &request.path,
                    headers: &request.headers,
                    body: &request.body,
                }
            }
            Some(StepRequest::Fixed {
                method,
                path,
                destination,
            }) => Self {
                method: *method,
                destination: match (destination, destinations) {
                    (Some(d), _) => d,
                    (None, [only]) => only,
                    _ => return Err(Error::policy("send", "fixed request without destination")),
                },
                path,
                headers: &[],
                body: &[],
            },
            None => return Err(Error::policy("send", "an HTTPS send needs a request")),
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
    pub kinds: &'a Kinds<'a>,
    pub fields: &'a Fields,
    pub temps: &'a Temps,
    pub unix_ms: u64,
    pub budget: &'a Budget,
}

/// What kind of request a build makes.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Wire<'k> {
    /// A request on its own connection (`Connection: close`).
    Plain,
    /// A unary gRPC call: the body framed as one message, `content-type: application/grpc`
    /// and `te: trailers`.
    Grpc,
    /// The opening handshake of a WebSocket, with this `Sec-WebSocket-Key`.
    Upgrade(&'k str),
}

/// Renders the injections of `send` and builds the HTTP/1.1 bytes.
pub(crate) fn build(
    send: &Send,
    request: &Outbound<'_>,
    inputs: &Inputs<'_>,
    wire_kind: Wire<'_>,
) -> Result<Built> {
    let ctx = Context {
        fields: inputs.fields,
        temps: inputs.temps,
        vars: request.vars(inputs.unix_ms),
        unix: inputs.unix_ms / 1000,
        budget: inputs.budget,
    };
    let kind = |name: &str| inputs.kinds.kind(name);

    let mut headers: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut query: Vec<(&str, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut params: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut body: Option<Zeroizing<Vec<u8>>> = None;
    let mut tainted = Vec::new();

    for injection in &send.inject {
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
    let framed;
    let body_bytes: &[u8] = if matches!(wire_kind, Wire::Grpc) {
        framed = crate::grpc::frame(body_bytes)?;
        &framed
    } else {
        body_bytes
    };
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
    let upgrade;
    let fixed: &[u8] = match wire_kind {
        Wire::Plain => FIXED,
        Wire::Grpc => crate::grpc::HEADERS,
        Wire::Upgrade(key) => {
            upgrade = format!(
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
            );
            upgrade.as_bytes()
        }
    };
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
        + fixed.len()
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
    out.extend_from_slice(fixed);
    out.extend_from_slice(body_bytes);
    Ok(Built { wire, tainted })
}
