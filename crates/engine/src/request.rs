//! Building the request of one step from the caller request (or the one the policy fixes) and
//! the injections of the step.
//!
//! The injections render in dependency order (each template reads the request as it is sent,
//! but for its own target: `docs/policy.md`, Injection order); every rendered value is placed
//! by its target, in the order the policy lists them; the wire bytes are built in one buffer
//! of a length computed up front, so no reallocation leaves a copy of a value behind, and the
//! buffer is a [`Secret`].

use std::collections::HashMap;

use getrandom::SysRng;
use getrandom::rand_core::{Rng as _, UnwrapErr};
use zeroize::{Zeroize as _, Zeroizing};

use crate::fields::Fields;
use crate::policy::{Destination, Injection, Kinds, Method, Operation, Send, StepRequest, Target};
use crate::primitives::{hex, pct};
use crate::secret::Secret;
use crate::template::{Budget, Context, Template, Temps, Var};

mod order;

use crate::{Error, Result};
pub(crate) use order::{Plan, injects_header, injects_query};

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

    /// The variables that do not depend on the injections: one `$nonce` and one `$boundary`
    /// for the whole request.
    fn fixed_vars(&self, unix_ms: u64) -> HashMap<Var, Vec<u8>> {
        let mut random = [0u8; 16];
        UnwrapErr(SysRng).fill_bytes(&mut random);
        let nonce = hex(&random).to_vec();
        UnwrapErr(SysRng).fill_bytes(&mut random);
        let boundary = format!("boundary-{}", String::from_utf8_lossy(&hex(&random)));
        HashMap::from([
            (Var::Method, self.method.as_str().as_bytes().to_vec()),
            (Var::Host, self.destination.host.as_bytes().to_vec()),
            (Var::Port, self.destination.port.to_string().into_bytes()),
            (Var::Scheme, b"https".to_vec()),
            (Var::Authority, self.authority().into_bytes()),
            (Var::Unix, (unix_ms / 1000).to_string().into_bytes()),
            (Var::UnixMs, unix_ms.to_string().into_bytes()),
            (Var::Boundary, boundary.into_bytes()),
            (Var::Nonce, nonce),
        ])
    }

    /// The host in lowercase, then `:` and the port unless it is 443 (RFC 9421 section
    /// 2.2.3).
    fn authority(&self) -> String {
        let host = self.destination.host.to_ascii_lowercase();
        match self.destination.port {
            443 => host,
            port => format!("{host}:{port}"),
        }
    }
}

/// The request as it is sent, seen from one injection: the values rendered so far but the
/// injection's own (`own`). With no `own` and every value rendered, the request on the wire.
struct View<'v> {
    request: &'v Outbound<'v>,
    inject: &'v [Injection],
    values: &'v [Option<Zeroizing<Vec<u8>>>],
    own: Option<usize>,
}

impl View<'_> {
    /// The rendered values other than `own`'s, as they go on the wire, in listed order, with
    /// their targets.
    fn others(&self) -> impl Iterator<Item = (&Target, &[u8])> {
        self.inject
            .iter()
            .zip(self.values)
            .enumerate()
            .filter(move |(j, _)| Some(*j) != self.own)
            .filter_map(|(_, (i, v))| v.as_deref().map(|v| (&i.target, v.as_slice())))
    }

    /// The path with the path parameters filled, and the caller's query.
    fn path(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut path = Zeroizing::new(self.request.path.as_bytes().to_vec());
        for (target, value) in self.others() {
            let Target::PathParam { name } = target else {
                continue;
            };
            let placeholder = format!("{{{name}}}");
            let at = crate::response::find(&path, placeholder.as_bytes())
                .ok_or(invalid("path parameter missing"))?;
            let rest = at + placeholder.len();
            let mut next = Zeroizing::new(Vec::with_capacity(
                path.len().saturating_sub(placeholder.len()) + value.len(),
            ));
            next.extend_from_slice(path.get(..at).unwrap_or_default());
            next.extend_from_slice(value);
            next.extend_from_slice(path.get(rest..).unwrap_or_default());
            path = next;
        }
        Ok(path)
    }

    /// The injected query parameters, encoded, in listed order.
    fn query(&self) -> Vec<(&str, &[u8])> {
        self.others()
            .filter_map(|(target, value)| match target {
                Target::Query { name } => Some((name.as_str(), value)),
                _ => None,
            })
            .collect()
    }

    /// The request target: the filled path, then each injected query parameter.
    fn target(&self) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.path()?;
        let query = self.query();
        let len = path.len()
            + query
                .iter()
                .map(|(n, v)| n.len() + v.len() + 2)
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&path);
        let mut has_query = path.contains(&b'?');
        for (name, value) in query {
            out.push(if has_query { b'&' } else { b'?' });
            has_query = true;
            out.extend_from_slice(name.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value);
        }
        Ok(out)
    }

    /// The injected headers, in listed order.
    fn injected_headers(&self) -> Vec<(&str, &[u8])> {
        self.others()
            .filter_map(|(target, value)| match target {
                Target::Header { name } => Some((name.as_str(), value)),
                _ => None,
            })
            .collect()
    }

    /// Every header a template may read: the caller's, then the injected ones.
    fn headers(&self) -> Vec<(&str, &[u8])> {
        let mut out: Vec<(&str, &[u8])> = self
            .request
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes()))
            .collect();
        out.extend(self.injected_headers());
        out
    }

    /// The body: the injected one, else the caller's.
    fn body(&self) -> &[u8] {
        self.others()
            .find(|(target, _)| **target == Target::Body)
            .map_or(self.request.body, |(_, value)| value)
    }

    /// Adds the variables `template` reads that depend on the injections.
    fn add_vars(&self, template: &Template, vars: &mut HashMap<Var, Vec<u8>>) -> Result<()> {
        let reads = template.vars();
        let any = |list: &[Var]| reads.iter().any(|v| list.contains(v));
        if any(&[
            Var::Path,
            Var::PathName,
            Var::Query,
            Var::QueryParam,
            Var::TargetUri,
        ]) {
            let target = self.target()?;
            let (pathname, query) = match target.iter().position(|b| *b == b'?') {
                Some(at) => (
                    target.get(..at).unwrap_or_default(),
                    target.get(at + 1..).unwrap_or_default(),
                ),
                None => (target.as_slice(), &[][..]),
            };
            let authority = self.request.authority();
            let mut uri = Vec::with_capacity(8 + authority.len() + target.len());
            uri.extend_from_slice(b"https://");
            uri.extend_from_slice(authority.as_bytes());
            uri.extend_from_slice(&target);
            vars.insert(Var::PathName, pathname.to_vec());
            vars.insert(Var::Query, query.to_vec());
            vars.insert(Var::Path, target.to_vec());
            vars.insert(Var::TargetUri, uri);
        }
        if any(&[Var::Body]) {
            vars.insert(Var::Body, self.body().to_vec());
        }
        Ok(())
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

/// Renders the injections of `send` in their order ([`Plan`]) and builds the HTTP/1.1
/// bytes. Each template reads the request as it is sent but for its own target.
pub(crate) fn build(
    send: &Send,
    request: &Outbound<'_>,
    inputs: &Inputs<'_>,
    wire_kind: Wire<'_>,
) -> Result<Built> {
    let plan =
        Plan::new(&send.inject).map_err(|fault| Error::TemplateInvalid { rule: fault.rule() })?;
    let kind = |name: &str| inputs.kinds.kind(name);
    let props = plan.props(&send.inject, &kind);
    let fixed_vars = request.fixed_vars(inputs.unix_ms);

    let mut values: Vec<Option<Zeroizing<Vec<u8>>>> = send.inject.iter().map(|_| None).collect();
    let mut tainted = Vec::new();
    for &i in &plan.order {
        let (Some(injection), Some(template)) = (send.inject.get(i), plan.templates.get(i)) else {
            return Err(invalid("injection out of range"));
        };
        let value = {
            let view = View {
                request,
                inject: &send.inject,
                values: &values,
                own: Some(i),
            };
            let mut vars = fixed_vars.clone();
            view.add_vars(template, &mut vars)?;
            let headers = view.headers();
            let mut ctx = Context {
                fields: inputs.fields,
                temps: inputs.temps,
                vars,
                headers: &headers,
                unix: inputs.unix_ms / 1000,
                budget: inputs.budget,
            };
            let rendered = template.render(&ctx);
            // The variables can hold what other injections put in the request.
            ctx.vars.values_mut().for_each(|v| v.zeroize());
            rendered?
        };
        // A template that breaks a rule counts as tainted, as the analysis takes it.
        let reversible = props
            .get(i)
            .is_none_or(|p| p.as_ref().map_or(true, |p| p.tainted()));
        if reversible && !matches!(injection.target, Target::Body) {
            tainted.push(value.clone());
        }
        let placed = match &injection.target {
            Target::Header { .. } => {
                if !value
                    .iter()
                    .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
                {
                    return Err(Error::SecretInvalid);
                }
                value
            }
            Target::Query { .. } | Target::PathParam { .. } => pct(&value),
            Target::Body => value,
        };
        if let Some(slot) = values.get_mut(i) {
            *slot = Some(placed);
        }
    }

    let view = View {
        request,
        inject: &send.inject,
        values: &values,
        own: None,
    };
    let target = view.target()?;
    let headers = view.injected_headers();
    let body_bytes = view.body();
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
        + target.len()
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
    out.extend_from_slice(&target);
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
