//! The `run` step: code that computes on secret bytes in the sandbox of layer 3
//! (`docs/design.md`, sections 2 and 8e).
//!
//! The code is never the caller's or an agent's: it is a module the node fetches from the
//! destination's own origin (its URL, and optionally its SHA-256, are in the signed policy), or
//! a reviewed library compiled into the node. Its output is **confined**: it, and every value
//! computed from it, may only go into a request the policy fixes to that same origin. It never
//! reaches `return`, a request of the caller, another destination or the log. The origin
//! already receives the secret, so running its own code on it gives it nothing new.

use serde::{Deserialize, Serialize};

use super::{
    Checked, Connection, Destination, Kinds, Open, Operation, Policy, Step, StepRequest, Store,
    ensure, fail, is_token, path_fault,
};
use crate::template::{Template, Var};

/// Most inputs of a `run` step.
pub const MAX_RUN_INPUTS: usize = sandbox::MAX_INPUTS;
/// Longest module URL.
pub const MAX_URL: usize = 2048;

/// Where the code of a `run` step comes from: a URL on the destination's own origin, with an
/// optional SHA-256 pin, or a reviewed library of the node. Exactly one of `url` and
/// `library`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSource {
    /// `https://host[:port]/path`: the host and port are one of the connection's
    /// destinations, and the origin the output may go to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The SHA-256 of the module, 64 lowercase hex digits. Without it the site may change
    /// the code at any time; the summary flags it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The name of a reviewed library module ([`sandbox::LIBRARIES`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
}

/// The `run` step: runs `entry` of a module on rendered `inputs` (secrets allowed) and keeps
/// the output under the name `into`, confined to the module's origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunModule {
    /// The module.
    pub module: ModuleSource,
    /// The exported function `() -> ()` to call.
    pub entry: String,
    /// Templates rendered into the inputs, in order (at most 16).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<String>,
    /// The name of the output.
    pub into: String,
    /// For a library: the destination its output may go to. It may be left out when the
    /// connection has exactly one concrete destination. A URL module's origin is its URL's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Destination>,
}

/// A module, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleRef<'a> {
    /// Fetched with `GET path` from `origin` over the operation's connection.
    Url {
        /// Host and port.
        origin: Destination,
        /// Path and query.
        path: &'a str,
        /// The pin.
        sha256: Option<[u8; 32]>,
    },
    /// A reviewed library module.
    Library(&'a str),
}

/// Splits `https://host[:port]/path` into the destination and the path, or `None`.
pub fn parse_url(url: &str) -> Option<(Destination, &str)> {
    if url.len() > MAX_URL {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let slash = rest.find('/')?;
    let (authority, path) = rest.split_at(slash);
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            let digits =
                !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
            (
                host,
                if digits {
                    port.parse::<u16>().ok()?
                } else {
                    return None;
                },
            )
        }
        None => (authority, 443),
    };
    // The host as written: lowercase, so the summary shows what is fetched.
    let destination = Destination {
        host: host.to_string(),
        port,
    };
    (destination.is_concrete() && path_fault(path, false).is_none()).then_some((destination, path))
}

fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let text = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

impl RunModule {
    /// The module, or `None` when the source is malformed.
    pub fn source(&self) -> Option<ModuleRef<'_>> {
        match (&self.module.url, &self.module.library) {
            (Some(url), None) => {
                let (origin, path) = parse_url(url)?;
                let sha256 = match &self.module.sha256 {
                    Some(hex) => Some(parse_sha256(hex)?),
                    None => None,
                };
                Some(ModuleRef::Url {
                    origin,
                    path,
                    sha256,
                })
            }
            (None, Some(name)) if self.module.sha256.is_none() => Some(ModuleRef::Library(name)),
            _ => None,
        }
    }

    /// The origin the output may go to, on the connection `open`.
    pub fn origin(&self, open: &Open) -> Option<Destination> {
        match self.source()? {
            ModuleRef::Url { origin, .. } => Some(origin),
            ModuleRef::Library(_) => match &self.destination {
                Some(d) => Some(d.clone()),
                None => match open.destinations.as_slice() {
                    [only] if only.is_concrete() => Some(only.clone()),
                    _ => None,
                },
            },
        }
    }

    /// How the module is named in a summary: its URL, or `library <name>`.
    pub fn module_name(&self) -> String {
        match (&self.module.url, &self.module.library) {
            (Some(url), _) => url.clone(),
            (None, Some(name)) => format!("library {name}"),
            (None, None) => String::new(),
        }
    }

    /// True for a module fetched without a SHA-256 pin.
    pub fn unpinned(&self) -> bool {
        self.module.url.is_some() && self.module.sha256.is_none()
    }
}

/// True when the template reads one of `names`, or does not parse.
fn reads_any(template: &str, names: &[&str]) -> bool {
    match Template::parse(template) {
        Ok(t) => t.names().into_iter().any(|n| names.contains(&n)),
        Err(_) => true,
    }
}

impl Policy {
    /// Checks one `run` step: the connection, where the module comes from, the entry, the
    /// inputs and the name of the output.
    pub(super) fn check_run(
        &self,
        at: &str,
        kinds: &Kinds<'_>,
        open: Option<&Open>,
        run: &RunModule,
        known: &[&str],
    ) -> Checked {
        let Some(open) = open.filter(|o| o.connection == Connection::Https) else {
            return fail(
                at,
                "run needs an HTTPS connection: its output goes only into a request to the module's origin",
            );
        };
        let Some(source) = run.source() else {
            return fail(
                format!("{at}.module"),
                "module is a url on https (with an optional sha256 of 64 lowercase hex digits) or a library",
            );
        };
        match source {
            ModuleRef::Url { origin, .. } => {
                ensure(
                    run.destination.is_none(),
                    || format!("{at}.destination"),
                    "a module URL names its origin; destination is for a library",
                )?;
                ensure(
                    open.destinations.iter().any(|d| d.matches(&origin)),
                    || format!("{at}.module.url"),
                    "the module comes from the destination's own origin: a URL on one of the connection's destinations",
                )?;
            }
            ModuleRef::Library(name) => {
                ensure(
                    sandbox::library(name).is_some(),
                    || format!("{at}.module.library"),
                    "unknown library module",
                )?;
                let origin = run.origin(open);
                ensure(
                    origin.is_some_and(|d| {
                        d.is_concrete() && open.destinations.iter().any(|p| p.matches(&d))
                    }),
                    || format!("{at}.destination"),
                    "a library's output needs a concrete destination of the connection (it may be left out when the connection has one)",
                )?;
            }
        }
        ensure(
            is_token(&run.entry),
            || format!("{at}.entry"),
            "entry is not a token",
        )?;
        ensure(
            run.inputs.len() <= MAX_RUN_INPUTS,
            || format!("{at}.inputs"),
            "at most 16 inputs",
        )?;
        for (i, input) in run.inputs.iter().enumerate() {
            self.check_template(
                &format!("{at}.inputs[{i}]"),
                kinds,
                input,
                known,
                Var::in_compute,
            )?;
        }
        ensure(
            is_token(&run.into) && !self.is_field(&run.into) && !known.contains(&run.into.as_str()),
            || format!("{at}.into"),
            "run into a new token name (never a field)",
        )
    }
}

/// Checks that the output of every `run` step of the operation, and every value computed
/// from it, goes only into requests the policy fixes to the module's origin. Run after the
/// steps are checked one by one.
pub(super) fn check_confined(at: &str, operation: &Operation) -> Checked {
    let Some(open) = operation.open() else {
        return Ok(());
    };
    let mut origin: Option<Destination> = None;
    for (i, step) in operation.steps.iter().enumerate() {
        if let Step::Run(run) = step {
            let here = run.origin(open);
            match (&origin, here) {
                (_, None) => return fail(format!("{at}.steps[{i}]"), "run step without an origin"),
                (None, Some(d)) => origin = Some(d),
                (Some(first), Some(d)) => ensure(
                    *first == d,
                    || format!("{at}.steps[{i}]"),
                    "every run step of an operation has the same origin",
                )?,
            }
        }
    }
    let Some(origin) = origin else {
        return Ok(());
    };
    let mut confined: Vec<&str> = Vec::new();
    // True while the last request carried a confined value: what its response gives into
    // temporary values may echo it, so those values are confined too.
    let mut carried = false;
    for (i, step) in operation.steps.iter().enumerate() {
        let at = format!("{at}.steps[{i}]");
        match step {
            Step::Run(run) => confined.push(&run.into),
            Step::Compute(c) => {
                if reads_any(&c.template, &confined) {
                    confined.push(&c.into);
                }
            }
            Step::Send(send) => {
                carried = send
                    .inject
                    .iter()
                    .any(|j| reads_any(&j.template, &confined));
                let fixed_to = match &send.request {
                    Some(StepRequest::Fixed {
                        destination: Some(d),
                        ..
                    }) => Some(d.clone()),
                    Some(StepRequest::Fixed {
                        destination: None, ..
                    }) => match open.destinations.as_slice() {
                        [only] => Some(only.clone()),
                        _ => None,
                    },
                    _ => None,
                };
                for (j, injection) in send.inject.iter().enumerate() {
                    if reads_any(&injection.template, &confined) {
                        ensure(
                            fixed_to.as_ref() == Some(&origin),
                            || format!("{at}.inject[{j}]"),
                            "the output of a run step goes only into a request the policy fixes to the origin of its module",
                        )?;
                    }
                }
                if let Some(template) = &send.template {
                    if reads_any(template, &confined) {
                        return fail(
                            format!("{at}.template"),
                            "the output of a run step goes only into a request the policy fixes to the origin of its module",
                        );
                    }
                }
            }
            Step::Return(ret) => {
                if let Some(template) = &ret.template {
                    if reads_any(template, &confined) {
                        return fail(
                            format!("{at}.template"),
                            "the output of a run step never goes back to the caller",
                        );
                    }
                }
            }
            Step::Receive(receive) => {
                if carried {
                    confined.extend(receive.capture.iter().filter_map(|c| match &c.into {
                        Store::Temp { name, .. } => Some(name.as_str()),
                        // A field is a secret of the record (a capture into a public field is
                        // refused), analysed wherever it is used.
                        Store::Field { .. } => None,
                    }));
                }
            }
            Step::Open(_) | Step::Repeat(_) | Step::If(_) => {}
        }
    }
    Ok(())
}

/// The summary line of a `run` step.
pub(super) fn summary_line(run: &RunModule, open: Option<&Open>) -> Vec<String> {
    let origin = open
        .and_then(|o| run.origin(o))
        .map(|d| format!("{}:{}", d.host, d.port))
        .unwrap_or_default();
    let pin = match &run.module.sha256 {
        Some(hex) => format!(" (sha256 {hex})"),
        None if run.module.url.is_some() => " (not pinned)".into(),
        None => String::new(),
    };
    let mut out = vec![format!(
        "  run {} of {}{pin} on [{}] into {}, only to {origin}",
        run.entry,
        run.module_name(),
        run.inputs.join(", "),
        run.into
    )];
    if run.unpinned() {
        out.push(format!(
            "  ! the module {} has no sha256: the site can change the code that reads the secrets",
            run.module_name()
        ));
    }
    out
}
