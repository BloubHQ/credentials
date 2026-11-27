//! The `run` step: code that computes on secret bytes in the sandbox of layer 3
//! (`docs/design.md`, sections 2 and 8e).
//!
//! The code is never the caller's or an agent's: it is a module the node fetches from the
//! destination's own origin (its URL, and optionally its SHA-256, are in the signed policy), or
//! a reviewed library compiled into the node. Its output is **confined**: it, and every value
//! computed from it, may only go into a request the policy fixes to that same origin. It never
//! reaches `return`, a request of the caller, another destination or the log. The origin
//! already receives the secret, so running its own code on it gives it nothing new.
//!
//! A JavaScript source runs the same way: the step names the reviewed engine module
//! ([`sandbox::JS`]) as its library and the `script`, a URL on the destination's own origin
//! pinned by its SHA-256 (required). The output goes to the script's origin. The bounds of a
//! run (fuel, memory, time, the size of a script) may be lowered by the signed policy
//! (`limits`), never raised past the node's.

use serde::{Deserialize, Serialize};

use super::{
    Checked, Connection, Destination, Kinds, Open, Operation, Policy, Step, StepRequest, Store,
    ensure, fail, is_token, path_fault,
};
use crate::template::{Template, Var};

/// Most inputs of a `run` step.
pub const MAX_RUN_INPUTS: usize = sandbox::MAX_INPUTS;
/// Most inputs of a `run` step that runs a script: the engine takes two for the source and
/// the function name.
pub const MAX_SCRIPT_INPUTS: usize = sandbox::MAX_SCRIPT_ARGS;
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
    /// the code at any time; the summary flags it. For a library it is optional and pins the
    /// release's bytes: a node whose library differs refuses the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The name of a reviewed library module ([`sandbox::LIBRARIES`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
}

/// A JavaScript source for the engine module: fetched with `GET` from the destination's own
/// origin and pinned.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptSource {
    /// `https://host[:port]/path` on one of the connection's destinations: where the script
    /// comes from and where the output may go.
    pub url: String,
    /// The SHA-256 of the script's bytes, 64 lowercase hex digits. Required: the engine runs
    /// only the source the owner signed.
    pub sha256: String,
}

/// Bounds of one `run`, each at most the node's ([`sandbox::Limits::default`]). A bound left
/// out is the node's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    /// Fuel, 1 to [`sandbox::MAX_FUEL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
    /// Linear memory in bytes, 1 to [`sandbox::MAX_MEMORY`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<u64>,
    /// Wall-clock milliseconds, 1 to [`sandbox::MAX_TIME`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<u64>,
    /// For a script: its largest size in bytes, 1 to [`sandbox::MAX_SCRIPT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<u64>,
}

impl RunLimits {
    /// The sandbox's limits: the node's, lowered by these.
    pub fn sandbox(&self) -> sandbox::Limits {
        let node = sandbox::Limits::default();
        let size = |v: Option<u64>, cap: usize| {
            v.map_or(cap, |v| usize::try_from(v).unwrap_or(usize::MAX).min(cap))
        };
        sandbox::Limits {
            fuel: self.fuel.map_or(node.fuel, |v| v.min(node.fuel)),
            memory: size(self.memory, node.memory),
            time: self.time_ms.map_or(node.time, |ms| {
                core::time::Duration::from_millis(ms).min(node.time)
            }),
            script: size(self.source, node.script),
        }
    }

    /// The first bound out of its range, as a rule.
    fn fault(&self, script: bool) -> Option<&'static str> {
        let max_time = u64::try_from(sandbox::MAX_TIME.as_millis()).unwrap_or(u64::MAX);
        let within = |v: Option<u64>, cap: u64| v.is_none_or(|v| (1..=cap).contains(&v));
        let as_u64 = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        if !within(self.fuel, sandbox::MAX_FUEL) {
            Some("limits.fuel is 1 to 1000000000")
        } else if !within(self.memory, as_u64(sandbox::MAX_MEMORY)) {
            Some("limits.memory is 1 to 67108864 bytes")
        } else if !within(self.time_ms, max_time) {
            Some("limits.time_ms is 1 to 5000")
        } else if !within(self.source, as_u64(sandbox::MAX_SCRIPT)) {
            Some("limits.source is 1 to 262144 bytes")
        } else if self.source.is_some() && !script {
            Some("limits.source bounds a script; this step runs no script")
        } else {
            None
        }
    }
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
    /// connection has exactly one concrete destination. A URL module's origin is its URL's,
    /// a script's its script's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Destination>,
    /// A JavaScript source the engine module runs: `module` is then `{"library": "js"}` and
    /// `entry` the name of the function the script defines, called with the inputs as
    /// `Uint8Array`s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptSource>,
    /// Bounds of the run, lower than the node's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<RunLimits>,
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
    /// A JavaScript source fetched with `GET path` from `origin`, run by the engine module
    /// [`sandbox::JS`].
    Script {
        /// Host and port.
        origin: Destination,
        /// Path and query.
        path: &'a str,
        /// The pin.
        sha256: [u8; 32],
    },
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
        let pin = match &self.module.sha256 {
            Some(hex) => Some(parse_sha256(hex)?),
            None => None,
        };
        match (&self.module.url, &self.module.library, &self.script) {
            (Some(url), None, None) => {
                let (origin, path) = parse_url(url)?;
                Some(ModuleRef::Url {
                    origin,
                    path,
                    sha256: pin,
                })
            }
            (None, Some(name), None) => Some(ModuleRef::Library(name)),
            (None, Some(name), Some(script)) if name == sandbox::JS => {
                let (origin, path) = parse_url(&script.url)?;
                Some(ModuleRef::Script {
                    origin,
                    path,
                    sha256: parse_sha256(&script.sha256)?,
                })
            }
            _ => None,
        }
    }

    /// The SHA-256 pin of a library, when the policy gives one.
    pub fn library_pin(&self) -> Option<[u8; 32]> {
        match (&self.module.library, &self.module.sha256) {
            (Some(_), Some(hex)) => parse_sha256(hex),
            _ => None,
        }
    }

    /// The sandbox's limits of this step: the node's, lowered by `limits`.
    pub fn sandbox_limits(&self) -> sandbox::Limits {
        self.limits.unwrap_or_default().sandbox()
    }

    /// The origin the output may go to, on the connection `open`.
    pub fn origin(&self, open: &Open) -> Option<Destination> {
        match self.source()? {
            ModuleRef::Url { origin, .. } | ModuleRef::Script { origin, .. } => Some(origin),
            ModuleRef::Library(_) => match &self.destination {
                Some(d) => Some(d.clone()),
                None => match open.destinations.as_slice() {
                    [only] if only.is_concrete() => Some(only.clone()),
                    _ => None,
                },
            },
        }
    }

    /// How the module is named in a summary: its URL, `library <name>`, or for a script its
    /// URL.
    pub fn module_name(&self) -> String {
        match (&self.module.url, &self.module.library, &self.script) {
            (Some(url), _, _) => url.clone(),
            (None, Some(_), Some(script)) => script.url.clone(),
            (None, Some(name), None) => format!("library {name}"),
            (None, None, _) => String::new(),
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
        if run.script.is_some() {
            ensure(
                run.module.url.is_none()
                    && run.module.library.as_deref() == Some(sandbox::JS)
                    && run.source().is_some(),
                || format!("{at}.script"),
                "a script runs on the library js and is a url on https with a sha256 of 64 lowercase hex digits",
            )?;
        }
        let Some(source) = run.source() else {
            return fail(
                format!("{at}.module"),
                "module is a url on https or a library, each with an optional sha256 of 64 lowercase hex digits",
            );
        };
        if let Some(fault) = run.limits.and_then(|l| l.fault(run.script.is_some())) {
            return fail(format!("{at}.limits"), fault);
        }
        match source {
            ModuleRef::Script { origin, .. } => {
                ensure(
                    run.destination.is_none(),
                    || format!("{at}.destination"),
                    "a script names its origin; destination is for a library",
                )?;
                ensure(
                    open.destinations.iter().any(|d| d.matches(&origin)),
                    || format!("{at}.script.url"),
                    "the script comes from the destination's own origin: a URL on one of the connection's destinations",
                )?;
                ensure(
                    run.inputs.len() <= MAX_SCRIPT_INPUTS,
                    || format!("{at}.inputs"),
                    "at most 14 inputs for a script",
                )?;
            }
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
                ensure(
                    name != sandbox::JS,
                    || format!("{at}.script"),
                    "the library js runs a script: name it in script",
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
/// steps are checked one by one. Inside a loop the body is followed until no new value is
/// confined (a capture at its end reaches a send at its start on the next run); both bodies
/// of a branch are followed, and what either confines stays confined.
pub(super) fn check_confined(at: &str, operation: &Operation) -> Checked {
    let Some(open) = operation.open() else {
        return Ok(());
    };
    let mut origin: Option<Destination> = None;
    for (i, step) in super::flow::walk_indexed(&operation.steps) {
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
    confine(
        &format!("{at}.steps"),
        &operation.steps,
        open,
        &origin,
        &mut confined,
    )
}

fn push<'a>(confined: &mut Vec<&'a str>, name: &'a str) {
    if !confined.contains(&name) {
        confined.push(name);
    }
}

/// Follows the confined values through `steps`.
fn confine<'a>(
    at: &str,
    steps: &'a [Step],
    open: &Open,
    origin: &Destination,
    confined: &mut Vec<&'a str>,
) -> Checked {
    // True while the last request carried a confined value: what its response gives into
    // temporary values may echo it, so those values are confined too.
    let mut carried = false;
    for (i, step) in steps.iter().enumerate() {
        let at = format!("{at}[{i}]");
        match step {
            Step::Run(run) => push(confined, &run.into),
            Step::Compute(c) => {
                if reads_any(&c.template, confined) {
                    push(confined, &c.into);
                }
            }
            Step::Send(send) => {
                carried = send.inject.iter().any(|j| reads_any(&j.template, confined));
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
                    if reads_any(&injection.template, confined) {
                        ensure(
                            fixed_to.as_ref() == Some(origin),
                            || format!("{at}.inject[{j}]"),
                            "the output of a run step goes only into a request the policy fixes to the origin of its module",
                        )?;
                    }
                }
                if let Some(template) = &send.template
                    && reads_any(template, confined)
                {
                    return fail(
                        format!("{at}.template"),
                        "the output of a run step goes only into a request the policy fixes to the origin of its module",
                    );
                }
            }
            Step::Return(ret) => {
                if let Some(template) = &ret.template
                    && reads_any(template, confined)
                {
                    return fail(
                        format!("{at}.template"),
                        "the output of a run step never goes back to the caller",
                    );
                }
            }
            Step::Receive(receive) => {
                if carried {
                    for c in &receive.capture {
                        match &c.into {
                            Store::Temp { name, .. } => push(confined, name),
                            // A field is a secret of the record (a capture into a public field
                            // is refused), analysed wherever it is used.
                            Store::Field { .. } => {}
                        }
                    }
                }
            }
            // A status request the node polls while it waits is not a request the confined
            // value may ride on: refused outright.
            Step::Await(wait) => {
                if let Some(poll) = &wait.challenge.poll {
                    for (j, injection) in poll.send.inject.iter().enumerate() {
                        if reads_any(&injection.template, confined) {
                            return fail(
                                format!("{at}.challenge.poll.send.inject[{j}]"),
                                "the output of a run step goes only into a request the policy fixes to the origin of its module",
                            );
                        }
                    }
                }
            }
            Step::Repeat(r) => loop {
                let before = confined.len();
                confine(&format!("{at}.steps"), &r.steps, open, origin, confined)?;
                if confined.len() == before {
                    break;
                }
            },
            Step::If(b) => {
                confine(&format!("{at}.then"), &b.then, open, origin, confined)?;
                confine(&format!("{at}.else"), &b.otherwise, open, origin, confined)?;
            }
            Step::Open(_) => {}
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
    let pin = match (&run.script, &run.module.sha256) {
        (Some(script), _) => format!(" (sha256 {}) in library js", script.sha256),
        (None, Some(hex)) => format!(" (sha256 {hex})"),
        (None, None) if run.module.url.is_some() => " (not pinned)".into(),
        (None, None) => String::new(),
    };
    let mut out = vec![format!(
        "  run {} of {}{pin} on [{}] into {}, only to {origin}",
        run.entry,
        run.module_name(),
        run.inputs.join(", "),
        run.into
    )];
    if let Some(limits) = &run.limits {
        let mut bounds = Vec::new();
        if let Some(v) = limits.fuel {
            bounds.push(format!("fuel {v}"));
        }
        if let Some(v) = limits.memory {
            bounds.push(format!("memory {v} bytes"));
        }
        if let Some(v) = limits.time_ms {
            bounds.push(format!("time {v} ms"));
        }
        if let Some(v) = limits.source {
            bounds.push(format!("script at most {v} bytes"));
        }
        out.push(format!("    limits: {}", bounds.join(", ")));
    }
    if run.unpinned() {
        out.push(format!(
            "  ! the module {} has no sha256: the site can change the code that reads the secrets",
            run.module_name()
        ));
    }
    out
}
