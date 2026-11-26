//! The policy format before the step language (operations of kind `http`, `stream` and
//! `derive`), read only to convert it with [`upgrade`].
//!
//! A converted policy is a new policy: its owner reads its summary and signs it again (the
//! signature of the old one does not cover it, and the signing domain changed). Where the old
//! format let a caller choose more than the new contracts allow, the conversion keeps the
//! safe side and says so in a note, for the owner to widen what is needed before signing:
//!
//! - an HTTPS operation returns the status only (`return.response` lists no header and no
//!   body), so nothing a server issues reaches the caller unless the owner declares it;
//! - a caller request may send no query parameter until the owner lists them;
//! - a stream relays none of the caller's exchanges until the owner lists the sends allowed;
//! - a derivation that reads `$input` takes any bytes, as before, with a note to declare an
//!   input schema;
//! - path prefixes become templates that match the same paths (`/v1/` becomes `/v1/**`,
//!   `/v1` becomes `/v1` and `/v1/**`).

use serde::{Deserialize, Serialize};

use super::{
    Caller, CallerRequest, Capture, Connection, Destination, FieldSpec, Identity, Injection,
    Method, Open, Operation as NewOperation, Policy as NewPolicy, Receive, Return, Send,
    Step as NewStep, StepRequest as NewRequest, Target,
};
use crate::policy::input::Input;
use crate::template::{Template, Var};

/// A policy in the old format.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The fields.
    pub fields: Vec<FieldSpec>,
    /// The callers.
    pub callers: Vec<Caller>,
    /// The operations.
    pub operations: Vec<Operation>,
}

/// A signed policy in the old format; the signature is dropped by the conversion.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    /// The policy.
    pub policy: Policy,
    /// The old signature (not checked, not kept).
    pub signature: String,
}

/// What request an old HTTP step sent.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepRequest {
    /// The caller's request.
    #[default]
    Caller,
    /// A fixed request.
    Fixed {
        /// Method.
        method: Method,
        /// Path.
        path: String,
        /// Destination.
        #[serde(default)]
        destination: Option<Destination>,
    },
}

/// An old HTTP step.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The request.
    #[serde(default)]
    pub request: StepRequest,
    /// The injections.
    #[serde(default)]
    pub inject: Vec<Injection>,
    /// The captures.
    #[serde(default)]
    pub capture: Vec<Capture>,
}

/// An old stream script entry.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Exchange {
    /// A write.
    Send {
        /// The template.
        template: String,
    },
    /// A read.
    Expect {
        /// The delimiters.
        until: Vec<String>,
        /// The captures.
        #[serde(default)]
        capture: Vec<Capture>,
    },
}

/// An old operation.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// HTTP requests.
    Http {
        /// Name.
        name: String,
        /// Destinations.
        destinations: Vec<Destination>,
        /// Methods of the caller.
        #[serde(default)]
        methods: Vec<Method>,
        /// Path prefixes of the caller.
        #[serde(default)]
        paths: Vec<String>,
        /// Headers of the caller.
        #[serde(default)]
        caller_headers: Vec<String>,
        /// Client certificate.
        #[serde(default)]
        identity: Option<Identity>,
        /// The steps.
        steps: Vec<Step>,
    },
    /// A stream.
    Stream {
        /// Name.
        name: String,
        /// Destinations.
        destinations: Vec<Destination>,
        /// Client certificate.
        #[serde(default)]
        identity: Option<Identity>,
        /// The script.
        script: Vec<Exchange>,
    },
    /// A derivation.
    Derive {
        /// Name.
        name: String,
        /// The template.
        template: String,
    },
}

/// A converted policy and what the owner should read before signing it.
#[derive(Clone, Debug, Serialize)]
pub struct Upgrade {
    /// The policy in the step language, not signed.
    pub policy: NewPolicy,
    /// What the conversion narrowed or could not decide, one line each.
    pub notes: Vec<String>,
}

/// The path templates that match what an old path prefix allowed: `/v1/` allowed `/v1/`
/// and below, `/v1` allowed `/v1` itself and below.
pub fn templates_of_prefix(prefix: &str) -> Vec<String> {
    if prefix.ends_with('/') {
        vec![format!("{prefix}**")]
    } else {
        vec![prefix.to_string(), format!("{prefix}/**")]
    }
}

fn reads_input(template: &str) -> bool {
    Template::parse(template).is_ok_and(|t| t.vars().contains(&Var::Input))
}

/// Converts a policy of the old format into the step language. The result is not checked:
/// [`super::Policy::validate`] (or signing) does that, and fails where the owner must decide,
/// such as where a caller's path parameter goes.
pub fn upgrade(old: Policy) -> Upgrade {
    let mut notes = vec![
        "the policy must be signed again: a converted policy is a new policy for its owner to read and sign".to_string(),
    ];
    let operations = old
        .operations
        .into_iter()
        .map(|operation| convert(operation, &mut notes))
        .collect();
    Upgrade {
        policy: NewPolicy {
            item: None,
            fields: old.fields,
            callers: old.callers,
            operations,
        },
        notes,
    }
}

/// Reads a policy of the old format, signed or not, from JSON and converts it.
pub fn upgrade_json(json: &str) -> crate::Result<Upgrade> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| crate::Error::policy("", "not JSON"))?;
    let signed = value
        .as_object()
        .is_some_and(|o| o.contains_key("signature") && o.contains_key("policy"));
    let old = if signed {
        serde_json::from_value::<SignedPolicy>(value).map(|s| s.policy)
    } else {
        serde_json::from_value::<Policy>(value)
    }
    .map_err(|_| crate::Error::policy("", "not a policy of the old format"))?;
    let mut upgraded = upgrade(old);
    if signed {
        upgraded
            .notes
            .push("the old signature was dropped".to_string());
    }
    Ok(upgraded)
}

fn convert(operation: Operation, notes: &mut Vec<String>) -> NewOperation {
    match operation {
        Operation::Http {
            name,
            destinations,
            methods,
            paths,
            caller_headers,
            identity,
            steps,
        } => {
            let mut out = vec![NewStep::Open(Open {
                connection: Connection::Https,
                destinations,
                identity,
                protocol: None,
                limits: None,
                login: None,
                host_keys: Vec::new(),
                tls: None,
                version: None,
                browser: None,
            })];
            let mut templates: Vec<String> = Vec::new();
            for path in &paths {
                for t in templates_of_prefix(path) {
                    if !templates.contains(&t) {
                        templates.push(t);
                    }
                }
            }
            let mut caller_params = false;
            for step in steps {
                let request = match step.request {
                    StepRequest::Caller => {
                        caller_params |= step
                            .inject
                            .iter()
                            .any(|i| matches!(i.target, Target::PathParam { .. }));
                        NewRequest::Caller(CallerRequest {
                            methods: methods.clone(),
                            paths: templates.clone(),
                            headers: caller_headers.clone(),
                            ..CallerRequest::default()
                        })
                    }
                    StepRequest::Fixed {
                        method,
                        path,
                        destination,
                    } => NewRequest::Fixed {
                        method,
                        path,
                        destination,
                    },
                };
                out.push(NewStep::Send(Send {
                    request: Some(request),
                    inject: step.inject,
                    template: None,
                    grpc: false,
                    frame: None,
                    command: None,
                    fill: None,
                }));
                if !step.capture.is_empty() {
                    out.push(NewStep::Receive(Receive {
                        until: Vec::new(),
                        capture: step.capture,
                    }));
                }
            }
            out.push(NewStep::Return(Return::default()));
            notes.push(format!(
                "operation {name}: returns the status only; list in return.response the headers and JSON members (or \"body\": \"all\") the caller needs"
            ));
            if !methods.is_empty() {
                notes.push(format!(
                    "operation {name}: the caller may send no query parameter; list the ones it needs in request.query"
                ));
            }
            if caller_params {
                notes.push(format!(
                    "operation {name}: write each path parameter as a whole {{name}} segment of request.paths"
                ));
            }
            NewOperation {
                name,
                input: None,
                steps: out,
                payment: None,
                approval: false,
                vend: None,
            }
        }
        Operation::Stream {
            name,
            destinations,
            identity,
            script,
        } => {
            let mut out = vec![NewStep::Open(Open {
                connection: Connection::Tls,
                destinations,
                identity,
                protocol: None,
                limits: None,
                login: None,
                host_keys: Vec::new(),
                tls: None,
                version: None,
                browser: None,
            })];
            for exchange in script {
                out.push(match exchange {
                    Exchange::Send { template } => NewStep::Send(Send {
                        template: Some(template),
                        ..Send::default()
                    }),
                    Exchange::Expect { until, capture } => {
                        NewStep::Receive(Receive { until, capture })
                    }
                });
            }
            out.push(NewStep::Return(Return::default()));
            notes.push(format!(
                "operation {name}: relays none of the caller's exchanges; list the sends allowed in return.relay.sends"
            ));
            NewOperation {
                name,
                input: None,
                steps: out,
                payment: None,
                approval: false,
                vend: None,
            }
        }
        Operation::Derive { name, template } => {
            let input = reads_input(&template).then(|| {
                notes.push(format!(
                    "operation {name}: the input is any bytes, as before; declare an input schema (json, rlp or a raw pattern) to bound what the key signs"
                ));
                Input::any()
            });
            NewOperation {
                name,
                input,
                steps: vec![NewStep::Return(Return {
                    template: Some(template),
                    ..Return::default()
                })],
                payment: None,
                approval: false,
                vend: None,
            }
        }
    }
}
