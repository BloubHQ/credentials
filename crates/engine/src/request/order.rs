//! The order the injections of one `send` render in, and what each reads of the request.
//!
//! A template of an injection reads the request **as it is sent**: path parameters filled,
//! injected query parameters appended, injected headers set and an injected body in place,
//! except for its own target. So an injection depends on every other injection of the `send`
//! whose target lies in a component its template reads:
//!
//! | Target of the other injection | Seen through |
//! | --- | --- |
//! | a path parameter | `$path`, `$pathname`, `$target_uri` |
//! | a query parameter `n` | `$path`, `$query`, `$target_uri`, `$query_param("n")` |
//! | a header `n` | `$header("n")` |
//! | the body | `$body` |
//!
//! The dependencies are known from the policy alone: a component is named by a literal, and
//! a variable stands for one fixed part of the request. They must form no cycle; a policy
//! with one is refused at signing. The injections render in dependency order, ties broken by
//! the order the policy lists them, so an order exists exactly when there is no cycle and the
//! same policy always renders the same way. Where a value goes on the wire does not follow
//! the render order: headers and query parameters are written in the listed order.
//!
//! A template never reads its own target: the header or query parameter it sets is refused
//! by name, and a variable that holds it (`$query` in a query injection, `$path` in a path
//! parameter's) holds the request without it (a path parameter's own `{name}` stays as
//! written). In the body's own injection, `$body` is the caller's body.
//!
//! The analysis follows the same edges: a component holds what the injections into it make
//! of it, so a secret a policy puts in the path taints `$path` exactly as if the template had
//! written it there, and every rule of the analysis applies to it unchanged.

use crate::policy::{Injection, Target};
use crate::template::{Component, NameKind, Props, Template, Var};

/// Why the injections of a `send` have no render order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The template of this injection does not parse.
    Syntax(usize),
    /// This injection's template reads the header or query parameter it sets.
    OwnTarget(usize),
    /// This injection is part of a cycle: it reads, through others, what it writes.
    Cycle(usize),
}

impl Fault {
    /// The injection the fault is at.
    pub(crate) fn index(self) -> usize {
        match self {
            Fault::Syntax(i) | Fault::OwnTarget(i) | Fault::Cycle(i) => i,
        }
    }

    /// The rule it breaks.
    pub(crate) fn rule(self) -> &'static str {
        match self {
            Fault::Syntax(_) => "template syntax",
            Fault::OwnTarget(_) => {
                "a template reads the header or query parameter its own injection sets"
            }
            Fault::Cycle(_) => "injections read each other's components in a cycle",
        }
    }
}

/// True when the query parameter a template names (as RFC 9421 section 2.2.8 writes it) may
/// be `name`: under any case and percent-encoding, more than the value lookup matches, so the
/// analysis never misses a dependency.
fn same_query_name(written: &str, name: &str) -> bool {
    written.eq_ignore_ascii_case(name)
        || crate::primitives::pct_decode(written.as_bytes())
            .is_ok_and(|d| d.eq_ignore_ascii_case(name.as_bytes()))
}

/// True when a template reads the component `target` puts a value in.
fn sees(template: &Template, target: &Target) -> bool {
    let vars = template.vars();
    let reads = |list: &[Var]| vars.iter().any(|v| list.contains(v));
    match target {
        Target::PathParam { .. } => reads(&[Var::Path, Var::PathName, Var::TargetUri]),
        Target::Query { name } => {
            reads(&[Var::Path, Var::Query, Var::TargetUri])
                || template
                    .query_params()
                    .iter()
                    .any(|q| same_query_name(q, name))
        }
        Target::Header { name } => template
            .headers()
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name)),
        Target::Body => reads(&[Var::Body]),
    }
}

/// True when a template names the header or query parameter `target` sets.
fn names_own(template: &Template, target: &Target) -> bool {
    match target {
        Target::Header { name } => template
            .headers()
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name)),
        Target::Query { name } => template
            .query_params()
            .iter()
            .any(|q| same_query_name(q, name)),
        Target::PathParam { .. } | Target::Body => false,
    }
}

/// True when an injection of `inject` sets the header `name`.
pub(crate) fn injects_header(inject: &[Injection], name: &str) -> bool {
    inject
        .iter()
        .any(|i| matches!(&i.target, Target::Header { name: n } if n.eq_ignore_ascii_case(name)))
}

/// True when an injection of `inject` may set the query parameter a template names.
pub(crate) fn injects_query(inject: &[Injection], written: &str) -> bool {
    inject
        .iter()
        .any(|i| matches!(&i.target, Target::Query { name } if same_query_name(written, name)))
}

/// The render order of the injections of one `send`.
pub(crate) struct Plan {
    /// The parsed template of each injection, in listed order.
    pub templates: Vec<Template>,
    /// For each injection, the other injections whose values its template sees.
    pub reads: Vec<Vec<usize>>,
    /// The injections in the order they render.
    pub order: Vec<usize>,
}

impl Plan {
    /// Parses the templates of `inject` and orders them.
    pub(crate) fn new(inject: &[Injection]) -> Result<Self, Fault> {
        let templates = inject
            .iter()
            .enumerate()
            .map(|(i, injection)| {
                Template::parse(&injection.template).map_err(|_| Fault::Syntax(i))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut reads = Vec::with_capacity(inject.len());
        for (i, (template, injection)) in templates.iter().zip(inject).enumerate() {
            if names_own(template, &injection.target) {
                return Err(Fault::OwnTarget(i));
            }
            reads.push(
                inject
                    .iter()
                    .enumerate()
                    .filter(|(j, other)| *j != i && sees(template, &other.target))
                    .map(|(j, _)| j)
                    .collect::<Vec<_>>(),
            );
        }
        // The first listed injection whose dependencies have all rendered renders next. At
        // most 16 injections, so the quadratic search is cheap.
        let mut order: Vec<usize> = Vec::with_capacity(inject.len());
        while order.len() < inject.len() {
            let ready = reads
                .iter()
                .enumerate()
                .find(|(i, deps)| !order.contains(i) && deps.iter().all(|j| order.contains(j)))
                .map(|(i, _)| i);
            match ready {
                Some(i) => order.push(i),
                None => {
                    let stuck = (0..inject.len()).find(|i| !order.contains(i)).unwrap_or(0);
                    return Err(Fault::Cycle(stuck));
                }
            }
        }
        Ok(Self {
            templates,
            reads,
            order,
        })
    }

    /// The properties of each injection's output, in listed order, for the analysis: its
    /// template with every request component it reads being what the injections into it make
    /// of it. One whose template breaks a rule gets that rule, and counts as
    /// [`Props::unknown`] for the injections that read it.
    pub(crate) fn props(
        &self,
        inject: &[Injection],
        kind: &dyn Fn(&str) -> NameKind,
    ) -> Vec<Result<Props, &'static str>> {
        let mut out: Vec<Option<Result<Props, &'static str>>> = vec![None; inject.len()];
        for &i in &self.order {
            let Some(template) = self.templates.get(i) else {
                continue;
            };
            let result = {
                let known = |j: usize| -> Props {
                    match out.get(j) {
                        Some(Some(Ok(props))) => *props,
                        _ => Props::unknown(),
                    }
                };
                let component = |c: Component<'_>| component_props(c, i, inject, &known);
                template.props_in(kind, &component)
            };
            if let Some(slot) = out.get_mut(i) {
                *slot = Some(result);
            }
        }
        out.into_iter()
            .map(|o| o.unwrap_or(Err("an injection has no render order")))
            .collect()
    }
}

/// What a request component read by injection `own` is: the caller's part (as the analysis
/// takes it without injections) followed by what the other injections put in it, or exactly
/// what an injected header, query parameter or body is. `None` when no injection goes in it.
fn component_props(
    component: Component<'_>,
    own: usize,
    inject: &[Injection],
    known: &dyn Fn(usize) -> Props,
) -> Option<Props> {
    let others = || inject.iter().enumerate().filter(move |(j, _)| *j != own);
    let appended = |var: Var, takes: &dyn Fn(&Target) -> bool| -> Option<Props> {
        let mut parts = others().filter(|(_, i)| takes(&i.target)).peekable();
        parts.peek()?;
        Some(parts.fold(Props::chosen(var), |acc, (j, _)| {
            acc.then(known(j).encoded())
        }))
    };
    match component {
        Component::Var(var @ (Var::Path | Var::TargetUri)) => appended(var, &|t| {
            matches!(t, Target::PathParam { .. } | Target::Query { .. })
        }),
        Component::Var(var @ Var::PathName) => {
            appended(var, &|t| matches!(t, Target::PathParam { .. }))
        }
        Component::Var(var @ Var::Query) => appended(var, &|t| matches!(t, Target::Query { .. })),
        Component::Var(Var::Body) => others()
            .find(|(_, i)| i.target == Target::Body)
            .map(|(j, _)| known(j)),
        Component::Header(name) => others()
            .find(|(_, i)| matches!(&i.target, Target::Header { name: n } if n.eq_ignore_ascii_case(name)))
            .map(|(j, _)| known(j)),
        Component::QueryParam(written) => others()
            .find(|(_, i)| matches!(&i.target, Target::Query { name } if same_query_name(written, name)))
            .map(|(j, _)| known(j).encoded()),
        Component::Var(_) => None,
    }
}
