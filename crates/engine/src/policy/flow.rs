//! Loops and branches: [`Repeat`] runs a body of steps a bounded number of times, [`Branch`]
//! runs one of two bodies. Both decide on a [`Test`] of one name.
//!
//! What the analysis holds them to, before the policy is signed:
//!
//! - A test reads only a name no secret influences: a public field, the status
//!   of a response, a public capture from a response to a request that carried nothing
//!   secret, or a value computed from those (or from a derivation's checked input). Which
//!   body runs, and how many requests go out, is seen by whoever watches the requests or
//!   their timing, so a test on a secret would hand its bits out one request at a time.
//! - A loop runs 1 to [`MAX_REPEAT`] times, repeats at least one request each time, and its
//!   requests count against the requests of the operation as often as the loop may run.
//! - Loops and branches nest at most [`MAX_NESTING`] deep and hold only `send`, `receive`,
//!   `compute`, `repeat` and `if`: never `await` (a parked operation resumes at a step of the
//!   top level), `run` (its output's confinement and its module fetch stay straight-line),
//!   `open` or `return`.
//! - Both bodies of a branch are checked like straight-line steps. A name defined in only one
//!   of them is not readable after the branch; a name defined in both carries the properties
//!   of both definitions joined.
//! - Inside a loop a capture may give a new value to a name captured before the loop (with
//!   the same secrecy), so a loop can retry with what the last answer said (a fresh nonce).

use serde::{Deserialize, Serialize};

use super::{
    Checked, Kinds, Open, Operation, Policy, Send, Source, Step, StepRequest, Store, ensure, fail,
    is_token,
};
use crate::template::{Template, Var};

/// Most iterations of a `repeat`.
pub const MAX_REPEAT: u32 = 8;
/// Deepest nesting of `repeat` and `if` (a loop or branch at the top level is 1 deep).
pub const MAX_NESTING: usize = 2;
/// Most values a [`Test`] compares with.
pub const MAX_TEST_VALUES: usize = 16;
/// Longest value a [`Test`] compares with, in bytes.
pub const MAX_TEST_VALUE: usize = 256;

/// A test of one name: it holds when the value is one of `one_of`, or when it is none of
/// `none_of` (exactly one of the two is given). A name with no value (an optional capture
/// that found nothing) never makes a test hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Test {
    /// The name read: a field, a capture or a computed value no secret influences.
    pub name: String,
    /// The values that make the test hold, compared exactly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<String>,
    /// The values that make the test fail, compared exactly; any other value holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub none_of: Vec<String>,
}

impl Test {
    /// A test that holds when `name` is one of `values`.
    pub fn one_of<I, S>(name: &str, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            one_of: values.into_iter().map(Into::into).collect(),
            none_of: Vec::new(),
        }
    }

    /// A test that holds when `name` has a value that is none of `values`.
    pub fn none_of<I, S>(name: &str, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            one_of: Vec::new(),
            none_of: values.into_iter().map(Into::into).collect(),
        }
    }

    /// True when `value` makes the test hold; no value never does.
    pub fn holds(&self, value: Option<&[u8]>) -> bool {
        let Some(value) = value else {
            return false;
        };
        let listed = |values: &[String]| values.iter().any(|v| v.as_bytes() == value);
        if self.one_of.is_empty() {
            !listed(&self.none_of)
        } else {
            listed(&self.one_of)
        }
    }

    pub(super) fn fault(&self) -> Option<&'static str> {
        let values = |v: &[String]| {
            v.len() <= MAX_TEST_VALUES && v.iter().all(|s| s.len() <= MAX_TEST_VALUE)
        };
        if !is_token(&self.name) {
            return Some("a test reads a name: a token");
        }
        (!(self.one_of.is_empty() != self.none_of.is_empty()
            && values(&self.one_of)
            && values(&self.none_of)))
        .then_some("a test lists 1 to 16 values of at most 256 bytes in one_of or in none_of")
    }

    /// The test in words, for the summary.
    pub fn describe(&self) -> String {
        if self.one_of.is_empty() {
            format!("{} is none of {:?}", self.name, self.none_of)
        } else {
            format!("{} is one of {:?}", self.name, self.one_of)
        }
    }
}

/// A bounded loop: `steps` run, then `until` is tested; the loop ends when it holds or after
/// `times` runs. Without `until` the steps run exactly `times` times.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repeat {
    /// Most runs of the steps: 1 to [`MAX_REPEAT`], fixed by the signed policy.
    pub times: u32,
    /// The steps repeated.
    pub steps: Vec<Step>,
    /// The test that ends the loop, after each run of the steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Test>,
}

/// A branch: `then` runs when the test holds, `else` otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    /// The test.
    pub when: Test,
    /// The steps when it holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub then: Vec<Step>,
    /// The steps otherwise.
    #[serde(default, rename = "else", skip_serializing_if = "Vec::is_empty")]
    pub otherwise: Vec<Step>,
}

impl From<Repeat> for Step {
    fn from(step: Repeat) -> Self {
        Step::Repeat(step)
    }
}

impl From<Branch> for Step {
    fn from(step: Branch) -> Self {
        Step::If(step)
    }
}

/// Every step of `steps`, the bodies of loops and branches included, in the order written
/// (a loop or branch before its body).
pub(crate) fn walk(steps: &[Step]) -> Vec<&Step> {
    let mut out = Vec::new();
    for (_, step) in walk_indexed(steps) {
        out.push(step);
    }
    out
}

/// [`walk`], with the index of the top-level step each step is, or is inside of.
pub(crate) fn walk_indexed(steps: &[Step]) -> Vec<(usize, &Step)> {
    fn push<'a>(top: usize, steps: &'a [Step], out: &mut Vec<(usize, &'a Step)>) {
        for step in steps {
            out.push((top, step));
            match step {
                Step::Repeat(r) => push(top, &r.steps, out),
                Step::If(b) => {
                    push(top, &b.then, out);
                    push(top, &b.otherwise, out);
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        push(i, core::slice::from_ref(step), &mut out);
    }
    out
}

/// The fields every run of `steps` fills from a response: those a loop's body fills (it runs
/// at least once), and those both bodies of a branch fill.
pub(crate) fn sure_field_captures(steps: &[Step]) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for step in steps {
        let here: Vec<&str> = match step {
            Step::Receive(r) => r
                .capture
                .iter()
                .filter_map(|c| match &c.into {
                    Store::Field { name } => Some(name.as_str()),
                    Store::Temp { .. } => None,
                })
                .collect(),
            Step::Repeat(r) => sure_field_captures(&r.steps),
            Step::If(b) => {
                let otherwise = sure_field_captures(&b.otherwise);
                sure_field_captures(&b.then)
                    .into_iter()
                    .filter(|f| otherwise.contains(f))
                    .collect()
            }
            _ => Vec::new(),
        };
        for f in here {
            if !out.contains(&f) {
                out.push(f);
            }
        }
    }
    out
}

/// The most and the least requests a run of some steps makes: each `send` and each status
/// request an `await` polls with counts once, a loop as often as it may run, a branch as its
/// larger (or smaller) side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Requests {
    pub most: u64,
    pub least: u64,
}

impl Requests {
    pub(crate) fn of(steps: &[Step]) -> Self {
        let mut out = Requests::default();
        for step in steps {
            let here = match step {
                Step::Send(_) => Requests { most: 1, least: 1 },
                Step::Await(a) if a.challenge.poll.is_some() => Requests { most: 1, least: 1 },
                Step::Repeat(r) => Requests::of(&r.steps).repeated(r),
                Step::If(b) => Requests::of(&b.then).either(Requests::of(&b.otherwise)),
                _ => Requests::default(),
            };
            out = out.then(here);
        }
        out
    }

    pub(crate) fn then(self, next: Requests) -> Self {
        Requests {
            most: self.most.saturating_add(next.most),
            least: self.least.saturating_add(next.least),
        }
    }

    pub(crate) fn either(self, other: Requests) -> Self {
        Requests {
            most: self.most.max(other.most),
            least: self.least.min(other.least),
        }
    }

    /// The requests of a loop whose body makes `self`: at most `times` runs; at least one
    /// when `until` may end it early, else exactly `times`.
    pub(crate) fn repeated(self, repeat: &Repeat) -> Self {
        let times = u64::from(repeat.times);
        Requests {
            most: self.most.saturating_mul(times),
            least: if repeat.until.is_some() {
                self.least
            } else {
                self.least.saturating_mul(times)
            },
        }
    }
}

impl Operation {
    /// The most requests a run of the operation can make, loops counted as often as they may
    /// run. A signed policy keeps it at most [`super::MAX_REQUESTS`].
    pub fn most_requests(&self) -> u64 {
        Requests::of(&self.steps).most
    }

    /// True when the operation has a loop or a branch.
    pub fn branches(&self) -> bool {
        self.steps
            .iter()
            .any(|s| matches!(s, Step::Repeat(_) | Step::If(_)))
    }
}

/// The templates a `send` renders.
fn send_templates(send: &Send) -> Vec<&str> {
    let mut out: Vec<&str> = send.inject.iter().map(|i| i.template.as_str()).collect();
    out.extend(send.template.as_deref());
    if let Some(command) = &send.command {
        out.push(command.text.as_str());
        out.extend(command.params.iter().map(String::as_str));
    }
    if let Some(fill) = &send.fill {
        out.extend(fill.fields.iter().map(|f| f.template.as_str()));
    }
    out
}

/// The names of an operation a secret can influence, for the tests of its loops and
/// branches. It is wider than taint: a hash or a MAC of a secret is not tainted (it does not
/// give the secret back), but a branch on it still tells which value it has, so it counts.
///
/// - Secret fields (an unknown name counts as one), secret captures, the outputs of `run`
///   steps and the codes of challenges.
/// - A value computed from such a name.
/// - A capture into a public name from the response to a request that carried such a name,
///   or went over a connection with a client certificate: what an authenticated answer holds
///   is the account's, and the status is the only part of it the analysis lets a test read
///   (the status of every request is in the log, and the server, not the node, chooses it).
///
/// It is flow-insensitive: a name some definition makes influenced is influenced everywhere,
/// which is exact for names defined once and safe for a name defined in both bodies of a
/// branch or captured again in a loop.
pub(crate) struct Influence<'a> {
    names: Vec<&'a str>,
    defined: Vec<&'a str>,
}

impl<'a> Influence<'a> {
    pub(crate) fn of(policy: &Policy, operation: &'a Operation) -> Self {
        let mut this = Influence {
            names: Vec::new(),
            defined: Vec::new(),
        };
        for step in walk(&operation.steps) {
            match step {
                Step::Receive(r) => {
                    this.defined
                        .extend(r.capture.iter().filter_map(|c| match &c.into {
                            Store::Temp { name, .. } => Some(name.as_str()),
                            Store::Field { .. } => None,
                        }))
                }
                Step::Compute(c) => this.defined.push(&c.into),
                Step::Run(run) => this.defined.push(&run.into),
                Step::Await(a) => this.defined.extend(a.challenge.into.as_deref()),
                _ => {}
            }
        }
        let identity = operation.open().is_some_and(|o| o.identity.is_some());
        // Each pass adds names; a loop's capture can influence a send before it in the next
        // run, so passes go on until nothing is added (at most once per name).
        loop {
            let before = this.names.len();
            this.pass(policy, &operation.steps, identity);
            if this.names.len() == before {
                break;
            }
        }
        this
    }

    fn add(&mut self, name: &'a str) {
        if !self.names.contains(&name) {
            self.names.push(name);
        }
    }

    fn reads(&self, policy: &Policy, template: &str) -> bool {
        match Template::parse(template) {
            Ok(t) => t.names().into_iter().any(|n| self.reaches(policy, n)),
            Err(_) => true,
        }
    }

    fn pass(&mut self, policy: &Policy, steps: &'a [Step], identity: bool) {
        let mut carried = false;
        for step in steps {
            match step {
                Step::Send(send) => {
                    carried = identity
                        || send_templates(send)
                            .into_iter()
                            .any(|t| self.reads(policy, t));
                }
                Step::Receive(r) => {
                    for c in &r.capture {
                        if let Store::Temp { name, secret } = &c.into
                            && (*secret || (carried && c.source != Source::Status))
                        {
                            self.add(name);
                        }
                    }
                }
                Step::Compute(c) => {
                    if self.reads(policy, &c.template) {
                        self.add(&c.into);
                    }
                }
                Step::Run(run) => self.add(&run.into),
                Step::Await(a) => {
                    if let Some(into) = &a.challenge.into {
                        self.add(into);
                    }
                }
                Step::Repeat(r) => self.pass(policy, &r.steps, identity),
                Step::If(b) => {
                    self.pass(policy, &b.then, identity);
                    self.pass(policy, &b.otherwise, identity);
                }
                Step::Open(_) | Step::Return(_) => {}
            }
        }
    }

    /// True when a secret can influence the value of `name`.
    pub(crate) fn reaches(&self, policy: &Policy, name: &str) -> bool {
        self.names.contains(&name) || (!self.defined.contains(&name) && policy.is_secret(name))
    }
}

/// The names only captures define (no `compute`, `run` or challenge), with their secrecy
/// (each name once, as its first capture has it): those a loop may capture again.
fn captured_temps(operation: &Operation) -> Vec<(&str, bool)> {
    let steps = walk(&operation.steps);
    let mut out: Vec<(&str, bool)> = Vec::new();
    for step in &steps {
        for (name, how) in definitions(step) {
            if let Definition::Captured(secret) = how
                && matches!(step, Step::Receive(_))
                && !out.iter().any(|(n, _)| *n == name)
            {
                out.push((name, secret));
            }
        }
    }
    let other = |name: &str| {
        steps.iter().any(|s| {
            !matches!(s, Step::Receive(_)) && definitions(s).iter().any(|(n, _)| *n == name)
        })
    };
    out.retain(|(name, _)| !other(name));
    out
}

/// How a step defines a name, for [`check_definitions`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Definition {
    /// By `compute`.
    Computed,
    /// By a capture, a `run` step or a challenge, secret or not.
    Captured(bool),
}

/// The names one step defines, and how.
fn definitions(step: &Step) -> Vec<(&str, Definition)> {
    match step {
        Step::Receive(r) => r
            .capture
            .iter()
            .filter_map(|c| match &c.into {
                Store::Temp { name, secret } => {
                    Some((name.as_str(), Definition::Captured(*secret)))
                }
                Store::Field { .. } => None,
            })
            .collect(),
        Step::Compute(c) => vec![(c.into.as_str(), Definition::Computed)],
        Step::Run(run) => vec![(run.into.as_str(), Definition::Captured(true))],
        Step::Await(a) => a
            .challenge
            .into
            .as_deref()
            .map(|n| (n, Definition::Captured(true)))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// Checks that every name the operation defines more than once (in both bodies of a branch,
/// again in a loop, or in a body and again after it) is defined the same way: always by
/// `compute`, or always by captures (and `run` or `await`) of one secrecy. The analysis gives
/// a name one set of properties, so its definitions must agree on what it is.
pub(super) fn check_definitions(at: &str, operation: &Operation) -> Checked {
    let mut seen: Vec<(&str, Definition)> = Vec::new();
    for step in walk(&operation.steps) {
        for (name, how) in definitions(step) {
            match seen.iter().find(|(n, _)| *n == name) {
                Some((_, before)) => ensure(
                    *before == how,
                    || format!("{at}.steps ({name})"),
                    "a name defined twice (in both bodies of a branch, or in a loop) is defined the same way: computed both times, or captured with the same secrecy",
                )?,
                None => seen.push((name, how)),
            }
        }
    }
    Ok(())
}

/// What the checks of a loop or a branch read from their operation.
pub(super) struct Scope<'s, 'a> {
    kinds: &'s Kinds<'a>,
    /// The connection (HTTPS), or none for a derivation.
    open: Option<&'a Open>,
    influence: Influence<'a>,
    captured: Vec<(&'a str, bool)>,
}

impl<'s, 'a> Scope<'s, 'a> {
    pub(super) fn new(
        policy: &Policy,
        kinds: &'s Kinds<'a>,
        operation: &'a Operation,
        open: Option<&'a Open>,
    ) -> Self {
        Scope {
            kinds,
            open,
            influence: Influence::of(policy, operation),
            captured: captured_temps(operation),
        }
    }
}

impl Policy {
    /// Checks a `repeat` or an `if` at `depth` (1 at the top level), and gives the requests
    /// it may make. `known` gets the names readable after it.
    pub(super) fn check_flow<'a>(
        &self,
        at: &str,
        scope: &Scope<'_, 'a>,
        step: &'a Step,
        known: &mut Vec<&'a str>,
        rebind: &[(&'a str, bool)],
        depth: usize,
    ) -> crate::Result<Requests> {
        ensure(
            depth <= MAX_NESTING,
            || at.to_string(),
            "loops and branches nest at most 2 deep",
        )?;
        match step {
            Step::Repeat(r) => self.check_repeat(at, scope, r, known, depth),
            Step::If(b) => self.check_branch(at, scope, b, known, rebind, depth),
            _ => Err(crate::Error::policy(at, "not a loop or a branch")),
        }
    }

    fn check_repeat<'a>(
        &self,
        at: &str,
        scope: &Scope<'_, 'a>,
        repeat: &'a Repeat,
        known: &mut Vec<&'a str>,
        depth: usize,
    ) -> crate::Result<Requests> {
        ensure(
            scope.open.is_some(),
            || at.to_string(),
            "a loop repeats requests: an operation with no connection has none to repeat",
        )?;
        ensure(
            (1..=MAX_REPEAT).contains(&repeat.times),
            || format!("{at}.times"),
            "a loop runs 1 to 8 times",
        )?;
        // A capture in the body may give a new value to a name captured before the loop.
        let rebind: Vec<(&'a str, bool)> = scope
            .captured
            .iter()
            .filter(|(n, _)| known.contains(n))
            .copied()
            .collect();
        let body = self.check_block(
            &format!("{at}.steps"),
            scope,
            &repeat.steps,
            known,
            &rebind,
            depth,
        )?;
        ensure(
            body.least > 0,
            || format!("{at}.steps"),
            "every run of a loop sends at least one request",
        )?;
        if let Some(test) = &repeat.until {
            self.check_test(&format!("{at}.until"), scope, test, known)?;
        }
        Ok(body.repeated(repeat))
    }

    fn check_branch<'a>(
        &self,
        at: &str,
        scope: &Scope<'_, 'a>,
        branch: &'a Branch,
        known: &mut Vec<&'a str>,
        rebind: &[(&'a str, bool)],
        depth: usize,
    ) -> crate::Result<Requests> {
        self.check_test(&format!("{at}.when"), scope, &branch.when, known)?;
        ensure(
            !(branch.then.is_empty() && branch.otherwise.is_empty()),
            || at.to_string(),
            "a branch has steps in then or else",
        )?;
        let mut then_known = known.clone();
        let then = self.check_block(
            &format!("{at}.then"),
            scope,
            &branch.then,
            &mut then_known,
            rebind,
            depth,
        )?;
        let mut else_known = known.clone();
        let otherwise = self.check_block(
            &format!("{at}.else"),
            scope,
            &branch.otherwise,
            &mut else_known,
            rebind,
            depth,
        )?;
        // After the branch, a name is readable only when both bodies define it.
        let before = known.len();
        for name in then_known.iter().skip(before) {
            if else_known.iter().skip(before).any(|n| n == name) && !known.contains(name) {
                known.push(name);
            }
        }
        Ok(then.either(otherwise))
    }

    /// Checks the steps of a loop's or a branch's body, `depth` deep.
    fn check_block<'a>(
        &self,
        at: &str,
        scope: &Scope<'_, 'a>,
        steps: &'a [Step],
        known: &mut Vec<&'a str>,
        rebind: &[(&'a str, bool)],
        depth: usize,
    ) -> crate::Result<Requests> {
        let mut requests = Requests::default();
        let kinds = scope.kinds;
        for (i, step) in steps.iter().enumerate() {
            let at = format!("{at}[{i}]");
            let previous = i.checked_sub(1).and_then(|p| steps.get(p));
            match step {
                Step::Send(send) => {
                    let Some(open) = scope.open else {
                        return Err(crate::Error::policy(at, "send needs an open connection"));
                    };
                    ensure(
                        send.command.is_none(),
                        || at.clone(),
                        "command is for a protocol connection",
                    )?;
                    self.check_https_send(&at, kinds, open, send, known)?;
                    requests = requests.then(Requests { most: 1, least: 1 });
                }
                Step::Receive(receive) => {
                    let fixed = match previous {
                        Some(Step::Send(send)) => {
                            matches!(send.request, Some(StepRequest::Fixed { .. }))
                        }
                        _ => {
                            return Err(crate::Error::policy(
                                at,
                                "an HTTPS receive follows its send in the same body",
                            ));
                        }
                    };
                    ensure(
                        receive.until.is_empty(),
                        || format!("{at}.until"),
                        "an HTTPS receive reads the whole response; until is for streams",
                    )?;
                    self.check_captures_in(&at, &receive.capture, false, fixed, known, rebind)?;
                }
                Step::Compute(compute) => {
                    ensure(
                        is_token(&compute.into)
                            && !self.is_field(&compute.into)
                            && !known.contains(&compute.into.as_str()),
                        || format!("{at}.into"),
                        "compute into a new token name",
                    )?;
                    let var_ok = if scope.open.is_none() {
                        Var::in_derive
                    } else {
                        Var::in_compute
                    };
                    self.check_template(
                        &format!("{at}.template"),
                        kinds,
                        &compute.template,
                        known,
                        var_ok,
                    )?;
                    known.push(&compute.into);
                }
                Step::Repeat(_) | Step::If(_) => {
                    let inner = self.check_flow(&at, scope, step, known, rebind, depth + 1)?;
                    requests = requests.then(inner);
                }
                Step::Open(_) | Step::Return(_) | Step::Run(_) | Step::Await(_) => {
                    return Err(crate::Error::policy(
                        at,
                        "a loop or branch holds only send, receive, compute, repeat and if: no open, return, run or await",
                    ));
                }
            }
        }
        Ok(requests)
    }

    /// Checks a test: a name defined before it that no secret influences.
    fn check_test(&self, at: &str, scope: &Scope<'_, '_>, test: &Test, known: &[&str]) -> Checked {
        if let Some(rule) = test.fault() {
            return fail(at, rule);
        }
        ensure(
            known.contains(&test.name.as_str()) || self.is_field(&test.name),
            || format!("{at}.name ({})", test.name),
            "a test reads a field or a name defined before it on every path",
        )?;
        ensure(
            !scope.influence.reaches(self, &test.name),
            || format!("{at}.name ({})", test.name),
            "a test may not read a value a secret influences: the requests made, and their timing, would tell it",
        )
    }
}
