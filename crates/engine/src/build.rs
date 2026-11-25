//! Short constructors for policies written in Rust rather than JSON.
//!
//! ```
//! use engine::keys::CallerKey;
//! use engine::policy::{Caller, CallerRequest, Capture, Destination, FieldSpec, Injection,
//!     Method, Operation, Policy, Receive, Return, Send, Source, Store};
//!
//! let app = CallerKey::generate();
//! let policy = Policy::new()
//!     .with_field(FieldSpec::secret("refresh_token"))
//!     .with_field(FieldSpec::secret("access_token").optional())
//!     .with_operation(
//!         Operation::https("refresh", Destination::https("auth.example.com"))
//!             .then(Send::fixed(Method::Post, "/oauth/token").inject(Injection::body(
//!                 "grant_type=refresh_token&refresh_token={{pct(refresh_token)}}",
//!             )))
//!             .then(Receive::response().capture(Capture::new(
//!                 Source::json("/access_token"),
//!                 Store::field("access_token"),
//!             )))
//!             .then(Return::status()),
//!     )
//!     .with_operation(
//!         Operation::https("call", Destination::https("api.example.com"))
//!             .then(
//!                 Send::caller(CallerRequest::new([Method::Get]).paths(["/v1/repos/*"]))
//!                     .inject(Injection::header("Authorization", "Bearer {{access_token}}")),
//!             )
//!             .then(Return::status().json("/name").json("/stars")),
//!     )
//!     .with_caller(Caller::new("agent", app.public(), ["refresh", "call"]).limit(100, 60_000));
//! policy.validate().unwrap();
//! ```

use crate::keys::CallerPublicKey;
use crate::policy::{
    Await, BodyProjection, Caller, CallerRequest, Capture, Challenge, ChallengeKind, Compute,
    Connection, Destination, FieldSpec, Identity, Injection, Input, Limit, Method, Open, Operation,
    Payment, Policy, Poll, Projection, QueryRule, Receive, Relay, Return, Send, Source, Step,
    StepRequest, Store, Target,
};

impl Policy {
    /// An empty policy, to fill with [`Policy::with_field`], [`Policy::with_caller`]
    /// and [`Policy::with_operation`].
    pub fn new() -> Self {
        Self {
            item: None,
            fields: Vec::new(),
            callers: Vec::new(),
            operations: Vec::new(),
        }
    }

    /// Makes the policy the policy of a typed item.
    #[must_use]
    pub fn with_item(mut self, item: crate::item::ItemBinding) -> Self {
        self.item = Some(item);
        self
    }

    /// Adds a field.
    #[must_use]
    pub fn with_field(mut self, field: FieldSpec) -> Self {
        self.fields.push(field);
        self
    }

    /// Adds a caller.
    #[must_use]
    pub fn with_caller(mut self, caller: Caller) -> Self {
        self.callers.push(caller);
        self
    }

    /// Adds an operation.
    #[must_use]
    pub fn with_operation(mut self, operation: Operation) -> Self {
        self.operations.push(operation);
        self
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Caller {
    /// A caller that may run `operations`, with no rate limit.
    pub fn new<I, S>(name: &str, key: CallerPublicKey, operations: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.into(),
            key,
            operations: operations.into_iter().map(Into::into).collect(),
            limit: None,
        }
    }

    /// Allows at most `count` calls per `window_ms` milliseconds.
    #[must_use]
    pub fn limit(mut self, count: u32, window_ms: u64) -> Self {
        self.limit = Some(Limit { count, window_ms });
        self
    }
}

impl Injection {
    /// An injection into `target`.
    pub fn new(target: Target, template: &str) -> Self {
        Self {
            target,
            template: template.into(),
        }
    }

    /// An injection into the placeholder `{name}` of the path.
    pub fn path_param(name: &str, template: &str) -> Self {
        Self::new(Target::PathParam { name: name.into() }, template)
    }
}

impl Source {
    /// A JSON pointer into the body.
    pub fn json(pointer: &str) -> Self {
        Source::Json {
            pointer: pointer.into(),
        }
    }

    /// A response header.
    pub fn header(name: &str) -> Self {
        Source::Header { name: name.into() }
    }

    /// A `Set-Cookie` value.
    pub fn cookie(name: &str) -> Self {
        Source::Cookie { name: name.into() }
    }

    /// The bytes between two delimiters.
    pub fn between(start: &str, end: &str) -> Self {
        Source::Between {
            start: start.into(),
            end: end.into(),
        }
    }
}

impl Store {
    /// A secret field of the record (the node returns a new record).
    pub fn field(name: &str) -> Self {
        Store::Field { name: name.into() }
    }

    /// A temporary value for later steps of the same operation.
    pub fn temp(name: &str, secret: bool) -> Self {
        Store::Temp {
            name: name.into(),
            secret,
        }
    }
}

impl Capture {
    /// A capture that must find a value.
    pub fn new(source: Source, into: Store) -> Self {
        Self {
            source,
            into,
            optional: false,
        }
    }

    /// Makes a missing value not an error.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

impl CallerRequest {
    /// A contract that lets the caller use `methods` on the paths added with
    /// [`CallerRequest::paths`]; no header and no query parameter yet.
    pub fn new(methods: impl IntoIterator<Item = Method>) -> Self {
        Self {
            methods: methods.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Sets the path templates.
    #[must_use]
    pub fn paths<I, S>(mut self, list: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths = list.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the headers the caller may send.
    #[must_use]
    pub fn headers<I, S>(mut self, list: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.headers = list.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a query parameter the caller may send.
    #[must_use]
    pub fn query(mut self, rule: QueryRule) -> Self {
        self.query.push(rule);
        self
    }

    /// Allows `%25` in the path (off by default).
    #[must_use]
    pub fn encoded_percent(mut self, allow: bool) -> Self {
        self.encoded_percent = allow;
        self
    }

    /// Allows the reserved method-override parameter names (off by default).
    #[must_use]
    pub fn override_params(mut self, allow: bool) -> Self {
        self.override_params = allow;
        self
    }
}

impl Send {
    /// A `send` of the caller's request, within `contract` (HTTPS).
    pub fn caller(contract: CallerRequest) -> Self {
        Self {
            request: Some(StepRequest::Caller(contract)),
            ..Self::default()
        }
    }

    /// A `send` of a request the policy fixes, to the one destination of the operation
    /// (HTTPS).
    pub fn fixed(method: Method, path: &str) -> Self {
        Self {
            request: Some(StepRequest::Fixed {
                method,
                path: path.into(),
                destination: None,
            }),
            ..Self::default()
        }
    }

    /// A `send` of a request the policy fixes, to `destination` (HTTPS).
    pub fn fixed_to(method: Method, path: &str, destination: Destination) -> Self {
        Self {
            request: Some(StepRequest::Fixed {
                method,
                path: path.into(),
                destination: Some(destination),
            }),
            ..Self::default()
        }
    }

    /// A `send` that writes a rendered template (TLS).
    pub fn write(template: &str) -> Self {
        Self {
            template: Some(template.into()),
            ..Self::default()
        }
    }

    /// Adds an injection (HTTPS).
    #[must_use]
    pub fn inject(mut self, injection: Injection) -> Self {
        self.inject.push(injection);
        self
    }
}

impl Receive {
    /// A `receive` of the response of the `send` before it (HTTPS).
    pub fn response() -> Self {
        Self::default()
    }

    /// A `receive` up to the first of `until` (TLS).
    pub fn until<I, S>(until: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            until: until.into_iter().map(Into::into).collect(),
            capture: Vec::new(),
        }
    }

    /// Adds a capture.
    #[must_use]
    pub fn capture(mut self, capture: Capture) -> Self {
        self.capture.push(capture);
        self
    }
}

impl Return {
    /// The status only (HTTPS), no relay (TLS).
    pub fn status() -> Self {
        Self::default()
    }

    /// Lets a response header go back (HTTPS).
    #[must_use]
    pub fn header(mut self, name: &str) -> Self {
        self.response
            .get_or_insert_with(Projection::default)
            .headers
            .push(name.into());
        self
    }

    /// Lets the whole response body go back (HTTPS).
    #[must_use]
    pub fn body(mut self) -> Self {
        self.response.get_or_insert_with(Projection::default).body = Some(BodyProjection::All);
        self
    }

    /// Lets the JSON member at `pointer` go back (HTTPS).
    #[must_use]
    pub fn json(mut self, pointer: &str) -> Self {
        let projection = self.response.get_or_insert_with(Projection::default);
        match &mut projection.body {
            Some(BodyProjection::Json(pointers)) => pointers.push(pointer.into()),
            _ => projection.body = Some(BodyProjection::Json(vec![pointer.into()])),
        }
        self
    }

    /// Relays the caller's sends that match one of `patterns` whole (TLS).
    pub fn relay<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            relay: Some(Relay {
                sends: patterns.into_iter().map(Into::into).collect(),
            }),
            ..Self::default()
        }
    }

    /// Hands back a rendered template (no connection).
    pub fn output(template: &str) -> Self {
        Self {
            template: Some(template.into()),
            ..Self::default()
        }
    }
}

impl From<Open> for Step {
    fn from(step: Open) -> Self {
        Step::Open(step)
    }
}

impl From<Send> for Step {
    fn from(step: Send) -> Self {
        Step::Send(step)
    }
}

impl From<Receive> for Step {
    fn from(step: Receive) -> Self {
        Step::Receive(step)
    }
}

impl From<Compute> for Step {
    fn from(step: Compute) -> Self {
        Step::Compute(step)
    }
}

impl From<Return> for Step {
    fn from(step: Return) -> Self {
        Step::Return(step)
    }
}

impl From<Await> for Step {
    fn from(step: Await) -> Self {
        Step::Await(Box::new(step))
    }
}

impl Challenge {
    /// A code challenge (`sms`, `email`, `app` or `3ds`): the owner's device answers with a
    /// code, which later steps read as the secret temporary value `into`.
    pub fn code(kind: ChallengeKind, hint: &str, into: &str) -> Self {
        Self {
            kind,
            hint: hint.into(),
            into: Some(into.into()),
            pattern: None,
            poll: None,
            timeout_ms: None,
        }
    }

    /// An external challenge: the owner approves in another app, and the node polls the site.
    pub fn external(hint: &str, poll: Poll) -> Self {
        Self {
            kind: ChallengeKind::External,
            hint: hint.into(),
            into: None,
            pattern: None,
            poll: Some(poll),
            timeout_ms: None,
        }
    }

    /// Sets how long the operation waits, in milliseconds.
    #[must_use]
    pub fn waiting_at_most(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
}

impl From<Challenge> for Step {
    fn from(challenge: Challenge) -> Self {
        Step::Await(Box::new(Await { challenge }))
    }
}

impl Operation {
    fn opening(name: &str, connection: Connection, destination: Destination) -> Self {
        Self {
            name: name.into(),
            input: None,
            steps: vec![Step::Open(Open {
                connection,
                destinations: vec![destination],
                identity: None,
            })],
            payment: None,
            approval: false,
        }
    }

    /// An operation that opens HTTPS to `destination`; add its steps with
    /// [`Operation::then`].
    pub fn https(name: &str, destination: Destination) -> Self {
        Self::opening(name, Connection::Https, destination)
    }

    /// An operation that opens a TLS stream to `destination`.
    pub fn tls(name: &str, destination: Destination) -> Self {
        Self::opening(name, Connection::Tls, destination)
    }

    /// An operation with no connection.
    pub fn local(name: &str) -> Self {
        Self {
            name: name.into(),
            input: None,
            steps: Vec::new(),
            payment: None,
            approval: false,
        }
    }

    /// An operation with no connection that hands back `template`, with no input.
    pub fn derive(name: &str, template: &str) -> Self {
        Self::local(name).then(Return::output(template))
    }

    /// Declares that the operation pays: the node checks the amount against the spending
    /// limits of the record, and asks the owner above them.
    #[must_use]
    pub fn pays(mut self, payment: Payment) -> Self {
        self.payment = Some(payment);
        self
    }

    /// Makes every use of the operation wait for the owner's approval.
    #[must_use]
    pub fn approved_each_time(mut self) -> Self {
        self.approval = true;
        self
    }

    /// Declares the schema of the caller's input.
    #[must_use]
    pub fn input(mut self, input: Input) -> Self {
        self.input = Some(input);
        self
    }

    /// Adds a destination to the `open` step.
    #[must_use]
    pub fn destination(mut self, destination: Destination) -> Self {
        if let Some(Step::Open(open)) = self.steps.first_mut() {
            open.destinations.push(destination);
        }
        self
    }

    /// Sets the client certificate of the `open` step.
    #[must_use]
    pub fn identity(mut self, cert: &str, key: &str) -> Self {
        if let Some(Step::Open(open)) = self.steps.first_mut() {
            open.identity = Some(Identity {
                cert: cert.into(),
                key: key.into(),
            });
        }
        self
    }

    /// Adds a step.
    #[must_use]
    pub fn then(mut self, step: impl Into<Step>) -> Self {
        self.steps.push(step.into());
        self
    }

    /// Adds a `compute` step.
    #[must_use]
    pub fn compute(self, into: &str, template: &str) -> Self {
        self.then(Compute {
            into: into.into(),
            template: template.into(),
        })
    }
}
