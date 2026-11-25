//! Short constructors for policies written in Rust rather than JSON.
//!
//! ```
//! use engine::keys::CallerKey;
//! use engine::policy::{Caller, Capture, Destination, FieldSpec, Injection, Method, Operation,
//!     Policy, Source, Step, Store};
//!
//! let app = CallerKey::generate();
//! let policy = Policy::new()
//!     .with_field(FieldSpec::secret("refresh_token"))
//!     .with_field(FieldSpec::secret("access_token").optional())
//!     .with_operation(Operation::http("refresh", Destination::https("auth.example.com")).step(
//!         Step::fixed(Method::Post, "/oauth/token")
//!             .inject(Injection::body("grant_type=refresh_token&refresh_token={{pct(refresh_token)}}"))
//!             .capture(Capture::new(Source::json("/access_token"), Store::field("access_token"))),
//!     ))
//!     .with_operation(
//!         Operation::http("call", Destination::https("api.example.com"))
//!             .methods([Method::Get])
//!             .paths(["/v1/"])
//!             .step(Step::caller().inject(Injection::header("Authorization", "Bearer {{access_token}}"))),
//!     )
//!     .with_caller(Caller::new("agent", app.public(), ["refresh", "call"]).limit(100, 60_000));
//! policy.validate().unwrap();
//! ```

use crate::keys::CallerPublicKey;
use crate::policy::{
    Caller, Capture, Destination, Exchange, FieldSpec, Identity, Injection, Limit, Method,
    Operation, Policy, Source, Step, StepRequest, Store, Target,
};

impl Policy {
    /// An empty policy, to fill with [`Policy::with_field`], [`Policy::with_caller`]
    /// and [`Policy::with_operation`].
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            callers: Vec::new(),
            operations: Vec::new(),
        }
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

impl Step {
    /// A step that sends the request of the caller.
    pub fn caller() -> Self {
        Self {
            request: StepRequest::Caller,
            inject: Vec::new(),
            capture: Vec::new(),
        }
    }

    /// A step that sends a request the policy fixes, to the one destination of the operation.
    pub fn fixed(method: Method, path: &str) -> Self {
        Self {
            request: StepRequest::Fixed {
                method,
                path: path.into(),
                destination: None,
            },
            inject: Vec::new(),
            capture: Vec::new(),
        }
    }

    /// A step that sends a request the policy fixes, to `destination`.
    pub fn fixed_to(method: Method, path: &str, destination: Destination) -> Self {
        Self {
            request: StepRequest::Fixed {
                method,
                path: path.into(),
                destination: Some(destination),
            },
            inject: Vec::new(),
            capture: Vec::new(),
        }
    }

    /// Adds an injection.
    #[must_use]
    pub fn inject(mut self, injection: Injection) -> Self {
        self.inject.push(injection);
        self
    }

    /// Adds a capture.
    #[must_use]
    pub fn capture(mut self, capture: Capture) -> Self {
        self.capture.push(capture);
        self
    }
}

impl Exchange {
    /// Writes a rendered template.
    pub fn send(template: &str) -> Self {
        Exchange::Send {
            template: template.into(),
        }
    }

    /// Reads up to the first of `until`.
    pub fn expect<I, S>(until: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Exchange::Expect {
            until: until.into_iter().map(Into::into).collect(),
            capture: Vec::new(),
        }
    }

    /// Adds a capture to an `expect`; on a `send` it does nothing.
    #[must_use]
    pub fn capture(mut self, capture: Capture) -> Self {
        if let Exchange::Expect { capture: c, .. } = &mut self {
            c.push(capture);
        }
        self
    }
}

impl Operation {
    /// An HTTP operation to `destination`, with no steps yet.
    pub fn http(name: &str, destination: Destination) -> Self {
        Operation::Http {
            name: name.into(),
            destinations: vec![destination],
            methods: Vec::new(),
            paths: Vec::new(),
            caller_headers: Vec::new(),
            identity: None,
            steps: Vec::new(),
        }
    }

    /// A stream operation to `destination`, with an empty script.
    pub fn stream(name: &str, destination: Destination) -> Self {
        Operation::Stream {
            name: name.into(),
            destinations: vec![destination],
            identity: None,
            script: Vec::new(),
        }
    }

    /// A derivation.
    pub fn derive(name: &str, template: &str) -> Self {
        Operation::Derive {
            name: name.into(),
            template: template.into(),
        }
    }

    /// Adds a destination (HTTP and stream).
    #[must_use]
    pub fn destination(mut self, destination: Destination) -> Self {
        if let Operation::Http { destinations, .. } | Operation::Stream { destinations, .. } =
            &mut self
        {
            destinations.push(destination);
        }
        self
    }

    /// Sets the methods the caller may use (HTTP).
    #[must_use]
    pub fn methods(mut self, list: impl IntoIterator<Item = Method>) -> Self {
        if let Operation::Http { methods, .. } = &mut self {
            *methods = list.into_iter().collect();
        }
        self
    }

    /// Sets the path prefixes the caller may use (HTTP).
    #[must_use]
    pub fn paths<I, S>(mut self, list: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Operation::Http { paths, .. } = &mut self {
            *paths = list.into_iter().map(Into::into).collect();
        }
        self
    }

    /// Sets the headers the caller may send (HTTP).
    #[must_use]
    pub fn caller_headers<I, S>(mut self, list: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Operation::Http { caller_headers, .. } = &mut self {
            *caller_headers = list.into_iter().map(Into::into).collect();
        }
        self
    }

    /// Sets the client certificate (HTTP and stream).
    #[must_use]
    pub fn identity(mut self, cert: &str, key: &str) -> Self {
        if let Operation::Http { identity, .. } | Operation::Stream { identity, .. } = &mut self {
            *identity = Some(Identity {
                cert: cert.into(),
                key: key.into(),
            });
        }
        self
    }

    /// Adds a step (HTTP).
    #[must_use]
    pub fn step(mut self, step: Step) -> Self {
        if let Operation::Http { steps, .. } = &mut self {
            steps.push(step);
        }
        self
    }

    /// Adds an exchange to the script (stream).
    #[must_use]
    pub fn exchange(mut self, exchange: Exchange) -> Self {
        if let Operation::Stream { script, .. } = &mut self {
            script.push(exchange);
        }
        self
    }
}
