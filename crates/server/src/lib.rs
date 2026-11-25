//! The server of a credentials node: a [`Node`] behind a small HTTP/1.1 server.
//!
//! `credentials serve` runs it over TCP with its log in a JSONL file; the `enclave` program
//! runs it over vsock inside an AWS Nitro Enclave with its log on the parent instance. Both
//! give it:
//!
//! - a [`Sink`]: where log entries go, which tells how far the log got;
//! - a transport for each act that may run at once (TLS to the destinations of operations);
//! - [`Hooks`]: where checkpoints are kept, and any endpoint of their own (the enclave answers
//!   `GET /attestation`).
//!
//! There is no authentication of the connection: every act is authorized by what it carries
//! (a sealed grant, a device signature, a signed call). TLS termination, and any limit on who
//! may connect, is the deployer's job.
//!
//! The endpoints: `GET /identity`, `GET /checkpoint`, and `POST /grant`, `/revoke`, `/pin`,
//! `/device/add`, `/device/retire`, `/call`, `/answer` (a code for a challenge, sealed by a
//! device of the owner), `/approve` (the owner's approval of a waiting operation) and
//! `/limits` (spending limits a device of the owner signed). Bodies and answers are JSON.

pub mod http;
pub mod logfile;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};

use engine::Error;
use engine::approval::Approval;
use engine::call::{Output, SignedCall};
use engine::egress::Transport;
use engine::encoding::to_b64;
use engine::grant::{NodeIdentity, Revocation, SealedGrant};
use engine::keys::{Endorsement, Retirement};
use engine::limits::SpendingLimits;
use engine::log::{LogSink, SignedEntry, SignedHead};
use engine::node::{Node, SystemClock};
use engine::record::Pin;
use engine::session::SealedAnswer;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub use http::{Connection, ReadError, Request};

/// Largest request body by default: a call with a 1 MiB input (base64url in JSON) and a
/// record of up to about 2 MiB.
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;

/// Most connections open at once by default; beyond it the server answers 503.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Acts that run at once by default.
pub const DEFAULT_THREADS: usize = 4;

/// A status and a JSON body.
pub type Reply = (u16, Value);

/// Where the log of a served node goes.
pub trait Sink: LogSink + Send {
    /// A number that grows with every confirmed entry (the length of a file, a count): an
    /// act that left it as it was appended nothing, so it needs no new checkpoint.
    fn confirmed(&self) -> u64;

    /// The last entry the store holds (`Some(None)` when it is empty), or `None` when that is
    /// unknown. A halted log is reconciled with it.
    fn stored(&mut self) -> Option<Option<SignedEntry>>;
}

/// What a deployment adds to the server.
pub trait Hooks: Send + Sync {
    /// Keeps a checkpoint of the log: called at the start and after every act that appended.
    /// A real deployment keeps it where the operator cannot roll it back.
    fn checkpoint(&self, head: &SignedHead) {
        let _ = head;
    }

    /// Answers a request the node has no endpoint for; `None` gives 404.
    fn route(&self, request: &Request, identity: &NodeIdentity) -> Option<Reply> {
        let _ = (request, identity);
        None
    }
}

/// No hooks: checkpoints are not kept and there is no endpoint of its own.
pub struct NoHooks;

impl Hooks for NoHooks {}

/// Limits of the server.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Acts that run at once, each with its own transport.
    pub threads: usize,
    /// Most connections open at once; beyond it the server answers 503.
    pub max_connections: usize,
    /// Largest request body, in bytes.
    pub max_body: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: DEFAULT_THREADS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_body: DEFAULT_MAX_BODY,
        }
    }
}

/// The node of a server.
pub type ServerNode<S> = Node<S, SystemClock>;

/// A node behind an HTTP server.
pub struct Server<S: Sink, T> {
    shared: Arc<Shared<S, T>>,
}

struct Shared<S: Sink, T> {
    node: ServerNode<S>,
    hooks: Box<dyn Hooks>,
    head_lock: Mutex<()>,
    pool: Pool<T>,
    open: Arc<AtomicUsize>,
    options: Options,
}

impl<S, T> Server<S, T>
where
    S: Sink + 'static,
    T: Transport + Send + 'static,
{
    /// A server of `node`, with `options.threads` transports made by `transport`.
    pub fn new(
        node: ServerNode<S>,
        mut transport: impl FnMut() -> T,
        options: Options,
        hooks: impl Hooks + 'static,
    ) -> Self {
        let options = Options {
            threads: options.threads.max(1),
            max_connections: options.max_connections.max(1),
            max_body: options.max_body,
        };
        let pool = Pool::new((0..options.threads).map(|_| transport()).collect());
        Self {
            shared: Arc::new(Shared {
                node,
                hooks: Box::new(hooks),
                head_lock: Mutex::new(()),
                pool,
                open: Arc::new(AtomicUsize::new(0)),
                options,
            }),
        }
    }

    /// The node.
    pub fn node(&self) -> &ServerNode<S> {
        &self.shared.node
    }

    /// Signs a checkpoint and hands it to [`Hooks::checkpoint`].
    pub fn checkpoint(&self) {
        self.shared.write_head_if(None);
    }

    /// Serves the connections of `incoming`, each on a thread of its own, until it ends.
    pub fn run<C, I>(&self, incoming: I)
    where
        C: Connection + Send + 'static,
        I: IntoIterator<Item = io::Result<C>>,
    {
        let max_connections = self.shared.options.max_connections;
        for stream in incoming {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("error: accepting a connection failed: {e}");
                    continue;
                }
            };
            let Some(slot) = Slot::take(&self.shared.open, max_connections) else {
                eprintln!("refused a connection: {max_connections} connections already open");
                let body = json!({"error": "too many connections; try again later"});
                http::respond(&mut stream, 503, body.to_string().as_bytes());
                continue;
            };
            let shared = Arc::clone(&self.shared);
            let spawned = std::thread::Builder::new()
                .name("connection".into())
                .spawn(move || {
                    shared.handle(stream);
                    drop(slot);
                });
            if let Err(e) = spawned {
                eprintln!("error: cannot start a connection thread: {e}");
            }
        }
    }
}

/// One of the open connections; frees its place when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(open: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        if open.fetch_add(1, Ordering::SeqCst) >= max {
            open.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self(Arc::clone(open)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The transports of the acts in flight: an act takes one and gives it back, so at most
/// `threads` acts run at once whatever the number of connections.
struct Pool<T> {
    give: SyncSender<T>,
    take: Mutex<Receiver<T>>,
}

impl<T> Pool<T> {
    fn new(transports: Vec<T>) -> Self {
        let (give, take) = sync_channel(transports.len());
        for transport in transports {
            // The channel holds exactly as many, so this does not block.
            let _ = give.try_send(transport);
        }
        Self {
            give,
            take: Mutex::new(take),
        }
    }

    /// Waits for a free transport.
    fn lease(&self) -> Option<Lease<'_, T>> {
        let transport = self
            .take
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv()
            .ok()?;
        Some(Lease {
            pool: self,
            transport: Some(transport),
        })
    }
}

/// A transport taken from the pool; given back when dropped, even on a panic.
struct Lease<'a, T> {
    pool: &'a Pool<T>,
    transport: Option<T>,
}

impl<T> Drop for Lease<'_, T> {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            let _ = self.pool.give.try_send(transport);
        }
    }
}

impl<S: Sink, T: Transport> Shared<S, T> {
    fn confirmed(&self) -> u64 {
        self.node.with_sink(|sink| sink.confirmed())
    }

    /// Hands a new checkpoint to the hooks when the log is no longer at `before` (always
    /// without `before`): a refused act appends nothing, so it costs no signature.
    fn write_head_if(&self, before: Option<u64>) {
        if before.is_some_and(|before| before == self.confirmed()) {
            return;
        }
        let _guard = self
            .head_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match self.node.checkpoint() {
            Ok(head) => self.hooks.checkpoint(&head),
            Err(e) => eprintln!("warning: cannot sign a checkpoint: {e}"),
        }
    }

    /// `None` when the log takes entries; else the reply. A halted log is reconciled first
    /// when the sink knows what the store ends with.
    fn halted(&self) -> Option<Reply> {
        if !self.node.is_halted() {
            return None;
        }
        if let Some(stored) = self.node.with_sink(|sink| sink.stored())
            && self.node.reconcile(stored.as_ref()).is_ok()
            && !self.node.is_halted()
        {
            eprintln!("log reconciled after an unconfirmed entry");
            return None;
        }
        Some((
            503,
            json!({"error": "log halted after an unconfirmed entry; the node takes no act until its log is reconciled", "record": null}),
        ))
    }

    fn act<V: DeserializeOwned>(
        &self,
        body: &[u8],
        run: impl FnOnce(&ServerNode<S>, &V) -> engine::Result<()>,
    ) -> Reply {
        let value: V = match parse(body) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        if let Some(reply) = self.halted() {
            return reply;
        }
        let before = self.confirmed();
        let result = run(&self.node, &value);
        self.write_head_if(Some(before));
        match result {
            Ok(()) => (200, json!({ "ok": true })),
            Err(e) => error_reply(status_of(&e), e.to_string()),
        }
    }

    fn call(&self, transport: &mut T, body: &[u8]) -> Reply {
        let call: SignedCall = match parse(body) {
            Ok(call) => call,
            Err((status, mut reply)) => {
                if let Some(object) = reply.as_object_mut() {
                    object.insert("record".into(), Value::Null);
                }
                return (status, reply);
            }
        };
        if let Some(reply) = self.halted() {
            return reply;
        }
        let before = self.confirmed();
        let outcome = self.node.run(&call, transport);
        self.write_head_if(Some(before));
        let record = match &outcome.record {
            None => Value::Null,
            Some(record) => match serde_json::to_value(record) {
                Ok(value) => value,
                Err(e) => {
                    return error_reply(500, format!("cannot encode the new record: {e}"));
                }
            },
        };
        match &outcome.result {
            Ok(output) => (200, json!({ "ok": output_json(output), "record": record })),
            Err(e) => (
                status_of(e),
                json!({ "error": e.to_string(), "record": record }),
            ),
        }
    }

    fn route(&self, request: &Request) -> Reply {
        let body = request.body.as_slice();
        let path = request.path.as_str();
        match (request.method.as_str(), path) {
            ("GET", "/identity") => match serde_json::to_value(self.node.identity()) {
                Ok(value) => (200, value),
                Err(e) => error_reply(500, e.to_string()),
            },
            ("GET", "/checkpoint") => match self.node.checkpoint() {
                Ok(head) => match serde_json::to_value(head) {
                    Ok(value) => (200, value),
                    Err(e) => error_reply(500, e.to_string()),
                },
                Err(e) => error_reply(500, e.to_string()),
            },
            (
                "POST",
                "/grant" | "/revoke" | "/pin" | "/device/add" | "/device/retire" | "/call"
                | "/answer" | "/approve" | "/limits",
            ) => {
                // Acts run on at most `threads` transports at once; reads of the identity and
                // the checkpoint above never wait for them.
                let Some(mut lease) = self.pool.lease() else {
                    return error_reply(503, "the node is shutting down".into());
                };
                let Some(transport) = lease.transport.as_mut() else {
                    return error_reply(503, "no transport free".into());
                };
                match path {
                    "/grant" => self.act(body, |n, g: &SealedGrant| n.grant(g)),
                    "/revoke" => self.act(body, |n, r: &Revocation| n.revoke(r)),
                    "/pin" => self.act(body, |n, p: &Pin| n.pin(p)),
                    "/device/add" => self.act(body, |n, e: &Endorsement| n.add_device(e)),
                    "/device/retire" => self.act(body, |n, r: &Retirement| n.retire_device(r)),
                    "/answer" => self.act(body, |n, a: &SealedAnswer| n.answer(a)),
                    "/approve" => self.act(body, |n, a: &Approval| n.approve(a)),
                    "/limits" => self.act(body, |n, l: &SpendingLimits| n.set_limits(l)),
                    _ => self.call(transport, body),
                }
            }
            (
                method,
                "/identity" | "/checkpoint" | "/grant" | "/revoke" | "/pin" | "/device/add"
                | "/device/retire" | "/call" | "/answer" | "/approve" | "/limits",
            ) => error_reply(405, format!("method {method} not allowed here")),
            _ => self
                .hooks
                .route(request, &self.node.identity())
                .unwrap_or_else(|| error_reply(404, format!("no endpoint {path}"))),
        }
    }

    fn handle<C: Connection>(&self, mut stream: C) {
        let (status, body, label) = match http::read_request(&mut stream, self.options.max_body) {
            Ok(request) => {
                let (status, body) = self.route(&request);
                (status, body, format!("{} {}", request.method, request.path))
            }
            Err(ReadError::Reply(status, message)) => (
                status,
                json!({ "error": message }),
                "(unread request)".to_string(),
            ),
            Err(ReadError::Gone) => return,
        };
        eprintln!("{label} -> {status}");
        let data = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        http::respond(&mut stream, status, &data);
    }
}

fn status_of(error: &Error) -> u16 {
    match error {
        // Failures before the caller is authenticated share one status, so the status tells
        // a stranger nothing more than "refused" about the grant or record of an owner.
        Error::NoGrant
        | Error::GrantExpired
        | Error::RecordUnpinned
        | Error::RecordStale { .. }
        | Error::PolicySignature => 403,
        Error::LogUnconfirmed | Error::LogHalted => 503,
        Error::Transport(_) => 502,
        Error::RateLimited | Error::ParkedFull => 429,
        e if e.is_caller_error() => 400,
        _ => 403,
    }
}

/// A reply with this status and an `error` message.
pub fn error_reply(status: u16, message: String) -> Reply {
    (status, json!({ "error": message }))
}

fn parse<V: DeserializeOwned>(body: &[u8]) -> Result<V, Reply> {
    serde_json::from_slice(body).map_err(|e| {
        error_reply(
            400,
            format!("body is not valid JSON for this endpoint: {e}"),
        )
    })
}

/// An [`Output`] as JSON: bytes are base64url.
pub fn output_json(output: &Output) -> Value {
    match output {
        Output::Http(response) => json!({
            "kind": "http",
            "response": serde_json::to_value(response).unwrap_or(Value::Null),
        }),
        Output::Stream(stream) => json!({
            "kind": "stream",
            "reads": stream.reads.iter().map(|r| to_b64(r)).collect::<Vec<_>>(),
            "error": stream.error.as_ref().map(ToString::to_string),
        }),
        Output::Derive(bytes) => json!({
            "kind": "derive",
            "output": to_b64(bytes),
            "utf8": std::str::from_utf8(bytes).ok(),
        }),
        Output::Describe(description) => json!({
            "kind": "describe",
            "description": serde_json::to_value(description).unwrap_or(Value::Null),
        }),
        // `{"kind": "challenge", "id", "challenge", "hint", "expires_ms"}` or
        // `{"kind": "approval_required", "id", "summary"}`: resume with the id.
        Output::Pending(pending) => serde_json::to_value(pending).unwrap_or(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(query: &str) -> Request {
        Request {
            method: "GET".into(),
            path: "/attestation".into(),
            query: query.into(),
            body: Vec::new(),
        }
    }

    #[test]
    fn query_parameters() {
        let r = request("nonce=abc&x=1&flag");
        assert_eq!(r.query_param("nonce"), Some("abc"));
        assert_eq!(r.query_param("x"), Some("1"));
        assert_eq!(r.query_param("flag"), Some(""));
        assert_eq!(r.query_param("none"), None);
        assert_eq!(request("").query_param("nonce"), None);
    }

    #[test]
    fn slots_are_capped_and_freed() {
        let open = Arc::new(AtomicUsize::new(0));
        let first = Slot::take(&open, 1);
        assert!(first.is_some());
        assert!(Slot::take(&open, 1).is_none());
        drop(first);
        assert!(Slot::take(&open, 1).is_some());
    }
}
