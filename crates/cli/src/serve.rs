//! The node server: a [`Node`] behind a small HTTP/1.1 server, with its log in an append-only
//! JSONL file (one [`SignedEntry`] per line).
//!
//! There is no authentication of the connection: every act is authorized by what it carries
//! (a sealed grant, a device signature, a signed call). TLS termination, and any limit on who
//! may connect, is the deployer's job.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};

use engine::Error;
use engine::call::{Output, SignedCall};
use engine::encoding::to_b64;
use engine::grant::{Revocation, SealedGrant};
use engine::keys::{Endorsement, NodeKey, Retirement};
use engine::log::{LogSink, SignedEntry, SignedHead};
use engine::node::{Node, SystemClock};
use engine::record::Pin;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use transport::TlsTransport;

use crate::files::{self, Failure, Res};
use crate::http::{self, ReadError};

/// Largest request body by default: a call with a 1 MiB input (base64url in JSON) and a
/// record of up to about 2 MiB.
pub const DEFAULT_MAX_BODY: usize = 4 * 1024 * 1024;

/// Most connections open at once by default; beyond it the server answers 503.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// An append-only JSONL file of signed entries. `append` returns `Ok` only after the line is
/// written and `sync_data` returned.
pub struct FileSink {
    file: File,
    len: u64,
    /// The last entry in the file (`Some(None)` for an empty file), or `None` when a write
    /// failed and the file could not be cut back, so its end is unknown.
    stored: Option<Option<SignedEntry>>,
}

impl FileSink {
    /// Opens the log at `path` (created when missing) and reads every entry in it. A last
    /// line without its newline is an entry whose write never completed, so never confirmed:
    /// it is cut off.
    pub fn open(path: &Path) -> Res<(Self, Vec<SignedEntry>)> {
        let io = |e: std::io::Error| Failure::io(format!("{}: {e}", path.display()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(io)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io)?;
        let complete = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i.saturating_add(1));
        if complete < bytes.len() {
            eprintln!(
                "warning: {}: cutting an incomplete last line ({} bytes); its entry was never confirmed",
                path.display(),
                bytes.len().saturating_sub(complete)
            );
            file.set_len(complete as u64)
                .and_then(|()| file.sync_data())
                .map_err(io)?;
        }
        let mut entries = Vec::new();
        let lines = bytes.get(..complete).unwrap_or(&[]).split(|b| *b == b'\n');
        for (i, line) in lines.enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let entry: SignedEntry = serde_json::from_slice(line).map_err(|e| {
                Failure::io(format!(
                    "{}: line {}: {e}",
                    path.display(),
                    i.saturating_add(1)
                ))
            })?;
            entries.push(entry);
        }
        let sink = Self {
            file,
            len: complete as u64,
            stored: Some(entries.last().cloned()),
        };
        Ok((sink, entries))
    }

    /// The last entry the file holds, when known.
    pub fn stored(&self) -> Option<Option<SignedEntry>> {
        self.stored.clone()
    }

    /// The length of the confirmed part of the file, in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }
}

impl LogSink for FileSink {
    fn append(&mut self, entry: &SignedEntry) -> engine::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(|_| Error::LogUnconfirmed)?;
        line.push(b'\n');
        let written = self
            .file
            .seek(SeekFrom::Start(self.len))
            .and_then(|_| self.file.write_all(&line))
            .and_then(|()| self.file.flush())
            .and_then(|()| self.file.sync_data());
        match written {
            Ok(()) => {
                self.len = self.len.saturating_add(line.len() as u64);
                self.stored = Some(Some(entry.clone()));
                Ok(())
            }
            Err(e) => {
                eprintln!("error: log write failed: {e}");
                // Cut what may have been written, so the file ends with the last confirmed
                // entry again.
                let cut = self
                    .file
                    .set_len(self.len)
                    .and_then(|()| self.file.sync_data());
                if cut.is_err() {
                    self.stored = None;
                }
                Err(Error::LogUnconfirmed)
            }
        }
    }
}

/// A sink that stores nothing; for a node used only to compute its identity.
pub struct NoSink;

impl LogSink for NoSink {
    fn append(&mut self, _: &SignedEntry) -> engine::Result<()> {
        Err(Error::LogUnconfirmed)
    }
}

/// Settings of `credentials serve`.
pub struct Config {
    /// The node key file.
    pub key: PathBuf,
    /// The JSONL log.
    pub log: PathBuf,
    /// Address to listen on.
    pub listen: String,
    /// The checkpoint the log must reach.
    pub anchor: Option<PathBuf>,
    /// Requests that run acts at once (each with its own TLS transport).
    pub threads: usize,
    /// Most connections open at once.
    pub max_connections: usize,
    /// Largest request body, in bytes.
    pub max_body: usize,
}

type ServerNode = Node<FileSink, SystemClock>;

struct Shared {
    node: ServerNode,
    head_path: PathBuf,
    head_lock: Mutex<()>,
}

/// Reads a node key file.
pub fn node_key(path: &Path) -> Res<NodeKey> {
    let mut bytes = files::read_key32(path)?;
    Ok(NodeKey::from_bytes(&mut bytes))
}

/// The path of the checkpoint written next to the log.
pub fn head_path(log: &Path) -> PathBuf {
    let mut path = log.as_os_str().to_owned();
    path.push(".head.json");
    PathBuf::from(path)
}

fn warn_if_exposed(listen: &str) {
    let loopback = listen
        .to_socket_addrs()
        .map(|mut addrs| addrs.all(|a| a.ip().is_loopback()))
        .unwrap_or(false);
    if !loopback {
        eprintln!(
            "warning: listening on {listen}, which is not only loopback. The server does not \
             authenticate connections (only the signed grants and calls they carry) and speaks \
             plain HTTP: terminate TLS in front of it and limit who can reach it."
        );
    }
}

/// Runs the node server until the process ends.
pub fn serve(config: &Config) -> Res<()> {
    let key = node_key(&config.key)?;
    let (sink, entries) = FileSink::open(&config.log)?;
    let restored = match &config.anchor {
        Some(path) => {
            let anchor: SignedHead = files::read_json(path)?;
            Node::restore_anchored(key, sink, SystemClock, &entries, &anchor)
        }
        None => Node::restore(key, sink, SystemClock, &entries),
    };
    let node = restored.map_err(|e| {
        Failure::io(format!(
            "cannot restore the node from {}: {e}",
            config.log.display()
        ))
    })?;
    let shared = Arc::new(Shared {
        node,
        head_path: head_path(&config.log),
        head_lock: Mutex::new(()),
    });
    shared.write_head();
    warn_if_exposed(&config.listen);
    let listener = TcpListener::bind(config.listen.as_str())
        .map_err(|e| Failure::io(format!("cannot listen on {}: {e}", config.listen)))?;
    let address = listener
        .local_addr()
        .map_or_else(|_| config.listen.clone(), |a| a.to_string());
    eprintln!(
        "node {} restored {} log entries; listening on http://{address}",
        shared.node.public_key().to_b64(),
        entries.len()
    );
    let pool = Arc::new(Pool::new(config.threads.max(1)));
    let open = Arc::new(AtomicUsize::new(0));
    let max_connections = config.max_connections.max(1);
    let max_body = config.max_body;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("error: accepting a connection failed: {e}");
                continue;
            }
        };
        let slot = Slot::take(&open, max_connections);
        let Some(slot) = slot else {
            eprintln!("refused a connection: {max_connections} connections already open");
            let body = json!({"error": "too many connections; try again later"});
            http::respond(&mut stream, 503, body.to_string().as_bytes());
            continue;
        };
        let shared = Arc::clone(&shared);
        let pool = Arc::clone(&pool);
        let spawned = std::thread::Builder::new()
            .name("connection".into())
            .spawn(move || {
                handle(&shared, &pool, stream, max_body);
                drop(slot);
            });
        if let Err(e) = spawned {
            eprintln!("error: cannot start a connection thread: {e}");
        }
    }
    Ok(())
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

/// The TLS transports of the acts in flight: an act takes one and gives it back, so at most
/// `threads` acts run at once whatever the number of connections.
struct Pool {
    give: SyncSender<TlsTransport>,
    take: Mutex<Receiver<TlsTransport>>,
}

impl Pool {
    fn new(threads: usize) -> Self {
        let (give, take) = sync_channel(threads);
        for _ in 0..threads {
            // The channel holds exactly `threads`, so this does not block.
            let _ = give.try_send(TlsTransport::new());
        }
        Self {
            give,
            take: Mutex::new(take),
        }
    }

    /// Waits for a free transport.
    fn lease(&self) -> Option<Lease<'_>> {
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
struct Lease<'a> {
    pool: &'a Pool,
    transport: Option<TlsTransport>,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            let _ = self.pool.give.try_send(transport);
        }
    }
}

impl Shared {
    /// Writes the checkpoint next to the log. A real deployment keeps it where the operator
    /// cannot roll it back (TEE sealed storage or a monotonic counter) and restarts with
    /// `--anchor`.
    fn write_head(&self) {
        self.write_head_if(None);
    }

    /// The length of the log file, to tell whether an act appended to it.
    fn log_len(&self) -> u64 {
        self.node.with_sink(|sink| sink.len())
    }

    /// Writes the checkpoint when the log is no longer `before` bytes long (always without
    /// `before`): a refused act appends nothing, so it costs no signature and no fsync.
    fn write_head_if(&self, before: Option<u64>) {
        if before.is_some_and(|before| before == self.log_len()) {
            return;
        }
        let _guard = self
            .head_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match self.node.checkpoint() {
            Ok(head) => {
                if let Err(e) = files::write_json_atomic(&self.head_path, &head) {
                    eprintln!("warning: {e}");
                }
            }
            Err(e) => eprintln!("warning: cannot sign a checkpoint: {e}"),
        }
    }

    /// `None` when the log takes entries; else the reply. A halted log is reconciled first
    /// when the sink knows what the file ends with.
    fn halted(&self) -> Option<(u16, Value)> {
        if !self.node.is_halted() {
            return None;
        }
        if let Some(stored) = self.node.with_sink(|sink| sink.stored()) {
            if self.node.reconcile(stored.as_ref()).is_ok() && !self.node.is_halted() {
                eprintln!("log reconciled after an unconfirmed entry");
                return None;
            }
        }
        Some((
            503,
            json!({"error": "log halted after an unconfirmed entry; the node takes no act until its log is reconciled", "record": null}),
        ))
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
        Error::RateLimited => 429,
        e if e.is_caller_error() => 400,
        _ => 403,
    }
}

fn error_reply(status: u16, message: String) -> (u16, Value) {
    (status, json!({ "error": message }))
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, (u16, Value)> {
    serde_json::from_slice(body).map_err(|e| {
        error_reply(
            400,
            format!("body is not valid JSON for this endpoint: {e}"),
        )
    })
}

fn act<T: DeserializeOwned>(
    shared: &Shared,
    body: &[u8],
    run: impl FnOnce(&ServerNode, &T) -> engine::Result<()>,
) -> (u16, Value) {
    let value: T = match parse(body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    if let Some(reply) = shared.halted() {
        return reply;
    }
    let before = shared.log_len();
    let result = run(&shared.node, &value);
    shared.write_head_if(Some(before));
    match result {
        Ok(()) => (200, json!({ "ok": true })),
        Err(e) => error_reply(status_of(&e), e.to_string()),
    }
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
    }
}

fn call(shared: &Shared, transport: &mut TlsTransport, body: &[u8]) -> (u16, Value) {
    let call: SignedCall = match parse(body) {
        Ok(call) => call,
        Err((status, mut reply)) => {
            if let Some(object) = reply.as_object_mut() {
                object.insert("record".into(), Value::Null);
            }
            return (status, reply);
        }
    };
    if let Some(reply) = shared.halted() {
        return reply;
    }
    let before = shared.log_len();
    let outcome = shared.node.run(&call, transport);
    shared.write_head_if(Some(before));
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

fn route(shared: &Shared, pool: &Pool, request: &http::Request) -> (u16, Value) {
    let body = request.body.as_slice();
    let path = request.path.as_str();
    match (request.method.as_str(), path) {
        ("GET", "/identity") => match serde_json::to_value(shared.node.identity()) {
            Ok(value) => (200, value),
            Err(e) => error_reply(500, e.to_string()),
        },
        ("GET", "/checkpoint") => match shared.node.checkpoint() {
            Ok(head) => match serde_json::to_value(head) {
                Ok(value) => (200, value),
                Err(e) => error_reply(500, e.to_string()),
            },
            Err(e) => error_reply(500, e.to_string()),
        },
        ("POST", "/grant" | "/revoke" | "/pin" | "/device/add" | "/device/retire" | "/call") => {
            // Acts run on at most `threads` transports at once; reads of the identity and
            // the checkpoint above never wait for them.
            let Some(mut lease) = pool.lease() else {
                return error_reply(503, "the node is shutting down".into());
            };
            let Some(transport) = lease.transport.as_mut() else {
                return error_reply(503, "no transport free".into());
            };
            match path {
                "/grant" => act(shared, body, |n, g: &SealedGrant| n.grant(g)),
                "/revoke" => act(shared, body, |n, r: &Revocation| n.revoke(r)),
                "/pin" => act(shared, body, |n, p: &Pin| n.pin(p)),
                "/device/add" => act(shared, body, |n, e: &Endorsement| n.add_device(e)),
                "/device/retire" => act(shared, body, |n, r: &Retirement| n.retire_device(r)),
                _ => call(shared, transport, body),
            }
        }
        (
            method,
            "/identity" | "/checkpoint" | "/grant" | "/revoke" | "/pin" | "/device/add"
            | "/device/retire" | "/call",
        ) => error_reply(405, format!("method {method} not allowed here")),
        _ => error_reply(404, format!("no endpoint {path}")),
    }
}

fn handle(shared: &Shared, pool: &Pool, mut stream: TcpStream, max_body: usize) {
    let (status, body, label) = match http::read_request(&mut stream, max_body) {
        Ok(request) => {
            let (status, body) = route(shared, pool, &request);
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
