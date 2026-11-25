//! `credentials serve`: a [`Node`] behind the HTTP server of the `server` crate, with its log
//! in an append-only JSONL file (one [`SignedEntry`] per line).
//!
//! There is no authentication of the connection: every act is authorized by what it carries
//! (a sealed grant, a device signature, a signed call). TLS termination, and any limit on who
//! may connect, is the deployer's job.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};

use engine::Error;
use engine::keys::NodeKey;
use engine::log::{LogSink, SignedEntry, SignedHead};
use engine::node::{Node, SystemClock};
use server::{Hooks, Options, Server, Sink};
use transport::TlsTransport;

use crate::files::{self, Failure, Res};

pub use server::{DEFAULT_MAX_BODY, DEFAULT_MAX_CONNECTIONS};

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

impl Sink for FileSink {
    fn confirmed(&self) -> u64 {
        self.len
    }

    fn stored(&mut self) -> Option<Option<SignedEntry>> {
        self.stored.clone()
    }
}

/// Keeps the checkpoint in a file next to the log. A real deployment keeps it where the
/// operator cannot roll it back (TEE sealed storage or a monotonic counter) and restarts with
/// `--anchor`.
struct HeadFile(PathBuf);

impl Hooks for HeadFile {
    fn checkpoint(&self, head: &SignedHead) {
        if let Err(e) = files::write_json_atomic(&self.0, head) {
            eprintln!("warning: {e}");
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
    let server = Server::new(
        node,
        TlsTransport::new,
        Options {
            threads: config.threads,
            max_connections: config.max_connections,
            max_body: config.max_body,
        },
        HeadFile(head_path(&config.log)),
    );
    server.checkpoint();
    warn_if_exposed(&config.listen);
    let listener = TcpListener::bind(config.listen.as_str())
        .map_err(|e| Failure::io(format!("cannot listen on {}: {e}", config.listen)))?;
    let address = listener
        .local_addr()
        .map_or_else(|_| config.listen.clone(), |a| a.to_string());
    eprintln!(
        "node {} restored {} log entries; listening on http://{address}",
        server.node().public_key().to_b64(),
        entries.len()
    );
    server.run(listener.incoming());
    Ok(())
}
