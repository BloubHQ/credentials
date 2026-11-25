//! `credentials serve`: a [`Node`] behind the HTTP server of the `server` crate, with its log
//! in an append-only JSONL file (one [`SignedEntry`] per line).
//!
//! There is no authentication of the connection: every act is authorized by what it carries
//! (a sealed grant, a device signature, a signed call). TLS termination, and any limit on who
//! may connect, is the deployer's job.

use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};

use engine::Error;
use engine::keys::NodeKey;
use engine::log::{LogSink, SignedEntry, SignedHead};
use engine::node::{Node, SystemClock};
use server::logfile::{FileSink, HeadFile, head_path};
use server::{Options, Server};
use transport::TlsTransport;

use crate::files::{self, Failure, Res};

pub use server::{DEFAULT_MAX_BODY, DEFAULT_MAX_CONNECTIONS};

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
    let (sink, entries) = FileSink::open(&config.log).map_err(|e| Failure::io(e.to_string()))?;
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
            streams: server::DEFAULT_STREAMS,
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
