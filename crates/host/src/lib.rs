//! `credentials host`: the program on the parent instance of a Nitro Enclave that runs the
//! `enclave` node. It
//!
//! - forwards each TCP connection of a client to the HTTP port of the enclave (vsock);
//! - relays the egress of the node: it connects only to the `host:port` the node asks for
//!   (and, with `--allow`, only to those listed), and carries bytes it cannot read (TLS ends
//!   inside the enclave);
//! - writes the log of the node: one JSONL file per node key in `--log-dir`, each entry
//!   synced before the node is told it is stored (the semantics of `credentials serve`'s
//!   log file), and the latest checkpoint next to it.
//!
//! The wire is described in the `relay` crate. Only Linux has vsock; elsewhere [`run`]
//! returns [`Error::Unsupported`].

// The log writer and the checks are used by the Linux program (and the tests) only.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use engine::keys::NodePublicKey;
use engine::log::{LogSink, SignedEntry, SignedHead};
use relay::LogStore;
use server::Sink;
use server::logfile::{self, FileSink, head_path};

/// Why the host program could not start or stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// This system has no vsock: the host runs only on the Linux parent instance.
    #[error(
        "`credentials host` runs on the Linux parent instance of an AWS Nitro Enclave (it \
         needs vsock); run a node elsewhere with `credentials serve`"
    )]
    Unsupported,
    /// A file, a directory or a socket failed; `context` says which and what was done.
    #[error("{context}: {source}")]
    Io {
        /// What was done, and with what.
        context: String,
        /// The failure.
        source: io::Error,
    },
}

/// Settings of `credentials host`.
pub struct Config {
    /// TCP address clients connect to.
    pub listen: String,
    /// The vsock CID of the enclave.
    pub enclave_cid: u32,
    /// The vsock port of the node server in the enclave.
    pub http_port: u32,
    /// The vsock port of the egress relay on this host.
    pub egress_port: u32,
    /// The vsock port of the log writer on this host.
    pub log_port: u32,
    /// Where the logs go.
    pub log_dir: PathBuf,
    /// The only `host:port` the relay connects to over TCP, and `udp/host:port` it relays
    /// datagrams to; empty: whatever the node asks.
    pub allow: Vec<String>,
    /// Most client connections open at once.
    pub max_connections: usize,
}

/// Whether the relay may connect to `host:port` over TCP: any destination with an empty
/// list, else only one listed (the host compared without case).
pub fn allowed(allow: &[String], host: &str, port: u16) -> bool {
    allow.is_empty() || allow.iter().any(|entry| names(entry, host, port))
}

/// Whether the relay may send datagrams to `host:port`: any destination with an empty list,
/// else only one listed as `udp/host:port`. A TCP entry does not allow datagrams, nor a UDP
/// entry a TCP connection.
pub fn allowed_datagrams(allow: &[String], host: &str, port: u16) -> bool {
    allow.is_empty()
        || allow.iter().any(|entry| {
            entry
                .strip_prefix(UDP_PREFIX)
                .is_some_and(|entry| names(entry, host, port))
        })
}

/// The prefix of an `--allow` entry for datagrams.
const UDP_PREFIX: &str = "udp/";

fn names(entry: &str, host: &str, port: u16) -> bool {
    entry
        .rsplit_once(':')
        .is_some_and(|(h, p)| h.eq_ignore_ascii_case(host) && p.parse::<u16>().ok() == Some(port))
}

/// Checks an `--allow` value: `host:port`, or `udp/host:port` for datagrams.
pub fn parse_allow(entry: &str) -> Result<String, String> {
    let target = entry.strip_prefix(UDP_PREFIX).unwrap_or(entry);
    match target.rsplit_once(':') {
        Some((host, port))
            if relay::valid_host(host) && port.parse::<u16>().is_ok_and(|p| p > 0) =>
        {
            Ok(entry.to_string())
        }
        _ => Err(format!("{entry:?} is not host:port or udp/host:port")),
    }
}

/// The logs of the nodes this host ran: `<dir>/<node log key>.jsonl`, with the checkpoint in
/// `<dir>/<node log key>.jsonl.head.json`.
pub struct LogDir {
    dir: PathBuf,
    open: Mutex<HashMap<NodePublicKey, FileSink>>,
}

impl LogDir {
    /// The logs in `dir`, which is created when missing.
    pub fn new(dir: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(dir).map_err(|source| Error::Io {
            context: dir.display().to_string(),
            source,
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            open: Mutex::new(HashMap::new()),
        })
    }

    /// The log file of `node`.
    pub fn path(&self, node: &NodePublicKey) -> PathBuf {
        self.dir.join(format!("{}.jsonl", node.to_b64()))
    }
}

impl LogStore for LogDir {
    fn open(&self, node: &NodePublicKey) -> Result<Option<SignedEntry>, String> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = open.get_mut(node) {
            return sink
                .stored()
                .ok_or_else(|| "the end of the log file is unknown after a failed write".into());
        }
        let path = self.path(node);
        let (sink, entries) = FileSink::open(&path).map_err(|e| e.to_string())?;
        eprintln!(
            "log of node {}: {} ({} entries)",
            node.to_b64(),
            path.display(),
            entries.len()
        );
        open.insert(*node, sink);
        Ok(entries.last().cloned())
    }

    fn append(&self, node: &NodePublicKey, entry: &SignedEntry) -> Result<(), String> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let sink = open
            .get_mut(node)
            .ok_or_else(|| "the log of this node is not open".to_string())?;
        sink.append(entry).map_err(|e| e.to_string())
    }

    fn checkpoint(&self, node: &NodePublicKey, head: &SignedHead) -> Result<(), String> {
        logfile::write_json_atomic(&head_path(&self.path(node)), head).map_err(|e| e.to_string())
    }
}

#[cfg(target_os = "linux")]
pub use linux::run;

/// Runs the host program: only on the Linux parent instance of an enclave.
#[cfg(not(target_os = "linux"))]
pub fn run(_: &Config) -> Result<(), Error> {
    Err(Error::Unsupported)
}

/// Carries the hand-over protocol from the enclave `from_cid` (the running node) to the
/// enclave `to_cid` (a node of the release `statement` names), over vsock port
/// [`continuity::wire::HANDOVER_PORT`] of each. The enclaves check everything: the host
/// only relays (see [`continuity::wire::drive`]).
#[cfg(target_os = "linux")]
pub fn hand_over(
    from_cid: u32,
    to_cid: u32,
    statement: &continuity::SignedStatement,
) -> Result<engine::node::TakenOver, HandOverError> {
    use continuity::wire::HANDOVER_PORT;
    use relay::vsock::Vsock;
    let connect = |cid: u32| {
        Vsock::connect(cid, HANDOVER_PORT).map_err(|source| Error::Io {
            context: format!("cannot reach the enclave (cid {cid}, port {HANDOVER_PORT})"),
            source,
        })
    };
    let mut old = connect(from_cid)?;
    let mut new = connect(to_cid)?;
    Ok(continuity::wire::drive(&mut old, &mut new, statement)?)
}

/// Carries the hand-over protocol: only on the Linux parent instance of the enclaves.
#[cfg(not(target_os = "linux"))]
pub fn hand_over(
    _: u32,
    _: u32,
    _: &continuity::SignedStatement,
) -> Result<engine::node::TakenOver, HandOverError> {
    Err(HandOverError::Host(Error::Unsupported))
}

/// Why a hand-over did not complete.
#[derive(Debug, thiserror::Error)]
pub enum HandOverError {
    /// The host could not reach an enclave.
    #[error(transparent)]
    Host(#[from] Error),
    /// An enclave refused, or the protocol failed.
    #[error(transparent)]
    Protocol(#[from] continuity::Error),
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::{TcpListener, TcpStream, ToSocketAddrs};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use relay::datagram::{self, Egress};
    use relay::vsock::{self, Vsock};
    use relay::{answer_tunnel, serve_log, splice};
    use transport::Socket;

    use super::{Config, Error, LogDir, allowed, allowed_datagrams};

    /// How long the relay waits to connect to a destination.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// How long a relayed connection may stay silent (the node gives up after 120 s).
    const IDLE_TIMEOUT: Duration = Duration::from_secs(130);

    fn spawn(name: &str, work: impl FnOnce() + Send + 'static) {
        if let Err(e) = thread::Builder::new().name(name.into()).spawn(work) {
            eprintln!("error: cannot start a {name} thread: {e}");
        }
    }

    fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address for the host");
        for address in (host, port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn pair<S: Socket + 'static>(
        stream: S,
        clone: io::Result<S>,
    ) -> io::Result<(Box<dyn Socket>, Box<dyn Socket>)> {
        let clone = clone?;
        stream.set_timeouts(Some(IDLE_TIMEOUT))?;
        Ok((Box::new(stream), Box::new(clone)))
    }

    fn egress(mut link: Vsock, allow: &[String]) {
        let _ = link.0.set_read_timeout(Some(CONNECT_TIMEOUT));
        let (kind, host, port) = match datagram::read_egress_request(&mut link) {
            Ok(target) => target,
            Err(e) => {
                eprintln!("egress: {e}");
                return;
            }
        };
        if kind == Egress::Datagram {
            datagrams(link, allow, &host, port);
            return;
        }
        if !allowed(allow, &host, port) {
            eprintln!("egress: refused {host}:{port} (not in --allow)");
            let _ = answer_tunnel(&mut link, Err("destination not allowed by the host"));
            return;
        }
        let tcp = match connect_tcp(&host, port) {
            Ok(tcp) => tcp,
            Err(e) => {
                eprintln!("egress: cannot connect to {host}:{port}: {e}");
                let _ = answer_tunnel(&mut link, Err("cannot connect"));
                return;
            }
        };
        if answer_tunnel(&mut link, Ok(())).is_err() {
            return;
        }
        eprintln!("egress: {host}:{port}");
        let clone = link.try_clone();
        let tcp_clone = tcp.try_clone();
        match (pair(link, clone), pair(tcp, tcp_clone)) {
            (Ok((a, a2)), Ok((b, b2))) => splice(a, a2, b, b2),
            _ => eprintln!("egress: cannot set up the relay of {host}:{port}"),
        }
    }

    /// Relays the datagrams of a `DATAGRAM` link to `host:port`.
    fn datagrams(mut link: Vsock, allow: &[String], host: &str, port: u16) {
        if !allowed_datagrams(allow, host, port) {
            eprintln!("egress: refused udp/{host}:{port} (not in --allow)");
            let _ = answer_tunnel(&mut link, Err("destination not allowed by the host"));
            return;
        }
        let udp = match datagram::connect_udp(host, port) {
            Ok(udp) => udp,
            Err(e) => {
                eprintln!("egress: cannot open udp/{host}:{port}: {e}");
                let _ = answer_tunnel(&mut link, Err("cannot connect"));
                return;
            }
        };
        if answer_tunnel(&mut link, Ok(())).is_err() {
            return;
        }
        eprintln!("egress: udp/{host}:{port}");
        let clone = link.try_clone();
        match pair(link, clone) {
            Ok((a, a2)) => {
                if let Err(e) = datagram::serve_datagrams(a, a2, udp, datagram::IDLE) {
                    eprintln!("egress: udp/{host}:{port}: {e}");
                }
            }
            Err(_) => eprintln!("egress: cannot set up the relay of udp/{host}:{port}"),
        }
    }

    fn forward(client: TcpStream, cid: u32, port: u32) {
        let enclave = match Vsock::connect(cid, port) {
            Ok(enclave) => enclave,
            Err(e) => {
                eprintln!("error: cannot reach the enclave (cid {cid}, port {port}): {e}");
                let mut client = client;
                let body = br#"{"error":"the enclave is not reachable"}"#;
                server::http::respond(&mut client, 502, body);
                return;
            }
        };
        let client_clone = client.try_clone();
        let enclave_clone = enclave.try_clone();
        match (pair(client, client_clone), pair(enclave, enclave_clone)) {
            (Ok((a, a2)), Ok((b, b2))) => splice(a, a2, b, b2),
            _ => eprintln!("error: cannot set up the forwarding of a connection"),
        }
    }

    /// Runs the host program until the TCP listener fails.
    pub fn run(config: &Config) -> Result<(), Error> {
        let store = Arc::new(LogDir::new(&config.log_dir)?);
        let bind = |port: u32| {
            vsock::listen(port).map_err(|source| Error::Io {
                context: format!("cannot listen on vsock port {port}"),
                source,
            })
        };
        let log_listener = bind(config.log_port)?;
        let egress_listener = bind(config.egress_port)?;
        let listener = TcpListener::bind(config.listen.as_str()).map_err(|source| Error::Io {
            context: format!("cannot listen on {}", config.listen),
            source,
        })?;

        spawn("log", move || {
            for link in log_listener.incoming() {
                let Ok(link) = link else { continue };
                let store = Arc::clone(&store);
                spawn("log link", move || {
                    let mut link = Vsock(link);
                    if let Err(e) = serve_log(&mut link, store.as_ref()) {
                        eprintln!("log: {e}");
                    }
                });
            }
        });
        let allow = Arc::new(config.allow.clone());
        spawn("egress", move || {
            for link in egress_listener.incoming() {
                let Ok(link) = link else { continue };
                let allow = Arc::clone(&allow);
                spawn("egress link", move || egress(Vsock(link), &allow));
            }
        });

        eprintln!(
            "forwarding http://{} to enclave cid {} port {}; egress on vsock port {}, log on \
             vsock port {} into {}",
            config.listen,
            config.enclave_cid,
            config.http_port,
            config.egress_port,
            config.log_port,
            config.log_dir.display()
        );
        let open = Arc::new(AtomicUsize::new(0));
        let max = config.max_connections.max(1);
        let (cid, port) = (config.enclave_cid, config.http_port);
        for client in listener.incoming() {
            let Ok(mut client) = client else { continue };
            if open.fetch_add(1, Ordering::SeqCst) >= max {
                open.fetch_sub(1, Ordering::SeqCst);
                let body = br#"{"error":"too many connections; try again later"}"#;
                server::http::respond(&mut client, 503, body);
                continue;
            }
            let open = Arc::clone(&open);
            spawn("forward", move || {
                forward(client, cid, port);
                open.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use engine::grant::GrantTerms;
    use engine::keys::{DeviceKey, NodeKey, UserKey};
    use engine::log::MemorySink;
    use engine::node::{Node, SystemClock};

    use super::*;

    #[test]
    fn allow_list() {
        let allow = vec!["api.example.com:443".to_string()];
        assert!(allowed(&allow, "API.example.com", 443));
        assert!(!allowed(&allow, "api.example.com", 80));
        assert!(!allowed(&allow, "other.example.com", 443));
        assert!(allowed(&[], "anything", 1));
        assert!(parse_allow("api.example.com:443").is_ok());
        assert!(parse_allow("api.example.com").is_err());
        assert!(parse_allow("api.example.com:0").is_err());
        assert!(parse_allow("bad host:443").is_err());
        // Datagrams need their own entries.
        assert!(parse_allow("udp/radius.example.com:1812").is_ok());
        let allow = vec![
            "udp/radius.example.com:1812".to_string(),
            "api.example.com:443".to_string(),
        ];
        assert!(allowed_datagrams(&allow, "RADIUS.example.com", 1812));
        assert!(!allowed_datagrams(&allow, "radius.example.com", 1813));
        assert!(!allowed_datagrams(&allow, "api.example.com", 443));
        assert!(!allowed(&allow, "radius.example.com", 1812));
        assert!(allowed_datagrams(&[], "anything", 53));
        assert!(parse_allow("udp/radius.example.com").is_err());
        assert!(parse_allow("tcp/radius.example.com:1812").is_err());
    }

    #[test]
    fn log_dir_keeps_one_file_per_node() {
        let dir = std::env::temp_dir().join(format!(
            "host-logs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let Ok(store) = LogDir::new(&dir) else {
            return;
        };
        let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
        let device = DeviceKey::generate();
        let terms = GrantTerms::new("alice", Duration::from_secs(60));
        let sealed = device.grant(&UserKey::generate(), &node.identity(), terms);
        assert!(sealed.is_ok_and(|sealed| node.grant(&sealed).is_ok()));
        let entries = node.with_sink(|sink| sink.entries().to_vec());
        let key = node.public_key();

        let Some(first) = entries.first() else {
            return;
        };
        assert!(store.append(&key, first).is_err(), "not open yet");
        assert_eq!(store.open(&key), Ok(None));
        for entry in &entries {
            assert_eq!(store.append(&key, entry), Ok(()));
        }
        assert_eq!(store.open(&key), Ok(entries.last().cloned()));
        let head = node.checkpoint();
        assert!(head.is_ok_and(|head| store.checkpoint(&key, &head).is_ok()));
        assert!(head_path(&store.path(&key)).exists());

        // A new host process reads the file back.
        let again = LogDir::new(&dir);
        assert!(again.is_ok_and(|again| again.open(&key) == Ok(entries.last().cloned())));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
