//! The log link of an enclave node against the log writer of a host, over TCP loopback in
//! place of vsock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use engine::grant::GrantTerms;
use engine::keys::{DeviceKey, NodeKey, NodePublicKey, UserKey};
use engine::log::{SignedEntry, SignedHead};
use engine::node::{Node, SystemClock};
use server::Sink;
use server::relay::{LogLink, LogStore, RelaySink, send_head, serve_log};
use transport::Socket;

#[derive(Default)]
struct MemoryStore {
    entries: Mutex<HashMap<NodePublicKey, Vec<SignedEntry>>>,
    heads: Mutex<Vec<SignedHead>>,
    refuse: AtomicBool,
}

impl LogStore for MemoryStore {
    fn open(&self, node: &NodePublicKey) -> Result<Option<SignedEntry>, String> {
        let entries = self.entries.lock().unwrap();
        Ok(entries.get(node).and_then(|e| e.last().cloned()))
    }

    fn append(&self, node: &NodePublicKey, entry: &SignedEntry) -> Result<(), String> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err("disk full".into());
        }
        let mut entries = self.entries.lock().unwrap();
        entries.entry(*node).or_default().push(entry.clone());
        Ok(())
    }

    fn checkpoint(&self, _: &NodePublicKey, head: &SignedHead) -> Result<(), String> {
        self.heads.lock().unwrap().push(head.clone());
        Ok(())
    }
}

/// A host log writer on loopback; returns the address and the store.
fn host() -> (std::net::SocketAddr, Arc<MemoryStore>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let store = Arc::new(MemoryStore::default());
    let shared = Arc::clone(&store);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let store = Arc::clone(&shared);
            thread::spawn(move || {
                let _ = serve_log(&mut stream, store.as_ref());
            });
        }
    });
    (address, store)
}

fn dial(address: std::net::SocketAddr) -> impl Fn() -> io::Result<Box<dyn Socket>> {
    move || {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        Ok(Box::new(stream) as Box<dyn Socket>)
    }
}

fn grant<S: engine::log::LogSink>(node: &Node<S, SystemClock>, owner: &str) -> engine::Result<()> {
    let device = DeviceKey::generate();
    let terms = GrantTerms::new(owner, Duration::from_secs(3600));
    let sealed = device.grant(&UserKey::generate(), &node.identity(), terms)?;
    node.grant(&sealed)
}

#[test]
fn entries_are_confirmed_by_the_host() {
    let (address, store) = host();
    let key = NodeKey::generate();
    let public = key.public();
    let (link, last) = LogLink::connect(dial(address), public).unwrap();
    assert_eq!(last, None);
    let link = Arc::new(Mutex::new(link));
    let node = Node::new(key, RelaySink::new(Arc::clone(&link), last), SystemClock);

    grant(&node, "alice").unwrap();
    assert_eq!(node.with_sink(|s| s.confirmed()), 1);
    let stored = store.entries.lock().unwrap().get(&public).cloned().unwrap();
    assert_eq!(stored.len(), 1);

    send_head(&link, &node.checkpoint().unwrap()).unwrap();
    assert_eq!(store.heads.lock().unwrap().len(), 1);

    // A host that does not store the entry halts the log; once it stores again, the node
    // learns what the host holds and goes on.
    store.refuse.store(true, Ordering::SeqCst);
    assert!(matches!(
        grant(&node, "bob"),
        Err(engine::Error::LogUnconfirmed)
    ));
    assert!(node.is_halted());
    store.refuse.store(false, Ordering::SeqCst);
    let held = node.with_sink(|s| s.stored());
    assert_eq!(held, Some(stored.last().cloned()));
    node.reconcile(held.flatten().as_ref()).unwrap();
    assert!(!node.is_halted());
    grant(&node, "carol").unwrap();
    assert_eq!(store.entries.lock().unwrap().get(&public).unwrap().len(), 2);
}

#[test]
fn the_first_message_is_hello() {
    use server::relay::{LineReader, LogMessage, LogReply, write_json};

    let (address, _) = host();
    let mut stream = TcpStream::connect(address).unwrap();
    let node = Node::new(NodeKey::generate(), Discard, SystemClock);
    let head = node.checkpoint().unwrap();
    write_json(&mut stream, &LogMessage::Head(head)).unwrap();
    let reply: Option<LogReply> = LineReader::new(1024).read_json(&mut stream).unwrap();
    assert!(matches!(reply, Some(LogReply::Refused(_))));
}

struct Discard;

impl engine::log::LogSink for Discard {
    fn append(&mut self, _: &SignedEntry) -> engine::Result<()> {
        Err(engine::Error::LogUnconfirmed)
    }
}
