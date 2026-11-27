//! DTLS against an in-process server (the server side of the same `dimpl` crate, on the
//! provider of the transport) over in-memory datagram sockets that can lose and repeat
//! datagrams: the handshake of DTLS 1.2 and 1.3, the certificate checks, pins, bounds,
//! retransmission and timeouts, and a node whose server echoes a secret.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dimpl::{Config, Dtls, DtlsCertificate, Output};
use engine::Error;
use engine::caller::Payload;
use engine::egress::{Arrived, Stream, Transport};
use engine::error::TransportKind;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{CallerExchange, Clock, Node, SystemClock};
use engine::policy::{Caller, Destination, FieldSpec, Operation, Policy, Receive, Return, Send};
use engine::record::Record;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PublicKeyData, date_time_ymd,
};
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use transport::TlsTransport;
use transport::dtls::{DtlsError, DtlsStream, MAX_RECORD, Trust};
use transport::udp::{DatagramConnector, DatagramSocket};

const HOST: &str = "coap.example.com";
const PORT: u16 = 5684;

// --- Datagram sockets in memory ---------------------------------------------------------

/// Decides, for the n-th datagram a socket sends (from 0), how many copies go out (0: lost).
type Plan = Box<dyn FnMut(usize, &[u8]) -> usize + std::marker::Send>;

struct MemorySocket {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    sent: Arc<AtomicUsize>,
    plan: Plan,
}

impl DatagramSocket for MemorySocket {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let n = self.sent.fetch_add(1, Ordering::SeqCst);
        for _ in 0..(self.plan)(n, datagram) {
            // A peer that is gone loses what is sent to it, as on a network.
            let _ = self.tx.send(datagram.to_vec());
        }
        Ok(())
    }

    fn recv(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        match self.rx.recv_timeout(wait) {
            Ok(datagram) => Ok(Some(datagram)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

fn every(_: usize, _: &[u8]) -> usize {
    1
}

/// Two connected sockets: the client's and the server's, each with its plan.
fn pair(client: Plan, server: Plan) -> (MemorySocket, MemorySocket, Arc<AtomicUsize>) {
    let (to_server, from_client) = mpsc::channel();
    let (to_client, from_server) = mpsc::channel();
    let client_sent = Arc::new(AtomicUsize::new(0));
    (
        MemorySocket {
            tx: to_server,
            rx: from_server,
            sent: client_sent.clone(),
            plan: client,
        },
        MemorySocket {
            tx: to_client,
            rx: from_client,
            sent: Arc::new(AtomicUsize::new(0)),
            plan: server,
        },
        client_sent,
    )
}

/// Hands out one socket, once.
struct OneSocket(Mutex<Option<MemorySocket>>);

impl DatagramConnector for OneSocket {
    fn open(&self, _: &str, _: u16, _: Instant) -> io::Result<Box<dyn DatagramSocket>> {
        let socket = self.0.lock().unwrap().take();
        socket
            .map(|s| Box::new(s) as Box<dyn DatagramSocket>)
            .ok_or_else(|| io::Error::other("one socket only"))
    }
}

// --- Certificates -----------------------------------------------------------------------

struct Pki {
    root: CertificateDer<'static>,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

fn authority() -> Pki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer = CertifiedIssuer::self_signed(params, key).unwrap();
    Pki {
        root: issuer.der().clone(),
        issuer,
    }
}

fn roots_of(pki: &Pki) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots.add(pki.root.clone()).unwrap();
    Arc::new(roots)
}

/// A server certificate and its PKCS#8 key.
struct Leaf {
    cert: Vec<u8>,
    key: Vec<u8>,
    spki: Vec<u8>,
}

fn params(host: &str) -> CertificateParams {
    CertificateParams::new(vec![host.to_string()]).unwrap()
}

fn issued(pki: &Pki, params: CertificateParams) -> Leaf {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.signed_by(&key, &pki.issuer).unwrap();
    Leaf {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
        spki: key.subject_public_key_info(),
    }
}

fn self_signed(host: &str) -> Leaf {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let cert = params(host).self_signed(&key).unwrap();
    Leaf {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
        spki: key.subject_public_key_info(),
    }
}

fn pin_of(leaf: &Leaf) -> [u8; 32] {
    let hash = ring::digest::digest(&ring::digest::SHA256, &leaf.spki);
    hash.as_ref().try_into().unwrap()
}

// --- The server -------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Debug)]
enum Version {
    V12,
    V13,
}

/// What the server saw.
#[derive(Default, Debug)]
struct Seen {
    records: Vec<Vec<u8>>,
    connected: bool,
}

/// What the server answers to a record.
type Answer = fn(&[u8]) -> Vec<Vec<u8>>;

fn pong(record: &[u8]) -> Vec<Vec<u8>> {
    let mut answer = b"pong:".to_vec();
    answer.extend_from_slice(record);
    vec![answer]
}

struct Server {
    version: Version,
    leaf: Leaf,
    require_client_certificate: bool,
    answer: Answer,
}

impl Server {
    fn new(version: Version, leaf: Leaf) -> Self {
        Self {
            version,
            leaf,
            require_client_certificate: false,
            answer: pong,
        }
    }

    /// Runs on `socket` until the client is gone or ten seconds pass.
    fn spawn(self, mut socket: MemorySocket) -> JoinHandle<Seen> {
        thread::spawn(move || {
            let config = Arc::new(
                Config::builder()
                    .with_crypto_provider(transport::dtls::provider())
                    .require_client_certificate(self.require_client_certificate)
                    .build()
                    .unwrap(),
            );
            let identity = DtlsCertificate {
                certificate: self.leaf.cert.clone(),
                private_key: self.leaf.key.clone(),
            };
            let start = Instant::now();
            let mut dtls = match self.version {
                Version::V12 => Dtls::new_12(config, identity, start),
                Version::V13 => Dtls::new_13(config, identity, start),
            };
            let mut seen = Seen::default();
            let mut buffer = vec![0u8; 1 << 17];
            let end = start + Duration::from_secs(10);
            if dtls.handle_timeout(start).is_err() {
                return seen;
            }
            while Instant::now() < end {
                let mut answers = Vec::new();
                loop {
                    match dtls.poll_output(&mut buffer) {
                        Output::Packet(p) => socket.send(p).unwrap(),
                        Output::Timeout(_) => break,
                        Output::Connected => seen.connected = true,
                        Output::ApplicationData(d) => {
                            seen.records.push(d.to_vec());
                            answers.extend((self.answer)(d));
                        }
                        _ => {}
                    }
                }
                for answer in answers {
                    if dtls.send_application_data(&answer).is_err() {
                        return seen;
                    }
                }
                if !answers_pending(&mut dtls, &mut buffer, &mut socket) {
                    return seen;
                }
                let Ok(received) = socket.recv(Duration::from_millis(20)) else {
                    // The client is gone.
                    return seen;
                };
                match received {
                    Some(datagram) => {
                        if dtls.handle_timeout(Instant::now()).is_err()
                            || dtls.handle_packet(&datagram).is_err()
                        {
                            return seen;
                        }
                    }
                    None => {
                        if dtls.handle_timeout(Instant::now()).is_err() {
                            return seen;
                        }
                    }
                }
            }
            seen
        })
    }
}

/// Sends what answering queued; false when the connection failed.
fn answers_pending(dtls: &mut Dtls, buffer: &mut [u8], socket: &mut MemorySocket) -> bool {
    loop {
        match dtls.poll_output(buffer) {
            Output::Packet(p) => {
                if socket.send(p).is_err() {
                    return false;
                }
            }
            Output::Timeout(_) => return true,
            _ => {}
        }
    }
}

fn trust(pki: &Pki, host: &str, pins: &[[u8; 32]]) -> Trust {
    Trust::new(roots_of(pki), host, pins, &[])
}

fn connect(client: MemorySocket, trust: Trust, wait: Duration) -> Result<DtlsStream, DtlsError> {
    DtlsStream::connect(
        Box::new(client),
        trust,
        Duration::from_secs(5),
        Instant::now() + wait,
    )
}

// --- Handshakes -------------------------------------------------------------------------

#[test]
fn the_provider_passes_the_checks_of_dimpl() {
    // `build` runs dimpl's own test vectors on the provider: AEAD, the PRF and HKDF, the
    // record number mask of DTLS 1.3, signatures and key exchange.
    let built = Config::builder()
        .with_crypto_provider(transport::dtls::provider())
        .build();
    assert!(built.is_ok(), "{:?}", built.err());
}

#[test]
fn a_handshake_with_a_valid_certificate_carries_records_both_ways() {
    for version in [Version::V12, Version::V13] {
        let pki = authority();
        let (client, server, _) = pair(Box::new(every), Box::new(every));
        let seen = Server::new(version, issued(&pki, params(HOST))).spawn(server);
        let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
        let expected = match version {
            Version::V12 => "1.2",
            Version::V13 => "1.3",
        };
        assert_eq!(stream.version(), Some(expected));
        stream.write(b"ping").unwrap();
        assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
        stream.write(b"again").unwrap();
        assert_eq!(
            stream.read_some(1024, Duration::from_secs(5)).unwrap(),
            Arrived::Bytes(b"pong:again".to_vec())
        );
        // Delimiters do not apply to records.
        assert_eq!(
            stream.read_until(&[b"\n"], 1024),
            Err(Error::transport(TransportKind::Unsupported, true))
        );
        stream.close().unwrap();
        drop(stream);
        let seen = seen.join().unwrap();
        assert!(seen.connected, "{version:?}");
        assert_eq!(seen.records, vec![b"ping".to_vec(), b"again".to_vec()]);
    }
}

#[test]
fn the_transport_opens_dtls_through_its_datagram_connector() {
    let pki = authority();
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let seen = Server::new(Version::V13, issued(&pki, params(HOST))).spawn(server);
    let mut roots = RootCertStore::empty();
    roots.add(pki.root.clone()).unwrap();
    let mut transport =
        TlsTransport::with_roots(roots).datagrams(OneSocket(Mutex::new(Some(client))));
    {
        let mut stream = transport
            .open_dtls(&Destination::new(HOST, PORT), &[], &[])
            .unwrap();
        stream.write(b"ping").unwrap();
        assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
    }
    assert_eq!(seen.join().unwrap().records, vec![b"ping".to_vec()]);
}

/// Connects to a server with `leaf` and returns why it was refused, after checking the
/// server got no record.
fn refusal(leaf: Leaf, trust: Trust) -> DtlsError {
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let seen = Server::new(Version::V13, leaf).spawn(server);
    let error = connect(client, trust, Duration::from_secs(10)).unwrap_err();
    let seen = seen.join().unwrap();
    assert!(seen.records.is_empty(), "nothing is sent before the check");
    assert!(!seen.connected, "the client never finished the handshake");
    error
}

#[test]
fn a_certificate_for_another_host_is_refused() {
    let pki = authority();
    let leaf = issued(&pki, params("other.example.com"));
    assert_eq!(
        refusal(leaf, trust(&pki, HOST, &[])),
        DtlsError::Certificate
    );
}

#[test]
fn an_expired_certificate_is_refused() {
    let pki = authority();
    let mut expired = params(HOST);
    expired.not_before = date_time_ymd(2000, 1, 1);
    expired.not_after = date_time_ymd(2001, 1, 1);
    let leaf = issued(&pki, expired);
    assert_eq!(
        refusal(leaf, trust(&pki, HOST, &[])),
        DtlsError::Certificate
    );
}

#[test]
fn a_certificate_of_an_untrusted_authority_is_refused() {
    let pki = authority();
    let stranger = authority();
    let leaf = issued(&stranger, params(HOST));
    assert_eq!(
        refusal(leaf, trust(&pki, HOST, &[])),
        DtlsError::Certificate
    );
}

/// A CA that `pki` issued: its `root` field holds the intermediate's own certificate.
fn intermediate(pki: &Pki) -> Pki {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer = CertifiedIssuer::signed_by(params, key, &pki.issuer).unwrap();
    Pki {
        root: issuer.der().clone(),
        issuer,
    }
}

#[test]
fn a_certificate_under_an_intermediate_is_accepted_through_the_listed_one() {
    for version in [Version::V12, Version::V13] {
        let pki = authority();
        let ca = intermediate(&pki);
        let (client, server, _) = pair(Box::new(every), Box::new(every));
        let seen = Server::new(version, issued(&ca, params(HOST))).spawn(server);
        let trust = Trust::new(roots_of(&pki), HOST, &[], &[ca.root.to_vec()]);
        let mut stream = connect(client, trust, Duration::from_secs(10)).unwrap();
        stream.write(b"ping").unwrap();
        assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
        drop(stream);
        assert_eq!(seen.join().unwrap().records, vec![b"ping".to_vec()]);
    }
}

#[test]
fn a_certificate_under_an_intermediate_that_is_not_listed_is_refused() {
    let pki = authority();
    let ca = intermediate(&pki);
    let leaf = issued(&ca, params(HOST));
    assert_eq!(
        refusal(leaf, trust(&pki, HOST, &[])),
        DtlsError::Certificate
    );
}

#[test]
fn an_intermediate_of_an_untrusted_authority_widens_nothing() {
    // The chain must still end at one of the roots: a listed intermediate that a stranger
    // issued does not make its certificates trusted.
    let pki = authority();
    let stranger = authority();
    let ca = intermediate(&stranger);
    let leaf = issued(&ca, params(HOST));
    let trust = Trust::new(
        roots_of(&pki),
        HOST,
        &[],
        &[ca.root.to_vec(), stranger.root.to_vec()],
    );
    assert_eq!(refusal(leaf, trust), DtlsError::Certificate);
}

#[test]
fn a_self_signed_certificate_is_refused_unless_pinned() {
    let pki = authority();
    assert_eq!(
        refusal(self_signed(HOST), trust(&pki, HOST, &[])),
        DtlsError::Certificate
    );
    // Pinned, but another key.
    let other = self_signed(HOST);
    assert_eq!(
        refusal(self_signed(HOST), trust(&pki, HOST, &[pin_of(&other)])),
        DtlsError::Certificate
    );
    // Pinned, but for another host: the name is still checked.
    let wrong = self_signed("other.example.com");
    let pin = pin_of(&wrong);
    assert_eq!(
        refusal(wrong, trust(&pki, HOST, &[pin])),
        DtlsError::Certificate
    );
}

#[test]
fn a_pinned_certificate_is_accepted() {
    let pki = authority();
    for leaf in [self_signed(HOST), issued(&pki, params(HOST))] {
        let pin = pin_of(&leaf);
        let (client, server, _) = pair(Box::new(every), Box::new(every));
        let seen = Server::new(Version::V12, leaf).spawn(server);
        let mut stream = connect(
            client,
            trust(&pki, HOST, &[[0; 32], pin]),
            Duration::from_secs(10),
        )
        .unwrap();
        stream.write(b"ping").unwrap();
        assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
        drop(stream);
        assert_eq!(seen.join().unwrap().records, vec![b"ping".to_vec()]);
    }
    // A certificate the roots accept, but whose key is not pinned.
    let leaf = issued(&pki, params(HOST));
    let other = issued(&pki, params(HOST));
    assert_eq!(
        refusal(leaf, trust(&pki, HOST, &[pin_of(&other)])),
        DtlsError::Certificate
    );
}

#[test]
fn a_server_that_asks_for_a_client_certificate_is_refused() {
    let pki = authority();
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let mut server_side = Server::new(Version::V12, issued(&pki, params(HOST)));
    server_side.require_client_certificate = true;
    let seen = server_side.spawn(server);
    let error = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap_err();
    assert_eq!(error, DtlsError::Handshake);
    assert!(seen.join().unwrap().records.is_empty());
}

// --- Bounds -----------------------------------------------------------------------------

#[test]
fn a_record_has_a_size_each_way() {
    let pki = authority();
    let (client, server, client_sent) = pair(Box::new(every), Box::new(every));
    let mut server_side = Server::new(Version::V13, issued(&pki, params(HOST)));
    server_side.answer = |_| vec![vec![b'x'; MAX_RECORD + 1]];
    let seen = server_side.spawn(server);
    let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
    let before = client_sent.load(Ordering::SeqCst);
    assert_eq!(
        stream.write(&vec![b'a'; MAX_RECORD + 1]),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    assert_eq!(
        stream.write(b""),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    assert_eq!(client_sent.load(Ordering::SeqCst), before, "nothing sent");
    // A record of the most bytes goes; an answer over the limit is refused.
    stream.write(&vec![b'a'; MAX_RECORD]).unwrap();
    assert_eq!(
        stream.read_until(&[], usize::MAX),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    // The connection is over after that.
    assert!(stream.write(b"ping").is_err());
    drop(stream);
    assert_eq!(seen.join().unwrap().records.len(), 1);
}

#[test]
fn a_read_takes_at_most_its_maximum() {
    let pki = authority();
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let seen = Server::new(Version::V12, issued(&pki, params(HOST))).spawn(server);
    let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
    stream.write(b"ping").unwrap();
    assert_eq!(
        stream.read_until(&[], 4),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
    drop(stream);
    seen.join().unwrap();
}

// --- Loss, repetition and silence -------------------------------------------------------

#[test]
fn lost_handshake_flights_are_sent_again() {
    for version in [Version::V12, Version::V13] {
        let pki = authority();
        // The client's first datagram (its first ClientHello) and the server's first
        // datagram are lost.
        let (client, server, client_sent) = pair(
            Box::new(|n, _| usize::from(n != 0)),
            Box::new(|n, _| usize::from(n != 0)),
        );
        let seen = Server::new(version, issued(&pki, params(HOST))).spawn(server);
        let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
        assert!(client_sent.load(Ordering::SeqCst) > 2);
        stream.write(b"ping").unwrap();
        assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
        drop(stream);
        assert_eq!(seen.join().unwrap().records, vec![b"ping".to_vec()]);
    }
}

#[test]
fn a_lost_request_is_sent_again() {
    let pki = authority();
    let lost = Arc::new(AtomicUsize::new(usize::MAX));
    let mark = lost.clone();
    // Once the handshake is done, the next datagram the client sends is lost.
    let (client, server, client_sent) = pair(
        Box::new(move |n, _| usize::from(n != mark.load(Ordering::SeqCst))),
        Box::new(every),
    );
    let seen = Server::new(Version::V13, issued(&pki, params(HOST))).spawn(server);
    let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
    lost.store(client_sent.load(Ordering::SeqCst), Ordering::SeqCst);
    stream.write(b"ping").unwrap();
    let started = Instant::now();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "after the first resend"
    );
    drop(stream);
    assert_eq!(seen.join().unwrap().records, vec![b"ping".to_vec()]);
}

#[test]
fn a_repeated_record_is_read_once() {
    let pki = authority();
    // Every datagram of the server arrives twice: the second copy is a replay.
    let (client, server, _) = pair(Box::new(every), Box::new(|_, _| 2));
    let seen = Server::new(Version::V12, issued(&pki, params(HOST))).spawn(server);
    let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
    stream.write(b"ping").unwrap();
    assert_eq!(stream.read_until(&[], 1024).unwrap(), b"pong:ping");
    assert_eq!(
        stream.read_some(1024, Duration::from_millis(300)).unwrap(),
        Arrived::Nothing
    );
    drop(stream);
    seen.join().unwrap();
}

#[test]
fn a_silent_server_times_out() {
    let pki = authority();
    let (client, _server, _) = pair(Box::new(every), Box::new(every));
    let started = Instant::now();
    let error = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(2)).unwrap_err();
    assert_eq!(error, DtlsError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_server_that_stops_answering_times_out_a_read() {
    let pki = authority();
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let mut server_side = Server::new(Version::V13, issued(&pki, params(HOST)));
    server_side.answer = |_| Vec::new();
    let seen = server_side.spawn(server);
    let mut stream = connect(client, trust(&pki, HOST, &[]), Duration::from_secs(10)).unwrap();
    stream.write(b"ping").unwrap();
    assert_eq!(
        stream.read_some(1024, Duration::from_millis(500)).unwrap(),
        Arrived::Nothing
    );
    drop(stream);
    seen.join().unwrap();
}

// --- A node over DTLS -------------------------------------------------------------------

const SECRET: &[u8] = b"sk-test-not-a-real-secret-0123456789";

/// A node with one `dtls` operation, the record holding `SECRET`, and a granted caller.
fn node_setup(pins: &[String]) -> (Node<MemorySink, SystemClock>, Record, CallerKey) {
    let device = DeviceKey::generate();
    let caller = CallerKey::generate();
    let user_key = [7u8; 32];
    let mut operation = Operation::dtls("call", Destination::new(HOST, PORT));
    for pin in pins {
        operation = operation.pin(pin);
    }
    let policy = Policy {
        item: None,
        fields: vec![FieldSpec::secret("key")],
        callers: vec![Caller::new("app", caller.public(), ["call"])],
        operations: vec![
            operation
                .then(Send::write("auth {{key}}"))
                .then(Receive::response())
                .then(Return::relay(["[a-z]{1,16}"])),
        ],
    };
    let mut values = Fields::new();
    values.insert("key", SECRET.to_vec()).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "coap",
        "alice",
        device.sign_policy(policy).unwrap(),
        &values,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let now = SystemClock.now_ms();
    let sealed = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            GrantTerms {
                owner: "alice".into(),
                allow_successor: true,
                expires_ms: now + 60_000,
                issued_ms: now,
                pins: vec![RecordPin {
                    record_id: "coap".into(),
                    generation: record.generation,
                }],
            },
        )
        .unwrap();
    node.grant(&sealed).unwrap();
    (node, record, caller)
}

fn exchanges(sends: &[&[u8]]) -> Vec<CallerExchange> {
    sends
        .iter()
        .map(|s| CallerExchange {
            send: s.to_vec(),
            until: vec![],
        })
        .collect()
}

#[test]
fn a_node_sends_a_secret_over_dtls_and_refuses_an_echo_of_it() {
    let pki = authority();
    let leaf = issued(&pki, params(HOST));
    let pin = format!("sha256/{}", base64_standard(&pin_of(&leaf)));
    let (node, record, caller) = node_setup(&[pin]);
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let mut server_side = Server::new(Version::V13, leaf);
    // The server answers the sign-in, then echoes what the caller sends, then the secret.
    server_side.answer = |record| {
        if record.starts_with(b"auth ") {
            vec![b"ok".to_vec()]
        } else if record == b"leak" {
            vec![SECRET.to_vec()]
        } else {
            vec![record.to_vec()]
        }
    };
    let seen = server_side.spawn(server);
    let mut roots = RootCertStore::empty();
    roots.add(pki.root.clone()).unwrap();
    let mut transport =
        TlsTransport::with_roots(roots).datagrams(OneSocket(Mutex::new(Some(client))));
    let destination = Destination::new(HOST, PORT);
    let calls = exchanges(&[b"hello", b"leak"]);
    let payload = Payload::Stream {
        destination: &destination,
        exchanges: &calls,
    };
    let auth = caller
        .authorize(
            "app",
            &node.public_key(),
            &record,
            "call",
            &payload,
            SystemClock.now_ms(),
        )
        .unwrap();
    let out = node
        .stream(&record, "call", &auth, &destination, &calls, &mut transport)
        .result
        .unwrap();
    // The echoed secret ends the exchanges, and no read of the call goes back, not even the
    // one before it.
    assert_eq!(out.error, Some(Error::Reflection));
    assert!(out.reads.is_empty());
    let seen = seen.join().unwrap();
    // The policy's record carried the secret to the server whose certificate was checked;
    // the caller's records followed.
    assert_eq!(seen.records.len(), 3);
    assert!(seen.records[0].starts_with(b"auth "));
    assert!(
        seen.records[0].ends_with(SECRET),
        "the secret went over DTLS"
    );
    assert_eq!(&seen.records[1..], &[b"hello".to_vec(), b"leak".to_vec()]);
}

#[test]
fn a_node_sends_nothing_to_a_server_with_another_key() {
    let pki = authority();
    let leaf = issued(&pki, params(HOST));
    let other = issued(&pki, params(HOST));
    let pin = format!("sha256/{}", base64_standard(&pin_of(&other)));
    let (node, record, caller) = node_setup(&[pin]);
    let (client, server, _) = pair(Box::new(every), Box::new(every));
    let seen = Server::new(Version::V12, leaf).spawn(server);
    let mut roots = RootCertStore::empty();
    roots.add(pki.root.clone()).unwrap();
    let mut transport =
        TlsTransport::with_roots(roots).datagrams(OneSocket(Mutex::new(Some(client))));
    let destination = Destination::new(HOST, PORT);
    let calls = exchanges(&[b"hello"]);
    let payload = Payload::Stream {
        destination: &destination,
        exchanges: &calls,
    };
    let auth = caller
        .authorize(
            "app",
            &node.public_key(),
            &record,
            "call",
            &payload,
            SystemClock.now_ms(),
        )
        .unwrap();
    let outcome = node.stream(&record, "call", &auth, &destination, &calls, &mut transport);
    assert_eq!(
        outcome.result.err(),
        Some(Error::transport(TransportKind::Tls, false))
    );
    assert!(seen.join().unwrap().records.is_empty());
}

/// Standard, padded base64 (the spelling of a pin).
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
