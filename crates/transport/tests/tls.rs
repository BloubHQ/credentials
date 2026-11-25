//! The transport against local TLS servers with a test certificate authority.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use engine::egress::{ClientIdentity, Transport, Version, Versions};
use engine::error::TransportKind;
use engine::policy::Destination;
use engine::{Error, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use transport::TlsTransport;
use zeroize::Zeroizing;

type Server = StreamOwned<ServerConnection, TcpStream>;

struct Leaf {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    cert_pem: String,
    key_pem: String,
}

/// A certificate and key of `tests/fixtures`, made once with openssl (P-256, valid to 2126).
fn load(name: &str) -> Leaf {
    let (cert_pem, key_pem) = match name {
        "api" => (
            include_str!("fixtures/api.pem"),
            include_str!("fixtures/api.key"),
        ),
        "other" => (
            include_str!("fixtures/other.pem"),
            include_str!("fixtures/other.key"),
        ),
        "imap" => (
            include_str!("fixtures/imap.pem"),
            include_str!("fixtures/imap.key"),
        ),
        "client" => (
            include_str!("fixtures/client.pem"),
            include_str!("fixtures/client.key"),
        ),
        "stranger-api" => (
            include_str!("fixtures/stranger-api.pem"),
            include_str!("fixtures/stranger-api.key"),
        ),
        other => panic!("no fixture {other}"),
    };
    Leaf {
        der: CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap(),
        key: PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap(),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
    }
}

/// The test authority that issued every fixture but `stranger-api`.
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(include_bytes!("fixtures/ca.pem")).unwrap())
        .unwrap();
    roots
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config(server: &Leaf, client_ca: Option<RootCertStore>) -> ServerConfig {
    let builder = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(roots) => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
                .build()
                .unwrap(),
        ),
    };
    builder
        .with_single_cert(vec![server.der.clone()], server.key.clone_key())
        .unwrap()
}

/// Serves one connection with `handle`; the receiver gets what it returns.
fn serve<T: Send + 'static>(
    config: ServerConfig,
    handle: impl FnOnce(&mut Server) -> T + Send + 'static,
) -> (SocketAddr, mpsc::Receiver<T>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let config = Arc::new(config);
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
        let _ = tx.send(handle(&mut stream));
    });
    (address, rx)
}

/// Reads one request head, answers `reply` and closes.
fn http(reply: Vec<u8>) -> impl FnOnce(&mut Server) -> Vec<u8> {
    move |stream| {
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => got.push(byte[0]),
                _ => return got,
            }
        }
        let _ = stream.write_all(&reply);
        stream.conn.send_close_notify();
        let _ = stream.flush();
        got
    }
}

fn transport(address: SocketAddr) -> TlsTransport {
    TlsTransport::with_roots(roots()).resolver(move |_, _| Ok(vec![address]))
}

fn send(
    transport: &mut TlsTransport,
    host: &str,
    identity: Option<&ClientIdentity>,
    max: usize,
) -> Result<Vec<u8>> {
    let wire = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    transport.send(&Destination::https(host), identity, wire.as_bytes(), max)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

#[test]
fn sends_a_request_and_reads_the_response() {
    let server = load("api");
    let (address, got) = serve(server_config(&server, None), http(OK.to_vec()));
    let response = send(&mut transport(address), "api.test", None, 1 << 20).unwrap();
    assert_eq!(response, OK);
    let request = got.recv().unwrap();
    assert!(request.starts_with(b"GET / HTTP/1.1\r\nHost: api.test\r\n"));
}

#[test]
fn refuses_a_certificate_for_another_host() {
    let server = load("other");
    let (address, got) = serve(server_config(&server, None), http(OK.to_vec()));
    assert_eq!(
        send(&mut transport(address), "api.test", None, 1 << 20),
        Err(Error::transport(TransportKind::Tls, false))
    );
    assert!(
        got.recv().unwrap().is_empty(),
        "no request reached the server"
    );
}

#[test]
fn refuses_a_server_the_roots_do_not_trust() {
    let server = load("stranger-api");
    let (address, got) = serve(server_config(&server, None), http(OK.to_vec()));
    assert_eq!(
        send(&mut transport(address), "api.test", None, 1 << 20),
        Err(Error::transport(TransportKind::Tls, false))
    );
    assert!(got.recv().unwrap().is_empty());
}

#[test]
fn stops_at_the_size_limit() {
    let server = load("api");
    let mut big = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    big.resize(100 * 1024, b'x');
    let (address, _got) = serve(server_config(&server, None), http(big));
    assert_eq!(
        send(&mut transport(address), "api.test", None, 10 * 1024),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
}

#[test]
fn presents_the_client_certificate_of_the_operation() {
    let server = load("api");
    let client = load("client");
    let identity = ClientIdentity::new(
        Zeroizing::new(client.cert_pem.clone().into_bytes()),
        Zeroizing::new(client.key_pem.clone().into_bytes()),
    );
    let (address, got) = serve(server_config(&server, Some(roots())), |stream| {
        let request = http(OK.to_vec())(stream);
        let presented = stream
            .conn
            .peer_certificates()
            .map(|c| c.to_vec())
            .unwrap_or_default();
        (request, presented)
    });
    let response = send(
        &mut transport(address),
        "api.test",
        Some(&identity),
        1 << 20,
    )
    .unwrap();
    assert_eq!(response, OK);
    let (request, presented) = got.recv().unwrap();
    assert!(!request.is_empty());
    assert_eq!(presented, vec![client.der.clone()]);

    // Without the identity the server refuses the connection.
    let (address, got) = serve(server_config(&server, Some(roots())), http(OK.to_vec()));
    let result = send(&mut transport(address), "api.test", None, 1 << 20);
    assert!(result.is_err(), "{result:?}");
    assert!(got.recv().unwrap().is_empty());
}

#[test]
fn a_silent_server_times_out() {
    let server = load("api");
    let (address, _got) = serve(server_config(&server, None), |stream| {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        thread::sleep(Duration::from_secs(3));
    });
    let mut transport = transport(address).timeouts(
        Duration::from_secs(2),
        Duration::from_millis(300),
        Duration::from_secs(5),
    );
    let started = Instant::now();
    assert_eq!(
        send(&mut transport, "api.test", None, 1 << 20),
        Err(Error::transport(TransportKind::Timeout, true))
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_stream_reads_up_to_each_delimiter() {
    let server = load("imap");
    let (address, got) = serve(server_config(&server, None), |stream| {
        stream.write_all(b"* OK ready\r\na1 OK done\r\n").unwrap();
        stream.flush().unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            stream.read_exact(&mut byte).unwrap();
            line.push(byte[0]);
        }
        stream.write_all(b"a2 OK bye\r\n").unwrap();
        stream.flush().unwrap();
        line
    });
    let mut transport = transport(address);
    let mut stream = transport
        .open(&Destination::new("imap.test", 993), None)
        .unwrap();
    assert_eq!(
        stream.read_until(&[b"\r\n"], 1024).unwrap(),
        b"* OK ready\r\n"
    );
    assert_eq!(
        stream.read_until(&[b"NO", b"\r\n"], 1024).unwrap(),
        b"a1 OK done\r\n"
    );
    stream.write(b"a2 LOGOUT\r\n").unwrap();
    assert_eq!(
        stream.read_until(&[b"\r\n"], 1024).unwrap(),
        b"a2 OK bye\r\n"
    );
    stream.close().unwrap();
    assert_eq!(got.recv().unwrap(), b"a2 LOGOUT\r\n");
}

#[test]
fn a_stream_stops_at_its_limit_without_a_delimiter() {
    let server = load("imap");
    let (address, _got) = serve(server_config(&server, None), |stream| {
        stream.write_all(&[b'z'; 4096]).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(500));
    });
    let mut transport = transport(address);
    let mut stream = transport
        .open(&Destination::new("imap.test", 993), None)
        .unwrap();
    assert_eq!(
        stream.read_until(&[b"\r\n"], 1000).map(|_| ()),
        Err(Error::transport(TransportKind::TooLarge, true))
    );
}

fn with_alpn(server: &Leaf, protocols: &[&[u8]]) -> ServerConfig {
    let mut config = server_config(server, None);
    config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
    config
}

fn exchange(address: SocketAddr, versions: Versions) -> Result<(Vec<u8>, Version)> {
    let wire =
        b"GET / HTTP/1.1\r\nHost: api.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    transport(address).exchange(
        &Destination::https("api.test"),
        None,
        wire,
        1 << 20,
        versions,
    )
}

#[test]
fn a_pinned_http2_is_not_downgraded_by_the_server() {
    // A server that ignores ALPN (it would speak HTTP/1.1) is refused by the transport; one
    // that knows only HTTP/1.1 ends the handshake itself. Either way nothing is written.
    let only_http1: &[&[u8]] = &[b"http/1.1"];
    for (protocols, kind) in [
        (&[][..], TransportKind::Downgrade),
        (only_http1, TransportKind::Tls),
    ] {
        let (address, got) = serve(with_alpn(&load("api"), protocols), http(OK.to_vec()));
        assert_eq!(
            exchange(address, Versions::Http2).err(),
            Some(Error::transport(kind, false))
        );
        assert!(got.recv().unwrap().is_empty(), "the request was not sent");
    }
    // Unpinned, the same server answers over HTTP/1.1.
    let (address, _got) = serve(with_alpn(&load("api"), only_http1), http(OK.to_vec()));
    let (response, version) = exchange(address, Versions::Any).unwrap();
    assert_eq!(response, OK);
    assert_eq!(version, Version::Http1);
}

#[test]
fn http2_is_taken_when_the_server_offers_it() {
    use transport::h2::frame;
    let (address, got) = serve(with_alpn(&load("api"), &[b"h2"]), |stream: &mut Server| {
        let mut preface = [0u8; 24];
        stream.read_exact(&mut preface).unwrap();
        let mut answer = frame(4, 0, 0, &[]);
        answer.extend(frame(4, 1, 0, &[]));
        let block = transport::hpack::encode(&[(b":status", b"200"), (b"x-a", b"1")]);
        answer.extend(frame(1, 4, 1, &block));
        answer.extend(frame(0, 1, 1, b"hi"));
        stream.write_all(&answer).unwrap();
        stream.flush().unwrap();
        // Read until the client closes, so the answer is not cut short by a reset.
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        preface
    });
    let (response, version) = exchange(address, Versions::Http2).unwrap();
    assert_eq!(version, Version::Http2);
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 \r\n"), "{text}");
    assert!(text.contains("x-a: 1\r\n"), "{text}");
    assert!(text.ends_with("hi\r\n0\r\n\r\n"), "{text}");
    assert_eq!(&got.recv().unwrap(), b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

/// Reads one line on the server, then exports keying material as `tls_exporter` does.
fn export_after_line(stream: &mut Server) -> (Vec<u8>, Vec<u8>) {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") {
        stream.read_exact(&mut byte).unwrap();
        line.push(byte[0]);
    }
    let mut out = vec![0u8; 32];
    let exported = stream
        .conn
        .export_keying_material(&mut out, b"EXPORTER-Channel-Binding", Some(b""))
        .is_ok();
    (line, if exported { out } else { Vec::new() })
}

#[test]
fn the_exporter_of_a_stream_matches_the_server() {
    let server = load("imap");
    let (address, got) = serve(server_config(&server, None), export_after_line);
    let mut transport = transport(address);
    let mut stream = transport
        .open(&Destination::new("imap.test", 993), None)
        .unwrap();
    stream.write(b"a1 NOOP\n").unwrap();
    let ours = stream
        .tls_exporter(b"EXPORTER-Channel-Binding", b"", 32)
        .unwrap();
    let (line, theirs) = got.recv().unwrap();
    assert_eq!(line, b"a1 NOOP\n");
    assert_eq!(theirs.len(), 32);
    assert!(ours.as_slice() == theirs.as_slice(), "the two sides differ");
    // Another context gives other bytes.
    let other = stream
        .tls_exporter(b"EXPORTER-Channel-Binding", b"x", 32)
        .unwrap();
    assert!(
        other.as_slice() != theirs.as_slice(),
        "the context is ignored"
    );
}

#[test]
fn no_exporter_over_tls12() {
    let server = load("imap");
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![server.der.clone()], server.key.clone_key())
        .unwrap();
    let (address, _got) = serve(config, export_after_line);
    let mut transport = transport(address);
    let mut stream = transport
        .open(&Destination::new("imap.test", 993), None)
        .unwrap();
    stream.write(b"a1 NOOP\n").unwrap();
    let refused = stream.tls_exporter(b"EXPORTER-Channel-Binding", b"", 32);
    assert_eq!(
        refused.err(),
        Some(Error::transport(TransportKind::Unsupported, true))
    );
}
