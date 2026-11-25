//! A node sending through the TLS transport to a local server: the whole path of a value.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use engine::caller::Payload;
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{MemorySink, verify_chain};
use engine::node::{Clock, Node, SystemClock};
use engine::policy::{
    Caller, Destination, FieldSpec, Injection, Method, Operation, Policy, Step, StepRequest,
};
use engine::record::Record;
use engine::request::Request;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use transport::TlsTransport;

const TOKEN: &[u8] = b"tok_live_9f8e7d6c5b4a";

#[test]
fn a_node_sends_through_tls_and_hands_back_the_response() {
    // A server with a certificate for api.test from the test authority of the fixtures.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(include_bytes!("fixtures/api.pem")).unwrap()],
            PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/api.key")).unwrap(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream: StreamOwned<ServerConnection, TcpStream> =
            StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), tcp);
        let mut got = Vec::new();
        let mut byte = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            got.push(byte[0]);
        }
        let body = br#"{"login":"octo"}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(reply.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        tx.send(got).unwrap();
    });

    // The owner: a device, a user key, a caller, and a record with a policy.
    let device = DeviceKey::generate();
    let caller = CallerKey::generate();
    let user_key = [7u8; 32];
    let policy = Policy {
        fields: vec![FieldSpec::secret("token")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller.public(),
            operations: vec!["call".into()],
            limit: None,
        }],
        operations: vec![Operation::Http {
            name: "call".into(),
            destinations: vec![Destination::https("api.test")],
            methods: vec![Method::Get],
            paths: vec!["/user".into()],
            caller_headers: vec![],
            identity: None,
            steps: vec![Step {
                request: StepRequest::Caller,
                inject: vec![Injection::header("Authorization", "Bearer {{token}}")],
                capture: vec![],
            }],
        }],
    };
    let mut values = Fields::new();
    values.insert("token", TOKEN.to_vec()).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "github",
        "alice",
        device.sign_policy(policy).unwrap(),
        &values,
    )
    .unwrap();

    // The node, granted by the device.
    let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
    let now = SystemClock.now_ms();
    let sealed = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            GrantTerms {
                owner: "alice".into(),
                expires_ms: now + 60_000,
                issued_ms: now,
                pins: vec![RecordPin {
                    record_id: "github".into(),
                    generation: record.generation,
                }],
            },
        )
        .unwrap();
    node.grant(&sealed).unwrap();

    // The caller asks for GET /user; the node adds the token and sends it over TLS.
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(include_bytes!("fixtures/ca.pem")).unwrap())
        .unwrap();
    let mut transport = TlsTransport::with_roots(roots).resolver(move |_, _| Ok(vec![address]));
    let request = Request::new(Method::Get, Destination::https("api.test"), "/user");
    let auth = caller
        .authorize(
            "app",
            &node.public_key(),
            &record,
            "call",
            &Payload::Http(Some(&request)),
            now,
        )
        .unwrap();
    let response = node
        .http(&record, "call", &auth, Some(&request), &mut transport)
        .result
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), br#"{"login":"octo"}"#);

    let sent = String::from_utf8(rx.recv().unwrap()).unwrap();
    assert!(sent.starts_with("GET /user HTTP/1.1\r\n"), "{sent}");
    assert!(
        sent.contains("Authorization: Bearer tok_live_9f8e7d6c5b4a\r\n"),
        "{sent}"
    );
    let entries = node.with_sink(|sink| sink.entries().to_vec());
    verify_chain(&entries, &node.public_key()).unwrap();
}
