//! SSH remote port forwarding (RFC 4254, 7.1): the server listens on the address and port the
//! policy fixes, and the one connection it forwards there becomes the caller's relay. A
//! channel the node did not ask for, to another address or port, or past the live limits is
//! refused; a hand-over ends it.

use engine::node::{CallerFrame, FromCaller, Successor};
use engine::policy::summary::{FlagCode, summarize};
use engine::policy::{Caller, FieldSpec, FrameKind};
use serde_json::{Value, json};

use super::fake_ssh::{HostKind, SshServer};
use super::*;

const PASSWORD: &[u8] = b"hunter2-pass";

fn host() -> HostKind {
    HostKind::Ed25519([11; 32])
}

fn open_step(limits: Value) -> Value {
    json!({"do": "open", "connection": "ssh",
           "destinations": [{"host": "box.example.com", "port": 22}],
           "host_keys": [host().line()],
           "login": {"user": "deploy", "password": "{{password}}"},
           "limits": limits})
}

fn relay(commands: Value) -> Value {
    json!({"server": true,
           "frames": [{"kind": "binary", "shape": {"raw": {"pattern": "[ -~]{1,1024}"}}}],
           "commands": commands})
}

fn remote_operation(limits: Value) -> Operation {
    operation(json!({"name": "back", "steps": [
        open_step(limits),
        {"do": "return", "relay": relay(json!([
            {"name": "web", "text": "127.0.0.1:8080", "channel": "tcpip-forward"},
            {"name": "db", "text": "db.internal:5432", "channel": "direct-tcpip"}
        ]))}
    ]}))
}

fn remote_setup() -> Setup {
    setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![remote_operation(json!({}))],
    )
}

fn server() -> SshServer {
    let mut server = SshServer::new(host());
    server.remote_opens = vec![("forwarded-tcpip", "127.0.0.1", 8080)];
    server
}

fn frame(call: &SignedCall, seq: u64, data: &[u8]) -> FromCaller {
    FromCaller::Frame(CallerFrame {
        seq,
        kind: FrameKind::Binary,
        data: data.to_vec(),
        signature: caller_key().sign_frame(&call.auth, seq, true, data),
    })
}

fn call_of(s: &Setup, commands: Vec<CallerCommand>) -> SignedCall {
    sign(
        s,
        "back",
        session("box.example.com", 22, commands, Vec::new()),
    )
}

fn forward(
    s: &Setup,
    server: SshServer,
    commands: Vec<CallerCommand>,
    frames: &[&[u8]],
) -> (Fake<SshServer>, TestCaller, engine::Result<Output>) {
    let mut fake = Fake::new(server);
    let call = call_of(s, commands);
    let mut caller = TestCaller::default();
    for (i, data) in frames.iter().enumerate() {
        caller.sends.push_back(frame(&call, i as u64, data));
    }
    caller.close = true;
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    (fake, caller, result)
}

/// The `forwarded` notice the caller was handed, if any.
fn notice(caller: &TestCaller) -> Option<Value> {
    caller.parts.iter().find_map(|p| match p {
        Part::Text(t) => serde_json::from_slice(t).ok(),
        _ => None,
    })
}

#[test]
fn a_remote_forward_relays_the_one_connection_to_its_bind() {
    let s = remote_setup();
    let mut server = server();
    // A second connection to the same bind is refused: a forward serves one per call.
    server
        .remote_opens
        .push(("forwarded-tcpip", "127.0.0.1", 8080));
    let sent: &[u8] = &[b'p'; 300];
    let (fake, caller, result) = forward(&s, server, vec![command("web", &[])], &[sent]);
    assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
    let peer = &fake.peer;
    assert_eq!(peer.binds, ["127.0.0.1:8080"]);
    assert_eq!(peer.open_answers, [(100, None), (101, Some(1))]);
    assert_eq!(peer.forwarded, sent);
    assert_eq!(peer.cancels, ["127.0.0.1:8080"], "cancelled at the end");
    assert_eq!(
        notice(&caller),
        Some(json!({"forwarded": {"originator": "203.0.113.9", "port": 40000}}))
    );
    let mut echo = b"echo:".to_vec();
    echo.extend_from_slice(sent);
    // The stream search holds back a tail as long as the longest secret until more comes;
    // the caller closed first, so what came back is a prefix of the echo.
    let back = caller.output();
    assert!(
        back.len() > 5 && echo.starts_with(&back),
        "{} bytes back",
        back.len()
    );
}

#[test]
fn a_channel_not_asked_for_or_to_another_bind_is_refused() {
    let s = remote_setup();
    for opens in [
        vec![("forwarded-tcpip", "127.0.0.1", 8081)],
        vec![("forwarded-tcpip", "10.0.0.1", 8080)],
        vec![("forwarded-tcpip", "0.0.0.0", 8080)],
        vec![("x11", "127.0.0.1", 8080)],
        vec![("session", "127.0.0.1", 8080)],
    ] {
        let mut server = SshServer::new(host());
        server.remote_opens = opens.clone();
        let (fake, caller, result) = forward(&s, server, vec![command("web", &[])], &[]);
        assert!(
            matches!(result, Ok(Output::Closed(_))),
            "{opens:?}: {result:?}"
        );
        assert_eq!(fake.peer.open_answers, [(100, Some(1))], "{opens:?}");
        assert!(notice(&caller).is_none(), "{opens:?}");
    }
    // A local forward asks for no remote one: a forwarded channel is refused.
    let mut server = SshServer::new(host());
    server.reachable = vec!["db.internal:5432".into()];
    server.open_unasked = true;
    server.remote_opens = vec![("forwarded-tcpip", "127.0.0.1", 8080)];
    let (fake, _, result) = forward(&s, server, vec![command("db", &[])], &[b"ping"]);
    assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
    assert!(fake.peer.binds.is_empty());
    assert_eq!(fake.peer.open_answers, [(100, Some(1))]);
    assert_eq!(fake.peer.forwarded, b"ping", "the local forward still runs");
}

#[test]
fn more_refused_channels_than_the_bound_end_the_connection() {
    let s = remote_setup();
    let mut server = SshServer::new(host());
    server.remote_opens =
        vec![("x11", "127.0.0.1", 8080); engine::proto::ssh::MAX_REFUSED_OPENS + 1];
    let (fake, _, result) = forward(&s, server, vec![command("web", &[])], &[]);
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "{result:?}"
    );
    assert_eq!(
        fake.peer.open_answers.len(),
        engine::proto::ssh::MAX_REFUSED_OPENS
    );
}

#[test]
fn the_caller_cannot_pick_the_bind() {
    let s = remote_setup();
    for commands in [
        vec![command("web", &["0.0.0.0:22"])],
        vec![command("0.0.0.0:22", &[])],
        vec![command("web", &[]), command("db", &[])],
    ] {
        let (fake, _, result) = forward(&s, server(), commands, &[]);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "{result:?}"
        );
        assert!(fake.peer.binds.is_empty());
        assert!(fake.opened.is_empty(), "refused before anything opens");
    }
}

#[test]
fn a_frame_before_the_connection_arrives_is_refused() {
    let s = remote_setup();
    let (fake, _, result) = forward(
        &s,
        SshServer::new(host()),
        vec![command("web", &[])],
        &[b"early"],
    );
    assert!(
        matches!(result, Err(engine::Error::FrameRefused { .. })),
        "{result:?}"
    );
    assert!(fake.peer.forwarded.is_empty());
}

#[test]
fn a_server_refusing_to_listen_ends_the_call() {
    let s = remote_setup();
    let mut server = server();
    server.remote_ok = false;
    let (fake, caller, result) = forward(&s, server, vec![command("web", &[])], &[]);
    assert!(result.is_err(), "{result:?}");
    assert_eq!(fake.peer.binds, ["127.0.0.1:8080"]);
    assert!(fake.peer.open_answers.is_empty());
    assert!(notice(&caller).is_none());
}

#[test]
fn a_secret_echoed_through_a_remote_forward_never_goes_back() {
    let s = remote_setup();
    let (_, caller, result) = forward(&s, server(), vec![command("web", &[])], &[PASSWORD]);
    assert!(
        matches!(result, Err(engine::Error::Reflection)),
        "{result:?}"
    );
    assert!(!holds(&caller.output(), b"hunter2"));
}

#[test]
fn a_forwarded_connection_takes_a_live_slot() {
    // Three calls hold three of the caller's slots; the fourth call takes the last one, so
    // the connection the server forwards to it finds the caller full and is refused.
    let s = setup(
        &[(FieldSpec::secret("password"), PASSWORD)],
        vec![remote_operation(json!({"duration_ms": 5_000}))],
    );
    let node = &s.node;
    let held = engine::node::MAX_STREAMS_PER_CALLER - 1;
    // Each held call tells when its server took the forward, so the check waits for a real
    // signal instead of a fixed pause; the held calls last long enough not to end first.
    let (ready, opened) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let threads: Vec<_> = (0..held)
            .map(|_| {
                let call = call_of(&s, vec![command("web", &[])]);
                let ready = ready.clone();
                scope.spawn(move || {
                    // A server that never forwards a connection, and a caller that waits.
                    let mut peer = SshServer::new(host());
                    peer.ready = Some(ready);
                    let mut fake = Fake::new(peer);
                    let mut caller = TestCaller::default();
                    node.relay(&call, &mut fake, &mut caller).result.is_ok()
                })
            })
            .collect();
        for _ in 0..held {
            opened
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("a held call set up its forward");
        }
        let (fake, caller, result) = forward(&s, server(), vec![command("web", &[])], &[]);
        assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
        // 4: SSH_OPEN_RESOURCE_SHORTAGE.
        assert_eq!(fake.peer.open_answers, [(100, Some(4))]);
        assert!(notice(&caller).is_none());
        for t in threads {
            t.join().unwrap();
        }
    });
    // With the slots back, the same forward is taken.
    let (fake, _, result) = forward(&s, server(), vec![command("web", &[])], &[]);
    assert!(matches!(result, Ok(Output::Closed(_))), "{result:?}");
    assert_eq!(fake.peer.open_answers, [(100, None)]);
}

/// A caller whose node hands over when it is handed part `at` (0: the head, 1: the notice).
struct HandingOver<'a> {
    node: &'a TestNode,
    at: usize,
    parts: usize,
    sends: VecDeque<FromCaller>,
}

impl Relay for HandingOver<'_> {
    fn deliver(&mut self, _: Part) -> engine::Result<()> {
        if self.parts == self.at {
            let successor = Successor {
                identity: Node::new(NodeKey::generate(), MemorySink::new(), SystemClock).identity(),
                release: "v9.9.9".into(),
                statement_sha256: [7; 32],
            };
            self.node.hand_over(&successor)?;
        }
        self.parts += 1;
        Ok(())
    }

    fn next(&mut self, _: Duration) -> engine::Result<Option<FromCaller>> {
        Ok(Some(self.sends.pop_front().unwrap_or(FromCaller::Close)))
    }
}

#[test]
fn a_hand_over_closes_the_forwarded_connection() {
    for at in [0, 1] {
        let s = remote_setup();
        let call = call_of(&s, vec![command("web", &[])]);
        let mut fake = Fake::new(server());
        let mut caller = HandingOver {
            node: &s.node,
            at,
            parts: 0,
            sends: vec![frame(&call, 0, b"after")].into(),
        };
        let outcome = s.node.relay(&call, &mut fake, &mut caller);
        assert!(
            matches!(outcome.result, Err(engine::Error::HandedOver)),
            "{at}: {:?}",
            outcome.result
        );
        assert!(
            fake.peer.forwarded.is_empty(),
            "{at}: nothing written after it"
        );
        let answers = &fake.peer.open_answers;
        match at {
            // Handed over before the server forwarded: the channel is refused.
            0 => assert_eq!(answers, &[(100, Some(4))]),
            // Handed over once it was open: it ends with the call.
            _ => assert_eq!(answers, &[(100, None)]),
        }
        assert_eq!(fake.peer.cancels, ["127.0.0.1:8080"], "{at}");
    }
}

fn policy_of(commands: Value) -> Policy {
    Policy {
        item: None,
        fields: vec![FieldSpec::secret("password")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: vec!["back".into()],
            limit: None,
        }],
        operations: vec![operation(json!({"name": "back", "steps": [
            open_step(json!({})),
            {"do": "return", "relay": relay(commands)}
        ]}))],
    }
}

#[test]
fn remote_forward_rules_are_checked_when_the_policy_is_signed() {
    let ok =
        policy_of(json!([{"name": "x", "text": "127.0.0.1:8080", "channel": "tcpip-forward"}]));
    let valid = ok.validate();
    assert!(valid.is_ok(), "{valid:?}");
    for commands in [
        // A bind the caller fills, port 0 (the server would choose), no port, a parameter.
        json!([{"name": "x", "text": "{{host}}:8080", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "127.0.0.1:0", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "127.0.0.1", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "127.0.0.1:8080", "channel": "tcpip-forward",
                "params": [{"pattern": "[0-9]{1,5}"}]}]),
        // Every address of the server, without the policy saying so.
        json!([{"name": "x", "text": "0.0.0.0:8080", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "*:8080", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "[::]:8080", "channel": "tcpip-forward"}]),
        json!([{"name": "x", "text": "0.0.0.0:8080", "channel": "tcpip-forward",
                "wildcard_bind": false}]),
        // The flag on a local forward.
        json!([{"name": "x", "text": "db.internal:5432", "channel": "direct-tcpip",
                "wildcard_bind": true}]),
    ] {
        assert!(
            policy_of(commands.clone()).validate().is_err(),
            "{commands}"
        );
    }
    // A remote forward on a relay that does not stream.
    let mut flat = policy_of(json!([]));
    flat.operations = vec![operation(json!({"name": "back", "steps": [
        open_step(json!({})),
        {"do": "return", "relay": {"commands": [
            {"name": "x", "text": "127.0.0.1:8080", "channel": "tcpip-forward"}]}}
    ]}))];
    assert!(flat.validate().is_err());
}

#[test]
fn the_summary_flags_a_remote_forward_and_a_wildcard_bind() {
    let codes =
        |p: &Policy| -> Vec<FlagCode> { summarize(p, None).flags.iter().map(|f| f.code).collect() };
    let loopback =
        policy_of(json!([{"name": "x", "text": "127.0.0.1:8080", "channel": "tcpip-forward"}]));
    let flags = codes(&loopback);
    assert!(flags.contains(&FlagCode::RemoteForward));
    assert!(!flags.contains(&FlagCode::WildcardBind));
    let lines = loopback.summary().join("\n");
    assert!(lines.contains("127.0.0.1:8080"), "{lines}");

    let wildcard = policy_of(
        json!([{"name": "x", "text": "0.0.0.0:8080", "channel": "tcpip-forward",
                                      "wildcard_bind": true}]),
    );
    let valid = wildcard.validate();
    assert!(valid.is_ok(), "{valid:?}");
    let flags = codes(&wildcard);
    assert!(flags.contains(&FlagCode::RemoteForward));
    assert!(flags.contains(&FlagCode::WildcardBind));
}
