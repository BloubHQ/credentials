//! SSH: sign-in, pinned host keys, algorithms, commands within their shapes, reflection,
//! limits and the shell relay.

use engine::log::Event;
use engine::node::{CallerFrame, FromCaller};
use engine::policy::{FieldSpec, FrameKind};
use serde_json::{Value, json};

use super::fake_ssh::{HostKind, Misbehave, SshServer};
use super::*;

const PASSWORD: &[u8] = b"hunter2-pass";

fn host() -> HostKind {
    HostKind::Ed25519([11; 32])
}

fn open(host_keys: Vec<String>, login: Value, limits: Value) -> Value {
    json!({"do": "open", "connection": "ssh",
           "destinations": [{"host": "box.example.com", "port": 22}],
           "host_keys": host_keys, "login": login, "limits": limits})
}

fn password_login() -> Value {
    json!({"user": "deploy", "password": "{{password}}"})
}

/// An operation that runs caller commands `echo` (a word of letters and spaces) and `cat`
/// (a file name), after an optional fixed command.
fn ssh_operation(name: &str, open_step: Value, fixed: Option<&str>) -> Operation {
    let mut steps = vec![open_step];
    if let Some(text) = fixed {
        steps.push(json!({"do": "send", "command": {"text": text}}));
        steps.push(json!({"do": "receive", "capture": [
            {"source": {"from": "all"}, "into": {"kind": "temp", "name": "motd", "secret": false}}
        ]}));
    }
    steps.push(json!({"do": "return", "relay": {"commands": [
        {"name": "echo", "text": "echo", "params": [{"pattern": "[a-z ;/-]{1,64}"}]},
        {"name": "cat", "text": "cat", "params": [{"pattern": "[a-z.]{1,32}"}]},
        {"name": "id", "text": "id"}
    ]}}));
    operation(json!({"name": name, "steps": steps}))
}

fn password_field() -> (FieldSpec, &'static [u8]) {
    (FieldSpec::secret("password"), PASSWORD)
}

fn server() -> SshServer {
    let mut server = SshServer::new(host());
    server.exec = |command| match command {
        b"id" => (b"uid=1000(deploy)\n".to_vec(), Vec::new(), 0),
        b"cat secret.txt" | b"cat 'secret.txt'" => (b"pw: hunter2-pass\n".to_vec(), Vec::new(), 0),
        b"motd" => (b"welcome\n".to_vec(), Vec::new(), 0),
        other => {
            let mut out = b"ran: ".to_vec();
            out.extend_from_slice(other);
            (out, b"warn\n".to_vec(), 3)
        }
    };
    server
}

fn run_session(
    s: &Setup,
    fake: &mut Fake<SshServer>,
    commands: Vec<CallerCommand>,
) -> engine::Result<engine::call::Output> {
    let call = sign(
        s,
        "ssh",
        session("box.example.com", 22, commands, Vec::new()),
    );
    s.node.run(&call, fake).result
}

fn basic(limits: Value) -> Setup {
    setup(
        &[password_field()],
        vec![ssh_operation(
            "ssh",
            open(vec![host().line()], password_login(), limits),
            None,
        )],
    )
}

#[test]
fn password_sign_in_runs_commands_with_quoted_parameters() {
    let s = basic(json!({}));
    let mut fake = Fake::new(server());
    let out = session_output(run_session(
        &s,
        &mut fake,
        vec![command("id", &[]), command("echo", &["hello world"])],
    ));
    assert!(out.error.is_none(), "error: {:?}", out.error.is_some());
    assert_eq!(out.results.len(), 2);
    assert_eq!(out.results[0].data, b"uid=1000(deploy)\n");
    assert_eq!(out.results[0].status, Some(0));
    assert_eq!(out.results[1].data, b"ran: echo 'hello world'");
    assert_eq!(out.results[1].stderr, b"warn\n");
    assert_eq!(out.results[1].status, Some(3));
    assert_eq!(fake.opened, ["plain"]);
    assert_eq!(fake.peer.methods, ["password"]);
    assert_eq!(fake.peer.agreed_cipher, "aes256-gcm@openssh.com");
    assert_eq!(fake.peer.agreed_kex, "curve25519-sha256");
    let (ok, reason) = last_closed(&s);
    assert!(ok);
    assert_eq!(reason, "done");
    // The use, then how it ended.
    let kinds: Vec<&str> = events(&s)
        .iter()
        .filter_map(|e| match e {
            Event::Stream { .. } => Some("use"),
            Event::Closed { .. } => Some("closed"),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, ["use", "closed"]);
}

#[test]
fn shell_injection_through_a_parameter_stays_one_word() {
    let s = basic(json!({}));
    let mut fake = Fake::new(server());
    let out = session_output(run_session(
        &s,
        &mut fake,
        vec![command("echo", &["x; rm -rf /"])],
    ));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.execs, [b"echo 'x; rm -rf /'".to_vec()]);
}

#[test]
fn a_command_outside_its_shape_is_refused_before_anything_is_written() {
    let s = basic(json!({}));
    for commands in [
        vec![command("rm", &["-rf"])],
        vec![command("echo", &["$(reboot)"])],
        vec![command("echo", &["a", "b"])],
        vec![command("id", &["extra"])],
        vec![command("cat", &["../etc/passwd"])],
    ] {
        let mut fake = Fake::new(server());
        let result = run_session(&s, &mut fake, commands);
        assert!(
            matches!(result, Err(engine::Error::RequestInvalid { .. })),
            "refused"
        );
        assert!(fake.opened.is_empty(), "nothing opened");
    }
    assert!(
        !events(&s).iter().any(|e| matches!(e, Event::Stream { .. })),
        "nothing logged as a use"
    );
}

#[test]
fn a_host_key_that_is_not_pinned_is_refused() {
    let other = HostKind::Ed25519([12; 32]);
    let s = setup(
        &[password_field()],
        vec![ssh_operation(
            "ssh",
            open(vec![other.line()], password_login(), json!({})),
            None,
        )],
    );
    let mut fake = Fake::new(server());
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(
        matches!(result, Err(engine::Error::ServerUntrusted { .. })),
        "untrusted"
    );
    assert!(!fake.peer.signed_in);
    assert!(fake.peer.methods.is_empty(), "no credential sent");
    assert_eq!(last_closed(&s), (false, "untrusted".into()));
}

#[test]
fn a_host_key_of_a_type_not_pinned_is_never_offered() {
    // The server has a P-256 key; only an Ed25519 key is pinned.
    let s = basic(json!({}));
    let mut peer = server();
    peer.host = HostKind::P256([13; 32]);
    peer.host_algs = vec!["ecdsa-sha2-nistp256"];
    let mut fake = Fake::new(peer);
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
}

#[test]
fn a_pinned_p256_host_key_and_ecdh_key_exchange_work() {
    let key = HostKind::P256([13; 32]);
    let s = setup(
        &[password_field()],
        vec![ssh_operation(
            "ssh",
            open(vec![key.line()], password_login(), json!({})),
            None,
        )],
    );
    let mut peer = server();
    peer.host = key;
    peer.kex = vec!["ecdh-sha2-nistp256"];
    peer.ciphers = vec!["aes128-gcm@openssh.com"];
    let mut fake = Fake::new(peer);
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.agreed_kex, "ecdh-sha2-nistp256");
    assert_eq!(fake.peer.agreed_cipher, "aes128-gcm@openssh.com");
}

#[test]
fn a_host_signature_that_does_not_verify_is_refused() {
    let s = basic(json!({}));
    let mut peer = server();
    peer.misbehave = Misbehave::WrongSignature;
    let mut fake = Fake::new(peer);
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
    assert!(fake.peer.methods.is_empty());
}

#[test]
fn weak_algorithms_are_never_agreed() {
    let s = basic(json!({}));
    type Tweak = fn(&mut SshServer);
    let downgrades: [Tweak; 4] = [
        |p| p.kex = vec!["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
        |p| p.ciphers = vec!["aes256-cbc", "aes128-ctr", "3des-cbc"],
        |p| p.host_algs = vec!["ssh-rsa", "ssh-dss"],
        // ChaCha20-Poly1305 without strict key exchange (Terrapin).
        |p| {
            p.ciphers = vec!["chacha20-poly1305@openssh.com"];
            p.strict = false;
        },
    ];
    for tweak in downgrades {
        let mut peer = server();
        tweak(&mut peer);
        let mut fake = Fake::new(peer);
        let result = run_session(&s, &mut fake, vec![command("id", &[])]);
        assert!(
            matches!(result, Err(engine::Error::ServerUntrusted { .. })),
            "downgrade refused"
        );
        assert!(fake.peer.methods.is_empty(), "no credential sent");
    }
}

#[test]
fn chacha20_poly1305_runs_with_strict_key_exchange() {
    let s = basic(json!({}));
    let mut peer = server();
    peer.ciphers = vec!["chacha20-poly1305@openssh.com"];
    let mut fake = Fake::new(peer);
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.agreed_cipher, "chacha20-poly1305@openssh.com");
}

#[test]
fn a_packet_before_key_exchange_under_strict_kex_is_refused() {
    let s = basic(json!({}));
    let mut peer = server();
    peer.misbehave = Misbehave::IgnoreBeforeKexinit;
    let mut fake = Fake::new(peer);
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(matches!(result, Err(engine::Error::ServerUntrusted { .. })));
}

#[test]
fn a_key_re_exchange_is_refused() {
    let s = basic(json!({}));
    let mut peer = server();
    peer.misbehave = Misbehave::Rekey;
    let mut fake = Fake::new(peer);
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(result.is_err() || session_output(result).error.is_some());
}

#[test]
fn a_secret_echoed_in_output_never_goes_back() {
    let s = basic(json!({}));
    let mut fake = Fake::new(server());
    let out = session_output(run_session(
        &s,
        &mut fake,
        vec![command("id", &[]), command("cat", &["secret.txt"])],
    ));
    assert_eq!(out.results.len(), 1, "only the clean result");
    assert!(matches!(out.error, Some(engine::Error::Reflection)));
    assert!(out.results.iter().all(|r| !holds(&r.data, PASSWORD)));
    assert_eq!(last_closed(&s), (false, "reflection".into()));
}

#[test]
fn a_fixed_command_runs_and_its_output_is_captured() {
    let s = setup(
        &[password_field()],
        vec![ssh_operation(
            "ssh",
            open(vec![host().line()], password_login(), json!({})),
            Some("motd"),
        )],
    );
    let mut fake = Fake::new(server());
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.execs, [b"motd".to_vec(), b"id".to_vec()]);
}

#[test]
fn public_key_sign_in_signs_inside_the_node() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    use ring::signature::KeyPair as _;
    let mut blob = fake_ssh::string(b"ssh-ed25519");
    blob.extend(fake_ssh::string(pair.public_key().as_ref()));
    let s = setup(
        &[(FieldSpec::secret("key"), pkcs8.as_ref())],
        vec![ssh_operation(
            "ssh",
            open(
                vec![host().line()],
                json!({"user": "deploy", "key": "{{key}}"}),
                json!({}),
            ),
            None,
        )],
    );
    let mut peer = server();
    peer.keys = vec![blob];
    let mut fake = Fake::new(peer);
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.methods, ["publickey"]);
    assert!(fake.peer.signed_in);
}

#[test]
fn keyboard_interactive_answers_only_prompts_it_knows() {
    let make = |prompt: &'static str| {
        let s = setup(
            &[password_field()],
            vec![ssh_operation(
                "ssh",
                open(
                    vec![host().line()],
                    json!({"user": "deploy", "answers": [
                        {"prompt": "Password: ", "template": "{{password}}"}
                    ]}),
                    json!({}),
                ),
                None,
            )],
        );
        let mut peer = server();
        peer.prompts = vec![(prompt, PASSWORD.to_vec())];
        (s, Fake::new(peer))
    };
    let (s, mut fake) = make("Password: ");
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
    assert_eq!(fake.peer.methods, ["keyboard-interactive"]);
    // A prompt the policy does not know gets no answer.
    let (s, mut fake) = make("Verification code: ");
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert!(!fake.peer.signed_in);
}

#[test]
fn a_wrong_password_is_an_auth_error() {
    let s = basic(json!({}));
    let mut peer = server();
    peer.password = b"other".to_vec();
    let mut fake = Fake::new(peer);
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    assert!(matches!(result, Err(engine::Error::AuthRefused { .. })));
    assert_eq!(last_closed(&s), (false, "auth".into()));
}

#[test]
fn the_byte_limit_ends_the_connection() {
    let s = basic(json!({"bytes": 1500}));
    let mut fake = Fake::new(server());
    let result = run_session(&s, &mut fake, vec![command("id", &[])]);
    let budget = match result {
        Err(engine::Error::Budget { .. }) => true,
        Ok(engine::call::Output::Session(out)) => {
            matches!(out.error, Some(engine::Error::Budget { .. }))
        }
        _ => false,
    };
    assert!(budget, "bytes limit");
}

#[test]
fn the_idle_and_duration_limits_end_a_silent_connection() {
    for limits in [json!({"idle_ms": 50}), json!({"duration_ms": 200})] {
        let s = basic(limits);
        let mut peer = server();
        peer.misbehave = Misbehave::Silent;
        let mut fake = Fake::new(peer);
        let started = std::time::Instant::now();
        let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
        assert!(matches!(
            out.error,
            Some(engine::Error::Transport(engine::error::TransportFault {
                kind: engine::error::TransportKind::Timeout,
                ..
            }))
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(!last_closed(&s).0);
    }
}

fn shell_operation() -> Operation {
    operation(json!({"name": "shell", "steps": [
        open(vec![host().line()], password_login(), json!({})),
        {"do": "return", "relay": {"server": true, "frames": [
            {"kind": "binary", "shape": {"raw": {"pattern": "[ -~\\n]{1,256}"}}}
        ]}}
    ]}))
}

fn frame(call: &SignedCall, seq: u64, data: &[u8]) -> FromCaller {
    FromCaller::Frame(CallerFrame {
        seq,
        kind: FrameKind::Binary,
        data: data.to_vec(),
        signature: caller_key().sign_frame(&call.auth, seq, true, data),
    })
}

#[test]
fn a_shell_relays_signed_frames_and_its_output() {
    let s = setup(&[password_field()], vec![shell_operation()]);
    let mut peer = server();
    peer.exec = |input| (input.to_vec(), Vec::new(), 0);
    let mut fake = Fake::new(peer);
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    let mut caller = TestCaller::default();
    caller.sends.push_back(frame(
        &call, 0, b"ls
",
    ));
    caller.sends.push_back(frame(
        &call, 1, b"exit
",
    ));
    let closed = match s.node.relay(&call, &mut fake, &mut caller).result {
        Ok(engine::call::Output::Closed(closed)) => closed,
        Ok(_) => panic!("not closed"),
        Err(e) => panic!("relay failed: {e}"),
    };
    assert_eq!(closed.reason, "server");
    assert_eq!(
        caller.output(),
        b"$ ls
"
    );
    assert_eq!(
        fake.peer.shell_input,
        b"ls
exit
"
    );
    assert_eq!(last_closed(&s), (true, "server".into()));
}

#[test]
fn output_and_exit_status_while_the_window_is_zero_still_reach_the_caller() {
    // The server's window is 0 when the caller's first frame is written: the output, error
    // output and exit status that come while the write waits are kept for the relay, in
    // order, not dropped.
    let s = setup(&[password_field()], vec![shell_operation()]);
    let mut peer = server();
    peer.exec = |input| (input.to_vec(), Vec::new(), 0);
    peer.hold_window = true;
    let mut fake = Fake::new(peer);
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    let mut caller = TestCaller::default();
    caller.sends.push_back(frame(&call, 0, b"ls\n"));
    caller.sends.push_back(frame(&call, 1, b"exit\n"));
    let closed = match s.node.relay(&call, &mut fake, &mut caller).result {
        Ok(engine::call::Output::Closed(closed)) => closed,
        Ok(_) => panic!("not closed"),
        Err(e) => panic!("relay failed: {e}"),
    };
    assert_eq!(closed.reason, "server");
    assert_eq!(
        String::from_utf8_lossy(&caller.output()),
        "$ late\nwarn\nls\n",
        "the output that came while the write waited is relayed"
    );
    assert_eq!(fake.peer.shell_input, b"ls\nexit\n");
    // The exit status 3 came while the write waited: the relay does not end as a success.
    assert_eq!(last_closed(&s), (false, "server".into()));
}

#[test]
fn a_secret_echoed_by_a_shell_ends_the_relay_before_it_goes_back() {
    let s = setup(&[password_field()], vec![shell_operation()]);
    let mut peer = server();
    peer.exec = |input| match input {
        b"show
" => (
            b"pw: hunter2-pass
"
            .to_vec(),
            Vec::new(),
            0,
        ),
        other => (other.to_vec(), Vec::new(), 0),
    };
    let mut fake = Fake::new(peer);
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    let mut caller = TestCaller::default();
    caller.sends.push_back(frame(
        &call, 0, b"ls
",
    ));
    caller.sends.push_back(frame(
        &call, 1, b"show
",
    ));
    caller.sends.push_back(frame(
        &call, 2, b"exit
",
    ));
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    assert!(matches!(result, Err(engine::Error::Reflection)));
    assert!(
        !holds(&caller.output(), PASSWORD),
        "the secret never goes back"
    );
    assert!(!holds(&caller.output(), b"hunter2"), "nor a prefix of it");
    assert_eq!(last_closed(&s), (false, "reflection".into()));
}

#[test]
fn a_shell_refuses_a_frame_outside_its_shape_or_unsigned() {
    let s = setup(&[password_field()], vec![shell_operation()]);
    let mut fake = Fake::new(server());
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    let mut caller = TestCaller::default();
    caller.sends.push_back(frame(&call, 0, b"\x1b[201~bad"));
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    assert!(result.is_err());
    assert!(fake.peer.shell_input.is_empty(), "nothing written");

    let mut fake = Fake::new(server());
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    let mut caller = TestCaller::default();
    caller.sends.push_back(FromCaller::Frame(CallerFrame {
        seq: 0,
        kind: FrameKind::Binary,
        data: b"ls\n".to_vec(),
        signature: [0; 64],
    }));
    let result = s.node.relay(&call, &mut fake, &mut caller).result;
    assert!(result.is_err());
    assert!(fake.peer.shell_input.is_empty(), "nothing written");
}

#[test]
fn a_shell_operation_on_a_plain_call_is_refused() {
    let s = setup(&[password_field()], vec![shell_operation()]);
    let mut fake = Fake::new(server());
    let call = sign(
        &s,
        "shell",
        session("box.example.com", 22, Vec::new(), Vec::new()),
    );
    assert!(matches!(
        s.node.run(&call, &mut fake).result,
        Err(engine::Error::RequestInvalid { .. })
    ));
}

#[test]
fn open_connections_count_against_the_callers_slots() {
    // Four connections held open by a silent server fill the caller's slots; the fifth is
    // refused before anything is opened, and a slot comes back when one ends.
    let s = basic(json!({"duration_ms": 1500}));
    let node = &s.node;
    std::thread::scope(|scope| {
        let held: Vec<_> = (0..engine::node::MAX_STREAMS_PER_CALLER)
            .map(|_| {
                let call = sign(
                    &s,
                    "ssh",
                    session("box.example.com", 22, vec![command("id", &[])], Vec::new()),
                );
                scope.spawn(move || {
                    let mut peer = server();
                    peer.misbehave = Misbehave::Silent;
                    let mut fake = Fake::new(peer);
                    node.run(&call, &mut fake).result.is_ok()
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut fake = Fake::new(server());
        let result = run_session(&s, &mut fake, vec![command("id", &[])]);
        assert!(matches!(
            result,
            Err(engine::Error::StreamsFull { who: "caller" })
        ));
        assert!(fake.opened.is_empty());
        for h in held {
            h.join().unwrap();
        }
    });
    let mut fake = Fake::new(server());
    let out = session_output(run_session(&s, &mut fake, vec![command("id", &[])]));
    assert!(out.error.is_none());
}

#[test]
fn an_approved_session_runs_the_commands_it_was_signed_with() {
    same_after_approval(
        &basic(json!({})),
        "ssh",
        session(
            "box.example.com",
            22,
            vec![command("id", &[]), command("echo", &["hello world"])],
            Vec::new(),
        ),
        || Fake::new(server()),
    );
}
