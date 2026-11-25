//! The `run` step (layer 3): site code from the destination's own origin, or a reviewed
//! library, computes on a secret in the sandbox, and its output reaches only that origin.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::collections::VecDeque;

use engine::Error;
use engine::caller::Payload;
use engine::egress::{ClientIdentity, Transport};
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::MemorySink;
use engine::node::{Clock, Node, Outcome, Response};
use engine::policy::summary::FlagCode;
use engine::policy::{
    Caller, CallerRequest, Compute, Destination, FieldSpec, Injection, Method, ModuleSource,
    Operation, Policy, Return, RunModule, Send, Step, Target, summarize,
};
use engine::record::Record;
use sha2::{Digest, Sha256};

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
/// The test secret. Assertion messages never print it.
const SECRET: &[u8] = b"test-password-5c1e";
const MODULE_PATH: &str = "/static/enc.wasm";

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(NOW) };
}

struct TestClock;

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        TIME.with(Cell::get)
    }
}

fn login() -> Destination {
    Destination::https("login.example.com")
}

fn other() -> Destination {
    Destination::https("api.example.net")
}

fn module_url() -> String {
    format!("https://login.example.com{MODULE_PATH}")
}

/// Records the destination and bytes of each request; answers from `replies` in order.
#[derive(Default)]
struct FakeTransport {
    sent: Vec<(Destination, Vec<u8>)>,
    replies: VecDeque<Vec<u8>>,
}

impl Transport for FakeTransport {
    fn send(
        &mut self,
        destination: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push((destination.clone(), wire.to_vec()));
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()))
    }
}

fn http_200(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

const IMPORTS: &str = r#"
  (import "credentials" "input_len" (func $input_len (param i32) (result i32)))
  (import "credentials" "input_read" (func $input_read (param i32 i32)))
  (import "credentials" "output" (func $output (param i32 i32)))
  (memory (export "memory") 1)
"#;

fn wasm(body: &str) -> Vec<u8> {
    wat::parse_str(format!("(module {IMPORTS} {body})")).unwrap()
}

/// "Site code": XORs input 0 with 0x5a, byte by byte.
fn xor_module() -> Vec<u8> {
    wasm(
        r#"(func (export "run")
             (local $i i32) (local $n i32)
             (local.set $n (call $input_len (i32.const 0)))
             (call $input_read (i32.const 0) (i32.const 0))
             (block $done (loop $next
               (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
               (i32.store8 (local.get $i)
                 (i32.xor (i32.load8_u (local.get $i)) (i32.const 0x5a)))
               (local.set $i (i32.add (local.get $i) (i32.const 1)))
               (br $next)))
             (call $output (i32.const 0) (local.get $n)))"#,
    )
}

/// Writes input 0 back, unchanged.
fn echo_module() -> Vec<u8> {
    wasm(
        r#"(func (export "run")
             (call $input_read (i32.const 0) (i32.const 0))
             (call $output (i32.const 0) (call $input_len (i32.const 0))))"#,
    )
}

fn xored() -> Vec<u8> {
    SECRET.iter().map(|b| b ^ 0x5a).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn run_step(module: ModuleSource) -> Step {
    Step::Run(RunModule {
        module,
        entry: "run".into(),
        inputs: vec!["{{password}}".into()],
        into: "enc".into(),
        destination: None,
    })
}

fn url_module(sha256: Option<&[u8]>) -> ModuleSource {
    ModuleSource {
        url: Some(module_url()),
        sha256: sha256.map(|m| hex(&Sha256::digest(m))),
        library: None,
    }
}

fn body(template: &str) -> Injection {
    Injection {
        target: Target::Body,
        template: template.into(),
    }
}

/// Fetches the module from the login origin, runs it on the password, and posts the output
/// to the login origin. The connection also reaches a second destination.
fn login_policy(module: ModuleSource, send: Send) -> Policy {
    let mut send = send;
    if send.inject.is_empty() {
        send.inject.push(body("pw={{ hex(enc) }}"));
    }
    let operation = Operation::https("login", login())
        .destination(other())
        .then(run_step(module))
        .then(send)
        .then(Return::status());
    policy_of(vec![operation])
}

fn policy_of(operations: Vec<Operation>) -> Policy {
    Policy {
        item: None,
        fields: vec![FieldSpec::guessable("password")],
        callers: vec![Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: operations.iter().map(|o| o.name().to_string()).collect(),
            limit: None,
        }],
        operations,
    }
}

fn post_login() -> Send {
    Send::fixed_to(Method::Post, "/login", login())
}

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

struct Setup<'c> {
    node: Node<MemorySink, &'c TestClock>,
    record: Record,
}

fn setup(clock: &TestClock, policy: Policy) -> Setup<'_> {
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(policy).unwrap();
    let mut fields = Fields::new();
    fields.insert("password", SECRET.to_vec()).unwrap();
    let record = Record::seal(
        &UserKey::from_bytes(&mut user_key.clone()),
        "rec-1",
        OWNER,
        signed,
        &fields,
    )
    .unwrap();
    let node = Node::new(NodeKey::generate(), MemorySink::new(), clock);
    let terms = GrantTerms {
        owner: OWNER.into(),
        allow_successor: true,
        expires_ms: NOW + DAY,
        issued_ms: NOW,
        pins: vec![RecordPin {
            record_id: "rec-1".into(),
            generation: 1,
        }],
    };
    let sealed = device
        .grant(
            &UserKey::from_bytes(&mut user_key.clone()),
            &node.identity(),
            terms,
        )
        .unwrap();
    node.grant(&sealed).unwrap();
    Setup { node, record }
}

fn call(s: &Setup<'_>, transport: &mut FakeTransport) -> Outcome<Response> {
    let payload = Payload::Http(None);
    let auth = caller_key()
        .authorize(
            "app",
            &s.node.public_key(),
            &s.record,
            "login",
            &payload,
            NOW,
        )
        .unwrap();
    s.node.http(&s.record, "login", &auth, None, transport)
}

fn sign_error(policy: Policy) -> String {
    match DeviceKey::generate().sign_policy(policy) {
        Ok(_) => panic!("the policy was signed"),
        Err(Error::PolicyInvalid { at, rule }) => format!("{at}: {rule}"),
        Err(other) => panic!("not a policy error: {other}"),
    }
}

#[test]
fn module_output_goes_only_to_its_pinned_origin() {
    let clock = TestClock;
    let module = xor_module();
    let s = setup(
        &clock,
        login_policy(url_module(Some(&module)), post_login()),
    );
    let mut transport = FakeTransport {
        replies: VecDeque::from([http_200(&module)]),
        ..FakeTransport::default()
    };
    let outcome = call(&s, &mut transport);
    let response = outcome.result.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(transport.sent.len(), 2);
    // Both requests, the fetch and the login, go to the login origin and nowhere else.
    assert!(transport.sent.iter().all(|(d, _)| *d == login()));
    let fetch = String::from_utf8_lossy(&transport.sent[0].1).into_owned();
    assert!(fetch.starts_with(&format!("GET {MODULE_PATH} HTTP/1.1\r\n")));
    let posted = &transport.sent[1].1;
    assert!(
        contains(posted, format!("pw={}", hex(&xored())).as_bytes()),
        "the login request carries the module's output"
    );
    for (_, wire) in &transport.sent {
        assert!(
            !contains(wire, SECRET),
            "no request carries the secret as is"
        );
    }
    // The response the caller gets, and the log, hold neither the secret nor the output.
    let returned = response.to_bytes();
    assert!(!contains(&returned, SECRET) && !contains(&returned, &xored()));
    let log = serde_json::to_vec(&s.node.with_sink(|sink| sink.entries().to_vec())).unwrap();
    assert!(!contains(&log, SECRET), "the log holds no secret");
    assert!(!contains(&log, &xored()), "the log holds no module output");
    assert!(!contains(&log, hex(&xored()).as_bytes()), "nor its hex");
}

#[test]
fn a_reviewed_library_runs_without_a_fetch() {
    let clock = TestClock;
    let library = ModuleSource {
        library: Some("lenprefix8".into()),
        ..ModuleSource::default()
    };
    let mut policy = login_policy(library, post_login());
    // One concrete destination: the library's output goes to it.
    if let Step::Open(open) = &mut policy.operations[0].steps[0] {
        open.destinations.truncate(1);
    }
    let s = setup(&clock, policy);
    let mut transport = FakeTransport::default();
    call(&s, &mut transport).result.unwrap();
    assert_eq!(transport.sent.len(), 1, "no module is fetched");
    let mut framed = vec![u8::try_from(SECRET.len()).unwrap()];
    framed.extend_from_slice(SECRET);
    assert!(contains(
        &transport.sent[0].1,
        format!("pw={}", hex(&framed)).as_bytes()
    ));
    // With two destinations, a library names the one its output goes to.
    let library = ModuleSource {
        library: Some("lenprefix8".into()),
        ..ModuleSource::default()
    };
    let rule = sign_error(login_policy(library, post_login()));
    assert!(
        rule.contains("a library's output needs a concrete destination"),
        "{rule}"
    );
    let unknown = ModuleSource {
        library: Some("nope".into()),
        ..ModuleSource::default()
    };
    assert!(sign_error(login_policy(unknown, post_login())).contains("unknown library module"));
}

#[test]
fn a_pin_mismatch_is_refused_before_the_login() {
    let clock = TestClock;
    let pinned = xor_module();
    let s = setup(
        &clock,
        login_policy(url_module(Some(&pinned)), post_login()),
    );
    // The origin serves other code (the echo) than the one pinned.
    let mut transport = FakeTransport {
        replies: VecDeque::from([http_200(&echo_module())]),
        ..FakeTransport::default()
    };
    let error = call(&s, &mut transport).result.unwrap_err();
    assert_eq!(
        error,
        Error::ModuleRefused {
            rule: "the module does not match its sha256 pin"
        }
    );
    assert_eq!(transport.sent.len(), 1, "only the fetch went out");
    // A module that is not served with 200 is refused too.
    let mut transport = FakeTransport {
        replies: VecDeque::from([b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()]),
        ..FakeTransport::default()
    };
    assert!(matches!(
        call(&s, &mut transport).result,
        Err(Error::ModuleRefused { .. })
    ));
}

#[test]
fn an_unpinned_module_runs_and_is_flagged() {
    let clock = TestClock;
    let policy = login_policy(url_module(None), post_login());
    let summary = summarize(&policy, None);
    assert!(
        summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::RunUnpinned)
    );
    let run = &summary.operations[0].runs[0];
    assert!(run.unpinned && run.sha256.is_none());
    assert_eq!(run.module, module_url());
    assert_eq!(run.origin.as_ref().unwrap().host, "login.example.com");
    assert!(policy.summary().iter().any(|l| l.contains("! the module")));
    // The password is listed as going into the module, at the login origin.
    let uses = &summary.secrets[0].uses;
    assert!(uses.iter().any(|u| matches!(&u.form,
        engine::policy::summary::Form::ModuleInput { module } if *module == module_url())
        && u.destinations.iter().all(|d| d.host == "login.example.com")));
    // A pinned module is not flagged, and the summary shows the pin.
    let module = xor_module();
    let pinned = login_policy(url_module(Some(&module)), post_login());
    let summary = summarize(&pinned, None);
    assert!(
        !summary
            .flags
            .iter()
            .any(|f| f.code == FlagCode::RunUnpinned)
    );
    assert_eq!(
        summary.operations[0].runs[0].sha256.as_deref(),
        Some(hex(&Sha256::digest(&module)).as_str())
    );
    let s = setup(&clock, policy);
    let mut transport = FakeTransport {
        replies: VecDeque::from([http_200(&module)]),
        ..FakeTransport::default()
    };
    call(&s, &mut transport).result.unwrap();
    assert_eq!(transport.sent.len(), 2);
}

#[test]
fn fuel_and_memory_exhaustion_stop_the_module() {
    let clock = TestClock;
    let spin = wasm(r#"(func (export "run") (loop $l (br $l)))"#);
    let grow =
        wasm(r#"(func (export "run") (loop $l (drop (memory.grow (i32.const 64))) (br $l)))"#);
    for (module, expected) in [(spin, sandbox::Error::Fuel), (grow, sandbox::Error::Memory)] {
        let s = setup(
            &clock,
            login_policy(url_module(Some(&module)), post_login()),
        );
        let mut transport = FakeTransport {
            replies: VecDeque::from([http_200(&module)]),
            ..FakeTransport::default()
        };
        assert_eq!(
            call(&s, &mut transport).result.unwrap_err(),
            Error::Sandbox(expected)
        );
        assert_eq!(transport.sent.len(), 1, "the login never went out");
    }
}

#[test]
fn a_module_from_another_origin_is_refused() {
    // On a destination the connection does not have.
    let mut source = url_module(None);
    source.url = Some(format!("https://cdn.example.org{MODULE_PATH}"));
    let rule = sign_error(login_policy(source, post_login()));
    assert!(rule.contains("the destination's own origin"), "{rule}");
    // On the second destination: allowed to fetch, but then the output may go only there,
    // and this login posts it to the first.
    let mut source = url_module(None);
    source.url = Some(format!("https://api.example.net{MODULE_PATH}"));
    let rule = sign_error(login_policy(source, post_login()));
    assert!(
        rule.contains("goes only into a request the policy fixes"),
        "{rule}"
    );
    // Malformed sources.
    for url in [
        "http://login.example.com/enc.wasm",
        "https://*.example.com/enc.wasm",
        "https://login.example.com",
        "https://login.example.com:0/enc.wasm",
        "https://Login.example.com/enc.wasm",
        "https://login.example.com/../enc.wasm",
        "https://user@login.example.com/enc.wasm",
    ] {
        let mut source = url_module(None);
        source.url = Some(url.into());
        let rule = sign_error(login_policy(source, post_login()));
        assert!(rule.contains("module"), "{url}: {rule}");
    }
    let mut short_pin = url_module(None);
    short_pin.sha256 = Some("abcd".into());
    assert!(sign_error(login_policy(short_pin, post_login())).contains("sha256"));
    let both = ModuleSource {
        url: Some(module_url()),
        sha256: None,
        library: Some("lenprefix8".into()),
    };
    assert!(sign_error(login_policy(both, post_login())).contains("module"));
}

/// Every way out of the origin is refused when the policy is signed.
#[test]
fn every_escape_of_the_output_is_refused_at_signing() {
    let refused = "goes only into a request the policy fixes";
    // Into the caller's request (the caller picks the path, so an echoing endpoint).
    let caller = Send::caller(CallerRequest::new([Method::Post]).paths(["/**"]));
    let rule = sign_error(login_policy(url_module(None), caller));
    assert!(rule.contains(refused), "{rule}");
    // Into a fixed request to another destination.
    let rule = sign_error(login_policy(
        url_module(None),
        Send::fixed_to(Method::Post, "/x", other()),
    ));
    assert!(rule.contains(refused), "{rule}");
    // Through a computed value, to another destination, in a header.
    let operation = Operation::https("login", login())
        .destination(other())
        .then(run_step(url_module(None)))
        .then(Step::Compute(Compute {
            into: "laundered".into(),
            template: "{{ b64(sha256(enc)) }}".into(),
        }))
        .then(Send {
            inject: vec![Injection::header("X-Token", "{{laundered}}")],
            ..Send::fixed_to(Method::Get, "/x", other())
        })
        .then(Return::status());
    let rule = sign_error(policy_of(vec![operation]));
    assert!(rule.contains(refused), "{rule}");
    // Back to the caller: a run needs a connection, so no derivation can return it.
    let derive = Operation::local("derive")
        .then(run_step(url_module(None)))
        .then(Return::output("{{enc}}"));
    let rule = sign_error(policy_of(vec![derive]));
    assert!(rule.contains("run needs an HTTPS connection"), "{rule}");
    // On a TLS stream.
    let stream = Operation::tls("login", login())
        .then(run_step(url_module(None)))
        .then(Send::write("{{enc}}"))
        .then(Return::default());
    let rule = sign_error(policy_of(vec![stream]));
    assert!(rule.contains("run needs an HTTPS connection"), "{rule}");
    // Into a field of the record, which another operation could hand out.
    let mut into_field = login_policy(url_module(None), post_login());
    if let Step::Run(run) = &mut into_field.operations[0].steps[1] {
        run.into = "password".into();
    }
    let rule = sign_error(into_field);
    assert!(rule.contains("never a field"), "{rule}");
    // A second module of another origin, fed the first one's output.
    let mut second = RunModule {
        module: url_module(None),
        entry: "run".into(),
        inputs: vec!["{{enc}}".into()],
        into: "again".into(),
        destination: None,
    };
    second.module.url = Some(format!("https://api.example.net{MODULE_PATH}"));
    let operation = Operation::https("login", login())
        .destination(other())
        .then(run_step(url_module(None)))
        .then(Step::Run(second))
        .then(Send {
            inject: vec![body("{{again}}")],
            ..Send::fixed_to(Method::Post, "/x", other())
        })
        .then(Return::status());
    let rule = sign_error(policy_of(vec![operation]));
    assert!(rule.contains("the same origin"), "{rule}");
    // Echoed by the origin into a temporary value, then sent elsewhere.
    let operation = Operation::https("login", login())
        .destination(other())
        .then(run_step(url_module(None)))
        .then(Send {
            inject: vec![body("{{enc}}")],
            ..post_login()
        })
        .then(engine::policy::Receive {
            until: vec![],
            capture: vec![engine::policy::Capture {
                source: engine::policy::Source::All,
                into: engine::policy::Store::Temp {
                    name: "echo".into(),
                    secret: false,
                },
                optional: false,
            }],
        })
        .then(Send {
            inject: vec![body("{{echo}}")],
            ..Send::fixed_to(Method::Post, "/x", other())
        })
        .then(Return::status());
    let rule = sign_error(policy_of(vec![operation]));
    assert!(rule.contains(refused), "{rule}");
    // Read before the step that makes it.
    let early = Operation::https("login", login())
        .then(Send {
            inject: vec![body("{{enc}}")],
            ..post_login()
        })
        .then(run_step(url_module(None)))
        .then(Return::status());
    let rule = sign_error(policy_of(vec![early]));
    assert!(rule.contains("unknown or later name"), "{rule}");
    // The caller's input is no input of a module on a connection.
    let mut caller_input = login_policy(url_module(None), post_login());
    if let Step::Run(run) = &mut caller_input.operations[0].steps[1] {
        run.inputs.push("{{$body}}".into());
    }
    let rule = sign_error(caller_input);
    assert!(rule.contains("variable not available"), "{rule}");
}

#[test]
fn errors_and_echoes_never_carry_the_output() {
    let clock = TestClock;
    // The echo module copies the secret; a header cannot hold the line break the output ends
    // with, so the request fails, and the error says why without the value.
    let module = echo_module();
    let mut policy = login_policy(
        url_module(Some(&module)),
        Send {
            inject: vec![Injection::header("X-Pw", "{{enc}}")],
            ..post_login()
        },
    );
    if let Step::Run(run) = &mut policy.operations[0].steps[1] {
        run.inputs = vec!["{{password}}\r\nX-Evil: 1".into()];
    }
    let s = setup(&clock, policy);
    let mut transport = FakeTransport {
        replies: VecDeque::from([http_200(&module)]),
        ..FakeTransport::default()
    };
    let error = call(&s, &mut transport).result.unwrap_err();
    let text = format!("{error} {error:?}");
    assert!(
        !contains(text.as_bytes(), SECRET),
        "the error holds no secret"
    );
    assert_eq!(transport.sent.len(), 1, "the login never went out");

    // A site that echoes the output back: the response is refused, not handed over.
    let module = xor_module();
    let operation = Operation::https("login", login())
        .then(run_step(url_module(Some(&module))))
        .then(Send {
            inject: vec![body("{{enc}}")],
            ..post_login()
        })
        .then(Return::status().body());
    let s = setup(&clock, policy_of(vec![operation]));
    let mut echoed = b"you sent ".to_vec();
    echoed.extend_from_slice(&xored());
    let mut transport = FakeTransport {
        replies: VecDeque::from([http_200(&module), http_200(&echoed)]),
        ..FakeTransport::default()
    };
    let result = call(&s, &mut transport).result;
    match result {
        Ok(response) => assert!(
            !contains(&response.to_bytes(), &xored()),
            "an echoed output is never handed back"
        ),
        Err(error) => assert_eq!(error, Error::Reflection),
    }
}

#[test]
fn the_output_does_not_ride_on_a_status_poll() {
    // A status request the node polls while it waits is not one the output may go into, even
    // to the module's own origin.
    let policy = login_policy(url_module(None), post_login());
    let mut value = serde_json::to_value(&policy).unwrap();
    let poll: serde_json::Value = serde_json::json!({
        "do": "await",
        "challenge": {
            "kind": "external",
            "hint": "Approve the sign-in in the other app",
            "poll": {
                "send": {
                    "request": {"from": "fixed", "method": "GET", "path": "/status",
                                "destination": serde_json::to_value(login()).unwrap()},
                    "inject": [{"target": {"kind": "header", "name": "X-Token"},
                                "template": "{{enc}}"}]
                },
                "success": {"source": {"from": "json", "pointer": "/state"},
                            "one_of": ["approved"]},
                "every_ms": 3000
            }
        }
    });
    let steps = value["operations"][0]["steps"].as_array_mut().unwrap();
    steps.insert(2, poll);
    let policy: Policy = serde_json::from_value(value).unwrap();
    let rule = sign_error(policy);
    assert!(
        rule.contains("challenge.poll.send.inject[0]")
            && rule.contains("goes only into a request the policy fixes"),
        "{rule}"
    );
}
