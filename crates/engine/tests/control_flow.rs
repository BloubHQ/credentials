//! Loops (`repeat`) and branches (`if`) of the policy IR: what the analysis refuses before a
//! policy is signed (a test on a value a secret influences, caps, nesting, names defined on
//! one path only, confinement broken in a body), what the summary and its diff show, and
//! retries that run end to end against a fake server.
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
use engine::caller::{Authorization, Payload};
use engine::egress::{ClientIdentity, Stream, Transport};
use engine::fields::Fields;
use engine::grant::{GrantTerms, RecordPin};
use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
use engine::log::{Event, MemorySink};
use engine::node::{Clock, Node, Outcome, Response};
use engine::policy::summary::FlagCode;
use engine::policy::{Destination, MAX_REQUESTS, Policy, diff, summarize};
use engine::record::Record;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

const OWNER: &str = "user-1";
const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const KEY: &[u8] = b"k_live_5d4c3b2a19f8e7d6";

// ---- policies as JSON -------------------------------------------------------------------

fn caller_key() -> CallerKey {
    CallerKey::from_bytes(&mut [5u8; 32])
}

/// A policy of `fields` and one operation `op` of `steps`, the caller `app` listed.
fn policy_of(fields: Value, input: Option<Value>, steps: Value) -> Policy {
    let mut operation = json!({"name": "op", "steps": steps});
    if let Some(input) = input {
        operation["input"] = input;
    }
    let value = json!({
        "fields": fields,
        "callers": [{"name": "app", "key": caller_key().public().to_b64(), "operations": ["op"]}],
        "operations": [operation],
    });
    serde_json::from_value(value).unwrap()
}

fn https(steps: &[Value]) -> Policy {
    let mut all = vec![open(&["api.example.com"])];
    all.extend(steps.iter().cloned());
    policy_of(
        json!([{"name": "key", "secret": true}, {"name": "region", "secret": false}]),
        None,
        Value::Array(all),
    )
}

fn open(hosts: &[&str]) -> Value {
    let destinations: Vec<Value> = hosts
        .iter()
        .map(|h| json!({"host": h, "port": 443}))
        .collect();
    json!({"do": "open", "connection": "https", "destinations": destinations})
}

/// A fixed request, with header injections `(name, template)`.
fn send(method: &str, path: &str, headers: &[(&str, &str)]) -> Value {
    let inject: Vec<Value> = headers
        .iter()
        .map(|(n, t)| json!({"target": {"kind": "header", "name": n}, "template": t}))
        .collect();
    json!({"do": "send", "request": {"from": "fixed", "method": method, "path": path}, "inject": inject})
}

fn send_to(host: &str, path: &str, headers: &[(&str, &str)]) -> Value {
    let mut s = send("POST", path, headers);
    s["request"]["destination"] = json!({"host": host, "port": 443});
    s
}

fn capture(source: Value, name: &str, secret: bool) -> Value {
    json!({"source": source, "into": {"kind": "temp", "name": name, "secret": secret}})
}

fn optional(mut capture: Value) -> Value {
    capture["optional"] = json!(true);
    capture
}

fn receive(captures: &[Value]) -> Value {
    json!({"do": "receive", "capture": captures})
}

fn status_into(name: &str) -> Value {
    capture(json!({"from": "status"}), name, false)
}

fn header_into(header: &str, name: &str) -> Value {
    capture(json!({"from": "header", "name": header}), name, false)
}

fn compute(into: &str, template: &str) -> Value {
    json!({"do": "compute", "into": into, "template": template})
}

fn repeat(times: u32, until: Option<Value>, steps: &[Value]) -> Value {
    let mut r = json!({"do": "repeat", "times": times, "steps": steps});
    if let Some(until) = until {
        r["until"] = until;
    }
    r
}

fn branch(when: Value, then: &[Value], otherwise: &[Value]) -> Value {
    json!({"do": "if", "when": when, "then": then, "else": otherwise})
}

fn one_of(name: &str, values: &[&str]) -> Value {
    json!({"name": name, "one_of": values})
}

fn none_of(name: &str, values: &[&str]) -> Value {
    json!({"name": name, "none_of": values})
}

fn ret() -> Value {
    json!({"do": "return", "response": {"body": "all"}})
}

/// The rule a policy breaks, or `None`.
fn rule_of(policy: &Policy) -> Option<(String, &'static str)> {
    match policy.validate() {
        Ok(()) => None,
        Err(Error::PolicyInvalid { at, rule }) => Some((at, rule)),
        Err(other) => panic!("{other:?}"),
    }
}

fn refused_with(policy: &Policy, part: &str) {
    let (at, rule) = rule_of(policy).unwrap_or_else(|| panic!("accepted, expected: {part}"));
    assert!(rule.contains(part), "{at}: {rule} (expected: {part})");
}

fn accepted(policy: &Policy) {
    if let Some((at, rule)) = rule_of(policy) {
        panic!("refused at {at}: {rule}");
    }
}

const INFLUENCED: &str = "a secret influences";

// ---- the analysis -----------------------------------------------------------------------

#[test]
fn a_test_on_a_secret_field_is_refused() {
    let p = https(&[
        send("GET", "/x", &[]),
        branch(one_of("key", &["a"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // A public field is fine.
    let p = https(&[
        send("GET", "/x", &[]),
        branch(one_of("region", &["eu"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    accepted(&p);
}

#[test]
fn a_test_on_a_value_computed_from_a_secret_is_refused() {
    // A MAC of the key is not tainted (it may go back from a derivation), yet a branch on it
    // would tell its bits.
    for template in [
        "{{ hex(hmac_sha256(key, \"x\")) }}",
        "{{ len(key) }}",
        "{{ key }}",
    ] {
        let p = https(&[
            compute("h", template),
            send("GET", "/x", &[]),
            branch(one_of("h", &["00"]), &[send("GET", "/y", &[])], &[]),
            ret(),
        ]);
        refused_with(&p, INFLUENCED);
    }
    // Two steps away, through another computed value.
    let p = https(&[
        compute("h", "{{ hex(sha256(key)) }}"),
        compute("first", "{{ slice(h, \"0\", \"2\") }}"),
        send("GET", "/x", &[]),
        branch(one_of("first", &["ab"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
}

#[test]
fn a_test_on_a_capture_from_a_request_that_carried_a_secret_is_refused() {
    let auth = [("Authorization", "Bearer {{key}}")];
    let state = capture(json!({"from": "json", "pointer": "/state"}), "state", false);
    // The answer to an authenticated request is the account's: only its status may be tested.
    let p = https(&[
        send("GET", "/x", &auth),
        receive(std::slice::from_ref(&state)),
        branch(one_of("state", &["ok"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // Through a value computed from the capture.
    let p = https(&[
        send("GET", "/x", &auth),
        receive(std::slice::from_ref(&state)),
        compute("upper", "{{ state }}!"),
        branch(one_of("upper", &["ok!"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // Through a value derived from the secret, not the secret itself.
    let mac = [("Authorization", "Mac {{ hex(hmac_sha256(key, \"x\")) }}")];
    let p = https(&[
        send("GET", "/x", &mac),
        receive(std::slice::from_ref(&state)),
        branch(one_of("state", &["ok"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // A capture marked secret, whatever the request.
    let p = https(&[
        send("GET", "/x", &[]),
        receive(&[capture(json!({"from": "header", "name": "X-T"}), "t", true)]),
        branch(one_of("t", &["1"]), &[send("GET", "/y", &[])], &[]),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // The status of the same request may be tested; a capture of an unauthenticated answer
    // too.
    let p = https(&[
        send("GET", "/x", &auth),
        receive(&[status_into("status")]),
        branch(one_of("status", &["401"]), &[send("GET", "/y", &auth)], &[]),
        ret(),
    ]);
    accepted(&p);
    let p = https(&[
        send("GET", "/x", &[]),
        receive(&[state]),
        branch(one_of("state", &["ok"]), &[send("GET", "/y", &auth)], &[]),
        ret(),
    ]);
    accepted(&p);
}

#[test]
fn a_capture_over_a_client_certificate_is_influenced() {
    let p = policy_of(
        json!([{"name": "cert", "secret": false}, {"name": "key", "secret": true}]),
        None,
        json!([
            {"do": "open", "connection": "https",
             "destinations": [{"host": "api.example.com", "port": 443}],
             "identity": {"cert": "{{cert}}", "key": "{{key}}"}},
            send("GET", "/x", &[]),
            receive(&[capture(json!({"from": "json", "pointer": "/state"}), "state", false), status_into("status")]),
            branch(one_of("state", &["ok"]), &[send("GET", "/y", &[])], &[]),
            ret(),
        ]),
    );
    refused_with(&p, INFLUENCED);
}

#[test]
fn a_loop_whose_exit_a_secret_influences_is_refused() {
    let auth = [("Authorization", "Bearer {{key}}")];
    // The loop's test reads a capture of an authenticated answer.
    let p = https(&[
        repeat(
            3,
            Some(one_of("state", &["done"])),
            &[
                send("GET", "/x", &auth),
                receive(&[capture(
                    json!({"from": "json", "pointer": "/state"}),
                    "state",
                    false,
                )]),
            ],
        ),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // A name first captured from an unauthenticated answer, then captured again in the loop
    // from an authenticated one: influenced, though its first definition is not.
    let p = https(&[
        send("GET", "/nonce", &[]),
        receive(&[header_into("Replay-Nonce", "nonce")]),
        repeat(
            3,
            Some(one_of("nonce", &["stop"])),
            &[
                send(
                    "POST",
                    "/x",
                    &[("Authorization", "Mac {{ hex(hmac_sha256(key, nonce)) }}")],
                ),
                receive(&[optional(header_into("Replay-Nonce", "nonce"))]),
            ],
        ),
        ret(),
    ]);
    refused_with(&p, INFLUENCED);
    // On the status, the same loop is fine.
    let p = https(&[
        send("GET", "/nonce", &[]),
        receive(&[header_into("Replay-Nonce", "nonce")]),
        repeat(
            3,
            Some(none_of("status", &["401"])),
            &[
                send(
                    "POST",
                    "/x",
                    &[("Authorization", "Mac {{ hex(hmac_sha256(key, nonce)) }}")],
                ),
                receive(&[
                    status_into("status"),
                    optional(header_into("Replay-Nonce", "nonce")),
                ]),
            ],
        ),
        ret(),
    ]);
    accepted(&p);
}

#[test]
fn a_derivation_branches_on_its_input_never_on_a_secret() {
    let fields = json!([{"name": "key", "secret": true}]);
    let input = Some(json!({"raw": {"pattern": "a|b"}}));
    let ok = policy_of(
        fields.clone(),
        input.clone(),
        json!([
            compute("mode", "{{ $input }}"),
            branch(
                one_of("mode", &["a"]),
                &[compute("out", "{{ hex(hmac_sha256(key, \"a\")) }}")],
                &[compute("out", "{{ hex(hmac_sha256(key, \"b\")) }}")]
            ),
            {"do": "return", "template": "{{ out }}"},
        ]),
    );
    accepted(&ok);
    // A name both bodies define has the properties of both: one tainted body taints it.
    let joined = policy_of(
        fields.clone(),
        input.clone(),
        json!([
            compute("mode", "{{ $input }}"),
            branch(one_of("mode", &["a"]), &[compute("out", "{{ key }}")], &[compute("out", "x")]),
            {"do": "return", "template": "{{ out }}"},
        ]),
    );
    refused_with(&joined, "hand a secret back");
    // A loop in a derivation has no request to repeat.
    let looped = policy_of(
        fields,
        input,
        json!([
            compute("mode", "{{ $input }}"),
            repeat(2, None, &[compute("x", "y")]),
            {"do": "return", "template": "{{ mode }}"},
        ]),
    );
    refused_with(&looped, "no connection");
}

#[test]
fn caps_are_fixed_in_the_signed_policy() {
    let body = [send("GET", "/x", &[]), receive(&[status_into("status")])];
    let until = Some(one_of("status", &["200"]));
    refused_with(
        &https(&[repeat(0, until.clone(), &body), ret()]),
        "1 to 8 times",
    );
    refused_with(
        &https(&[repeat(9, until.clone(), &body), ret()]),
        "1 to 8 times",
    );
    accepted(&https(&[repeat(8, until.clone(), &body), ret()]));
    // Each request counts as often as the loop may run: 2 x 5 > 8.
    let two = [
        send("GET", "/x", &[]),
        send("GET", "/y", &[]),
        receive(&[status_into("status")]),
    ];
    refused_with(
        &https(&[repeat(5, until.clone(), &two), ret()]),
        "at most 8 requests",
    );
    accepted(&https(&[repeat(4, until.clone(), &two), ret()]));
    // Requests before the loop count too: 3 + 3 x 2 > 8.
    let mut steps = vec![
        send("GET", "/a", &[]),
        send("GET", "/b", &[]),
        send("GET", "/c", &[]),
    ];
    steps.push(repeat(3, until.clone(), &two));
    steps.push(ret());
    refused_with(&https(&steps), "at most 8 requests");
    // A branch counts as its larger side.
    let big: Vec<Value> = (0..6).map(|i| send("GET", &format!("/{i}"), &[])).collect();
    let mut steps = vec![send("GET", "/s", &[]), receive(&[status_into("status")])];
    steps.push(branch(one_of("status", &["200"]), &big, &[]));
    steps.push(send("GET", "/t", &[]));
    steps.push(send("GET", "/u", &[]));
    steps.push(ret());
    refused_with(&https(&steps), "at most 8 requests");
    // Nesting: two deep is fine, three is not.
    let inner = repeat(2, None, &[send("GET", "/i", &[])]);
    accepted(&https(&[
        send("GET", "/s", &[]),
        receive(&[status_into("status")]),
        branch(
            one_of("status", &["200"]),
            std::slice::from_ref(&inner),
            &[],
        ),
        ret(),
    ]));
    let deeper = branch(one_of("status", &["200"]), &[inner], &[]);
    refused_with(
        &https(&[
            send("GET", "/s", &[]),
            receive(&[status_into("status")]),
            branch(one_of("status", &["200"]), &[deeper], &[]),
            ret(),
        ]),
        "nest at most 2 deep",
    );
    // Every run of a loop sends a request; one only on some paths is not enough.
    refused_with(
        &https(&[
            send("GET", "/x", &[]),
            repeat(2, None, &[compute("c", "x")]),
            ret(),
        ]),
        "at least one request",
    );
    refused_with(
        &https(&[
            send("GET", "/s", &[]),
            receive(&[status_into("status")]),
            repeat(
                2,
                None,
                &[branch(
                    one_of("status", &["1"]),
                    &[send("GET", "/x", &[])],
                    &[],
                )],
            ),
            ret(),
        ]),
        "at least one request",
    );
    // The values of a test are bounded.
    let many: Vec<String> = (0..17).map(|i| i.to_string()).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    refused_with(
        &https(&[repeat(2, Some(one_of("status", &many)), &body), ret()]),
        "1 to 16 values",
    );
    refused_with(
        &https(&[repeat(2, Some(json!({"name": "status"})), &body), ret()]),
        "1 to 16 values",
    );
    // A test reads a name defined before it.
    refused_with(
        &https(&[repeat(2, Some(one_of("nothing", &["1"])), &body), ret()]),
        "defined before it",
    );
    // Every signed operation stays within the requests of an operation.
    let p = https(&[repeat(8, until, &body), ret()]);
    assert!(p.operations[0].most_requests() <= MAX_REQUESTS as u64);
}

#[test]
fn no_signed_nesting_exceeds_the_request_bound() {
    // Every combination of an outer loop or branch, an inner loop, their caps and the
    // requests in the inner body: what validates stays within the bound, and what exceeds it
    // is refused.
    let mut signed = 0;
    let mut refused = 0;
    for outer_loop in [false, true] {
        for outer in 1..=9u32 {
            for inner in 1..=9u32 {
                for sends in 1..=3usize {
                    let body: Vec<Value> = (0..sends)
                        .map(|i| send("GET", &format!("/{i}"), &[]))
                        .collect();
                    let inner_loop = repeat(inner, None, &body);
                    let outer_step = if outer_loop {
                        repeat(
                            outer,
                            Some(one_of("status", &["200"])),
                            &[
                                send("GET", "/s", &[]),
                                receive(&[status_into("status")]),
                                inner_loop,
                            ],
                        )
                    } else {
                        branch(one_of("status", &["200"]), &[inner_loop], &[])
                    };
                    let p = https(&[
                        send("GET", "/s", &[]),
                        receive(&[status_into("status")]),
                        outer_step,
                        ret(),
                    ]);
                    let most = p.operations[0].most_requests();
                    match rule_of(&p) {
                        None => {
                            signed += 1;
                            assert!(most <= MAX_REQUESTS as u64, "{most}");
                        }
                        Some(_) => {
                            refused += 1;
                            let caps = outer <= 8 && inner <= 8;
                            assert!(!caps || most > MAX_REQUESTS as u64, "{most}");
                        }
                    }
                }
            }
        }
    }
    assert!(signed > 0 && refused > 0, "{signed} {refused}");
}

#[test]
fn bodies_hold_only_plain_steps() {
    let status = [send("GET", "/s", &[]), receive(&[status_into("status")])];
    let when = one_of("status", &["200"]);
    let await_step =
        json!({"do": "await", "challenge": {"kind": "sms", "hint": "code", "into": "otp"}});
    let run_step = json!({"do": "run", "module": {"library": "lenprefix8"}, "entry": "run",
                          "inputs": ["{{key}}"], "into": "enc"});
    for (inner, part) in [
        (await_step.clone(), "no open, return, run or await"),
        (run_step, "no open, return, run or await"),
        (open(&["api.example.com"]), "no open, return, run or await"),
    ] {
        let mut steps = status.to_vec();
        steps.push(branch(when.clone(), std::slice::from_ref(&inner), &[]));
        steps.push(ret());
        refused_with(&https(&steps), part);
        let mut steps = status.to_vec();
        steps.push(repeat(2, None, &[send("GET", "/x", &[]), inner]));
        steps.push(ret());
        refused_with(&https(&steps), part);
    }
    // A receive follows its send inside the same body.
    let mut steps = status.to_vec();
    steps.push(branch(when.clone(), &[receive(&[])], &[]));
    steps.push(ret());
    refused_with(&https(&steps), "follows its send");
    // A branch needs steps.
    let mut steps = status.to_vec();
    steps.push(branch(when.clone(), &[], &[]));
    steps.push(ret());
    refused_with(&https(&steps), "has steps");
}

#[test]
fn loops_and_branches_stay_on_https_and_derivations() {
    // A TLS stream.
    let p = policy_of(
        json!([{"name": "key", "secret": true}]),
        None,
        json!([
            {"do": "open", "connection": "tls", "destinations": [{"host": "imap.example.com", "port": 993}]},
            {"do": "send", "template": "a LOGIN x {{key}}\r\n"},
            {"do": "receive", "until": ["\r\n"], "capture": [capture(json!({"from": "all"}), "line", false)]},
            branch(
                one_of("line", &["ok"]),
                &[json!({"do": "send", "template": "b NOOP\r\n"})],
                &[]
            ),
            {"do": "return"},
        ]),
    );
    refused_with(&p, "for HTTPS and operations with no connection");
    // A payment: its request goes out once.
    let mut p = https(&[
        send("GET", "/s", &[]),
        receive(&[status_into("status")]),
        repeat(
            2,
            Some(one_of("status", &["200"])),
            &[send("POST", "/pay", &[]), receive(&[status_into("paid")])],
        ),
        ret(),
    ]);
    p.operations[0].payment = Some(
        serde_json::from_value(
            json!({"currency": "EUR", "exponent": 2, "amount": {"from": "fixed", "value": "100"}}),
        )
        .unwrap(),
    );
    refused_with(&p, "pays");
    // A streamed response.
    let p = https(&[
        send("GET", "/s", &[]),
        receive(&[status_into("status")]),
        branch(one_of("status", &["200"]), &[send("GET", "/x", &[])], &[]),
        send("GET", "/stream", &[]),
        json!({"do": "return", "response": {"body": "stream"}}),
    ]);
    refused_with(&p, "streams");
}

#[test]
fn a_name_defined_on_one_path_only_is_unusable_after() {
    let status = [send("GET", "/s", &[]), receive(&[status_into("status")])];
    let when = one_of("status", &["200"]);
    // Only `then` defines `x`.
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[compute("x", "a")],
        &[compute("y", "b")],
    ));
    steps.push(send("GET", "/x", &[("X-V", "{{x}}")]));
    steps.push(ret());
    refused_with(&https(&steps), "unknown or later name");
    // Both define it.
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[compute("x", "a")],
        &[compute("x", "b")],
    ));
    steps.push(send("GET", "/x", &[("X-V", "{{x}}")]));
    steps.push(ret());
    accepted(&https(&steps));
    // A capture defined inside a branch is not readable after it either.
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[send("GET", "/a", &[]), receive(&[header_into("X-A", "a")])],
        &[send("GET", "/b", &[])],
    ));
    steps.push(send("GET", "/x", &[("X-V", "{{a}}")]));
    steps.push(ret());
    refused_with(&https(&steps), "unknown or later name");
    // Both bodies must agree on what the name is.
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[send("GET", "/a", &[]), receive(&[header_into("X-A", "a")])],
        &[
            send("GET", "/b", &[]),
            receive(&[capture(json!({"from": "header", "name": "X-A"}), "a", true)]),
        ],
    ));
    steps.push(ret());
    refused_with(&https(&steps), "defined the same way");
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[send("GET", "/a", &[]), receive(&[header_into("X-A", "a")])],
        &[compute("a", "b")],
    ));
    steps.push(ret());
    refused_with(&https(&steps), "defined the same way");
    // A name defined in one body may not be defined again later in another way.
    let mut steps = status.to_vec();
    steps.push(branch(
        when.clone(),
        &[compute("x", "a")],
        &[compute("y", "b")],
    ));
    steps.push(send("GET", "/b", &[]));
    steps.push(receive(&[header_into("X-A", "x")]));
    steps.push(ret());
    refused_with(&https(&steps), "defined the same way");
    // Inside a loop, only a name captured before the loop may be captured again, with the
    // same secrecy.
    let mut steps = vec![send("GET", "/n", &[]), receive(&[header_into("N", "n")])];
    steps.push(repeat(
        2,
        None,
        &[
            send("GET", "/x", &[("N", "{{n}}")]),
            receive(&[capture(json!({"from": "header", "name": "N"}), "n", true)]),
        ],
    ));
    steps.push(ret());
    refused_with(&https(&steps), "new token");
    let mut steps = vec![compute("n", "x")];
    steps.push(repeat(
        2,
        None,
        &[
            send("GET", "/x", &[("N", "{{n}}")]),
            receive(&[header_into("N", "n")]),
        ],
    ));
    steps.push(ret());
    refused_with(&https(&steps), "new token");
}

/// A run step's output, confined to the origin of its module, `a.example.com`.
fn confined(steps: &[Value]) -> Policy {
    let mut all = vec![
        open(&["a.example.com", "b.example.com"]),
        json!({"do": "run", "module": {"library": "lenprefix8"}, "entry": "run",
               "inputs": ["{{key}}"], "into": "enc",
               "destination": {"host": "a.example.com", "port": 443}}),
    ];
    all.extend(steps.iter().cloned());
    policy_of(
        json!([{"name": "key", "secret": true}]),
        None,
        Value::Array(all),
    )
}

#[test]
fn a_branch_or_loop_cannot_send_a_confined_value_elsewhere() {
    const CONFINED: &str = "goes only into a request the policy fixes to the origin";
    let status = [
        send_to("a.example.com", "/s", &[]),
        receive(&[status_into("status")]),
    ];
    // Straight-line, as before.
    let mut steps = status.to_vec();
    steps.push(send_to("b.example.com", "/x", &[("X-E", "{{ hex(enc) }}")]));
    steps.push(ret());
    refused_with(&confined(&steps), CONFINED);
    // The same request in a branch is refused the same way, in either body.
    for then in [true, false] {
        let leak = send_to("b.example.com", "/x", &[("X-E", "{{ hex(enc) }}")]);
        let ok = send_to("a.example.com", "/y", &[]);
        let (t, e) = if then { (leak, ok) } else { (ok, leak) };
        let mut steps = status.to_vec();
        steps.push(branch(one_of("status", &["200"]), &[t], &[e]));
        steps.push(ret());
        refused_with(&confined(&steps), CONFINED);
    }
    // To the module's origin it is fine.
    let mut steps = status.to_vec();
    steps.push(branch(
        one_of("status", &["200"]),
        &[send_to("a.example.com", "/x", &[("X-E", "{{ hex(enc) }}")])],
        &[],
    ));
    steps.push(ret());
    accepted(&confined(&steps));
    // Across the runs of a loop: the answer to a request that carried the confined value is
    // captured into `n`, which the next run sends to the other destination.
    let mut steps = vec![
        send_to("a.example.com", "/n", &[]),
        receive(&[header_into("N", "n")]),
    ];
    steps.push(repeat(
        2,
        None,
        &[
            send_to("b.example.com", "/x", &[("N", "{{n}}")]),
            receive(&[status_into("status")]),
            send_to("a.example.com", "/y", &[("X-E", "{{ hex(enc) }}")]),
            receive(&[header_into("N", "n")]),
        ],
    ));
    steps.push(ret());
    refused_with(&confined(&steps), CONFINED);
}

#[test]
fn a_renewal_fills_its_session_on_every_path() {
    let policy = |renew: Vec<Value>| -> Policy {
        let value = json!({
            "fields": [
                {"name": "password", "secret": true},
                {"name": "session", "secret": true, "optional": true,
                 "session": {"lifetime_ms": 3_600_000, "expires": "session_exp",
                             "renew": {"by": "operation", "name": "login"}}},
                {"name": "session_exp", "secret": false, "optional": true},
            ],
            "callers": [{"name": "app", "key": caller_key().public().to_b64(), "operations": ["login"]}],
            "operations": [{"name": "login", "steps": renew}],
        });
        serde_json::from_value(value).unwrap()
    };
    let fill = json!({"do": "receive", "capture": [{"source": {"from": "cookie", "name": "sid"},
                                                     "into": {"kind": "field", "name": "session"}}]});
    let login = send("POST", "/login", &[("Authorization", "Basic {{password}}")]);
    // Filled in only one body of a branch: not a renewal.
    let p = policy(vec![
        open(&["api.example.com"]),
        send("GET", "/s", &[]),
        receive(&[status_into("status")]),
        branch(
            one_of("status", &["200"]),
            &[login.clone(), fill.clone()],
            &[send("GET", "/x", &[])],
        ),
        ret(),
    ]);
    refused_with(&p, "fills the session field");
    // Filled in a loop's body, which runs at least once: a renewal.
    let p = policy(vec![
        open(&["api.example.com"]),
        repeat(
            2,
            Some(none_of("status", &["503"])),
            &[
                login,
                json!({"do": "receive", "capture": [
            {"source": {"from": "cookie", "name": "sid"}, "into": {"kind": "field", "name": "session"}},
            {"source": {"from": "status"}, "into": {"kind": "temp", "name": "status", "secret": false}}]}),
            ],
        ),
        ret(),
    ]);
    accepted(&p);
}

// ---- summary and diff -------------------------------------------------------------------

fn retry_policy(times: u32) -> Policy {
    https(&[
        send("GET", "/nonce", &[]),
        receive(&[header_into("Replay-Nonce", "nonce")]),
        repeat(
            times,
            Some(none_of("status", &["401"])),
            &[
                compute("mac", "{{ hex(hmac_sha256(key, nonce)) }}"),
                send(
                    "POST",
                    "/resource",
                    &[("Authorization", "Mac nonce={{nonce}}, mac={{mac}}")],
                ),
                receive(&[
                    status_into("status"),
                    optional(header_into("Replay-Nonce", "nonce")),
                ]),
            ],
        ),
        ret(),
    ])
}

#[test]
fn the_summary_shows_loops_branches_and_the_most_requests() {
    let p = retry_policy(2);
    accepted(&p);
    let summary = summarize(&p, None);
    let op = &summary.operations[0];
    assert_eq!(op.most_requests, 3);
    assert_eq!(
        op.control,
        vec![r#"step 3: repeat up to 2 times, until status is none of ["401"]"#.to_string()]
    );
    // The request inside the loop is listed, at the step of the loop.
    assert!(
        op.requests
            .iter()
            .any(|r| r.step == 3 && r.paths == ["/resource"])
    );
    // The key's use inside the loop is listed.
    let key = summary.secrets.iter().find(|s| s.field == "key").unwrap();
    assert!(key.uses.iter().any(|u| u.step == 3));
    assert!(summary.flags.iter().any(|f| f.code == FlagCode::Repeat));
    let lines = p.summary();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  repeat up to 2 times")),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l == "  end of repeat"), "{lines:?}");
}

#[test]
fn diff_flags_a_larger_cap_and_new_requests_in_a_body() {
    let wider = |prev: &Policy, cur: &Policy| diff(prev, cur).0;
    // A cap that grows is wider; one that shrinks is not.
    let w = wider(&retry_policy(2), &retry_policy(3));
    assert!(w.iter().any(|l| l.contains("may now run 3 times")), "{w:?}");
    assert!(w.iter().any(|l| l.contains("up to 4 requests")), "{w:?}");
    assert!(wider(&retry_policy(3), &retry_policy(2)).is_empty());
    // The test that ends the loop.
    let mut cur = retry_policy(2);
    let mut value = serde_json::to_value(&cur).unwrap();
    value["operations"][0]["steps"][3]["until"] = none_of("status", &["401", "403"]);
    cur = serde_json::from_value(value).unwrap();
    let w = wider(&retry_policy(2), &cur);
    assert!(
        w.iter().any(|l| l.contains("test that ends the loop")),
        "{w:?}"
    );
    // A branch that gains a request, to a new path.
    let base = |then: Vec<Value>| {
        https(&[
            send("GET", "/s", &[]),
            receive(&[status_into("status")]),
            branch(one_of("status", &["401"]), &then, &[]),
            ret(),
        ])
    };
    let one = base(vec![send("GET", "/a", &[])]);
    let two = base(vec![send("GET", "/a", &[]), send("GET", "/b", &[])]);
    let w = wider(&one, &two);
    assert!(
        w.iter().any(|l| l.contains("then: the steps changed")),
        "{w:?}"
    );
    assert!(w.iter().any(|l| l.contains("up to 3 requests")), "{w:?}");
    assert!(
        wider(&two, &one)
            .iter()
            .all(|l| l.contains("steps changed"))
    );
    // A request in a body that now goes to another path or destination.
    let moved = base(vec![send("GET", "/elsewhere", &[])]);
    let w = wider(&one, &moved);
    assert!(w.iter().any(|l| l.contains("the request changed")), "{w:?}");
    // The branch's test.
    let mut value = serde_json::to_value(&one).unwrap();
    value["operations"][0]["steps"][3]["when"] = one_of("status", &["401", "403"]);
    let retested: Policy = serde_json::from_value(value).unwrap();
    let w = wider(&one, &retested);
    assert!(w.iter().any(|l| l.contains("test of the branch")), "{w:?}");
    assert!(wider(&one, &one).is_empty());
}

// ---- end to end -------------------------------------------------------------------------

thread_local! {
    static TIME: Cell<u64> = const { Cell::new(0) };
}

struct TestClock;

impl Clock for &TestClock {
    fn now_ms(&self) -> u64 {
        TIME.with(Cell::get)
    }
}

/// Answers from `replies` in order (200 with no body after them) and keeps what it is sent.
#[derive(Default)]
struct FakeServer {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Vec<u8>>,
}

impl Transport for FakeServer {
    fn send(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
        wire: &[u8],
        _: usize,
    ) -> engine::Result<Vec<u8>> {
        self.sent.push(wire.to_vec());
        Ok(self
            .replies
            .pop_front()
            .unwrap_or_else(|| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()))
    }

    fn open(
        &mut self,
        _: &Destination,
        _: Option<&ClientIdentity>,
    ) -> engine::Result<Box<dyn Stream + '_>> {
        Err(Error::OperationUnknown {
            name: "stream".into(),
        })
    }
}

type TestNode<'c> = Node<MemorySink, &'c TestClock>;

fn setup(clock: &TestClock, policy: Policy) -> (TestNode<'_>, Record) {
    TIME.with(|t| t.set(NOW));
    let device = DeviceKey::generate();
    let user_key = [7u8; 32];
    let signed = device.sign_policy(policy).unwrap();
    let mut fields = Fields::new();
    fields.insert("key", KEY.to_vec()).unwrap();
    fields.insert("region", b"eu".to_vec()).unwrap();
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
    (node, record)
}

fn authorize(node: &TestNode<'_>, record: &Record, payload: &Payload<'_>) -> Authorization {
    caller_key()
        .authorize("app", &node.public_key(), record, "op", payload, NOW)
        .unwrap()
}

fn call(node: &TestNode<'_>, record: &Record, server: &mut FakeServer) -> Outcome<Response> {
    let auth = authorize(node, record, &Payload::Http(None));
    node.http(record, "op", &auth, None, server)
}

fn requests_logged(node: &TestNode<'_>) -> usize {
    node.with_sink(|sink| {
        sink.entries()
            .iter()
            .filter(|e| matches!(e.entry.event, Event::Use { .. }))
            .count()
    })
}

fn reply(status: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (n, v) in headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.into_bytes()
}

fn mac(nonce: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    m.update(nonce.as_bytes());
    m.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn holds(wire: &[u8], text: &str) -> bool {
    wire.windows(text.len()).any(|w| w == text.as_bytes())
}

fn status_of(response: &Response) -> u16 {
    response.status()
}

#[test]
fn a_loop_retries_once_with_the_fresh_nonce_of_a_401() {
    let clock = TestClock;
    let (node, record) = setup(&clock, retry_policy(2));
    // The cached nonce is stale: the server answers 401 with a fresh one, then accepts.
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("401 Unauthorized", &[("Replay-Nonce", "n2")], ""),
            reply("200 OK", &[], "done"),
        ]),
        ..FakeServer::default()
    };
    let response = call(&node, &record, &mut server).result.unwrap();
    assert_eq!(status_of(&response), 200);
    assert_eq!(response.body(), b"done");
    assert_eq!(server.sent.len(), 3, "requests sent");
    let first = format!("Mac nonce=n1, mac={}", mac("n1"));
    let second = format!("Mac nonce=n2, mac={}", mac("n2"));
    assert!(holds(&server.sent[1], &first), "the first try signs n1");
    assert!(
        holds(&server.sent[2], &second),
        "the retry signs the fresh n2"
    );
    // No request carries the key itself.
    assert!(
        server.sent.iter().all(|w| !holds(w, "k_live_")),
        "a request holds the key"
    );
    // One log entry per request, as for straight-line steps.
    assert_eq!(requests_logged(&node), 3);

    // Accepted at once: the loop ends after one run.
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("200 OK", &[], "done"),
        ]),
        ..FakeServer::default()
    };
    let response = call(&node, &record, &mut server).result.unwrap();
    assert_eq!(status_of(&response), 200);
    assert_eq!(server.sent.len(), 2, "requests sent");

    // Refused every time: the loop stops at its cap and the last answer goes back.
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("401 Unauthorized", &[("Replay-Nonce", "n2")], ""),
            reply("401 Unauthorized", &[("Replay-Nonce", "n3")], ""),
            reply("200 OK", &[], "never asked"),
        ]),
        ..FakeServer::default()
    };
    let response = call(&node, &record, &mut server).result.unwrap();
    assert_eq!(status_of(&response), 401);
    assert_eq!(server.sent.len(), 3, "requests sent");

    // A 401 without a fresh nonce: the optional capture finds nothing, so the next run has no
    // nonce to sign (never the stale one) and the operation fails before sending.
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("401 Unauthorized", &[], ""),
        ]),
        ..FakeServer::default()
    };
    assert!(call(&node, &record, &mut server).result.is_err());
    assert_eq!(server.sent.len(), 2, "requests sent");
}

#[test]
fn a_branch_retries_once_with_the_fresh_nonce_of_a_401() {
    let policy = https(&[
        send("GET", "/nonce", &[]),
        receive(&[header_into("Replay-Nonce", "nonce")]),
        compute("mac", "{{ hex(hmac_sha256(key, nonce)) }}"),
        send(
            "POST",
            "/resource",
            &[("Authorization", "Mac nonce={{nonce}}, mac={{mac}}")],
        ),
        receive(&[
            status_into("status"),
            optional(header_into("Replay-Nonce", "fresh")),
        ]),
        branch(
            one_of("status", &["401"]),
            &[
                compute("mac2", "{{ hex(hmac_sha256(key, fresh)) }}"),
                send(
                    "POST",
                    "/resource",
                    &[("Authorization", "Mac nonce={{fresh}}, mac={{mac2}}")],
                ),
            ],
            &[],
        ),
        ret(),
    ]);
    let clock = TestClock;
    let (node, record) = setup(&clock, policy);
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("401 Unauthorized", &[("Replay-Nonce", "n2")], ""),
            reply("201 Created", &[], "made"),
        ]),
        ..FakeServer::default()
    };
    let response = call(&node, &record, &mut server).result.unwrap();
    assert_eq!(status_of(&response), 201);
    assert_eq!(response.body(), b"made");
    assert_eq!(server.sent.len(), 3, "requests sent");
    let retry = format!("Mac nonce=n2, mac={}", mac("n2"));
    assert!(
        holds(&server.sent[2], &retry),
        "the retry signs the fresh nonce"
    );
    assert_eq!(requests_logged(&node), 3);
    // No 401: the branch is skipped.
    let mut server = FakeServer {
        replies: VecDeque::from([
            reply("200 OK", &[("Replay-Nonce", "n1")], ""),
            reply("200 OK", &[], "fine"),
        ]),
        ..FakeServer::default()
    };
    let response = call(&node, &record, &mut server).result.unwrap();
    assert_eq!(response.body(), b"fine");
    assert_eq!(server.sent.len(), 2, "requests sent");
}

#[test]
fn a_derivation_takes_the_branch_its_input_names() {
    let policy = policy_of(
        json!([{"name": "key", "secret": true}, {"name": "region", "secret": false}]),
        Some(json!({"raw": {"pattern": "a|b"}})),
        json!([
            compute("mode", "{{ $input }}"),
            branch(
                one_of("mode", &["a"]),
                &[compute("out", "{{ hex(hmac_sha256(key, \"a\")) }}")],
                &[compute("out", "{{ hex(hmac_sha256(key, \"b\")) }}")]
            ),
            {"do": "return", "template": "{{ out }}"},
        ]),
    );
    let clock = TestClock;
    let (node, record) = setup(&clock, policy);
    for input in ["a", "b"] {
        let auth = authorize(&node, &record, &Payload::Derive(input.as_bytes()));
        let out = node.derive(&record, "op", &auth, input.as_bytes()).unwrap();
        assert_eq!(out, mac(input).into_bytes(), "the output for input {input}");
    }
    // Input outside the schema is refused before any branch runs.
    let auth = authorize(&node, &record, &Payload::Derive(b"c"));
    assert!(node.derive(&record, "op", &auth, b"c").is_err());
}
