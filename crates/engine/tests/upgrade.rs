//! Every policy of the format before the step language that the repository showed (the
//! README, docs/policy.md, the CLI README and each example) converts, and the conversion keeps
//! the safe side: it narrows what the caller gets and says so.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use engine::Error;
use engine::keys::{CallerKey, DeviceKey};
use engine::policy::legacy::{templates_of_prefix, upgrade_json};
use engine::policy::{Connection, Input, Policy, Step, StepRequest};

const FIXTURES: [(&str, &str); 9] = [
    ("readme", include_str!("fixtures/legacy/readme.json")),
    ("policy-md", include_str!("fixtures/legacy/policy-md.json")),
    (
        "cli-readme",
        include_str!("fixtures/legacy/cli-readme.json"),
    ),
    (
        "example-github-user",
        include_str!("fixtures/legacy/example-github-user.json"),
    ),
    (
        "example-aws-sigv4",
        include_str!("fixtures/legacy/example-aws-sigv4.json"),
    ),
    (
        "example-imap-stream",
        include_str!("fixtures/legacy/example-imap-stream.json"),
    ),
    (
        "example-jwt-derive",
        include_str!("fixtures/legacy/example-jwt-derive.json"),
    ),
    (
        "example-node-restore",
        include_str!("fixtures/legacy/example-node-restore.json"),
    ),
    (
        "example-oauth-refresh",
        include_str!("fixtures/legacy/example-oauth-refresh.json"),
    ),
];

fn with_key(json: &str) -> String {
    json.replace(
        "<caller public key>",
        &CallerKey::generate().public().to_b64(),
    )
}

/// What every converted operation must look like, whatever it was.
fn assert_safe_defaults(name: &str, policy: &Policy) {
    for operation in &policy.operations {
        let returns = operation.returns().expect("a return");
        match operation.connection() {
            Some(Connection::Https) => {
                assert_eq!(returns.response, None, "{name}: status only");
                for step in &operation.steps {
                    if let Step::Send(send) = step
                        && let Some(StepRequest::Caller(contract)) = &send.request
                    {
                        assert!(contract.query.is_empty(), "{name}: no query");
                        assert!(!contract.encoded_percent, "{name}: strict");
                        assert!(!contract.override_params, "{name}: no overrides");
                    }
                }
            }
            Some(
                Connection::Tls
                | Connection::Websocket
                | Connection::Udp
                | Connection::Dtls
                | Connection::Browser,
            ) => {
                assert_eq!(returns.relay, None, "{name}: no relay")
            }
            Some(c) => panic!("{name}: an upgrade makes no {} connection", c.scheme()),
            None => {
                let reads_input = returns
                    .template
                    .as_deref()
                    .is_some_and(|t| t.contains("$input"));
                assert_eq!(
                    operation.input.is_some(),
                    reads_input,
                    "{name}: an input exactly when $input is read"
                );
                if reads_input {
                    assert_eq!(operation.input, Some(Input::any()), "{name}");
                }
            }
        }
    }
}

#[test]
fn every_policy_of_the_repository_converts_and_signs() {
    let device = DeviceKey::generate();
    for (name, json) in FIXTURES {
        let upgraded = upgrade_json(&with_key(json)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            upgraded.notes[0].contains("must be signed again"),
            "{name}: {:?}",
            upgraded.notes
        );
        assert_safe_defaults(name, &upgraded.policy);
        // The converted policy is plain JSON of the new format.
        let text = serde_json::to_string(&upgraded.policy).unwrap();
        let back: Policy = serde_json::from_str(&text).unwrap();
        assert_eq!(back, upgraded.policy, "{name}");
        device
            .sign_policy(upgraded.policy)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn every_narrowing_is_noted() {
    let readme = upgrade_json(&with_key(FIXTURES[0].1)).unwrap();
    let notes = readme.notes.join("\n");
    assert!(
        notes.contains("operation refresh: returns the status only"),
        "{notes}"
    );
    assert!(
        notes.contains("operation call: the caller may send no query parameter"),
        "{notes}"
    );
    let docs = upgrade_json(&with_key(FIXTURES[1].1)).unwrap();
    let notes = docs.notes.join("\n");
    assert!(notes.contains("operation imap: relays none"), "{notes}");
    assert!(
        notes.contains("operation sign: the input is any bytes"),
        "{notes}"
    );
}

#[test]
fn prefixes_become_templates_of_the_same_paths() {
    assert_eq!(templates_of_prefix("/v1/"), vec!["/v1/**"]);
    assert_eq!(templates_of_prefix("/v1"), vec!["/v1", "/v1/**"]);
    assert_eq!(templates_of_prefix("/"), vec!["/**"]);
    let readme = upgrade_json(&with_key(FIXTURES[0].1)).unwrap();
    let call = &readme.policy.operations[1];
    let Step::Send(send) = &call.steps[1] else {
        panic!("a send")
    };
    let Some(StepRequest::Caller(contract)) = &send.request else {
        panic!("a caller send")
    };
    assert_eq!(contract.paths, vec!["/v1/**"]);
}

#[test]
fn a_path_parameter_needs_the_owner() {
    // The old format let the caller place `{token}` anywhere in the path; the new one takes it
    // only as a whole segment the owner writes, so the conversion says so and the result does
    // not sign until the owner writes it.
    let upgraded =
        upgrade_json(&with_key(include_str!("fixtures/legacy/path-param.json"))).unwrap();
    assert!(
        upgraded
            .notes
            .iter()
            .any(|n| n.contains("whole {name} segment")),
        "{:?}",
        upgraded.notes
    );
    assert!(matches!(
        upgraded.policy.validate(),
        Err(Error::PolicyInvalid { .. })
    ));
}

#[test]
fn a_signed_old_policy_converts_without_its_signature() {
    let signed = format!(
        r#"{{"policy": {}, "signature": "AAAA"}}"#,
        with_key(FIXTURES[2].1)
    );
    let upgraded = upgrade_json(&signed).unwrap();
    assert!(
        upgraded
            .notes
            .iter()
            .any(|n| n.contains("signature was dropped"))
    );
    // A policy of the new format is not an old one.
    let text = serde_json::to_string(&upgraded.policy).unwrap();
    assert!(upgrade_json(&text).is_err());
}
