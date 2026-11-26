//! What a policy with protocol connections may say, and how its summary shows it.

use engine::policy::summary::{FlagCode, Form};
use engine::policy::{FieldSpec, Policy, summarize};
use serde_json::{Value, json};

use super::*;

const HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpE5S3nEfaq9h6S6l5bSkF1H0R1mAEbvYMVg4Ccmi6G";

fn policy_of(steps: Value) -> Policy {
    Policy {
        item: None,
        fields: vec![FieldSpec::secret("password"), FieldSpec::secret("key")],
        callers: vec![engine::policy::Caller {
            name: "app".into(),
            key: caller_key().public(),
            operations: vec!["op".into()],
            limit: None,
        }],
        operations: vec![operation(json!({"name": "op", "steps": steps}))],
    }
}

fn ssh_open(extra: Value) -> Value {
    let mut open = json!({"do": "open", "connection": "ssh",
        "destinations": [{"host": "box.example.com", "port": 22}],
        "host_keys": [HOST_KEY],
        "login": {"user": "deploy", "password": "{{password}}"}});
    for (k, v) in extra.as_object().unwrap() {
        open[k] = v.clone();
    }
    open
}

fn commands() -> Value {
    json!({"do": "return", "relay": {"commands": [{"name": "id", "text": "id"}]}})
}

fn valid(steps: Value) -> bool {
    policy_of(steps).validate().is_ok()
}

#[test]
fn a_well_formed_ssh_operation_is_valid() {
    assert!(valid(json!([ssh_open(json!({})), commands()])));
}

#[test]
fn ssh_needs_pinned_host_keys_and_a_login_that_fits_its_mechanism() {
    let cases = [
        json!({"host_keys": []}),
        json!({"host_keys": ["ssh-ed25519 not-base64!"]}),
        json!({"host_keys": ["ssh-dss AAAAB3NzaC1kc3MAAACBAP"]}),
        json!({"login": null}),
        json!({"login": {"user": "deploy", "password": "{{password}}", "mechanism": "scram-sha-256"}}),
        json!({"login": {"user": "deploy", "password": "{{password}}", "key": "{{key}}"}}),
        json!({"login": {"user": "", "password": "{{password}}"}}),
        json!({"tls": "starttls"}),
        json!({"identity": {"cert": "{{key}}", "key": "{{key}}"}}),
    ];
    for extra in cases {
        let mut open = ssh_open(json!({}));
        for (k, v) in extra.as_object().unwrap() {
            if v.is_null() {
                open.as_object_mut().unwrap().remove(k);
            } else {
                open[k] = v.clone();
            }
        }
        assert!(!valid(json!([open, commands()])), "refused: {extra}");
    }
}

#[test]
fn protocol_steps_take_only_their_own_members() {
    // A run step, an HTTP request on SSH, a command on HTTPS, SMTP commands, mail elsewhere,
    // columns outside PostgreSQL, a Redis command that is not literal words.
    let https_open = json!({"do": "open", "connection": "https",
        "destinations": [{"host": "api.example.com", "port": 443}]});
    let smtp_open = json!({"do": "open", "connection": "smtp",
        "destinations": [{"host": "mail.example.com", "port": 465}],
        "login": {"user": "me", "password": "{{password}}"}});
    let redis_open = json!({"do": "open", "connection": "redis",
        "destinations": [{"host": "cache.example.com", "port": 6380}],
        "login": {"user": "", "password": "{{password}}"}});
    let mail = json!({"senders": ["me@example\\.com"], "recipients": [".+@example\\.com"]});
    let cases = [
        json!([ssh_open(json!({})), {"do": "send", "request": {"from": "fixed", "method": "GET", "path": "/"}}, commands()]),
        json!([https_open, {"do": "send", "command": {"text": "id"}}, {"do": "return"}]),
        json!([smtp_open, {"do": "send", "command": {"text": "NOOP"}}, {"do": "return", "relay": {"mail": mail}}]),
        json!([smtp_open, {"do": "return", "relay": {"commands": [{"name": "x", "text": "NOOP"}], "mail": mail}}]),
        json!([ssh_open(json!({})), {"do": "return", "relay": {"mail": mail}}]),
        json!([ssh_open(json!({})), {"do": "return", "relay": {"commands": [{"name": "x", "text": "id", "columns": ["a"]}]}}]),
        json!([redis_open, {"do": "return", "relay": {"commands": [{"name": "x", "text": "GET {{password}}"}]}}]),
        json!([redis_open, {"do": "return", "relay": {"commands": [{"name": "x", "text": "EVAL \"return 1\""}]}}]),
        json!([ssh_open(json!({})), {"do": "return", "relay": {"commands": [{"name": "x", "text": "id", "params": [{"pattern": "("}]}]}}]),
        json!([ssh_open(json!({})), {"do": "return", "relay": {"commands": [{"name": "x", "text": "id", "params": [{"template": "{{password}}", "pattern": "a"}]}]}}]),
    ];
    for steps in cases {
        assert!(!valid(steps.clone()), "refused: {steps}");
    }
    let smtp_ok = json!([smtp_open, {"do": "return", "relay": {"mail": mail}}]);
    assert!(valid(smtp_ok));
}

#[test]
fn the_summary_flags_what_a_protocol_operation_hands_out() {
    let policy = policy_of(json!([
        ssh_open(json!({})),
        {"do": "return", "relay": {"commands": [
            {"name": "echo", "text": "echo", "params": [{}]}
        ]}}
    ]));
    policy.validate().unwrap();
    let summary = summarize(&policy, None);
    let codes: Vec<FlagCode> = summary.flags.iter().map(|f| f.code).collect();
    assert!(codes.contains(&FlagCode::PasswordToServer));
    assert!(codes.contains(&FlagCode::ParamUnpinned));
    let uses = &summary.secrets[0].uses;
    assert!(uses.iter().any(|u| u.form
        == Form::Login {
            mechanism: "password".into()
        }));
    assert_eq!(uses[0].destinations[0].scheme, "ssh");

    // A key sign-in hands the server no password.
    let keyed = policy_of(json!([
        ssh_open(json!({"login": {"user": "deploy", "key": "{{key}}"}})),
        commands()
    ]));
    let codes: Vec<FlagCode> = summarize(&keyed, None)
        .flags
        .iter()
        .map(|f| f.code)
        .collect();
    assert!(!codes.contains(&FlagCode::PasswordToServer));
}

#[test]
fn a_new_host_key_widens_the_policy() {
    let before = policy_of(json!([ssh_open(json!({})), commands()]));
    let after = policy_of(json!([
        ssh_open(
            json!({"host_keys": [HOST_KEY, "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="]})
        ),
        commands()
    ]));
    after.validate().unwrap();
    let summary = summarize(&after, Some(&before));
    assert!(summary.flags.iter().any(|f| f.code == FlagCode::Wider
        && f.detail.contains("ecdsa-sha2-nistp256 host key")));
}

#[test]
fn every_flag_and_form_round_trips_through_json() {
    let policy = policy_of(json!([ssh_open(json!({})), commands()]));
    let summary = summarize(&policy, None);
    let json = serde_json::to_string(&summary).unwrap();
    let back: engine::policy::Summary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

#[test]
fn the_examples_of_the_reference_are_valid_policies() {
    let doc = include_str!("../../../../docs/policy.md");
    let start = doc.find("### Protocol connections").unwrap();
    let end = start + doc[start..].find("### `receive` and captures").unwrap();
    let mut count = 0;
    for block in doc[start..end].split("```json").skip(1) {
        let text = block.split("```").next().unwrap();
        let op: Operation = serde_json::from_str(text).unwrap();
        let fields = [
            "ssh_key",
            "db_password",
            "smtp_password",
            "access_token",
            "last_code",
            "redis_password",
            "mqtt_password",
            "amqp_password",
        ];
        let policy = Policy {
            item: None,
            fields: fields.iter().map(|f| FieldSpec::secret(f)).collect(),
            callers: vec![engine::policy::Caller {
                name: "app".into(),
                key: caller_key().public(),
                operations: vec![op.name().to_string()],
                limit: None,
            }],
            operations: vec![op],
        };
        policy.validate().unwrap();
        count += 1;
    }
    assert_eq!(count, 13);
}
