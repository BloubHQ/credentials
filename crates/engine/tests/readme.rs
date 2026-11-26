//! The README shows code that works: its policy signs, and its quick start is the example. So
//! do the translations, the CLI README and the policy reference.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use engine::keys::{CallerKey, DeviceKey};
use engine::policy::{Caller, FieldSpec, Operation, Policy, QueryRule, Step};

const READMES: [(&str, &str); 4] = [
    ("README.md", include_str!("../../../README.md")),
    (
        "README.ko.md",
        include_str!("../../../docs/i18n/README.ko.md"),
    ),
    (
        "README.ja.md",
        include_str!("../../../docs/i18n/README.ja.md"),
    ),
    (
        "README.zh-CN.md",
        include_str!("../../../docs/i18n/README.zh-CN.md"),
    ),
];

/// The blocks of `text` fenced as `lang`; a checkout on Windows may turn line ends into CRLF.
fn blocks(text: &str, lang: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n");
    let open = format!("```{lang}\n");
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find(&open) {
        let body = &rest[start + open.len()..];
        let end = body.find("```").expect("its end");
        out.push(body[..end].to_string());
        rest = &body[end..];
    }
    out
}

fn sign(name: &str, json: &str) {
    let key = CallerKey::generate().public().to_b64();
    let json = json.replace("<caller public key>", &key);
    let policy: Policy =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("{name}: {e}\n{json}"));
    DeviceKey::generate()
        .sign_policy(policy)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
}

#[test]
fn the_readme_policy_signs() {
    for (name, text) in READMES {
        sign(name, &blocks(text, "json")[0]);
    }
    // The translations show the same policy.
    let english = &blocks(READMES[0].1, "json")[0];
    for (name, text) in &READMES[1..] {
        assert_eq!(&blocks(text, "json")[0], english, "{name}");
    }
}

#[test]
fn the_cli_readme_policy_signs() {
    let readme = include_str!("../../cli/README.md").replace("\r\n", "\n");
    let start = readme
        .find("cat > policy.json <<EOF\n")
        .expect("the policy")
        + 24;
    let end = start + readme[start..].find("\nEOF\n").expect("its end");
    // The shell expands `$CALLER` and `\$`.
    let json = readme[start..end]
        .replace("$CALLER", "<caller public key>")
        .replace("\\$", "$");
    sign("crates/cli/README.md", &json);
}

#[test]
fn the_policy_reference_parses() {
    // Every JSON block of docs/policy.md is a field, a caller, an operation, a step or a query
    // rule; every operation also validates in a policy that declares its names.
    let doc = include_str!("../../../docs/policy.md");
    let json = blocks(doc, "json");
    assert!(json.len() >= 10, "{}", json.len());
    let mut operations = 0;
    for block in &json {
        // A block may hold several values, one per line, as in the loop syntax.
        let values: Vec<&str> = if block.trim_start().starts_with("{\"do\": \"repeat\"") {
            block.lines().filter(|l| !l.trim().is_empty()).collect()
        } else {
            vec![block.as_str()]
        };
        for value in values {
            let value = value.replace("[ ... ]", "[]");
            if let Ok(operation) = serde_json::from_str::<Operation>(&value) {
                operations += 1;
                let names = [
                    "key",
                    "cert",
                    "access_token",
                    "repo_id",
                    "user",
                    "password",
                    "secret",
                    "ssh_key",
                    "db_password",
                    "smtp_password",
                    "redis_password",
                    "mqtt_password",
                    "amqp_password",
                    "last_code",
                    "refresh_token",
                    "card_number",
                    "web_session",
                    "client_id",
                    "server_key",
                    "recipient",
                    "ec_key",
                    "sp_entity_id",
                    "relay_state",
                    "certificate",
                    "consumer_key",
                    "consumer_secret",
                    "token",
                    "token_secret",
                    "access_key_id",
                    "secret_access_key",
                    "domain",
                ];
                let policy = Policy {
                    item: None,
                    fields: names
                        .iter()
                        .map(|n| match *n {
                            "cert" | "user" | "repo_id" | "client_id" | "server_key"
                            | "recipient" | "sp_entity_id" | "relay_state" | "certificate"
                            | "consumer_key" | "token" | "access_key_id" | "domain" => {
                                FieldSpec::public(n)
                            }
                            _ => FieldSpec::secret(n),
                        })
                        .collect(),
                    callers: vec![Caller::new(
                        "app",
                        CallerKey::generate().public(),
                        [operation.name().to_string()],
                    )],
                    operations: vec![operation],
                };
                policy.validate().unwrap_or_else(|e| panic!("{e}\n{value}"));
                continue;
            }
            let parses = serde_json::from_str::<Step>(&value).is_ok()
                || serde_json::from_str::<FieldSpec>(&value).is_ok()
                || serde_json::from_str::<QueryRule>(&value).is_ok()
                || serde_json::from_str::<engine::item::ItemBinding>(&value).is_ok()
                || serde_json::from_str::<engine::item::KindSchema>(&value)
                    .is_ok_and(|k| k.validate().is_ok())
                || serde_json::from_str::<serde_json::Value>(&value)
                    .is_ok_and(|v| v.get("key").is_some() && v.get("operations").is_some());
            assert!(parses, "docs/policy.md block does not parse:\n{value}");
        }
    }
    assert!(operations >= 2, "{operations}");
}

#[test]
fn the_readme_quick_start_is_the_example() {
    // Every code line of the first rust block of the README is a line of the example, so the
    // snippet cannot drift from code that compiles.
    let readme = include_str!("../../../README.md");
    let example = include_str!("../../transport/examples/github_user.rs").replace("\r\n", "\n");
    let example: Vec<&str> = example.lines().map(str::trim).collect();
    let block = &blocks(readme, "rust")[0];
    let code: Vec<&str> = block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    assert!(code.len() >= 5, "{code:?}");
    for line in code {
        assert!(
            example.contains(&line),
            "README line not in crates/transport/examples/github_user.rs: {line}"
        );
    }
}
