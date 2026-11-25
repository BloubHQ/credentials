//! The published JSON Schema of the policy IR (`crates/engine/policy.schema.json`) agrees with
//! the parser: every policy of the README, its translations, docs/policy.md, the examples, the
//! legacy fixtures and the reviewed kinds validates against it, and a member the parser
//! refuses, the schema refuses too.
//!
//! The schema is written by hand; this test holds it to the code. The validator below covers
//! the keywords the schema uses (draft 2020-12) and fails on any other, so the schema cannot
//! grow a keyword nobody checks here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::type_complexity,
    missing_docs
)]

use engine::item::{ITEMS_JSON, ItemBinding, KindSchema};
use engine::keys::{CallerKey, DeviceKey};
use engine::policy::{Caller, FieldSpec, JSON_SCHEMA, Operation, Policy, QueryRule, Step, legacy};
use serde_json::{Value, json};

const KEYWORDS: [&str; 22] = [
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "propertyNames",
    "enum",
    "const",
    "items",
    "minItems",
    "maxItems",
    "oneOf",
    "minimum",
    "maximum",
    "pattern",
    "minLength",
    "maxLength",
];

fn root() -> Value {
    serde_json::from_str(JSON_SCHEMA).unwrap()
}

fn resolve<'a>(root: &'a Value, reference: &str) -> &'a Value {
    let pointer = reference.strip_prefix('#').expect("a local reference");
    root.pointer(pointer)
        .unwrap_or_else(|| panic!("no {reference}"))
}

fn type_is(name: &str, value: &Value) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "integer" => value.is_u64() || value.is_i64(),
        "number" => value.is_number(),
        other => panic!("type {other}"),
    }
}

/// Appends to `errors` each way `value` breaks `schema`.
fn check(root: &Value, schema: &Value, value: &Value, at: &str, errors: &mut Vec<String>) {
    let schema = match schema {
        Value::Bool(true) => return,
        Value::Bool(false) => {
            errors.push(format!("{at}: not allowed"));
            return;
        }
        Value::Object(map) => map,
        other => panic!("schema {other}"),
    };
    for key in schema.keys() {
        assert!(
            KEYWORDS.contains(&key.as_str()),
            "keyword {key} is not checked here"
        );
    }
    // In 2020-12 `$ref` applies beside the other keywords.
    if let Some(Value::String(r)) = schema.get("$ref") {
        check(root, resolve(root, r), value, at, errors);
    }
    let mut fail_list = Vec::new();
    let mut fail = |what: String| errors.push(format!("{at}: {what}"));
    if let Some(t) = schema.get("type") {
        let ok = match t {
            Value::String(name) => type_is(name, value),
            Value::Array(names) => names.iter().any(|n| type_is(n.as_str().unwrap(), value)),
            _ => panic!("type"),
        };
        if !ok {
            fail(format!("not of type {t}"));
            return;
        }
    }
    if let Some(Value::Array(values)) = schema.get("enum") {
        if !values.contains(value) {
            fail(format!("{value} not in {values:?}"));
        }
    }
    if let Some(c) = schema.get("const") {
        if c != value {
            fail(format!("{value} is not {c}"));
        }
    }
    if let Value::String(s) = value {
        let len = s.chars().count() as u64;
        if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
            if len < min {
                fail(format!("shorter than {min}"));
            }
        }
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            if len > max {
                fail(format!("longer than {max}"));
            }
        }
        if let Some(Value::String(p)) = schema.get("pattern") {
            if !regex::Regex::new(p).unwrap().is_match(s) {
                fail(format!("{s:?} does not match {p}"));
            }
        }
    }
    if value.is_number() {
        let n = value.as_f64().unwrap();
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
            if n < min {
                fail(format!("below {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
            if n > max {
                fail(format!("above {max}"));
            }
        }
    }
    if let Value::Array(items) = value {
        if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
            if (items.len() as u64) < min {
                fail(format!("fewer than {min} items"));
            }
        }
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
            if items.len() as u64 > max {
                fail(format!("more than {max} items"));
            }
        }
        if let Some(each) = schema.get("items") {
            for (i, item) in items.iter().enumerate() {
                check(root, each, item, &format!("{at}/{i}"), &mut fail_list);
            }
        }
    }
    if let Value::Object(members) = value {
        if let Some(Value::Array(required)) = schema.get("required") {
            for name in required {
                if !members.contains_key(name.as_str().unwrap()) {
                    fail(format!("lacks {name}"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (name, member) in members {
            let path = format!("{at}/{name}");
            if let Some(names) = schema.get("propertyNames") {
                check(
                    root,
                    names,
                    &Value::String(name.clone()),
                    &path,
                    &mut fail_list,
                );
            }
            match properties.and_then(|p| p.get(name)) {
                Some(s) => check(root, s, member, &path, &mut fail_list),
                None => {
                    if let Some(extra) = schema.get("additionalProperties") {
                        check(root, extra, member, &path, &mut fail_list);
                    }
                }
            }
        }
    }
    if let Some(Value::Array(options)) = schema.get("oneOf") {
        let passing = options
            .iter()
            .filter(|o| {
                let mut e = Vec::new();
                check(root, o, value, at, &mut e);
                e.is_empty()
            })
            .count();
        if passing != 1 {
            fail(format!("{passing} of the oneOf options hold"));
        }
    }
    errors.extend(fail_list);
}

fn errors_as(def: &str, value: &Value) -> Vec<String> {
    let root = root();
    let schema = json!({"$ref": format!("#/$defs/{def}")});
    let mut errors = Vec::new();
    check(&root, &schema, value, "", &mut errors);
    errors
}

fn holds(def: &str, value: &Value) -> bool {
    errors_as(def, value).is_empty()
}

fn assert_policy(name: &str, value: &Value) {
    let errors = errors_as("Policy", value);
    assert!(errors.is_empty(), "{name}: {errors:#?}\n{value:#}");
}

/// Every object inside `value`, as a JSON pointer.
fn objects(value: &Value, at: String, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            out.push(at.clone());
            for (k, v) in map {
                objects(
                    v,
                    format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                objects(v, format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// A member of no meaning added to any object: the parser refuses it, and so does the schema.
fn junk_is_refused(name: &str, value: &Value) {
    let mut at = Vec::new();
    objects(value, String::new(), &mut at);
    assert!(!at.is_empty());
    for pointer in at {
        let mut changed = value.clone();
        changed
            .pointer_mut(&pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("junk".into(), json!(1));
        assert!(
            serde_json::from_value::<Policy>(changed.clone()).is_err(),
            "{name}{pointer}: the parser took junk"
        );
        assert!(
            !holds("Policy", &changed),
            "{name}{pointer}: the schema took junk"
        );
    }
}

fn caller_key() -> String {
    CallerKey::from_bytes(&mut [3u8; 32]).public().to_b64()
}

/// The blocks of `text` fenced as `lang`.
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

#[test]
fn the_schema_is_json_of_draft_2020_12() {
    let root = root();
    assert_eq!(
        root["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    // Every reference resolves.
    for r in JSON_SCHEMA.split("\"$ref\": \"").skip(1) {
        let r = &r[..r.find('"').unwrap()];
        resolve(&root, r);
    }
    assert_eq!(JSON_SCHEMA, include_str!("../policy.schema.json"));
}

#[test]
fn the_readme_policies_hold() {
    for (name, text) in [
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
    ] {
        let mut policies = 0;
        for block in blocks(text, "json") {
            let block = block.replace("<caller public key>", &caller_key());
            let Ok(value) = serde_json::from_str::<Value>(&block) else {
                continue;
            };
            if serde_json::from_value::<Policy>(value.clone()).is_ok() {
                policies += 1;
                assert_policy(name, &value);
                junk_is_refused(name, &value);
            }
        }
        assert!(policies >= 1, "{name}");
    }
}

#[test]
fn the_policy_reference_holds() {
    // Each block of docs/policy.md is a fragment; it holds against the definition of the type
    // that parses it, and against none the parser refuses.
    let doc = include_str!("../../../docs/policy.md");
    let parses: [(&str, fn(&Value) -> bool); 8] = [
        ("Policy", |v| {
            serde_json::from_value::<Policy>(v.clone()).is_ok()
        }),
        ("Operation", |v| {
            serde_json::from_value::<Operation>(v.clone()).is_ok()
        }),
        ("Step", |v| {
            serde_json::from_value::<Step>(v.clone()).is_ok()
        }),
        ("FieldSpec", |v| {
            serde_json::from_value::<FieldSpec>(v.clone()).is_ok()
        }),
        ("QueryRule", |v| {
            serde_json::from_value::<QueryRule>(v.clone()).is_ok()
        }),
        ("Caller", |v| {
            serde_json::from_value::<Caller>(v.clone()).is_ok()
        }),
        ("ItemBinding", |v| {
            serde_json::from_value::<ItemBinding>(v.clone()).is_ok()
        }),
        ("KindSchema", |v| {
            serde_json::from_value::<KindSchema>(v.clone()).is_ok()
        }),
    ];
    let mut matched = 0;
    for block in blocks(doc, "json") {
        let lines: Vec<String> = if block.trim_start().starts_with("{\"do\": \"repeat\"") {
            block
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_string)
                .collect()
        } else {
            vec![block]
        };
        for text in lines {
            let text = text
                .replace("[ ... ]", "[]")
                .replace("<caller public key>", &caller_key());
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            for (def, parse) in parses {
                let parsed = parse(&value);
                assert_eq!(
                    holds(def, &value),
                    parsed,
                    "{def}: parser {parsed}, schema {:?}\n{text}",
                    errors_as(def, &value)
                );
                matched += usize::from(parsed);
            }
        }
    }
    assert!(matched >= 10, "{matched}");
}

#[test]
fn the_example_and_legacy_policies_hold_once_upgraded() {
    let fixtures = [
        include_str!("fixtures/legacy/cli-readme.json"),
        include_str!("fixtures/legacy/example-aws-sigv4.json"),
        include_str!("fixtures/legacy/example-github-user.json"),
        include_str!("fixtures/legacy/example-imap-stream.json"),
        include_str!("fixtures/legacy/example-jwt-derive.json"),
        include_str!("fixtures/legacy/example-node-restore.json"),
        include_str!("fixtures/legacy/example-oauth-refresh.json"),
        include_str!("fixtures/legacy/path-param.json"),
        include_str!("fixtures/legacy/policy-md.json"),
        include_str!("fixtures/legacy/readme.json"),
    ];
    for (i, fixture) in fixtures.iter().enumerate() {
        let fixture = fixture.replace("<caller public key>", &caller_key());
        let upgraded = legacy::upgrade_json(&fixture).unwrap();
        let value = serde_json::to_value(&upgraded.policy).unwrap();
        let name = format!("fixture {i}");
        assert_policy(&name, &value);
        junk_is_refused(&name, &value);
        // The old format is not the step language: the schema refuses it as the parser does.
        let old: Value = serde_json::from_str(&fixture).unwrap();
        assert!(serde_json::from_value::<Policy>(old.clone()).is_err());
        assert!(!holds("Policy", &old), "{name}");
    }
}

fn typed() -> Policy {
    let device = DeviceKey::generate();
    let kind: KindSchema = serde_json::from_value(json!({
        "name": "door", "description": "A door code.",
        "fields": [
            {"name": "site", "disclosure": "public", "pinned": true, "checks": [{"check": "origin"}]},
            {"name": "code", "disclosure": "secret", "guessable": true,
             "checks": [{"check": "pattern", "regex": "[0-9]{6}"}, {"check": "length", "min": 6, "max": 6}]},
            {"name": "label", "disclosure": "masked", "optional": true, "mask": "initial"}
        ],
        "shape": {"connections": ["https"], "destinations": {"from": "origin", "field": "site"},
                  "returns": "status"}
    }))
    .unwrap();
    Policy::new()
        .with_item(
            ItemBinding::custom(device.sign_kind(kind).unwrap())
                .pin("site", "https://door.example"),
        )
        .with_field(FieldSpec::public("site"))
        .with_field(FieldSpec::guessable("code"))
        .with_operation(
            Operation::https("open", engine::policy::Destination::https("door.example"))
                .then(
                    engine::policy::Send::fixed(engine::policy::Method::Post, "/open")
                        .inject(engine::policy::Injection::body("{{code}}")),
                )
                .then(engine::policy::Return::status()),
        )
        .with_caller(Caller::new("app", CallerKey::generate().public(), ["open"]))
}

#[test]
fn typed_policies_and_the_reviewed_kinds_hold() {
    let policy = typed();
    policy.validate().unwrap();
    let value = serde_json::to_value(&policy).unwrap();
    assert_policy("typed", &value);
    junk_is_refused("typed", &value);
    let catalog: Value = serde_json::from_str(ITEMS_JSON).unwrap();
    for kind in catalog["kinds"].as_array().unwrap() {
        let errors = errors_as("KindSchema", kind);
        assert!(errors.is_empty(), "{}: {errors:#?}", kind["name"]);
    }
    // A wrong disclosure or an unknown check: refused by both.
    for bad in [
        json!({"check": "luhn", "digits": 16}),
        json!({"check": "credit"}),
        json!({"check": "integer", "min": 1}),
    ] {
        assert!(serde_json::from_value::<engine::item::Check>(bad.clone()).is_err());
        assert!(!holds("Check", &bad), "{bad}");
    }
    let mut binding = value["item"].clone();
    binding["custom"]["kind"]["fields"][0]["disclosure"] = json!("hidden");
    assert!(serde_json::from_value::<ItemBinding>(binding.clone()).is_err());
    assert!(!holds("ItemBinding", &binding));
}
