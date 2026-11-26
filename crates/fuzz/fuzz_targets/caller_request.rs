//! Checks arbitrary requests (JSON of `engine::request::Request`) against fixed caller
//! contracts, two of them with a body contract (JSON and form). A request must be accepted or
//! refused with an error, never a panic; an accepted path never holds a dot segment, an encoded
//! separator or an injected query name; a body the contract wrote again is accepted again and
//! written the same (the node sends what it checked), with the contract's content type.

#![no_main]

use engine::policy::Operation;
use engine::request::Request;
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_800_000_000_000;

const OPERATIONS: [&str; 4] = [
    r#"{"name": "call", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "*.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "caller", "methods": ["GET", "POST"],
            "paths": ["/v1/{id}/**", "/v2/{id}/items/*"], "headers": ["Accept"],
            "query": [{"name": "page", "min": "1", "max": "100"},
                      {"name": "sort", "one_of": ["asc", "desc"]},
                      {"name": "q", "pattern": "[a-z]{1,16}"}]},
         "inject": [{"target": {"kind": "query", "name": "key"}, "template": "{{token}}"},
                    {"target": {"kind": "path_param", "name": "id"}, "template": "{{token}}"}]},
        {"do": "return", "response": {"body": "all"}}]}"#,
    r#"{"name": "call", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "api.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "caller", "methods": ["POST", "DELETE"],
            "paths": ["/files/**"], "encoded_percent": true, "override_params": true,
            "query": [{"name": "x"}]}},
        {"do": "return", "response": {}}]}"#,
    r#"{"name": "call", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "pay.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/charges"],
            "body": {"json": {"members": [
                {"pointer": "/amount", "type": "number", "min": "0", "max": "100000"},
                {"pointer": "/currency", "equals": "EUR"},
                {"pointer": "/items", "type": "array"},
                {"pointer": "/note", "type": "string", "optional": true},
                {"pointer": "/at", "set": "unix"}]}}}},
        {"do": "return", "response": {}}]}"#,
    r#"{"name": "call", "steps": [
        {"do": "open", "connection": "https", "destinations": [{"host": "pay.example.com", "port": 443}]},
        {"do": "send", "request": {"from": "caller", "methods": ["POST"], "paths": ["/v1/charges"],
            "body": {"form": {"fields": [
                {"name": "amount", "required": true, "min": "0", "max": "100000"},
                {"name": "currency", "required": true, "equals": "EUR"},
                {"name": "note"}]}}}},
        {"do": "return", "response": {}}]}"#,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, request)) = data.split_first() else {
        return;
    };
    let Some(operation) = OPERATIONS.get(usize::from(pick) % OPERATIONS.len()) else {
        return;
    };
    let Ok(operation) = serde_json::from_str::<Operation>(operation) else {
        return;
    };
    let Ok(request) = serde_json::from_slice::<Request>(request) else {
        return;
    };
    if let Ok(Some(sent)) = request.checked(&operation, NOW) {
        let Some(body) = operation
            .caller_sends()
            .find_map(|(contract, _)| contract.body.as_ref())
        else {
            panic!("a request was written again without a body contract");
        };
        assert_eq!(
            body.apply(&sent.body, NOW).ok().as_deref(),
            Some(sent.body.as_slice()),
            "a written body does not read back the same"
        );
        assert_eq!(
            sent.headers.first().map(|(_, value)| value.as_str()),
            Some(body.content_type())
        );
    }
    if request.validate(&operation).is_ok() {
        let lower = request.path.to_ascii_lowercase();
        let path = lower.split(['?', '#']).next().unwrap_or_default();
        for bad in ["/../", "/./", "%2e", "%2f", "%5c", "\\"] {
            assert!(
                !path.contains(bad) && !path.ends_with("/.."),
                "accepted path holds {bad}: {}",
                request.path
            );
        }
    }
});
