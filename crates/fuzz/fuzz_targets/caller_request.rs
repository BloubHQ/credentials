//! Checks arbitrary requests (JSON of `engine::request::Request`) against fixed caller
//! contracts. A request must be accepted or refused with an error, never a panic; an accepted
//! path never holds a dot segment, an encoded separator or an injected query name.

#![no_main]

use engine::policy::Operation;
use engine::request::Request;
use libfuzzer_sys::fuzz_target;

const OPERATIONS: [&str; 2] = [
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
