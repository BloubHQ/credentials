//! The README shows code that works: its policy signs, and its quick start is the example.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use engine::keys::{CallerKey, DeviceKey};
use engine::policy::Policy;

#[test]
fn the_readme_policy_signs() {
    // A checkout on Windows may turn line ends into CRLF.
    let readme = include_str!("../../../README.md").replace("\r\n", "\n");
    let start = readme.find("```json\n").expect("a json block") + "```json\n".len();
    let end = start + readme[start..].find("```").expect("its end");
    let key = CallerKey::generate().public().to_b64();
    let json = readme[start..end].replace("<caller public key>", &key);
    let policy: Policy = serde_json::from_str(&json).unwrap();
    DeviceKey::generate().sign_policy(policy).unwrap();
}

#[test]
fn the_readme_quick_start_is_the_example() {
    // Every code line of the first rust block of the README is a line of the example, so the
    // snippet cannot drift from code that compiles.
    let readme = include_str!("../../../README.md").replace("\r\n", "\n");
    let example = include_str!("../../transport/examples/github_user.rs").replace("\r\n", "\n");
    let example: Vec<&str> = example.lines().map(str::trim).collect();
    let start = readme.find("```rust\n").expect("a rust block") + "```rust\n".len();
    let end = start + readme[start..].find("```").expect("its end");
    let code: Vec<&str> = readme[start..end]
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
