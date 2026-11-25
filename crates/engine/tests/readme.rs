//! The policy in the README is a policy the engine accepts.
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
    let readme = include_str!("../../../README.md");
    let start = readme.find("```json\n").expect("a json block") + "```json\n".len();
    let end = start + readme[start..].find("```").expect("its end");
    let key = CallerKey::generate().public().to_b64();
    let json = readme[start..end].replace("<caller public key>", &key);
    let policy: Policy = serde_json::from_str(&json).unwrap();
    DeviceKey::generate().sign_policy(policy).unwrap();
}
