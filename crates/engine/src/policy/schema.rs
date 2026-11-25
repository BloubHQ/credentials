//! The JSON Schema of the policy format, so a draft (an agent's) can be checked before it
//! reaches the owner.

/// The JSON Schema (draft 2020-12) of a [`super::Policy`], typed items and custom kinds
/// included: `crates/engine/policy.schema.json`. It is tested against every policy the
/// repository shows (`tests/schema.rs`). It checks the form only; signing a policy also runs
/// the template analysis, the path rules and the shape of the item's kind.
pub const JSON_SCHEMA: &str = include_str!("../../policy.schema.json");
