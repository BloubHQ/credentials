//! Credential vault core.
//!
//! A credential is stored as a [`record::Record`]: named [`fields::Fields`] encrypted under a
//! key derived from the user key, bound to a [`policy::Policy`] that a device of the owner
//! signed. The policy says, as [`template`]s, where the values go and which
//! [`caller`]s may ask; the engine knows no kind of credential.
//!
//! A [`node::Node`] opens a record only while it holds a [`grant`] of the owner (sealed to the
//! node, signed by a known device), checks the signed call of the caller, and writes a
//! [`log`] entry its sink confirmed before every act ([`log::Confirmed`]).
//!
//! The value of a record never leaves this crate except as the bytes of one outbound request
//! handed to an [`egress::Transport`], the one sink of secret bytes.
//!
//! # End to end
//!
//! The owner's device seals a key into a record whose policy allows one derivation, and grants
//! a node; an application signs a call; the node checks it, logs it and runs it. A derivation
//! sends nothing, so the transport is never used here; `transport` has a TLS one
//! and examples that reach real services.
//!
//! ```
//! use std::time::Duration;
//!
//! use engine::call::{Body, Output};
//! use engine::egress::{ClientIdentity, Transport};
//! use engine::fields::Fields;
//! use engine::grant::GrantTerms;
//! use engine::keys::{CallerKey, DeviceKey, NodeKey, UserKey};
//! use engine::log::{MemorySink, verify_chain};
//! use engine::node::{Node, SystemClock};
//! use engine::policy::{Caller, Destination, FieldSpec, Input, Operation, Policy, RawInput};
//! use engine::record::Record;
//!
//! /// A transport that sends nothing: a derivation needs none.
//! struct NoNetwork;
//!
//! impl Transport for NoNetwork {
//!     fn send(
//!         &mut self,
//!         _: &Destination,
//!         _: Option<&ClientIdentity>,
//!         _: &[u8],
//!         _: usize,
//!     ) -> engine::Result<Vec<u8>> {
//!         unreachable!("a derivation sends nothing")
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // On the owner's device: the policy lets the caller "app" get an HMAC of its input, of at
//! // most 256 bytes.
//! let device = DeviceKey::generate();
//! let user_key = UserKey::generate();
//! let app = CallerKey::generate();
//! let policy = Policy::new()
//!     .with_field(FieldSpec::secret("key"))
//!     .with_operation(
//!         Operation::derive("mac", "{{ hex(hmac_sha256(key, $input)) }}")
//!             .input(Input::Raw(RawInput { max_len: Some(256), pattern: None })),
//!     )
//!     .with_caller(Caller::new("app", app.public(), ["mac"]));
//! let mut values = Fields::new();
//! values.insert("key", b"0123456789abcdef0123456789abcdef".to_vec())?;
//! let record = Record::seal(&user_key, "mac", "alice", device.sign_policy(policy)?, &values)?;
//!
//! // The node publishes its identity; the device seals a grant to it.
//! let node = Node::new(NodeKey::generate(), MemorySink::new(), SystemClock);
//! let terms = GrantTerms::new("alice", Duration::from_secs(600)).pin(&record);
//! node.grant(&device.grant(&user_key, &node.identity(), terms)?)?;
//!
//! // The application holds the record (ciphertext) and its caller key, never the key.
//! let call = app.sign_call("app", &node.public_key(), record, "mac", Body::derive(b"hello"))?;
//! let outcome = node.run(&call, &mut NoNetwork);
//! let Output::Derive(mac) = outcome.result? else { unreachable!() };
//! assert_eq!(mac.len(), 64); // hex of HMAC-SHA256
//!
//! // The log: a grant, then the derivation, signed and chained by the node.
//! let entries = node.with_sink(|sink| sink.entries().to_vec());
//! assert_eq!(entries.len(), 2);
//! verify_chain(&entries, &node.public_key())?;
//! # Ok(())
//! # }
//! ```

pub mod approval;
pub mod build;
pub mod call;
pub mod caller;
pub mod egress;
pub mod encoding;
pub mod error;
pub mod extract;
pub mod fields;
pub mod grant;
pub mod grpc;
pub mod item;
pub mod keys;
pub mod limits;
pub mod log;
pub mod node;
pub mod policy;
mod primitives;
pub mod record;
pub mod reflection;
pub mod request;
pub mod response;
pub mod secret;
pub mod session;
pub mod template;
mod totp;
#[cfg(test)]
mod vectors;
#[cfg(test)]
mod vectors_families;
pub mod websocket;

pub use error::{Error, Result};
