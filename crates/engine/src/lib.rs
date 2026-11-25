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

pub mod caller;
pub mod egress;
pub mod encoding;
pub mod error;
pub mod fields;
pub mod grant;
pub mod keys;
pub mod log;
pub mod node;
pub mod policy;
mod primitives;
pub mod record;
pub mod reflection;
pub mod request;
pub mod response;
pub mod secret;
pub mod template;
mod totp;

pub use error::{Error, Result};
