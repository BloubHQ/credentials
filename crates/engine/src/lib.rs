//! Credential vault core.
//!
//! A credential is stored as a [`record::Record`]: named [`fields::Fields`] encrypted under a
//! key derived from the user key, bound to a [`policy::Policy`] that the device of the owner
//! signed. The policy says, as [`template`]s, where the values go; the engine knows no kind of
//! credential. A node opens a
//! record only while it holds a grant of the owner, uses the value only in the way the policy
//! names, and writes a log entry that its log sink confirmed before every act
//! ([`log::Confirmed`]).
//!
//! The value of a record never leaves this crate except as the bytes of one outbound request
//! handed to a [`egress::Transport`], the one sink of secret bytes.

pub mod egress;
pub mod encoding;
pub mod error;
pub mod fields;
pub mod keys;
pub mod log;
pub mod node;
pub mod policy;
pub mod record;
pub mod reflection;
pub mod request;
pub mod response;
pub mod secret;
pub mod template;
mod totp;

pub use error::{Error, Result};
