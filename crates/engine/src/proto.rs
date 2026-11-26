//! Protocol clients of layer 1 for the connection kinds that are not HTTP: SSH, databases,
//! mail and message queues.
//!
//! Each is a standard protocol family, never a site's: the node authenticates with the item's
//! secret, runs the commands or queries its policy fixes or shapes, and hands back results
//! after the reflection search. The clients are synchronous, like the rest of the node, and
//! read through [`io::Io`], which enforces the connection's bounds.

pub mod imap;
pub mod io;
pub mod postgres;
pub mod redis;
pub mod smtp;
pub mod ssh;
pub mod wire;
