//! Protocol clients of layer 1 for the connection kinds that are not HTTP: SSH (with SFTP and
//! port forwarding), databases, mail (SMTP, IMAP, POP3), file transfer (SFTP, FTP over TLS)
//! and message queues.
//!
//! Each is a standard protocol family, never a site's: the node authenticates with the item's
//! secret, runs the commands or queries its policy fixes or shapes, and hands back results
//! after the reflection search. The clients are synchronous, like the rest of the node, and
//! read through [`io::Io`], which enforces the connection's bounds.

pub mod amqp;
pub mod amqp1;
pub mod ftp;
pub mod imap;
pub mod io;
pub mod mqtt;
pub mod mysql;
pub mod pop3;
pub mod postgres;
pub mod redis;
pub mod sftp;
pub mod smtp;
pub mod ssh;
pub mod wire;

/// Most elements reserved ahead for a count a server announced. A count is a claim, not
/// elements: a vector sized by it grows as the elements arrive, which the bytes pay for, so
/// nested headers cannot reserve memory nothing sent (#52).
pub(crate) const MAX_PREALLOC: usize = 1024;

/// An empty vector for `announced` elements a server said will follow; see [`MAX_PREALLOC`].
pub(crate) fn announced<T>(announced: usize) -> Vec<T> {
    Vec::with_capacity(announced.min(MAX_PREALLOC))
}
