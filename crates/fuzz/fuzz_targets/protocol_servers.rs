//! Plays arbitrary bytes, in arbitrary pieces, as the server of each protocol client: SSH,
//! PostgreSQL, SMTP, IMAP and Redis. A client must never panic, never sign in to a server
//! that did not prove what it must (an SSH host key that is not pinned, a SCRAM signature),
//! and never read past the connection's byte limit.

#![no_main]

use std::time::Duration;

use engine::Result;
use engine::egress::{Arrived, Stream};
use engine::policy::Mechanism;
use engine::proto::io::{Bounds, Io};
use engine::proto::{imap, postgres, redis, smtp, ssh};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const MAX: usize = 64 * 1024;

/// A server that sends `bytes` in pieces of `step`, then closes.
struct Replay<'a> {
    bytes: &'a [u8],
    step: usize,
}

impl Stream for Replay<'_> {
    fn write(&mut self, _: &[u8]) -> Result<()> {
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> Result<Vec<u8>> {
        Err(engine::Error::transport(
            engine::error::TransportKind::Unsupported,
            true,
        ))
    }

    fn read_some(&mut self, max: usize, _: Duration) -> Result<Arrived> {
        if self.bytes.is_empty() {
            return Ok(Arrived::End);
        }
        let n = self.step.min(max).min(self.bytes.len()).max(1);
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(Arrived::Bytes(head.to_vec()))
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&head, bytes)) = data.split_first() else {
        return;
    };
    let step = usize::from(head >> 3).max(1);
    let mut stream = Replay { bytes, step };
    let io = Io::new(&mut stream, Bounds::new(1000, 5000, 1 << 20));
    let params = [Zeroizing::new(b"p".to_vec())];
    match head & 7 {
        0 => {
            // A pinned key no input can hold the private half of.
            let pinned = ssh::HostKey::parse(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpE5S3nEfaq9h6S6l5bSkF1H0R1mAEbvYMVg4Ccmi6G",
            )
            .into_iter()
            .collect::<Vec<_>>();
            assert!(ssh::Client::connect(io, &pinned).is_err());
        }
        1 => {
            // Signing in needs the server to prove the password; random bytes cannot.
            assert!(postgres::Client::connect(io, b"u", Some("d"), b"pw").is_err());
        }
        2 => {
            if let Ok(mut c) = smtp::Client::connect(io, false, Mechanism::Plain, b"u", b"pw") {
                let _ = c.send("a@example.com", &["b@example.com".into()], b"hi\r\n");
            }
        }
        3 => {
            if let Ok(mut c) = imap::Client::connect(io, false, Mechanism::Login, b"u", b"pw")
                && let Ok(r) = c.command(b"NOOP", &params, MAX)
            {
                assert!(r.bytes.len() <= MAX + 64 * 1024);
            }
        }
        4 => {
            if let Ok(mut c) = redis::Client::connect(io, b"", b"pw") {
                let _ = c.command(b"GET", &params, MAX);
            }
        }
        5 => {
            // A server-final message before the client-final one never verifies.
            let mut scram = postgres::Scram::with_nonce("fuzznonce");
            assert!(scram.verify(bytes).is_err());
            let _ = scram.last(bytes, b"pw");
        }
        6 => {
            let _ = ssh::ClientKey::parse(bytes);
            if let Ok(text) = core::str::from_utf8(bytes) {
                let _ = ssh::HostKey::parse(text);
            }
            let _ = ssh::parse_kexinit(bytes);
        }
        _ => {
            let mut io = io;
            let _ = postgres::prelude(&mut io);
            let _ = smtp::prelude(&mut io);
            let _ = imap::prelude(&mut io);
        }
    }
});
