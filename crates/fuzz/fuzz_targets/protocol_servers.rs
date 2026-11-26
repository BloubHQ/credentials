//! Plays arbitrary bytes, in arbitrary pieces, as the server of each protocol client: SSH,
//! PostgreSQL, MySQL, SMTP, IMAP, Redis, MQTT and AMQP. A client must never panic, never sign
//! in to a server that did not prove what it must (an SSH host key that is not pinned, a SCRAM
//! signature), never hand back a message on a topic it did not subscribe to, and never read
//! past the connection's byte limit. SFTP paths go through the traversal check.

#![no_main]

use std::time::Duration;

use engine::Result;
use engine::egress::{Arrived, Stream};
use engine::policy::Mechanism;
use engine::proto::io::{Bounds, Io};
use engine::proto::{amqp, imap, mqtt, mysql, postgres, redis, sftp, smtp, ssh};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const MAX: usize = 64 * 1024;
/// The number of cases below.
const CASES: u8 = 12;

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
    let step = usize::from(head / CASES).max(1);
    let mut stream = Replay { bytes, step };
    let io = Io::new(&mut stream, Bounds::new(1000, 5000, 1 << 20));
    let params = [Zeroizing::new(b"p".to_vec())];
    match head % CASES {
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
            let _ = sftp::normalize(bytes);
        }
        7 => {
            let mut io = io;
            let _ = postgres::prelude(&mut io);
            let _ = smtp::prelude(&mut io);
            let _ = imap::prelude(&mut io);
            let _ = mysql::prelude(&mut io, true);
        }
        8 => {
            let _ = mysql::parse_greeting(bytes);
            let greeting = mysql::Greeting {
                capabilities: 0x0108_ae0f,
                nonce: Zeroizing::new(vec![7; 20]),
            };
            if let Ok(mut c) = mysql::Client::connect(io, &greeting, b"u", Some("d"), b"pw")
                && let Ok(rows) = c.query(b"SELECT ?", &params, &[], MAX)
            {
                assert!(rows.raw.len() <= MAX + 16 * 1024 * 1024);
            }
        }
        9 => {
            if let Ok(mut c) = mqtt::Client::connect(io, mqtt::Version::V5, b"c", b"u", b"pw")
                && c.subscribe("a/+", 1).is_ok()
            {
                // Whatever comes, a message handed back is on a subscribed topic.
                while let Ok(Some(m)) = c.poll_message(Duration::ZERO) {
                    assert!(mqtt::matches("a/+", &m.topic));
                }
            }
        }
        10 => {
            if let Ok(mut c) = mqtt::Client::connect(io, mqtt::Version::V311, b"c", b"u", b"pw") {
                let _ = c.publish(b"a/b", b"x", 1);
                let _ = c.collect(Duration::from_millis(1), 4, MAX);
            }
        }
        _ => {
            if let Ok(mut c) = amqp::Client::connect(io, b"/", b"u", b"pw") {
                let _ = c.publish(b"ex", b"key", b"body");
                if let Ok((_, messages)) = c.get(b"q", 4, MAX) {
                    assert!(messages.iter().map(|m| m.body.len()).sum::<usize>() <= MAX);
                }
            }
        }
    }
});
