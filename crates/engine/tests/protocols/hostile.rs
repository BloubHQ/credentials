//! Each client against servers that send noise or truncated answers: no panic, no sign-in.
//! (The fuzz target `protocol_servers` does the same with coverage guidance.)

use engine::policy::Mechanism;
use engine::proto::io::{Bounds, Io};
use engine::proto::{imap, postgres, redis, smtp, ssh};
use zeroize::Zeroizing;

use super::*;

struct Replay<'a> {
    bytes: &'a [u8],
    step: usize,
}

impl Stream for Replay<'_> {
    fn write(&mut self, _: &[u8]) -> engine::Result<()> {
        Ok(())
    }

    fn read_until(&mut self, _: &[&[u8]], _: usize) -> engine::Result<Vec<u8>> {
        Err(engine::Error::transport(TransportKind::Unsupported, true))
    }

    fn read_some(&mut self, max: usize, _: Duration) -> engine::Result<Arrived> {
        if self.bytes.is_empty() {
            return Ok(Arrived::End);
        }
        let n = self.step.min(max).min(self.bytes.len()).max(1);
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(Arrived::Bytes(head.to_vec()))
    }
}

/// Inputs: noise, and prefixes of well-formed openings with noise after them.
fn inputs() -> Vec<Vec<u8>> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seeds: [&[u8]; 6] = [
        b"SSH-2.0-x\r\n\0\0\0\x2c\x04\x14",
        b"R\0\0\0\x17\0\0\0\x0aSCRAM-SHA-256\0\0",
        b"220 hi\r\n250-x\r\n250 AUTH PLAIN\r\n235 ok\r\n",
        b"* OK hi\r\n* CAPABILITY IMAP4rev1\r\na1 OK\r\na2 OK\r\n* 1 FETCH {9999999}\r\n",
        b"+OK\r\n*3\r\n$5\r\n",
        b"S",
    ];
    let mut out = Vec::new();
    for i in 0..3000u64 {
        let seed = seeds[(i % 6) as usize];
        let cut = (next() as usize) % (seed.len() + 1);
        let mut bytes = seed[..cut].to_vec();
        for _ in 0..(next() % 96) {
            bytes.push(next() as u8);
        }
        out.push(bytes);
    }
    out
}

#[test]
fn clients_survive_noise_and_never_sign_in_to_it() {
    let pinned: Vec<ssh::HostKey> =
        ssh::HostKey::parse(&fake_ssh::HostKind::Ed25519([1; 32]).line())
            .into_iter()
            .collect();
    let params = [Zeroizing::new(b"p".to_vec())];
    for (i, bytes) in inputs().iter().enumerate() {
        let step = 1 + i % 7;
        let run = |kind: usize| {
            let mut stream = Replay { bytes, step };
            let io = Io::new(&mut stream, Bounds::new(1000, 5000, 1 << 20));
            match kind {
                0 => assert!(ssh::Client::connect(io, &pinned).is_err()),
                1 => assert!(postgres::Client::connect(io, b"u", None, b"pw").is_err()),
                2 => {
                    if let Ok(mut c) =
                        smtp::Client::connect(io, false, Mechanism::Plain, b"u", b"pw")
                    {
                        let _ = c.send("a@example.com", &["b@example.com".into()], b"x\r\n");
                    }
                }
                3 => {
                    if let Ok(mut c) =
                        imap::Client::connect(io, false, Mechanism::Login, b"u", b"pw")
                    {
                        let _ = c.command(b"NOOP", &params, 4096);
                    }
                }
                _ => {
                    if let Ok(mut c) = redis::Client::connect(io, b"", b"pw") {
                        let _ = c.command(b"GET", &params, 4096);
                    }
                }
            }
        };
        for kind in 0..5 {
            run(kind);
        }
        let _ = ssh::ClientKey::parse(bytes);
        let _ = ssh::parse_kexinit(bytes);
        let _ = postgres::Scram::with_nonce("n").last(bytes, b"pw");
    }
}
