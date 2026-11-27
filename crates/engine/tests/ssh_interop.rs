//! The SSH client against a real OpenSSH server, an implementation independent of the fake
//! one the protocol tests use. The test is ignored by default: the `ssh-interop` CI job
//! starts `sshd` with a small `RekeyLimit` and one key exchange, cipher and host key
//! algorithm each, and runs it with `--ignored`, pointing `CREDENTIALS_SSH_INTEROP_DIR` at a
//! directory that holds:
//!
//! - `port`, `user`, `host_key.pub` (the server's public host key), `id` (an unencrypted
//!   client key the server authorizes);
//! - `expect_kex`, `expect_cipher`, `expect_host_key`: what the client must agree on;
//! - `sftp_dir`: an absolute directory the SFTP transfer writes into.
//!
//! A missing variable or file fails the test: a job whose setup drifted does not pass.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use engine::egress::{Arrived, Stream};
use engine::error::TransportKind;
use engine::proto::io::{Bounds, Io};
use engine::proto::sftp::Sftp;
use engine::proto::ssh::{Auth, Client, ClientKey, HostKey};

/// A plain TCP connection.
struct Tcp {
    sock: TcpStream,
    ahead: Vec<u8>,
}

fn io_fault(e: &std::io::Error) -> engine::Error {
    let kind = match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => TransportKind::Timeout,
        _ => TransportKind::Io,
    };
    engine::Error::transport(kind, true)
}

impl Stream for Tcp {
    fn write(&mut self, bytes: &[u8]) -> engine::Result<()> {
        self.sock.write_all(bytes).map_err(|e| io_fault(&e))
    }

    fn read_until(&mut self, delimiters: &[&[u8]], max: usize) -> engine::Result<Vec<u8>> {
        loop {
            for d in delimiters {
                if let Some(at) = self.ahead.windows(d.len()).position(|w| w == *d) {
                    return Ok(self.ahead.drain(..at + d.len()).collect());
                }
            }
            if self.ahead.len() > max {
                return Err(engine::Error::transport(TransportKind::TooLarge, true));
            }
            self.sock
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| io_fault(&e))?;
            let mut chunk = [0u8; 4096];
            match self.sock.read(&mut chunk) {
                Ok(0) => return Err(engine::Error::transport(TransportKind::Closed, true)),
                Ok(n) => self.ahead.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(io_fault(&e)),
            }
        }
    }

    fn read_some(&mut self, max: usize, wait: Duration) -> engine::Result<Arrived> {
        if !self.ahead.is_empty() {
            let n = max.min(self.ahead.len());
            return Ok(Arrived::Bytes(self.ahead.drain(..n).collect()));
        }
        self.sock
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|e| io_fault(&e))?;
        let mut chunk = vec![0u8; max.clamp(1, 65_536)];
        match self.sock.read(&mut chunk) {
            Ok(0) => Ok(Arrived::End),
            Ok(n) => {
                chunk.truncate(n);
                Ok(Arrived::Bytes(chunk))
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(Arrived::Nothing)
            }
            Err(e) => Err(io_fault(&e)),
        }
    }
}

fn read(dir: &std::path::Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .trim()
        .to_string()
}

/// 1 MiB that no two offsets repeat within a packet.
fn blob() -> Vec<u8> {
    (0u32..1 << 18)
        .flat_map(|i| i.wrapping_mul(2_654_435_761).to_be_bytes())
        .collect()
}

#[test]
#[ignore = "needs the sshd of the ssh-interop CI job"]
fn openssh_agrees_rekeys_and_loses_nothing() {
    let dir = PathBuf::from(
        std::env::var_os("CREDENTIALS_SSH_INTEROP_DIR")
            .expect("CREDENTIALS_SSH_INTEROP_DIR names the directory the job prepared"),
    );
    let port: u16 = read(&dir, "port").parse().unwrap();
    let host_key = HostKey::parse(&read(&dir, "host_key.pub")).expect("host key");
    let client_key = ClientKey::parse(read(&dir, "id").as_bytes()).expect("client key");
    let user = read(&dir, "user");

    let mut tcp = Tcp {
        sock: TcpStream::connect(("127.0.0.1", port)).unwrap(),
        ahead: Vec::new(),
    };
    let io = Io::new(&mut tcp, Bounds::new(30_000, 300_000, 256 << 20));
    let mut client = Client::connect(io, &[host_key]).expect("key exchange");
    eprintln!("agreed: {:?}", client.agreed);
    assert_eq!(client.agreed.kex, read(&dir, "expect_kex"));
    assert_eq!(client.agreed.cipher_out, read(&dir, "expect_cipher"));
    assert_eq!(client.agreed.cipher_in, read(&dir, "expect_cipher"));
    assert_eq!(client.agreed.host_key, read(&dir, "expect_host_key"));
    assert!(
        client.agreed.strict,
        "OpenSSH agrees on strict key exchange"
    );
    eprintln!("client key: {}", client_key.algorithm());
    client
        .authenticate(user.as_bytes(), &Auth::Key(&client_key))
        .expect("sign-in");

    // About 1.2 MB of output, many times the server's RekeyLimit: dozens of re-exchanges,
    // some of them between two parts of one pipe read.
    let out = client.exec(b"seq 1 200000", 4 << 20).expect("exec");
    let want: String = (1..=200_000).map(|i| format!("{i}\n")).collect();
    assert_eq!(out.exit, Some(0));
    assert_eq!(
        out.stdout.len(),
        want.len(),
        "every byte of the output came"
    );
    assert!(
        out.stdout.as_slice() == want.as_bytes(),
        "the output is intact"
    );
    let after_exec = client.rekeys;
    eprintln!("rekeys during the command: {after_exec}");
    assert!(after_exec >= 2, "the server rekeyed: {after_exec}");

    // 1 MiB up and back over SFTP: re-exchanges in the middle of a transfer, with writes
    // that wait for window.
    let data = blob();
    let path = format!("{}/blob", read(&dir, "sftp_dir"));
    {
        let mut sftp = Sftp::start(&mut client).expect("sftp");
        sftp.write_file(path.as_bytes(), &data).expect("put");
        let back = sftp.read_file(path.as_bytes(), 2 << 20).expect("get");
        assert_eq!(back.len(), data.len(), "every byte came back");
        assert!(back.as_slice() == data.as_slice(), "the file is intact");
        sftp.finish().expect("sftp end");
    }
    let during_sftp = client.rekeys - after_exec;
    eprintln!("rekeys during the transfer: {during_sftp}");
    assert!(during_sftp >= 2, "the server rekeyed: {during_sftp}");

    // The server's own view of the file, on a channel after all of it.
    let digest = ring::digest::digest(&ring::digest::SHA256, &data);
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let out = client
        .exec(format!("sha256sum {path}").as_bytes(), 1024)
        .expect("sha256sum");
    assert!(
        out.stdout.starts_with(hex.as_bytes()),
        "the server holds the same bytes"
    );
    eprintln!("rekeys in all: {}", client.rekeys);
}
