//! The SSH client against a real OpenSSH server, an implementation independent of the fake
//! one the protocol tests use. CI starts `sshd` with a small `RekeyLimit` and points
//! `CREDENTIALS_SSH_INTEROP_DIR` at a directory holding `port`, `host_key.pub` (the server's
//! public host key), `id_ed25519` (an unencrypted client key the server authorizes) and
//! `user`. Without that variable the test does nothing.
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

#[test]
fn openssh_rekeys_while_a_command_prints_and_nothing_is_lost() {
    let Some(dir) = std::env::var_os("CREDENTIALS_SSH_INTEROP_DIR").map(PathBuf::from) else {
        eprintln!("CREDENTIALS_SSH_INTEROP_DIR is not set: skipped");
        return;
    };
    let port: u16 = read(&dir, "port").parse().unwrap();
    let host_key = HostKey::parse(&read(&dir, "host_key.pub")).expect("host key");
    let client_key = ClientKey::parse(read(&dir, "id_ed25519").as_bytes()).expect("client key");
    let user = read(&dir, "user");

    let mut tcp = Tcp {
        sock: TcpStream::connect(("127.0.0.1", port)).unwrap(),
        ahead: Vec::new(),
    };
    let io = Io::new(&mut tcp, Bounds::new(30_000, 120_000, 64 << 20));
    let mut client = Client::connect(io, &[host_key]).expect("key exchange");
    eprintln!("agreed: {:?}", client.agreed);
    assert!(
        client.agreed.strict,
        "OpenSSH agrees on strict key exchange"
    );
    client
        .authenticate(user.as_bytes(), &Auth::Key(&client_key))
        .expect("sign-in");

    // About 109 KB of output, many times the server's RekeyLimit.
    let out = client.exec(b"seq 1 20000", 1 << 20).expect("exec");
    let want: String = (1..=20_000).map(|i| format!("{i}\n")).collect();
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
    let after_first = client.rekeys;
    eprintln!("rekeys during the first command: {after_first}");
    assert!(after_first >= 2, "the server rekeyed: {after_first}");

    // A second channel on the same connection, after the re-exchanges.
    let out = client.exec(b"echo done", 1024).expect("second exec");
    assert_eq!(out.stdout.as_slice(), b"done\n");
    eprintln!("rekeys in all: {}", client.rekeys);
}
