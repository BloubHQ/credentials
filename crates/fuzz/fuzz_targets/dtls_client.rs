//! Reads arbitrary bytes as a DTLS pin, as a server certificate, and as the datagrams a
//! server sends a DTLS client during its handshake (each a 2-byte big-endian length and its
//! bytes). A pin that reads has its one spelling; with no roots no certificate is accepted;
//! and no handshake completes against a server that cannot prove a certificate the client
//! trusts: errors, never a panic.

#![no_main]

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use rustls::RootCertStore;
use transport::dtls::{DtlsStream, Trust};
use transport::udp::DatagramSocket;

/// Hands out the datagrams of the input, then fails (no wait for a timer).
struct Scripted(VecDeque<Vec<u8>>);

impl DatagramSocket for Scripted {
    fn send(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn recv(&mut self, _: Duration) -> io::Result<Option<Vec<u8>>> {
        self.0
            .pop_front()
            .map(Some)
            .ok_or_else(|| io::Error::other("no more datagrams"))
    }
}

fn datagrams(mut data: &[u8]) -> VecDeque<Vec<u8>> {
    let mut out = VecDeque::new();
    while let [a, b, rest @ ..] = data {
        let n = usize::from(u16::from_be_bytes([*a, *b])).min(rest.len());
        let (datagram, tail) = rest.split_at(n);
        out.push_back(datagram.to_vec());
        data = tail;
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if engine::policy::parse_pin(&text).is_some() {
        assert!(text.len() == 51 && text.starts_with("sha256/"));
    }
    let trust = Trust::new(
        Arc::new(RootCertStore::empty()),
        "coap.example.com",
        &[[0u8; 32]],
    );
    assert!(trust.check(data).is_err());
    let socket = Scripted(datagrams(data));
    let connected = DtlsStream::connect(
        Box::new(socket),
        trust,
        Duration::from_millis(10),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(connected.is_err());
});
