//! FTP and POP3 server replies as arbitrary bytes: the reply, passive-address, listing,
//! status and multi-line readers must not panic and must keep their bounds, a path that
//! passes the check holds no byte that ends or splits a command, and a scrubbed reply holds
//! no sign-in value.

#![no_main]

use engine::proto::{ftp, io::Scrub, pop3};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const USER: &[u8] = b"reports-user";
const SECRET: &[u8] = b"hunter2-pass";

/// The bytes as CRLF lines, the last one as it is.
fn lines(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some(at) = rest.windows(2).position(|w| w == b"\r\n") {
        out.push(rest[..at + 2].to_vec());
        rest = &rest[at + 2..];
    }
    if !rest.is_empty() {
        out.push(rest.to_vec());
    }
    out
}

fn reader(lines: &[Vec<u8>]) -> impl FnMut() -> engine::Result<Zeroizing<Vec<u8>>> + '_ {
    let mut next = lines.iter();
    move || {
        next.next()
            .map(|l| Zeroizing::new(l.clone()))
            .ok_or(engine::Error::transport(
                engine::error::TransportKind::Closed,
                true,
            ))
    }
}

fuzz_target!(|data: &[u8]| {
    let all = lines(data);
    let mut next = reader(&all);
    if let Ok(reply) = ftp::read_reply(&mut next) {
        assert!(reply.lines.len() <= 256);
        assert!(reply.code >= 100 && reply.code <= 599);
        let _ = ftp::parse_epsv(&reply.text());
        let _ = ftp::parse_pasv(&reply.text());
    }
    let _ = ftp::parse_epsv(data);
    if let Some((_, port)) = ftp::parse_pasv(data) {
        let _ = port;
    }
    for mlsd in [true, false] {
        if let Ok(entries) = ftp::parse_listing(data, mlsd) {
            assert!(entries.len() <= 10_000);
            for entry in &entries {
                let _ = entry.json();
            }
        }
    }
    if ftp::check_path(data).is_ok() {
        assert!(data.first() == Some(&b'/'));
        assert!(!data.iter().any(|b| *b < 0x20 || *b == 0x7f || *b == 0xff));
    }

    let mut next = reader(&all);
    if let Ok(body) = pop3::read_body(&mut next, 4096) {
        assert!(body.len() <= 4096);
    }
    let _ = pop3::status_of(data);
    let _ = pop3::timestamp(data);
    let _ = pop3::number_ok(data);

    let scrubbed = Scrub::new(&[USER, SECRET]).apply(data);
    let found = |needle: &[u8]| scrubbed.windows(needle.len()).any(|w| w == needle);
    assert!(!found(SECRET), "a scrubbed reply holds the secret");
    assert!(!found(USER), "a scrubbed reply holds the user name");
});
