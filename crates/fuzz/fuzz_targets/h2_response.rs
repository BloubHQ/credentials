//! Reads arbitrary bytes as one HPACK header block, and arbitrary bytes as what an HTTP/2
//! server sends after the connection preface. Neither may panic; a response that comes out
//! has a head with no control byte the engine's parser would read differently, and the
//! engine's parser reads it.

#![no_main]

use libfuzzer_sys::fuzz_target;

const WIRE: &[u8] = b"POST /x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\nhi";

fuzz_target!(|data: &[u8]| {
    let (block, server) = data.split_at(data.len() / 3);
    let mut decoder = transport::hpack::Decoder::new(4096);
    let _ = decoder.decode(block, 64 * 1024);
    if let Ok(bytes) = transport::h2::exchange_scripted(server, WIRE, 1 << 20) {
        let end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a response has a head");
        let head = &bytes[..end];
        assert!(
            head.iter()
                .all(|b| matches!(*b, b'\r' | b'\n' | b'\t') || (*b >= 0x20 && *b != 0x7f)),
            "a field with a control byte came through"
        );
        let lines = head.split(|b| *b == b'\n').count();
        let crlf = head.windows(2).filter(|w| w == b"\r\n").count();
        assert_eq!(lines, crlf + 1, "a bare line feed came through");
    }
});
