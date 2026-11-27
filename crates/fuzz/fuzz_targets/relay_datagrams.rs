//! Reads arbitrary bytes as what crosses the egress relay for datagrams: the request line of
//! a link, then frames. Parsing must never panic, a frame never exceeds the largest datagram,
//! and a frame written back reads the same.

#![no_main]

use std::io::Cursor;

use engine::readbuf::ReadBuf;
use libfuzzer_sys::fuzz_target;
use relay::datagram::{
    MAX_DATAGRAM, read_datagram, read_egress_request, take_datagram, write_datagram,
};

fuzz_target!(|data: &[u8]| {
    if let Ok((_, host, port)) = read_egress_request(&mut Cursor::new(data)) {
        assert!(relay::valid_host(&host) && port != 0);
    }
    // The same bytes as frames, read from a stream and taken off a buffer.
    let mut stream = Cursor::new(data);
    while let Ok(Some(frame)) = read_datagram(&mut stream) {
        assert!(!frame.is_empty() && frame.len() <= MAX_DATAGRAM);
        let mut written = Vec::new();
        assert!(write_datagram(&mut written, &frame).is_ok());
        let again = read_datagram(&mut Cursor::new(written));
        assert!(matches!(again, Ok(Some(ref f)) if *f == frame));
    }
    let mut pending = ReadBuf::new();
    pending.push(data);
    while let Ok(Some(frame)) = take_datagram(&mut pending) {
        assert!(!frame.is_empty() && frame.len() <= MAX_DATAGRAM);
    }
});
