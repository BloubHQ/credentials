//! Reads arbitrary bytes, in arbitrary pieces, as WebSocket frames from a server. It must
//! never panic, never hand back a message over the limit, and every text message is UTF-8.

#![no_main]

use engine::websocket::{Decoder, Message};
use libfuzzer_sys::fuzz_target;

const MAX: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some((&step, bytes)) = data.split_first() else {
        return;
    };
    let step = usize::from(step).max(1);
    let mut decoder = Decoder::new(MAX);
    for piece in bytes.chunks(step) {
        if decoder.push(piece).is_err() {
            return;
        }
        loop {
            match decoder.message() {
                Ok(Some(Message::Text(text))) => {
                    assert!(text.len() <= MAX);
                    assert!(core::str::from_utf8(&text).is_ok());
                }
                Ok(Some(Message::Binary(bytes))) => assert!(bytes.len() <= MAX),
                Ok(Some(Message::Ping(p) | Message::Pong(p))) => assert!(p.len() <= 125),
                Ok(Some(Message::Close(_))) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
});
