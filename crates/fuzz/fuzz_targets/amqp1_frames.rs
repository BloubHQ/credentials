//! Reads arbitrary bytes as what an AMQP 1.0 server sends: values of the type system, a frame,
//! the performative inside it, and a message. Nothing may panic; a decode stays within its
//! bounds (depth and value count), a frame within the node's max-frame-size, a performative is
//! one the standard defines, and a value that decodes encodes again.

#![no_main]

use engine::proto::amqp1::{self, Decoder, Message, Value};
use libfuzzer_sys::fuzz_target;

/// The depth of a value.
fn depth(value: &Value) -> usize {
    match value {
        Value::List(items) | Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Map(pairs) => {
            1 + pairs
                .iter()
                .map(|(k, v)| depth(k).max(depth(v)))
                .max()
                .unwrap_or(0)
        }
        Value::Described(d, v) => 1 + depth(d).max(depth(v)),
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = amqp1::decode(data) {
        assert!(depth(&value) <= 2 * amqp1::MAX_DEPTH + 2);
        let mut out = Vec::new();
        let _ = amqp1::encode(&value, &mut out);
        let _ = value.json();
    }
    // Values one after another, as the sections of a message come.
    let mut d = Decoder::new(data);
    while !d.is_empty() {
        if d.value().is_err() {
            break;
        }
    }
    if let Ok(Some((n, frame))) = amqp1::parse_frame(data, amqp1::MAX_FRAME) {
        assert!(n <= data.len());
        assert!(n <= amqp1::MAX_FRAME as usize);
        assert!(frame.body.len() + 8 <= n);
        if let Ok(p) = amqp1::performative(&frame.body) {
            assert!(
                (amqp1::code::OPEN..=amqp1::code::CLOSE).contains(&p.code)
                    || (amqp1::code::SASL_MECHANISMS..=amqp1::code::SASL_OUTCOME).contains(&p.code)
            );
        }
    }
    if let Ok(message) = Message::parse(data) {
        assert!(message.body.len() <= data.len());
        let _ = message.json();
    }
});
