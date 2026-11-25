//! Reads arbitrary bytes as a frame of the hand-over protocol and as a hand-over package, and
//! offers the package to a fresh node, which must refuse it (it is not sealed to that node)
//! and stay empty.

#![no_main]

use continuity::wire::{Request, Response, parse_frame, read_frame};
use engine::keys::NodeKey;
use engine::log::MemorySink;
use engine::node::{HandOver, Node, SystemClock};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_frame::<Request>(data);
    let _ = parse_frame::<Response>(data);
    let _ = read_frame::<_, Request>(&mut &data[..]);
    let Ok(hand_over) = serde_json::from_slice::<HandOver>(data) else {
        return;
    };
    let _ = hand_over.package_sha256();
    let node = Node::new(
        NodeKey::from_bytes(&mut [7u8; 32]),
        MemorySink::new(),
        SystemClock,
    );
    let predecessor = NodeKey::from_bytes(&mut [9u8; 32]).public();
    assert!(node.take_over(&predecessor, &hand_over).is_err());
    assert!(node.with_sink(|sink| sink.entries().is_empty()));
});
