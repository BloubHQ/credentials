//! Reads arbitrary bytes as one CDP message from a browser, then its result with every typed
//! reader of a browser fill, and the bytes as URLs and origins. It must never panic; a frame
//! tree that reads is bounded and ordered (each frame after its parent), a target list is
//! bounded, and an origin that reads serializes to what reads back the same.

#![no_main]

use engine::cdp::{self, Incoming, WebOrigin};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Incoming::Answer {
        result: Ok(raw), ..
    }) = cdp::parse(data)
    {
        if let Ok(frames) = cdp::frame_tree(raw) {
            assert!(!frames.is_empty() && frames.len() <= cdp::MAX_FRAMES);
            assert!(frames[0].parent.is_none() && frames[0].depth == 0);
            for (i, frame) in frames.iter().enumerate() {
                assert!(frame.depth <= cdp::MAX_DEPTH);
                if let Some(parent) = &frame.parent {
                    let at = frames[..i].iter().position(|f| &f.id == parent);
                    assert!(at.is_some_and(|p| frames[p].depth + 1 == frame.depth));
                }
            }
        }
        if let Ok(targets) = cdp::targets(raw) {
            assert!(targets.len() <= cdp::MAX_TARGETS);
        }
        let _ = cdp::session_id(raw);
        let _ = cdp::context_id(raw);
        let _ = cdp::remote(raw);
        let _ = cdp::navigated(raw);
    }
    let text = String::from_utf8_lossy(data);
    for origin in [WebOrigin::parse(&text), WebOrigin::of_url(&text)]
        .into_iter()
        .flatten()
    {
        let shown = origin.serialize();
        assert_eq!(WebOrigin::parse(&shown).as_ref(), Some(&origin));
        assert_eq!(WebOrigin::of_url(&shown).as_ref(), Some(&origin));
    }
});
