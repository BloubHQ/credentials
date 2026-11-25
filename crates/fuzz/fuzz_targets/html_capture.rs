//! Runs the `html` capture source on arbitrary bytes: the first byte splits a selector from
//! the page, the second picks an attribute or the text of the element.

#![no_main]

use engine::extract::{MAX_SCAN, html};
use libfuzzer_sys::fuzz_target;

const ATTRIBUTES: [Option<&str>; 4] = [None, Some("value"), Some("content"), Some("id")];

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let Some((&pick, rest)) = rest.split_first() else {
        return;
    };
    let split = usize::from(split).min(rest.len());
    let (selector, page) = rest.split_at(split);
    let selector = String::from_utf8_lossy(selector);
    let attribute = ATTRIBUTES[usize::from(pick) % ATTRIBUTES.len()];
    let result = html(page, &selector, attribute);
    if page.len() > MAX_SCAN {
        assert!(result.is_err());
    }
    if let (Ok(Some(text)), None) = (&result, attribute) {
        // The text of an element is bounded like any captured value.
        assert!(text.len() <= engine::response::MAX_CAPTURE);
    }
});
