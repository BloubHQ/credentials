//! Runs the `regex` capture source on arbitrary bytes: the first byte splits a pattern from
//! the text, the second picks the group.

#![no_main]

use engine::extract::regex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let Some((&group, rest)) = rest.split_first() else {
        return;
    };
    let split = usize::from(split).min(rest.len());
    let (pattern, text) = rest.split_at(split);
    let pattern = String::from_utf8_lossy(pattern);
    let group = (group < 8).then_some(group);
    if let Ok(Some(value)) = regex(text, &pattern, group) {
        // A match is a part of the text.
        assert!(value.len() <= text.len());
        assert!(value.is_empty() || text.windows(value.len()).any(|w| w == value.as_slice()));
    }
});
