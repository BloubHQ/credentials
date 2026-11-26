//! Normalizes arbitrary bytes as up to eight parameter lists (split at each 0xff), as
//! `sorted_params` does. No panic; the output stays within the bound the budget is checked
//! against; a normalized list is its own normalized form.

#![no_main]

use engine::params::{MAX_LISTS, bound, sorted};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lists: Vec<&[u8]> = data.split(|b| *b == 0xff).take(MAX_LISTS).collect();
    if let Ok(out) = sorted(&lists) {
        let total = lists.iter().map(|l| l.len()).sum();
        assert!(out.len() <= bound(total, lists.len()));
        let again = sorted(&[out.as_slice()]).expect("a normalized list is a list");
        assert_eq!(again.as_slice(), out.as_slice());
    }
});
