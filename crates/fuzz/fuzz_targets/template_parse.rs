//! Parses arbitrary text as a template and runs the analysis on whatever parses.

#![no_main]

use engine::template::{NameKind, Template};
use libfuzzer_sys::fuzz_target;

const KINDS: [NameKind; 5] = [
    NameKind::SecretField,
    NameKind::GuessableField,
    NameKind::PublicField,
    NameKind::SecretTemp,
    NameKind::PublicTemp,
];

fn check(template: &Template, kind: &dyn Fn(&str) -> NameKind) {
    let analyzed = template.analyze(kind);
    let tainted = template.tainted(kind);
    let guessable = template.guessable(kind);
    // A template that breaks a rule counts as tainted and guessable.
    if analyzed.is_err() {
        assert!(tainted && guessable);
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let Ok(template) = Template::parse(&text) else {
        return;
    };
    let _ = template.names();
    for var in template.vars() {
        let _ = (var.in_request(), var.in_stream(), var.in_derive());
    }
    for kind in KINDS {
        check(&template, &move |_: &str| kind);
    }
    // Give different names different kinds, so mixed expressions are covered too.
    check(&template, &|name: &str| {
        let pick = name
            .bytes()
            .fold(0usize, |acc, b| acc.wrapping_add(usize::from(b)));
        KINDS
            .get(pick % KINDS.len())
            .copied()
            .unwrap_or(NameKind::PublicField)
    });
});
