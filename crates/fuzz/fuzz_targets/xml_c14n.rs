//! Canonicalizes arbitrary bytes as an XML document: the first byte picks one of the six
//! algorithms, whether the bytes up to the first 0xff are an inclusive prefix list, and a
//! limit. No panic; the output stays within the limit given; a canonical form is its own
//! canonical form; the input escaped by `xml_escape` is character data.

#![no_main]

use engine::xml::{MAX_CANONICAL, MAX_XML, c14n, escape};
use libfuzzer_sys::fuzz_target;

const ALGORITHMS: [&str; 6] = [
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    "http://www.w3.org/2006/12/xml-c14n11",
    "http://www.w3.org/2006/12/xml-c14n11#WithComments",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let algorithm = ALGORITHMS[usize::from(pick) % ALGORITHMS.len()].as_bytes();
    let (prefixes, document) = match (pick & 0x80 != 0, rest.iter().position(|b| *b == 0xff)) {
        (true, Some(at)) => (&rest[..at], &rest[at + 1..]),
        _ => (&[][..], rest),
    };
    let limit = if pick & 0x40 == 0 { usize::MAX } else { 4096 };
    if let Ok(out) = c14n(algorithm, document, prefixes, limit) {
        assert!(out.len() <= MAX_CANONICAL && out.len() <= limit);
        if out.len() <= MAX_XML {
            let again = c14n(algorithm, &out, prefixes, usize::MAX)
                .expect("a canonical form is a document");
            assert_eq!(again.as_slice(), out.as_slice());
        }
    }
    if let Ok(text) = escape(document) {
        let mut wrapped = b"<r>".to_vec();
        wrapped.extend_from_slice(&text);
        wrapped.extend_from_slice(b"</r>");
        if wrapped.len() <= MAX_XML {
            let out = c14n(ALGORITHMS[4].as_bytes(), &wrapped, b"", usize::MAX)
                .expect("escaped text is character data");
            assert!(out.len() >= 7);
        }
    }
});
