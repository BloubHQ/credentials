//! The capture sources that read structure in text: `html` (an element of an HTML page, by a
//! simple selector) and `regex` (a group of a regular expression).
//!
//! Both work in time linear in the bytes they read, and both read at most [`MAX_SCAN`] bytes:
//!
//! - `regex` uses the `regex` crate, which never backtracks (finite automata only), compiled
//!   with bounded program and cache sizes, matching bytes without Unicode classes.
//! - `html` uses `html5gum`, a WHATWG tokenizer with no dependencies and no unsafe code. Only
//!   tokens are read, not a tree: a selector is one compound selector (a tag, `#id`, `.class`,
//!   `[attr]`, `[attr=value]`), matched against each start tag, so there is no combinator to
//!   make the match cost grow with nesting.

use html5gum::{Token, Tokenizer};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Most bytes `html` and `regex` read.
pub const MAX_SCAN: usize = 2 * 1024 * 1024;
/// Longest pattern or selector, in bytes.
pub const MAX_PATTERN: usize = 256;
/// Most bytes of the compiled program of a pattern.
const REGEX_SIZE: usize = 256 * 1024;
/// Most bytes of the lazy DFA cache of a pattern.
const REGEX_CACHE: usize = 1024 * 1024;
/// Most bytes of text an `html` capture collects before it fails.
const MAX_TEXT: usize = crate::response::MAX_CAPTURE;

fn invalid(rule: &'static str) -> Error {
    Error::ResponseInvalid { rule }
}

/// Compiles a pattern of a `regex` capture. `None` when it is too long, does not parse, or
/// compiles to more than the size limits.
pub(crate) fn compile(pattern: &str) -> Option<regex::bytes::Regex> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN {
        return None;
    }
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_CACHE)
        .nest_limit(32)
        .build()
        .ok()
}

/// Compiles a pattern that must match a whole value (a query value, an input member, a
/// caller send of a stream), with the limits of [`compile`]. `None` as for [`compile`].
pub(crate) fn compile_whole(pattern: &str) -> Option<regex::bytes::Regex> {
    // The pattern alone is checked first, so the anchors do not count against its length and
    // an alternation in it cannot escape them.
    compile(pattern)?;
    regex::bytes::RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
        .unicode(false)
        .size_limit(REGEX_SIZE)
        .dfa_size_limit(REGEX_CACHE)
        .nest_limit(32)
        .build()
        .ok()
}

/// The group of a pattern a capture takes: `group` when given (it must exist), otherwise 1
/// when the pattern has a group and 0 (the whole match) when it has none.
pub(crate) fn group_of(regex: &regex::bytes::Regex, group: Option<u8>) -> Option<usize> {
    let groups = regex.captures_len();
    match group {
        Some(g) => Some(usize::from(g)).filter(|g| *g < groups),
        None => Some(usize::from(groups > 1)),
    }
}

/// The group of the first match of `pattern` in `bytes`.
pub fn regex(bytes: &[u8], pattern: &str, group: Option<u8>) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if bytes.len() > MAX_SCAN {
        return Err(invalid("too large for regex"));
    }
    let regex = compile(pattern).ok_or(invalid("regex pattern"))?;
    let index = group_of(&regex, group).ok_or(invalid("regex group"))?;
    Ok(regex
        .captures(bytes)
        .and_then(|c| c.get(index))
        .map(|m| Zeroizing::new(m.as_bytes().to_vec())))
}

/// One condition of a compound selector.
#[derive(Debug, PartialEq, Eq)]
enum Condition {
    Id(Vec<u8>),
    Class(Vec<u8>),
    Has(Vec<u8>),
    Equals(Vec<u8>, Vec<u8>),
}

/// A compound selector: an optional tag name and conditions on attributes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Selector {
    tag: Option<Vec<u8>>,
    conditions: Vec<Condition>,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':'
}

fn ident(text: &[u8]) -> (&[u8], &[u8]) {
    let end = text
        .iter()
        .position(|b| !is_ident(*b))
        .unwrap_or(text.len());
    text.split_at(end)
}

impl Selector {
    /// Parses `tag#id.class[attr][attr=value][attr="value"]`; every part is optional but one
    /// must be present. Names are ASCII and compared lowercase; values are compared exactly.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || text.len() > MAX_PATTERN {
            return None;
        }
        let mut rest = text.as_bytes();
        let (tag, after) = ident(rest);
        let tag = if tag.is_empty() {
            if let Some(r) = rest.strip_prefix(b"*") {
                rest = r;
            }
            None
        } else {
            rest = after;
            Some(tag.to_ascii_lowercase())
        };
        let mut conditions = Vec::new();
        while let Some((&first, tail)) = rest.split_first() {
            match first {
                b'#' | b'.' => {
                    let (name, after) = ident(tail);
                    if name.is_empty() {
                        return None;
                    }
                    conditions.push(if first == b'#' {
                        Condition::Id(name.to_vec())
                    } else {
                        Condition::Class(name.to_vec())
                    });
                    rest = after;
                }
                b'[' => {
                    let close = tail.iter().position(|b| *b == b']')?;
                    let (inner, after) = tail.split_at(close);
                    rest = after.get(1..)?;
                    let (name, value) = ident(inner);
                    if name.is_empty() {
                        return None;
                    }
                    let name = name.to_ascii_lowercase();
                    conditions.push(match value.strip_prefix(b"=") {
                        None if value.is_empty() => Condition::Has(name),
                        None => return None,
                        Some(v) => {
                            let v = match v.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\""))
                            {
                                Some(quoted) => quoted,
                                None if v.iter().all(|b| is_ident(*b)) => v,
                                None => return None,
                            };
                            Condition::Equals(name, v.to_vec())
                        }
                    });
                }
                _ => return None,
            }
        }
        if tag.is_none() && conditions.is_empty() {
            return None;
        }
        Some(Self { tag, conditions })
    }

    fn matches(&self, tag: &html5gum::StartTag<()>) -> bool {
        if self
            .tag
            .as_ref()
            .is_some_and(|t| t.as_slice() != tag.name.as_slice())
        {
            return false;
        }
        let attr = |name: &[u8]| tag.attributes.get(name).map(|v| v.as_slice());
        self.conditions.iter().all(|c| match c {
            Condition::Id(id) => attr(b"id") == Some(id.as_slice()),
            Condition::Class(class) => attr(b"class").is_some_and(|v| {
                v.split(|b| b.is_ascii_whitespace())
                    .any(|c| c == class.as_slice())
            }),
            Condition::Has(name) => attr(name).is_some(),
            Condition::Equals(name, value) => attr(name) == Some(value.as_slice()),
        })
    }
}

/// Elements that have no content and no end tag.
const VOID: [&[u8]; 14] = [
    b"area", b"base", b"br", b"col", b"embed", b"hr", b"img", b"input", b"link", b"meta", b"param",
    b"source", b"track", b"wbr",
];

/// The first element `selector` matches in `bytes`: the value of its attribute `attribute`,
/// or, without one, its text (the text tokens up to its end tag, entities decoded).
pub fn html(
    bytes: &[u8],
    selector: &str,
    attribute: Option<&str>,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if bytes.len() > MAX_SCAN {
        return Err(invalid("too large for html"));
    }
    let selector = Selector::parse(selector).ok_or(invalid("html selector"))?;
    let attribute = attribute.map(str::to_ascii_lowercase);
    let mut emitter = html5gum::DefaultEmitter::default();
    // Raw text elements (script, style, textarea, title) are read as text, not as tags.
    emitter.naively_switch_states(true);
    let mut tokens = Tokenizer::new_with_emitter(bytes, emitter).flatten();
    let found = tokens.by_ref().find_map(|token| match token {
        Token::StartTag(tag) if selector.matches(&tag) => Some(tag),
        _ => None,
    });
    let Some(tag) = found else {
        return Ok(None);
    };
    if let Some(name) = attribute {
        return Ok(tag
            .attributes
            .get(name.as_bytes())
            .map(|v| Zeroizing::new(v.to_vec())));
    }
    if tag.self_closing || VOID.contains(&tag.name.as_slice()) {
        return Ok(None);
    }
    let mut text = Zeroizing::new(Vec::new());
    let mut depth = 0usize;
    for token in tokens {
        match token {
            Token::String(s) => {
                if text.len() + s.len() > MAX_TEXT {
                    return Err(invalid("captured value too large"));
                }
                text.extend_from_slice(&s);
            }
            Token::StartTag(t) if t.name == tag.name && !t.self_closing => depth += 1,
            Token::EndTag(t) if t.name == tag.name => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    Ok(Some(text))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PAGE: &[u8] = br#"<!doctype html><html><head><meta name="csrf-token" content="m&amp;1">
<title>T</title></head><body><form id=login class="form main">
<input type="hidden" name="_csrf" value="abc&quot;123">
<input type=hidden name=other value=x>
<div class="a"><span>one</span> &amp; <div>two</div></div>
<script>var s = "<input name='_csrf' value='fake'>";</script>
</form></body></html>"#;

    fn attr(selector: &str, attribute: &str) -> Option<Vec<u8>> {
        html(PAGE, selector, Some(attribute))
            .unwrap()
            .map(|v| v.to_vec())
    }

    #[test]
    fn html_reads_attributes_and_text() {
        assert_eq!(
            attr(r#"input[name="_csrf"]"#, "value").unwrap(),
            b"abc\"123"
        );
        assert_eq!(attr("input[name=other]", "value").unwrap(), b"x");
        assert_eq!(attr("meta[name=csrf-token]", "content").unwrap(), b"m&1");
        assert_eq!(attr("form#login.main", "class").unwrap(), b"form main");
        assert_eq!(attr("#login.missing", "class"), None);
        assert_eq!(attr("input[name=_csrf]", "missing"), None);
        let text = |s: &str| html(PAGE, s, None).unwrap().map(|v| v.to_vec());
        assert_eq!(text("div.a").unwrap(), b"one & two");
        assert_eq!(text("title").unwrap(), b"T");
        // Text inside a script is text, not tags.
        assert_eq!(
            text("script").unwrap(),
            br#"var s = "<input name='_csrf' value='fake'>";"#
        );
        assert_eq!(text("input"), None);
    }

    #[test]
    fn selectors_parse_strictly() {
        for bad in [
            "", "div > a", "a b", "[x", "[=x]", "#", "a[x=y z]", "a:hover(", "*",
        ] {
            assert_eq!(Selector::parse(bad), None, "{bad}");
        }
        assert!(Selector::parse("*[name]").is_some());
        assert!(Selector::parse(&"a".repeat(MAX_PATTERN + 1)).is_none());
    }

    #[test]
    fn regex_takes_a_group() {
        let body = b"key=abc123,ff00ee\n";
        let get = |p: &str, g: Option<u8>| regex(body, p, g).unwrap().map(|v| v.to_vec());
        assert_eq!(get("^([^,]*),", None).unwrap(), b"key=abc123");
        assert_eq!(get(",([0-9a-f]+)", None).unwrap(), b"ff00ee");
        assert_eq!(get("([a-z]+)=([a-z0-9]+)", Some(2)).unwrap(), b"abc123");
        assert_eq!(get("[0-9]+", None).unwrap(), b"123");
        assert_eq!(get("nothing", None), None);
        assert_eq!(
            regex(body, "(a)", Some(2)).map(|_| ()),
            Err(invalid("regex group"))
        );
        // Backreferences and look-around are not regular: refused.
        for bad in [r"(a)\1", "(?=a)", "(", &"a".repeat(MAX_PATTERN + 1)] {
            assert!(compile(bad).is_none(), "{bad}");
        }
        // A pattern whose program exceeds the size limit.
        assert!(compile("[a-z]{1000}{1000}").is_none());
    }

    #[test]
    fn scans_are_bounded() {
        let big = vec![b'a'; MAX_SCAN + 1];
        assert!(regex(&big, "b", None).is_err());
        assert!(html(&big, "a", None).is_err());
    }
}
