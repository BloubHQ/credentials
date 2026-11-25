//! The contract of a caller request: the methods, path templates, headers and query
//! parameters a signed policy lets a caller choose, and the checks a request passes before
//! anything is rendered, logged or sent.
//!
//! - **Paths** are templates matched exactly, segment by segment: a literal segment, `*` (one
//!   non-empty segment), `{name}` (the placeholder of a path parameter the policy fills: the
//!   caller writes it there and nowhere else) and, last, `**` (one or more segments).
//! - **Path checks** refuse dot segments in every form a server may read them: as sent, with
//!   `;` parameters stripped, after one decoding and after a second one; `%25` is refused
//!   unless the policy allows encoded percent signs, so a second decoding changes nothing.
//! - **Query parameters** are allowed by name: each name the caller sends must be listed, at
//!   most once, with its value within the rule; names the policy injects and reserved
//!   method-override names are refused.

use serde::{Deserialize, Serialize};

use super::{Method, is_false, is_token};
use crate::primitives::pct_decode;
use crate::request::{MAX_BODY, MAX_HEADER_VALUE, MAX_HEADERS, MAX_PATH, Request};
use crate::{Error, Result};

/// Most query parameters a contract names.
pub const MAX_QUERY_RULES: usize = 32;
/// Most values of a `one_of` rule.
pub const MAX_ONE_OF: usize = 32;
/// Longest decimal bound of a `min` or `max` rule, in digits.
pub const MAX_DIGITS: usize = 80;

/// Parameter names some web frameworks read as the method of the request. A caller may not
/// send them, in the query or the body, unless the contract allows it.
pub const RESERVED_PARAMS: [&str; 6] = [
    "_method",
    "__method",
    "_httpmethod",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// What the caller may choose in a request a `send` step takes from it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerRequest {
    /// Methods the caller may use.
    #[serde(default)]
    pub methods: Vec<Method>,
    /// Path templates the caller's path must match exactly (see the module documentation).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Headers the caller may set (case does not matter).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// Query parameters the caller may send. None by default: a query parameter that is not
    /// listed is refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query: Vec<QueryRule>,
    /// Allows `%25` in the path. Off by default (strict): with it, a server that decodes twice
    /// may read another path than the one checked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub encoded_percent: bool,
    /// Allows the reserved method-override parameter names ([`RESERVED_PARAMS`]) in the query
    /// and the body. Off by default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub override_params: bool,
}

/// A query parameter the caller may send, and the values it may take. A rule with no
/// `equals`, `one_of`, `pattern`, `min` or `max` allows any value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRule {
    /// The name, as the server reads it (percent-decoded).
    pub name: String,
    /// True when the caller must send it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    /// The one value allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    /// The values allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<String>,
    /// A regular expression the whole value must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The smallest decimal integer allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    /// The largest decimal integer allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
}

impl QueryRule {
    /// A parameter that must be sent with exactly `value`.
    pub fn fixed(name: &str, value: &str) -> Self {
        Self {
            name: name.into(),
            required: true,
            equals: Some(value.into()),
            ..Self::default()
        }
    }

    /// A parameter that may be sent with any value.
    pub fn any(name: &str) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    pub(crate) fn allowed(&self) -> Allowed<'_> {
        Allowed {
            equals: self.equals.as_deref(),
            one_of: &self.one_of,
            pattern: self.pattern.as_deref(),
            min: self.min.as_deref(),
            max: self.max.as_deref(),
        }
    }
}

/// The value rules of a query parameter or an input member, borrowed.
#[derive(Clone, Copy)]
pub(crate) struct Allowed<'a> {
    pub equals: Option<&'a str>,
    pub one_of: &'a [String],
    pub pattern: Option<&'a str>,
    pub min: Option<&'a str>,
    pub max: Option<&'a str>,
}

/// True for a decimal integer written `-?(0|[1-9][0-9]*)`, at most [`MAX_DIGITS`] digits.
pub(crate) fn is_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty()
        && digits.len() <= MAX_DIGITS
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text != "-0"
}

/// Compares two decimal integers [`is_decimal`] accepts.
pub(crate) fn compare_decimal(a: &str, b: &str) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let (a_neg, a_digits) = a.strip_prefix('-').map_or((false, a), |d| (true, d));
    let (b_neg, b_digits) = b.strip_prefix('-').map_or((false, b), |d| (true, d));
    let magnitude = a_digits
        .len()
        .cmp(&b_digits.len())
        .then_with(|| a_digits.cmp(b_digits));
    match (a_neg, b_neg) {
        (false, false) => magnitude,
        (true, true) => magnitude.reverse(),
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
    }
}

impl Allowed<'_> {
    /// True when the rule allows any value.
    pub fn is_any(&self) -> bool {
        self.equals.is_none()
            && self.one_of.is_empty()
            && self.pattern.is_none()
            && self.min.is_none()
            && self.max.is_none()
    }

    /// Why the rule itself is invalid, if it is.
    pub fn fault(&self) -> Option<&'static str> {
        let kinds = usize::from(self.equals.is_some())
            + usize::from(!self.one_of.is_empty())
            + usize::from(self.pattern.is_some())
            + usize::from(self.min.is_some() || self.max.is_some());
        if kinds > 1 {
            return Some("a value rule is one of equals, one_of, pattern, or min and max");
        }
        if self.one_of.len() > MAX_ONE_OF {
            return Some("one_of holds at most 32 values");
        }
        if let Some(pattern) = self.pattern {
            if crate::extract::compile_whole(pattern).is_none() {
                return Some(
                    "pattern must be a regular expression of at most 256 bytes within the size limits",
                );
            }
        }
        let bound_ok = |b: Option<&str>| b.is_none_or(is_decimal);
        if !bound_ok(self.min) || !bound_ok(self.max) {
            return Some("min and max are decimal integers of at most 80 digits");
        }
        if let (Some(min), Some(max)) = (self.min, self.max) {
            if compare_decimal(min, max) == core::cmp::Ordering::Greater {
                return Some("min is greater than max");
            }
        }
        None
    }

    /// True when `value` passes the rule.
    pub fn admits(&self, value: &[u8]) -> bool {
        if let Some(equals) = self.equals {
            return value == equals.as_bytes();
        }
        if !self.one_of.is_empty() {
            return self.one_of.iter().any(|v| v.as_bytes() == value);
        }
        if let Some(pattern) = self.pattern {
            return crate::extract::compile_whole(pattern).is_some_and(|r| r.is_match(value));
        }
        if self.min.is_some() || self.max.is_some() {
            let Some(text) = core::str::from_utf8(value).ok().filter(|t| is_decimal(t)) else {
                return false;
            };
            let low = self
                .min
                .is_none_or(|m| compare_decimal(text, m) != core::cmp::Ordering::Less);
            let high = self
                .max
                .is_none_or(|m| compare_decimal(text, m) != core::cmp::Ordering::Greater);
            return low && high;
        }
        true
    }

    /// The rule in words, for a summary.
    pub fn describe(&self) -> String {
        if let Some(equals) = self.equals {
            return format!("= {equals:?}");
        }
        if !self.one_of.is_empty() {
            return format!("one of {:?}", self.one_of);
        }
        if let Some(pattern) = self.pattern {
            return format!("matching /{pattern}/");
        }
        match (self.min, self.max) {
            (Some(min), Some(max)) => format!("from {min} to {max}"),
            (Some(min), None) => format!("at least {min}"),
            (None, Some(max)) => format!("at most {max}"),
            (None, None) => "any value".into(),
        }
    }
}

fn decoded(text: &str) -> Option<Vec<u8>> {
    pct_decode(text.as_bytes()).ok().map(|v| v.to_vec())
}

/// Decodes every valid `%XX` escape and keeps any other byte as it is.
fn lenient_decode(bytes: &[u8]) -> Vec<u8> {
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let escape = (b == b'%')
            .then(|| Some((hex(*bytes.get(i + 1)?)?, hex(*bytes.get(i + 2)?)?)))
            .flatten();
        match escape {
            Some((high, low)) => {
                out.push(u8::try_from(high * 16 + low).unwrap_or(b'%'));
                i += 3;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// True when `form` (a segment as sent, or decoded) would be read as `.` or `..`, or as more
/// than one segment, by a server: also after `;` parameters are stripped.
fn dot_or_separator(form: &[u8], decoded: bool) -> bool {
    let stripped = form.split(|b| *b == b';').next().unwrap_or_default();
    let dot = |s: &[u8]| s == b"." || s == b"..";
    dot(form)
        || dot(stripped)
        || (decoded && form.iter().any(|b| *b == b'/' || *b == b'\\' || *b < 0x20))
}

/// Why a path (path and query, as sent) is unsafe to send, if it is. With `encoded_percent`
/// false (strict), `%25` is refused anywhere.
pub fn path_fault(path: &str, encoded_percent: bool) -> Option<&'static str> {
    if !path.starts_with('/') {
        return Some("path must start with /");
    }
    if path.len() > MAX_PATH {
        return Some("path longer than 2048 bytes");
    }
    if !path.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Some("path holds a fragment or a byte that is not visible ASCII");
    }
    let pathname = path.split_once('?').map_or(path, |(p, _)| p);
    if pathname.contains('\\') {
        return Some("path holds a backslash");
    }
    let lower = path.to_ascii_lowercase();
    if !encoded_percent && lower.contains("%25") {
        return Some("path holds an encoded % (%25), which a server may decode twice");
    }
    let lower_pathname = pathname.to_ascii_lowercase();
    if ["%2f", "%5c", "%2e"]
        .iter()
        .any(|e| lower_pathname.contains(e))
    {
        return Some("path holds an encoded /, \\ or .");
    }
    for segment in pathname.split('/').skip(1) {
        let Some(once) = decoded(segment) else {
            return Some("path holds a malformed percent escape");
        };
        // A server that decodes twice may skip what is not an escape and decode the rest.
        let unsafe_twice = dot_or_separator(&lenient_decode(&once), true);
        if dot_or_separator(segment.as_bytes(), false)
            || dot_or_separator(&once, true)
            || unsafe_twice
        {
            return Some(
                "path holds a dot segment or separator, as sent, after ; parameters or after decoding",
            );
        }
    }
    None
}

/// The placeholder name of a segment written `{name}`.
pub(crate) fn placeholder(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .filter(|name| is_token(name))
}

/// Why a path template is invalid, if it is.
pub fn template_fault(template: &str) -> Option<&'static str> {
    if template.contains('?') {
        return Some("a path template holds no query");
    }
    if path_fault(template, false).is_some() {
        return Some(
            "a path template starts with / and holds no dot segment, encoded separator or %25",
        );
    }
    let segments: Vec<&str> = template.split('/').skip(1).collect();
    for (i, segment) in segments.iter().enumerate() {
        let ok = match *segment {
            "**" => i + 1 == segments.len(),
            "*" => true,
            s if s.contains(['{', '}', '*']) => placeholder(s).is_some(),
            _ => true,
        };
        if !ok {
            return Some(
                "a path template segment is a literal, *, {name}, or ** at the end, and holds no other { } or *",
            );
        }
    }
    None
}

/// The placeholders of a path template or of a fixed path (in its path, not its query).
pub(crate) fn placeholders(path: &str) -> Vec<&str> {
    let pathname = path.split_once('?').map_or(path, |(p, _)| p);
    pathname
        .split('/')
        .skip(1)
        .filter_map(placeholder)
        .collect()
}

/// True when the pathname matches the template exactly.
pub fn template_matches(template: &str, pathname: &str) -> bool {
    let wanted: Vec<&str> = template.split('/').skip(1).collect();
    let given: Vec<&str> = pathname.split('/').skip(1).collect();
    let free = |s: &&str| !s.contains(['{', '}']);
    for (i, want) in wanted.iter().enumerate() {
        match *want {
            "**" => {
                return given
                    .get(i..)
                    .is_some_and(|rest| !rest.is_empty() && rest.iter().all(free));
            }
            "*" => {
                if !given.get(i).is_some_and(|s| !s.is_empty() && free(s)) {
                    return false;
                }
            }
            literal => {
                if given.get(i) != Some(&literal) {
                    return false;
                }
            }
        }
    }
    given.len() == wanted.len()
}

/// One query parameter as sent and as a server reads it.
pub(crate) struct Param<'a> {
    pub raw_value: &'a str,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// Splits a query into its parameters. Empty parameters, names with `+` and malformed escapes
/// are refused, so every name reads the same to every server.
pub(crate) fn parse_query(query: &str) -> core::result::Result<Vec<Param<'_>>, &'static str> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    query
        .split('&')
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            if name.is_empty() {
                return Err("query parameter without a name");
            }
            if name.contains('+') {
                return Err("query parameter name holds + (write a space as %20)");
            }
            Ok(Param {
                raw_value: value,
                name: decoded(name).ok_or("query holds a malformed percent escape")?,
                value: decoded(value).ok_or("query holds a malformed percent escape")?,
            })
        })
        .collect()
}

fn is_reserved(name: &[u8]) -> bool {
    RESERVED_PARAMS
        .iter()
        .any(|r| r.as_bytes().eq_ignore_ascii_case(name))
}

/// The top-level member names of a JSON object, all of them (duplicates included).
fn json_keys(body: &[u8]) -> Option<Vec<String>> {
    struct Keys;
    impl<'de> serde::de::Visitor<'de> for Keys {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let mut keys = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                map.next_value::<serde::de::IgnoredAny>()?;
                keys.push(key);
            }
            Ok(keys)
        }
    }
    use serde::Deserializer as _;
    let mut de = serde_json::Deserializer::from_slice(body);
    de.deserialize_map(Keys).ok()
}

/// True when a body names a reserved parameter as a form field, a top-level JSON member or a
/// multipart part.
pub(crate) fn body_overrides(body: &[u8]) -> bool {
    let form = body.split(|b| *b == b'&').any(|part| {
        let name = part.split(|b| *b == b'=').next().unwrap_or_default();
        let spaced: Vec<u8> = name
            .iter()
            .map(|b| if *b == b'+' { b' ' } else { *b })
            .collect();
        pct_decode(&spaced).is_ok_and(|n| is_reserved(n.trim_ascii()))
    });
    let trimmed = body.trim_ascii_start();
    let json = trimmed.first() == Some(&b'{')
        && json_keys(trimmed).is_some_and(|keys| keys.iter().any(|k| is_reserved(k.as_bytes())));
    let lower = body.to_ascii_lowercase();
    let multipart = RESERVED_PARAMS.iter().any(|r| {
        [format!("name=\"{r}\""), format!("name={r}")]
            .iter()
            .any(|needle| crate::response::find(&lower, needle.as_bytes()).is_some())
    });
    form || json || multipart
}

fn invalid(rule: &'static str) -> Error {
    Error::RequestInvalid { rule }
}

impl CallerRequest {
    /// Checks a caller request against the contract. `injected` are the query names the
    /// step injects, `params` the path parameters it fills. The destination is checked
    /// against the connection, not here.
    pub fn check(&self, request: &Request, injected: &[&str], params: &[&str]) -> Result<()> {
        if !self.methods.contains(&request.method) {
            return Err(Error::MethodDenied {
                method: request.method.as_str().to_string(),
            });
        }
        if let Some(rule) = path_fault(&request.path, self.encoded_percent) {
            return Err(invalid(rule));
        }
        let (pathname, query) = request
            .path
            .split_once('?')
            .unwrap_or((request.path.as_str(), ""));
        if query.contains(['{', '}']) {
            return Err(invalid(
                "a path parameter placeholder must be a whole path segment, not in the query",
            ));
        }
        for segment in pathname.split('/').skip(1) {
            if segment.contains(['{', '}'])
                && !placeholder(segment).is_some_and(|name| params.contains(&name))
            {
                return Err(invalid(
                    "a path parameter placeholder must be a whole path segment the policy fills",
                ));
            }
        }
        let found = placeholders(pathname);
        if params
            .iter()
            .any(|p| found.iter().filter(|f| *f == p).count() != 1)
        {
            return Err(invalid("path must hold each path parameter once"));
        }
        if !self.paths.iter().any(|t| template_matches(t, pathname)) {
            return Err(Error::PathDenied {
                path: pathname.to_string(),
            });
        }
        self.check_query(query, injected)?;
        if request.body.len() > MAX_BODY {
            return Err(invalid("body too large"));
        }
        if !self.override_params && body_overrides(&request.body) {
            return Err(invalid(
                "body names a reserved method-override parameter (_method and the like)",
            ));
        }
        self.check_headers(request)
    }

    fn check_query(&self, query: &str, injected: &[&str]) -> Result<()> {
        let params = parse_query(query).map_err(invalid)?;
        let mut seen: Vec<Vec<u8>> = Vec::with_capacity(params.len());
        for param in &params {
            let lower = param.name.to_ascii_lowercase();
            if !self.override_params && is_reserved(&lower) {
                return Err(invalid(
                    "query names a reserved method-override parameter (_method and the like)",
                ));
            }
            if injected
                .iter()
                .any(|i| i.as_bytes().eq_ignore_ascii_case(&param.name))
            {
                return Err(invalid(
                    "the caller sends a query parameter the policy injects",
                ));
            }
            if seen.contains(&lower) {
                return Err(invalid("query parameter repeated"));
            }
            seen.push(lower);
            let Some(rule) = self.query.iter().find(|r| r.name.as_bytes() == param.name) else {
                return Err(invalid("query parameter not allowed by the policy"));
            };
            let allowed = rule.allowed();
            if !allowed.is_any() && param.raw_value.contains('+') {
                return Err(invalid(
                    "a checked query value holds + (write a space as %20 and + as %2B)",
                ));
            }
            if !allowed.admits(&param.value) {
                return Err(invalid("query value not allowed by the policy"));
            }
        }
        let missing = self.query.iter().any(|r| {
            r.required
                && !params
                    .iter()
                    .any(|p| p.name.eq_ignore_ascii_case(r.name.as_bytes()))
        });
        if missing {
            return Err(invalid("a required query parameter is missing"));
        }
        Ok(())
    }

    fn check_headers(&self, request: &Request) -> Result<()> {
        if request.headers.len() > MAX_HEADERS {
            return Err(invalid("too many headers"));
        }
        let mut seen: Vec<String> = Vec::with_capacity(request.headers.len());
        for (name, value) in &request.headers {
            let lower = name.to_ascii_lowercase();
            let value_ok = value.len() <= MAX_HEADER_VALUE
                && value
                    .bytes()
                    .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b));
            if !is_token(name) || !value_ok || super::RESERVED_HEADERS.contains(&lower.as_str()) {
                return Err(invalid("header name or value malformed or reserved"));
            }
            if !self.headers.iter().any(|h| h.eq_ignore_ascii_case(name)) {
                return Err(invalid("header not allowed by the operation"));
            }
            if seen.contains(&lower) {
                return Err(invalid("header repeated"));
            }
            seen.push(lower);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dot_segments_are_refused_in_every_form() {
        for path in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/..;/admin",
            "/v1/.;/..;/admin",
            "/v1/..%3b/admin",
            "/v1/..%3B/admin",
            "/v1%2Fadmin",
            "/v1\\admin",
            "/v1/%zz",
            "/v1/%00",
        ] {
            assert!(path_fault(path, false).is_some(), "{path}");
            assert!(path_fault(path, true).is_some(), "{path}");
        }
        // Double encoding: refused outright in strict mode, and by the second decoding when
        // encoded percent signs are allowed.
        for path in [
            "/v1/%252e%252e/admin",
            "/v1/%252F",
            "/v1/%25%32%65%25%32%65/x",
        ] {
            assert!(path_fault(path, false).is_some(), "{path}");
            assert!(path_fault(path, true).is_some(), "{path}");
        }
        assert!(path_fault("/v1/100%25", false).is_some());
        assert_eq!(path_fault("/v1/100%25", true), None);
        assert_eq!(path_fault("/v1/a.b;v=1?x=..%2F", false), None);
    }

    #[test]
    fn templates_match_exactly() {
        assert!(template_matches("/v1/**", "/v1/x/y"));
        assert!(template_matches("/v1/**", "/v1/"));
        assert!(!template_matches("/v1/**", "/v1"));
        assert!(!template_matches("/v1/**", "/v10/x"));
        assert!(template_matches("/v1", "/v1"));
        assert!(!template_matches("/v1", "/v1/x"));
        assert!(template_matches("/**", "/"));
        assert!(template_matches("/", "/"));
        assert!(!template_matches("/", "/x"));
        assert!(template_matches("/a/*/c", "/a/b/c"));
        assert!(!template_matches("/a/*/c", "/a//c"));
        assert!(template_matches("/a/{id}/c", "/a/{id}/c"));
        assert!(!template_matches("/a/*/c", "/a/{id}/c"));
        assert!(!template_matches("/a/**", "/a/{id}"));
        assert!(!template_matches("/a/{id}/c", "/a/b/c"));
        assert_eq!(
            template_fault("/a/**/b"),
            Some(
                "a path template segment is a literal, *, {name}, or ** at the end, and holds no other { } or *"
            )
        );
        assert!(template_fault("/a/x{id}").is_some());
        assert!(template_fault("/a?x=1").is_some());
        assert_eq!(template_fault("/a/{id}/**"), None);
    }

    #[test]
    fn decimals_compare() {
        use core::cmp::Ordering;
        assert_eq!(compare_decimal("10", "9"), Ordering::Greater);
        assert_eq!(compare_decimal("-10", "-9"), Ordering::Less);
        assert_eq!(compare_decimal("-1", "0"), Ordering::Less);
        assert_eq!(compare_decimal("123", "123"), Ordering::Equal);
        assert!(is_decimal("0") && is_decimal("-5") && !is_decimal("05") && !is_decimal("-0"));
        assert!(!is_decimal("1e3") && !is_decimal("") && !is_decimal("+1"));
    }

    #[test]
    fn bodies_that_override_the_method_are_found() {
        for body in [
            &b"a=1&_method=DELETE"[..],
            b"%5Fmethod=DELETE",
            b"_METHOD=delete",
            br#"{"x":1,"_method":"DELETE"}"#,
            b"--b\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--b--",
            b"X-HTTP-Method-Override=PUT",
        ] {
            assert!(body_overrides(body), "{}", String::from_utf8_lossy(body));
        }
        for body in [&b"a=1&method=x"[..], br#"{"method":"x"}"#, b""] {
            assert!(!body_overrides(body));
        }
    }
}
