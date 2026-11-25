//! Input schemas: what a caller may hand an operation with no connection as `$input`.
//!
//! A schema is closed: every value of the input must be declared by a member (or lie under
//! one), and every declared member must be present unless it is optional. Members fix a
//! value, list the values allowed, bound a decimal integer, or (JSON) are set by the node from
//! its clock, so a caller cannot choose what the owner's policy fixes.
//!
//! - `raw`: any bytes, optionally bounded in length and matched whole by a pattern.
//! - `json`: one JSON value; members are JSON pointers. The node writes the checked value
//!   again (compact, members in the order given, numbers as written), and that is `$input`.
//!   Duplicate member names are refused.
//! - `rlp`: Recursive Length Prefix (optionally after fixed prefix bytes, such as the type byte
//!   of a typed transaction); members are pointers of list indexes (`/4`). Only canonical
//!   encodings are accepted. `$input` is the input as given.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::contract::{Allowed, compare_decimal};
use super::is_false;
use crate::{Error, Result};

/// Most members of a schema.
pub const MAX_MEMBERS: usize = 64;
/// Deepest nesting of an input value.
pub const MAX_INPUT_DEPTH: usize = 32;

/// The schema of the caller's input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    /// Bytes.
    Raw(RawInput),
    /// A JSON value.
    Json(JsonInput),
    /// An RLP value.
    Rlp(RlpInput),
}

/// Bytes, bounded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInput {
    /// Longest input, in bytes (at most the node's limit of 1 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<usize>,
    /// A regular expression the whole input must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// A JSON value and its members.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonInput {
    /// The members; nothing else may be present.
    #[serde(default)]
    pub members: Vec<Member>,
}

/// The type of a JSON member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonType {
    /// A string.
    String,
    /// A number.
    Number,
    /// `true` or `false`.
    Boolean,
    /// `null`.
    Null,
    /// An object.
    Object,
    /// An array.
    Array,
}

/// A clock value the node writes into a member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeTime {
    /// Unix seconds.
    Unix,
    /// Unix milliseconds.
    UnixMs,
}

/// One member of a JSON input. Without a value rule (`equals`, `one_of`, `pattern`, `min`,
/// `max`, `set`) any value is allowed there, objects and arrays included. Value rules read
/// the text of a string (unescaped) or a number, `true`, `false` or `null` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    /// JSON pointer (RFC 6901); empty for the whole value.
    pub pointer: String,
    /// True when the member may be absent.
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    /// The type the value must have.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<JsonType>,
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
    /// The node writes its clock here (a number), whatever the caller sent; `offset` is added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<NodeTime>,
    /// Added to the clock value of `set`, in its unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
}

impl Member {
    /// A member that must equal `value`.
    pub fn equals(pointer: &str, value: &str) -> Self {
        Self {
            pointer: pointer.into(),
            equals: Some(value.into()),
            ..Self::default()
        }
    }

    /// Requires the value to be of type `kind`.
    #[must_use]
    pub fn of(mut self, kind: JsonType) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Bounds a decimal integer value (either bound may be `None`).
    #[must_use]
    pub fn between(mut self, min: Option<&str>, max: Option<&str>) -> Self {
        self.min = min.map(Into::into);
        self.max = max.map(Into::into);
        self
    }

    /// Lets the member be absent.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// A member any value may fill.
    pub fn any(pointer: &str) -> Self {
        Self {
            pointer: pointer.into(),
            ..Self::default()
        }
    }

    /// A member the node sets to its clock plus `offset`.
    pub fn time(pointer: &str, time: NodeTime, offset: i64) -> Self {
        Self {
            pointer: pointer.into(),
            set: Some(time),
            offset: (offset != 0).then_some(offset),
            ..Self::default()
        }
    }

    fn allowed(&self) -> Allowed<'_> {
        Allowed {
            equals: self.equals.as_deref(),
            one_of: &self.one_of,
            pattern: self.pattern.as_deref(),
            min: self.min.as_deref(),
            max: self.max.as_deref(),
        }
    }
}

/// An RLP value: a list of items after optional prefix bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RlpInput {
    /// Bytes, in hex, the input must start with before its RLP (`02` for an EIP-1559
    /// transaction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The items; nothing else may be present.
    #[serde(default)]
    pub items: Vec<RlpItem>,
}

/// One item of an RLP input, by a pointer of list indexes (`/3`, `/8/0`; empty for the whole
/// value). Without a rule, any item is allowed there, lists included. `equals` and `one_of`
/// are hex; `min` and `max` bound the item read as a big-endian unsigned integer without
/// leading zero bytes (the empty string is 0).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RlpItem {
    /// Pointer of list indexes.
    pub pointer: String,
    /// True when the item may be absent (the list ends before it).
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    /// The one value allowed, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    /// The values allowed, hex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<String>,
    /// The smallest integer allowed, decimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    /// The largest integer allowed, decimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
}

impl RlpItem {
    /// An item that must equal `hex`.
    pub fn equals(pointer: &str, hex: &str) -> Self {
        Self {
            pointer: pointer.into(),
            equals: Some(hex.into()),
            ..Self::default()
        }
    }

    /// An item any value may fill.
    pub fn any(pointer: &str) -> Self {
        Self {
            pointer: pointer.into(),
            ..Self::default()
        }
    }

    /// An integer item of at most `max` (decimal).
    pub fn at_most(pointer: &str, max: &str) -> Self {
        Self {
            pointer: pointer.into(),
            max: Some(max.into()),
            ..Self::default()
        }
    }
}

fn invalid(rule: &'static str) -> Error {
    Error::InputInvalid { rule }
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Some(digit(*hi)? * 16 + digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// The tokens of a JSON pointer, or `None` when it is not one.
fn tokens(pointer: &str) -> Option<Vec<String>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    let rest = pointer.strip_prefix('/')?;
    Some(
        rest.split('/')
            .map(|t| t.replace("~1", "/").replace("~0", "~"))
            .collect(),
    )
}

fn unique_pointers<'a>(pointers: impl Iterator<Item = &'a str>) -> bool {
    let mut all: Vec<&str> = pointers.collect();
    let len = all.len();
    all.sort_unstable();
    all.dedup();
    all.len() == len
}

fn bounded(count: usize) -> Option<&'static str> {
    (count > MAX_MEMBERS).then_some("an input schema has at most 64 members")
}

impl Input {
    /// Any bytes.
    pub fn any() -> Self {
        Input::Raw(RawInput::default())
    }

    /// Why the schema is invalid, if it is.
    pub fn fault(&self) -> Option<&'static str> {
        match self {
            Input::Raw(raw) => {
                if raw.max_len.is_some_and(|m| m > crate::node::MAX_INPUT) {
                    return Some("max_len is at most 1048576");
                }
                raw.pattern
                    .as_deref()
                    .filter(|p| crate::extract::compile_whole(p).is_none())
                    .map(|_| "pattern must be a regular expression of at most 256 bytes within the size limits")
            }
            Input::Json(json) => {
                if let Some(rule) = bounded(json.members.len()) {
                    return Some(rule);
                }
                if !unique_pointers(json.members.iter().map(|m| m.pointer.as_str())) {
                    return Some("member pointers must be unique");
                }
                for member in &json.members {
                    if tokens(&member.pointer).is_none() {
                        return Some("a member pointer is empty or starts with /");
                    }
                    let allowed = member.allowed();
                    if let Some(rule) = allowed.fault() {
                        return Some(rule);
                    }
                    if member.set.is_some()
                        && (!allowed.is_any() || member.kind.is_some() || member.optional)
                    {
                        return Some("a member the node sets has no other rule");
                    }
                    if member.offset.is_some() && member.set.is_none() {
                        return Some("offset needs set");
                    }
                    if member.set.is_some() && member.pointer.is_empty() {
                        return Some("the node sets a member, not the whole value");
                    }
                }
                None
            }
            Input::Rlp(rlp) => {
                if let Some(rule) = bounded(rlp.items.len()) {
                    return Some(rule);
                }
                if rlp
                    .prefix
                    .as_deref()
                    .is_some_and(|p| hex_bytes(p).is_none_or(|b| b.is_empty() || b.len() > 8))
                {
                    return Some("prefix is 1 to 8 bytes of hex");
                }
                if !unique_pointers(rlp.items.iter().map(|i| i.pointer.as_str())) {
                    return Some("item pointers must be unique");
                }
                for item in &rlp.items {
                    let index_ok = tokens(&item.pointer).is_some_and(|t| {
                        t.iter().all(|i| {
                            i.parse::<usize>().is_ok() && (i == "0" || !i.starts_with('0'))
                        })
                    });
                    if !index_ok {
                        return Some("an item pointer is a list of indexes, such as /3");
                    }
                    let hex_ok = item
                        .equals
                        .as_deref()
                        .is_none_or(|h| hex_bytes(h).is_some())
                        && item.one_of.iter().all(|h| hex_bytes(h).is_some());
                    if !hex_ok {
                        return Some("equals and one_of of an RLP item are hex");
                    }
                    let allowed = Allowed {
                        equals: item.equals.as_deref(),
                        one_of: &item.one_of,
                        pattern: None,
                        min: item.min.as_deref(),
                        max: item.max.as_deref(),
                    };
                    if let Some(rule) = allowed.fault() {
                        return Some(rule);
                    }
                    if item.min.as_deref().is_some_and(|m| m.starts_with('-')) {
                        return Some("an RLP integer is not negative");
                    }
                }
                None
            }
        }
    }

    /// Checks `input` and gives the bytes the templates read as `$input`.
    pub fn apply(&self, input: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        match self {
            Input::Raw(raw) => {
                if raw.max_len.is_some_and(|m| input.len() > m) {
                    return Err(invalid("input longer than the schema allows"));
                }
                if let Some(pattern) = &raw.pattern {
                    let ok =
                        crate::extract::compile_whole(pattern).is_some_and(|r| r.is_match(input));
                    if !ok {
                        return Err(invalid("input does not match the schema pattern"));
                    }
                }
                Ok(input.to_vec())
            }
            Input::Json(schema) => json::apply(schema, input, now_ms),
            Input::Rlp(schema) => rlp::apply(schema, input),
        }
    }

    /// The schema in words, for a summary.
    pub fn describe(&self) -> String {
        match self {
            Input::Raw(raw) => match (&raw.max_len, &raw.pattern) {
                (None, None) => "any bytes".into(),
                (max, pattern) => format!(
                    "bytes{}{}",
                    max.map(|m| format!(", at most {m}")).unwrap_or_default(),
                    pattern
                        .as_deref()
                        .map(|p| format!(", matching /{p}/"))
                        .unwrap_or_default()
                ),
            },
            Input::Json(json) => format!(
                "JSON with {}",
                json.members
                    .iter()
                    .map(|m| {
                        let rule = match m.set {
                            Some(time) => format!(
                                "set by the node to {}{}",
                                match time {
                                    NodeTime::Unix => "$unix",
                                    NodeTime::UnixMs => "$unix_ms",
                                },
                                m.offset.map(|o| format!(" + {o}")).unwrap_or_default()
                            ),
                            None => m.allowed().describe(),
                        };
                        format!("{:?} {rule}", m.pointer)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Input::Rlp(rlp) => format!(
                "RLP{} with {}",
                rlp.prefix
                    .as_deref()
                    .map(|p| format!(" after {p}"))
                    .unwrap_or_default(),
                rlp.items
                    .iter()
                    .map(|i| {
                        let rule = match (&i.equals, i.one_of.is_empty(), &i.min, &i.max) {
                            (Some(e), _, _, _) => format!("= {e}"),
                            (None, false, _, _) => format!("one of {:?}", i.one_of),
                            (None, true, None, None) => "any value".into(),
                            (None, true, min, max) => format!(
                                "from {} to {}",
                                min.as_deref().unwrap_or("0"),
                                max.as_deref().unwrap_or("any")
                            ),
                        };
                        format!("{:?} {rule}", i.pointer)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// True when some declared pointer is a prefix of `path` (the value lies at or under it).
fn covered(declared: &[Vec<String>], path: &[String]) -> bool {
    declared.iter().any(|d| path.starts_with(d))
}

/// True when `path` holds a declared pointer below it (an empty object, array or list there
/// is where optional members would be).
fn holds_declared(declared: &[Vec<String>], path: &[String]) -> bool {
    declared
        .iter()
        .any(|d| d.len() > path.len() && d.starts_with(path))
}

mod json {
    use super::*;

    /// A JSON value with numbers kept as written.
    enum Json {
        Null,
        Bool(bool),
        Num(String),
        Str(String),
        Arr(Vec<Json>),
        Obj(Vec<(String, Json)>),
    }

    struct Members;

    impl<'de> serde::de::Visitor<'de> for Members {
        type Value = Vec<(String, &'de RawValue)>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let mut out: Vec<(String, &'de RawValue)> = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                if out.iter().any(|(k, _)| *k == key) {
                    return Err(serde::de::Error::custom("duplicate member"));
                }
                let value = map.next_value::<&'de RawValue>()?;
                out.push((key, value));
            }
            Ok(out)
        }
    }

    fn parse(raw: &RawValue, depth: usize) -> Result<Json> {
        if depth > MAX_INPUT_DEPTH {
            return Err(invalid("input nested too deep"));
        }
        let bad = || invalid("input is not JSON, or holds a duplicate member");
        let text = raw.get().trim();
        Ok(match text.as_bytes().first() {
            Some(b'{') => {
                use serde::Deserializer as _;
                let mut de = serde_json::Deserializer::from_str(text);
                let members = de.deserialize_map(Members).map_err(|_| bad())?;
                Json::Obj(
                    members
                        .into_iter()
                        .map(|(k, v)| parse(v, depth + 1).map(|v| (k, v)))
                        .collect::<Result<_>>()?,
                )
            }
            Some(b'[') => {
                let items: Vec<&RawValue> = serde_json::from_str(text).map_err(|_| bad())?;
                Json::Arr(
                    items
                        .into_iter()
                        .map(|v| parse(v, depth + 1))
                        .collect::<Result<_>>()?,
                )
            }
            Some(b'"') => Json::Str(serde_json::from_str(text).map_err(|_| bad())?),
            _ if text == "true" => Json::Bool(true),
            _ if text == "false" => Json::Bool(false),
            _ if text == "null" => Json::Null,
            _ => Json::Num(text.to_string()),
        })
    }

    fn write(value: &Json, out: &mut String) -> Result<()> {
        match value {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => {
                out.push_str(&serde_json::to_string(s).map_err(|_| Error::Encoding)?);
            }
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out)?;
                }
                out.push(']');
            }
            Json::Obj(members) => {
                out.push('{');
                for (i, (key, item)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).map_err(|_| Error::Encoding)?);
                    out.push(':');
                    write(item, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    fn get<'v>(value: &'v Json, path: &[String]) -> Option<&'v Json> {
        let Some((first, rest)) = path.split_first() else {
            return Some(value);
        };
        let next = match value {
            Json::Obj(members) => members.iter().find(|(k, _)| k == first).map(|(_, v)| v),
            Json::Arr(items) => first
                .parse::<usize>()
                .ok()
                .filter(|_| first == "0" || !first.starts_with('0'))
                .and_then(|i| items.get(i)),
            _ => None,
        }?;
        get(next, rest)
    }

    /// Writes `number` at `path`, creating the last member when it is absent; its parent
    /// must be an object or array that exists.
    fn set(value: &mut Json, path: &[String], number: String) -> Result<()> {
        let missing = || invalid("the parent of a member the node sets is missing");
        let Some((first, rest)) = path.split_first() else {
            *value = Json::Num(number);
            return Ok(());
        };
        match value {
            Json::Obj(members) => {
                if let Some((_, v)) = members.iter_mut().find(|(k, _)| k == first) {
                    return set(v, rest, number);
                }
                if !rest.is_empty() {
                    return Err(missing());
                }
                members.push((first.clone(), Json::Num(number)));
                Ok(())
            }
            Json::Arr(items) => {
                let item = first
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| items.get_mut(i))
                    .ok_or_else(missing)?;
                set(item, rest, number)
            }
            _ => Err(missing()),
        }
    }

    /// Every value not at or under a declared pointer is refused: a scalar or an empty
    /// container outside the schema is a member the caller added.
    fn closed(value: &Json, path: &mut Vec<String>, declared: &[Vec<String>]) -> Result<()> {
        if covered(declared, path) {
            return Ok(());
        }
        let undeclared = || invalid("input holds a member the schema does not declare");
        match value {
            Json::Obj(members) if holds_declared(declared, path) => {
                for (key, item) in members {
                    path.push(key.clone());
                    closed(item, path, declared)?;
                    path.pop();
                }
                Ok(())
            }
            Json::Arr(items) if holds_declared(declared, path) => {
                for (i, item) in items.iter().enumerate() {
                    path.push(i.to_string());
                    closed(item, path, declared)?;
                    path.pop();
                }
                Ok(())
            }
            _ => Err(undeclared()),
        }
    }

    fn type_of(value: &Json) -> JsonType {
        match value {
            Json::Null => JsonType::Null,
            Json::Bool(_) => JsonType::Boolean,
            Json::Num(_) => JsonType::Number,
            Json::Str(_) => JsonType::String,
            Json::Arr(_) => JsonType::Array,
            Json::Obj(_) => JsonType::Object,
        }
    }

    fn text(value: &Json) -> Option<&str> {
        Some(match value {
            Json::Null => "null",
            Json::Bool(true) => "true",
            Json::Bool(false) => "false",
            Json::Num(n) => n,
            Json::Str(s) => s,
            Json::Arr(_) | Json::Obj(_) => return None,
        })
    }

    pub(super) fn apply(schema: &JsonInput, input: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        let raw: &RawValue = serde_json::from_slice(input)
            .map_err(|_| invalid("input is not JSON, or holds a duplicate member"))?;
        let mut value = parse(raw, 0)?;
        let mut declared = Vec::with_capacity(schema.members.len());
        for member in &schema.members {
            let path = tokens(&member.pointer).ok_or(invalid("member pointer"))?;
            if let Some(time) = member.set {
                let clock = match time {
                    NodeTime::Unix => i128::from(now_ms / 1000),
                    NodeTime::UnixMs => i128::from(now_ms),
                };
                let number = clock + i128::from(member.offset.unwrap_or(0));
                set(&mut value, &path, number.to_string())?;
            } else {
                match get(&value, &path) {
                    None if member.optional => {}
                    None => return Err(invalid("input lacks a member the schema requires")),
                    Some(found) => {
                        if member.kind.is_some_and(|k| k != type_of(found)) {
                            return Err(invalid("input member of the wrong type"));
                        }
                        let allowed = member.allowed();
                        if !allowed.is_any() {
                            let ok = text(found).is_some_and(|t| allowed.admits(t.as_bytes()));
                            if !ok {
                                return Err(invalid(
                                    "input member value not allowed by the schema",
                                ));
                            }
                        }
                    }
                }
            }
            declared.push(path);
        }
        closed(&value, &mut Vec::new(), &declared)?;
        let mut out = String::with_capacity(input.len() + 32);
        write(&value, &mut out)?;
        Ok(out.into_bytes())
    }
}

mod rlp {
    use super::*;

    enum Rlp<'a> {
        Bytes(&'a [u8]),
        List(Vec<Rlp<'a>>),
    }

    fn bad() -> Error {
        invalid("input is not canonical RLP")
    }

    /// A big-endian length of `n` bytes without leading zeros, at least 56.
    fn long_length(bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() || bytes.len() > 4 || bytes.first() == Some(&0) {
            return Err(bad());
        }
        let len = bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        if len < 56 { Err(bad()) } else { Ok(len) }
    }

    /// One item at the start of `bytes`, and the bytes after it.
    fn take(rest: &[u8], len: usize) -> Result<(&[u8], &[u8])> {
        if rest.len() < len {
            Err(bad())
        } else {
            Ok(rest.split_at(len))
        }
    }

    fn item(bytes: &[u8], depth: usize) -> Result<(Rlp<'_>, &[u8])> {
        if depth > MAX_INPUT_DEPTH {
            return Err(invalid("input nested too deep"));
        }
        let (&first, rest) = bytes.split_first().ok_or_else(bad)?;
        match first {
            0x00..=0x7f => Ok((Rlp::Bytes(bytes.get(..1).ok_or_else(bad)?), rest)),
            0x80..=0xb7 => {
                let (body, after) = take(rest, usize::from(first - 0x80))?;
                if body.len() == 1 && body.first().is_some_and(|b| *b < 0x80) {
                    return Err(bad());
                }
                Ok((Rlp::Bytes(body), after))
            }
            0xb8..=0xbf => {
                let (len_bytes, rest) = take(rest, usize::from(first - 0xb7))?;
                let (body, after) = take(rest, long_length(len_bytes)?)?;
                Ok((Rlp::Bytes(body), after))
            }
            0xc0..=0xf7 => {
                let (body, after) = take(rest, usize::from(first - 0xc0))?;
                Ok((Rlp::List(list(body, depth)?), after))
            }
            0xf8..=0xff => {
                let (len_bytes, rest) = take(rest, usize::from(first - 0xf7))?;
                let (body, after) = take(rest, long_length(len_bytes)?)?;
                Ok((Rlp::List(list(body, depth)?), after))
            }
        }
    }

    fn list(mut body: &[u8], depth: usize) -> Result<Vec<Rlp<'_>>> {
        let mut out = Vec::new();
        while !body.is_empty() {
            let (one, rest) = item(body, depth + 1)?;
            out.push(one);
            body = rest;
        }
        Ok(out)
    }

    fn get<'v, 'a>(value: &'v Rlp<'a>, path: &[String]) -> Option<&'v Rlp<'a>> {
        let Some((first, rest)) = path.split_first() else {
            return Some(value);
        };
        match value {
            Rlp::List(items) => get(items.get(first.parse::<usize>().ok()?)?, rest),
            Rlp::Bytes(_) => None,
        }
    }

    fn closed(value: &Rlp<'_>, path: &mut Vec<String>, declared: &[Vec<String>]) -> Result<()> {
        if covered(declared, path) {
            return Ok(());
        }
        match value {
            Rlp::List(items) if holds_declared(declared, path) => {
                for (i, one) in items.iter().enumerate() {
                    path.push(i.to_string());
                    closed(one, path, declared)?;
                    path.pop();
                }
                Ok(())
            }
            _ => Err(invalid("input holds an item the schema does not declare")),
        }
    }

    /// The decimal digits of a big-endian unsigned integer.
    fn decimal(bytes: &[u8]) -> String {
        let mut number: Vec<u8> = bytes.to_vec();
        let mut digits = Vec::new();
        while number.iter().any(|b| *b != 0) {
            let mut remainder = 0u16;
            for byte in number.iter_mut() {
                let current = (remainder << 8) | u16::from(*byte);
                *byte = u8::try_from(current / 10).unwrap_or(0);
                remainder = current % 10;
            }
            digits.push(b'0' + u8::try_from(remainder).unwrap_or(0));
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        String::from_utf8(digits).unwrap_or_default()
    }

    pub(super) fn apply(schema: &RlpInput, input: &[u8]) -> Result<Vec<u8>> {
        let prefix = schema
            .prefix
            .as_deref()
            .map(|p| hex_bytes(p).ok_or(invalid("prefix")))
            .transpose()?
            .unwrap_or_default();
        let body = input
            .strip_prefix(prefix.as_slice())
            .ok_or(invalid("input does not start with the schema prefix"))?;
        let (value, rest) = item(body, 0)?;
        if !rest.is_empty() {
            return Err(bad());
        }
        let mut declared = Vec::with_capacity(schema.items.len());
        for rule in &schema.items {
            let path = tokens(&rule.pointer).ok_or(invalid("item pointer"))?;
            match get(&value, &path) {
                None if rule.optional => {}
                None => return Err(invalid("input lacks an item the schema requires")),
                Some(Rlp::List(_))
                    if rule.equals.is_some()
                        || !rule.one_of.is_empty()
                        || rule.min.is_some()
                        || rule.max.is_some() =>
                {
                    return Err(invalid("input item is a list where the schema wants bytes"));
                }
                Some(Rlp::List(_)) => {}
                Some(Rlp::Bytes(bytes)) => {
                    let hex = |h: &String| hex_bytes(h).is_some_and(|v| v == *bytes);
                    let fixed_ok = rule.equals.as_ref().is_none_or(hex)
                        && (rule.one_of.is_empty() || rule.one_of.iter().any(hex));
                    let bounded = rule.min.is_some() || rule.max.is_some();
                    let number_ok = !bounded
                        || (bytes.first() != Some(&0) && {
                            let n = decimal(bytes);
                            rule.min
                                .as_deref()
                                .is_none_or(|m| compare_decimal(&n, m) != core::cmp::Ordering::Less)
                                && rule.max.as_deref().is_none_or(|m| {
                                    compare_decimal(&n, m) != core::cmp::Ordering::Greater
                                })
                        });
                    if !fixed_ok || !number_ok {
                        return Err(invalid("input item value not allowed by the schema"));
                    }
                }
            }
            declared.push(path);
        }
        closed(&value, &mut Vec::new(), &declared)?;
        Ok(input.to_vec())
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use super::*;

        #[test]
        fn integers_read_as_decimal() {
            assert_eq!(decimal(&[]), "0");
            assert_eq!(decimal(&[0x01, 0x00]), "256");
            // 1000 ETH in wei.
            assert_eq!(
                decimal(&[0x36, 0x35, 0xc9, 0xad, 0xc5, 0xde, 0xa0, 0x00, 0x00]),
                "1000000000000000000000"
            );
        }

        #[test]
        fn only_canonical_rlp_reads() {
            for bad in [
                &[0x81, 0x05][..],   // a single byte below 0x80 with a length
                &[0xb8, 0x01, 0x00], // a long form for a short string
                &[0x82, 0x00],       // shorter than its length
                &[0xc1, 0x01, 0x02], // bytes after the list
            ] {
                let whole = item(bad, 0).map(|(_, rest)| rest.is_empty());
                assert!(!matches!(whole, Ok(true)), "{bad:02x?}");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn schema() -> Input {
        Input::Json(JsonInput {
            members: vec![
                Member::equals("/aud", "https://api.example.com"),
                Member {
                    pointer: "/scope".into(),
                    one_of: vec!["read".into(), "write".into()],
                    ..Member::default()
                },
                Member {
                    pointer: "/amount".into(),
                    min: Some("1".into()),
                    max: Some("100000".into()),
                    kind: Some(JsonType::Number),
                    ..Member::default()
                },
                Member::time("/exp", NodeTime::Unix, 300),
                Member::any("/note").optional(),
            ],
        })
    }

    #[test]
    fn json_inputs_follow_the_schema() {
        let s = schema();
        assert_eq!(s.fault(), None);
        let out = s
            .apply(
                br#"{"aud":"https://api.example.com","scope":"read","amount":250,"note":{"x":[1]},"exp":99999999999}"#,
                1_800_000_000_000,
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"aud":"https://api.example.com","scope":"read","amount":250,"note":{"x":[1]},"exp":1800000300}"#
        );
        for (input, rule) in [
            (
                r#"{"aud":"https://evil.example","scope":"read","amount":1}"#,
                "input member value not allowed by the schema",
            ),
            (
                r#"{"aud":"https://api.example.com","scope":"admin","amount":1}"#,
                "input member value not allowed by the schema",
            ),
            (
                r#"{"aud":"https://api.example.com","scope":"read","amount":100001}"#,
                "input member value not allowed by the schema",
            ),
            (
                r#"{"aud":"https://api.example.com","scope":"read","amount":"5"}"#,
                "input member of the wrong type",
            ),
            (
                r#"{"aud":"https://api.example.com","scope":"read","amount":5,"admin":true}"#,
                "input holds a member the schema does not declare",
            ),
            (
                r#"{"aud":"https://api.example.com","scope":"read"}"#,
                "input lacks a member the schema requires",
            ),
            (
                r#"{"aud":"https://api.example.com","aud":"https://evil.example","scope":"read","amount":1}"#,
                "input is not JSON, or holds a duplicate member",
            ),
        ] {
            assert_eq!(
                s.apply(input.as_bytes(), 0),
                Err(Error::InputInvalid { rule }),
                "{input}"
            );
        }
    }

    #[test]
    fn large_numbers_keep_their_digits() {
        let s = Input::Json(JsonInput {
            members: vec![Member {
                pointer: "/wei".into(),
                max: Some("1000000000000000000".into()),
                ..Member::default()
            }],
        });
        assert_eq!(
            s.apply(br#"{"wei":999999999999999999}"#, 0).unwrap(),
            br#"{"wei":999999999999999999}"#
        );
        assert!(s.apply(br#"{"wei":1000000000000000000000}"#, 0).is_err());
        assert!(s.apply(br#"{"wei":1e30}"#, 0).is_err());
    }

    #[test]
    fn schemas_are_checked() {
        let both = Input::Json(JsonInput {
            members: vec![Member {
                pointer: "/a".into(),
                equals: Some("x".into()),
                pattern: Some("x".into()),
                ..Member::default()
            }],
        });
        assert!(both.fault().is_some());
        let set_and_rule = Input::Json(JsonInput {
            members: vec![Member {
                equals: Some("1".into()),
                ..Member::time("/iat", NodeTime::Unix, 0)
            }],
        });
        assert!(set_and_rule.fault().is_some());
        let rlp = Input::Rlp(RlpInput {
            prefix: Some("0g".into()),
            items: vec![],
        });
        assert!(rlp.fault().is_some());
        assert_eq!(Input::any().fault(), None);
    }
}
