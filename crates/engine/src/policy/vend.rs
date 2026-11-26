//! Credential vending: an operation that mints a scoped, short-lived credential from the
//! long-lived secret and hands back only that (`docs/design.md`, section 8b).
//!
//! An operation with a [`Vend`] says how long what it hands back may stay valid, and where the
//! node reads when it ends. The node checks that before anything goes back:
//!
//! - over HTTPS, the expiry is read from the last response (a capture source and a time
//!   format); a response whose credential is valid longer than `lifetime_ms` from now, or
//!   whose expiry cannot be read, is refused and nothing of it goes back;
//! - with no connection (a token the node signs itself), the expiry is a member of the
//!   checked JSON input the node sets to its clock, and the policy check proves the offset is
//!   within `lifetime_ms`.
//!
//! The policy fixes the scope: a vending operation over HTTPS sends only requests the policy
//! fixes (the caller chooses no path, parameter, body or duration), and returns only declared
//! JSON members; one with no connection takes a closed JSON input.

use serde::{Deserialize, Serialize};

use super::{
    BodyProjection, Checked, Connection, Input, NodeTime, Operation, Source, ensure, fail,
};
use crate::template::{Template, Var};

/// Longest lifetime a vending operation may give: 12 hours.
pub const MAX_VEND_MS: u64 = 12 * 60 * 60 * 1000;
/// How much later than `now + lifetime_ms` a site's expiry may be, for the clocks of the site
/// and the node: one minute.
pub const VEND_SKEW_MS: u64 = 60 * 1000;

/// How a time is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    /// Unix seconds, a decimal integer.
    Unix,
    /// Unix milliseconds, a decimal integer.
    UnixMs,
    /// RFC 3339 (`2026-11-26T12:00:00Z`, `2026-11-26T21:00:00.5+09:00`).
    Rfc3339,
    /// Seconds from now, a decimal integer (`expires_in`).
    Seconds,
}

impl TimeFormat {
    /// The name in JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            TimeFormat::Unix => "unix",
            TimeFormat::UnixMs => "unix_ms",
            TimeFormat::Rfc3339 => "rfc3339",
            TimeFormat::Seconds => "seconds",
        }
    }
}

/// Where the node reads when the vended credential ends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expiry {
    /// HTTPS: read from the last response, as a capture reads (not `all`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// No connection: the JSON pointer of an input member the node sets (`set`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// How the value is written. For `input`, the unit of its `set`: `unix` or `unix_ms`.
    pub format: TimeFormat,
}

/// What a vending operation hands back, and for how long.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vend {
    /// The longest the credential may stay valid from when the node hands it back, in
    /// milliseconds: 1 second to [`MAX_VEND_MS`].
    pub lifetime_ms: u64,
    /// Where its expiry is read.
    pub expires: Expiry,
}

impl Vend {
    /// True when `other` gives the caller no longer credential than `self`, read the same way.
    pub fn covers(&self, other: &Vend) -> bool {
        self.expires == other.expires && other.lifetime_ms <= self.lifetime_ms
    }

    /// Where the expiry is read, in words.
    pub fn describe(&self) -> String {
        match (&self.expires.source, &self.expires.input) {
            (Some(source), _) => format!(
                "the response ({}, {})",
                serde_json::to_string(source).unwrap_or_default(),
                self.expires.format.as_str()
            ),
            (None, Some(pointer)) => format!(
                "the input member {pointer} the node sets ({})",
                self.expires.format.as_str()
            ),
            (None, None) => "nowhere".into(),
        }
    }
}

/// Checks a vending operation when its policy is signed.
pub(super) fn check(at: &str, operation: &Operation, vend: &Vend) -> Checked {
    ensure(
        (1000..=MAX_VEND_MS).contains(&vend.lifetime_ms),
        || format!("{at}.lifetime_ms"),
        "a vended credential lives 1 second to 12 hours",
    )?;
    let expires = &vend.expires;
    match operation.connection() {
        Some(Connection::Https) => {
            ensure(
                !operation.takes_request(),
                || at.to_string(),
                "a vending operation sends only requests the policy fixes: the caller chooses no scope or lifetime",
            )?;
            ensure(
                expires.input.is_none()
                    && expires
                        .source
                        .as_ref()
                        .is_some_and(|s| !matches!(s, Source::All)),
                || format!("{at}.expires"),
                "over HTTPS the expiry is read from the response by a capture source (not all)",
            )?;
            let projects_json = operation
                .returns()
                .and_then(|r| r.response.as_ref())
                .is_some_and(|p| matches!(p.body, Some(BodyProjection::Json(_))));
            ensure(
                projects_json,
                || at.to_string(),
                "a vending operation returns declared JSON members of the response, not the whole body",
            )
        }
        None => {
            let (None, Some(pointer)) = (&expires.source, &expires.input) else {
                return fail(
                    format!("{at}.expires"),
                    "with no connection the expiry is an input member the node sets",
                );
            };
            let unit_ms: i128 = match expires.format {
                TimeFormat::Unix => 1000,
                TimeFormat::UnixMs => 1,
                TimeFormat::Rfc3339 | TimeFormat::Seconds => {
                    return fail(
                        format!("{at}.expires.format"),
                        "an input member the node sets is unix or unix_ms",
                    );
                }
            };
            let member = match &operation.input {
                Some(Input::Json(schema)) => schema.members.iter().find(|m| m.pointer == *pointer),
                _ => None,
            };
            let Some(member) = member else {
                return fail(
                    format!("{at}.expires.input"),
                    "the expiry is a member of the operation's JSON input",
                );
            };
            let unit_matches = matches!(
                (member.set, expires.format),
                (Some(NodeTime::Unix), TimeFormat::Unix)
                    | (Some(NodeTime::UnixMs), TimeFormat::UnixMs)
            );
            let offset_ms = i128::from(member.offset.unwrap_or(0)) * unit_ms;
            ensure(
                unit_matches && offset_ms <= i128::from(vend.lifetime_ms),
                || format!("{at}.expires.input"),
                "the expiry member is set by the node, in the format's unit, at most lifetime_ms ahead",
            )?;
            let reads_input = operation
                .returns()
                .and_then(|r| r.template.as_deref())
                .and_then(|t| Template::parse(t).ok())
                .is_some_and(|t| t.vars().contains(&Var::Input));
            ensure(
                reads_input,
                || at.to_string(),
                "the output of a vending derivation is made from the checked input that holds the expiry",
            )
        }
        Some(_) => fail(
            at.to_string(),
            "a vending operation is HTTPS or has no connection",
        ),
    }
}

const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1970-01-01 to the civil date (proleptic Gregorian), for any year 0 to 9999.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn digits(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0i64, |n, b| {
        n.checked_mul(10)?.checked_add(i64::from(b - b'0'))
    })
}

/// An RFC 3339 date-time (section 5.6) as Unix milliseconds: `YYYY-MM-DDTHH:MM:SS`, an
/// optional fraction (up to 9 digits, read to the millisecond, cut down), and `Z` or an offset
/// `±HH:MM`. `T` and `Z` may be lower case. Leap seconds (`:60`) are refused. `None` for
/// anything else, or a time before 1970.
pub fn parse_rfc3339(text: &[u8]) -> Option<u64> {
    let date = text.get(..10)?;
    let rest = text.get(10..)?;
    if date.get(4) != Some(&b'-') || date.get(7) != Some(&b'-') {
        return None;
    }
    let year = digits(date.get(..4)?)?;
    let month = digits(date.get(5..7)?)?;
    let day = digits(date.get(8..10)?)?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let (sep, rest) = rest.split_first()?;
    if !matches!(sep, b'T' | b't') {
        return None;
    }
    let clock = rest.get(..8)?;
    let mut rest = rest.get(8..)?;
    if clock.get(2) != Some(&b':') || clock.get(5) != Some(&b':') {
        return None;
    }
    let hour = digits(clock.get(..2)?)?;
    let minute = digits(clock.get(3..5)?)?;
    let second = digits(clock.get(6..8)?)?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut millis = 0i64;
    if let Some(after) = rest.strip_prefix(b".") {
        let n = after.iter().take_while(|b| b.is_ascii_digit()).count();
        if n == 0 || n > 9 {
            return None;
        }
        let fraction = after.get(..n)?;
        for (i, b) in fraction.iter().take(3).enumerate() {
            let scale = [100, 10, 1].get(i).copied()?;
            millis += i64::from(b - b'0') * scale;
        }
        rest = after.get(n..)?;
    }
    let offset_min = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let h = digits(&[*h1, *h2])?;
            let m = digits(&[*m1, *m2])?;
            if h > 23 || m > 59 {
                return None;
            }
            let total = h * 60 + m;
            if *sign == b'-' { -total } else { total }
        }
        _ => return None,
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
        - offset_min * 60;
    let ms = seconds.checked_mul(1000)?.checked_add(millis)?;
    u64::try_from(ms).ok()
}

/// The time a captured value names, as Unix milliseconds, with `now_ms` for relative
/// formats. `None` when it is not one of the format.
pub fn parse_time(value: &[u8], format: TimeFormat, now_ms: u64) -> Option<u64> {
    let integer = || -> Option<u64> {
        if value.len() > 20 || (value.len() > 1 && value.first() == Some(&b'0')) {
            return None;
        }
        u64::try_from(digits(value)?).ok()
    };
    match format {
        TimeFormat::Unix => integer()?.checked_mul(1000),
        TimeFormat::UnixMs => integer(),
        TimeFormat::Seconds => now_ms.checked_add(integer()?.checked_mul(1000)?),
        TimeFormat::Rfc3339 => parse_rfc3339(value),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_reads_the_forms_of_the_standard() {
        assert_eq!(parse_rfc3339(b"1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339(b"2026-11-26T12:00:00Z"),
            Some(1_795_694_400_000)
        );
        assert_eq!(
            parse_rfc3339(b"2026-11-26T21:00:00+09:00"),
            parse_rfc3339(b"2026-11-26T12:00:00Z")
        );
        assert_eq!(
            parse_rfc3339(b"2026-11-26t12:00:00.123456z"),
            Some(1_795_694_400_123)
        );
        assert_eq!(
            parse_rfc3339(b"2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
        for bad in [
            &b"2023-02-29T00:00:00Z"[..],
            b"2026-13-01T00:00:00Z",
            b"2026-11-26T24:00:00Z",
            b"2026-11-26T23:59:60Z",
            b"2026-11-26 12:00:00Z",
            b"2026-11-26T12:00:00",
            b"2026-11-26T12:00:00.Z",
            b"2026-11-26T12:00:00.1234567890Z",
            b"2026-11-26T12:00:00+0900",
            b"1969-12-31T23:59:59Z",
            b"+2026-11-26T12:00:00Z",
            b"",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn integers_are_plain_decimals() {
        assert_eq!(
            parse_time(b"1700000000", TimeFormat::Unix, 0),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_time(b"3600", TimeFormat::Seconds, 5), Some(3_600_005));
        assert_eq!(parse_time(b"5", TimeFormat::UnixMs, 0), Some(5));
        for bad in [
            &b"012"[..],
            b"-1",
            b"1.5",
            b"1e3",
            b" 1",
            b"",
            b"99999999999999999999999",
        ] {
            assert_eq!(parse_time(bad, TimeFormat::Unix, 0), None);
        }
        assert_eq!(
            parse_time(b"18446744073709551615", TimeFormat::Unix, 0),
            None
        );
    }
}
