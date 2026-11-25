//! The checks of item values. Each returns the rule that failed.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};

use super::Check;
use crate::policy::Destination;

/// The sign-off an `http://` origin needs.
pub(super) const PLAIN_HTTP: &str = "plain_http";

type Rule = core::result::Result<(), &'static str>;

/// A card brand, from the issuer identification number (IIN) ranges of ISO/IEC 7812 as the
/// networks publish them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Brand {
    /// IIN 34, 37: 15 digits, a 4-digit code.
    Amex,
    /// IIN 300–305, 36, 38, 39.
    Diners,
    /// IIN 6011, 644–649, 65.
    Discover,
    /// IIN 3528–3589.
    Jcb,
    /// IIN 51–55, 2221–2720.
    Mastercard,
    /// IIN 2200–2204.
    Mir,
    /// IIN 62.
    Unionpay,
    /// IIN 4.
    Visa,
    /// Any other range.
    Unknown,
}

impl Brand {
    /// The name shown in a masked card number.
    pub fn as_str(self) -> &'static str {
        match self {
            Brand::Amex => "amex",
            Brand::Diners => "diners",
            Brand::Discover => "discover",
            Brand::Jcb => "jcb",
            Brand::Mastercard => "mastercard",
            Brand::Mir => "mir",
            Brand::Unionpay => "unionpay",
            Brand::Visa => "visa",
            Brand::Unknown => "card",
        }
    }

    /// The lengths of its security code.
    fn cvc_lengths(self) -> &'static [usize] {
        match self {
            Brand::Amex => &[4],
            Brand::Unknown => &[3, 4],
            _ => &[3],
        }
    }
}

/// The leading `n` digits of a number, as an integer.
fn prefix(digits: &[u8], n: usize) -> Option<u32> {
    let head = digits.get(..n)?;
    head.iter().try_fold(0u32, |acc, d| {
        d.is_ascii_digit().then(|| acc * 10 + u32::from(d - b'0'))
    })
}

/// The brand of a card number by its IIN range.
pub fn brand_of(number: &[u8]) -> Brand {
    let in_range =
        |n: usize, lo: u32, hi: u32| prefix(number, n).is_some_and(|p| (lo..=hi).contains(&p));
    if in_range(2, 34, 34) || in_range(2, 37, 37) {
        Brand::Amex
    } else if in_range(3, 300, 305) || in_range(2, 36, 36) || in_range(2, 38, 39) {
        Brand::Diners
    } else if in_range(4, 6011, 6011) || in_range(3, 644, 649) || in_range(2, 65, 65) {
        Brand::Discover
    } else if in_range(4, 3528, 3589) {
        Brand::Jcb
    } else if in_range(2, 51, 55) || in_range(4, 2221, 2720) {
        Brand::Mastercard
    } else if in_range(4, 2200, 2204) {
        Brand::Mir
    } else if in_range(2, 62, 62) {
        Brand::Unionpay
    } else if in_range(1, 4, 4) {
        Brand::Visa
    } else {
        Brand::Unknown
    }
}

fn all_digits(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(u8::is_ascii_digit)
}

fn luhn(value: &[u8]) -> Rule {
    if !(12..=19).contains(&value.len()) || !all_digits(value) {
        return Err("a card number is 12 to 19 digits");
    }
    let mut sum = 0u32;
    for (i, d) in value.iter().rev().enumerate() {
        let mut d = u32::from(d - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    if sum.is_multiple_of(10) {
        Ok(())
    } else {
        Err("the Luhn checksum does not hold")
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i64::from(month);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn number(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `MM/YY` or `MM/YYYY`: the month and the full year.
pub(super) fn expiry_parts(value: &[u8]) -> Option<(u32, u32)> {
    let text = core::str::from_utf8(value).ok()?;
    let (month, year) = text.split_once('/')?;
    if month.len() != 2 || !(year.len() == 2 || year.len() == 4) {
        return None;
    }
    let month = number(month).filter(|m| (1..=12).contains(m))?;
    let year = number(year)?;
    let year = if year < 100 { 2000 + year } else { year };
    Some((month, year))
}

fn expiry(value: &[u8], now_ms: Option<u64>) -> Rule {
    let (month, year) = expiry_parts(value).ok_or("an expiry is MM/YY or MM/YYYY")?;
    let Some(now_ms) = now_ms else {
        return Ok(());
    };
    // The card is valid through the last day of its month: it ends when the next month
    // starts (UTC; a day of margin either way would be a policy, not a check).
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let end_days = days_from_civil(i64::from(next_year), next_month, 1);
    let now_days = i64::try_from(now_ms / 86_400_000).unwrap_or(i64::MAX);
    if now_days < end_days {
        Ok(())
    } else {
        Err("the card has expired")
    }
}

fn date(value: &[u8]) -> Rule {
    let fail = "a date is YYYY-MM-DD";
    let text = core::str::from_utf8(value).map_err(|_| fail)?;
    let mut parts = text.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(fail);
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(fail);
    }
    let (Some(y), Some(m), Some(d)) = (number(y), number(m), number(d)) else {
        return Err(fail);
    };
    if (1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m) {
        Ok(())
    } else {
        Err("no such calendar date")
    }
}

/// An exact origin: whether it is `https`, and its host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// True for `https`, false for `http`.
    pub https: bool,
    /// The host and port (443 or 80 by default).
    pub destination: Destination,
}

impl Origin {
    /// `scheme://host[:port]`, with the port only when it is not the default.
    pub fn text(&self) -> String {
        let (scheme, default) = if self.https {
            ("https", 443)
        } else {
            ("http", 80)
        };
        if self.destination.port == default {
            format!("{scheme}://{}", self.destination.host)
        } else {
            format!(
                "{scheme}://{}:{}",
                self.destination.host, self.destination.port
            )
        }
    }
}

/// Reads `https://host[:port]` (or `http://`): a lowercase host name, a port of 1 to 65535
/// without leading zeros, and nothing else: no user, path, query or fragment.
pub fn parse_origin(text: &str) -> Option<Origin> {
    let (https, rest) = match text.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix("http://")?),
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => {
            if port.starts_with('0') {
                return None;
            }
            (host, number(port).and_then(|p| u16::try_from(p).ok())?)
        }
        None => (rest, if https { 443 } else { 80 }),
    };
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let destination = Destination::new(host, port);
    destination
        .is_concrete()
        .then_some(Origin { https, destination })
}

fn host(value: &[u8]) -> Rule {
    let text = core::str::from_utf8(value).map_err(|_| "not a host name")?;
    let ok =
        !text.bytes().any(|b| b.is_ascii_uppercase()) && Destination::new(text, 1).is_concrete();
    if ok {
        Ok(())
    } else {
        Err("a lowercase host name")
    }
}

fn integer(value: &[u8], min: u64, max: u64) -> Rule {
    let fail = "a decimal integer within bounds, without leading zeros";
    if !all_digits(value) || (value.len() > 1 && value.first() == Some(&b'0')) {
        return Err(fail);
    }
    let n: u64 = core::str::from_utf8(value)
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or(fail)?;
    if (min..=max).contains(&n) {
        Ok(())
    } else {
        Err(fail)
    }
}

fn email(value: &[u8]) -> Rule {
    let fail = "an e-mail address with a lowercase host name";
    let text = core::str::from_utf8(value).map_err(|_| fail)?;
    let (local, domain) = text.rsplit_once('@').ok_or(fail)?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"@<>()[]\\,;:\"".contains(&b));
    if local_ok && domain.contains('.') && host(domain.as_bytes()).is_ok() {
        Ok(())
    } else {
        Err(fail)
    }
}

fn base32(value: &[u8], min_bits: u32) -> Rule {
    let fail = "base32 of enough bits";
    let mut bits = 0u32;
    for b in value {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7' => bits = bits.saturating_add(5),
            b' ' | b'=' => {}
            _ => return Err(fail),
        }
    }
    // Trailing bits that do not fill a byte carry nothing.
    let bits = bits - bits % 8;
    if bits >= min_bits { Ok(()) } else { Err(fail) }
}

fn base64_key(value: &[u8], bytes: usize) -> Rule {
    let decoded = STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .map_err(|_| "standard base64")?;
    if decoded.len() == bytes {
        Ok(())
    } else {
        Err("a key of the wrong length")
    }
}

/// Reads one SSH string (u32 length, bytes) from the front of `blob`.
fn ssh_string(blob: &[u8]) -> Option<&[u8]> {
    let len: [u8; 4] = blob.get(..4)?.try_into().ok()?;
    let len = usize::try_from(u32::from_be_bytes(len)).ok()?;
    blob.get(4..4usize.checked_add(len)?)
}

/// The algorithms of a host key, with the type its key blob names.
const HOST_KEY_ALGORITHMS: [(&str, &str); 9] = [
    ("ssh-ed25519", "ssh-ed25519"),
    ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
    ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"),
    ("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"),
    ("rsa-sha2-256", "ssh-rsa"),
    ("rsa-sha2-512", "ssh-rsa"),
    ("ssh-rsa", "ssh-rsa"),
    ("sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519@openssh.com"),
    (
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ),
];

fn ssh_host_key(value: &[u8]) -> Rule {
    let fail = "an SSH host key (algorithm and base64 key blob) or a SHA256: fingerprint";
    let text = core::str::from_utf8(value).map_err(|_| fail)?;
    if let Some(fingerprint) = text.strip_prefix("SHA256:") {
        let digest = STANDARD_NO_PAD.decode(fingerprint).map_err(|_| fail)?;
        return if digest.len() == 32 {
            Ok(())
        } else {
            Err(fail)
        };
    }
    let mut parts = text.split(' ');
    let (Some(algorithm), Some(blob)) = (parts.next(), parts.next()) else {
        return Err(fail);
    };
    let blob_type = HOST_KEY_ALGORITHMS
        .iter()
        .find(|(a, _)| *a == algorithm)
        .map(|(_, t)| *t)
        .ok_or("an SSH host key algorithm of the standard")?;
    let blob = STANDARD.decode(blob).map_err(|_| fail)?;
    match ssh_string(&blob) {
        Some(named) if named == blob_type.as_bytes() => {}
        _ => return Err("the key blob names another algorithm"),
    }
    if blob_type == "ssh-ed25519" {
        // The type, then one string of exactly 32 bytes.
        let key = blob
            .get(4 + blob_type.len()..)
            .and_then(|rest| ssh_string(rest).map(|k| (k.len(), rest.len())));
        if key != Some((32, 36)) {
            return Err("an Ed25519 host key is 32 bytes");
        }
    }
    Ok(())
}

/// Runs one check on a value.
pub(super) fn run(
    check: &Check,
    value: &[u8],
    signoff: &[String],
    now_ms: Option<u64>,
    other: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Rule {
    let text = core::str::from_utf8(value).ok();
    match check {
        Check::Luhn {} => luhn(value),
        Check::Expiry {} => expiry(value, now_ms),
        Check::Cvc { number } => {
            let number = other(number).ok_or("a security code needs its card number")?;
            if all_digits(value) && brand_of(&number).cvc_lengths().contains(&value.len()) {
                Ok(())
            } else {
                Err("a security code of the length of the card's brand")
            }
        }
        Check::Origin {} => {
            let origin = text
                .and_then(parse_origin)
                .ok_or("an exact origin: https://host or https://host:port")?;
            if origin.https || signoff.iter().any(|s| s == PLAIN_HTTP) {
                Ok(())
            } else {
                Err("an http origin needs the sign-off plain_http")
            }
        }
        Check::Host {} => host(value),
        Check::Integer { min, max } => integer(value, *min, *max),
        Check::Length { min, max } => {
            if (*min..=*max).contains(&value.len()) {
                Ok(())
            } else {
                Err("a length within bounds")
            }
        }
        Check::Pattern { regex } => match crate::extract::compile_whole(regex) {
            Some(re) if re.is_match(value) => Ok(()),
            _ => Err("the value does not match the pattern"),
        },
        Check::OneOf { values } => {
            if text.is_some_and(|t| values.iter().any(|v| v == t)) {
                Ok(())
            } else {
                Err("not one of the allowed values")
            }
        }
        Check::Email {} => email(value),
        Check::Date {} => date(value),
        Check::Base32 { min_bits } => base32(value, *min_bits),
        Check::Base64Key { bytes } => base64_key(value, *bytes),
        Check::SshHostKey {} => ssh_host_key(value),
        Check::Signoff { values, flag } => {
            let needs = text.is_some_and(|t| values.iter().any(|v| v == t));
            if !needs || signoff.iter().any(|s| s == flag) {
                Ok(())
            } else {
                Err("this value needs the owner's sign-off")
            }
        }
    }
}
