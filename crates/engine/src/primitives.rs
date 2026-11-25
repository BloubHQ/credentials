//! The functions of the template language.
//!
//! Every function that builds a buffer from secret bytes sizes it before it writes, so no
//! reallocation leaves an unzeroized copy of a secret on the heap.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::template::{Budget, Bytes, Func};
use crate::{Error, Result, totp};

/// Most PBKDF2 iterations of one call.
pub const MAX_PBKDF2_ROUNDS: u64 = 1_000_000;

const HEX: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn bad(rule: &'static str) -> Error {
    Error::TemplateInvalid { rule }
}

pub(crate) fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn b64<E: Engine>(engine: &E, input: &[u8]) -> Result<Bytes> {
    let len = base64::encoded_len(input.len(), true).ok_or(Error::Encoding)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let written = engine
        .encode_slice(input, out.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    out.truncate(written);
    Ok(out)
}

pub(crate) fn pct(input: &[u8]) -> Bytes {
    let len = input
        .iter()
        .map(|b| if is_unreserved(*b) { 1 } else { 3 })
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for &b in input {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.extend(HEX_UPPER.get(usize::from(b >> 4)));
            out.extend(HEX_UPPER.get(usize::from(b & 0x0f)));
        }
    }
    out
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Encoding),
    }
}

pub(crate) fn pct_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    let mut iter = input.iter();
    while let Some(&b) = iter.next() {
        if b == b'%' {
            let hi = hex_digit(*iter.next().ok_or(Error::Encoding)?)?;
            let lo = hex_digit(*iter.next().ok_or(Error::Encoding)?)?;
            out.push(hi * 16 + lo);
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

fn json_escaped_len(b: u8) -> usize {
    match b {
        b'"' | b'\\' | b'\n' | b'\r' | b'\t' => 2,
        0..=0x1f => 6,
        _ => 1,
    }
}

pub(crate) fn json_escape(input: &[u8]) -> Bytes {
    let len = input.iter().map(|b| json_escaped_len(*b)).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for &b in input {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.extend(HEX.get(usize::from(b >> 4)));
                out.extend(HEX.get(usize::from(b & 0x0f)));
            }
            _ => out.push(b),
        }
    }
    out
}

pub(crate) fn hex(input: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 2));
    for &b in input {
        out.extend(HEX.get(usize::from(b >> 4)));
        out.extend(HEX.get(usize::from(b & 0x0f)));
    }
    out
}

fn hex_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() / 2));
    for pair in input.chunks(2) {
        let [hi, lo] = pair else {
            return Err(Error::Encoding);
        };
        out.push(hex_digit(*hi)? * 16 + hex_digit(*lo)?);
    }
    Ok(out)
}

fn b32_decode(input: &[u8]) -> Result<Bytes> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8 + 1));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for &c in input {
        let v = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            b'=' | b'-' => continue,
            c if c.is_ascii_whitespace() => continue,
            _ => return Err(Error::Encoding),
        };
        buffer = ((buffer << 5) | u64::from(v)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).map_err(|_| Error::Encoding)?);
        }
    }
    buffer.zeroize();
    Ok(out)
}

/// Base64 in either alphabet, padding optional, whitespace ignored. Trailing bits that are
/// not zero are accepted.
fn b64_decode(input: &[u8]) -> Result<Bytes> {
    let keep = |b: &&u8| !b.is_ascii_whitespace() && **b != b'=';
    let mut text = Zeroizing::new(Vec::with_capacity(input.iter().filter(keep).count()));
    text.extend(input.iter().filter(keep));
    let url = text.iter().any(|b| *b == b'-' || *b == b'_');
    let engine = if url {
        base64::engine::GeneralPurpose::new(
            &base64::alphabet::URL_SAFE,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
        )
    } else {
        base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true)
                .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
        )
    };
    let mut out = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(text.len())]);
    let written = engine
        .decode_slice(text.as_slice(), out.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    out.truncate(written);
    Ok(out)
}

/// The base64 body between the first `-----BEGIN ` line and its `-----END ` line, whatever
/// the label.
fn pem_body(input: &[u8]) -> Result<Bytes> {
    let text = core::str::from_utf8(input).map_err(|_| Error::Encoding)?;
    let mut lines = text.lines().map(str::trim);
    lines
        .by_ref()
        .find(|l| l.starts_with("-----BEGIN ") && l.ends_with("-----"))
        .ok_or(Error::Encoding)?;
    let mut body = Zeroizing::new(Vec::with_capacity(input.len()));
    for line in lines {
        if line.starts_with("-----END ") {
            return b64_decode(&body);
        }
        if !line.contains(':') {
            body.extend_from_slice(line.as_bytes());
        }
    }
    Err(Error::Encoding)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

pub(crate) fn replaced_len(text: &[u8], from: &[u8], to: &[u8]) -> usize {
    if from.is_empty() {
        return text.len();
    }
    let count = memchr::memmem::find_iter(text, from).count();
    text.len() - count * from.len() + count * to.len()
}

fn replace(text: &[u8], from: &[u8], to: &[u8]) -> Result<Bytes> {
    if from.is_empty() {
        return Err(bad("replace of an empty text"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(replaced_len(text, from, to)));
    let mut rest = text;
    while let Some(at) = find(rest, from) {
        out.extend_from_slice(rest.get(..at).unwrap_or_default());
        out.extend_from_slice(to);
        rest = rest.get(at + from.len()..).unwrap_or_default();
    }
    out.extend_from_slice(rest);
    Ok(out)
}

/// True when the JSON object has a member named `key`. The values are skipped, not copied.
fn has_member(object: &[u8], key: &str) -> Result<bool> {
    use serde::de::{Deserializer as _, IgnoredAny, MapAccess, Visitor};

    struct Finder<'k>(&'k str);

    impl<'de> Visitor<'de> for Finder<'_> {
        type Value = bool;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> core::result::Result<bool, A::Error> {
            let mut found = false;
            while let Some(mut name) = map.next_key::<String>()? {
                found |= name == self.0;
                name.zeroize();
                map.next_value::<IgnoredAny>()?;
            }
            Ok(found)
        }
    }

    let mut de = serde_json::Deserializer::from_slice(object);
    let found = de
        .deserialize_map(Finder(key))
        .map_err(|_| bad("json_set of a value that is not a JSON object"))?;
    de.end().map_err(|_| bad("json_set of trailing data"))?;
    Ok(found)
}

/// The JSON object `object` with the string member `key: value` added at its end. The object
/// must not have that member; an empty object text is `{}`.
pub(crate) fn json_set(object: &[u8], key: &[u8], value: &[u8]) -> Result<Bytes> {
    let trimmed = object.trim_ascii();
    let key_text = core::str::from_utf8(key).map_err(|_| Error::Encoding)?;
    let empty = trimmed.is_empty() || trimmed == b"{}";
    if !trimmed.is_empty() && has_member(trimmed, key_text)? {
        return Err(bad("json_set of a member the object has"));
    }
    let open: &[u8] = if trimmed.is_empty() {
        b"{"
    } else {
        trimmed
            .strip_suffix(b"}")
            .ok_or(bad("json_set of a value that is not a JSON object"))?
    };
    let escaped_key = json_escape(key);
    let escaped = json_escape(value);
    let len = open.len() + usize::from(!empty) + escaped_key.len() + escaped.len() + 6;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(open.trim_ascii_end());
    if !empty {
        out.push(b',');
    }
    out.push(b'"');
    out.extend_from_slice(&escaped_key);
    out.extend_from_slice(b"\":\"");
    out.extend_from_slice(&escaped);
    out.extend_from_slice(b"\"}");
    Ok(out)
}

fn canonical_query(query: &[u8]) -> Result<Bytes> {
    let mut pairs: Vec<(Bytes, Bytes)> = Vec::new();
    for part in query.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        let mut halves = part.splitn(2, |b| *b == b'=');
        let name = halves.next().unwrap_or_default();
        let value = halves.next().unwrap_or_default();
        pairs.push((pct(&pct_decode(name)?), pct(&pct_decode(value)?)));
    }
    pairs.sort_by(|a, b| (a.0.as_slice(), a.1.as_slice()).cmp(&(b.0.as_slice(), b.1.as_slice())));
    let len = pairs.iter().map(|(n, v)| n.len() + v.len() + 2).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        out.extend_from_slice(name);
        out.push(b'=');
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Year, month and day of a count of days since 1970-01-01 (proleptic Gregorian).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Seconds accepted by `time`: years 0 to 9999.
const TIME_RANGE: core::ops::RangeInclusive<i64> = -62_167_219_200..=253_402_300_799;

fn time_format(unix: &[u8], format: &[u8]) -> Result<Bytes> {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds: i64 = core::str::from_utf8(unix)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|s| TIME_RANGE.contains(s))
        .ok_or(bad("time of a value that is not a Unix time"))?;
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil(days);
    let weekday = usize::try_from(days.rem_euclid(7)).map_err(|_| Error::Encoding)?;
    let month_index = usize::try_from(month - 1).map_err(|_| Error::Encoding)?;
    let mut out = String::with_capacity(format.len() * 8);
    let mut chars = core::str::from_utf8(format)
        .map_err(|_| bad("time format not UTF-8"))?
        .chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next().ok_or(bad("time format ends with %"))? {
            'Y' => out.push_str(&format!("{year:04}")),
            'm' => out.push_str(&format!("{month:02}")),
            'd' => out.push_str(&format!("{day:02}")),
            'H' => out.push_str(&format!("{:02}", of_day / 3600)),
            'M' => out.push_str(&format!("{:02}", of_day / 60 % 60)),
            'S' => out.push_str(&format!("{:02}", of_day % 60)),
            'a' => out.push_str(DAYS.get(weekday).ok_or(Error::Encoding)?),
            'b' => out.push_str(MONTHS.get(month_index).ok_or(Error::Encoding)?),
            's' => out.push_str(&seconds.to_string()),
            '%' => out.push('%'),
            _ => return Err(bad("time format with an unknown directive")),
        }
    }
    Ok(Zeroizing::new(out.into_bytes()))
}

fn arg(args: &[Bytes], i: usize) -> Result<&[u8]> {
    args.get(i)
        .map(|a| a.as_slice())
        .ok_or(bad("missing argument"))
}

fn number(args: &[Bytes], i: usize, default: u64) -> Result<u64> {
    match args.get(i) {
        None => Ok(default),
        Some(a) => core::str::from_utf8(a)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(bad("argument is not a number")),
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Result<Bytes> {
    let mut mac = <M as Mac>::new_from_slice(key).map_err(|_| Error::KeyInvalid)?;
    mac.update(message);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

fn ed25519_key(bytes: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    if let Ok(seed) = <[u8; 32]>::try_from(bytes) {
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed));
    }
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

fn p256_key(bytes: &[u8]) -> Result<p256::ecdsa::SigningKey> {
    if bytes.len() == 32 {
        return p256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| Error::KeyInvalid);
    }
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

fn k256_key(bytes: &[u8]) -> Result<k256::ecdsa::SigningKey> {
    if bytes.len() == 32 {
        return k256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| Error::KeyInvalid);
    }
    use k256::pkcs8::DecodePrivateKey;
    k256::ecdsa::SigningKey::from_pkcs8_der(bytes).map_err(|_| Error::KeyInvalid)
}

/// RSA signing with ring. ring keeps no copy of the key in memory it frees itself, but its
/// key structure is not erased on drop: run nodes with a zeroizing allocator (see the README).
/// RustCrypto `rsa` 0.10 was measured to leave more unerased copies (11 blocks per signature
/// against 1), from temporaries while it parses and checks the key.
fn rsa_sign(key: &[u8], message: &[u8], pss: bool) -> Result<Bytes> {
    use ring::signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256, RsaKeyPair};
    let pair = RsaKeyPair::from_pkcs8(key)
        .or_else(|_| RsaKeyPair::from_der(key))
        .map_err(|_| Error::KeyInvalid)?;
    let mut out = Zeroizing::new(vec![0u8; pair.public().modulus_len()]);
    let rng = ring::rand::SystemRandom::new();
    let padding: &'static dyn ring::signature::RsaEncoding = if pss {
        &RSA_PSS_SHA256
    } else {
        &RSA_PKCS1_SHA256
    };
    pair.sign(padding, &rng, message, &mut out)
        .map_err(|_| Error::KeyInvalid)?;
    Ok(out)
}

fn p384_sign(key: &[u8], message: &[u8]) -> Result<Bytes> {
    use p384::ecdsa::signature::Signer as _;
    use p384::pkcs8::DecodePrivateKey as _;
    let key = if key.len() == 48 {
        p384::ecdsa::SigningKey::from_slice(key).map_err(|_| Error::KeyInvalid)?
    } else {
        p384::ecdsa::SigningKey::from_pkcs8_der(key).map_err(|_| Error::KeyInvalid)?
    };
    let signature: p384::ecdsa::Signature = key.try_sign(message).map_err(|_| Error::KeyInvalid)?;
    Ok(Zeroizing::new(signature.to_bytes().to_vec()))
}

fn aes_gcm(key: &[u8], nonce: &[u8], message: &[u8], aad: &[u8]) -> Result<Bytes> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
    if nonce.len() != 12 {
        return Err(Error::KeyInvalid);
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload { msg: message, aad };
    let out = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt(nonce, payload),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt(nonce, payload),
        _ => return Err(Error::KeyInvalid),
    };
    out.map(Zeroizing::new).map_err(|_| Error::Encoding)
}

fn aes_cbc(key: &[u8], iv: &[u8], message: &[u8]) -> Result<Bytes> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    let out = match key.len() {
        16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        32 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| Error::KeyInvalid)?
            .encrypt_padded_vec_mut::<Pkcs7>(message),
        _ => return Err(Error::KeyInvalid),
    };
    Ok(Zeroizing::new(out))
}

fn big_endian(text: &[u8], bytes: usize) -> Result<Bytes> {
    let value: u64 = core::str::from_utf8(text)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(bad("argument is not a number"))?;
    let all = value.to_be_bytes();
    let (high, low) = all.split_at(8 - bytes);
    if high.iter().any(|b| *b != 0) {
        return Err(bad("number too large"));
    }
    Ok(Zeroizing::new(low.to_vec()))
}

/// The most bytes `func` can produce from `args`, checked against the budget before the
/// function allocates.
pub(crate) fn output_bound(func: Func, args: &[Bytes]) -> usize {
    let len = |i: usize| args.get(i).map_or(0, |a| a.len());
    match func {
        Func::B64 | Func::B64Raw | Func::B64Url | Func::B64UrlRaw => len(0) / 3 * 4 + 4,
        Func::Hex => len(0) * 2,
        Func::Pct | Func::CanonicalQuery => len(0) * 3 + 2,
        Func::Json => len(0) * 6,
        Func::Replace => match (args.first(), args.get(1), args.get(2)) {
            (Some(t), Some(f), Some(to)) => replaced_len(t, f, to),
            _ => 0,
        },
        Func::JsonSet => len(0) + len(1) * 6 + len(2) * 6 + 8,
        Func::Time => len(1) * 8,
        Func::AesGcmEncrypt | Func::AesCbcEncrypt => len(2) + 32,
        Func::RsaSignPkcs1Sha256 | Func::RsaSignPssSha256 => 1024,
        _ => len(0) + 128,
    }
}

pub(crate) fn call(func: Func, args: &[Bytes], unix: u64, budget: &Budget) -> Result<Bytes> {
    let a = arg(args, 0)?;
    Ok(match func {
        Func::B64 => b64(&STANDARD, a)?,
        Func::B64Raw => b64(&STANDARD_NO_PAD, a)?,
        Func::B64Url => b64(&URL_SAFE, a)?,
        Func::B64UrlRaw => b64(&URL_SAFE_NO_PAD, a)?,
        Func::B64Decode => b64_decode(a)?,
        Func::B32Decode => b32_decode(a)?,
        Func::Hex => hex(a),
        Func::HexDecode => hex_decode(a)?,
        Func::Pct => pct(a),
        Func::PctDecode => pct_decode(a)?,
        Func::Json => json_escape(a),
        Func::Upper => Zeroizing::new(a.to_ascii_uppercase()),
        Func::Lower => Zeroizing::new(a.to_ascii_lowercase()),
        Func::Trim => Zeroizing::new(a.trim_ascii().to_vec()),
        Func::Replace => replace(a, arg(args, 1)?, arg(args, 2)?)?,
        Func::Pem => pem_body(a)?,
        Func::JsonSet => json_set(a, arg(args, 1)?, arg(args, 2)?)?,
        Func::CanonicalQuery => canonical_query(a)?,
        Func::Time => time_format(a, arg(args, 1)?)?,
        Func::Len => Zeroizing::new(a.len().to_string().into_bytes()),
        Func::Be16 => big_endian(a, 2)?,
        Func::Be32 => big_endian(a, 4)?,
        Func::Xor => {
            let b = arg(args, 1)?;
            if a.len() != b.len() {
                return Err(bad("xor of values of different lengths"));
            }
            Zeroizing::new(a.iter().zip(b).map(|(x, y)| x ^ y).collect())
        }
        Func::Md5 => Zeroizing::new(md5::Md5::digest(a).to_vec()),
        Func::Sha1 => Zeroizing::new(Sha1::digest(a).to_vec()),
        Func::Sha256 => Zeroizing::new(Sha256::digest(a).to_vec()),
        Func::Sha512 => Zeroizing::new(Sha512::digest(a).to_vec()),
        Func::Keccak256 => Zeroizing::new(sha3::Keccak256::digest(a).to_vec()),
        Func::HmacSha1 => mac::<Hmac<Sha1>>(a, arg(args, 1)?)?,
        Func::HmacSha256 => mac::<Hmac<Sha256>>(a, arg(args, 1)?)?,
        Func::HmacSha512 => mac::<Hmac<Sha512>>(a, arg(args, 1)?)?,
        Func::Pbkdf2Sha256 => {
            let rounds = number(args, 2, 0)?;
            let length = usize::try_from(number(args, 3, 32)?).map_err(|_| bad("length"))?;
            if rounds == 0 || rounds > MAX_PBKDF2_ROUNDS || !(1..=64).contains(&length) {
                return Err(bad("pbkdf2 rounds or length out of range"));
            }
            budget.rounds(rounds)?;
            let mut out = Zeroizing::new(vec![0u8; length]);
            let rounds = u32::try_from(rounds).map_err(|_| bad("rounds"))?;
            pbkdf2::pbkdf2_hmac::<Sha256>(a, arg(args, 1)?, rounds, &mut out);
            out
        }
        Func::Totp => {
            let digits = u32::try_from(number(args, 1, 6)?).map_err(|_| bad("digits"))?;
            let period = number(args, 2, 30)?;
            let code = totp::code(a, unix, digits, period)?;
            let width = usize::try_from(digits).map_err(|_| bad("digits"))?;
            Zeroizing::new(format!("{code:0width$}").into_bytes())
        }
        Func::Ed25519Sign => {
            budget.signature()?;
            Zeroizing::new(ed25519_key(a)?.sign(arg(args, 1)?).to_bytes().to_vec())
        }
        Func::P256Sign | Func::P256SignDer => {
            use p256::ecdsa::signature::Signer as _;
            budget.signature()?;
            let signature: p256::ecdsa::Signature = p256_key(a)?.sign(arg(args, 1)?);
            Zeroizing::new(if func == Func::P256Sign {
                signature.to_bytes().to_vec()
            } else {
                signature.to_der().as_bytes().to_vec()
            })
        }
        Func::P384Sign => {
            budget.signature()?;
            p384_sign(a, arg(args, 1)?)?
        }
        Func::K256Sign => {
            use k256::ecdsa::signature::Signer as _;
            budget.signature()?;
            let signature: k256::ecdsa::Signature = k256_key(a)?.sign(arg(args, 1)?);
            Zeroizing::new(signature.to_bytes().to_vec())
        }
        Func::K256SignRecoverable => {
            budget.signature()?;
            let digest = arg(args, 1)?;
            if digest.len() != 32 {
                return Err(bad(
                    "k256_sign_recoverable of a digest that is not 32 bytes",
                ));
            }
            let (signature, id) = k256_key(a)?.sign_prehash_recoverable(digest);
            let mut out = Zeroizing::new(Vec::with_capacity(65));
            out.extend_from_slice(&signature.to_bytes());
            out.push(27 + id.to_byte());
            out
        }
        Func::RsaSignPkcs1Sha256 | Func::RsaSignPssSha256 => {
            budget.signature()?;
            rsa_sign(a, arg(args, 1)?, func == Func::RsaSignPssSha256)?
        }
        Func::AesGcmEncrypt => {
            let aad = args.get(3).map_or(&[][..], |v| v.as_slice());
            aes_gcm(a, arg(args, 1)?, arg(args, 2)?, aad)?
        }
        Func::AesCbcEncrypt => aes_cbc(a, arg(args, 1)?, arg(args, 2)?)?,
    })
}
