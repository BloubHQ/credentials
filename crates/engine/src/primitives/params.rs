//! Sorted parameter lists: the normalization of RFC 5849 section 3.4.1.3.2 (OAuth 1.0a), which
//! other signing schemes share (a query-string signature over every parameter, sorted and
//! encoded the same way).
//!
//! Each argument is a list in the `application/x-www-form-urlencoded` form: pairs separated by
//! `&`, a name and a value separated by the first `=`, `+` a space and `%XX` an octet. The
//! pairs of every argument are decoded, encoded again with RFC 3986 percent-encoding (every
//! octet but the unreserved `A-Z a-z 0-9 - . _ ~` as `%XX` in uppercase), sorted by name and
//! then by value in octet order, and joined as `name=value` with `&`. A pair without `=` has
//! an empty value; empty pairs are dropped. A `%` not followed by two hex digits is refused.

use zeroize::Zeroizing;

use super::{hex_digit, pct};
use crate::template::Bytes;
use crate::{Error, Result};

/// Most arguments of `sorted_params`.
pub const MAX_LISTS: usize = 8;

/// One name or value as `application/x-www-form-urlencoded` reads it, encoded again.
fn reencode(raw: &[u8]) -> Result<Bytes> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        match b {
            b'%' => {
                let hi = hex_digit(*raw.get(i + 1).ok_or(Error::Encoding)?)?;
                let lo = hex_digit(*raw.get(i + 2).ok_or(Error::Encoding)?)?;
                decoded.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            other => {
                decoded.push(other);
                i += 1;
            }
        }
    }
    Ok(pct(&decoded))
}

/// `sorted_params(list, ...)`: the pairs of every list, normalized as RFC 5849 section
/// 3.4.1.3.2 says.
pub fn sorted(lists: &[&[u8]]) -> Result<Bytes> {
    if lists.is_empty() || lists.len() > MAX_LISTS {
        return Err(Error::TemplateInvalid {
            rule: "sorted_params takes 1 to 8 lists",
        });
    }
    let mut pairs: Vec<(Bytes, Bytes)> = Vec::new();
    for list in lists {
        for pair in list.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
            let (name, value) = match pair.iter().position(|b| *b == b'=') {
                Some(at) => (
                    pair.get(..at).unwrap_or_default(),
                    pair.get(at + 1..).unwrap_or_default(),
                ),
                None => (pair, &[][..]),
            };
            pairs.push((reencode(name)?, reencode(value)?));
        }
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

/// The most octets [`sorted`] writes for lists of `total` octets in `count` arguments.
pub fn bound(total: usize, count: usize) -> usize {
    total
        .saturating_mul(3)
        .saturating_add(count)
        .saturating_add(2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc5849_section_3_4_1_3_2() {
        // The query, the form body and the protocol parameters of the example of RFC 5849
        // section 3.4.1.3.1, normalized as section 3.4.1.3.2 shows.
        let out = sorted(&[
            b"b5=%3D%253D&a3=a&c%40=&a2=r%20b",
            b"c2&a3=2+q",
            b"oauth_consumer_key=9djdj82h48djs9d2&oauth_token=kkk9d7dh3k39sjv7&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_nonce=7d8f3e4a",
        ])
        .unwrap();
        assert_eq!(
            core::str::from_utf8(&out).unwrap(),
            "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2\
             &oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201\
             &oauth_token=kkk9d7dh3k39sjv7"
        );
    }

    #[test]
    fn encoding_and_refusals() {
        assert_eq!(
            sorted(&[b"b=%7e%2a&a=%C3%A9 x&&=v"]).unwrap().as_slice(),
            b"=v&a=%C3%A9%20x&b=~%2A"
        );
        assert_eq!(sorted(&[b"", b""]).unwrap().as_slice(), b"");
        assert!(sorted(&[b"a=%4"]).is_err());
        assert!(sorted(&[b"a=%zz"]).is_err());
        assert!(sorted(&[]).is_err());
        assert!(sorted(&[&b"a"[..]; 9]).is_err());
        let out = sorted(&[b"x=\xff\x00"]).unwrap();
        assert!(out.len() <= bound(4, 1));
        // Idempotent: a normalized list is its own normalization.
        assert_eq!(sorted(&[&out]).unwrap(), out);
    }
}
