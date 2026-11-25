//! The reflection check: a response that sends a secret back is dropped.
//!
//! The search knows every secret field of 8 bytes or more as raw bytes, standard and URL-safe
//! base64, and (up to 64 KiB) percent encoding, JSON escaping and hex; and every rendered
//! header, query or path value that holds a secret in reversible form. A server that echoes a
//! value in another form is not caught; see the README.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::fields::Fields;
use crate::policy::Policy;
use crate::template::{hex, json_escape, pct};
use crate::{Error, Result};

/// Shortest value searched for: a shorter one cannot be told apart in a response.
pub const MIN_NEEDLE: usize = 8;
const ENCODED_LIMIT: usize = 64 * 1024;

fn b64_with<E: Engine>(engine: &E, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = base64::encoded_len(bytes.len(), true).ok_or(Error::Encoding)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let written = engine
        .encode_slice(bytes, out.as_mut_slice())
        .map_err(|_| Error::Encoding)?;
    out.truncate(written);
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() >= MIN_NEEDLE && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fails with [`Error::Reflection`] when `response` holds a secret in a known form.
pub(crate) fn check(
    response: &[u8],
    policy: &Policy,
    fields: &Fields,
    rendered: &[Zeroizing<Vec<u8>>],
) -> Result<()> {
    if rendered.iter().any(|r| contains(response, r)) {
        return Err(Error::Reflection);
    }
    for (name, value) in fields.values() {
        if !policy.is_secret(name) || value.len() < MIN_NEEDLE {
            continue;
        }
        let mut needles = vec![
            b64_with(&STANDARD, value)?,
            b64_with(&URL_SAFE_NO_PAD, value)?,
        ];
        if value.len() <= ENCODED_LIMIT {
            needles.extend([pct(value), json_escape(value), hex(value)]);
        }
        if contains(response, value) || needles.iter().any(|n| contains(response, n)) {
            return Err(Error::Reflection);
        }
    }
    Ok(())
}
