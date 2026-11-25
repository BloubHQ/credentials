//! Masked projections. Each shows a fixed, small part of the value, and nothing when the
//! value is too short for that part to stay a small part.

use super::Mask;
use super::checks::{brand_of, expiry_parts};

const HIDDEN: &str = "\u{2022}\u{2022}\u{2022}\u{2022}";

/// The last `n` characters of `text` after the hidden mark, when `text` has at least `min`.
fn last(text: &str, n: usize, min: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < min {
        return HIDDEN.to_string();
    }
    let tail: String = chars
        .get(chars.len().saturating_sub(n)..)
        .unwrap_or_default()
        .iter()
        .collect();
    format!("{HIDDEN}{tail}")
}

/// The first character and the hidden mark, when `text` has at least `min` characters.
fn initial(text: &str, min: usize) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if text.chars().count() >= min => format!("{first}***"),
        _ => "***".to_string(),
    }
}

fn year(text: &str, value: &[u8]) -> String {
    if let Some((_, year)) = expiry_parts(value) {
        return year.to_string();
    }
    // YYYY-MM-DD
    match text.split('-').next() {
        Some(y) if y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()) && text.len() == 10 => {
            y.to_string()
        }
        _ => HIDDEN.to_string(),
    }
}

/// The projection of a value under a mask.
pub(super) fn apply(mask: Mask, value: &[u8]) -> String {
    let Ok(text) = core::str::from_utf8(value) else {
        return HIDDEN.to_string();
    };
    match mask {
        Mask::Card => {
            let brand = brand_of(value).as_str();
            if value.len() >= 12 && value.iter().all(u8::is_ascii_digit) {
                format!("{brand} {}", last(text, 4, 12))
            } else {
                format!("{brand} {HIDDEN}")
            }
        }
        Mask::Email => match text.rsplit_once('@') {
            Some((local, domain)) if !domain.is_empty() => {
                format!("{}@{domain}", initial(local, 2))
            }
            _ => initial(text, 2),
        },
        Mask::Initial => initial(text, 2),
        Mask::Year => year(text, value),
        Mask::Last2 => last(text, 2, 8),
        Mask::Last4 => last(text, 4, 12),
    }
}
