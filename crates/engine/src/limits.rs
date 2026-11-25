//! Spending limits: how much an item may pay without the owner's approval.
//!
//! The owner's device signs [`SpendingLimits`] for one record on one node: rules per currency,
//! optionally per merchant origin, with a most per payment, per rolling day and per rolling 30
//! days. The node keeps them in its state, like floors and devices, and counts every payment it
//! makes. Before an operation that declares a [`crate::policy::Payment`] sends anything, the
//! node checks the payment against every rule that applies; a payment no rule covers, or one
//! above a rule, waits for the owner's approval. Approved payments count too.
//!
//! The limits and each counted payment are written to the log sealed under a key only the node
//! derives from its own key, so a restarted node counts them again and the log store reads
//! neither amounts nor merchants.

use std::collections::VecDeque;

use chacha20poly1305::aead::{Aead, Generate as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{b64_array, canonical};
use crate::item::parse_origin;
use crate::keys::{DeviceKey, DevicePublicKey, NodeKey, NodePublicKey};
use crate::log::SealedDetail;
use crate::record::check_name;
use crate::{Error, Result};

const LIMITS_DOMAIN: &[u8] = b"limits/v1\0";
const STATE_KEY_INFO: &[u8] = b"node-state/v1\0";

/// Most rules of one item.
pub const MAX_RULES: usize = 16;
/// The rolling day of `per_day`.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// The rolling month of `per_month`: 30 days.
pub const MONTH_MS: u64 = 30 * DAY_MS;
/// Most payments the node remembers per item within a month; beyond, every payment waits for
/// the owner's approval.
pub const MAX_SPENDS: usize = 4096;
/// Digits after the decimal point the node counts in.
pub const SCALE: u32 = 8;

/// A limit on the payments of one item in one currency, at one merchant or at any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitRule {
    /// The ISO 4217 code.
    pub currency: String,
    /// The merchant, an exact origin (`https://shop.example`); absent for every merchant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    /// The most one payment may be, a decimal (`25.00`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_payment: Option<String>,
    /// The most all payments of the last 24 hours may be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_day: Option<String>,
    /// The most all payments of the last 30 days may be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_month: Option<String>,
}

/// The spending limits of one record on one node, signed by a device of the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendingLimits {
    /// The node they are for.
    pub node: NodePublicKey,
    /// The owner.
    pub owner: String,
    /// The record.
    pub record_id: String,
    /// The rules; none means every payment waits for the owner's approval.
    pub rules: Vec<LimitRule>,
    /// The device that signed.
    pub device: DevicePublicKey,
    /// When it signed, Unix milliseconds. A node takes it within five minutes of its clock and
    /// after the limits it holds for the record.
    pub issued_ms: u64,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct LimitsMessage<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    record_id: &'a str,
    rules: &'a [LimitRule],
    device: &'a DevicePublicKey,
    issued_ms: u64,
}

fn invalid(rule: &'static str) -> Error {
    Error::LimitsInvalid { rule }
}

/// A decimal amount (`12.50`, `3`) in units of 10^-8, or `None` when it is not one: digits,
/// at most one `.` followed by 1 to 8 digits, no leading zero, at most 20 whole digits.
pub fn scaled(value: &str) -> Option<u128> {
    let (whole, fraction) = match value.split_once('.') {
        Some((w, f)) => (w, f),
        None => (value, ""),
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || whole.len() > 20
        || !digits(whole)
        || (whole.len() > 1 && whole.starts_with('0'))
        || (value.contains('.') && fraction.is_empty())
        || fraction.len() > SCALE as usize
        || !digits(fraction)
    {
        return None;
    }
    let whole: u128 = whole.parse().ok()?;
    let mut padded = fraction.to_string();
    while padded.len() < SCALE as usize {
        padded.push('0');
    }
    let fraction: u128 = padded.parse().ok()?;
    whole.checked_mul(10u128.pow(SCALE))?.checked_add(fraction)
}

/// An integer amount in minor units with `exponent` digits after the point, in units of
/// 10^-8.
pub fn from_minor(minor: u64, exponent: u8) -> Option<u128> {
    let shift = SCALE.checked_sub(u32::from(exponent))?;
    u128::from(minor).checked_mul(10u128.pow(shift))
}

/// An integer amount in minor units as a decimal: `1250` with exponent 2 is `12.50`.
pub fn decimal(minor: u64, exponent: u8) -> String {
    let digits = minor.to_string();
    let exponent = usize::from(exponent);
    if exponent == 0 {
        return digits;
    }
    let padded = format!("{digits:0>width$}", width = exponent + 1);
    let (whole, fraction) = padded.split_at(padded.len() - exponent);
    format!("{whole}.{fraction}")
}

/// An amount in units of 10^-8 as a decimal, without trailing zeros after the point.
pub fn show(scaled: u128) -> String {
    let unit = 10u128.pow(SCALE);
    let (whole, fraction) = (scaled / unit, scaled % unit);
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:08}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

impl LimitRule {
    fn fault(&self) -> Option<&'static str> {
        if !crate::policy::is_currency(&self.currency) {
            return Some("a currency is an ISO 4217 code");
        }
        if self
            .merchant
            .as_deref()
            .is_some_and(|m| parse_origin(m).is_none_or(|o| o.text() != m))
        {
            return Some("a merchant is an exact origin");
        }
        let bounds = [&self.per_payment, &self.per_day, &self.per_month];
        if bounds.iter().all(|b| b.is_none()) {
            return Some("a rule bounds a payment, a day or a month");
        }
        if !bounds
            .iter()
            .all(|b| b.as_deref().is_none_or(|v| scaled(v).is_some()))
        {
            return Some("a bound is a decimal of at most 20 whole and 8 fraction digits");
        }
        None
    }

    fn applies(&self, spend: &Spend) -> bool {
        self.currency == spend.currency
            && self
                .merchant
                .as_ref()
                .is_none_or(|m| spend.merchant.as_ref() == Some(m))
    }
}

impl SpendingLimits {
    /// Checks the form of the limits.
    pub fn validate(&self) -> Result<()> {
        check_name(&self.owner)?;
        check_name(&self.record_id)?;
        if self.rules.len() > MAX_RULES {
            return Err(invalid("at most 16 rules"));
        }
        if let Some(rule) = self.rules.iter().find_map(LimitRule::fault) {
            return Err(invalid(rule));
        }
        let mut keys: Vec<(&str, Option<&str>)> = self
            .rules
            .iter()
            .map(|r| (r.currency.as_str(), r.merchant.as_deref()))
            .collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(invalid("one rule per currency and merchant"));
        }
        Ok(())
    }

    fn message(&self) -> Result<Vec<u8>> {
        canonical(
            LIMITS_DOMAIN,
            &LimitsMessage {
                node: &self.node,
                owner: &self.owner,
                record_id: &self.record_id,
                rules: &self.rules,
                device: &self.device,
                issued_ms: self.issued_ms,
            },
        )
    }

    /// Checks the signature of the device named in the limits.
    pub(crate) fn verify(&self) -> Result<()> {
        self.device
            .verify(&self.message()?, &self.signature)
            .map_err(|_| invalid("the signature does not verify"))
    }
}

impl DeviceKey {
    /// Signs the spending limits of `record_id` of `owner` on `node`, at `issued_ms`. Runs on
    /// the owner's device. No rule at all means every payment of the item waits for approval.
    pub fn sign_limits(
        &self,
        node: &NodePublicKey,
        owner: &str,
        record_id: &str,
        rules: Vec<LimitRule>,
        issued_ms: u64,
    ) -> Result<SpendingLimits> {
        let mut limits = SpendingLimits {
            node: *node,
            owner: owner.to_string(),
            record_id: record_id.to_string(),
            rules,
            device: self.public(),
            issued_ms,
            signature: [0; 64],
        };
        limits.validate()?;
        limits.signature = self.sign(&limits.message()?);
        Ok(limits)
    }
}

/// A payment the node is about to make, or made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Spend {
    /// The ISO 4217 code.
    pub currency: String,
    /// Where it goes, an origin; absent for an operation with no connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    /// The amount in units of 10^-8, as a decimal integer.
    pub scaled: String,
    /// The amount in minor units, and the exponent of the currency.
    #[serde(skip)]
    pub minor: u64,
    #[serde(skip)]
    pub exponent: u8,
}

impl Spend {
    fn amount(&self) -> u128 {
        self.scaled.parse().unwrap_or(u128::MAX)
    }
}

/// What the limits say of a payment.
pub(crate) enum Verdict {
    /// Every rule that applies allows it, and at least one applies.
    Within,
    /// It waits for the owner's approval; the lines say why.
    Above(Vec<String>),
}

/// The limits of one record and the payments it made within a month.
#[derive(Default)]
pub(crate) struct Ledger {
    rules: Vec<LimitRule>,
    pub issued_ms: u64,
    spends: VecDeque<(u64, Spend)>,
}

impl Ledger {
    pub fn set(&mut self, rules: Vec<LimitRule>, issued_ms: u64) {
        self.rules = rules;
        self.issued_ms = self.issued_ms.max(issued_ms);
    }

    fn expire(&mut self, now: u64) {
        while self
            .spends
            .front()
            .is_some_and(|(t, _)| t.saturating_add(MONTH_MS) <= now)
        {
            self.spends.pop_front();
        }
    }

    fn spent(&self, rule: &LimitRule, since: u64) -> u128 {
        self.spends
            .iter()
            .filter(|(t, s)| *t > since && rule.applies(s))
            .fold(0u128, |sum, (_, s)| sum.saturating_add(s.amount()))
    }

    pub fn verdict(&mut self, spend: &Spend, now: u64) -> Verdict {
        self.expire(now);
        let amount = spend.amount();
        let applying: Vec<&LimitRule> = self.rules.iter().filter(|r| r.applies(spend)).collect();
        if applying.is_empty() {
            return Verdict::Above(vec![format!(
                "no spending limit of this item covers {}{}",
                spend.currency,
                spend
                    .merchant
                    .as_deref()
                    .map(|m| format!(" at {m}"))
                    .unwrap_or_default()
            )]);
        }
        if self.spends.len() >= MAX_SPENDS {
            return Verdict::Above(vec![
                "more payments this month than the node counts without approval".into(),
            ]);
        }
        let mut lines = Vec::new();
        for rule in applying {
            let at = rule
                .merchant
                .as_deref()
                .map(|m| format!(" at {m}"))
                .unwrap_or_default();
            let bound = |b: &Option<String>| b.as_deref().and_then(scaled);
            if let Some(max) = bound(&rule.per_payment)
                && amount > max
            {
                lines.push(format!(
                    "above the limit of {} {} per payment{at}",
                    show(max),
                    rule.currency
                ));
            }
            for (max, window, what) in [
                (bound(&rule.per_day), DAY_MS, "day"),
                (bound(&rule.per_month), MONTH_MS, "30 days"),
            ] {
                let Some(max) = max else { continue };
                let spent = self.spent(rule, now.saturating_sub(window));
                if spent.saturating_add(amount) > max {
                    lines.push(format!(
                        "above the limit of {} {} per {what}{at}: {} spent before this one",
                        show(max),
                        rule.currency,
                        show(spent)
                    ));
                }
            }
        }
        if lines.is_empty() {
            Verdict::Within
        } else {
            Verdict::Above(lines)
        }
    }

    pub fn record(&mut self, spend: Spend, at: u64) {
        self.expire(at);
        if self.spends.len() >= MAX_SPENDS {
            self.spends.pop_front();
        }
        self.spends.push_back((at, spend));
    }

    /// The rules and the payments counted, to move them to a successor node.
    pub fn snapshot(&self) -> LedgerState {
        LedgerState {
            rules: self.rules.clone(),
            issued_ms: self.issued_ms,
            spends: self.spends.iter().cloned().collect(),
        }
    }

    /// A ledger from a [`Ledger::snapshot`], within the bounds of a ledger.
    pub fn from_state(state: LedgerState) -> Result<Self> {
        if state.rules.len() > MAX_RULES || state.spends.len() > MAX_SPENDS {
            return Err(Error::LimitsInvalid {
                rule: "more rules or payments than a ledger holds",
            });
        }
        Ok(Self {
            rules: state.rules,
            issued_ms: state.issued_ms,
            spends: state.spends.into(),
        })
    }
}

/// The content of a [`Ledger`], as a hand-over moves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerState {
    pub rules: Vec<LimitRule>,
    pub issued_ms: u64,
    pub spends: Vec<(u64, Spend)>,
}

/// The key a node seals its own state into the log with: derived from the node key, so only
/// the same node (also after a restart) opens it.
pub(crate) struct StateKey(Zeroizing<[u8; 32]>);

impl StateKey {
    pub fn of(node: &NodeKey) -> Self {
        let bytes = node.to_bytes();
        let mut hash = Sha256::new();
        hash.update(STATE_KEY_INFO);
        hash.update(bytes.as_slice());
        Self(Zeroizing::new(hash.finalize().into()))
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305> {
        ChaCha20Poly1305::new_from_slice(self.0.as_slice()).map_err(|_| Error::KeyInvalid)
    }

    fn aad(owner: &str, record_id: &str, what: &str) -> Vec<u8> {
        [owner.as_bytes(), record_id.as_bytes(), what.as_bytes()].join(&0u8)
    }

    pub fn seal<T: Serialize>(
        &self,
        owner: &str,
        record_id: &str,
        what: &str,
        value: &T,
    ) -> Result<SealedDetail> {
        let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Encoding)?);
        let nonce: [u8; 12] = Nonce::generate().into();
        let ct = self
            .cipher()?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &plain,
                    aad: &Self::aad(owner, record_id, what),
                },
            )
            .map_err(|_| Error::Encoding)?;
        Ok(SealedDetail { nonce, ct })
    }

    pub fn open<T: for<'de> Deserialize<'de>>(
        &self,
        owner: &str,
        record_id: &str,
        what: &str,
        sealed: &SealedDetail,
    ) -> Result<T> {
        let plain = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &Nonce::from(sealed.nonce),
                    Payload {
                        msg: &sealed.ct,
                        aad: &Self::aad(owner, record_id, what),
                    },
                )
                .map_err(|_| Error::LogMismatch)?,
        );
        serde_json::from_slice(&plain).map_err(|_| Error::Encoding)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn amounts_read_and_print_exactly() {
        assert_eq!(scaled("12.50"), Some(1_250_000_000));
        assert_eq!(scaled("0"), Some(0));
        assert_eq!(scaled("0.00000001"), Some(1));
        for bad in [
            "",
            "01",
            "1.",
            ".5",
            "1.123456789",
            "-1",
            "1e3",
            "1,5",
            " 1",
        ] {
            assert_eq!(scaled(bad), None, "{bad:?}");
        }
        assert_eq!(decimal(1250, 2), "12.50");
        assert_eq!(decimal(5, 2), "0.05");
        assert_eq!(decimal(1250, 0), "1250");
        assert_eq!(from_minor(1250, 2), scaled("12.50"));
        assert_eq!(from_minor(1, 9), None);
        assert_eq!(show(scaled("12.50").unwrap()), "12.5");
        assert_eq!(show(scaled("100").unwrap()), "100");
    }

    #[test]
    fn minor_units_print_and_read_back_exactly() {
        for minor in [0, 1, 9, 10, 99, 100, 1250, 123_456_789, u64::MAX] {
            for exponent in 0..=8u8 {
                let value = from_minor(minor, exponent).unwrap();
                assert_eq!(scaled(&decimal(minor, exponent)), Some(value));
                assert_eq!(scaled(&show(value)), Some(value));
            }
            assert_eq!(from_minor(minor, 9), None);
        }
    }

    #[test]
    fn a_rule_bounds_one_currency_at_one_merchant() {
        let rule = LimitRule {
            currency: "EUR".into(),
            merchant: Some("https://shop.example".into()),
            per_payment: Some("25".into()),
            per_day: None,
            per_month: None,
        };
        assert_eq!(rule.fault(), None);
        for (what, broken) in [
            (
                "lower case",
                LimitRule {
                    currency: "eur".into(),
                    ..rule.clone()
                },
            ),
            (
                "a merchant with a path",
                LimitRule {
                    merchant: Some("https://shop.example/x".into()),
                    ..rule.clone()
                },
            ),
            (
                "no bound",
                LimitRule {
                    per_payment: None,
                    ..rule.clone()
                },
            ),
            (
                "a bound that is no decimal",
                LimitRule {
                    per_payment: Some("1e3".into()),
                    ..rule.clone()
                },
            ),
        ] {
            assert!(rule.fault().is_none() && broken.fault().is_some(), "{what}");
        }
        let mut ledger = Ledger::default();
        ledger.set(vec![rule], 1);
        let spend = |merchant: &str, cents: u64| Spend {
            currency: "EUR".into(),
            merchant: Some(merchant.into()),
            scaled: from_minor(cents, 2).unwrap().to_string(),
            minor: cents,
            exponent: 2,
        };
        assert!(matches!(
            ledger.verdict(&spend("https://shop.example", 2500), 10),
            Verdict::Within
        ));
        assert!(matches!(
            ledger.verdict(&spend("https://shop.example", 2501), 10),
            Verdict::Above(_)
        ));
        assert!(matches!(
            ledger.verdict(&spend("https://other.example", 1), 10),
            Verdict::Above(_)
        ));
        // The month forgets what is older than 30 days.
        ledger.record(spend("https://shop.example", 100), 10);
        assert_eq!(ledger.spends.len(), 1);
        ledger.expire(10 + MONTH_MS);
        assert_eq!(ledger.spends.len(), 0);
    }
}
