//! What an operation waits for, what it pays, and how a session it keeps is renewed.
//!
//! - [`Await`]: the step that parks an operation until a one-time code arrives from the
//!   owner's device, or until a site reports that the owner approved in another app
//!   ([`Challenge`]). The node keeps the operation's values in its memory meanwhile
//!   (`docs/design.md` section 5).
//! - [`Payment`]: where the amount of a payment is read, so the node can build the approval
//!   summary and apply the owner's spending limits. The amount comes only from a value a
//!   contract checked as a bounded integer (a query rule with `min` and `max`, an input member
//!   of type number with `min` and `max`, a member or field of a body contract) or from the
//!   policy itself, never from free text. An amount in a body is read from the body the node
//!   wrote again and sends, by the parser that wrote it ([`read_amount`]).
//! - [`SessionRule`]: a secret field that holds a session the node obtained (cookies, a
//!   bearer token), its lifetime, and how it is renewed.

use serde::{Deserialize, Serialize};

use super::{Destination, Method, Send, Source, StepRequest, is_token};

/// Most `await` steps of one operation.
pub const MAX_AWAITS: usize = 4;
/// Longest hint of a challenge, in bytes.
pub const MAX_HINT: usize = 256;
/// Longest a parked operation waits: five minutes.
pub const MAX_WAIT_MS: u64 = 5 * 60 * 1000;
/// Shortest wait between two polls of an external challenge.
pub const MIN_POLL_MS: u64 = 1000;
/// Most values a poll condition compares with.
pub const MAX_CONDITION_VALUES: usize = 16;
/// Largest amount of a payment, in minor units: 10^18, so it fits a 64-bit integer.
pub const MAX_AMOUNT: u64 = 1_000_000_000_000_000_000;
/// Most digits after the decimal point of a currency (`exponent`).
pub const MAX_EXPONENT: u8 = 8;
/// Longest lifetime of a session the node keeps: 30 days.
pub const MAX_SESSION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The pattern of a one-time code when the challenge gives none.
pub const DEFAULT_CODE_PATTERN: &str = "[0-9A-Za-z-]{1,64}";

/// What kind of challenge an operation waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    /// A code sent by text message.
    Sms,
    /// A code sent by e-mail.
    Email,
    /// A code from an authenticator app.
    App,
    /// A 3-D Secure code of a card payment.
    #[serde(rename = "3ds")]
    ThreeDs,
    /// No code: the site waits for the owner to approve in another app; the node polls.
    External,
}

impl ChallengeKind {
    /// The name in JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::Sms => "sms",
            ChallengeKind::Email => "email",
            ChallengeKind::App => "app",
            ChallengeKind::ThreeDs => "3ds",
            ChallengeKind::External => "external",
        }
    }
}

/// A condition on the response of a poll: the captured value is one of `one_of`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Where the value is read (as a capture of an HTTPS `receive`).
    pub source: Source,
    /// The values that make the condition hold, compared exactly.
    pub one_of: Vec<String>,
}

/// How the node asks a site whether the owner approved: a request the policy fixes, sent at
/// most every `every_ms`, until `success` or `failure` holds or the challenge lapses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    /// The request: a `send` whose request is fixed (`{"from": "fixed", ...}`), with its
    /// injections.
    pub send: Send,
    /// When it holds, the operation goes on with the step after the `await`.
    pub success: Condition,
    /// When it holds, the operation fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Condition>,
    /// The least time between two polls, in milliseconds (at least 1000).
    pub every_ms: u64,
}

/// A challenge the operation waits for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// The kind: a code (`sms`, `email`, `app`, `3ds`) or `external`.
    pub kind: ChallengeKind,
    /// What the owner is told, written by the owner in the policy: 1 to 256 bytes without
    /// control characters. The caller writes no part of it.
    pub hint: String,
    /// For a code: the secret temporary value later steps read it from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub into: Option<String>,
    /// For a code: a regular expression the whole code must match (by default
    /// [`DEFAULT_CODE_PATTERN`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// For `external`: how the node asks the site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<Poll>,
    /// How long the operation waits, in milliseconds: 1000 to 300000 (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl Challenge {
    /// How long the operation waits.
    pub fn timeout(&self) -> u64 {
        self.timeout_ms.unwrap_or(MAX_WAIT_MS)
    }

    /// The pattern a code must match.
    pub fn code_pattern(&self) -> &str {
        self.pattern.as_deref().unwrap_or(DEFAULT_CODE_PATTERN)
    }
}

/// The `await` step: the operation parks until the challenge is answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Await {
    /// What it waits for.
    pub challenge: Challenge,
}

/// Where the amount of a payment is read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum AmountSource {
    /// A query parameter of the caller's request whose rule is `required` with `min` (at
    /// least 0) and `max` (at most 10^18).
    Query {
        /// The parameter name, as in the rule.
        name: String,
    },
    /// A member of the caller's checked input whose rule is a required `number` with `min`
    /// (at least 0) and `max` (at most 10^18).
    Input {
        /// The JSON pointer of the member, as in the schema.
        pointer: String,
    },
    /// A member of the caller's JSON body, checked by the body contract of the request: a
    /// required member, read from the body the node wrote again and sends.
    Body {
        /// The JSON pointer of the member, as in the body contract.
        pointer: String,
        /// How the amount is written.
        #[serde(default, skip_serializing_if = "AmountFormat::is_minor")]
        format: AmountFormat,
        /// The JSON pointer of the member that holds the currency, when the body holds one;
        /// the contract must fix it to the payment's currency.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        currency_at: Option<String>,
    },
    /// A field of the caller's form body, checked by the body contract of the request.
    Form {
        /// The field name, as in the body contract.
        name: String,
        /// How the amount is written.
        #[serde(default, skip_serializing_if = "AmountFormat::is_minor")]
        format: AmountFormat,
        /// The field that holds the currency, when the body holds one; the contract must fix
        /// it to the payment's currency.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        currency_at: Option<String>,
    },
    /// A fixed amount the policy states.
    Fixed {
        /// A decimal integer, in minor units.
        value: String,
    },
}

/// How an amount in a body is written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountFormat {
    /// An integer of minor units (`1250` for 12.50 EUR): a JSON number or string, or a form
    /// field, bounded by the contract's `min` and `max`.
    #[default]
    Minor,
    /// A decimal of major units with exactly `exponent` digits after the point (`"12.50"`;
    /// no point when the exponent is 0): a JSON string or a form field, never a JSON number,
    /// which many servers read as binary floating point.
    Decimal,
}

impl AmountFormat {
    /// True for [`AmountFormat::Minor`], the default.
    pub fn is_minor(&self) -> bool {
        *self == AmountFormat::Minor
    }
}

/// Largest amount, in minor units, that a JSON number may carry: 2^53 - 1, the largest
/// integer every JSON parser that reads numbers as binary floating point reads exactly.
pub const MAX_JSON_NUMBER_AMOUNT: u64 = (1 << 53) - 1;

/// Reads an amount of a body, as the node checked and sends it, into minor units: an integer
/// written `0|[1-9][0-9]*`, or for [`AmountFormat::Decimal`] that and, when `exponent` is not
/// 0, a point and exactly `exponent` digits. No sign, exponent, space or other form; at most
/// [`MAX_AMOUNT`], and [`MAX_JSON_NUMBER_AMOUNT`] for a JSON number.
pub fn read_amount(text: &str, number: bool, format: AmountFormat, exponent: u8) -> Option<u64> {
    let canonical = |digits: &str| {
        !digits.is_empty()
            && digits.len() <= 19
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
    };
    let minor: u64 = match format {
        AmountFormat::Minor => {
            if !canonical(text) {
                return None;
            }
            text.parse().ok()?
        }
        AmountFormat::Decimal => {
            if number {
                return None;
            }
            let (whole, fraction) = match text.split_once('.') {
                Some((w, f)) => (w, Some(f)),
                None => (text, None),
            };
            let places = usize::from(exponent);
            let fraction = match (fraction, places) {
                (None, 0) => "",
                (Some(f), p) if p > 0 && f.len() == p && f.bytes().all(|b| b.is_ascii_digit()) => f,
                _ => return None,
            };
            if !canonical(whole) {
                return None;
            }
            let whole: u64 = whole.parse().ok()?;
            let fraction: u64 = if fraction.is_empty() {
                0
            } else {
                fraction.parse().ok()?
            };
            whole
                .checked_mul(10u64.checked_pow(u32::from(exponent))?)?
                .checked_add(fraction)?
        }
    };
    let most = if number {
        MAX_JSON_NUMBER_AMOUNT
    } else {
        MAX_AMOUNT
    };
    (minor <= most).then_some(minor)
}

/// What an operation pays: the amount, in minor units of `currency`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    /// Where the amount is read, an integer in minor units (cents for EUR).
    pub amount: AmountSource,
    /// The ISO 4217 code, fixed by the policy.
    pub currency: String,
    /// Digits after the decimal point of the currency: 2 for EUR, 0 for JPY (at most 8).
    pub exponent: u8,
}

/// How an expired session is renewed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "by", rename_all = "snake_case", deny_unknown_fields)]
pub enum Renew {
    /// The node runs this operation of the policy first (a login with the stored password,
    /// whose response fills the session field), then the operation that was asked for.
    Operation {
        /// The operation.
        name: String,
    },
    /// The owner logs in on the device, and the app seals the new session into the item.
    Owner {},
}

/// A secret field that holds a session the node obtained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRule {
    /// How long a session lasts once a response filled it, in milliseconds (at most 30 days).
    pub lifetime_ms: u64,
    /// The public, optional field the node writes the expiry into (Unix milliseconds).
    pub expires: String,
    /// How it is renewed.
    pub renew: Renew,
}

/// True for a text an owner wrote for another person to read: 1 to `max` bytes, no control
/// characters.
pub(crate) fn is_plain_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

/// True for an ISO 4217 code: three uppercase letters.
pub(crate) fn is_currency(code: &str) -> bool {
    code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase())
}

impl Poll {
    /// The method and path of the fixed request, when it is one.
    pub(crate) fn fixed(&self) -> Option<(Method, &str, Option<&Destination>)> {
        match &self.send.request {
            Some(StepRequest::Fixed {
                method,
                path,
                destination,
            }) => Some((*method, path.as_str(), destination.as_ref())),
            _ => None,
        }
    }
}

impl Condition {
    /// Why the condition is invalid, if it is.
    pub(crate) fn fault(&self) -> Option<&'static str> {
        if let Some(rule) = self.source.rule(false) {
            return Some(rule);
        }
        if self.one_of.is_empty()
            || self.one_of.len() > MAX_CONDITION_VALUES
            || !self.one_of.iter().all(|v| v.len() <= MAX_HINT)
        {
            return Some("a condition compares with 1 to 16 values of at most 256 bytes");
        }
        None
    }

    /// True when the captured value is one of the values.
    pub(crate) fn holds(&self, value: Option<&[u8]>) -> bool {
        value.is_some_and(|v| self.one_of.iter().any(|w| w.as_bytes() == v))
    }
}

impl SessionRule {
    /// Why the rule is invalid in itself, if it is.
    pub(crate) fn fault(&self) -> Option<&'static str> {
        if self.lifetime_ms < 1000 || self.lifetime_ms > MAX_SESSION_MS {
            return Some("a session lasts 1 second to 30 days");
        }
        if !is_token(&self.expires) {
            return Some("expires names a field");
        }
        if let Renew::Operation { name } = &self.renew
            && !is_token(name)
        {
            return Some("renew names an operation");
        }
        None
    }
}
