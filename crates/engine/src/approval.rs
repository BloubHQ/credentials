//! Approvals: the owner's device signs what the node is about to do.
//!
//! An operation that needs the owner's approval (a payment, or whatever the owner marks) is
//! described by the node in an [`ApprovalSummary`]: the node, the record and generation, the
//! caller and operation, the destination and origin, the amount, the item's masked view
//! ([`crate::item::Description`]) and plain lines, with a random id and a deadline. The node
//! builds it; the caller never writes any part of it. The owner's device shows it and signs an
//! [`Approval`] over the SHA-256 of its canonical bytes ([`ApprovalSummary::sha256`]), and the
//! node checks the approval against the summary it built ([`Approval::verify`]).
//!
//! The node parking the operation until the approval arrives, and refusing an id used twice,
//! is the runtime of challenges and approvals (`docs/design.md` section 5), a later part.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::encoding::{b64_array, canonical};
use crate::item::Description;
use crate::keys::{DeviceKey, DevicePublicKey, NodePublicKey};
use crate::policy::is_token;
use crate::record::check_name;
use crate::{Error, Result};

const SUMMARY_DOMAIN: &[u8] = b"approval-summary/v1\0";
const APPROVAL_DOMAIN: &[u8] = b"approval/v1\0";

/// Longest time an approval may stay open: five minutes, as a parked operation.
pub const MAX_APPROVAL_MS: u64 = 5 * 60 * 1000;
/// Most lines of a summary.
pub const MAX_LINES: usize = 32;
/// Longest line of a summary, in bytes.
pub const MAX_LINE: usize = 256;

/// An amount of money.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Amount {
    /// A decimal number: digits, and at most one `.` followed by 1 to 8 digits.
    pub value: String,
    /// An ISO 4217 code: three uppercase letters.
    pub currency: String,
}

impl Amount {
    fn is_valid(&self) -> bool {
        let (whole, fraction) = match self.value.split_once('.') {
            Some((w, f)) => (w, Some(f)),
            None => (self.value.as_str(), None),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        digits(whole)
            && whole.len() <= 20
            && (whole == "0" || !whole.starts_with('0'))
            && fraction.is_none_or(|f| digits(f) && f.len() <= 8)
            && self.currency.len() == 3
            && self.currency.bytes().all(|b| b.is_ascii_uppercase())
    }
}

/// What the node asks the owner to approve. Built by the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSummary {
    /// Random, chosen by the node.
    #[serde(with = "b64_array")]
    pub id: [u8; 16],
    /// The node that asks.
    pub node: NodePublicKey,
    /// The owner.
    pub owner: String,
    /// The record.
    pub record_id: String,
    /// Its generation.
    pub generation: u64,
    /// The caller that asked for the operation.
    pub caller: String,
    /// The operation.
    pub operation: String,
    /// Where the operation connects, `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// The origin the item is used for (a merchant), when the node knows one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The amount, for a payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>,
    /// The item's public fields and masked projections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<Description>,
    /// What else the owner should read, one line each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<String>,
    /// When the node made it, Unix milliseconds.
    pub created_ms: u64,
    /// When it lapses, Unix milliseconds: at most five minutes later.
    pub expires_ms: u64,
}

fn invalid(rule: &'static str) -> Error {
    Error::ApprovalInvalid { rule }
}

impl ApprovalSummary {
    /// Checks the form of the summary.
    pub fn validate(&self) -> Result<()> {
        check_name(&self.owner)?;
        check_name(&self.record_id)?;
        if !is_token(&self.caller)
            || !(is_token(&self.operation) || self.operation.starts_with(':'))
        {
            return Err(invalid("caller and operation are names"));
        }
        if self.expires_ms <= self.created_ms || self.expires_ms - self.created_ms > MAX_APPROVAL_MS
        {
            return Err(invalid("an approval lasts at most five minutes"));
        }
        if self.amount.as_ref().is_some_and(|a| !a.is_valid()) {
            return Err(invalid(
                "an amount is a decimal number and an ISO 4217 code",
            ));
        }
        let text_ok = |s: &str| s.len() <= MAX_LINE && !s.chars().any(char::is_control);
        if self.lines.len() > MAX_LINES
            || !self.lines.iter().all(|l| text_ok(l))
            || !self.destination.as_deref().is_none_or(text_ok)
            || !self.origin.as_deref().is_none_or(text_ok)
        {
            return Err(invalid(
                "at most 32 lines of 256 bytes, without control characters",
            ));
        }
        Ok(())
    }

    /// The SHA-256 of the canonical bytes of the summary: what the owner's device signs.
    pub fn sha256(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(canonical(SUMMARY_DOMAIN, self)?).into())
    }
}

/// The owner's approval of one summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// The id of the summary.
    #[serde(with = "b64_array")]
    pub id: [u8; 16],
    /// The SHA-256 of the summary.
    #[serde(with = "b64_array")]
    pub summary_sha256: [u8; 32],
    /// The device that approved.
    pub device: DevicePublicKey,
    /// When it approved, Unix milliseconds.
    pub issued_ms: u64,
    /// Ed25519 signature of the device.
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

#[derive(Serialize)]
struct Signed<'a> {
    node: &'a NodePublicKey,
    owner: &'a str,
    record_id: &'a str,
    #[serde(with = "b64_array")]
    id: [u8; 16],
    #[serde(with = "b64_array")]
    summary_sha256: [u8; 32],
    device: &'a DevicePublicKey,
    issued_ms: u64,
}

impl Approval {
    fn message(&self, summary: &ApprovalSummary) -> Result<Vec<u8>> {
        canonical(
            APPROVAL_DOMAIN,
            &Signed {
                node: &summary.node,
                owner: &summary.owner,
                record_id: &summary.record_id,
                id: self.id,
                summary_sha256: self.summary_sha256,
                device: &self.device,
                issued_ms: self.issued_ms,
            },
        )
    }

    /// Checks the approval against the summary the node built: the same id and hash, for this
    /// node, signed by a known device of the owner while the summary was open, and not after
    /// it lapsed (`now_ms`).
    pub fn verify(
        &self,
        summary: &ApprovalSummary,
        node: &NodePublicKey,
        devices: &[DevicePublicKey],
        now_ms: u64,
    ) -> Result<()> {
        summary.validate()?;
        if summary.node != *node {
            return Err(invalid("the summary is for another node"));
        }
        if self.id != summary.id || self.summary_sha256 != summary.sha256()? {
            return Err(invalid("the approval is for another summary"));
        }
        if !devices.contains(&self.device) {
            return Err(Error::GrantDenied);
        }
        if self.issued_ms < summary.created_ms
            || self.issued_ms >= summary.expires_ms
            || now_ms >= summary.expires_ms
        {
            return Err(invalid("approved outside the time the summary was open"));
        }
        self.device
            .verify(&self.message(summary)?, &self.signature)
            .map_err(|_| invalid("the signature does not verify"))
    }
}

impl DeviceKey {
    /// Approves a summary the node built, at `issued_ms`. Runs on the owner's device after the
    /// owner read the summary.
    pub fn approve(&self, summary: &ApprovalSummary, issued_ms: u64) -> Result<Approval> {
        summary.validate()?;
        let mut approval = Approval {
            id: summary.id,
            summary_sha256: summary.sha256()?,
            device: self.public(),
            issued_ms,
            signature: [0; 64],
        };
        approval.signature = self.sign(&approval.message(summary)?);
        Ok(approval)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::item::{Described, Disclosure};
    use crate::keys::NodeKey;

    fn summary(node: &NodePublicKey) -> ApprovalSummary {
        ApprovalSummary {
            id: [9; 16],
            node: *node,
            owner: "alice".into(),
            record_id: "card".into(),
            generation: 3,
            caller: "agent".into(),
            operation: "pay".into(),
            destination: Some("pay.example:443".into()),
            origin: Some("https://shop.example".into()),
            amount: Some(Amount {
                value: "12.50".into(),
                currency: "EUR".into(),
            }),
            item: Some(Description {
                kind: "card".into(),
                fields: vec![Described {
                    name: "number".into(),
                    disclosure: Disclosure::Masked,
                    value: "visa \u{2022}\u{2022}\u{2022}\u{2022}4242".into(),
                }],
            }),
            lines: vec!["one pair of shoes".into()],
            created_ms: 1_000_000,
            expires_ms: 1_000_000 + MAX_APPROVAL_MS,
        }
    }

    #[test]
    fn an_approval_verifies_only_for_its_summary_node_device_and_time() {
        let node = NodeKey::generate().public();
        let device = DeviceKey::generate();
        let devices = [device.public()];
        let s = summary(&node);
        let approval = device.approve(&s, 1_000_500).unwrap();
        approval.verify(&s, &node, &devices, 1_000_600).unwrap();

        // Any change to what the owner read breaks it: the amount, the item, a line.
        let mut other = s.clone();
        other.amount = Some(Amount {
            value: "1250".into(),
            currency: "EUR".into(),
        });
        assert!(matches!(
            approval.verify(&other, &node, &devices, 1_000_600),
            Err(Error::ApprovalInvalid { .. })
        ));
        let mut other = s.clone();
        other.lines.push("and a hat".into());
        assert!(approval.verify(&other, &node, &devices, 1_000_600).is_err());
        // Another node, an unknown device, after the deadline, before the summary.
        let elsewhere = NodeKey::generate().public();
        assert!(
            approval
                .verify(&s, &elsewhere, &devices, 1_000_600)
                .is_err()
        );
        let stranger = [DeviceKey::generate().public()];
        assert_eq!(
            approval.verify(&s, &node, &stranger, 1_000_600),
            Err(Error::GrantDenied)
        );
        assert!(approval.verify(&s, &node, &devices, s.expires_ms).is_err());
        let early = device.approve(&s, 999_999).unwrap();
        assert!(early.verify(&s, &node, &devices, 1_000_600).is_err());
        // A forged signature, or one moved to another id.
        let mut forged = approval.clone();
        forged.signature[0] ^= 1;
        assert!(forged.verify(&s, &node, &devices, 1_000_600).is_err());
        let mut moved = approval;
        moved.id = [1; 16];
        assert!(moved.verify(&s, &node, &devices, 1_000_600).is_err());
    }

    #[test]
    fn a_summary_is_checked_before_it_is_signed() {
        let node = NodeKey::generate().public();
        let device = DeviceKey::generate();
        let mut s = summary(&node);
        s.expires_ms = s.created_ms + MAX_APPROVAL_MS + 1;
        assert!(device.approve(&s, s.created_ms).is_err());
        for (value, currency) in [
            ("01", "EUR"),
            ("1.", "EUR"),
            ("1", "eur"),
            ("-1", "EUR"),
            ("1.123456789", "EUR"),
        ] {
            let mut s = summary(&node);
            s.amount = Some(Amount {
                value: value.into(),
                currency: currency.into(),
            });
            assert!(
                device.approve(&s, s.created_ms).is_err(),
                "{value} {currency}"
            );
        }
        let mut s = summary(&node);
        s.lines = vec!["a\nb".into()];
        assert!(device.approve(&s, s.created_ms).is_err());
        let s = summary(&node);
        // The hash is stable and depends on every member.
        assert_eq!(s.sha256().unwrap(), s.clone().sha256().unwrap());
        let mut t = s.clone();
        t.generation = 4;
        assert_ne!(s.sha256().unwrap(), t.sha256().unwrap());
    }
}
