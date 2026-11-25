//! The errors of the engine. Every failure is a variant; no error carries a secret.

use core::fmt;

/// What went wrong in a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// The connection could not be made.
    Connect,
    /// The TLS handshake failed (certificate, client identity, protocol).
    Tls,
    /// A deadline passed.
    Timeout,
    /// Reading or writing failed.
    Io,
    /// The peer sent more than the engine accepts.
    TooLarge,
    /// The peer closed the connection.
    Closed,
    /// The transport cannot do this (for example, no streams).
    Unsupported,
}

/// A failure of a [`crate::egress::Transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportFault {
    /// What went wrong.
    pub kind: TransportKind,
    /// True when some bytes of the request may have reached the destination, so a retry of a
    /// request that is not idempotent can repeat it.
    pub sent: bool,
}

impl fmt::Display for TransportFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (sent: {})", self.kind, self.sent)
    }
}

/// An error of the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No grant of the owner is in force on this node.
    #[error("no grant in force for this owner")]
    NoGrant,
    /// The grant of the owner ended.
    #[error("grant expired")]
    GrantExpired,
    /// A sealed grant or a revocation is malformed, not for this node, or stale.
    #[error("grant invalid: {rule}")]
    GrantInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The device that signed a grant or a revocation is not one this node knows for the
    /// owner.
    #[error("device not known for this owner")]
    GrantDenied,
    /// The policy breaks a rule. `at` is the path of the part, such as
    /// `operations[0].steps[1].inject[2]`.
    #[error("policy invalid at {at}: {rule}")]
    PolicyInvalid {
        /// Where.
        at: String,
        /// Which rule.
        rule: &'static str,
    },
    /// The signature of a policy, pin or endorsement does not verify under a device of the
    /// grant.
    #[error("policy signature invalid")]
    PolicySignature,
    /// A key could not be read.
    #[error("key invalid")]
    KeyInvalid,
    /// The fields of a record are malformed.
    #[error("record invalid")]
    RecordInvalid,
    /// The record did not decrypt under the user key of the grant.
    #[error("record could not be opened")]
    RecordOpen,
    /// No device of the owner pinned this record on this node (in a grant or with a pin), so
    /// the node cannot tell whether it is the newest.
    #[error("record not pinned by its owner")]
    RecordUnpinned,
    /// The record is older than one this node saw or the owner pinned (a rollback).
    #[error("record generation {have} is older than {need}")]
    RecordStale {
        /// The generation of the record given.
        have: u64,
        /// The lowest generation accepted.
        need: u64,
    },
    /// A rendered value does not fit its target.
    #[error("rendered value invalid for its target")]
    SecretInvalid,
    /// A template does not parse; `offset` is the byte where parsing stopped.
    #[error("template syntax error at byte {offset}")]
    TemplateSyntax {
        /// Byte offset in the template.
        offset: usize,
    },
    /// A template failed while rendering (bad input to a function, missing variable).
    #[error("template failed: {rule}")]
    TemplateInvalid {
        /// What failed.
        rule: &'static str,
    },
    /// A rendering used more than its budget (bytes, key-derivation rounds, signatures).
    #[error("render budget exceeded: {what}")]
    Budget {
        /// Which budget.
        what: &'static str,
    },
    /// A field the policy needs is missing, or the record holds a field the policy does not
    /// list.
    #[error("record fields do not match the policy")]
    FieldMissing,
    /// The request breaks a rule of the operation.
    #[error("request invalid: {rule}")]
    RequestInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The caller is not one the policy lists for this operation.
    #[error("caller not allowed")]
    CallerDenied,
    /// The authorization of the caller does not verify, is too old, or was seen before.
    #[error("caller authorization invalid: {rule}")]
    CallerInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The operation reached its rate limit.
    #[error("rate limit reached")]
    RateLimited,
    /// The destination of the request is not one of the operation.
    #[error("destination not allowed by policy")]
    DestinationDenied,
    /// The method of the request is not one of the operation.
    #[error("method not allowed by policy")]
    MethodDenied,
    /// The path of the request is not under a path of the operation.
    #[error("path not allowed by policy")]
    PathDenied,
    /// The policy has no operation of this name, or of this kind.
    #[error("operation unknown")]
    OperationUnknown,
    /// A capture the policy requires found nothing in the response.
    #[error("captured value missing from the response")]
    CaptureMissing,
    /// A response could not be read, or is of a form the engine refuses.
    #[error("response invalid: {rule}")]
    ResponseInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The log sink did not confirm the entry. The act did not happen.
    #[error("log sink did not confirm the entry")]
    LogUnconfirmed,
    /// An earlier entry was not confirmed; the log refuses further entries until
    /// [`crate::log::Log::reconcile`].
    #[error("log halted after an unconfirmed entry")]
    LogHalted,
    /// The entry given to resume or reconcile a log does not fit its state.
    #[error("log state does not match the entry given")]
    LogMismatch,
    /// The chain of entries is broken at this sequence number.
    #[error("log chain broken at seq {seq}")]
    ChainBroken {
        /// The first sequence number that does not follow.
        seq: u64,
    },
    /// The signature of the entry at this sequence number does not verify.
    #[error("log entry signature invalid at seq {seq}")]
    EntrySignature {
        /// The sequence number of the entry.
        seq: u64,
    },
    /// The response holds a secret in a form the search knows. It was dropped.
    #[error("response reflects a secret")]
    Reflection,
    /// The transport failed.
    #[error("transport failed: {0}")]
    Transport(TransportFault),
    /// Encoding or decoding failed.
    #[error("encoding failed")]
    Encoding,
}

impl Error {
    /// A policy error at `at`.
    pub(crate) fn policy(at: impl Into<String>, rule: &'static str) -> Self {
        Error::PolicyInvalid {
            at: at.into(),
            rule,
        }
    }

    /// A transport error.
    pub fn transport(kind: TransportKind, sent: bool) -> Self {
        Error::Transport(TransportFault { kind, sent })
    }

    /// True when the same call may succeed later without any change (time, network).
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Transport(fault) => !fault.sent,
            Error::RateLimited | Error::LogUnconfirmed => true,
            _ => false,
        }
    }

    /// True when the caller asked for something the policy does not allow, or sent a bad
    /// request; a retry of the same call fails the same way.
    pub fn is_caller_error(&self) -> bool {
        matches!(
            self,
            Error::CallerDenied
                | Error::CallerInvalid { .. }
                | Error::DestinationDenied
                | Error::MethodDenied
                | Error::PathDenied
                | Error::OperationUnknown
                | Error::RequestInvalid { .. }
        )
    }
}

/// The result type of the engine.
pub type Result<T> = core::result::Result<T, Error>;
