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
    /// The server agreed on an HTTP version the policy does not allow (it pins HTTP/2 and the
    /// server chose HTTP/1.1, or the reverse).
    Downgrade,
    /// The peer broke the framing of HTTP/2 or of a WebSocket (a malformed frame, a header
    /// block HPACK cannot decode, a forbidden header).
    Protocol,
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
    /// A kind schema breaks a rule. `at` is the path of the part, such as `fields[2].checks[0]`.
    #[error("kind invalid at {at}: {rule}")]
    KindInvalid {
        /// Where.
        at: String,
        /// Which rule.
        rule: &'static str,
    },
    /// The signature of a custom kind does not verify under a device of the owner.
    #[error("kind signature invalid")]
    KindSignature,
    /// A value of a typed item fails a check of its kind. `field` is its name (names are not
    /// secret; the value is never part of the error).
    #[error("field {field} invalid: {rule}")]
    FieldInvalid {
        /// The field.
        field: String,
        /// Which rule.
        rule: &'static str,
    },
    /// An approval does not fit the summary the node built, or the summary is malformed.
    #[error("approval invalid: {rule}")]
    ApprovalInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The operation waits for a challenge or the owner's approval. [`crate::node::Node::run`]
    /// hands back its id; the typed entry points (`http`, `stream`, `derive`) cannot.
    #[error("the operation waits for a challenge or an approval: run it with Node::run")]
    Pending,
    /// No operation waits under this id for this caller, record and operation: it ended,
    /// lapsed, was never there, or waits for another caller.
    #[error("no operation waits under this id for this caller")]
    ParkedUnknown,
    /// Too many operations wait for the owner, or for all owners of the node.
    #[error("too many operations wait for an answer or an approval")]
    ParkedFull,
    /// A challenge ended without an answer the operation can go on with.
    #[error("challenge failed: {rule}")]
    ChallengeFailed {
        /// Why.
        rule: &'static str,
    },
    /// An answer to a challenge is malformed, not for a waiting challenge, or not signed by a
    /// device of the owner.
    #[error("challenge answer invalid: {rule}")]
    AnswerInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// A session field has expired and its rule says the owner renews it on the device.
    /// `field` is its name (the value is never part of the error).
    #[error("session {field} expired: the owner logs in again on the device")]
    SessionExpired {
        /// The field.
        field: String,
    },
    /// Spending limits are malformed, not for this node, or stale.
    #[error("spending limits invalid: {rule}")]
    LimitsInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// A delegation, or a change of one, is malformed, not for this node, not signed by a
    /// known device of the owner, stale, or carries a policy wider than the record's.
    #[error("delegation invalid: {rule}")]
    DelegationInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// No delegation of this id is in force for the record: it was never given, ended,
    /// lapsed, was revoked, its device was withdrawn, or the record's policy changed since.
    #[error("no delegation of this id is in force for the record")]
    DelegationUnknown,
    /// Emergency access waits: the owner may still cancel it. `opens_ms` is when it opens.
    #[error("emergency access waits until {opens_ms} (Unix ms); the owner may cancel it")]
    DelegationWaiting {
        /// When the waiting period ends, Unix milliseconds.
        opens_ms: u64,
    },
    /// A vending operation was refused: the credential it minted would outlive the policy's
    /// lifetime, or its expiry could not be read. Nothing of it went back.
    #[error("vend refused: {rule}")]
    VendRefused {
        /// Which rule.
        rule: &'static str,
    },
    /// The record has no kind, so there is nothing a caller may be told of it.
    #[error("the record is not a typed item")]
    NotAnItem,
    /// A key could not be read.
    #[error("key invalid")]
    KeyInvalid,
    /// A signature does not verify under the key it was checked with.
    #[error("signature does not verify")]
    SignatureInvalid,
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
    /// list. `field` is its name (names are not secret).
    #[error("record fields do not match the policy: {field}")]
    FieldMissing {
        /// The field missing, or not listed.
        field: String,
    },
    /// The request breaks a rule of the operation.
    #[error("request invalid: {rule}")]
    RequestInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The caller's input breaks the input schema of the operation.
    #[error("input invalid: {rule}")]
    InputInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The caller is not one the policy lists, or not for this operation. Names are not
    /// secret; `operation` is empty when the caller is unknown to the policy.
    #[error("caller {caller} not allowed{}", if operation.is_empty() { String::new() } else { format!(" to call {operation}") })]
    CallerDenied {
        /// The caller named in the authorization.
        caller: String,
        /// The operation asked for.
        operation: String,
    },
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
    #[error("destination {host} not allowed by policy")]
    DestinationDenied {
        /// The destination asked for, `host:port`.
        host: String,
    },
    /// The method of the request is not one of the operation.
    #[error("method {method} not allowed by policy")]
    MethodDenied {
        /// The method asked for.
        method: String,
    },
    /// The path of the request is not under a path of the operation.
    #[error("path {path} not allowed by policy")]
    PathDenied {
        /// The path asked for, without its query.
        path: String,
    },
    /// The policy has no operation of this name, or of this kind.
    #[error("operation {name} unknown, or not of this kind")]
    OperationUnknown {
        /// The operation asked for.
        name: String,
    },
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
    /// The log given to [`crate::node::Node::restore_anchored`] is shorter than the checkpoint,
    /// or does not end in the entry it covers: entries were cut or replaced.
    #[error(
        "log has {len} entries but the checkpoint covers {anchor}: entries were cut or replaced"
    )]
    LogBehindAnchor {
        /// Entries in the log given.
        len: u64,
        /// Entries the checkpoint covers.
        anchor: u64,
    },
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
    /// This node handed its state over to a successor: it takes no act any more.
    #[error("this node handed over to its successor and takes no act")]
    HandedOver,
    /// A hand-over was refused: the package, its entry or the state of the node.
    #[error("hand-over refused: {rule}")]
    HandOverInvalid {
        /// Which rule.
        rule: &'static str,
    },
    /// The response holds a secret in a form the search knows. It was dropped.
    #[error("response reflects a secret")]
    Reflection,
    /// A frame of the caller on a live connection was refused: its signature or sequence
    /// number is wrong, or it matches no shape the policy declares.
    #[error("frame refused: {rule}")]
    FrameRefused {
        /// Which rule.
        rule: &'static str,
    },
    /// Too many live connections (streams, WebSockets) are open for the caller, the owner or
    /// the node.
    #[error("too many live connections are open: {who}")]
    StreamsFull {
        /// `caller`, `owner` or `node`.
        who: &'static str,
    },
    /// A browser fill was refused: the page is not at the policy's origin, it changed
    /// between the check and the fill, another client is attached to it, an element is
    /// missing or ambiguous, or the browser answered what the protocol or the node's bounds do
    /// not allow. The text is fixed: nothing the browser or the page sent is in it.
    #[error("fill refused: {rule}")]
    FillRefused {
        /// Which rule.
        rule: &'static str,
    },
    /// The module of a `run` step was refused: its origin did not answer 200, it is too
    /// large, it does not match its pin, or the library is unknown.
    #[error("module refused: {rule}")]
    ModuleRefused {
        /// Which rule.
        rule: &'static str,
    },
    /// The sandbox stopped a `run` step. The message is fixed: nothing the module computed.
    #[error("sandbox: {0}")]
    Sandbox(sandbox::Error),
    /// The server of a protocol connection (SSH, a database, mail, a queue) is not the one the
    /// policy trusts, or offered less than it requires: a host key that is not pinned, no
    /// algorithm or authentication mechanism the node accepts, no TLS where it is required.
    /// Nothing secret was sent to it.
    #[error("server not trusted: {rule}")]
    ServerUntrusted {
        /// Which rule.
        rule: &'static str,
    },
    /// The server of a protocol connection refused the node's credentials.
    #[error("authentication refused: {rule}")]
    AuthRefused {
        /// Which rule.
        rule: &'static str,
    },
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
            Error::RateLimited
            | Error::LogUnconfirmed
            | Error::ParkedFull
            | Error::StreamsFull { .. } => true,
            _ => false,
        }
    }

    /// True when the caller asked for something the policy does not allow, or sent a bad
    /// request; a retry of the same call fails the same way.
    pub fn is_caller_error(&self) -> bool {
        matches!(
            self,
            Error::CallerDenied { .. }
                | Error::CallerInvalid { .. }
                | Error::DestinationDenied { .. }
                | Error::MethodDenied { .. }
                | Error::PathDenied { .. }
                | Error::OperationUnknown { .. }
                | Error::RequestInvalid { .. }
                | Error::InputInvalid { .. }
                | Error::ParkedUnknown
                | Error::DelegationUnknown
                | Error::FrameRefused { .. }
        )
    }
}

/// The result type of the engine.
pub type Result<T> = core::result::Result<T, Error>;
