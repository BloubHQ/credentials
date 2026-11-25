//! The errors of the engine. Every failure is a variant; no error carries a secret.

/// An error of the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// No grant of the owner is in force on this node.
    #[error("no grant in force for this owner")]
    NoGrant,
    /// The grant of the owner ended.
    #[error("grant expired")]
    GrantExpired,
    /// The policy does not satisfy its rules.
    #[error("policy invalid")]
    PolicyInvalid,
    /// The signature of the policy does not verify under the device key of the grant.
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
    /// A rendered value does not fit its target.
    #[error("rendered value invalid for its target")]
    SecretInvalid,
    /// A template does not parse or reads what it may not.
    #[error("template invalid")]
    TemplateInvalid,
    /// A field the policy names is missing, or the record holds another set of fields.
    #[error("record fields do not match the policy")]
    FieldMissing,
    /// The request is malformed or names a header the engine sets itself.
    #[error("request invalid")]
    RequestInvalid,
    /// The destination of the request is not one of the policy.
    #[error("destination not allowed by policy")]
    DestinationDenied,
    /// The method of the request is not one of the policy.
    #[error("method not allowed by policy")]
    MethodDenied,
    /// The policy has no operation of this name, or of this kind.
    #[error("operation unknown")]
    OperationUnknown,
    /// A capture the policy requires found nothing in the response.
    #[error("captured value missing from the response")]
    CaptureMissing,
    /// A response could not be parsed.
    #[error("response invalid")]
    ResponseInvalid,
    /// The log sink did not confirm the entry. The act did not happen.
    #[error("log sink did not confirm the entry")]
    LogUnconfirmed,
    /// An earlier entry was not confirmed; the log refuses further entries until it is
    /// reconciled.
    #[error("log halted after an unconfirmed entry")]
    LogHalted,
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
    /// The response holds the secret in a form the search knows. It was dropped.
    #[error("response reflects the secret")]
    Reflection,
    /// The transport failed to deliver the request or to read the response.
    #[error("transport failed")]
    Transport,
    /// Encoding or decoding failed.
    #[error("encoding failed")]
    Encoding,
}

/// The result type of the engine.
pub type Result<T> = core::result::Result<T, Error>;
