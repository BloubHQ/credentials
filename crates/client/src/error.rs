//! The one error type of the client, with a stable code for the bindings.

/// Why a function of the client failed.
///
/// Each variant has a stable code ([`ClientError::code`]): in Swift and Kotlin the variant is
/// the case of the error enum, in JavaScript the `code` property of the thrown `Error`. The
/// `detail` is a message for people; it never holds a secret and may change between releases.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(not(target_arch = "wasm32"), derive(uniffi::Error))]
#[non_exhaustive]
pub enum ClientError {
    /// A key is not 32 bytes as unpadded base64url, or not a valid key of its kind.
    #[error("invalid key: {detail}")]
    InvalidKey {
        /// What is wrong.
        detail: String,
    },
    /// An argument is malformed: JSON that does not parse, an empty owner, a zero lifetime.
    #[error("invalid input: {detail}")]
    InvalidInput {
        /// What is wrong.
        detail: String,
    },
    /// The nonce was already used for a verification, or is older than five minutes.
    #[error("nonce rejected: {detail}")]
    NonceRejected {
        /// What is wrong.
        detail: String,
    },
    /// The list of accepted measurements does not parse or is empty.
    #[error("measurements invalid: {detail}")]
    MeasurementsInvalid {
        /// What is wrong.
        detail: String,
    },
    /// The attestation document was refused: structure, certificate chain, signature, nonce,
    /// a debug enclave, or measurements no accepted release has.
    #[error("attestation refused ({reason}): {detail}")]
    AttestationRefused {
        /// A stable code of the check that failed, such as `nonce_mismatch` or
        /// `unknown_measurement`.
        reason: String,
        /// What is wrong.
        detail: String,
    },
    /// The attestation document verifies but does not vouch for the node identity given: its
    /// user data is not the report data of that identity.
    #[error("binding mismatch: {detail}")]
    BindingMismatch {
        /// What is wrong.
        detail: String,
    },
    /// The node was verified more than five minutes ago: verify it again before a grant.
    #[error("verification expired: {detail}")]
    VerificationExpired {
        /// What is wrong.
        detail: String,
    },
    /// The engine refused: a policy that breaks a rule, a record that is invalid, too many
    /// pins.
    #[error("refused: {detail}")]
    Refused {
        /// What is wrong.
        detail: String,
    },
    /// A successor statement, or the node it was checked for, was refused; `reason` is a
    /// stable code of the check that failed (`downgrade`, `not_for_this_release`,
    /// `signer_mismatch`, `chain_untrusted`, `log_proof_invalid`, ...).
    #[error("successor refused ({reason}): {detail}")]
    SuccessorRefused {
        /// The stable code of the failed check.
        reason: String,
        /// What is wrong.
        detail: String,
    },
    /// A device transfer was refused: a wrong code, a changed message, too many attempts, or
    /// a transfer that expired.
    #[error("transfer refused: {detail}")]
    TransferRefused {
        /// What is wrong.
        detail: String,
    },
    /// A key backup cannot be opened: another backup key, another owner, or a changed blob.
    #[error("backup refused: {detail}")]
    BackupRefused {
        /// What is wrong.
        detail: String,
    },
}

impl ClientError {
    /// The stable code of the error, in snake case.
    pub fn code(&self) -> &'static str {
        match self {
            ClientError::InvalidKey { .. } => "invalid_key",
            ClientError::InvalidInput { .. } => "invalid_input",
            ClientError::NonceRejected { .. } => "nonce_rejected",
            ClientError::MeasurementsInvalid { .. } => "measurements_invalid",
            ClientError::AttestationRefused { .. } => "attestation_refused",
            ClientError::BindingMismatch { .. } => "binding_mismatch",
            ClientError::VerificationExpired { .. } => "verification_expired",
            ClientError::Refused { .. } => "refused",
            ClientError::SuccessorRefused { .. } => "successor_refused",
            ClientError::TransferRefused { .. } => "transfer_refused",
            ClientError::BackupRefused { .. } => "backup_refused",
        }
    }

    pub(crate) fn key(detail: impl Into<String>) -> Self {
        ClientError::InvalidKey {
            detail: detail.into(),
        }
    }

    pub(crate) fn input(detail: impl Into<String>) -> Self {
        ClientError::InvalidInput {
            detail: detail.into(),
        }
    }

    /// A JSON argument named `what` that does not parse.
    pub(crate) fn json(what: &str) -> impl FnOnce(serde_json::Error) -> Self + '_ {
        move |e| ClientError::input(format!("{what}: {e}"))
    }

    /// An engine error, with what the client was doing.
    pub(crate) fn engine(context: &str) -> impl FnOnce(engine::Error) -> Self + '_ {
        move |e| match e {
            engine::Error::KeyInvalid => ClientError::key(format!("{context}: {e}")),
            other => ClientError::Refused {
                detail: format!("{context}: {other}"),
            },
        }
    }
}

/// The stable reason code of a refused attestation document.
fn reason(error: &attest::Error) -> &'static str {
    match error {
        attest::Error::DocumentTooLarge => "document_too_large",
        attest::Error::NotCbor => "not_cbor",
        attest::Error::NotCoseSign1(_) => "not_cose_sign1",
        attest::Error::UnsupportedAlgorithm => "unsupported_algorithm",
        attest::Error::PayloadInvalid(_) => "payload_invalid",
        attest::Error::UnsupportedDigest(_) => "unsupported_digest",
        attest::Error::EmptyCaBundle => "empty_ca_bundle",
        attest::Error::CertificateInvalid(_) => "certificate_invalid",
        attest::Error::RootInvalid(_) => "root_invalid",
        attest::Error::CertificateNotValidAt { .. } => "certificate_not_valid_at",
        attest::Error::ChainUntrusted(_) => "chain_untrusted",
        attest::Error::LeafKeyNotP384 => "leaf_key_not_p384",
        attest::Error::SignatureInvalid => "signature_invalid",
        attest::Error::NonceEmpty => "nonce_empty",
        attest::Error::NonceMismatch => "nonce_mismatch",
        attest::Error::PcrMissing(_) => "pcr_missing",
        attest::Error::DebugEnclave => "debug_enclave",
        attest::Error::UnknownMeasurement => "unknown_measurement",
        _ => "other",
    }
}

impl From<attest::Error> for ClientError {
    fn from(error: attest::Error) -> Self {
        match error {
            attest::Error::Measurements(_) => ClientError::MeasurementsInvalid {
                detail: error.to_string(),
            },
            attest::Error::BindingMismatch => ClientError::BindingMismatch {
                detail: error.to_string(),
            },
            other => ClientError::AttestationRefused {
                reason: reason(&other).to_string(),
                detail: other.to_string(),
            },
        }
    }
}

/// The result type of the client.
pub type Result<T> = std::result::Result<T, ClientError>;
