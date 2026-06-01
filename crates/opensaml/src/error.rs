//! Error types for `opensaml`.

/// Errors produced by the `opensaml` Service Provider library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenSamlError {
    /// Raw DEFLATE (de)compression failed.
    #[error("deflate error: {0}")]
    Deflate(#[from] std::io::Error),
    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Malformed or unexpected XML.
    #[error("xml error: {0}")]
    Xml(String),
    /// Input failed validation.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// Functionality not yet implemented in the current milestone.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Issuer in the message does not match the one declared in metadata.
    #[error("ERR_UNMATCH_ISSUER")]
    UnmatchIssuer,
    /// Response carried an undefined `<StatusCode>`.
    #[error("ERR_UNDEFINED_STATUS")]
    UndefinedStatus,
    /// Response carried a non-success status (two-tier code).
    #[error("ERR_FAILED_STATUS with top tier code: {top}, second tier code: {second}")]
    FailedStatus {
        /// Top-tier status code.
        top: String,
        /// Second-tier status code (empty when absent).
        second: String,
    },
    /// `SessionNotOnOrAfter` has elapsed.
    #[error("ERR_EXPIRED_SESSION")]
    ExpiredSession,
    /// Assertion `<Conditions>` time window is invalid.
    #[error("ERR_SUBJECT_UNCONFIRMED")]
    SubjectUnconfirmed,
    /// A signature-wrapping (XSW) attempt was detected.
    #[error("ERR_POTENTIAL_WRAPPING_ATTACK")]
    PotentialWrappingAttack,
    /// Signed redirect/simpleSign message is missing `Signature`/`SigAlg`.
    #[error("ERR_MISSING_SIG_ALG")]
    MissingSigAlg,
    /// Detached (redirect/simpleSign) message signature failed verification.
    #[error("ERR_FAILED_MESSAGE_SIGNATURE_VERIFICATION")]
    FailedMessageSignatureVerification,
    /// XML-DSig signature failed verification.
    #[error("FAILED_TO_VERIFY_SIGNATURE")]
    FailedToVerifySignature,
    /// Certificate in the message does not match the metadata declaration.
    #[error("ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA")]
    UnmatchCertificate,
    /// Requested protocol binding is not supported.
    #[error("ERR_UNDEFINED_BINDING")]
    UndefinedBinding,
    /// Required metadata (endpoint/certificate) was missing.
    #[error("missing metadata: {0}")]
    MissingMetadata(String),
    /// A required cryptographic key was missing.
    #[error("missing key: {0}")]
    MissingKey(String),
    /// A delegated cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}
