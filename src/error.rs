//! Error types for `saml-rs`.
//!
//! [`SamlError`] is non-exhaustive. Callers should include a fallback match arm
//! so new semantic SAML validation failures can be added without breaking
//! source compatibility.

use crate::constants::Binding;
use crate::model::RelayStateParam;

/// Errors produced by the SAML-RS library.
///
/// Variants are grouped by validation category:
///
/// - wire and XML decoding failures;
/// - SAML protocol validation failures;
/// - signature, signed-reference, and delegated crypto failures;
/// - metadata and trust selection failures;
/// - configuration, unsupported binding, and compatibility failures.
///
/// This enum is `#[non_exhaustive]`; downstream callers should include a
/// fallback arm when matching.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    // Wire / XML errors.
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

    // Unsupported profiles and bindings.
    /// Functionality not yet implemented in the current milestone.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Requested binding is not supported by this API path.
    #[error("unsupported binding: {binding:?}")]
    UnsupportedBinding {
        /// Binding that reached an unsupported profile path.
        binding: Binding,
    },

    // SAML protocol validation.
    /// Issuer in the message does not match the expected peer entity ID.
    #[error("issuer mismatch: expected {expected}, got {actual:?}")]
    IssuerMismatch {
        /// Expected peer entity ID.
        expected: String,
        /// Actual issuer value extracted from the message, when available.
        actual: Option<String>,
    },
    /// Response `Destination` does not match the expected recipient URL.
    #[error("destination mismatch: expected {expected}, got {actual:?}")]
    DestinationMismatch {
        /// Expected recipient URL.
        expected: String,
        /// Actual destination value extracted from the message, when available.
        actual: Option<String>,
    },
    /// `InResponseTo` does not match the expected request ID.
    #[error("inResponseTo mismatch: expected {expected:?}, got {actual:?}")]
    InResponseToMismatch {
        /// Expected request ID. `None` means no request correlation was expected.
        expected: Option<String>,
        /// Actual `InResponseTo` value extracted from the message, when available.
        actual: Option<String>,
    },
    /// RelayState does not match the pending message correlation state.
    #[error("relay state mismatch")]
    RelayStateMismatch {
        /// Expected RelayState presence and value.
        expected: RelayStateParam,
        /// Actual RelayState presence and value.
        actual: RelayStateParam,
    },
    /// `<Audience>` does not include the expected Service Provider entity ID.
    #[error("audience restriction not satisfied: expected {expected}")]
    AudienceMismatch {
        /// Expected SP entity ID.
        expected: String,
    },
    /// Response carried a non-success SAML status code.
    #[error("status not success: top={top}, second={second:?}")]
    StatusNotSuccess {
        /// Top-tier status code.
        top: String,
        /// Optional second-tier status code.
        second: Option<String>,
    },
    /// Assertion or session time bounds are not satisfied.
    #[error("SAML time window is invalid for {field}")]
    TimeWindowInvalid {
        /// SAML field or validation scope whose time window failed.
        field: &'static str,
    },
    /// Bearer subject confirmation requirements are not satisfied.
    #[error("subject confirmation is not satisfied: {reason}")]
    SubjectConfirmationInvalid {
        /// Stable validation reason for callers and logs.
        reason: &'static str,
    },
    /// A duplicate SAML message or assertion key was detected.
    #[error("replayed SAML message or assertion: {key}")]
    ReplayDetected {
        /// Replay cache key or duplicate identifier.
        key: String,
    },

    // Signature / crypto validation.
    /// Required signature is absent.
    #[error("signature missing where required")]
    SignatureMissing,
    /// Required binding parameter is absent.
    #[error("required binding parameter missing: {name}")]
    MissingBindingParameter {
        /// Binding parameter name.
        name: &'static str,
    },
    /// Signature verification failed for a semantic SAML validation reason.
    #[error("signature verification failed: {reason}")]
    SignatureVerification {
        /// Stable verification reason for callers and logs.
        reason: &'static str,
    },
    /// Signed reference could not be resolved safely.
    #[error("signed reference could not be resolved: {reason}")]
    ReferenceResolution {
        /// Stable reference-resolution reason for callers and logs.
        reason: &'static str,
    },
    /// Verified signed reference does not cover the consumed payload.
    #[error("signed reference does not cover consumed payload")]
    SignedReferenceMismatch,

    // Metadata / trust validation.
    /// No trusted certificate could be selected for verification.
    #[error("no trusted certificate could be selected for verification")]
    NoTrustedCertificate,
    /// Certificate embedded in the message does not match configured metadata.
    #[error("certificate mismatch")]
    CertificateMismatch,

    // Legacy compatibility variants kept while callers migrate.
    /// Issuer in the message does not match the one declared in metadata.
    #[error("ERR_UNMATCH_ISSUER")]
    UnmatchIssuer,
    /// `<Audience>` does not include this Service Provider's entity ID.
    #[error("ERR_UNMATCH_AUDIENCE")]
    UnmatchAudience,
    /// Response `Destination` does not match this Service Provider's ACS URL.
    #[error("ERR_UNMATCH_DESTINATION")]
    UnmatchDestination,
    /// `InResponseTo` does not match the originating request ID.
    #[error("ERR_INVALID_IN_RESPONSE_TO")]
    InvalidInResponseTo,
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

impl SamlError {
    pub(crate) fn issuer_mismatch(expected: &str, actual: Option<&str>) -> Self {
        Self::IssuerMismatch {
            expected: expected.to_string(),
            actual: actual.map(str::to_string),
        }
    }

    pub(crate) fn destination_mismatch(expected: &str, actual: Option<&str>) -> Self {
        Self::DestinationMismatch {
            expected: expected.to_string(),
            actual: actual.map(str::to_string),
        }
    }

    pub(crate) fn in_response_to_mismatch(expected: Option<&str>, actual: Option<&str>) -> Self {
        Self::InResponseToMismatch {
            expected: expected.map(str::to_string),
            actual: actual.map(str::to_string),
        }
    }
}
