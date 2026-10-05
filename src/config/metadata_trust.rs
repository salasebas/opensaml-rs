use core::ops::Deref;

use crate::error::SamlError;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::error::SignatureVerificationReason;
use crate::metadata::Metadata;
#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
use crate::xml::XmlLimits;

use super::credentials::CertificatePem;
use super::descriptors::EntityId;

/// Explicit trust policy for imported SAML metadata.
///
/// This is a caller argument on descriptor import. It is not a field of
/// [`crate::SpValidationPolicy`] or [`crate::IdpValidationPolicy`], and there
/// is no `recommended()` constructor. The Web Browser SSO and Single Logout
/// field combinations do not select it, invent trust anchors, or accept a
/// signature that was not verified with pinned certificates.
///
/// SAML metadata trust is caller-pinned. This type does not use a public web
/// PKI CA store, `ds:KeyInfo`, or a metadata `KeyDescriptor` as a trust anchor.
/// [`UnsignedForCompatibility`](Self::UnsignedForCompatibility) preserves an
/// unsigned samlify-port or raw metadata import. It does not validate a
/// signature that happens to be present.
///
/// # Metadata trust
///
/// Typed import reads a document the caller already holds. It does not resolve
/// or cache metadata. The full record is `docs/conformance/metadata-and-replay.md`.
///
/// - Signing the root when there is no authenticated channel is a publisher
///   recommendation (Metadata §3). Actor: metadata publisher. Direction:
///   generate. This import does not reject unsigned metadata for that
///   recommendation.
/// - Validating a present signature is mandatory for the publication and
///   resolution path in Metadata §4.3.3.2. Actor: metadata consumer.
///   Direction: resolve. That path is outside this import.
/// - [`Self::RequireSignature`] verifies only the caller-pinned certificates.
///   Actor: metadata consumer. Direction: inbound. Level: the caller selected
///   this optional check, and coverage of the `EntityDescriptor` is then
///   mandatory (Metadata §3.1.2 and §3.1.4). An empty pin list is rejected.
///   Errata 05 E69 gives `KeyDescriptor` certificates no trust meaning.
///
/// # Examples
///
/// ```no_run
/// use saml_rs::{CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy};
///
/// # fn load_metadata() -> String { unimplemented!() }
/// # fn load_metadata_signing_cert() -> String { unimplemented!() }
/// # fn run() -> Result<(), saml_rs::SamlError> {
/// let cert = CertificatePem::new(load_metadata_signing_cert());
/// let certificates = [cert];
/// let idp = IdpDescriptor::from_metadata_xml_for(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     &load_metadata(),
///     MetadataTrustPolicy::RequireSignature {
///         trusted_certificates: &certificates,
///     },
/// )?;
/// assert!(idp.was_verified_with_pinned_certificates());
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy)]
pub enum MetadataTrustPolicy<'a> {
    /// Accept unsigned metadata to preserve a samlify-port or raw import.
    UnsignedForCompatibility,
    /// Require a valid metadata signature from one of the pinned certificates.
    RequireSignature {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(any(
        feature = "crypto-rustcrypto",
        feature = "crypto-aws-lc",
        feature = "crypto-fips"
    )),
    allow(dead_code)
)]
pub(super) enum AppliedMetadataTrust {
    UnsignedForCompatibility,
    SignedByPinnedCertificates {
        signed_entity_descriptor_xml: String,
    },
}
pub(super) fn metadata_entity_id<M>(metadata: &M) -> Result<&str, SamlError>
where
    M: Deref<Target = Metadata>,
{
    metadata
        .get_entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))
}

pub(super) fn ensure_expected_entity_id(
    expected: &EntityId,
    actual: &str,
) -> Result<(), SamlError> {
    if expected.as_str() == actual {
        return Ok(());
    }
    Err(SamlError::Invalid(format!(
        "metadata entityID `{actual}` did not match expected `{}`",
        expected.as_str()
    )))
}

pub(super) fn ensure_metadata_trust<M>(
    metadata: &M,
    trust: MetadataTrustPolicy<'_>,
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    match trust {
        MetadataTrustPolicy::UnsignedForCompatibility => {
            Ok(AppliedMetadataTrust::UnsignedForCompatibility)
        }
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates,
        } => verify_pinned_metadata_signature(metadata, trusted_certificates),
    }
}

#[cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]
fn verify_pinned_metadata_signature<M>(
    metadata: &M,
    trusted_certificates: &[CertificatePem],
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    let trusted_certificates: Vec<String> = trusted_certificates
        .iter()
        .map(|certificate| certificate.as_str().to_string())
        .collect();
    let verification = metadata
        .verify_signature_detailed_with_limits(&trusted_certificates, XmlLimits::default())?;
    if verification.verified() {
        let signed_entity_descriptor_xml = verification
            .into_signed_entity_descriptor_xml()
            .ok_or(SamlError::SignedReferenceMismatch)?;
        return Ok(AppliedMetadataTrust::SignedByPinnedCertificates {
            signed_entity_descriptor_xml,
        });
    }
    Err(SamlError::SignatureVerification {
        reason: SignatureVerificationReason::XmlSignature,
    })
}

#[cfg(not(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
)))]
fn verify_pinned_metadata_signature<M>(
    _metadata: &M,
    _trusted_certificates: &[CertificatePem],
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    Err(SamlError::Unsupported(
        "signed metadata verification requires a crypto provider feature".into(),
    ))
}
