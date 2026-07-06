use core::ops::Deref;

use crate::error::SamlError;
#[cfg(feature = "crypto-bergshamra")]
use crate::error::SignatureVerificationReason;
use crate::metadata::Metadata;
#[cfg(feature = "crypto-bergshamra")]
use crate::xml::XmlLimits;

use super::credentials::CertificatePem;
use super::descriptors::EntityId;

/// Explicit trust policy for imported SAML metadata.
///
/// SAML metadata trust is caller-pinned or federation-driven; this type does
/// not use a public web PKI CA store by default.
/// [`UnsignedForCompatibility`](Self::UnsignedForCompatibility) is for explicit
/// legacy interoperability, not the preferred production trust model.
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
    /// Accept unsigned metadata for legacy interoperability.
    UnsignedForCompatibility,
    /// Require a valid metadata signature from one of the pinned certificates.
    RequireSignature {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "crypto-bergshamra"), allow(dead_code))]
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

#[cfg(feature = "crypto-bergshamra")]
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

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_pinned_metadata_signature<M>(
    _metadata: &M,
    _trusted_certificates: &[CertificatePem],
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    Err(SamlError::Unsupported(
        "signed metadata verification requires the crypto-bergshamra feature".into(),
    ))
}
