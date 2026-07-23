//! Typed configuration building blocks for high-level SAML APIs.

mod algorithms;
mod builders;
mod credentials;
mod descriptors;
mod metadata_trust;
mod policies;

pub use algorithms::{
    DataEncryptionAlgorithm, DigestAlgorithm, KeyEncryptionAlgorithm, NameIdFormat,
    SignatureAlgorithm, TransformAlgorithm,
};
pub use builders::{IdpConfig, IdpConfigBuilder, SpConfig, SpConfigBuilder};
pub use credentials::{CertificatePem, Credentials, Passphrase, PrivateKeyPem};
pub use descriptors::{EntityId, IdpDescriptor, IdpMetadataConfig, SpDescriptor, SpMetadataConfig};
pub use metadata_trust::MetadataTrustPolicy;
pub use policies::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy, AudienceValidationPolicy,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, IdpValidationPolicy, LogoutPolicy,
    LogoutSignaturePolicy, NameIdCreationPolicy, ResponseSignaturePolicy, SpValidationPolicy,
    TemplatePolicy, XmlEncryptionPolicy, XmlPolicy,
};
