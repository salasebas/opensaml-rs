//! `saml-rs` - SAML 2.0 Service Provider and Identity Provider support.
//!
//! Start with [`Saml`] for planned high-level browser SSO/SLO APIs. The typed
//! facade is the public contract for future browser flows, while the current
//! low-level implementation remains available under [`raw`].
//!
//! The [`raw`] module contains the compatibility API and protocol helpers:
//! advanced callers should import [`raw::ServiceProvider`] and
//! [`raw::IdentityProvider`] there rather than using the root compatibility
//! exports.
//!
//! XML cryptography (XML-DSig sign/verify with anti-wrapping, XML-Enc, detached
//! message signatures) is delegated to `bergshamra` behind the
//! `crypto-bergshamra` feature (**on by default**; disable with
//! `default-features = false` to build the crypto-free protocol layer, where
//! crypto operations fail closed with [`crate::error::SamlError::Unsupported`]).
//!
//! Unsupported SAML profiles such as Artifact resolution, SOAP/back-channel,
//! ECP/PAOS, SAML queries, NameID management, and metadata federation are not
//! part of the high-level facade yet.

#![forbid(unsafe_code)]

pub mod api;
pub mod binding;
pub mod browser;
pub mod config;
pub mod constants;
pub mod context;
pub mod crypto;
pub mod entity;
pub mod error;
pub mod flow;
pub mod idp;
pub mod logout;
pub mod metadata;
pub mod model;
pub mod raw;
pub mod sp;
pub mod template;
pub mod util;
pub mod validator;
pub mod xml;

pub use api::{Idp, Saml, SamlError, Sp, Unknown};
pub use browser::{
    AcsEndpoint, BrowserInput, EndpointUrl, FormField, LogoutBinding, Outbound, Pending,
    PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, PostForm, SloEndpoint, SsoEndpoint,
    SsoRequestBinding, SsoResponseBinding, Started,
};
pub use config::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy, AudienceValidationPolicy,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, Credentials,
    DataEncryptionAlgorithm, DigestAlgorithm, EntityId, IdpConfig, IdpConfigBuilder, IdpDescriptor,
    IdpMetadataConfig, IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy,
    LogoutSignaturePolicy, MessageSignaturePolicy, MetadataTrustPolicy, NameIdCreationPolicy,
    NameIdFormat, Passphrase, PrivateKeyPem, SignatureAlgorithm, SpConfig, SpConfigBuilder,
    SpDescriptor, SpMetadataConfig, SpValidationPolicy, TemplatePolicy, TransformAlgorithm,
    XmlEncryptionPolicy, XmlPolicy,
};
#[doc = "Compatibility export. Prefer `raw::EntitySetting` for low-level APIs."]
pub use entity::EntitySetting;
#[doc = "Compatibility export. Prefer `raw::IdentityProvider` for low-level APIs."]
pub use idp::IdentityProvider;
pub use model::{
    Assertion, AssertionId, Attribute, AttributeValue, Attributes, AuthnRequest, AuthnSession,
    ClockSkew, LogoutCompleted, LogoutRequest, LogoutResponse, MessageId, NameId,
    NameIdCreationRequest, NameIdPolicy, Received, RelayState, RelayStateParam, ReplayCache,
    ReplayKey, ReplayPolicy, SamlInstant, SamlValidationContext, SessionIndex, SsoResponse,
    SsoSession, Subject, SubjectConfirmation, MAX_RELAY_STATE_BYTES,
};
#[doc = "Compatibility export. Prefer `raw::ServiceProvider` for low-level APIs."]
pub use sp::ServiceProvider;
