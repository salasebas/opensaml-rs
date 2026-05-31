//! `opensaml` — experimental SAML 2.0 **Service Provider** library.
//!
//! HTTP bindings (POST form, Redirect query, DEFLATE, base64, escaping) are
//! implemented in [`binding`]. Metadata, AuthnRequest, response parsing, and
//! logout are documented stubs for now. XML cryptography is delegated to
//! `bergshamra` behind the optional `crypto-bergshamra` feature. SP-first; see
//! the crate README for the roadmap.

#![forbid(unsafe_code)]

pub mod authn;
pub mod binding;
pub mod crypto;
pub mod error;
pub mod idp;
pub mod logout;
pub mod metadata;
pub mod response;
pub mod sp;

pub use error::OpenSamlError;
pub use idp::IdentityProvider;
pub use sp::ServiceProvider;
