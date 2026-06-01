//! `opensaml` — experimental SAML 2.0 **Service Provider** library.
//!
//! HTTP bindings (POST form, Redirect query, DEFLATE, base64, escaping) are
//! implemented in [`binding`]. Metadata, AuthnRequest, response parsing, and
//! logout are documented stubs for now. XML cryptography is delegated to
//! `bergshamra` behind the optional `crypto-bergshamra` feature. SP-first; see
//! the crate README for the roadmap.

#![forbid(unsafe_code)]

pub mod binding;
pub mod constants;
pub mod context;
pub mod crypto;
pub mod entity;
pub mod error;
pub mod flow;
pub mod idp;
pub mod logout;
pub mod metadata;
pub mod sp;
pub mod template;
pub mod util;
pub mod validator;
pub mod xml;

pub use entity::EntitySetting;
pub use error::OpenSamlError;
pub use idp::IdentityProvider;
pub use sp::ServiceProvider;
