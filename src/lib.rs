//! `saml-rs` - SAML 2.0 **Service Provider** and **Identity Provider** library.
//!
//! The crate supports SP/IdP metadata, HTTP-POST, HTTP-Redirect,
//! HTTP-POST-SimpleSign, browser SSO flows, Single Logout, bounded XML parsing,
//! and local-name field extraction over `quick-xml`.
//!
//! XML cryptography (XML-DSig sign/verify with anti-wrapping, XML-Enc, detached
//! message signatures) is delegated to `bergshamra` behind the
//! `crypto-bergshamra` feature (**on by default**; disable with
//! `default-features = false` to build the crypto-free protocol layer, where
//! crypto operations fail closed with [`SamlError::Unsupported`]).

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
pub use error::SamlError;
pub use idp::IdentityProvider;
pub use sp::ServiceProvider;
