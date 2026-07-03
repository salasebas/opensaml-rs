//! `saml-rs` — SAML 2.0 **Service Provider** and **Identity Provider** library.
//!
//! Originally ported from npm `samlify` v2.10.2 conformance fixtures:
//! constants, XML field extraction ([`xml`]), message [`template`]s,
//! [`metadata`] parse/generate, the three HTTP [`binding`]s (POST, Redirect,
//! POST-SimpleSign), the [`sp`]/[`idp`] [`entity`] orchestration, inbound
//! [`flow`] (decode → validate → verify/decrypt → extract), and Single
//! [`logout`]. XML
//! cryptography (XML-DSig sign/verify with anti-wrapping, XML-Enc, detached
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
