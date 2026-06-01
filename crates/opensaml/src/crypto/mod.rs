//! XML security backend abstraction.
//!
//! XML-DSig / XML-Enc / C14N live in `bergshamra`; `opensaml` only orchestrates
//! through the [`XmlSecurityBackend`] trait.

mod backend;
#[cfg(feature = "crypto-bergshamra")]
mod bergshamra;
#[cfg(feature = "crypto-bergshamra")]
pub mod enc;
#[cfg(feature = "crypto-bergshamra")]
pub mod keys;
#[cfg(feature = "crypto-bergshamra")]
pub mod sign;
#[cfg(feature = "crypto-bergshamra")]
pub mod verify;

pub use backend::XmlSecurityBackend;
#[cfg(feature = "crypto-bergshamra")]
pub use bergshamra::BergshamraBackend;
#[cfg(feature = "crypto-bergshamra")]
pub use enc::{decrypt_assertion, encrypt_assertion};
#[cfg(feature = "crypto-bergshamra")]
pub use sign::{construct_message_signature, construct_saml_signature, verify_message_signature};
#[cfg(feature = "crypto-bergshamra")]
pub use verify::verify_signature;
