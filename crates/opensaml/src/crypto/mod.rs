//! XML security backend abstraction.
//!
//! XML-DSig / XML-Enc / C14N live in `bergshamra`; `opensaml` only orchestrates
//! through the [`XmlSecurityBackend`] trait.

mod backend;
#[cfg(feature = "crypto-bergshamra")]
mod bergshamra;

pub use backend::XmlSecurityBackend;
#[cfg(feature = "crypto-bergshamra")]
pub use bergshamra::BergshamraBackend;
