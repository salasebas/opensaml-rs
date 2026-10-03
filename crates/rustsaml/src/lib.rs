#![forbid(unsafe_code)]
//! Deprecated. This crate will no longer be maintained.
//! Please use [`saml-rs`](https://crates.io/crates/saml-rs).
//!
//! ```
//! use rustsaml::{Saml, Sp};
//!
//! let _: Option<Saml<Sp>> = None;
//! ```

pub use saml_rs::*;
