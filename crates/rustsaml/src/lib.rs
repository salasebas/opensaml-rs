#![forbid(unsafe_code)]
//! Maintained compatibility re-export of [`saml-rs`](https://crates.io/crates/saml-rs).
//!
//! ```
//! use rustsaml::{Saml, Sp};
//!
//! let _: Option<Saml<Sp>> = None;
//! ```

pub use saml_rs::*;
