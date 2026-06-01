//! Thin re-export crate. All SAML logic lives in `opensaml`.
//!
//! # Disclaimer — no affiliation
//!
//! This is an independent, unofficial Rust crate. It is **not** affiliated
//! with, derived from, maintained by, endorsed by, or sponsored by the npm
//! [`samlify`](https://www.npmjs.com/package/samlify) package or its authors.
//! The name is only a Rust crate alias and shares no code with that package.

#![forbid(unsafe_code)]

pub use opensaml::*;
