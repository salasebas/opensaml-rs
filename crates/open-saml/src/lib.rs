//! Thin re-export crate. All SAML logic lives in [`opensaml`].
//!
//! # Disclaimer — no affiliation
//!
//! This is an independent Rust crate. It is **not** affiliated with, derived
//! from, maintained by, endorsed by, or sponsored by the Java
//! [OpenSAML](https://shibboleth.atlassian.net/wiki/spaces/OpenSAML/overview)
//! project, Shibboleth Consortium, or OASIS.

#![forbid(unsafe_code)]

pub use opensaml::*;
