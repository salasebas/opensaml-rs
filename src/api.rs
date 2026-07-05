//! Typed high-level API contract for `saml-rs`.
//!
//! This module contains the public facade names that future typed SSO/SLO
//! flows will build on. The role-specific operations are planned for later
//! milestones; advanced callers can continue to use [`crate::raw`] for the
//! current low-level protocol API.
//!
//! Artifact binding is not part of the planned high-level browser SSO request
//! binding contract.
//!
//! ```compile_fail
//! use saml_rs::SsoRequestBinding;
//!
//! let binding = SsoRequestBinding::Artifact;
//! ```

use std::marker::PhantomData;

/// Typed SAML facade for high-level browser SSO/SLO flows.
///
/// The `Role` parameter identifies whether this facade represents a Service
/// Provider or Identity Provider. Use [`Sp`] and [`Idp`] through the crate root
/// re-exports when naming role-specific handles.
pub struct Saml<Role = Unknown> {
    _role: PhantomData<Role>,
}

/// Marker role used before a facade has been configured as an SP or IdP.
pub enum Unknown {}

/// Marker role for a Service Provider facade.
pub enum Sp {}

/// Marker role for an Identity Provider facade.
pub enum Idp {}

/// Error type returned by the typed SAML API.
pub type SamlError = crate::error::SamlError;
