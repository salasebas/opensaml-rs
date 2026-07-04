//! Compatibility API and low-level protocol helpers.
//!
//! Prefer the crate-root [`crate::Saml`] facade for new high-level browser SSO
//! and SLO flows. Import from this module when you need direct access to the
//! existing entity, flow, metadata, and logout building blocks.

pub use crate::entity::{BindingContext, EntitySetting, User};
pub use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
pub use crate::idp::{IdentityProvider, LoginResponseOptions};
pub use crate::logout;
pub use crate::metadata;
pub use crate::sp::{LoginRequestOptions, ServiceProvider};
