//! Typed SAML domain models built from validated raw flow results.
//!
//! References: SAML Core 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> and SAML Profiles 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf>.

mod attributes;
mod authn;
mod endpoint;
mod extract;
mod identifiers;
mod logout;
mod received;
mod relay;
mod session;
mod sso;
mod subject;
mod validation;

pub(crate) use extract::authn_statement_not_on_or_after_values;
pub(crate) use session::earliest_authn_session_expiration;

pub use attributes::{Attribute, AttributeValue, Attributes};
pub use authn::AuthnRequest;
pub use endpoint::EndpointUrl;
pub use identifiers::{AssertionId, MessageId, SamlInstant, SessionIndex};
pub use logout::{LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject};
pub use received::Received;
pub use relay::{RelayState, RelayStateParam, MAX_RELAY_STATE_BYTES};
pub use session::AuthnSession;
pub use sso::{Assertion, SsoResponse, SsoSession};
pub use subject::{NameId, NameIdCreationRequest, NameIdPolicy, Subject, SubjectConfirmation};
pub use validation::{ClockSkew, ReplayCache, ReplayKey, ReplayPolicy, SamlValidationContext};
