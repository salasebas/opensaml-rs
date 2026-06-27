//! Identity Provider metadata (samlify `metadata-idp.ts`).

use super::Metadata;
use crate::constants::Binding;
use crate::error::OpenSamlError;
use crate::util::Value;
use crate::xml::{ExtractorField, XmlLimits};
use std::ops::Deref;

/// Parsed IdP metadata. Derefs to [`Metadata`] for the shared accessors.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    inner: Metadata,
}

impl IdpMetadata {
    /// Parse IdP metadata XML.
    pub fn from_xml(xml: &str) -> Result<Self, OpenSamlError> {
        Self::from_xml_with_limits(xml, XmlLimits::default())
    }

    /// Parse IdP metadata XML with explicit XML parser resource limits.
    pub fn from_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<Self, OpenSamlError> {
        let extra = vec![
            ExtractorField::new(
                "wantAuthnRequestsSigned",
                &["EntityDescriptor", "IDPSSODescriptor"],
            )
            .attrs(&["WantAuthnRequestsSigned"]),
            ExtractorField::new(
                "singleSignOnService",
                &[
                    "EntityDescriptor",
                    "IDPSSODescriptor",
                    "SingleSignOnService",
                ],
            )
            .aggregate(&["Binding"], &[])
            .attrs(&["Location"]),
        ];
        Ok(Self {
            inner: Metadata::parse_with_limits(xml, extra, limits)?,
        })
    }

    /// `WantAuthnRequestsSigned` flag (absent ⇒ false).
    pub fn is_want_authn_requests_signed(&self) -> bool {
        self.inner.meta.get_str("wantAuthnRequestsSigned") == Some("true")
    }

    /// `SingleSignOnService` location for `binding`.
    pub fn get_single_sign_on_service(&self, binding: Binding) -> Option<String> {
        self.inner
            .meta
            .get("singleSignOnService")
            .and_then(|m| m.get_key(binding.urn()))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

impl Deref for IdpMetadata {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.inner
    }
}
