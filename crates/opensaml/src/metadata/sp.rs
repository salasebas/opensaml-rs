//! Service Provider metadata (samlify `metadata-sp.ts`).

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::OpenSamlError;
use crate::xml::ExtractorField;
use std::ops::Deref;

/// Parsed SP metadata. Derefs to [`Metadata`] for the shared accessors.
#[derive(Debug, Clone)]
pub struct SpMetadata {
    inner: Metadata,
}

impl SpMetadata {
    /// Parse SP metadata XML.
    pub fn from_xml(xml: &str) -> Result<Self, OpenSamlError> {
        let extra = vec![
            ExtractorField::new("spSSODescriptor", &["EntityDescriptor", "SPSSODescriptor"])
                .attrs(&["WantAssertionsSigned", "AuthnRequestsSigned"]),
            ExtractorField::new(
                "assertionConsumerService",
                &[
                    "EntityDescriptor",
                    "SPSSODescriptor",
                    "AssertionConsumerService",
                ],
            )
            .attrs(&["Binding", "Location", "isDefault", "index"]),
        ];
        Ok(Self {
            inner: Metadata::parse(xml, extra)?,
        })
    }

    /// `WantAssertionsSigned` flag.
    pub fn is_want_assertions_signed(&self) -> bool {
        self.inner
            .meta
            .get_str("spSSODescriptor.wantAssertionsSigned")
            == Some("true")
    }

    /// `AuthnRequestsSigned` flag.
    pub fn is_authn_request_signed(&self) -> bool {
        self.inner
            .meta
            .get_str("spSSODescriptor.authnRequestsSigned")
            == Some("true")
    }

    /// `AssertionConsumerService` location for `binding`.
    pub fn get_assertion_consumer_service(&self, binding: Binding) -> Option<String> {
        let acs = self.inner.meta.get("assertionConsumerService")?;
        for obj in as_object_list(acs) {
            if obj.get_str("binding") == Some(binding.urn()) {
                return obj.get_str("location").map(str::to_string);
            }
        }
        None
    }
}

impl Deref for SpMetadata {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.inner
    }
}
