//! Service Provider metadata.

use super::{as_object_list, Metadata};
use crate::constants::Binding;
use crate::error::SamlError;
use crate::xml::{ExtractorField, XmlLimits};
use std::ops::Deref;

/// Parsed AssertionConsumerService endpoint from SP metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcsMetadataEndpoint {
    /// Protocol binding.
    pub(crate) binding: Binding,
    /// Endpoint location.
    pub(crate) location: String,
    /// Metadata index, when declared.
    pub(crate) index: Option<u16>,
    /// Whether the endpoint is marked as default.
    pub(crate) is_default: bool,
}

/// Parsed SP metadata. Derefs to [`Metadata`] for the shared accessors.
#[derive(Debug, Clone)]
pub struct SpMetadata {
    inner: Metadata,
}

impl SpMetadata {
    /// Parse SP metadata XML.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        Self::from_xml_with_limits(xml, XmlLimits::default())
    }

    /// Parse SP metadata XML with explicit XML parser resource limits.
    pub fn from_xml_with_limits(xml: &str, limits: XmlLimits) -> Result<Self, SamlError> {
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
            inner: Metadata::parse_with_limits(xml, extra, limits)?,
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
        self.get_assertion_consumer_service_endpoint(binding)
            .map(|endpoint| endpoint.location)
    }

    /// First `AssertionConsumerService` endpoint for `binding`.
    pub(crate) fn get_assertion_consumer_service_endpoint(
        &self,
        binding: Binding,
    ) -> Option<AcsMetadataEndpoint> {
        self.assertion_consumer_service_endpoints()
            .into_iter()
            .find(|endpoint| endpoint.binding == binding)
    }

    /// `AssertionConsumerService` endpoint with the declared metadata index.
    pub(crate) fn get_assertion_consumer_service_by_index(
        &self,
        index: u16,
    ) -> Result<Option<AcsMetadataEndpoint>, SamlError> {
        let mut matches = self
            .assertion_consumer_service_endpoints()
            .into_iter()
            .filter(|endpoint| endpoint.index == Some(index));
        let first = matches.next();
        if matches.next().is_some() {
            return Err(SamlError::Invalid(format!(
                "duplicate AssertionConsumerService index {index}"
            )));
        }
        Ok(first)
    }

    /// Whether metadata contains `location` for `binding`.
    pub(crate) fn has_assertion_consumer_service(&self, binding: Binding, location: &str) -> bool {
        self.assertion_consumer_service_endpoints()
            .iter()
            .any(|endpoint| endpoint.binding == binding && endpoint.location == location)
    }

    fn assertion_consumer_service_endpoints(&self) -> Vec<AcsMetadataEndpoint> {
        let Some(acs) = self.inner.meta.get("assertionConsumerService") else {
            return Vec::new();
        };
        as_object_list(acs)
            .into_iter()
            .filter_map(acs_metadata_endpoint_from_value)
            .collect()
    }
}

fn acs_metadata_endpoint_from_value(value: &crate::util::Value) -> Option<AcsMetadataEndpoint> {
    let binding = Binding::from_urn(value.get_str("binding")?)?;
    let location = value.get_str("location")?.to_string();
    let index = value
        .get_str("index")
        .and_then(|index| index.parse::<u16>().ok());
    let is_default = value.get_str("isDefault") == Some("true");
    Some(AcsMetadataEndpoint {
        binding,
        location,
        index,
        is_default,
    })
}

impl Deref for SpMetadata {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.inner
    }
}
