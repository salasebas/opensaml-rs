//! SAML metadata parsing (samlify `metadata.ts` + `metadata-sp/idp`).

pub mod generate;
pub mod idp;
pub mod sp;

pub use generate::{
    generate_idp_metadata, generate_sp_metadata, try_generate_idp_metadata, Endpoint,
    IdpMetadataConfig, SpMetadataConfig,
};
pub use idp::IdpMetadata;
pub use sp::SpMetadata;

use crate::constants::{Binding, CertUse};
use crate::error::OpenSamlError;
use crate::util::Value;
use crate::xml::{dom, extract_with_limits, ExtractorField, XmlLimits};

fn base_fields() -> Vec<ExtractorField> {
    vec![
        ExtractorField::new("entityID", &["EntityDescriptor"]).attrs(&["entityID"]),
        ExtractorField::new(
            "sharedCertificate",
            &[
                "EntityDescriptor",
                "~SSODescriptor",
                "KeyDescriptor",
                "KeyInfo",
                "X509Data",
                "X509Certificate",
            ],
        ),
        ExtractorField::new(
            "certificate",
            &["EntityDescriptor", "~SSODescriptor", "KeyDescriptor"],
        )
        .aggregate(&["use"], &["KeyInfo", "X509Data", "X509Certificate"]),
        ExtractorField::new(
            "singleLogoutService",
            &["EntityDescriptor", "~SSODescriptor", "SingleLogoutService"],
        )
        .attrs(&["Binding", "Location"]),
        ExtractorField::new(
            "nameIDFormat",
            &["EntityDescriptor", "~SSODescriptor", "NameIDFormat"],
        ),
    ]
}

/// Normalise a "single object or array of objects" value into a node list.
pub(crate) fn as_object_list(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    }
}

fn location_for_binding(value: Option<&Value>, binding: Binding) -> Option<String> {
    let value = value?;
    for obj in as_object_list(value) {
        if obj.get_str("binding") == Some(binding.urn()) {
            return obj.get_str("location").map(str::to_string);
        }
    }
    None
}

/// Parsed entity metadata (the base shared by SP and IdP).
#[derive(Debug, Clone)]
pub struct Metadata {
    xml: String,
    pub(crate) meta: Value,
}

impl Metadata {
    /// Parse `xml`, adding the role-specific `extra` extractor fields.
    ///
    /// Rejects documents carrying more than one top-level `<EntityDescriptor>`.
    pub fn parse(xml: &str, extra: Vec<ExtractorField>) -> Result<Self, OpenSamlError> {
        Self::parse_with_limits(xml, extra, XmlLimits::default())
    }

    /// Parse `xml` with explicit XML parser resource limits.
    pub fn parse_with_limits(
        xml: &str,
        extra: Vec<ExtractorField>,
        limits: XmlLimits,
    ) -> Result<Self, OpenSamlError> {
        let roots = dom::parse_roots_with_limits(xml, limits)?;
        if roots
            .iter()
            .filter(|n| n.local_name == "EntityDescriptor")
            .count()
            > 1
        {
            return Err(OpenSamlError::Xml(
                "ERR_MULTIPLE_METADATA_ENTITYDESCRIPTOR".into(),
            ));
        }

        let mut fields = base_fields();
        fields.extend(extra);
        let mut meta = extract_with_limits(xml, &fields, limits)?;

        // A single shared certificate is used for both signing and encryption.
        if let Some(shared) = meta.get_str("sharedCertificate") {
            let shared = shared.to_string();
            meta.insert(
                "certificate",
                Value::Object(vec![
                    ("signing".into(), Value::Str(shared.clone())),
                    ("encryption".into(), Value::Str(shared)),
                ]),
            );
        }

        Ok(Self {
            xml: xml.to_string(),
            meta,
        })
    }

    /// The original metadata XML.
    pub fn get_metadata(&self) -> &str {
        &self.xml
    }

    /// `entityID`.
    pub fn get_entity_id(&self) -> Option<&str> {
        self.meta.get_str("entityID")
    }

    /// Declared `<NameIDFormat>` values.
    pub fn get_name_id_format(&self) -> Vec<String> {
        match self.meta.get("nameIDFormat") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(Value::Str(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    /// All X.509 certificates declared for `use` (raw, as written in metadata).
    pub fn x509_certificates(&self, use_: CertUse) -> Vec<String> {
        match self
            .meta
            .get("certificate")
            .and_then(|c| c.get_key(use_.as_str()))
        {
            Some(Value::Str(s)) => vec![s.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// First X.509 certificate declared for `use`.
    pub fn get_x509_certificate(&self, use_: CertUse) -> Option<String> {
        self.x509_certificates(use_).into_iter().next()
    }

    /// `SingleLogoutService` location for `binding`.
    pub fn get_single_logout_service(&self, binding: Binding) -> Option<String> {
        location_for_binding(self.meta.get("singleLogoutService"), binding)
    }

    /// Write the metadata XML to `path` (samlify `exportMetadata`).
    pub fn export_metadata(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, &self.xml)
    }

    /// Bindings for which a `SingleLogoutService` endpoint is declared
    /// (samlify `getSupportBindings`).
    pub fn get_support_bindings(&self) -> Vec<Binding> {
        [Binding::Redirect, Binding::Post, Binding::SimpleSign]
            .into_iter()
            .filter(|b| self.get_single_logout_service(*b).is_some())
            .collect()
    }

    /// Verify this metadata document's enveloped signature against trusted
    /// certificate(s) (federation trust anchor). Requires `crypto-bergshamra`.
    #[cfg(feature = "crypto-bergshamra")]
    pub fn verify_signature(&self, trusted_certs: &[String]) -> Result<bool, OpenSamlError> {
        self.verify_signature_with_limits(trusted_certs, XmlLimits::default())
    }

    /// Verify this metadata document's signature with explicit XML parser limits.
    #[cfg(feature = "crypto-bergshamra")]
    pub fn verify_signature_with_limits(
        &self,
        trusted_certs: &[String],
        limits: XmlLimits,
    ) -> Result<bool, OpenSamlError> {
        crate::crypto::verify_metadata_signature_with_limits(&self.xml, trusted_certs, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDPMETA: &str = include_str!("../../tests/fixtures/idpmeta.xml");
    const SPMETA: &str = include_str!("../../tests/fixtures/spmeta.xml");
    const MULTIPLE: &str = include_str!("../../tests/fixtures/multiple_entitydescriptor.xml");

    #[test]
    fn rejects_multiple_entity_descriptors() {
        assert!(Metadata::parse(MULTIPLE, Vec::new()).is_err());
    }

    #[test]
    fn parses_idp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdpMetadata::from_xml(IDPMETA)?;
        assert_eq!(
            idp.get_entity_id(),
            Some("https://idp.example.com/metadata")
        );
        assert!(idp.is_want_authn_requests_signed());
        assert_eq!(
            idp.get_single_sign_on_service(Binding::Redirect).as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        assert!(idp.get_x509_certificate(CertUse::Signing).is_some());
        assert!(idp
            .get_name_id_format()
            .iter()
            .any(|f| f.contains("persistent")));
        Ok(())
    }

    #[test]
    fn parses_sp_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert_eq!(sp.get_entity_id(), Some("https://sp.example.org/metadata"));
        assert!(sp.is_want_assertions_signed());
        assert!(sp.is_authn_request_signed());
        assert_eq!(
            sp.get_assertion_consumer_service(Binding::Post).as_deref(),
            Some("https://sp.example.org/sp/sso")
        );
        assert_eq!(
            sp.get_single_logout_service(Binding::Redirect).as_deref(),
            Some("https://sp.example.org/sp/slo")
        );
        assert!(sp.get_x509_certificate(CertUse::Encryption).is_some());
        Ok(())
    }

    #[test]
    fn support_bindings_and_export() -> Result<(), Box<dyn std::error::Error>> {
        let sp = SpMetadata::from_xml(SPMETA)?;
        assert!(sp.get_support_bindings().contains(&Binding::Redirect));
        let mut path = std::env::temp_dir();
        path.push(format!("opensaml_md_{}.xml", std::process::id()));
        sp.export_metadata(&path)?;
        assert_eq!(std::fs::read_to_string(&path)?, sp.get_metadata());
        std::fs::remove_file(&path)?;
        Ok(())
    }
}
