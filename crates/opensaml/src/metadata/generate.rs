//! SAML metadata generation (samlify `metadata-sp.ts` / `metadata-idp.ts`).

use crate::constants::{elements_order, name_id_format, namespace, Binding};
use crate::error::OpenSamlError;
use crate::util::{is_non_empty_array, normalize_cert_string};

/// A protocol endpoint (`SingleSignOnService` / `SingleLogoutService` / ACS).
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Protocol binding.
    pub binding: Binding,
    /// Endpoint URL.
    pub location: String,
    /// Whether this is the default endpoint.
    pub is_default: bool,
}

impl Endpoint {
    /// Convenience constructor (non-default).
    pub fn new(binding: Binding, location: impl Into<String>) -> Self {
        Self {
            binding,
            location: location.into(),
            is_default: false,
        }
    }
}

/// SP metadata generation input.
#[derive(Debug, Clone, Default)]
pub struct SpMetadataConfig {
    /// `entityID`.
    pub entity_id: String,
    /// Signing certificates (PEM or bare base64).
    pub signing_certs: Vec<String>,
    /// Encryption certificates (PEM or bare base64).
    pub encrypt_certs: Vec<String>,
    /// `AuthnRequestsSigned`.
    pub authn_requests_signed: bool,
    /// `WantAssertionsSigned`.
    pub want_assertions_signed: bool,
    /// `<NameIDFormat>` values (defaults to email address when empty).
    pub name_id_format: Vec<String>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// `AssertionConsumerService` endpoints.
    pub assertion_consumer_service: Vec<Endpoint>,
    /// Element ordering profile (defaults to [`elements_order::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
}

/// IdP metadata generation input.
#[derive(Debug, Clone, Default)]
pub struct IdpMetadataConfig {
    /// `entityID`.
    pub entity_id: String,
    /// Signing certificates.
    pub signing_certs: Vec<String>,
    /// Encryption certificates.
    pub encrypt_certs: Vec<String>,
    /// `WantAuthnRequestsSigned`.
    pub want_authn_requests_signed: bool,
    /// `<NameIDFormat>` values.
    pub name_id_format: Vec<String>,
    /// `SingleSignOnService` endpoints (required by SAML).
    pub single_sign_on_service: Vec<Endpoint>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// Element ordering profile (defaults to [`elements_order::idp::DEFAULT`]).
    pub elements_order: Option<Vec<String>>,
}

fn key_descriptor(use_: &str, cert: &str) -> String {
    format!(
        "<KeyDescriptor use=\"{use_}\"><ds:KeyInfo xmlns:ds=\"{dsig}\"><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>",
        dsig = namespace::DSIG,
        cert = normalize_cert_string(cert),
    )
}

fn key_descriptors(signing: &[String], encrypt: &[String]) -> String {
    let mut out = String::new();
    for cert in signing {
        out.push_str(&key_descriptor("signing", cert));
    }
    for cert in encrypt {
        out.push_str(&key_descriptor("encryption", cert));
    }
    out
}

fn name_id_formats(formats: &[String]) -> String {
    let defaulted: Vec<String> = if is_non_empty_array(formats) {
        formats.to_vec()
    } else {
        vec![name_id_format::EMAIL_ADDRESS.to_string()]
    };
    defaulted
        .iter()
        .map(|f| format!("<NameIDFormat>{f}</NameIDFormat>"))
        .collect()
}

fn endpoint_attrs(e: &Endpoint, index: Option<usize>) -> String {
    use crate::binding::xml_escape;
    let mut attrs = String::new();
    if let Some(i) = index {
        attrs.push_str(&format!(" index=\"{i}\""));
    }
    if e.is_default {
        attrs.push_str(" isDefault=\"true\"");
    }
    attrs.push_str(&format!(
        " Binding=\"{}\" Location=\"{}\"",
        e.binding.urn(),
        xml_escape(&e.location)
    ));
    attrs
}

fn single_logout(endpoints: &[Endpoint]) -> String {
    endpoints
        .iter()
        .map(|e| format!("<SingleLogoutService{}/>", endpoint_attrs(e, None)))
        .collect()
}

/// Generate SP metadata XML.
pub fn generate_sp_metadata(cfg: &SpMetadataConfig) -> String {
    let order = cfg.elements_order.clone().unwrap_or_else(|| {
        elements_order::DEFAULT
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    let acs: String = cfg
        .assertion_consumer_service
        .iter()
        .enumerate()
        .map(|(i, e)| format!("<AssertionConsumerService{}/>", endpoint_attrs(e, Some(i))))
        .collect();

    let mut body = String::new();
    for name in &order {
        match name.as_str() {
            "KeyDescriptor" => {
                body.push_str(&key_descriptors(&cfg.signing_certs, &cfg.encrypt_certs))
            }
            "NameIDFormat" => body.push_str(&name_id_formats(&cfg.name_id_format)),
            "SingleLogoutService" => body.push_str(&single_logout(&cfg.single_logout_service)),
            "AssertionConsumerService" => body.push_str(&acs),
            _ => {}
        }
    }

    format!(
        "<EntityDescriptor entityID=\"{entity}\" xmlns=\"{md}\" xmlns:assertion=\"{assertion}\" xmlns:ds=\"{dsig}\"><SPSSODescriptor AuthnRequestsSigned=\"{ars}\" WantAssertionsSigned=\"{was}\" protocolSupportEnumeration=\"{protocol}\">{body}</SPSSODescriptor></EntityDescriptor>",
        entity = cfg.entity_id,
        md = namespace::METADATA,
        assertion = namespace::ASSERTION,
        dsig = namespace::DSIG,
        ars = cfg.authn_requests_signed,
        was = cfg.want_assertions_signed,
        protocol = namespace::PROTOCOL,
    )
}

/// Generate IdP metadata XML.
pub fn generate_idp_metadata(cfg: &IdpMetadataConfig) -> String {
    let is_custom_order = cfg.elements_order.is_some();
    let order = cfg.elements_order.clone().unwrap_or_else(|| {
        elements_order::idp::DEFAULT
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    let sso: String = cfg
        .single_sign_on_service
        .iter()
        .map(|e| format!("<SingleSignOnService{}/>", endpoint_attrs(e, None)))
        .collect();

    let keys = key_descriptors(&cfg.signing_certs, &cfg.encrypt_certs);
    let formats = if is_non_empty_array(&cfg.name_id_format) {
        name_id_formats(&cfg.name_id_format)
    } else {
        String::new()
    };
    let slo = single_logout(&cfg.single_logout_service);

    let descriptors = [
        ("KeyDescriptor", keys),
        ("NameIDFormat", formats),
        ("SingleSignOnService", sso),
        ("SingleLogoutService", slo),
    ];
    let mut body = String::new();
    for name in &order {
        if let Some((_, fragment)) = descriptors.iter().find(|(descriptor_name, fragment)| {
            descriptor_name == &name.as_str() && !fragment.is_empty()
        }) {
            body.push_str(fragment);
        }
    }
    if is_custom_order {
        if !order.iter().any(|ordered| ordered == "SingleSignOnService") {
            body.push_str(&descriptors[2].1);
        }
    } else {
        for (name, fragment) in &descriptors {
            if !fragment.is_empty() && !order.iter().any(|ordered| ordered == name) {
                body.push_str(fragment);
            }
        }
    }

    format!(
        "<EntityDescriptor entityID=\"{entity}\" xmlns=\"{md}\" xmlns:assertion=\"{assertion}\" xmlns:ds=\"{dsig}\"><IDPSSODescriptor WantAuthnRequestsSigned=\"{wars}\" protocolSupportEnumeration=\"{protocol}\">{body}</IDPSSODescriptor></EntityDescriptor>",
        entity = cfg.entity_id,
        md = namespace::METADATA,
        assertion = namespace::ASSERTION,
        dsig = namespace::DSIG,
        wars = cfg.want_authn_requests_signed,
        protocol = namespace::PROTOCOL,
    )
}

/// Generate IdP metadata XML, validating required config-driven metadata first.
pub fn try_generate_idp_metadata(cfg: &IdpMetadataConfig) -> Result<String, OpenSamlError> {
    if !is_non_empty_array(&cfg.single_sign_on_service) {
        return Err(OpenSamlError::MissingMetadata(
            "SingleSignOnService".to_string(),
        ));
    }
    Ok(generate_idp_metadata(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CertUse;
    use crate::metadata::{IdpMetadata, SpMetadata};

    #[test]
    fn sp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            encrypt_certs: vec!["MIIBencrypt".into()],
            authn_requests_signed: true,
            want_assertions_signed: true,
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_logout_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://sp.example.com/slo",
            )],
            assertion_consumer_service: vec![
                Endpoint {
                    binding: Binding::Post,
                    location: "https://sp.example.com/acs".into(),
                    is_default: true,
                },
                Endpoint::new(Binding::Redirect, "https://sp.example.com/acs-redirect"),
            ],
            elements_order: None,
        };
        let xml = generate_sp_metadata(&cfg);
        let parsed = SpMetadata::from_xml(&xml)?;
        assert_eq!(
            parsed.get_entity_id(),
            Some("https://sp.example.com/metadata")
        );
        assert!(parsed.is_authn_request_signed());
        assert!(parsed.is_want_assertions_signed());
        assert_eq!(
            parsed
                .get_assertion_consumer_service(Binding::Post)
                .as_deref(),
            Some("https://sp.example.com/acs")
        );
        assert_eq!(
            parsed
                .get_single_logout_service(Binding::Redirect)
                .as_deref(),
            Some("https://sp.example.com/slo")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Signing).as_deref(),
            Some("MIIBsigning")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Encryption).as_deref(),
            Some("MIIBencrypt")
        );
        Ok(())
    }

    #[test]
    fn sp_elements_order_respected() {
        let cfg = SpMetadataConfig {
            entity_id: "x".into(),
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        };
        let xml = generate_sp_metadata(&cfg);
        let slo = xml.find("SingleLogoutService").unwrap_or(usize::MAX);
        let acs = xml.find("AssertionConsumerService").unwrap_or(0);
        // default order places SingleLogoutService before AssertionConsumerService
        assert!(slo < acs);
    }

    #[test]
    fn idp_metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBidp".into()],
            want_authn_requests_signed: true,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        };
        let xml = generate_idp_metadata(&cfg);
        let parsed = IdpMetadata::from_xml(&xml)?;
        assert!(parsed.is_want_authn_requests_signed());
        assert_eq!(
            parsed
                .get_single_sign_on_service(Binding::Redirect)
                .as_deref(),
            Some("https://idp.example.com/sso")
        );
        assert_eq!(
            parsed.get_x509_certificate(CertUse::Signing).as_deref(),
            Some("MIIBidp")
        );
        Ok(())
    }

    #[test]
    fn try_generate_idp_metadata_rejects_missing_sso() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            ..Default::default()
        };

        let result = try_generate_idp_metadata(&cfg);

        assert!(matches!(
            result,
            Err(OpenSamlError::MissingMetadata(name)) if name == "SingleSignOnService"
        ));
    }

    #[test]
    fn idp_default_elements_order_matches_historical_output() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let name_id = xml.find("<NameIDFormat").unwrap_or(usize::MAX);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);
        let slo = xml.find("<SingleLogoutService").unwrap_or(usize::MAX);

        assert!(key < name_id);
        assert!(name_id < sso);
        assert!(sso < slo);
    }

    #[test]
    fn idp_custom_elements_order_can_place_sso_before_key_descriptor() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec![
                "SingleSignOnService".into(),
                "KeyDescriptor".into(),
                "NameIDFormat".into(),
                "SingleLogoutService".into(),
            ]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let name_id = xml.find("<NameIDFormat").unwrap_or(usize::MAX);
        let slo = xml.find("<SingleLogoutService").unwrap_or(usize::MAX);

        assert!(sso < key);
        assert!(key < name_id);
        assert!(name_id < slo);
    }

    #[test]
    fn idp_elements_order_filters_empty_groups() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec![
                "KeyDescriptor".into(),
                "NameIDFormat".into(),
                "SingleSignOnService".into(),
                "SingleLogoutService".into(),
            ]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);

        assert!(!xml.contains("<KeyDescriptor"));
        assert!(!xml.contains("<NameIDFormat"));
        assert!(xml.contains("<SingleSignOnService"));
        assert!(xml.contains("<SingleLogoutService"));
    }

    #[test]
    fn idp_custom_elements_order_omits_unlisted_optional_groups() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            name_id_format: vec![name_id_format::EMAIL_ADDRESS.to_string()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
            elements_order: Some(vec!["SingleSignOnService".into()]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);

        assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
        assert!(!xml.contains("<KeyDescriptor"));
        assert!(!xml.contains("<NameIDFormat"));
        assert!(!xml.contains("<SingleLogoutService"));
    }

    #[test]
    fn idp_custom_elements_order_preserves_omitted_populated_sso() {
        let cfg = IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec!["MIIBsigning".into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            elements_order: Some(vec!["KeyDescriptor".into()]),
            ..Default::default()
        };

        let xml = generate_idp_metadata(&cfg);
        let key = xml.find("<KeyDescriptor").unwrap_or(usize::MAX);
        let sso = xml.find("<SingleSignOnService").unwrap_or(usize::MAX);

        assert_eq!(xml.matches("<SingleSignOnService").count(), 1);
        assert!(key < sso);
    }

    #[test]
    fn idp_elements_order_profiles_match_upstream() {
        assert_eq!(
            elements_order::idp::DEFAULT,
            [
                "KeyDescriptor",
                "NameIDFormat",
                "SingleSignOnService",
                "SingleLogoutService",
            ]
        );
        assert_eq!(
            elements_order::idp::ONELOGIN,
            [
                "KeyDescriptor",
                "NameIDFormat",
                "SingleLogoutService",
                "SingleSignOnService",
            ]
        );
        assert_eq!(
            elements_order::idp::SHIBBOLETH,
            [
                "KeyDescriptor",
                "SingleLogoutService",
                "NameIDFormat",
                "SingleSignOnService",
            ]
        );
    }
}
