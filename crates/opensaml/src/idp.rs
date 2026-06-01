//! SAML Identity Provider entity (samlify `entity-idp.ts`).

use crate::constants::{status_code, Binding, ParserType};
use crate::entity::{generate_id, iso8601_offset, now_iso8601, BindingContext, EntitySetting};
use crate::error::OpenSamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::metadata::{generate_idp_metadata, IdpMetadata, IdpMetadataConfig};
use crate::sp::ServiceProvider;
use crate::template::{replace_tags_by_value, LOGIN_RESPONSE_TEMPLATE};

/// A SAML 2.0 Identity Provider: runtime [`EntitySetting`] plus parsed [`IdpMetadata`].
#[derive(Debug, Clone)]
pub struct IdentityProvider {
    /// Runtime configuration (keys, algorithms, flags).
    pub setting: EntitySetting,
    /// Parsed IdP metadata.
    pub metadata: IdpMetadata,
}

impl IdentityProvider {
    /// Build from IdP metadata XML, merging metadata-declared flags into `setting`.
    pub fn from_metadata(xml: &str, mut setting: EntitySetting) -> Result<Self, OpenSamlError> {
        let metadata = IdpMetadata::from_xml(xml)?;
        setting.want_authn_requests_signed = metadata.is_want_authn_requests_signed();
        let formats = metadata.get_name_id_format();
        if !formats.is_empty() {
            setting.name_id_format = formats;
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.get_entity_id().map(str::to_string);
        }
        Ok(Self { setting, metadata })
    }

    /// Build by generating IdP metadata from `config`, then importing it.
    pub fn from_config(
        config: &IdpMetadataConfig,
        setting: EntitySetting,
    ) -> Result<Self, OpenSamlError> {
        Self::from_metadata(&generate_idp_metadata(config), setting)
    }

    /// The IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.metadata.get_metadata()
    }

    fn entity_id(&self) -> String {
        self.setting
            .entity_id
            .clone()
            .or_else(|| self.metadata.get_entity_id().map(str::to_string))
            .unwrap_or_default()
    }

    /// Render the login `<Response>` XML for `sp` (samlify template fill).
    fn render_login_response(
        &self,
        sp: &ServiceProvider,
        in_response_to: Option<&str>,
        name_id: &str,
        id: &str,
        acs: &str,
    ) -> String {
        let now = now_iso8601();
        let later = iso8601_offset(300);
        let name_id_format = self
            .setting
            .name_id_format
            .first()
            .cloned()
            .unwrap_or_default();
        replace_tags_by_value(
            LOGIN_RESPONSE_TEMPLATE,
            &[
                ("ID", id.to_string()),
                ("AssertionID", generate_id()),
                ("Destination", acs.to_string()),
                ("SubjectRecipient", acs.to_string()),
                ("AssertionConsumerServiceURL", acs.to_string()),
                (
                    "Audience",
                    sp.metadata.get_entity_id().unwrap_or_default().to_string(),
                ),
                ("Issuer", self.entity_id()),
                ("IssueInstant", now.clone()),
                ("StatusCode", status_code::SUCCESS.to_string()),
                ("ConditionsNotBefore", now),
                ("ConditionsNotOnOrAfter", later.clone()),
                ("SubjectConfirmationDataNotOnOrAfter", later),
                ("NameIDFormat", name_id_format),
                ("NameID", name_id.to_string()),
                (
                    "InResponseTo",
                    in_response_to.unwrap_or_default().to_string(),
                ),
                ("AuthnStatement", String::new()),
                ("AttributeStatement", String::new()),
            ],
        )
    }

    /// Generate a login `<Response>` for `sp` over `binding` (samlify `createLoginResponse`).
    ///
    /// Requires the `crypto-bergshamra` feature: the response is always signed
    /// (assertion- or message-level) and optionally encrypted.
    pub fn create_login_response(
        &self,
        sp: &ServiceProvider,
        in_response_to: Option<&str>,
        binding: Binding,
        name_id: &str,
        relay_state: Option<&str>,
        encrypt_then_sign: bool,
    ) -> Result<BindingContext, OpenSamlError> {
        let acs = sp
            .metadata
            .get_assertion_consumer_service(binding)
            .ok_or_else(|| OpenSamlError::MissingMetadata("AssertionConsumerService".into()))?;
        let id = generate_id();
        let raw = self.render_login_response(sp, in_response_to, name_id, &id, &acs);
        let signed = self.finalize_login_response(sp, binding, &raw, encrypt_then_sign)?;
        let relay = relay_state.map(str::to_string);
        let (context, signature, sig_alg) =
            self.bind_response(binding, &signed, &acs, relay.as_deref())?;
        Ok(BindingContext {
            id,
            context,
            relay_state: relay,
            entity_endpoint: acs,
            binding,
            request_type: "SAMLResponse",
            signature,
            sig_alg,
        })
    }

    /// Wrap the finalized response XML into the per-binding transport context.
    #[cfg(feature = "crypto-bergshamra")]
    fn bind_response(
        &self,
        binding: Binding,
        xml: &str,
        acs: &str,
        relay_state: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), OpenSamlError> {
        use crate::binding::{append_signature, base64_encode, build_redirect_octet};
        use crate::crypto::{construct_message_signature, keys::load_private_key};

        match binding {
            Binding::Post => Ok((base64_encode(xml.as_bytes()), None, None)),
            Binding::Redirect => {
                let sig_alg = &self.setting.request_signature_algorithm;
                let key = load_private_key(
                    self.setting.private_key.as_deref().unwrap_or_default(),
                    self.setting.private_key_pass.as_deref(),
                )?;
                let octet =
                    build_redirect_octet(ParserType::SamlResponse, xml, relay_state, sig_alg)?;
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                Ok((append_signature(acs, &octet, &sig), None, None))
            }
            Binding::SimpleSign => {
                let sig_alg = &self.setting.request_signature_algorithm;
                let key = load_private_key(
                    self.setting.private_key.as_deref().unwrap_or_default(),
                    self.setting.private_key_pass.as_deref(),
                )?;
                let relay = relay_state.unwrap_or_default();
                let octet = format!("SAMLResponse={xml}&RelayState={relay}&SigAlg={sig_alg}");
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                Ok((
                    base64_encode(xml.as_bytes()),
                    Some(sig),
                    Some(sig_alg.clone()),
                ))
            }
            Binding::Artifact => Err(OpenSamlError::UndefinedBinding),
        }
    }

    #[cfg(not(feature = "crypto-bergshamra"))]
    fn bind_response(
        &self,
        _binding: Binding,
        _xml: &str,
        _acs: &str,
        _relay_state: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), OpenSamlError> {
        Err(OpenSamlError::Unsupported(
            "createLoginResponse requires feature crypto-bergshamra".into(),
        ))
    }

    #[cfg(feature = "crypto-bergshamra")]
    fn finalize_login_response(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        raw: &str,
        encrypt_then_sign: bool,
    ) -> Result<String, OpenSamlError> {
        use crate::crypto::{construct_saml_signature, encrypt_assertion, keys::load_private_key};

        let key_pem = self
            .setting
            .private_key
            .as_deref()
            .ok_or_else(|| OpenSamlError::MissingKey("private_key".into()))?;
        let cert = self
            .setting
            .signing_cert
            .as_deref()
            .ok_or_else(|| OpenSamlError::MissingKey("signing_cert".into()))?;
        let sig_alg = &self.setting.request_signature_algorithm;
        let key = load_private_key(key_pem, self.setting.private_key_pass.as_deref())?;

        let want_assertions_signed = sp.metadata.is_want_assertions_signed();
        // POST embeds an XML-DSig message signature; redirect/SimpleSign use a
        // detached query signature added later in `bind_response`.
        let sign_message =
            binding == Binding::Post && (sp.setting.want_message_signed || !want_assertions_signed);
        let mut xml = raw.to_string();

        // step: sign assertion -> (encrypt) -> sign message
        if want_assertions_signed {
            xml = construct_saml_signature(&xml, false, &key, cert, sig_alg)?;
        }
        if sign_message && !encrypt_then_sign {
            xml = construct_saml_signature(&xml, true, &key, cert, sig_alg)?;
        }
        if self.setting.is_assertion_encrypted {
            let encrypt_cert = sp
                .metadata
                .get_x509_certificate(crate::constants::CertUse::Encryption)
                .ok_or_else(|| OpenSamlError::MissingMetadata("encryption certificate".into()))?;
            xml = encrypt_assertion(
                &xml,
                &encrypt_cert,
                &self.setting.data_encryption_algorithm,
                &self.setting.key_encryption_algorithm,
                "saml",
            )?;
        }
        if sign_message && encrypt_then_sign {
            xml = construct_saml_signature(&xml, true, &key, cert, sig_alg)?;
        }
        Ok(xml)
    }

    #[cfg(not(feature = "crypto-bergshamra"))]
    fn finalize_login_response(
        &self,
        _sp: &ServiceProvider,
        _binding: Binding,
        _raw: &str,
        _encrypt_then_sign: bool,
    ) -> Result<String, OpenSamlError> {
        Err(OpenSamlError::Unsupported(
            "createLoginResponse requires feature crypto-bergshamra".into(),
        ))
    }

    /// Parse and validate an SP login `<AuthnRequest>` (samlify `parseLoginRequest`).
    pub fn parse_login_request(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, OpenSamlError> {
        let signing_certs = sp
            .metadata
            .x509_certificates(crate::constants::CertUse::Signing);
        flow(
            &FlowOptions {
                binding: Some(binding),
                parser_type: Some(ParserType::SamlRequest),
                check_signature: self.metadata.is_want_authn_requests_signed(),
                from_issuer: sp.metadata.get_entity_id(),
                signing_certs: &signing_certs,
                decrypt_key: None,
                decrypt_key_pass: None,
                clock_drifts: self.setting.clock_drifts,
            },
            request,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::Binding;

    const IDPMETA: &str = include_str!("../tests/fixtures/idpmeta.xml");

    #[test]
    fn from_metadata_merges_flags() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdentityProvider::from_metadata(IDPMETA, EntitySetting::default())?;
        assert!(idp.setting.want_authn_requests_signed);
        assert_eq!(
            idp.metadata
                .get_single_sign_on_service(Binding::Redirect)
                .as_deref(),
            Some("https://idp.example.org/sso/SingleSignOnService")
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "crypto-bergshamra"))]
mod crypto_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::metadata::{Endpoint, SpMetadataConfig};

    // A working RSA keypair (used as both IdP and SP signing material in tests).
    const PRIVKEY: &str = include_str!("../tests/fixtures/key/sp_privkey.pem");
    const CERT: &str = include_str!("../tests/fixtures/key/sp_signing_cert.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..Default::default()
        }
    }

    fn idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    fn sp() -> Result<ServiceProvider, OpenSamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                want_assertions_signed: true,
                signing_certs: vec![CERT.into()],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    #[test]
    fn idp_response_consumed_by_sp() -> Result<(), Box<dyn std::error::Error>> {
        let (idp, sp) = (idp()?, sp()?);
        let ctx = idp.create_login_response(
            &sp,
            Some("_req123"),
            Binding::Post,
            "user@example.com",
            None,
            false,
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let result = sp.parse_login_response(&idp, Binding::Post, &request)?;
        assert_eq!(result.extract.get_str("nameID"), Some("user@example.com"));
        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn parse_signed_login_request() -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        let (idp, sp) = (idp()?, sp()?);
        let ctx = sp.create_login_request(&idp, Binding::Post)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]);
        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;
        let signed_xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(signed_xml.contains("<ds:Signature"));
        assert_eq!(result.extract.get_str("request.id"), Some(ctx.id.as_str()));
        Ok(())
    }
}
