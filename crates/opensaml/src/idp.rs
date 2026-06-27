//! SAML Identity Provider entity (samlify `entity-idp.ts`).

use crate::constants::{status_code, Binding, ParserType};
use crate::entity::{
    generate_id, iso8601_offset, now_iso8601, BindingContext, CustomTagReplacement, EntitySetting,
    User,
};
use crate::error::OpenSamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::metadata::{generate_idp_metadata, IdpMetadata, IdpMetadataConfig};
use crate::sp::ServiceProvider;
use crate::template::{
    attr_tag, attribute_statement_builder, replace_tags_by_value, ATTRIBUTE_STATEMENT_TEMPLATE,
    ATTRIBUTE_TEMPLATE, LOGIN_RESPONSE_TEMPLATE,
};

/// Optional inputs for [`IdentityProvider::create_login_response`]
/// (samlify's `createLoginResponse` trailing parameters).
#[derive(Default)]
pub struct LoginResponseOptions<'a> {
    /// `InResponseTo` — the SP request id being answered.
    pub in_response_to: Option<&'a str>,
    /// RelayState to echo back to the SP.
    pub relay_state: Option<&'a str>,
    /// Encrypt-then-sign instead of the default sign-then-encrypt.
    pub encrypt_then_sign: bool,
    /// Custom template rendering hook (samlify `customTagReplacement`).
    pub custom: Option<CustomTagReplacement<'a>>,
}

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

    /// Render the login `<Response>` XML for `sp`, returning `(id, xml)`.
    ///
    /// `custom` (samlify `customTagReplacement`) overrides tag filling: it
    /// receives the template with the `<AttributeStatement>` already injected.
    fn render_login_response(
        &self,
        sp: &ServiceProvider,
        in_response_to: Option<&str>,
        user: &User,
        acs: &str,
        custom: Option<CustomTagReplacement<'_>>,
    ) -> (String, String) {
        let tmpl = self.setting.login_response_template.as_ref();
        let base = tmpl
            .and_then(|t| t.context.as_deref())
            .unwrap_or(LOGIN_RESPONSE_TEMPLATE);
        let attributes = tmpl.map(|t| t.attributes.as_slice()).unwrap_or(&[]);
        let attribute_statement = if attributes.is_empty() {
            String::new()
        } else {
            attribute_statement_builder(
                attributes,
                ATTRIBUTE_TEMPLATE,
                ATTRIBUTE_STATEMENT_TEMPLATE,
            )
        };
        let prepared = base.replacen("{AttributeStatement}", &attribute_statement, 1);
        if let Some(f) = custom {
            return f(&prepared);
        }
        let now = now_iso8601();
        let later = iso8601_offset(300);
        let name_id_format = self
            .setting
            .name_id_format
            .first()
            .cloned()
            .unwrap_or_default();
        let id = generate_id();
        let mut tags: Vec<(&str, String)> = vec![
            ("ID", id.clone()),
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
            ("NameID", user.name_id.clone()),
            (
                "InResponseTo",
                in_response_to.unwrap_or_default().to_string(),
            ),
            ("AuthnStatement", String::new()),
        ];
        // Attribute value placeholders ({attr<Tag>}) are filled from the user's
        // attributes after the AttributeStatement is expanded into the template.
        let attr_pairs: Vec<(String, String)> = user
            .attributes
            .iter()
            .map(|(tag, value)| (attr_tag(tag), value.clone()))
            .collect();
        for (key, value) in &attr_pairs {
            tags.push((key.as_str(), value.clone()));
        }
        (id, replace_tags_by_value(&prepared, &tags))
    }

    /// Generate a login `<Response>` for `sp` over `binding` (samlify `createLoginResponse`).
    ///
    /// Requires the `crypto-bergshamra` feature: the response is always signed
    /// (assertion- or message-level) and optionally encrypted. Attributes are
    /// taken from `user`; `options` carries `InResponseTo`, RelayState, the
    /// encrypt-then-sign toggle, and an optional `customTagReplacement` hook.
    pub fn create_login_response(
        &self,
        sp: &ServiceProvider,
        binding: Binding,
        user: &User,
        options: &LoginResponseOptions<'_>,
    ) -> Result<BindingContext, OpenSamlError> {
        let acs = sp
            .metadata
            .get_assertion_consumer_service(binding)
            .ok_or_else(|| OpenSamlError::MissingMetadata("AssertionConsumerService".into()))?;
        let (id, raw) =
            self.render_login_response(sp, options.in_response_to, user, &acs, options.custom);
        let signed = self.finalize_login_response(sp, binding, &raw, options.encrypt_then_sign)?;
        let relay = options.relay_state.map(str::to_string);
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
        _encrypt_then_sign: bool,
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
            xml = construct_saml_signature(
                &xml,
                false,
                &key,
                cert,
                sig_alg,
                &sp.setting.transformation_algorithms,
                None,
            )?;
        }
        // Sign-then-encrypt of a sub-element would invalidate an outer message
        // signature, so when encrypting we always sign the message *after*
        // encryption (sound encrypt-then-sign). Without encryption, sign here.
        if sign_message && !self.setting.is_assertion_encrypted {
            xml = construct_saml_signature(
                &xml,
                true,
                &key,
                cert,
                sig_alg,
                &sp.setting.transformation_algorithms,
                self.setting.signature_config.as_ref(),
            )?;
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
                &self.setting.tag_prefix_encrypted_assertion,
            )?;
        }
        if sign_message && self.setting.is_assertion_encrypted {
            xml = construct_saml_signature(
                &xml,
                true,
                &key,
                cert,
                sig_alg,
                &sp.setting.transformation_algorithms,
                self.setting.signature_config.as_ref(),
            )?;
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
                allow_insecure_software_rsa_key_transport_decryption: false,
                clock_drifts: self.setting.clock_drifts,
                redirect_inflate_max_bytes: self.setting.redirect_inflate_max_bytes,
                expected_audience: None,
                expected_in_response_to: None,
            },
            request,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::Binding;
    use crate::metadata::{Endpoint, SpMetadataConfig};

    const IDPMETA: &str = include_str!("../tests/fixtures/idpmeta.xml");

    fn unsigned_idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp(entity_id: &str) -> Result<ServiceProvider, OpenSamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

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

    #[test]
    fn parse_login_request_accepts_matching_sp_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let idp = unsigned_idp()?;
        let sp = unsigned_sp("https://sp.example.com/metadata")?;
        let ctx = sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;

        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://sp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn parse_login_request_rejects_unexpected_sp_issuer() -> Result<(), Box<dyn std::error::Error>>
    {
        let idp = unsigned_idp()?;
        let expected_sp = unsigned_sp("https://expected-sp.example.com/metadata")?;
        let attacker_sp = unsigned_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = attacker_sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(OpenSamlError::UnmatchIssuer)));
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

    fn signed_sp(entity_id: &str) -> Result<ServiceProvider, OpenSamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                authn_requests_signed: true,
                want_assertions_signed: true,
                signing_certs: vec![CERT.into()],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    fn sp() -> Result<ServiceProvider, OpenSamlError> {
        signed_sp("https://sp.example.com/metadata")
    }

    #[test]
    fn idp_response_consumed_by_sp() -> Result<(), Box<dyn std::error::Error>> {
        let (idp, sp) = (idp()?, sp()?);
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &User::new("user@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req123"),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let result =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req123")?;
        assert_eq!(result.extract.get_str("nameID"), Some("user@example.com"));
        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        Ok(())
    }

    #[test]
    fn login_response_with_attributes() -> Result<(), Box<dyn std::error::Error>> {
        use crate::template::{LoginResponseAttribute, LoginResponseTemplate};
        let mut setting = signing_setting();
        setting.login_response_template = Some(LoginResponseTemplate {
            context: None,
            attributes: vec![LoginResponseAttribute {
                name: "mail".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            }],
        });
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            setting,
        )?;
        let sp = sp()?;
        let user = User {
            name_id: "alice@example.com".into(),
            attributes: vec![("email".into(), "alice@example.com".into())],
            session_index: None,
        };
        let ctx = idp.create_login_response(
            &sp,
            Binding::Post,
            &user,
            &LoginResponseOptions {
                in_response_to: Some("_r1"),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
        let parsed =
            sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_r1")?;
        assert_eq!(
            parsed.extract.get_str("attributes.mail"),
            Some("alice@example.com")
        );
        Ok(())
    }

    #[test]
    fn parse_signed_login_request() -> Result<(), Box<dyn std::error::Error>> {
        use crate::binding::base64_decode;
        let (idp, sp) = (idp()?, sp()?);
        let ctx = sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]);
        let result = idp.parse_login_request(&sp, Binding::Post, &request)?;
        let signed_xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(signed_xml.contains("<ds:Signature"));
        assert_eq!(result.extract.get_str("request.id"), Some(ctx.id.as_str()));
        Ok(())
    }

    #[test]
    fn parse_signed_login_request_rejects_unexpected_sp_issuer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let idp = idp()?;
        let expected_sp = sp()?;
        let attacker_sp = signed_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = attacker_sp.create_login_request(&idp, Binding::Post, None)?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result = idp.parse_login_request(&expected_sp, Binding::Post, &request);

        assert!(matches!(result, Err(OpenSamlError::UnmatchIssuer)));
        Ok(())
    }
}
