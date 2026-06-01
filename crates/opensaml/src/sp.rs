//! SAML Service Provider entity (samlify `entity-sp.ts`).

use crate::binding::{base64_encode, build_redirect_url};
use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting};
use crate::error::OpenSamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::idp::IdentityProvider;
use crate::metadata::{generate_sp_metadata, SpMetadata, SpMetadataConfig};
use crate::template::{replace_tags_by_value, LOGIN_REQUEST_TEMPLATE};

/// A SAML 2.0 Service Provider: runtime [`EntitySetting`] plus parsed [`SpMetadata`].
#[derive(Debug, Clone)]
pub struct ServiceProvider {
    /// Runtime configuration (keys, algorithms, flags).
    pub setting: EntitySetting,
    /// Parsed SP metadata.
    pub metadata: SpMetadata,
}

impl ServiceProvider {
    /// Build from SP metadata XML, merging the metadata-declared flags into `setting`.
    pub fn from_metadata(xml: &str, mut setting: EntitySetting) -> Result<Self, OpenSamlError> {
        let metadata = SpMetadata::from_xml(xml)?;
        setting.authn_requests_signed = metadata.is_authn_request_signed();
        setting.want_assertions_signed = metadata.is_want_assertions_signed();
        let formats = metadata.get_name_id_format();
        if !formats.is_empty() {
            setting.name_id_format = formats;
        }
        if setting.entity_id.is_none() {
            setting.entity_id = metadata.get_entity_id().map(str::to_string);
        }
        Ok(Self { setting, metadata })
    }

    /// Build by generating SP metadata from `config`, then importing it.
    pub fn from_config(
        config: &SpMetadataConfig,
        setting: EntitySetting,
    ) -> Result<Self, OpenSamlError> {
        Self::from_metadata(&generate_sp_metadata(config), setting)
    }

    /// The SP metadata XML.
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

    /// Build a login `<AuthnRequest>` for `idp` over `binding`.
    ///
    /// When both sides require signing, the request is signed (requires the
    /// `crypto-bergshamra` feature and the SP's `private_key`/`signing_cert`).
    pub fn create_login_request(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
    ) -> Result<BindingContext, OpenSamlError> {
        if self.metadata.is_authn_request_signed() != idp.metadata.is_want_authn_requests_signed() {
            return Err(OpenSamlError::Invalid(
                "ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG".into(),
            ));
        }
        let destination = idp
            .metadata
            .get_single_sign_on_service(binding)
            .ok_or_else(|| OpenSamlError::MissingMetadata("SingleSignOnService".into()))?;
        let acs = self
            .metadata
            .get_assertion_consumer_service(Binding::Post)
            .unwrap_or_default();
        let name_id_format = self
            .setting
            .name_id_format
            .first()
            .cloned()
            .unwrap_or_default();
        let id = generate_id();
        let xml = replace_tags_by_value(
            LOGIN_REQUEST_TEMPLATE,
            &[
                ("ID", id.clone()),
                ("IssueInstant", now_iso8601()),
                ("Destination", destination.clone()),
                ("AssertionConsumerServiceURL", acs),
                ("Issuer", self.entity_id()),
                ("NameIDFormat", name_id_format),
                ("AllowCreate", self.setting.allow_create.to_string()),
            ],
        );
        let relay_state =
            (!self.setting.relay_state.is_empty()).then(|| self.setting.relay_state.clone());

        if self.metadata.is_authn_request_signed() {
            return self.signed_request_context(binding, &xml, destination, relay_state, id);
        }

        let context = match binding {
            Binding::Redirect => build_redirect_url(
                &destination,
                ParserType::SamlRequest,
                &xml,
                relay_state.as_deref(),
            )?,
            Binding::Post | Binding::SimpleSign => base64_encode(xml.as_bytes()),
            Binding::Artifact => return Err(OpenSamlError::UndefinedBinding),
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature: None,
            sig_alg: None,
        })
    }

    #[cfg(feature = "crypto-bergshamra")]
    fn signed_request_context(
        &self,
        binding: Binding,
        xml: &str,
        destination: String,
        relay_state: Option<String>,
        id: String,
    ) -> Result<BindingContext, OpenSamlError> {
        use crate::binding::{append_signature, build_redirect_octet};
        use crate::crypto::{
            construct_message_signature, construct_saml_signature, keys::load_private_key,
        };

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

        let (context, signature, sig_alg_out) = match binding {
            Binding::Redirect => {
                let octet = build_redirect_octet(
                    ParserType::SamlRequest,
                    xml,
                    relay_state.as_deref(),
                    sig_alg,
                )?;
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                (append_signature(&destination, &octet, &sig), None, None)
            }
            Binding::Post => {
                let signed = construct_saml_signature(xml, true, &key, cert, sig_alg)?;
                (base64_encode(signed.as_bytes()), None, None)
            }
            Binding::SimpleSign => {
                let relay = relay_state.clone().unwrap_or_default();
                let octet = format!("SAMLRequest={xml}&RelayState={relay}&SigAlg={sig_alg}");
                let sig = construct_message_signature(&octet, &key, sig_alg)?;
                (
                    base64_encode(xml.as_bytes()),
                    Some(sig),
                    Some(sig_alg.clone()),
                )
            }
            Binding::Artifact => return Err(OpenSamlError::UndefinedBinding),
        };
        Ok(BindingContext {
            id,
            context,
            relay_state,
            entity_endpoint: destination,
            binding,
            request_type: "SAMLRequest",
            signature,
            sig_alg: sig_alg_out,
        })
    }

    #[cfg(not(feature = "crypto-bergshamra"))]
    fn signed_request_context(
        &self,
        _binding: Binding,
        _xml: &str,
        _destination: String,
        _relay_state: Option<String>,
        _id: String,
    ) -> Result<BindingContext, OpenSamlError> {
        Err(OpenSamlError::Unsupported(
            "signing AuthnRequest requires feature crypto-bergshamra".into(),
        ))
    }

    /// Parse and validate an IdP login `<Response>` (signature required, samlify parity).
    pub fn parse_login_response(
        &self,
        idp: &IdentityProvider,
        binding: Binding,
        request: &HttpRequest,
    ) -> Result<FlowResult, OpenSamlError> {
        let signing_certs = idp.metadata.x509_certificates(CertUse::Signing);
        let decrypt_key = if self.setting.is_assertion_encrypted {
            self.setting.enc_private_key.as_deref()
        } else {
            None
        };
        flow(
            &FlowOptions {
                binding: Some(binding),
                parser_type: Some(ParserType::SamlResponse),
                check_signature: true,
                from_issuer: idp.metadata.get_entity_id(),
                signing_certs: &signing_certs,
                decrypt_key,
                decrypt_key_pass: self.setting.enc_private_key_pass.as_deref(),
                clock_drifts: self.setting.clock_drifts,
            },
            request,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode};
    use crate::metadata::{Endpoint, IdpMetadataConfig};
    use url::Url;

    fn unsigned_idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
                    Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    fn unsigned_sp() -> Result<ServiceProvider, OpenSamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(
                    Binding::Post,
                    "https://sp.example.com/acs",
                )],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn create_unsigned_login_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = unsigned_sp()?.create_login_request(&unsigned_idp()?, Binding::Redirect)?;
        let url = Url::parse(&ctx.context)?;
        let (_, value) = url
            .query_pairs()
            .find(|(k, _)| k == "SAMLRequest")
            .ok_or("missing SAMLRequest")?;
        let xml = String::from_utf8(deflate_raw_decode(&base64_decode(&value)?)?)?;
        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
        assert!(url.query_pairs().all(|(k, _)| k != "Signature"));
        Ok(())
    }

    #[test]
    fn create_unsigned_login_request_post_is_base64() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = unsigned_sp()?.create_login_request(&unsigned_idp()?, Binding::Post)?;
        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        Ok(())
    }
}

#[cfg(all(test, feature = "crypto-bergshamra"))]
mod crypto_tests {
    use super::*;
    use crate::binding::base64_decode;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::crypto::verify_signature;
    use crate::metadata::{Endpoint, IdpMetadataConfig};

    const RESPONSE_SIGNED: &str = include_str!("../tests/fixtures/response_signed.xml");
    const IDP_CERT: &str = include_str!("../tests/fixtures/key/idp_cert.cer");
    const SP_PRIVKEY: &str = include_str!("../tests/fixtures/key/sp_privkey.pem");
    const SP_SIGNING_CERT: &str = include_str!("../tests/fixtures/key/sp_signing_cert.cer");

    fn signing_idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![IDP_CERT.into()],
                want_authn_requests_signed: true,
                single_sign_on_service: vec![
                    Endpoint::new(Binding::Redirect, "https://idp/sso"),
                    Endpoint::new(Binding::Post, "https://idp/sso"),
                ],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn parse_signed_response_extracts_name_id() -> Result<(), Box<dyn std::error::Error>> {
        let idp = IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                signing_certs: vec![IDP_CERT.into()],
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                ..Default::default()
            },
            EntitySetting::default(),
        )?;
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                clock_drifts: (0, 9_000_000_000_000),
                ..Default::default()
            },
        )?;
        let request = HttpRequest::post(vec![(
            "SAMLResponse".into(),
            base64_encode(RESPONSE_SIGNED.as_bytes()),
        )]);
        let result = sp.parse_login_response(&idp, Binding::Post, &request)?;
        assert_eq!(
            result.extract.get_str("nameID"),
            Some("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7")
        );
        Ok(())
    }

    #[test]
    fn create_signed_post_request_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(&signing_idp()?, Binding::Post)?;
        let signed_xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        let (verified, _) = verify_signature(&signed_xml, &[SP_SIGNING_CERT.to_string()])?;
        assert!(
            verified,
            "signed AuthnRequest should verify with the SP cert"
        );
        Ok(())
    }

    #[test]
    fn create_signed_redirect_request_has_signature() -> Result<(), Box<dyn std::error::Error>> {
        let sp = ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: "https://sp.example.com/metadata".into(),
                authn_requests_signed: true,
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            EntitySetting {
                private_key: Some(SP_PRIVKEY.into()),
                signing_cert: Some(SP_SIGNING_CERT.into()),
                request_signature_algorithm: RSA_SHA256.into(),
                ..Default::default()
            },
        )?;
        let ctx = sp.create_login_request(&signing_idp()?, Binding::Redirect)?;
        assert!(ctx.context.contains("&SigAlg="));
        assert!(ctx.context.contains("&Signature="));
        Ok(())
    }
}
