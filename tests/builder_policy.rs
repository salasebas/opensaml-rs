use std::str::FromStr;

use saml_rs::{
    AcsEndpoint, AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy,
    AudienceValidationPolicy, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy,
    CertificatePem, Credentials, DataEncryptionAlgorithm, DigestAlgorithm, EntityId, EntitySetting,
    IdpConfig, IdpMetadataConfig, IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy,
    LogoutSignaturePolicy, MessageSignaturePolicy, NameIdCreationPolicy, Passphrase, PrivateKeyPem,
    SamlError, SignatureAlgorithm, SloEndpoint, SpConfig, SpMetadataConfig, SpValidationPolicy,
    SsoEndpoint, TemplatePolicy, TransformAlgorithm, XmlEncryptionPolicy, XmlPolicy,
};

fn signing_credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new("test signing key")),
        signing_certificate: Some(CertificatePem::new("test signing certificate")),
        ..Credentials::default()
    }
}

fn assert_missing_metadata(result: Result<impl Sized, SamlError>, field: &str) {
    assert!(matches!(
        result,
        Err(SamlError::MissingMetadata(message)) if message == field
    ));
}

fn assert_missing_key(result: Result<impl Sized, SamlError>, field: &str) {
    assert!(matches!(
        result,
        Err(SamlError::MissingKey(message)) if message == field
    ));
}

#[test]
fn sp_builder_and_struct_literal_reach_same_config() -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://sp.example.com/metadata")?;
    let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
    let slo = SloEndpoint::post("https://sp.example.com/slo")?;
    let credentials = signing_credentials();
    let validation = SpValidationPolicy::strict();

    let builder = SpConfig::builder(entity_id.clone())
        .acs_endpoint(acs.clone())
        .slo_endpoint(slo.clone())
        .name_id_format(saml_rs::NameIdFormat::EmailAddress)
        .credentials(credentials.clone())
        .validation(validation.clone())
        .build()?;
    let literal = SpConfig {
        entity_id,
        metadata: SpMetadataConfig {
            name_id_format: vec![saml_rs::NameIdFormat::EmailAddress],
            single_logout_service: vec![slo],
            assertion_consumer_service: vec![acs],
            elements_order: None,
        },
        credentials,
        validation,
        algorithms: AlgorithmPolicy::default(),
        xml: XmlPolicy::default(),
        templates: Default::default(),
    };
    literal.validate()?;

    assert_eq!(builder.entity_id, literal.entity_id);
    assert_eq!(builder.metadata, literal.metadata);
    assert_eq!(builder.credentials, literal.credentials);
    assert_eq!(builder.validation, literal.validation);
    assert_eq!(builder.algorithms, literal.algorithms);
    assert_eq!(builder.xml, literal.xml);
    Ok(())
}

#[test]
fn idp_builder_and_struct_literal_reach_same_config() -> Result<(), Box<dyn std::error::Error>> {
    let entity_id = EntityId::try_new("https://idp.example.com/metadata")?;
    let sso = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let slo = SloEndpoint::post("https://idp.example.com/slo")?;
    let validation = IdpValidationPolicy::strict();

    let builder = IdpConfig::builder(entity_id.clone())
        .sso_endpoint(sso.clone())
        .slo_endpoint(slo.clone())
        .validation(validation.clone())
        .build()?;
    let literal = IdpConfig {
        entity_id,
        metadata: IdpMetadataConfig {
            name_id_format: Vec::new(),
            single_sign_on_service: vec![sso],
            single_logout_service: vec![slo],
            elements_order: None,
        },
        credentials: Credentials::default(),
        validation,
        algorithms: AlgorithmPolicy::default(),
        xml: XmlPolicy::default(),
        templates: Default::default(),
    };
    literal.validate()?;

    assert_eq!(builder.entity_id, literal.entity_id);
    assert_eq!(builder.metadata, literal.metadata);
    assert_eq!(builder.validation, literal.validation);
    assert_eq!(builder.algorithms, literal.algorithms);
    assert_eq!(builder.xml, literal.xml);
    Ok(())
}

#[test]
fn builders_default_to_strict_validation() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(signing_credentials())
        .build()?;
    let idp = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .build()?;

    assert_eq!(sp.validation, SpValidationPolicy::strict());
    assert_eq!(idp.validation, IdpValidationPolicy::strict());
    assert_eq!(
        sp.validation.assertions,
        AssertionSignaturePolicy::RequireSigned
    );
    assert_eq!(
        sp.validation.messages,
        MessageSignaturePolicy::RequireSigned
    );
    assert_eq!(
        sp.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    );
    assert_eq!(sp.validation.audience, AudienceValidationPolicy::Validate);
    assert_eq!(
        sp.validation.name_id_creation,
        NameIdCreationPolicy::DoNotAllowCreate
    );
    assert_eq!(sp.validation.logout, LogoutPolicy::strict());
    Ok(())
}

#[test]
fn compatibility_policy_names_unsigned_choices_explicitly() {
    let sp = SpValidationPolicy::compatibility();
    let idp = IdpValidationPolicy::compatibility();

    assert_eq!(
        sp.assertions,
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        sp.messages,
        MessageSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        sp.authn_requests,
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    );
    assert_eq!(sp.audience, AudienceValidationPolicy::SkipForCompatibility);
    assert_eq!(sp.logout, LogoutPolicy::compatibility());
    assert_eq!(
        idp.authn_requests,
        AuthnRequestValidationPolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        idp.logout.requests,
        LogoutSignaturePolicy::AllowUnsignedForCompatibility
    );
}

#[test]
fn public_validation_defaults_remain_compatibility() {
    assert_eq!(
        SpValidationPolicy::default(),
        SpValidationPolicy::compatibility()
    );
    assert_eq!(
        IdpValidationPolicy::default(),
        IdpValidationPolicy::compatibility()
    );
    assert_eq!(
        AssertionSignaturePolicy::default(),
        AssertionSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        MessageSignaturePolicy::default(),
        MessageSignaturePolicy::AllowUnsignedForCompatibility
    );
    assert_eq!(
        AuthnRequestSigningPolicy::default(),
        AuthnRequestSigningPolicy::DoNotSignForCompatibility
    );
    assert_eq!(
        AuthnRequestValidationPolicy::default(),
        AuthnRequestValidationPolicy::AllowUnsignedForCompatibility
    );
}

#[test]
fn constructors_use_compatibility_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let sp = SpConfig::try_new(
        EntityId::try_new("https://sp.example.com/metadata")?,
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    )?;
    let idp = IdpConfig::try_new(
        EntityId::try_new("https://idp.example.com/metadata")?,
        IdpMetadataConfig::new(vec![SsoEndpoint::redirect("https://idp.example.com/sso")?]),
    )?;

    assert_eq!(sp.validation, SpValidationPolicy::compatibility());
    assert_eq!(idp.validation, IdpValidationPolicy::compatibility());
    Ok(())
}

#[test]
fn legacy_algorithm_variants_are_risk_named() {
    let variants = [
        format!("{:?}", DigestAlgorithm::Sha1ForCompatibility),
        format!("{:?}", DataEncryptionAlgorithm::TripleDesForCompatibility),
        format!("{:?}", KeyEncryptionAlgorithm::Rsa15ForCompatibility),
    ];

    assert!(variants
        .iter()
        .all(|variant| variant.contains("Compatibility") || variant.contains("Legacy")));
}

#[test]
fn custom_algorithm_variants_keep_simple_names() {
    let variants = [
        format!("{:?}", SignatureAlgorithm::Custom("urn:test".into())),
        format!("{:?}", DigestAlgorithm::Custom("urn:test".into())),
        format!("{:?}", DataEncryptionAlgorithm::Custom("urn:test".into())),
        format!("{:?}", KeyEncryptionAlgorithm::Custom("urn:test".into())),
        format!("{:?}", TransformAlgorithm::Custom("urn:test".into())),
    ];

    assert!(variants.iter().all(|variant| variant.contains("Custom")));
    assert!(variants
        .iter()
        .all(|variant| !variant.contains("Compatibility")));
}

#[test]
fn sp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let elements_order = vec!["AssertionConsumerService".to_string()];
    let algorithms = AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha512,
        data_encryption: DataEncryptionAlgorithm::Aes128,
        key_encryption: KeyEncryptionAlgorithm::RsaOaepMgf1p,
        signed_reference_transforms: vec![TransformAlgorithm::ExclusiveCanonicalization],
        ..AlgorithmPolicy::default()
    };
    let xml = XmlPolicy {
        clock_drifts: (-1000, 2000),
        ..XmlPolicy::default()
    };
    let templates = TemplatePolicy {
        relay_state: "relay-state".to_string(),
        tag_prefix_protocol: "p".to_string(),
        ..TemplatePolicy::default()
    };

    let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(signing_credentials())
        .elements_order(elements_order.clone())
        .algorithms(algorithms.clone())
        .xml(xml)
        .templates(templates.clone())
        .build()?;

    assert_eq!(config.metadata.elements_order, Some(elements_order));
    assert_eq!(config.algorithms, algorithms);
    assert_eq!(config.xml, xml);
    assert_eq!(config.templates.relay_state, templates.relay_state);
    assert_eq!(
        config.templates.tag_prefix_protocol,
        templates.tag_prefix_protocol
    );
    Ok(())
}

#[test]
fn idp_builder_sets_policy_setters() -> Result<(), Box<dyn std::error::Error>> {
    let elements_order = vec!["SingleSignOnService".to_string()];
    let algorithms = AlgorithmPolicy {
        signature: SignatureAlgorithm::RsaSha384,
        data_encryption: DataEncryptionAlgorithm::Aes256,
        key_encryption: KeyEncryptionAlgorithm::RsaOaepMgf1p,
        signed_reference_transforms: vec![TransformAlgorithm::EnvelopedSignature],
        ..AlgorithmPolicy::default()
    };
    let xml = XmlPolicy {
        clock_drifts: (-2000, 3000),
        ..XmlPolicy::default()
    };
    let templates = TemplatePolicy {
        relay_state: "idp-relay".to_string(),
        tag_prefix_assertion: "a".to_string(),
        ..TemplatePolicy::default()
    };

    let config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .elements_order(elements_order.clone())
        .algorithms(algorithms.clone())
        .xml(xml)
        .templates(templates.clone())
        .build()?;

    assert_eq!(config.metadata.elements_order, Some(elements_order));
    assert_eq!(config.algorithms, algorithms);
    assert_eq!(config.xml, xml);
    assert_eq!(config.templates.relay_state, templates.relay_state);
    assert_eq!(
        config.templates.tag_prefix_assertion,
        templates.tag_prefix_assertion
    );
    Ok(())
}

#[test]
fn entity_id_from_str_and_try_from_reject_empty_input() {
    let parsed = EntityId::from_str(" ");
    let tried = EntityId::try_from(String::new());

    assert!(matches!(parsed, Err(SamlError::Invalid(_))));
    assert!(matches!(tried, Err(SamlError::Invalid(_))));
}

#[test]
fn sp_builder_rejects_empty_entity_id() -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::new("   "))
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(signing_credentials())
        .build();

    assert!(matches!(result, Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn struct_literal_conversion_rejects_empty_entity_id() -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::new(
        EntityId::new(""),
        SpMetadataConfig::new(vec![AcsEndpoint::post("https://sp.example.com/acs")?]),
    );
    let result = EntitySetting::try_from(&config);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
    Ok(())
}

#[test]
fn sp_builder_rejects_signing_passphrase_without_signing_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        signing_key_passphrase: Some(Passphrase::new("test passphrase")),
        ..Credentials::default()
    };

    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .credentials(credentials)
        .build();

    assert_missing_key(result, "signing_key");
    Ok(())
}

#[test]
fn sp_builder_rejects_decryption_passphrase_without_decryption_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        decryption_key_passphrase: Some(Passphrase::new("test passphrase")),
        ..Credentials::default()
    };

    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .credentials(credentials)
        .build();

    assert_missing_key(result, "decryption_key");
    Ok(())
}

#[test]
fn sp_builder_rejects_missing_acs() -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .credentials(signing_credentials())
        .build();

    assert_missing_metadata(result, "AssertionConsumerService");
    Ok(())
}

#[test]
fn idp_builder_rejects_missing_sso() -> Result<(), Box<dyn std::error::Error>> {
    let result = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?).build();

    assert_missing_metadata(result, "SingleSignOnService");
    Ok(())
}

#[test]
fn sp_builder_requires_signing_credentials_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .build();

    assert_missing_key(result, "signing_key");
    Ok(())
}

#[test]
fn sp_builder_requires_signing_certificate_when_authn_requests_are_signed(
) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = Credentials {
        signing_key: Some(PrivateKeyPem::new("test signing key")),
        ..Credentials::default()
    };
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(credentials)
        .build();

    assert_missing_key(result, "signing_certificate");
    Ok(())
}

#[test]
fn sp_builder_allows_protocol_only_compatibility_without_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .build()?;

    assert_eq!(config.validation, SpValidationPolicy::compatibility());
    assert_eq!(config.credentials, Credentials::default());
    Ok(())
}

#[test]
fn sp_builder_requires_decryption_key_when_encrypted_assertions_are_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };
    let result = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .xml(xml)
        .build();

    assert_missing_key(result, "decryption_key");
    Ok(())
}

#[test]
fn metadata_try_new_rejects_missing_required_endpoints() {
    let sp = SpMetadataConfig::try_new(Vec::new());
    let idp = IdpMetadataConfig::try_new(Vec::new());

    assert_missing_metadata(sp, "AssertionConsumerService");
    assert_missing_metadata(idp, "SingleSignOnService");
}

#[test]
fn xml_encryption_policy_defaults_to_plaintext_assertions() {
    assert_eq!(
        XmlPolicy::default().encryption.assertions,
        AssertionEncryptionPolicy::PlaintextAssertions
    );
}
