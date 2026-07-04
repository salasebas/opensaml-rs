use saml_rs::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, name_id_format,
    signature_algorithm, transform_algorithm, Binding,
};
use saml_rs::metadata::Endpoint;
use saml_rs::xml::XmlLimits;
use saml_rs::{
    AssertionSignaturePolicy, AuthnRequestSignaturePolicy, CertificatePem, Credentials,
    DataEncryptionAlgorithm, DigestAlgorithm, EntityId, EntitySetting, IdpConfig, IdpDescriptor,
    IdpMetadataConfigTyped, KeyEncryptionAlgorithm, MessageSignaturePolicy, MetadataTrustPolicy,
    NameIdFormat, Passphrase, PrivateKeyPem, SamlError, SignatureAlgorithm, SpConfig, SpDescriptor,
    SpMetadataConfigTyped, TransformAlgorithm, XmlEncryptionPolicy,
};

const IDP_METADATA: &str = include_str!("fixtures/idpmeta.xml");
const SP_METADATA: &str = include_str!("fixtures/spmeta.xml");

#[test]
fn typed_config_private_key_debug_is_redacted() {
    let key = PrivateKeyPem::new("dummy-private-key-for-redaction-test");

    let debug = format!("{key:?}");

    assert!(!debug.contains("dummy-private-key-for-redaction-test"));
    assert!(debug.contains("redacted"));
}

#[test]
fn typed_config_passphrase_debug_is_redacted() {
    let passphrase = Passphrase::new("dummy-passphrase-for-redaction-test");

    let debug = format!("{passphrase:?}");

    assert!(!debug.contains("dummy-passphrase-for-redaction-test"));
    assert!(debug.contains("redacted"));
}

#[test]
fn typed_config_certificate_debug_does_not_dump_pem() {
    let certificate = CertificatePem::new("dummy-certificate-for-redaction-test");

    let debug = format!("{certificate:?}");

    assert!(!debug.contains("dummy-certificate-for-redaction-test"));
    assert!(debug.contains("CertificatePem"));
}

#[test]
fn typed_config_algorithm_enums_return_existing_uri_constants() {
    assert_eq!(
        SignatureAlgorithm::RsaSha256.as_uri(),
        signature_algorithm::RSA_SHA256
    );
    assert_eq!(
        SignatureAlgorithm::RsaSha384.as_uri(),
        signature_algorithm::RSA_SHA384
    );
    assert_eq!(
        SignatureAlgorithm::RsaSha512.as_uri(),
        signature_algorithm::RSA_SHA512
    );
    assert_eq!(DigestAlgorithm::Sha256.as_uri(), digest_algorithm::SHA256);
    assert_eq!(DigestAlgorithm::Sha384.as_uri(), digest_algorithm::SHA384);
    assert_eq!(
        DataEncryptionAlgorithm::Aes256.as_uri(),
        data_encryption_algorithm::AES_256
    );
    assert_eq!(
        KeyEncryptionAlgorithm::RsaOaepMgf1p.as_uri(),
        key_encryption_algorithm::RSA_OAEP_MGF1P
    );
    assert_eq!(
        TransformAlgorithm::EnvelopedSignature.as_uri(),
        transform_algorithm::ENVELOPED_SIGNATURE
    );
    assert_eq!(
        TransformAlgorithm::ExclusiveCanonicalization.as_uri(),
        transform_algorithm::EXC_C14N
    );
}

#[test]
fn typed_config_name_id_formats_return_existing_uri_constants() {
    assert_eq!(
        NameIdFormat::EmailAddress.as_uri(),
        name_id_format::EMAIL_ADDRESS
    );
    assert_eq!(
        NameIdFormat::Persistent.as_uri(),
        name_id_format::PERSISTENT
    );
    assert_eq!(NameIdFormat::Transient.as_uri(), name_id_format::TRANSIENT);
    assert_eq!(NameIdFormat::Entity.as_uri(), name_id_format::ENTITY);
    assert_eq!(
        NameIdFormat::Unspecified.as_uri(),
        name_id_format::UNSPECIFIED
    );
    assert_eq!(NameIdFormat::Kerberos.as_uri(), name_id_format::KERBEROS);
    assert_eq!(
        NameIdFormat::WindowsDomainQualifiedName.as_uri(),
        name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME
    );
    assert_eq!(
        NameIdFormat::X509SubjectName.as_uri(),
        name_id_format::X509_SUBJECT_NAME
    );
}

#[test]
fn typed_config_sp_config_converts_selected_settings() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = SpConfig::new(
        EntityId::new("https://sp.example.com/metadata"),
        SpMetadataConfigTyped::new(vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )]),
    );
    let limits = XmlLimits {
        max_bytes: 32_768,
        max_depth: 64,
        max_nodes: 512,
        max_attributes_per_element: 16,
        max_attribute_value_bytes: 2048,
        max_text_bytes: 4096,
    };
    config.metadata.name_id_format = vec![NameIdFormat::EmailAddress];
    config.credentials = Credentials {
        signing_key: Some(PrivateKeyPem::new("dummy-private-key-for-conversion-test")),
        signing_certificate: Some(CertificatePem::new(
            "dummy-signing-certificate-for-conversion-test",
        )),
        ..Credentials::default()
    };
    config.validation.assertions = AssertionSignaturePolicy::RequireSigned;
    config.validation.messages = MessageSignaturePolicy::RequireSigned;
    config.validation.authn_requests = AuthnRequestSignaturePolicy::RequireSigned;
    config.xml.clock_drifts = (-120_000, 180_000);
    config.xml.limits = limits;
    config.algorithms.signature = SignatureAlgorithm::RsaSha512;
    config.algorithms.data_encryption = DataEncryptionAlgorithm::Aes128;
    config.algorithms.key_encryption = KeyEncryptionAlgorithm::Rsa15;
    config.algorithms.signed_reference_transforms =
        vec![TransformAlgorithm::ExclusiveCanonicalization];

    let debug = format!("{:?}", config.credentials);
    let setting = EntitySetting::try_from(&config)?;

    assert!(!debug.contains("dummy-private-key-for-conversion-test"));
    assert_eq!(
        setting.entity_id.as_deref(),
        Some("https://sp.example.com/metadata")
    );
    assert_eq!(
        setting.private_key.as_deref(),
        Some("dummy-private-key-for-conversion-test")
    );
    assert_eq!(
        setting.signing_cert.as_deref(),
        Some("dummy-signing-certificate-for-conversion-test")
    );
    assert!(setting.want_assertions_signed);
    assert!(setting.want_message_signed);
    assert!(setting.authn_requests_signed);
    assert_eq!(setting.clock_drifts, (-120_000, 180_000));
    assert_eq!(setting.xml_limits, limits);
    assert_eq!(
        setting.request_signature_algorithm,
        signature_algorithm::RSA_SHA512
    );
    assert_eq!(
        setting.data_encryption_algorithm,
        data_encryption_algorithm::AES_128
    );
    assert_eq!(
        setting.key_encryption_algorithm,
        key_encryption_algorithm::RSA_1_5
    );
    assert_eq!(
        setting.transformation_algorithms,
        vec![transform_algorithm::EXC_C14N.to_string()]
    );
    Ok(())
}

#[test]
fn typed_config_idp_config_converts_authn_request_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let mut config = IdpConfig::new(
        EntityId::new("https://idp.example.com/metadata"),
        IdpMetadataConfigTyped::new(vec![Endpoint::new(
            Binding::Redirect,
            "https://idp.example.com/sso",
        )]),
    );
    config.metadata.name_id_format = vec![NameIdFormat::Transient];
    config.validation.authn_requests = AuthnRequestSignaturePolicy::RequireSigned;

    let setting = EntitySetting::try_from(&config)?;

    assert_eq!(
        setting.entity_id.as_deref(),
        Some("https://idp.example.com/metadata")
    );
    assert!(setting.want_authn_requests_signed);
    assert_eq!(
        setting.name_id_format,
        vec![name_id_format::TRANSIENT.to_string()]
    );
    Ok(())
}

#[test]
fn typed_config_insecure_rsa_key_transport_requires_explicit_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SpConfig::new(
        EntityId::new("https://sp.example.com/metadata"),
        SpMetadataConfigTyped::new(vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )]),
    );
    let default_setting = EntitySetting::try_from(&config)?;
    let mut explicit_config = config.clone();
    explicit_config.xml.encryption =
        XmlEncryptionPolicy::allow_insecure_software_rsa_key_transport_decryption();

    let explicit_setting = EntitySetting::try_from(&explicit_config)?;

    assert!(!default_setting.allow_insecure_software_rsa_key_transport_decryption);
    assert!(explicit_setting.allow_insecure_software_rsa_key_transport_decryption);
    Ok(())
}

#[test]
fn typed_config_idp_descriptor_accepts_expected_unsigned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::new("https://idp.example.com/metadata"),
        IDP_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    assert_eq!(
        descriptor.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert!(!descriptor.was_verified_with_pinned_certificates());
    Ok(())
}

#[test]
fn typed_config_idp_descriptor_rejects_unexpected_entity_id() {
    let result = IdpDescriptor::from_metadata_xml_for(
        EntityId::new("https://unexpected.example.com/metadata"),
        IDP_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    );

    assert!(
        matches!(
            &result,
            Err(SamlError::Invalid(message))
                if message.contains("metadata entityID")
                    && message.contains("https://unexpected.example.com/metadata")
                    && message.contains("https://idp.example.com/metadata")
        ),
        "unexpected entity ID error: {result:?}"
    );
}

#[test]
fn typed_config_sp_descriptor_accepts_expected_unsigned_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::new("https://sp.example.org/metadata"),
        SP_METADATA,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    assert_eq!(
        descriptor.entity_id().as_str(),
        "https://sp.example.org/metadata"
    );
    assert!(!descriptor.was_verified_with_pinned_certificates());
    Ok(())
}

#[test]
fn typed_config_pinned_certificate_trust_does_not_accept_unsigned_metadata() {
    let result = IdpDescriptor::from_metadata_xml_for(
        EntityId::new("https://idp.example.com/metadata"),
        IDP_METADATA,
        MetadataTrustPolicy::RequireSignedByPinnedCertificates(&[]),
    );

    assert!(
        result.is_err(),
        "empty pinned certificate trust must not accept unsigned metadata"
    );
}
