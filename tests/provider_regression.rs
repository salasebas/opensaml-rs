#![cfg(any(
    feature = "crypto-rustcrypto",
    feature = "crypto-aws-lc",
    feature = "crypto-fips"
))]

use saml_rs::constants::data_encryption_algorithm::AES_256;
use saml_rs::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{
    construct_message_signature, construct_saml_signature, decrypt_assertion, encrypt_assertion,
    verify_message_signature, verify_signature, AssertionDecryptionOptions,
};
#[cfg(feature = "crypto-fips")]
use saml_rs::SamlError;
use saml_rs::{initialize_crypto_provider, CryptoFipsStatus, CryptoProvider};

const PRIVATE_KEY: &str = include_str!("fixtures/key/idp/nocrypt.pem");
const CERTIFICATE: &str = include_str!("fixtures/key/idp/cert.cer");
const RESPONSE: &str = include_str!("fixtures/response.xml");

#[test]
fn provider_initialization_reports_selected_provider_and_attestation(
) -> Result<(), Box<dyn std::error::Error>> {
    let info = initialize_crypto_provider()?;

    #[cfg(feature = "crypto-rustcrypto")]
    assert_eq!(info.provider(), CryptoProvider::RustCrypto);
    #[cfg(any(feature = "crypto-aws-lc", feature = "crypto-fips"))]
    assert_eq!(info.provider(), CryptoProvider::AwsLc);
    #[cfg(feature = "crypto-fips")]
    assert_eq!(info.fips_status(), CryptoFipsStatus::Active);
    #[cfg(not(feature = "crypto-fips"))]
    assert_eq!(info.fips_status(), CryptoFipsStatus::Disabled);

    Ok(())
}

#[test]
fn provider_xml_signature_round_trip_uses_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;
    let signed =
        construct_saml_signature(RESPONSE, true, &key, CERTIFICATE, RSA_SHA256, &[], None)?;
    let (verified, signed_content) = verify_signature(&signed, &[CERTIFICATE.to_string()])?;

    assert!(verified);
    assert!(signed_content.is_some());
    Ok(())
}

#[test]
fn provider_detached_signature_round_trip_uses_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let key = load_private_key(PRIVATE_KEY, None)?;
    let signed_octets = "SAMLRequest=provider-matrix&RelayState=state";
    let signature = construct_message_signature(signed_octets, &key, RSA_SHA256)?;

    assert!(verify_message_signature(
        signed_octets,
        &signature,
        CERTIFICATE,
        RSA_SHA256,
    )?);
    Ok(())
}

#[cfg(not(feature = "crypto-fips"))]
#[test]
fn provider_xml_encryption_round_trip_preserves_assertion() -> Result<(), Box<dyn std::error::Error>>
{
    let encrypted = encrypt_assertion(RESPONSE, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "saml")?;
    let key = load_private_key(PRIVATE_KEY, None)?;
    let mut options = AssertionDecryptionOptions::default();
    options.allow_insecure_software_rsa_key_transport_decryption = true;
    let (_, assertion) = decrypt_assertion(&encrypted, &key, options)?;

    assert!(assertion.contains("Assertion"));
    Ok(())
}

#[cfg(feature = "crypto-fips")]
#[test]
fn fips_provider_rejects_sha1_rsa_oaep_key_transport() -> Result<(), Box<dyn std::error::Error>> {
    initialize_crypto_provider()?;

    assert!(matches!(
        encrypt_assertion(RESPONSE, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "saml",),
        Err(SamlError::Crypto(_))
    ));
    Ok(())
}
