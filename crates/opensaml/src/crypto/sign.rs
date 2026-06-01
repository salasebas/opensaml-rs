//! XML-DSig signing + detached message signatures (samlify
//! `constructSAMLSignature` / `constructMessageSignature` /
//! `verifyMessageSignature`), delegating crypto to `bergshamra`
//! (feature `crypto-bergshamra`).

use super::keys::{build_key_info, load_certificate};
use crate::binding::{base64_decode, base64_encode};
use crate::constants::{digest_for_signature, namespace};
use crate::error::OpenSamlError;
use crate::xml::dom::{self, Node};
use bergshamra::keys::Key;
use bergshamra::{sign, DsigContext, KeysManager};

const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

fn crypto_err(err: impl std::fmt::Display) -> OpenSamlError {
    OpenSamlError::Crypto(err.to_string())
}

fn find_assertion(root: &Node) -> Option<&Node> {
    if root.local_name == "Assertion" {
        return Some(root);
    }
    root.children.iter().find(|c| c.local_name == "Assertion")
}

/// Construct and embed an enveloped XML-DSig signature (samlify `constructSAMLSignature`).
///
/// When `sign_message` the whole root is referenced; otherwise the contained
/// `<Assertion>` is referenced. The `<Signature>` is inserted right after the
/// target's `<Issuer>` (samlify's default location), then bergshamra fills the
/// digest and signature value. Returns the signed XML.
pub fn construct_saml_signature(
    xml: &str,
    sign_message: bool,
    key: &Key,
    cert: &str,
    sig_alg: &str,
) -> Result<String, OpenSamlError> {
    let doc = dom::parse(xml)?;
    let target = if sign_message {
        &doc.root
    } else {
        find_assertion(&doc.root)
            .ok_or_else(|| OpenSamlError::MissingMetadata("Assertion to sign".into()))?
    };
    let id = target
        .attr("ID")
        .or_else(|| target.attr("AssertionID"))
        .ok_or_else(|| OpenSamlError::Invalid("signing target has no ID".into()))?;
    let digest = digest_for_signature(sig_alg)
        .ok_or_else(|| OpenSamlError::Crypto(format!("unknown signature algorithm: {sig_alg}")))?;
    let key_info = build_key_info(cert);

    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"{env}\"/><ds:Transform Algorithm=\"{exc}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue>{key_info}</ds:Signature>",
        dsig = namespace::DSIG,
        exc = EXC_C14N,
        env = ENVELOPED,
    );

    let issuer = target
        .children
        .iter()
        .find(|c| c.local_name == "Issuer")
        .ok_or_else(|| OpenSamlError::Invalid("signing target has no Issuer".into()))?;
    let pos = issuer.end;
    let templated = format!("{}{}{}", &xml[..pos], signature, &xml[pos..]);

    let mut manager = KeysManager::new();
    manager.add_key(key.clone());
    let ctx = DsigContext::new(manager).with_insecure(true);
    sign(&ctx, &templated).map_err(crypto_err)
}

/// Sign a detached octet string (redirect/SimpleSign binding) — samlify
/// `constructMessageSignature`. Returns the base64-encoded signature.
pub fn construct_message_signature(
    octet_string: &str,
    key: &Key,
    sig_alg: &str,
) -> Result<String, OpenSamlError> {
    let signing = key
        .to_signing_key()
        .ok_or_else(|| OpenSamlError::MissingKey("no signing key".into()))?;
    let alg = bergshamra::crypto::sign::from_uri(sig_alg).map_err(crypto_err)?;
    let signature = alg
        .sign(&signing, octet_string.as_bytes())
        .map_err(crypto_err)?;
    Ok(base64_encode(&signature))
}

/// Verify a detached octet-string signature against `cert` (samlify
/// `verifyMessageSignature`).
pub fn verify_message_signature(
    octet_string: &str,
    signature_b64: &str,
    cert: &str,
    sig_alg: &str,
) -> Result<bool, OpenSamlError> {
    let key = load_certificate(cert)?;
    let verifying = key
        .to_signing_key()
        .ok_or_else(|| OpenSamlError::MissingKey("no verification key".into()))?;
    let alg = bergshamra::crypto::sign::from_uri(sig_alg).map_err(crypto_err)?;
    let signature = base64_decode(signature_b64)?;
    alg.verify(&verifying, octet_string.as_bytes(), &signature)
        .map_err(crypto_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::signature_algorithm::{RSA_SHA1, RSA_SHA256, RSA_SHA512};
    use crate::crypto::keys::load_private_key;
    use crate::crypto::verify::verify_signature;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");

    const AUTHN_REQUEST: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>";

    #[test]
    fn sign_message_then_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        for alg in [RSA_SHA1, RSA_SHA256, RSA_SHA512] {
            let signed = construct_saml_signature(AUTHN_REQUEST, true, &key, SP_CERT, alg)?;
            assert!(signed.contains("<ds:Signature"));
            assert!(!signed.contains("<ds:SignatureValue></ds:SignatureValue>"));
            let (verified, _) = verify_signature(&signed, &[SP_CERT.to_string()])?;
            assert!(verified, "self-signed AuthnRequest should verify ({alg})");
        }
        Ok(())
    }

    #[test]
    fn sign_assertion_then_verify_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(RESPONSE, false, &key, SP_CERT, RSA_SHA256)?;
        let (verified, content) = verify_signature(&signed, &[SP_CERT.to_string()])?;
        assert!(verified, "signed assertion should verify");
        assert!(content.ok_or("expected assertion")?.contains("Assertion"));
        Ok(())
    }

    #[test]
    fn detached_message_signature_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let octet = "SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fexample";
        let sig = construct_message_signature(octet, &key, RSA_SHA256)?;
        assert!(verify_message_signature(octet, &sig, SP_CERT, RSA_SHA256)?);
        // tampered octet string must fail
        assert!(!verify_message_signature(
            "SAMLRequest=TAMPERED",
            &sig,
            SP_CERT,
            RSA_SHA256
        )?);
        Ok(())
    }
}
