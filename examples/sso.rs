//! End-to-end signed SSO: SP builds an `AuthnRequest`, the IdP parses it and
//! issues a signed `Response`, and the SP validates it.
//!
//! Run with: `cargo run -p opensaml --example sso`
//! (the `crypto-bergshamra` feature is on by default).

#[cfg(feature = "crypto-bergshamra")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use saml_rs::constants::{signature_algorithm::RSA_SHA256, Binding};
    use saml_rs::entity::{EntitySetting, User};
    use saml_rs::flow::HttpRequest;
    use saml_rs::idp::LoginResponseOptions;
    use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
    use saml_rs::{IdentityProvider, ServiceProvider};

    // A demo RSA keypair (test material; use real keys in production).
    let privkey = include_str!("../tests/fixtures/key/sp_privkey.pem");
    let cert = include_str!("../tests/fixtures/key/sp_signing_cert.cer");
    let signing = || {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(privkey.into());
        setting.signing_cert = Some(cert.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    };

    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![cert.into()],
            want_authn_requests_signed: true,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/sso",
            )],
            ..Default::default()
        },
        signing(),
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            authn_requests_signed: true,
            want_assertions_signed: true,
            signing_certs: vec![cert.into()],
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        signing(),
    )?;

    // 1. SP creates a signed AuthnRequest (HTTP-POST).
    let request = sp.create_login_request(&idp, Binding::Post, None)?;
    println!("SP  -> AuthnRequest id = {}", request.id);

    // 2. IdP receives and validates the request.
    let req = HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]);
    let parsed = idp.parse_login_request(&sp, Binding::Post, &req)?;
    println!(
        "IdP <- request issuer  = {:?}",
        parsed.extract.get_str("issuer")
    );

    // 3. IdP issues a signed Response bound to the request.
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(request.id.as_str()),
            ..Default::default()
        },
    )?;

    // 4. SP validates signature, issuer, audience, time and InResponseTo.
    let resp = HttpRequest::post(vec![("SAMLResponse".into(), response.context)]);
    let result =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &resp, &request.id)?;
    println!(
        "SP  <- authenticated   = {:?}",
        result.extract.get_str("nameID")
    );
    Ok(())
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn main() {
    eprintln!("Enable the `crypto-bergshamra` feature (on by default) to sign and verify.");
}
