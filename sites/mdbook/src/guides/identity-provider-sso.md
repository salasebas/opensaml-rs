# Identity provider

Issue a browser SSO response. You already have a service-provider peer, an SSO URL, and a signing credential.

## Calls

1. Build `IdpConfig` and call `Saml::idp`.
2. Import the service provider metadata.
3. Call `receive_sso` with the browser fields from the `AuthnRequest`.
4. Call `respond_sso` with the subject you authenticated.

```rust
let idp = Saml::idp(
    IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
        .credentials(credentials)
        .validation(IdpValidationPolicy::recommended())
        .build()?,
)?;

let sp = SpDescriptor::from_metadata_xml_for(
    EntityId::try_new("https://sp.example.com/metadata")?,
    sp_metadata_xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &[metadata_signing_cert],
    },
)?;

let request = idp.receive_sso(
    &sp,
    BrowserInput::<AuthnRequest>::post(request_fields),
    validation,
)?;

let response = idp.respond_sso(
    &sp,
    &request,
    Subject::new(NameId::new("alice@example.com", None), Vec::new()),
    RespondSso::post().apply_web_browser_sso_generation_rules(),
)?;
```

Send `response` back through the browser to the service provider's assertion consumer service.

`post()`, `redirect()`, and `simple_sign()` leave the generation rules off until you call `apply_web_browser_sso_generation_rules()`. Those rules are the producer rows in [SSO generation](../reference/conformance/web-browser-sso-generation.md).

## Encrypted assertions

A typed identity provider signs the Response when it generates an `EncryptedAssertion` with a known CBC-mode algorithm. That follows Approved Errata 05 E93. To keep an unsigned CBC response for a legacy peer:

```rust
let response = idp.respond_sso(
    &sp,
    &request,
    subject,
    RespondSso::post().allow_unsigned_encrypted_cbc(),
)?;
```

`allow_unsigned_encrypted_cbc()` relaxes that recommendation only. It is not the Compatibility preset. A service provider that already requires the signature still rejects the relaxed response.

Assertion encryption stays off until you select `XmlEncryptionPolicy::encrypt_assertions`. On RustCrypto, software RSA key-transport decryption stays off until the caller opts in. See [Security](../reference/security.md).

## Next

The paired flow is [Service provider](service-provider-sso.md). A round trip that includes logout is [`examples/slo.rs`](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs).
