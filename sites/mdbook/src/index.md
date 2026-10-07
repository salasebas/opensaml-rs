# saml-rs

Sign a person in with SAML 2.0, or issue that login from your own identity provider. The same crate reads metadata and runs Single Logout.

The package name is `saml-rs`. Rust imports `saml_rs`. Signatures and encryption go through [bergshamra](https://crates.io/crates/bergshamra), so the build does not need `libxml2`, `xmlsec1`, or OpenSSL. Method signatures live on [docs.rs](https://docs.rs/saml-rs).

> [!IMPORTANT]
> The crate is pre-1.0. A minor release can change the API. There has been no external security audit. Pin the peer's metadata signing key, and read [XML signatures](explanation/xml-signature-recommendations.md) before production.

## Start here

| You want to | Open |
| --- | --- |
| See one login succeed | [Run the example](tutorial/run-the-sso-example.md) |
| Accept a login | [Service provider](guides/service-provider-sso.md) |
| Issue a login | [Identity provider](guides/identity-provider-sso.md) |
| End a session | [Single Logout](guides/single-logout.md) |
| Pick RustCrypto, AWS-LC, or FIPS | [Crypto provider](guides/crypto-provider.md) |
| Move an existing integration | [Upgrade](guides/upgrade.md) |
