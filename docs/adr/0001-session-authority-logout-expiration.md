# Derive session-authority logout expiration from the IdP issuance policy

The typed `Saml<Idp>::start_slo` flow models a SAML Session Authority and must
therefore emit `LogoutRequest@NotOnOrAfter`. The deadline is derived from the
same configurable IdP issuance lifetime used for generated assertion time
bounds, with the existing five-minute lifetime retained as the saml-rs default;
this makes a later logout deadline no earlier than the latest assertion bounds
produced by the same IdP. The attribute cannot be disabled in the typed
session-authority flow, while typed SP and raw compatibility generation retain
their existing role-appropriate behavior. The five-minute value is library
policy, not an OASIS requirement.
