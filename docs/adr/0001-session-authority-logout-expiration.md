# Derive session-authority logout expiration from the IdP issuance policy

The typed `Saml<Idp>::start_slo` flow models a SAML Session Authority and must
therefore emit `LogoutRequest@NotOnOrAfter`. The deadline is derived from the
same configurable IdP issuance lifetime used for generated assertion time
bounds, with the existing five-minute lifetime retained as the saml-rs default;
this keeps a later logout deadline no earlier than assertion bounds generated
from the same immutable policy by that `Saml<Idp>` facade. The OASIS `SHOULD`
concerns the actual latest applicable assertion, so this policy does not claim
ordering against arbitrary historical, custom, or proxied assertions. The
attribute cannot be disabled in the typed
session-authority flow, while typed SP and raw compatibility generation retain
their existing role-appropriate behavior. The five-minute value is library
policy, not an OASIS requirement.

Normative provenance: SAML Core 2.0 section 3.7.3.2 requires a Session
Authority constructing a LogoutRequest to set `NotOnOrAfter`. Core section
3.7.1 describes that attribute as optional on the generic LogoutRequest, and
the official `saml-schema-protocol-2.0.xsd` likewise declares it with
`use="optional"`. Approved Errata 05 E38 was checked as part of this decision;
it clarifies `SessionIndex` semantics and does not alter either
`NotOnOrAfter` rule.
