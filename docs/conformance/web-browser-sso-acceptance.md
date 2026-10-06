# Web Browser SSO acceptance rules

This record classifies inbound rules for typed Web Browser SSO:
service-provider `finish_sso` and `accept_unsolicited_sso`, and identity-provider
`receive_sso`. `SpValidationPolicy::recommended` includes the service-provider
rows below. It also includes the Single Logout accept combination and leaves
AuthnRequest signing and identifier creation off. Those last three are not
part of this accept combination; they are recorded with logout and generation.
`IdpValidationPolicy::recommended` includes the identity-provider rows below
and the same logout accept combination. Recommended is the preset for these
claimed features. It is not an implementation of SAML V2.0 as a whole.
Compatibility is the legacy permissive preset. `Default`, `new`, and `try_new`
stay on Compatibility. Config builders stay on the deprecated `strict()`
bundle. That bundle is unchanged and does not select the RSA-SHA2 XML-DSig
profile.

Normative text is SAML Core 2.0, Profiles 2.0, and Bindings 2.0, as corrected
by Approved Errata 05. HTTP-POST-SimpleSign is the supported CD04 binding.
Schema citations are the OASIS assertion and protocol schemas.

Outbound AuthnRequest signing, identifier creation, and logout are not part of
the service-provider accept combination. Single Logout acceptance is classified
in [single-logout.md](single-logout.md). Replay and metadata trust stay caller
arguments, classified in [metadata-and-replay.md](metadata-and-replay.md).

## Service provider

`finish_sso` and `accept_unsolicited_sso` read `SpValidationPolicy`. Callers
select the accept combination by setting the fields below.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Do not require a signature directly on the Assertion | Accepting service provider | Inbound | Library hardening, off. `AssertionSignaturePolicy::AllowUnsignedForCompatibility`. `RequireSigned` is the hardening |
| Require a Response signature when an `EncryptedAssertion` uses CBC | Accepting service provider | Inbound | Recommendation, on. `ResponseSignaturePolicy::RequireForEncryptedCbc`. Relax it with `AllowUnsignedEncryptedCbc`. `RequireSigned` on every response is separate library hardening |
| Do not require the RSA-SHA2 XML signature profile | Accepting service provider | Inbound | Library hardening, off. `XmlSignatureProfile::AllowProviderSupportedForCompatibility`. Conformance §4.1 requires RSAwithSHA1, and Core §5.4.4 does not require a verifier to reject other transforms |
| Evaluate an `<AudienceRestriction>` that is present | Accepting service provider | Inbound | Mandatory when the element is present. `AudienceValidationPolicy::EvaluatePresentRestrictions`. `Validate` also rejects a missing restriction; that extra rejection is library hardening and stays off. `strict()` keeps `Validate` |
| UTC `IssueInstant` on the Response and the Assertion | Accepting service provider | Inbound | Mandatory. No off switch. Core §1.3.3 forbids a producer from generating a leap second and does not require the receiver to reject one |
| HTTP POST protects each assertion with a signature on the Assertion or the Response | Accepting service provider | Inbound | Mandatory. Errata 05 E26, Profiles §4.1.4.5 |
| Bearer `Recipient`, `NotOnOrAfter`, and `InResponseTo` | Accepting service provider | Inbound | Mandatory. Errata 05 E26, Profiles §4.1.4.3. An unsolicited response must not carry `InResponseTo` |
| A present `Destination` identifies the actual recipient | Accepting service provider | Inbound | Mandatory. Core §3.2.2. A signed HTTP-Redirect or HTTP-POST message carries `Destination`, and the recipient verifies it |
| Check the bearer `Address` | Accepting service provider | Inbound | Optional. Stays off. Profiles §4.1.4.3 |
| `RelayState` does not exceed 80 bytes | Accepting service provider | Inbound `finish_sso` and `accept_unsolicited_sso` | Mandatory prohibition. Bindings §3.5.3 and HTTP-POST-SimpleSign CD-04 §2.3 |
| HTTP-POST-SimpleSign verifies the raw XML octets, then `RelayState` when present, then `SigAlg` | Accepting service provider | Inbound | Mandatory when that binding is used. CD-04 §2.6. An absent `RelayState` is omitted |

## Identity provider

`receive_sso` reads `IdpValidationPolicy.authn_requests`. The accept combination
is `AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent`.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Require a signed `AuthnRequest` | Identity provider | Inbound | Optional. Stays off unless `RequireSigned` |
| Verify a signature that is present | Identity provider | Inbound | Mandatory. Core §3.2.1. `AllowUnsignedForCompatibility` is the samlify-port hatch and does not verify it |
| UTC `IssueInstant` | Identity provider | Inbound | Mandatory. No off switch. An inbound leap-second value stays accepted |
| A present `Destination` identifies this identity provider's SSO endpoint | Identity provider | Inbound | Mandatory. Core §3.2.1 |
| `AssertionConsumerServiceURL` or `AssertionConsumerServiceIndex` belongs to the service provider | Identity provider | Inbound | Mandatory. Profiles §4.1.4.1. The check runs when the response is issued |
| `RelayState` does not exceed 80 bytes | Identity provider | Inbound `receive_sso` | Mandatory prohibition. Bindings §3.4.3, §3.5.3, and HTTP-POST-SimpleSign CD-04 §2.3 |
| HTTP-Redirect verifies `SAMLRequest`, `RelayState` when present, then `SigAlg`, using the original URL-encoded values | Identity provider | Inbound AuthnRequest | Mandatory when the request is signed with that binding. Bindings §3.4.4.1. The message is raw-inflated after base64 decoding |
| HTTP-POST-SimpleSign verifies the raw XML octets, then `RelayState` when present, then `SigAlg` | Identity provider | Inbound AuthnRequest | Mandatory when that binding is used. CD-04 §2.6 |
