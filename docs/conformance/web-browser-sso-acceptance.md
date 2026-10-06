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
by Approved Errata 05. Schema citations are the OASIS assertion and protocol
schemas.

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
| Several `<AudienceRestriction>` elements are all required, and audiences inside one restriction are alternatives | Accepting service provider | Inbound | Mandatory when the elements are present. Core §2.5.1.4, as clarified by Approved Errata 05 E46. No off switch beyond the audience policy above |
| Reject a `<Conditions>` child that is not understood | Accepting service provider | Inbound | Mandatory. Core §2.5.1.1: an unevaluable or unrecognized condition is Indeterminate, and Indeterminate must be rejected. No off switch |
| `<OneTimeUse>` does not affect validity and the assertion is not retained | Accepting service provider | Inbound | Mandatory when the element is present. Core §2.5.1.5. The condition is always Valid. The typed session is the immediate use of the assertion and is not kept for a later protocol exchange |
| `<ProxyRestriction>` does not affect validity | Accepting service provider | Inbound | Mandatory understanding. Core §2.5.1.6: the condition is always Valid and limits a relying party that issues a later assertion. This service provider does not issue one, so the condition is accepted |
| Evaluate every assertion, which must share one issuer and one principal | Accepting service provider | Inbound | Mandatory. Approved Errata 05 E26, Profiles §§4.1.4.2 and 4.1.4.3. One successful bearer confirmation is enough for that assertion. This receiver treats `NameID` value, `Format`, `NameQualifier`, and `SPNameQualifier` as the principal identifier |
| An unsigned sibling assertion is not a second signed assertion | Accepting service provider | Inbound | Mandatory signature coverage. Errata 05 E26, Profiles §4.1.4.5, together with the existing wrapping rejection. Several assertions are accepted only when the response signature covers the response or every assertion is directly signed |
| UTC `IssueInstant` on the Response and the Assertion | Accepting service provider | Inbound | Mandatory. No off switch. Core §1.3.3 forbids a producer from generating a leap second and does not require the receiver to reject one |
| HTTP POST protects each assertion with a signature on the Assertion or the Response | Accepting service provider | Inbound | Mandatory. Errata 05 E26, Profiles §4.1.4.5 |
| Bearer `Recipient`, `NotOnOrAfter`, and `InResponseTo` | Accepting service provider | Inbound | Mandatory. Errata 05 E26, Profiles §4.1.4.3. An unsolicited response must not carry `InResponseTo` |
| A present `Destination` identifies the actual recipient | Accepting service provider | Inbound | Mandatory. Core §3.2.2. A signed HTTP-Redirect or HTTP-POST message carries `Destination`, and the recipient verifies it |
| Check the bearer `Address` | Accepting service provider | Inbound | Optional. Stays off. Profiles §4.1.4.3 |

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
