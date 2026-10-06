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
| Expose `ForceAuthn` when the attribute is present, and leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional attribute. Core §3.4.1. Omission is not stored as false; the processing default of false belongs to the identity provider application. `true` requires that application to authenticate the presenter directly. When this and `IsPassive` are both true, it must not freshly authenticate the presenter unless the `IsPassive` constraints can be met. Presence does not reject the request |
| Expose `IsPassive` when the attribute is present, and leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional attribute. Core §3.4.1. `true` means that application and the user agent must not visibly take control of the user interface. Omission stays absent; the processing default is false. Presence does not reject the request |
| `ForceAuthn` and `IsPassive` are XML Schema booleans and unqualified | Identity provider | Inbound `receive_sso` | Mandatory datatype and attribute form. Protocol schema `AuthnRequestType`. The lexical values are `true`, `false`, `1`, and `0`. Any other value, or a qualified attribute, is rejected |
| Expose a requested `Subject` when the element is present, and leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional element. Core §3.4.1 and §3.4.1.4, with Approved Errata 05 E75. No `<BaseID>`, `<NameID>`, or `<EncryptedID>` means the presenter is the requested subject. A `<NameID>` keeps the content and the attributes strong matching compares: `Format`, `NameQualifier`, `SPNameQualifier`, and `SPProvidedID`. A qualified form of those attributes is rejected on this `NameID` and cannot replace the unqualified value. `<BaseID>` and `<EncryptedID>` stay distinct and are not decoded. The application decides whether it can strongly match and, if it cannot, returns an error response. Presence does not reject the request. A `Subject` or identifier in another namespace is rejected. Two identifier elements, or two `Subject` elements, are rejected |
