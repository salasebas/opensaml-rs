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
| Allow five minutes of clock skew on `NotBefore` and `NotOnOrAfter` | Relying party | Inbound | Recommendation. Approved Errata 05 E92 adds Core §1.3.3 guidance to `Conditions` and to `SubjectConfirmationData`. A new `SamlValidationContext` uses five minutes, the top of the three-to-five-minute range. `NotBefore` is accepted that early. `NotOnOrAfter` stays exclusive after that allowance. The same `NotOnOrAfter` drift also widens `AuthnStatement@SessionNotOnOrAfter`. That session check is existing library policy, not an E92 insertion for the attribute. `ClockSkew::strict` is zero. An explicit skew replaces the five minutes. This is not a validation-preset field |
| Apply a caller-supplied outstanding logout to a later assertion for the same principal and session | Accepting service provider | Inbound `finish_sso_with_outstanding_logout` and `accept_unsolicited_sso_with_outstanding_logout` | Mandatory when the caller supplies the logout. Core §3.7.3.1. Typed NameID values must be equal, and a `Format` on the logout must match (Core §3.3.4). An omitted `Format` compares values only; a typed `LogoutRequest` NameID does not carry `Format`. `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` are not compared. No `SessionIndex` applies to every session of that principal. The context `NotOnOrAfter` skew applies. At or after that deadline the logout does not reject. `finish_sso` and `accept_unsolicited_sso` omit the check. No session store |
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
| Expose `ForceAuthn` when present; leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional. Core §3.4.1. Omission stays absent. Presence does not reject the request |
| Expose `IsPassive` when present; leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional. Core §3.4.1. Omission stays absent. Presence does not reject the request |
| `ForceAuthn` and `IsPassive` are unqualified booleans | Identity provider | Inbound `receive_sso` | Mandatory. Schema `AuthnRequestType`. Values are `true`, `false`, `1`, and `0`. A qualified attribute is rejected |
| Expose a requested `Subject` when present; leave it absent when omitted | Identity provider | Inbound `receive_sso` | Optional. Core §3.4.1 and §3.4.1.4 / E75. A valid subject does not reject the request |
| No identifier in that `Subject` means the presenter is the requested subject | Identity provider | Inbound `receive_sso` | Core §3.4.1. `<BaseID>` and `<EncryptedID>` stay distinct and are not decoded |
| Requested `<NameID>` keeps its content and qualifier attributes | Identity provider | Inbound `receive_sso` | Core §3.3.4. A qualified `NameQualifier`, `SPNameQualifier`, or `SPProvidedID` is rejected |
| One `Subject` and one identifier element | Identity provider | Inbound `receive_sso` | A second `Subject`, a second identifier, or a foreign namespace is rejected |
