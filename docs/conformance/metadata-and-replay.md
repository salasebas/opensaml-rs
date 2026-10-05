# Metadata trust and replay

This record classifies metadata trust and replay for the typed browser flows.
It does not publish `recommended()`. `Default`, `new`, `try_new`, the config
builders, and `strict()` stay on their current presets. Raw settings stay on
their historical defaults.

Metadata trust is `MetadataTrustPolicy`, passed to
`IdpDescriptor::from_metadata_xml_for` and
`SpDescriptor::from_metadata_xml_for`. Replay is `ReplayPolicy`, passed to
`SamlValidationContext::new`. Neither value is a field of
`SpValidationPolicy` or `IdpValidationPolicy`. The Web Browser SSO and Single
Logout field combinations do not select signed metadata, invent trust anchors,
or store replay.

Normative text is SAML Metadata 2.0 and Profiles 2.0, as corrected by Approved
Errata 05, plus Core 2.0 where a condition is named. Schema citations are the
OASIS metadata schema.

## Metadata trust

Typed import accepts a document the caller already holds. It does not publish
metadata, resolve a well-known location, query DNS, refresh a cache, or follow
TLS server authentication. Metadata §4 describes those mechanisms and says
other out-of-band mechanisms are permitted. Rules that obligate only that
resolution path stay outside this import.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| `ds:Signature` on `EntityDescriptor` or `EntitiesDescriptor` | Metadata publisher | Generate metadata | Optional. The schema marks the element optional. Metadata §3 says a signature is not always required when the relying party obtains the document directly over an authenticated secure channel |
| Sign at least the root element when that channel is absent | Metadata publisher | Generate metadata | Recommendation. Metadata §3. §4.3.3.2 also says published metadata documents should be signed. This import does not reject unsigned metadata because of that publisher recommendation. `UnsignedForCompatibility` remains the samlify-port import |
| Employ some document-integrity mechanism, and validate a signature that is present, when metadata is resolved through §4 | Metadata publisher and metadata consumer | Resolve metadata | Mandatory for that resolution path. Metadata §4.3.3 and §4.3.3.2. Typed import does not resolve metadata, so the field combination does not apply this duty and does not turn it into a rejection of every unsigned document |
| A relying party has some means to establish trust before using metadata | Metadata consumer | Inbound | Recommendation for resolved metadata. Metadata §4. The means here is the caller-supplied `MetadataTrustPolicy`. The field combination does not choose it |
| `KeyInfo` on a metadata signature may be absent, and a certificate in `KeyDescriptor` is not a trust anchor | Metadata consumer | Inbound | Optional material, with no implied trust. Metadata §3.1.5 lets `KeyInfo` be absent. Errata 05 E69 takes no position on `KeyDescriptor`'s `ds:KeyInfo` and says no trust implication follows from including a certificate. `RequireSignature` verifies only the caller-pinned certificates. An empty pin list does not fall back to `KeyInfo`. The field combination does not accept signed metadata without those pins |
| When `RequireSignature` is selected, the signature covers the `EntityDescriptor` and does not exclude its content | Metadata consumer | Inbound | Mandatory once that caller option is selected. Metadata §3.1.2 requires the signature to cover the signed element. §3.1.4 says a verifier that accepts other transforms must still ensure signed content is not excluded. The import rejects a signature that does not cover the consumed descriptor |
| `validUntil` and `cacheDuration` limit how long a consumer caches metadata | Metadata consumer | Cache resolved metadata | Mandatory for a consumer that caches. Metadata §2.3.1, §2.3.2, and §4.3.1, as clarified by Errata 05 E76 and E94. Typed import does not cache or refresh metadata, so these attributes are not a preset field |

## Replay

`ReplayPolicy::DisabledForCompatibility` skips storage. It is the samlify-port
hatch. It is not a named relaxation of a recommendation.
`ReplayPolicy::RequireCache` stores only in the cache the caller passes.
`SamlValidationContext` has no hidden cache.

| Rule | Actor | Direction | Level |
| --- | --- | --- | --- |
| Bearer assertions delivered by HTTP POST are not replayed | Accepting service provider | Inbound `finish_sso` and `accept_unsolicited_sso` | Mandatory for HTTP POST. Profiles §4.1.4.5. Approved Errata 05 E26 replaces only the signing sentence at lines 600–601 and leaves this paragraph in place. The check stays on `ReplayPolicy`. The accept combination does not enable it. `DisabledForCompatibility` is the samlify-port hatch for this mandatory rule |
| The kept HTTP POST identifier is the bearer assertion `ID`, for the `SubjectConfirmationData@NotOnOrAfter` window | Accepting service provider | Inbound | Mandatory for the HTTP POST rule above. Profiles §4.1.4.5 names that identifier and that window |
| Also store the Response `ID` | Accepting service provider | Inbound | Library policy. It is stored only when the caller supplies a cache |
| Expire the caller cache at the earliest of `Conditions`, bearer `SubjectConfirmationData`, and every `AuthnStatement` | Accepting service provider | Inbound | Library policy. This can be earlier than `SubjectConfirmationData@NotOnOrAfter`. Existing behavior is preserved and is not a preset field |
| The same caller cache on HTTP-Redirect or HTTP-POST-SimpleSign responses | Accepting service provider | Inbound | Library policy. Profiles §4.1.4.5 states the replay duty for HTTP POST. Security considerations §7.1.1.4 defers replay countermeasures to the binding and does not add a second receiver requirement. Storage on the other response bindings happens only when the caller supplies a cache |
| `AuthnRequest` `ID` | Identity provider | Inbound `receive_sso` | Library policy. Web Browser SSO does not require the identity provider to remember request identifiers. Storage happens only when the caller supplies a cache, and a request without `NotOnOrAfter` also needs `SamlValidationContext::with_replay_retention` |
| `LogoutRequest` `ID` and `LogoutResponse` `ID` | Logout recipient | Inbound `receive_slo` and `finish_slo` | Library policy. Single Logout does not require an identifier cache. Storage happens only when the caller supplies a cache. A `LogoutRequest` uses `NotOnOrAfter` as its deadline when that attribute is present; otherwise it uses `with_replay_retention`. Rejecting an expired `LogoutRequest@NotOnOrAfter` remains the separate library policy already recorded for logout |
| Do not retain an assertion that carries `<OneTimeUse>` | Relying party that would retain the assertion | Inbound | Mandatory when the element is present. Core §2.5.1.5 `MUST NOT` be retained for future use. For validity, the condition is always Valid. Typed SSO does not retain the assertion for later protocol use, so this is not a preset field and it is not part of the caller replay cache |
| Use a `<OneTimeUse>` assertion immediately | Relying party | Inbound | Recommendation. Core §2.5.1.5. It does not become a rejection of an assertion that arrives later |
