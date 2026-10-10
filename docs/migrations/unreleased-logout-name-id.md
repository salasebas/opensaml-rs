# Logout NameID format and qualifiers

This change is unreleased. It applies to the release that first sends the
logout subject's full `NameID`.

Typed `start_slo` now copies `Format`, `NameQualifier`, `SPNameQualifier`, and
`SPProvidedID` from the `LogoutSubject` `NameId` into the `LogoutRequest`.
`SsoSession` now reads the same qualifiers from the assertion `NameID`, so
`SsoSession::logout_subject` carries them into logout.

## Add qualifier placeholders to a custom logout request template

Who must change: code that sets `TemplatePolicy::logout_request_template` and
starts typed Single Logout for a subject whose `NameId` has a qualifier. That
includes a subject taken from an `SsoSession` whose assertion `NameID` had one.
Session Authority generation, and session participant generation with producer
rules, now fail with `SamlError::ProtocolProfile` when the rendered `NameID`
drops or changes a qualifier.

Add the placeholders to the template's `NameID`. An attribute whose complete
value is a placeholder is omitted when the `NameId` has no value for it.

```xml
<saml:NameID NameQualifier="{NameQualifier}" SPNameQualifier="{SPNameQualifier}"
    Format="{NameIDFormat}" SPProvidedID="{SPProvidedID}">{NameID}</saml:NameID>
```

## Expect qualifiers on the SSO session NameID

Who must change: code that compares `SsoSession::name_id()` or
`SsoSession::subject()` with a `NameId` built by `NameId::new`. When the
assertion `NameID` has qualifiers, the session `NameId` now holds them and is
no longer equal to a `NameId` without them. Compare `NameId::value()` and
`NameId::format()` when only those matter.

A `LogoutSubject` `NameId` with no `Format` still uses the first configured
local NameID format.
