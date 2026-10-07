# From 0.6

Upgrade `saml-rs`, `opensaml`, `samlify`, or `samlet` from the latest
`0.6.x` release.

`strict()` is removed. `Default`, `new`, `try_new`, and the config builders
start on Recommended together. `compatibility()` stays available by name and
keeps its permissive behavior. Raw settings defaults stay unchanged.

## Stop calling `strict()`

This breaks code that calls `SpValidationPolicy::strict`,
`IdpValidationPolicy::strict`, or `LogoutPolicy::strict`.

Who must change: that code.

Start from `recommended()` and add only the named options you want. A direct
Assertion signature and the RSA-SHA2 XML-DSig profile stay independent.
`recommended()` selects neither. The removed `strict()` method did not select
the RSA-SHA2 profile either.

Require a signature directly on the Assertion, and leave the XML-DSig profile
unchanged:

```rust
let require_assertion_signature = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::recommended()
};
```

Require the RSA-SHA2 profile, and leave Assertion signatures optional:

```rust
let require_rsa_sha2 = SpValidationPolicy {
    xml_signatures: XmlSignatureProfile::StrictRsaSha2,
    ..SpValidationPolicy::recommended()
};
```

Set both fields when you want both. `LogoutPolicy::recommended()` replaces
`LogoutPolicy::strict()`. Both require a signature on logout requests and
responses.

The removed service-provider bundle also signed `AuthnRequest`s and rejected
a bearer assertion that omitted `<AudienceRestriction>`. Recommended does
neither. Select those options only when you still want them:

```rust
let sp = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    authn_requests: AuthnRequestSigningPolicy::Sign,
    audience: AudienceValidationPolicy::Validate,
    ..SpValidationPolicy::recommended()
};
```

The removed identity-provider bundle rejected an unsigned `AuthnRequest`.
Recommended accepts an unsigned request and verifies a signature that is
present. Keep the rejection with:

```rust
let idp = IdpValidationPolicy {
    authn_requests: AuthnRequestValidationPolicy::RequireSigned,
    ..IdpValidationPolicy::recommended()
};
```

## Update constructors that changed preset

This breaks code that depended on `Default`, `new`, or `try_new` staying on
Compatibility, and code that depended on a config builder staying on the
removed bundle.

Who must change: that code. A config builder no longer rejects an unsigned
`AuthnRequest`, and it no longer rejects a bearer assertion that omits
`<AudienceRestriction>`. An identity provider that keeps the builder default
can issue an assertion for an unsigned request. A service provider that keeps
the builder default can accept an assertion that names no audience. Set the
options in the previous section when that rejection is still required.

`SpValidationPolicy::default`, `IdpValidationPolicy::default`, and
`LogoutPolicy::default` are Recommended. `SpConfig` and `IdpConfig` `new`,
`try_new`, and `builder` use that preset.

Keep the legacy permissive preset by naming it:

```rust
let sp = SpConfig::builder(entity_id)
    .acs_endpoint(acs)
    .validation(SpValidationPolicy::compatibility())
    .build()?;
```

`try_new` and `builder().build()` validate the selected preset. Recommended
requires a crypto provider feature: logout messages must be signed, and a
CBC-encrypted assertion requires a Response signature. A build without a
crypto provider returns `SamlError::Unsupported` from those constructors
unless you select `compatibility()`, or another policy that does not require
signatures. `new` still does not validate.

Field defaults such as `ResponseSignaturePolicy::default` and
`AuthnRequestValidationPolicy::default` are unchanged. They are not the
Recommended preset.

`SpValidationPolicy::compatibility`, `IdpValidationPolicy::compatibility`, and
`LogoutPolicy::compatibility` stay available by name. Raw settings defaults
stay unchanged.
