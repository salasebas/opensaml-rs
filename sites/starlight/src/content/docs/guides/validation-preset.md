---
title: "Validation"
description: "Start new typed code from `recommended()`. Add a direct Assertion signature, or the RSA-SHA2 XML-DSig profile, only when you want that extra check. Each one is its own field."
---

Start new typed code from `recommended()`. Add a direct Assertion signature, or the RSA-SHA2 XML-DSig profile, only when you want that extra check. Each one is its own field.

```rust
let policy = SpValidationPolicy::recommended();

let require_assertion_signature = SpValidationPolicy {
    assertions: AssertionSignaturePolicy::RequireSigned,
    ..SpValidationPolicy::recommended()
};

let require_rsa_sha2 = SpValidationPolicy {
    xml_signatures: XmlSignatureProfile::StrictRsaSha2,
    ..SpValidationPolicy::recommended()
};
```

`IdpValidationPolicy::recommended()` and `LogoutPolicy::recommended()` are the matching presets. `LogoutPolicy::recommended()` requires a signature on logout requests and responses.

## Compatibility

`compatibility()` is the legacy permissive preset: the samlify-port behaviour kept for a move off the raw API. It does not claim standards conformance. Name it explicitly. `Default`, `new`, and `try_new` still return that preset today.

## strict()

`strict()` is deprecated. It keeps its current behaviour and does not gain the RSA-SHA2 profile. The following release removes it and points `Default`, `new`, `try_new`, and the config builders at Recommended together.

Code that depends on `Default` staying permissive, or on a config builder staying on `strict()`, has to change in that release. The work is in [0.5 to 0.6](upgrade/v0-5-to-v0-6.md).

Why the presets are separate is in [Validation presets](../explanation/validation-presets.md). The rows each preset publishes are the [conformance records](../reference/conformance.md).
