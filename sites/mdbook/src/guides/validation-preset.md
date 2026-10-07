# Validation

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

`compatibility()` is the legacy permissive preset: the samlify-port behaviour kept for a move off the raw API. It does not claim standards conformance. Name it explicitly. `Default`, `new`, `try_new`, and the config builders start on Recommended.

Callers upgrading from 0.6, including code that called `strict()`, follow [From 0.6](upgrade/unreleased.md).

Why the presets are separate is in [Validation presets](../explanation/validation-presets.md). The rows each preset publishes are the [conformance records](../reference/conformance.md).
