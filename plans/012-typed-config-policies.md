# Plan 012: Replace EntitySetting as the primary config with typed policies

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/entity.rs src/constants.rs src/metadata/generate.rs src/sp.rs src/idp.rs src/lib.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md
- **Category**: migration / security / dx
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

`EntitySetting` currently mixes entity identity, security policy, XML parser
limits, algorithms, templates, prefixes, and private credentials in one public
`Debug` struct. That is convenient for porting samlify behavior, but it is a bad
front door for a typed SAML API. This plan introduces typed configs and policy
groups that map into `EntitySetting` internally while redacting secrets and
making common invalid setup harder to express.

## Current state

- `EntitySetting` is a large public struct:

  ```rust
  // src/entity.rs:11-18
  #[non_exhaustive]
  #[derive(Debug, Clone)]
  pub struct EntitySetting {
      pub entity_id: Option<String>,
      pub request_signature_algorithm: String,
      ...
  }
  ```

- The same struct contains private keys and passphrases:

  ```rust
  // src/entity.rs:57-68
  pub private_key: Option<String>,
  pub private_key_pass: Option<String>,
  pub signing_cert: Option<String>,
  pub encrypt_cert: Option<String>,
  pub enc_private_key: Option<String>,
  pub enc_private_key_pass: Option<String>,
  ```

- It also contains SAML validation policy and parser limits:

  ```rust
  // src/entity.rs:42-54
  pub authn_requests_signed: bool,
  pub want_assertions_signed,
  pub validate_audience: bool,
  pub want_message_signed,
  pub want_authn_requests_signed,
  pub want_logout_request_signed: bool,
  pub want_logout_response_signed: bool,

  // src/entity.rs:69-78
  pub clock_drifts: (i64, i64),
  pub redirect_inflate_max_bytes: usize,
  pub xml_limits: XmlLimits,
  ```

- Algorithm choices are raw strings:

  ```rust
  // src/entity.rs:19-24
  pub request_signature_algorithm: String,
  pub data_encryption_algorithm: String,
  pub key_encryption_algorithm: String,
  ```

- `Binding` includes unsupported Artifact for parity:

  ```rust
  // src/constants.rs:10-19
  pub enum Binding {
      Redirect,
      Post,
      SimpleSign,
      Artifact,
  }
  ```

- Metadata generation config derives `Default` even when operational fields are
  required by real SAML flows:

  ```rust
  // src/metadata/generate.rs:30-48
  #[derive(Debug, Clone, Default)]
  pub struct SpMetadataConfig {
      pub entity_id: String,
      ...
      pub assertion_consumer_service: Vec<Endpoint>,
  }
  ```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- `src/api.rs` or `src/saml.rs`
- New config module, for example `src/config.rs`
- New typed algorithm/policy module, for example `src/types.rs`
- `src/lib.rs`
- Focused tests in `tests/typed_config.rs`

**Out of scope**:

- Rewriting `EntitySetting` internals everywhere in one PR.
- Removing `EntitySetting` from `raw`.
- Changing XML crypto backend behavior.
- Adding dependencies such as `derive_builder`, `serde`, `http`, `zeroize`, or
  async traits without a separate proposal.
- Implementing metadata federation trust or public CA validation. SAML metadata
  trust remains explicit/pinned by caller policy.

## Git workflow

- Suggested branch: `advisor/012-typed-config-policies`
- Commit style: `feat(api): add typed SAML configuration policies`
- Do not push or open a PR unless the operator instructed it.

## Target design

Add typed config and policy groups as the primary constructor inputs:

```rust
pub struct SpConfig {
    pub entity_id: EntityId,
    pub metadata: SpMetadataConfig,
    pub credentials: Credentials,
    pub validation: SpValidationPolicy,
    pub algorithms: AlgorithmPolicy,
    pub xml: XmlPolicy,
    pub templates: TemplatePolicy,
}

pub struct IdpConfig {
    pub entity_id: EntityId,
    pub metadata: IdpMetadataConfig,
    pub credentials: Credentials,
    pub validation: IdpValidationPolicy,
    pub algorithms: AlgorithmPolicy,
    pub xml: XmlPolicy,
    pub templates: TemplatePolicy,
}
```

Use simple documented structs and enums. Do not make algorithms generic type
parameters. Keep compile time bounded.

Add redacted credential newtypes:

```rust
pub struct PrivateKeyPem(String);
pub struct CertificatePem(String);
pub struct Passphrase(String);

impl core::fmt::Debug for PrivateKeyPem { /* redact */ }
impl core::fmt::Debug for Passphrase { /* redact */ }
```

Add typed algorithms that map to existing URI constants:

```rust
pub enum SignatureAlgorithm {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    Custom(String),
}

impl SignatureAlgorithm {
    pub fn as_uri(&self) -> &str;
}
```

Include at least:

- `SignatureAlgorithm`
- `DigestAlgorithm` if it is needed by outgoing signatures now or by plan 013
- `DataEncryptionAlgorithm`
- `KeyEncryptionAlgorithm`
- `TransformAlgorithm`
- `NameIdFormat`
- Binding subsets are intentionally handled by plan 018; do not add a second
  browser binding enum in this plan.

Keep `Custom(String)` only for algorithms this crate currently forwards to
`bergshamra`. Document that `Custom` can still fail at runtime if unsupported by
the crypto backend.

## Steps

### Step 1: Add redacted credential types

Create the credential types in the new typed config/types module.

Requirements:

- `Clone` is allowed.
- `Debug` for private keys and passphrases must not print inner values.
- Certificate debug may print a short type marker but should avoid dumping full
  PEM by default.
- Provide `as_str()` methods for internal mapping.
- Provide constructors such as `PrivateKeyPem::new(value: impl Into<String>)`.

Add tests:

```rust
#[test]
fn private_key_debug_is_redacted() {
    let key = PrivateKeyPem::new("dummy-private-key-for-redaction-test");
    let debug = format!("{key:?}");
    assert!(!debug.contains("dummy-private-key-for-redaction-test"));
    assert!(debug.contains("redacted"));
}
```

**Verify**: `cargo nextest run -p saml-rs typed_config` -> tests pass.

### Step 2: Add typed algorithm and format enums

Map the new enums to existing URI constants in `src/constants.rs`.
Do not duplicate literal URIs when a constant exists.

For `Binding`, do not remove `Binding::Artifact` and do not introduce a
temporary `BrowserBinding` here. Plan 018 owns the public binding subset names
(`SsoRequestBinding`, `SsoResponseBinding`, and `LogoutBinding`) so the typed
API does not grow duplicate concepts.

Add tests:

- Algorithm enums return the same URI strings as existing constants.

**Verify**: `cargo nextest run -p saml-rs typed_config` -> tests pass.

### Step 3: Add policy groups and conversion into EntitySetting

Add typed policy structs:

- `SpValidationPolicy`
- `IdpValidationPolicy`
- `LogoutPolicy`
- `XmlPolicy`
- `AlgorithmPolicy`
- `TemplatePolicy`
- `Credentials`

Signature requirements must be named enums rather than booleans in the typed
API. Use variants such as:

```rust
pub enum AssertionSignaturePolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub enum MessageSignaturePolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub enum AuthnRequestSignaturePolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub enum LogoutSignaturePolicy {
    RequireSigned,
    FollowPeerMetadata,
    AllowUnsignedForCompatibility,
}
```

Provide conservative defaults matching current `EntitySetting::default()` unless
the current default is only for legacy compatibility. If you intentionally
change a default, document it in the struct docs and add a test.

Implement internal conversions:

```rust
impl TryFrom<&SpConfig> for EntitySetting { ... }
impl TryFrom<&IdpConfig> for EntitySetting { ... }
```

The conversion should:

- Copy XML limits and redirect inflate limits.
- Copy typed algorithms into URI strings.
- Copy credential material into the old fields.
- Set `allow_insecure_software_rsa_key_transport_decryption` only through a
  clearly named policy method such as
  `XmlEncryptionPolicy::allow_insecure_software_rsa_key_transport_decryption()`.

Do not expose a method named only `insecure(true)` in the typed API. Make the
risk visible at the call site.

**Verify**: `cargo clippy -p saml-rs --all-targets -- -D warnings` -> exit 0.

### Step 4: Add typed local and peer config shells

Add public shells for:

- `SpConfig`
- `IdpConfig`
- `SpDescriptor`
- `IdpDescriptor`
- no public generic `Peer<Role>` wrapper; descriptor naming is the source of
  truth for peer metadata

These may wrap existing metadata types for now:

```rust
pub struct IdpDescriptor {
    entity_id: EntityId,
    metadata_xml: String,
    // private parsed IdP metadata plus trust state
}

pub struct SpDescriptor {
    entity_id: EntityId,
    metadata_xml: String,
    // private parsed SP metadata plus trust state
}
```

Add constructors that make metadata trust and expected entity IDs visible:

- `IdpDescriptor::from_metadata_xml_for(expected_entity_id: EntityId, xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError>`
- `SpDescriptor::from_metadata_xml_for(expected_entity_id: EntityId, xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError>`

`from_metadata_xml(xml, trust)` may exist only as a convenience when the caller
accepts the metadata entity ID. Prefer the `_for` constructor in docs and tests.

For this plan, metadata trust should be explicit but not overbuilt. If plan 021
has not landed, implement only the compatibility policy and leave signed
metadata verification to plan 021:

```rust
pub enum MetadataTrustPolicy<'a> {
    UnsignedForCompatibility,
    RequireSignature {
        trusted_certificates: &'a [CertificatePem],
    },
}
```

Implement `UnsignedForCompatibility` now. For
`RequireSignature`, either implement using the verified
metadata boundary from plan 021 or return `Unsupported` with docs that plan 021
must implement it. Do not pretend this validates against a public CA store;
SAML metadata trust is usually pinned or federation-driven, not web PKI by
default.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 5: Add conversion parity tests

Add tests in `tests/typed_config.rs` that build typed SP and IdP
configs and compare selected converted settings to `EntitySetting`.

Cover:

- Entity ID.
- Signing key and cert fields exist after conversion but debug is redacted.
- `AssertionSignaturePolicy`, `MessageSignaturePolicy`, and
  `AuthnRequestSignaturePolicy` conversion into existing raw settings.
- Clock drift and XML limits.
- Algorithms map to existing URI strings.
- Insecure RSA key transport opt-in is false by default and true only through
  the explicit risk-named policy.

**Verify**: `cargo nextest run -p saml-rs typed_config` -> tests pass.

## Test plan

- `typed_config` integration tests cover redaction, enum URI mapping, and
  conversion into `EntitySetting`. Binding subset tests belong to plan 018.
- Doctests show a minimal typed config but use placeholder strings only, not
  fixture key contents.
- Existing flow tests continue to pass because old internals still receive
  equivalent settings.

## Done criteria

- [x] Public typed config and policy structs exist and are documented.
- [x] This plan does not add a duplicate public binding subset; plan 018 owns
      those types.
- [x] Secret-bearing types redact `Debug`.
- [x] Typed configs convert into `EntitySetting` without changing existing flow
  behavior.
- [x] No new dependencies are added.
- [x] `cargo fmt --all --check` exits 0.
- [x] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [x] `cargo nextest run -p saml-rs` exits 0.
- [x] `cargo test -p saml-rs --doc` exits 0.
- [x] `cargo check -p saml-rs --no-default-features` exits 0.
- [x] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- A typed config requires a new dependency to be ergonomic.
- Secret values appear in a `Debug` output test.
- Mapping typed configs into old internals changes existing conformance test
  output.
- You need to touch crypto internals to implement config shape.
- Metadata trust cannot be represented honestly without implementing signed
  metadata verification.

## Maintenance notes

- Reviewers should scrutinize names on risky toggles. Avoid call sites like
  `insecure(true)`; prefer names that state the risk.
- Keep public config types stable and small. It is easier to add fields before
  1.0 than to repair a confusing first impression on docs.rs.
- Do not make algorithm choices generic unless a real performance or safety
  need appears. Runtime enums are the right compile-time tradeoff here.
