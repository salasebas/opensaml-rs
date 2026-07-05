# Plan 020: Add caller-owned SAML validation context, clock, and replay policy

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/validator.rs src/flow.rs src/sp.rs src/idp.rs src/entity.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/012-typed-config-policies.md, plans/017-semantic-error-taxonomy.md, plans/018-type-narrowed-bindings-and-trackers.md
- **Category**: security / api / migration
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The typed browser API should not freeze the current hidden validation clock or
leave replay checks as an exercise hidden behind `FlowResult`. Inbound signed,
timed, and replay-sensitive browser messages should take explicit time and
replay state. This crate should adopt that caller-owned boundary while keeping
its existing framework-neutral design and without adding Redis, database,
async, or serde dependencies.

## Current state

- Time validation uses the process clock directly:

  ```rust
  // src/validator.rs:17-23
  pub fn verify_time(
      not_before: Option<&str>,
      not_on_or_after: Option<&str>,
      drift: (i64, i64),
  ) -> bool {
      let now = OffsetDateTime::now_utc();
      // ...
  }
  ```

- The inbound flow options carry only drift tolerances, not a caller-supplied
  instant:

  ```rust
  // src/flow.rs:97
  pub clock_drifts: (i64, i64),
  ```

- SP response validation passes `EntitySetting.clock_drifts` into flow:

  ```rust
  // src/sp.rs:487
  clock_drifts: self.setting.clock_drifts,
  ```

- The current SP finish path correlates only by `InResponseTo`; it does not
  expose a replay cache hook for assertion IDs, response IDs, or session IDs.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Focused tests | `cargo nextest run -p saml-rs typed_validation_context` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- Typed validation context models used by plans 013-015.
- A caller-supplied `now` path for SAML time-window checks.
- Replay cache trait/policy in the typed API lane.
- Internal flow adapters that keep raw compatibility behavior unchanged by
  default.
- Tests in `tests/typed_validation_context.rs`.

**Out of scope**:

- Adding a storage backend, async trait, serde requirement, or web framework
  integration.
- Changing accepted/rejected SAML behavior beyond making the validation instant
  explicit for typed callers.
- Implementing token/session persistence inside the crate.
- Replacing the semantic error work from plan 017.

## Git workflow

- Suggested branch: `advisor/020-typed-sso-validation-context`
- Commit style: `feat(api): add typed SAML validation context`
- Do not push or open a PR unless the operator instructed it.

## Target design

Add a small caller-owned validation context:

```rust
pub struct SamlValidationContext<'a> {
    pub now: SamlInstant,
    pub clock_skew: ClockSkew,
    pub replay: ReplayPolicy<'a>,
}

pub enum ReplayPolicy<'a> {
    DisabledForCompatibility,
    RequireCache(&'a mut dyn ReplayCache),
}

pub trait ReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SamlInstant)
        -> Result<(), SamlError>;
}

pub enum ReplayKey {
    ResponseId(MessageId),
    AssertionId(AssertionId),
    SessionIndex(SessionIndex),
}
```

Exact names can change to match plans 012-013. The invariants must not change:

- typed SP-initiated `finish_sso` receives an explicit validation context or an
  options value containing it;
- `accept_unsolicited_sso`, `receive_sso`, `receive_slo`, and `finish_slo`
  receive the same context wherever inbound signed, timed, or replay-sensitive
  browser messages are validated;
- `ReplayPolicy::RequireCache` is the recommended typed default;
- compatibility APIs can keep current behavior, but typed docs must make replay
  policy visible;
- replay failures use a semantic `SamlError` variant from plan 017.

## Steps

### Step 1: Make time validation accept an explicit instant internally

Refactor `validator::verify_time` into an internal function that accepts `now`:

```rust
pub(crate) fn verify_time_at(
    not_before: Option<&str>,
    not_on_or_after: Option<&str>,
    drift: (i64, i64),
    now: OffsetDateTime,
) -> bool;
```

Keep the current public/raw helper as a compatibility wrapper around
`OffsetDateTime::now_utc()`.

Add focused tests for:

- expired condition at a fixed instant;
- not-yet-valid condition at a fixed instant;
- invalid timestamp fails closed at a fixed instant.

**Verify**: `cargo nextest run -p saml-rs typed_validation_context` -> tests pass.

### Step 2: Thread the instant through flow options

Add a `now` field to the internal flow options, or add a typed-only flow wrapper
that supplies it. Prefer the smallest change that lets typed SSO avoid hidden
process time.

Rules:

- Raw `flow(...)`, `parse_login_response_with_request_id(...)`, and logout
  compatibility methods should keep today's behavior unless the caller opts into
  the new path.
- Typed SSO must not call a path that hardcodes `OffsetDateTime::now_utc()`.
- Do not widen the time window. Keep the existing inclusive/exclusive
  semantics unless a separate bug fix proves they are wrong.

**Verify**: `cargo nextest run -p saml-rs flow_conformance` -> tests pass.

### Step 3: Add replay models without storage dependencies

Add `ReplayCache`, `ReplayPolicy`, and `ReplayKey` in the typed API/model
module.

Rules:

- The trait is synchronous and minimal.
- The crate must not ship a production storage backend.
- Tests can use a small in-memory cache in the test module.
- If a replay key has no usable expiration, store it until the validated
  session or assertion `NotOnOrAfter` when available; otherwise return a
  semantic error rather than storing forever.

**Verify**: `cargo nextest run -p saml-rs typed_validation_context` -> tests pass.

### Step 4: Extract replay keys from validated SSO responses

When converting the raw `FlowResult` into the typed `SsoSession`, extract
candidate replay keys from structured fields already available in the flow
result or the signed XML:

- Response `ID`;
- Assertion `ID`;
- SessionIndex when present.

Do not add ad hoc string slicing. Use the existing XML extractor/DOM helpers.

**Verify**: `cargo nextest run -p saml-rs typed_validation_context` -> tests pass.

### Step 5: Enforce replay policy in typed inbound flows

Wire the validation context into plan 014's typed `finish_sso`,
`accept_unsolicited_sso`, and `receive_sso` paths, and plan 015's
`receive_slo` and `finish_slo` paths.

Rules:

- `ReplayPolicy::RequireCache` calls `check_and_store` only after signature,
  issuer, destination/recipient, `InResponseTo`, audience, and time validation
  pass.
- A duplicate key fails with a semantic replay error.
- `ReplayPolicy::DisabledForCompatibility` remains explicit in the call site or
  options builder; do not make it an invisible default in docs.

**Verify**:
`cargo nextest run -p saml-rs typed_sso` and
`cargo nextest run -p saml-rs typed_slo` -> tests pass.

## Test plan

- `tests/typed_validation_context.rs` covers fixed-clock success/failure,
  replay success, duplicate replay failure, compatibility-disabled replay, and
  use from SSO/SLO inbound typed flows.
- Existing flow and hardening tests still pass.
- Add at least one doc test showing a caller-provided validation context without
  requiring a storage dependency.

## Done criteria

- [ ] Typed inbound browser validation can run at a caller-supplied instant.
- [ ] Typed inbound browser flows expose replay policy in the method/options
      surface.
- [ ] Replay duplicate failure has a semantic `SamlError` variant.
- [ ] No storage, async, serde, or HTTP dependency was added.
- [ ] Raw compatibility methods preserve current time behavior.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Threading an explicit instant requires weakening any existing validation.
- Replay enforcement would require adding a production storage dependency.
- Existing extractor fields cannot reliably expose response/assertion IDs; add
  a smaller extractor-focused plan instead of string slicing.
- The typed API shape in plans 013-014 has changed enough that this plan's
  validation context no longer has a clear insertion point.

## Maintenance notes

This plan should land before plans 014 and 015 if possible. Without it, the
typed facades would look clean but still hide two security-critical application
responsibilities: clock choice and replay prevention.
