# Plan 019: Stabilize typed API architecture docs

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- docs/architecture plans`
>
> If any in-scope file changed since this plan was written, compare the
> architecture excerpts against the live docs before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Status**: DONE
- **Priority**: P2
- **Effort**: S/M
- **Risk**: LOW
- **Depends on**: plans/011-typed-saml-api-contract.md
- **Category**: docs / direction / security
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The repo has execution plans, but maintainers also need durable architecture
notes that explain the typed API direction. On this branch,
`docs/architecture` is that canonical architecture and naming draft. Plan 019
should stabilize and refine those files in place, not create a separate
architecture tree. A maintainer can move the material later if they choose a
different documentation convention.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Search architecture claims | `rg "Artifact resolution|SOAP/back-channel|ECP/PAOS|NameID management|metadata federation|bergshamra|FlowResult|Saml" docs/architecture plans` | relevant claims visible |
| Stale architecture paths | `rg "architecture tree|separate architecture" docs/architecture plans` | only plan 019 context |
| Format check | `cargo fmt --all --check` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Lint docs links indirectly | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |

## Scope

**In scope**:

- `docs/architecture/*.md`
- `plans/019-architecture-rfcs-validation-docs.md`
- `plans/README.md` if the title or dependencies need alignment

**Out of scope**:

- Implementing any code.
- Moving architecture docs to another directory.
- Creating a separate architecture or decision-record tree unless a maintainer
  explicitly chooses that later.
- Changing support claims to say Artifact resolution, SOAP/back-channel,
  ECP/PAOS, SAML queries, NameID management, or metadata federation are
  supported by the high-level typed API.
- Copying reference-crate text. Write docs for this repo's design.

## Target design

Refine the existing architecture set:

1. `README.md`
   - State that `docs/architecture` is the canonical branch architecture and
     naming draft.
   - Link the seven architecture documents.
   - List unsupported high-level profiles.

2. `001-naming.md`
   - Make `Saml<Sp>` / `Saml<Idp>` active local roles.
   - Make `IdpDescriptor` / `SpDescriptor` the source of truth for peer
     metadata names.
   - State that descriptor naming supersedes earlier peer wording.

3. `002-public-api-map.md`
   - Keep root discoverability complete for examples, including SSO/SLO option
     types, form helpers, status, validation context, raw compatibility, and
     pending snapshots.

4. `003-web-sso-api.md`
   - Document SP/IdP SSO shape, pending persistence, RelayState tri-state,
     expected peer/binding checks, SimpleSign raw form-body input, and
     validation context usage.

5. `004-single-logout-api.md`
   - Document SLO start/receive/respond/finish methods, `LogoutSubject`,
     `LogoutSigning`, pending persistence, RelayState tri-state, expected
     peer/binding checks, and validation context usage.

6. `005-config-and-metadata.md`
   - Replace signature booleans with policy enums.
   - Prefer `from_metadata_xml_for(expected_entity_id, xml, trust)`.
   - Avoid public generic verified metadata names that confuse role and trust.

7. `006-errors-and-validation.md`
   - Document semantic validation errors, validation order, caller-owned
     `SamlValidationContext`, exact RelayState mismatch semantics, and metadata
     signature coverage expectations.

8. `007-raw-compatibility.md`
   - Clarify `raw::ServiceProvider` and `raw::IdentityProvider` as the
     recommended raw imports.
   - Mark root role exports as migration-only compatibility before
     stabilization.

## Steps

### Step 1: Confirm architecture scope

Update `docs/architecture/README.md` to say these files are the canonical
architecture and naming draft for the typed API on this branch. Explicitly say
plan 019 refines them in place.

**Verify**:
`rg "canonical architecture|refine.*in place|Artifact resolution|ECP/PAOS" docs/architecture` -> expected claims are visible.

### Step 2: Stabilize naming

Update `001-naming.md` and dependent plans so `IdpDescriptor` and
`SpDescriptor` are the only typed peer metadata names. Note that descriptor
naming supersedes earlier peer wording.

**Verify**:
`rg "IdpDescriptor|SpDescriptor" docs/architecture plans` -> descriptor names are visible in architecture and plan examples.

### Step 3: Complete the public API map

Ensure `002-public-api-map.md` includes root-discoverable types used by the
planned examples:

- `StartSso`, `RespondSso`, `StartSlo`, `RespondSlo`
- `LogoutSubject`, `LogoutSigning`, `SamlStatus`
- `FormField`, `PostForm`
- `PendingSnapshot`
- `SamlValidationContext`

**Verify**:
`rg "StartSlo|RespondSlo|PendingSnapshot|SamlValidationContext|FormField|PostForm" docs/architecture/002-public-api-map.md` -> all names are present.

### Step 4: Document correlation and persistence rules

In Web SSO and SLO docs, specify:

- `Pending<Message>` has private fields.
- Web applications persist a snapshot without requiring `serde`.
- `from_snapshot` validates before reconstructing typed pending state.
- Snapshots store no keys or raw metadata.
- Finish methods check pending peer entity ID and expected binding.
- RelayState matching is exact tri-state: absent, present empty, present value.

**Verify**:
`rg "PendingSnapshot|from_snapshot|peer entity ID|present empty" docs/architecture` -> claims are visible.

### Step 5: Document validation context and SimpleSign boundaries

Ensure inbound typed methods use `SamlValidationContext` wherever signed,
timed, or replay-sensitive browser messages are validated. Ensure typed
SimpleSign POST input accepts raw form-body input and the library derives the
signature octets; manual detached octets remain raw compatibility only.

**Verify**:
`rg "SamlValidationContext|raw form body|manual detached" docs/architecture` -> claims are visible.

### Step 6: Document metadata and raw compatibility boundaries

Ensure metadata constructors bind expected entity IDs by default, role-specific
verified metadata names are used, signature policy enums replace booleans, and
raw role imports are documented under `raw`.

**Verify**:
`rg "from_metadata_xml_for|VerifiedIdpMetadata|AssertionSignaturePolicy|raw::ServiceProvider" docs/architecture plans` -> claims are visible.

## Test plan

This is a docs-only plan. Verification is:

- The `rg` checks listed above.
- `cargo fmt --all --check`
- `cargo test -p saml-rs --doc`
- `cargo clippy -p saml-rs --all-targets -- -D warnings`

## Execution Notes

Executed on 2026-07-04 on `advisor/typed-api-architecture`.

- `docs/architecture` is the canonical architecture and naming draft for this
  branch.
- Plan 019 refines `docs/architecture` in place.
- The architecture docs cover typed SSO, typed SLO, config/metadata trust,
  semantic errors/validation, and raw compatibility.
- Verification passed with the commands in this plan.

Verification run:

- `rg "Artifact resolution|SOAP/back-channel|ECP/PAOS|NameID management|metadata federation|bergshamra|FlowResult|Saml" docs/architecture plans`
  -> relevant claims visible.
- `rg "architecture tree|separate architecture" docs/architecture plans`
  -> only Plan 019 context.
- `rg "canonical architecture|refine.*in place|Artifact resolution|ECP/PAOS" docs/architecture`
  -> expected claims visible.
- `rg "IdpDescriptor|SpDescriptor" docs/architecture plans`
  -> descriptor names visible in architecture and plan examples.
- `rg "StartSlo|RespondSlo|PendingSnapshot|SamlValidationContext|FormField|PostForm" docs/architecture/002-public-api-map.md`
  -> all names present.
- `rg "PendingSnapshot|from_snapshot|peer entity ID|present empty" docs/architecture`
  -> persistence and correlation claims visible.
- `rg "SamlValidationContext|raw form body|manual detached" docs/architecture`
  -> validation context and SimpleSign boundaries visible.
- `rg "from_metadata_xml_for|VerifiedIdpMetadata|AssertionSignaturePolicy|raw::ServiceProvider" docs/architecture plans`
  -> metadata and raw compatibility boundaries visible.
- `cargo fmt --all --check` -> exit 0.
- `cargo test -p saml-rs --doc` -> exit 0.
- `cargo clippy -p saml-rs --all-targets -- -D warnings` -> exit 0.

## Done criteria

- [x] `docs/architecture` is identified as the branch canonical architecture
      and naming draft.
- [x] Plan 019 refines `docs/architecture` in place.
- [x] Unsupported high-level profiles are explicit.
- [x] Descriptor naming is the source of truth.
- [x] Public API map includes expected root-discoverable types.
- [x] Pending snapshot persistence is documented.
- [x] RelayState tri-state matching is documented.
- [x] SimpleSign typed input derives signature octets from raw browser input.
- [x] Inbound typed validation uses `SamlValidationContext`.
- [x] Metadata constructors bind expected entity IDs.
- [x] Raw compatibility imports are clear.
- [x] Verification commands pass.
- [x] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Existing architecture docs conflict with README support claims.
- A reviewer asks to move architecture docs out of `docs/architecture`.
- Any required update appears to require source-code changes.
- Any verification command fails for code unrelated to docs changes.

## Maintenance notes

These docs are meant to prevent future drift. API changes should update the
public API map, security-sensitive validation changes should update validation
docs, and dependency or crypto changes should update the crypto boundary notes.
