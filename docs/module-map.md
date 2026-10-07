# Module map

Where a SAML behaviour is implemented. Conformance rows for the same public
methods are in [`docs/conformance/`](conformance/). The typed-API design record
is in [`docs/architecture/`](architecture/README.md).

## Typed browser SSO

| Behaviour | File |
| --- | --- |
| SP `start_sso`, `finish_sso`, `accept_unsolicited_sso` | `src/api/sp.rs` |
| IdP `receive_sso`, `respond_sso`, `initiate_sso` | `src/api/idp.rs` |
| Assertion conditions on an accepted response | `src/assertion_acceptance.rs` |
| Typed `start_slo`, `receive_slo`, `respond_slo`, `finish_slo` | `src/api/slo.rs` |

`finish_sso_with_outstanding_logout` and
`accept_unsolicited_sso_with_outstanding_logout` are in `src/api/sp.rs`.

## Identity Provider Discovery

| Behaviour | File |
| --- | --- |
| IdP `remember_identity_provider` | `src/api/idp.rs`, `src/discovery.rs` |

## Raw login

| Behaviour | File |
| --- | --- |
| Raw service provider | `src/sp.rs` |
| Raw identity provider | `src/idp.rs` |
| Login response construction | `src/idp/login_response.rs` |
| Shared raw flow | `src/flow.rs` |

## Validation and cryptography

| Behaviour | File |
| --- | --- |
| XML signature verification | `src/crypto/verify.rs` |
| XML signature generation | `src/crypto/sign.rs` |
| Clock, replay context, and message age | `src/model/validation.rs` |
| Validation presets and named policies | `src/config/policies.rs` |
| Peer descriptors | `src/config/descriptors.rs` |

## Logout

| Behaviour | File |
| --- | --- |
| Logout request and response construction | `src/logout/creation.rs` |
| Parsing | `src/logout/parsing.rs` |
| Rendering | `src/logout/rendering.rs` |
| Signing | `src/logout/signing.rs` |

Logout is the directory `src/logout/`.

## Conformance rows

| Flow | Page |
| --- | --- |
| Inbound Web Browser SSO | [`web-browser-sso-acceptance.md`](conformance/web-browser-sso-acceptance.md) |
| Outbound Web Browser SSO | [`web-browser-sso-generation.md`](conformance/web-browser-sso-generation.md) |
| Single Logout | [`single-logout.md`](conformance/single-logout.md) |
| Identity Provider Discovery | [`identity-provider-discovery.md`](conformance/identity-provider-discovery.md) |
| Metadata trust and replay | [`metadata-and-replay.md`](conformance/metadata-and-replay.md) |

## Compatibility crates

| Crate | Path |
| --- | --- |
| `opensaml`, `samlify`, `samlet` | `crates/<name>` |

Workspace members are in the root `Cargo.toml`. Publish configuration is in
`release-plz.toml` and `.github/workflows/ci.yml`.

## Large modules

- `src/flow.rs`
- `src/idp.rs`
- `src/sp.rs`
- `src/crypto/verify.rs`
- `src/logout/creation.rs`
