# Standards conformance

This note explains how `saml-rs` interprets requirements from the OASIS SAML
specifications. It covers new protocol behaviour, validation, rendering,
metadata, bindings, profiles, and compatibility work. The steps for reviewing
a change are in
[How to review a SAML change](how-to-review-saml-behaviour.md).

The aim is precise conformance without inventing protocol requirements:

- mandatory requirements are always implemented for the applicable scope;
- recommendations are enabled by default and may be relaxed only through an
  explicit policy;
- optional capabilities are exposed intentionally;
- requirements aimed at one actor are not silently converted into requirements
  for another actor;
- behaviour not required by the applicable standards is not presented as OASIS
  validation.

## Normative sources

The source for a feature is the exact approved specification, schema, and
errata that govern it. The links below are a navigation aid, not a whitelist,
an exhaustive list, or a statement of the crate's current feature support.

The canonical catalogs for the SAML V2.0 specification set are:

- [SAML V2.0 Conformance Requirements](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf),
  which identifies the documents and schemas that comprise SAML V2.0 and
  defines its conformance model;
- the [official OASIS SAML V2.0 document and schema index](https://docs.oasis-open.org/security/saml/v2.0/),
  which contains the approved documents, schemas, and schema archive.

The base specification set commonly relevant to implementation work includes:

- [Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [Authentication Context](https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf)
- [Security and Privacy Considerations](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- the official assertion, protocol, metadata, authentication-context, and
  profile schemas in the OASIS index
- [approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/)

An applicable feature may also be governed by an approved OASIS SAML extension
or later OASIS specification and by dependent standards such as XML Schema,
XML Signature, XML Encryption, HTTP, URI, or TLS. Each source applies only
within its scope, and the record names the exact version and status. A draft
is not the default SAML requirement. A draft is a target only for an explicitly
experimental feature.

Requirement-language and dependent-standard references include:

- [RFC 2119 requirement levels](https://www.rfc-editor.org/rfc/rfc2119.html)
- [RFC 8174 capitalization clarification](https://www.rfc-editor.org/rfc/rfc8174.html)
- [W3C XML Schema](https://www.w3.org/TR/xmlschema-1/)

OASIS SAML Core uses the requirement language defined by RFC 2119. Its schema
documents take precedence over schema listings in prose when they disagree,
while normative prose may impose additional constraints beyond the schemas.

## Feature-Scoped Conformance

SAML conformance is not a single global switch. The OASIS conformance model
defines a feature by the combination of a profile, a message exchange or flow,
and a selected binding. A conformance or support claim must therefore identify
the applicable scope, including:

- operational mode and role, such as service provider, identity provider,
  sender, receiver, metadata publisher, or metadata consumer;
- protocol, message type, and direction;
- profile and the portion of its flow being implemented;
- binding;
- optional capability, attribute profile, or extension, when applicable.

Parsing or serializing a SAML element, supporting a protocol message, or
implementing one step of a flow does not by itself imply conformance with an
entire profile, binding, operational mode, or SAML V2.0 as a whole. A broad
claim such as "SAML V2.0 conformant" requires a documented support matrix that
shows the exact claimed features and their normative coverage.

This policy applies to every SAML feature that `saml-rs` implements. It neither
declares the crate's current support nor limits future support. Bindings,
profiles, operational modes, queries, extensions, and other capabilities may
be added incrementally, provided each one has an explicit boundary and meets
all mandatory requirements within the scope it claims. Unsupported and partial
features must remain explicit rather than being inferred from lower-level XML
support.

## Requirement Vocabulary

The RFC 2119 terms form three main levels:

| Level | Positive terms | Negative terms |
| --- | --- | --- |
| Mandatory | `MUST`, `REQUIRED`, `SHALL` | `MUST NOT`, `SHALL NOT` |
| Recommended | `SHOULD`, `RECOMMENDED` | `SHOULD NOT`, `NOT RECOMMENDED` |
| Optional | `MAY`, `OPTIONAL` | — |

Within each row, the terms have the same normative strength:

- `MUST`, `REQUIRED`, and `SHALL` are absolute requirements.
- `MUST NOT` and `SHALL NOT` are absolute prohibitions.
- `SHOULD` and `RECOMMENDED` describe the normal behaviour. A deviation requires
  a valid reason and an understanding of its interoperability and security
  consequences.
- `SHOULD NOT` and `NOT RECOMMENDED` describe behaviour that is normally
  avoided. An exception likewise requires explicit justification.
- `MAY` and `OPTIONAL` describe behaviour or capabilities that are truly
  optional.

OASIS also uses labels such as `[Required]` and `[Optional]` when describing
XML elements and attributes. These commonly express schema presence or
cardinality rather than a separate requirement level. A field can be optional
to include while still having mandatory processing rules when it is present.

Only uppercase requirement keywords carry the special RFC meaning. Normative
schemas and prose can still impose requirements without using one of those
keywords, so classification must consider the complete applicable text.

## What a rule actually obligates

A keyword is not enough to classify a rule. Classification names all of the
following:

- **Actor:** producer, sender, receiver, relying party, identity provider,
  service provider, metadata publisher, metadata consumer, or application.
- **Direction:** outbound generation, inbound acceptance, inbound validation,
  or local API behaviour.
- **Condition:** whether the rule applies only when a field, signature,
  binding, feature, or prior condition is present.
- **Scope:** Core, a particular profile, binding, role, message type, or
  optional extension.
- **Layer:** XML/schema validity, protocol processing, profile processing,
  cryptographic processing, or application policy.
- **Required outcome:** generate, accept, process, verify, ignore, reject, or
  expose a value.

A requirement for one actor does not create a rejection rule for another
actor. In particular:

- `MUST generate` does not imply that a receiver `MUST reject` every other
  representation.
- `MUST NOT generate` does not imply that a receiver `MUST reject` the prohibited
  output.
- `SHOULD` for a producer does not imply that a receiver should reject a
  producer that deviates.

Inbound rejection belongs in the library only when the applicable schema, Core
processing rule, binding, profile, conformance requirement, or another
normative source makes the input invalid or requires the receiver to reject
it.

Conditional requirements remain mandatory when their condition is true. For
example, an element may be optional, while a receiver `MUST` perform a
particular check whenever that element is present.

## What each requirement level means here

### Mandatory conformance

An applicable `MUST`, `REQUIRED`, `SHALL`, `MUST NOT`, or `SHALL NOT`
requirement has this shape in the library:

- every API that claims the applicable SAML behaviour implements it;
- a conformant typed flow has no policy that disables it;
- required XML structure, datatype, namespace, and cardinality rules inside
  the parser or validator's declared scope are enforced;
- a mandatory inbound validation rule that requires rejection fails closed
  with an explicit `SamlError`;
- the narrowest positive and negative tests prove the requirement;
- the rule stays inside its actor, condition, and profile.

Raw compatibility APIs can expose lower-level data and unsupported profiles.
They do not label non-conformant data as validated. A raw escape hatch does
not weaken the mandatory guarantees of a typed result.

### Recommended conformance

An applicable `SHOULD`, `RECOMMENDED`, `SHOULD NOT`, or `NOT RECOMMENDED`
requirement has this shape:

- the recommendation is the default;
- a deviation exists only as an explicit, typed, narrowly named policy or
  builder option;
- unrelated recommendations stay separate, rather than sharing one generic
  `strict` boolean;
- the relaxed recommendation, and its interoperability or security
  consequences, are named;
- a producer recommendation changes generated output and does not by itself
  become an inbound rejection;
- the conformant default is visible in API documentation and tests.

Recommended is the preset for claimed features. It is not an implementation
of SAML V2.0 as a whole. Compatibility is the legacy permissive preset: the
samlify-port behaviour kept for callers leaving the raw API. It is not an
alternate interpretation of OASIS, and a recommendation relaxation does not
use that name.

### Optional capabilities

An applicable `MAY` or `OPTIONAL` behaviour has this shape:

- support, when the capability is in scope, is an intentional API,
  configuration, builder, or feature flag;
- naming a capability in the specifications does not imply that this crate
  implements it;
- optional wire data stays available when interoperability needs it, even when
  the library does not otherwise use that data;
- mandatory processing rules that become active when the optional capability
  is selected, or the optional field is present, still apply;
- an unsupported profile stays explicit, rather than appearing as a partial
  implementation behind ambiguous behaviour.

### Unspecified behaviour and application policy

Terms such as `implementation-dependent`, `application-specific`,
`profile-specific`, and `unspecified` do not create another RFC requirement
level. They identify decisions left to an implementation, profile, deployment,
or caller.

For that kind of behaviour:

- the library does not invent an OASIS rejection rule;
- when the decision belongs to the caller, the library exposes an application
  policy or hook;
- a library default is documented as library policy, not standards conformance;
- protocol validation stays distinct from resource limits, parser safety, and
  other implementation-security controls.

Implementation-security controls, such as XML resource limits or disabling an
unsafe cryptographic backend, can remain library invariants even when they are
not SAML wire requirements. Their rationale is recorded separately from OASIS
text. Citing them as if OASIS required a peer's message to be rejected
misstates the source.

## Interpretation Examples

These examples are illustrative, not exhaustive, and do not define the crate's
current feature support:

- **Required `IssueInstant`:** The assertion and response schemas declare
  `IssueInstant` with `use="required"`. Missing values are structurally invalid,
  so typed inbound flows enforce their presence without a disable switch.
  SAML's UTC wire-format rule is separate from freshness, clock-skew, and
  replay policies, which require their own basis.
- **Producer-only leap-second rule:** SAML Core says implementations `MUST NOT
  generate` time instants that specify leap seconds. This is an absolute
  outbound rule, but it does not by itself require receivers to reject an
  inbound leap-second value. Rejection needs a separate normative receiver
  rule or an explicitly identified library or application policy.
- **LogoutRequest expiration:** `LogoutRequest@NotOnOrAfter` is optional for
  inbound general LogoutRequest processing, and Core says a recipient may
  discard the message after that instant. saml-rs' fail-closed rejection of an
  expired value is therefore documented as library policy, not an OASIS
  receiver `MUST`. The required UTC `IssueInstant` is checked separately and
  does not imply a library-selected maximum request age.
- **Optional field with mandatory processing:** `Destination` can be optional
  in the message schema while a receiver is required to compare it with the
  actual destination whenever it is present. Configuration may control
  outbound emission, but it may not disable a mandatory inbound comparison
  once its condition applies.
- **Signed HTTP binding destination:** The HTTP-Redirect and HTTP-POST
  bindings, and the supported HTTP-POST-SimpleSign CD04 binding, require a
  signed message to contain `Destination` and require the receiver to verify
  it against the actual endpoint. A typed receiver therefore rejects a missing
  or mismatched value after authenticating the binding-level message; an
  Assertion-only signature does not activate this Response-level condition.
- **CBC-encrypted assertions:** Approved Errata 05 E93 recommends integrity
  protection before a relying party processes CBC-encrypted SAML data and
  specifically recommends signing a Response that contains a CBC
  `EncryptedAssertion`. Typed defaults follow this producer and relying-party
  recommendation; accepting an unsigned CBC-encrypted Response requires
  `ResponseSignaturePolicy::AllowUnsignedEncryptedCbc`. Generating one
  requires `RespondSso::allow_unsigned_encrypted_cbc`.

The working checklist for a change is
[How to review a SAML change](how-to-review-saml-behaviour.md).
