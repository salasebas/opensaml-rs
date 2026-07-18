# Standards Conformance Policy

This document defines how `saml-rs` interprets and implements requirements from
the OASIS SAML specifications. It is the maintainer policy for new protocol
behavior, validation, rendering, metadata, bindings, profiles, and
compatibility work.

The goal is precise conformance without inventing protocol requirements:

- mandatory requirements are always implemented for the applicable scope;
- recommendations are enabled by default and may be relaxed only through an
  explicit policy;
- optional capabilities are exposed intentionally;
- requirements aimed at one actor are not silently converted into requirements
  for another actor;
- behavior not required by the applicable standards is not presented as OASIS
  validation.

## Normative Sources

Use the applicable approved OASIS SAML V2.0 documents, official XML schemas,
and approved errata. Depending on the change, this may include Core, Bindings,
Profiles, Metadata, Conformance, XML Signature, XML Encryption, and XML Schema.

Authoritative starting points include:

- [OASIS SAML V2.0 document and schema index](https://docs.oasis-open.org/security/saml/v2.0/)
- [SAML V2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [SAML V2.0 approved Errata 05](https://docs.oasis-open.org/security/saml/v2.0/errata05/os/)
- [SAML assertion schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd)
- [SAML protocol schema](https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd)
- [RFC 2119 requirement levels](https://www.rfc-editor.org/rfc/rfc2119.html)
- [RFC 8174 capitalization clarification](https://www.rfc-editor.org/rfc/rfc8174.html)
- [W3C XML Schema](https://www.w3.org/TR/xmlschema-1/)

Before implementing or reviewing SAML behavior:

1. Identify the exact normative document, section, and schema declaration.
2. Check applicable approved errata.
3. Check whether a binding or profile narrows or adds requirements.
4. Prefer final standards over drafts unless the feature explicitly targets a
   draft or extension.
5. Record enough provenance in the issue, PR, test, or code comment for a
   future maintainer to verify the interpretation.

OASIS SAML Core uses the requirement language defined by RFC 2119. Its schema
documents take precedence over schema listings in prose when they disagree,
while normative prose may impose additional constraints beyond the schemas.

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
- `SHOULD` and `RECOMMENDED` describe the normal behavior. A deviation requires
  a valid reason and an understanding of its interoperability and security
  consequences.
- `SHOULD NOT` and `NOT RECOMMENDED` describe behavior that is normally
  avoided. An exception likewise requires explicit justification.
- `MAY` and `OPTIONAL` describe behavior or capabilities that are truly
  optional.

OASIS also uses labels such as `[Required]` and `[Optional]` when describing
XML elements and attributes. These commonly express schema presence or
cardinality rather than a separate requirement level. A field can be optional
to include while still having mandatory processing rules when it is present.

Only uppercase requirement keywords carry the special RFC meaning. Normative
schemas and prose can still impose requirements without using one of those
keywords, so classification must consider the complete applicable text.

## Interpret The Rule Before Implementing It

Never classify a rule from its keyword alone. Determine all of the following:

- **Actor:** producer, sender, receiver, relying party, identity provider,
  service provider, metadata publisher, metadata consumer, or application.
- **Direction:** outbound generation, inbound acceptance, inbound validation,
  or local API behavior.
- **Condition:** whether the rule applies only when a field, signature,
  binding, feature, or prior condition is present.
- **Scope:** Core, a particular profile, binding, role, message type, or
  optional extension.
- **Layer:** XML/schema validity, protocol processing, profile processing,
  cryptographic processing, or application policy.
- **Required outcome:** generate, accept, process, verify, ignore, reject, or
  expose a value.

A requirement for one actor does not automatically create a rejection rule for
another actor. In particular:

- `MUST generate` does not imply that a receiver `MUST reject` every other
  representation.
- `MUST NOT generate` does not imply that a receiver `MUST reject` the prohibited
  output.
- `SHOULD` for a producer does not imply that a receiver should reject a
  producer that deviates.

Add inbound rejection only when the applicable schema, Core processing rule,
binding, profile, conformance requirement, or another normative source makes
the input invalid or requires the receiver to reject it.

Conditional requirements remain mandatory when their condition is true. For
example, an element may be optional, while a receiver `MUST` perform a
particular check whenever that element is present.

## Library Policy By Requirement Level

### Mandatory Conformance

For applicable `MUST`, `REQUIRED`, `SHALL`, `MUST NOT`, and `SHALL NOT`
requirements:

- implement the requirement in every API that claims the applicable SAML
  behavior;
- do not provide a policy that disables it in a conformant typed flow;
- enforce required XML structure, datatype, namespace, and cardinality rules
  that are within the parser or validator's declared scope;
- fail closed with an explicit `SamlError` when a mandatory inbound validation
  rule requires rejection;
- test the narrowest positive and negative cases that prove the requirement;
- do not broaden the rule beyond its actor, condition, or profile.

Raw compatibility APIs may expose lower-level data and unsupported profiles,
but they must not silently label non-conformant data as validated. A raw escape
hatch is not permission to weaken the mandatory guarantees of a typed result.

### Recommended Conformance

For applicable `SHOULD`, `RECOMMENDED`, `SHOULD NOT`, and `NOT RECOMMENDED`
requirements:

- follow the recommendation by default;
- permit a deviation only through an explicit, typed, and narrowly named
  policy or builder option;
- avoid generic `strict` booleans that combine unrelated recommendations;
- document the exact recommendation being relaxed and the interoperability or
  security consequences;
- apply producer recommendations to generated output without automatically
  turning them into inbound rejection rules;
- keep the conformant default visible in API documentation and tests.

Compatibility policies are exceptions, not alternate interpretations of
OASIS. Their names and documentation should make the deviation clear.

### Optional Capabilities

For applicable `MAY` and `OPTIONAL` behavior:

- expose support through an intentional API, configuration, builder, or
  feature flag when the capability is in scope;
- do not imply that every optional SAML capability must be implemented;
- accept or preserve optional wire data when required for interoperability,
  even if the library does not otherwise use that data;
- apply any mandatory processing rules that become active when the optional
  capability is selected or the optional field is present;
- keep unsupported profiles explicit rather than partially implementing them
  behind ambiguous behavior.

### Unspecified And Application Policy

Terms such as `implementation-dependent`, `application-specific`,
`profile-specific`, and `unspecified` do not create another RFC requirement
level. They identify decisions intentionally left to an implementation,
profile, deployment, or caller.

For such behavior:

- do not invent an OASIS rejection rule;
- expose an application policy or hook when the decision belongs to the caller;
- document library defaults as library policy, not standards conformance;
- distinguish protocol validation from resource limits, parser safety, and
  other implementation-security controls.

Implementation-security controls such as XML resource limits or disabling an
unsafe cryptographic backend may remain library invariants even when they are
not SAML wire requirements. Their rationale must be documented separately and
must not be cited as if OASIS required a peer's message to be rejected.

## Examples

### Required `IssueInstant`

The SAML assertion and response schemas declare `IssueInstant` with
`use="required"`. Missing values are structurally invalid, so typed inbound
flows enforce their presence without a disable switch.

SAML time values are `xs:dateTime` values and `MUST` use the UTC form required
by SAML. This is part of wire conformance, not a freshness policy. Message age,
clock skew, and replay checks require their own normative or application-policy
basis.

### Leap Seconds

SAML Core says implementations `MUST NOT generate` time instants that specify
leap seconds. This is an absolute outbound-generation rule.

That producer requirement does not by itself say that a receiver `MUST reject`
an inbound leap-second value. Any inbound rejection needs a separate normative
receiver rule or must be identified as an explicit library/application policy.

### Optional Field With Mandatory Processing

An attribute such as `Destination` can be optional in the message schema while
the receiver is required to compare it with the actual destination whenever it
is present. Configuration may control whether an optional outbound value is
emitted, but it may not disable the mandatory inbound comparison once the
condition applies.

## Change And Review Checklist

Every change that adds or alters SAML behavior should answer:

1. What exact standard, schema declaration, profile, binding, or erratum
   governs the behavior?
2. What is the requirement level?
3. Who is the obligated actor?
4. Is the rule conditional?
5. What message types, roles, bindings, and profiles are in scope?
6. Does the normative text require generation, processing, acceptance,
   verification, or rejection?
7. Is the implementation enforcing only that requirement, without adding a
   stricter receiver rule?
8. Is a recommendation default-on and relaxed only through an explicit policy?
9. Is optional behavior intentionally configured and interoperable?
10. Do focused tests cover the normative boundary without duplicating unrelated
    guarantees?

When the evidence is ambiguous, investigate the schemas, related OASIS
documents, approved errata, and interoperability behavior before changing
validation. Do not guess, and do not turn uncertainty into a new rejection
rule.
