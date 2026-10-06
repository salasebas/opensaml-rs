# How to review a SAML change

Use this when a change adds or alters SAML generation, parsing, validation,
bindings, profiles, or metadata. Why each check exists is explained in
[standards conformance](standards-conformance.md).

## Identify the rule

1. Identify the exact normative document, section, and schema declaration.
2. Check applicable approved errata.
3. Check whether a binding or profile narrows or adds requirements.
4. Prefer a final standard over a draft, unless the feature explicitly targets
   a draft or extension.
5. Record the normative provenance in the issue or pull request. A code
   comment states what the caller can do with the item
   ([coding standards](../CODING_STANDARDS.md)).

## Answer these before merging

1. What exact standard, schema declaration, profile, binding, or erratum
   governs the behaviour?
2. What feature-scoped conformance or support claim is affected?
3. What is the requirement level?
4. Who is the obligated actor?
5. Is the rule conditional?
6. What message types, roles, directions, bindings, and profiles are in scope?
7. Is the implementation complete for that claimed scope, or does it provide
   only lower-level parsing, serialisation, or partial flow support?
8. Does the normative text require generation, processing, acceptance,
   verification, or rejection?
9. Is the implementation enforcing only that requirement? A stricter receiver
   rule is library policy, stated in its own sentence in the pull request
   ([coding standards](../CODING_STANDARDS.md)).
10. Is a recommendation default-on and relaxed only through an explicit
    policy?
11. Is optional behaviour intentionally configured and interoperable?
12. Do focused tests cover the normative boundary without duplicating unrelated
    guarantees?

When the evidence is ambiguous, check the schemas, related OASIS documents,
approved errata, and interoperability behaviour before changing validation.
Leave the rule as it is until that evidence is clear. An uncertain reading
does not become a new rejection.
