# Issue #77: external SLO interoperability fixtures

Research date: 2026-07-23.

## Question and scope

[Issue #77](https://github.com/salasebas/opensaml-rs/issues/77) requests
immutable `LogoutRequest` fixtures signed by Shibboleth, SimpleSAMLphp, and
samlify for:

- HTTP-Redirect;
- HTTP-POST with XML Signature;
- HTTP-POST-SimpleSign, when supported by the producer.

This note evaluates that request against the local
[conformance policy](../standards-conformance.md), the OASIS specifications,
and the official code of the three producers. Its scope is receiving
`LogoutRequest` messages in the Single Logout (SLO) profile in both the
SP-to-IdP and IdP-to-SP directions. It does not evaluate `LogoutResponse`,
SOAP, or Artifact.

## Factual result

Authentication and integrity of a `LogoutRequest` received within the SLO
profile are subject to normative requirements. In particular, Profiles
section 4.4.3.1 explicitly requires a participant that sends a
`LogoutRequest` to the IdP over HTTP-Redirect or HTTP-POST to sign it. Core and
Profiles also require the receiver to authenticate the message or issuer,
depending on its role.

OASIS does not require an implementation to retain fixtures produced by third
parties, use these three products, or maintain a test matrix of frozen
messages. External fixtures and tampering tests are interoperability evidence
and project regression controls. The local policy requires focused tests at
normative boundaries, but does not prescribe that those tests come from
external implementations.

The repository already implements signed reception for all three bindings and
both roles, but its signed SLO tests generate and consume messages with
`saml-rs`. Before this change, no `receive_slo` test consumed a frozen, signed
`LogoutRequest` from an external producer.

## Resulting decision

The gap is treated as additional interoperability evidence, not as a
conformance defect or release gate. The first increment is limited to the SLO
`LogoutRequest` feature over HTTP-Redirect in both typed reception directions:

- Shibboleth IdP 5 to `Saml<Sp>::receive_slo`;
- SimpleSAMLphp SP to `Saml<Idp>::receive_slo`.

Each direction has an immutable external wire-level fixture, a positive test
with deterministic clock and replay behavior, validation of the consumed
fields, and a negative test that alters a signed field and fails at the
cryptographic boundary. Provenance must record the producer, role, version or
commit, generation configuration or command, binding, test certificate and
key, and license or source. No clones, vendor trees, or external generators
are committed.

HTTP-POST is outside this first increment. HTTP-POST-SimpleSign requires a
separate follow-up that explicitly declares its CD04 status. Samlify is not an
initial producer because some historical `saml-rs` behavior and tests were
ported from that project, reducing its value as an independent implementation
for this test.

## Implementation result

The agreed increment is implemented with two immutable, signed HTTP-Redirect
fixtures:

- Shibboleth Identity Provider 5.2.3 acting as an IdP toward
  `Saml<Sp>::receive_slo`;
- SimpleSAMLphp 2.5.2 configured as an SP toward
  `Saml<Idp>::receive_slo`.

The tests consume the preserved wire-level query, use a strict logout
signature policy with explicit clock and replay behavior, and verify issuer,
destination, ID, `IssueInstant`, every `SessionIndex`, Redirect binding, and
signature algorithm. The SimpleSAMLphp vector also verifies NameID and
RelayState. The full Shibboleth flow emitted `EncryptedID` by default and did
not send RelayState; the test asserts that wire shape and documents that the
current typed model authenticates and consumes the request but does not yet
expose the encrypted identifier. For each producer, a second execution alters
a field inside the signed message without re-signing and confirms that
cryptographic verification fails before any replay write. Exact provenance,
hashes, a reproduction recipe, and the public-test-key warning are recorded in
`tests/fixtures/PROVENANCE.md`.

## Normative sources and status

- [SAML Core 2.0, OASIS Standard, 15 March 2005](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf):
  sections 3.2.1, 3.7.1, 3.7.3.1, 3.7.3.2, and 5.2.
- [SAML Profiles 2.0, OASIS Standard, 15 March 2005](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf):
  sections 4.4.3.1, 4.4.3.3, and 4.4.4.1.
- [SAML Bindings 2.0, OASIS Standard, 15 March 2005](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf):
  sections 3.4.4.1, 3.4.5.2, and 3.5.5.2.
- [SAML Conformance Requirements 2.0, OASIS Standard, 15 March 2005](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf):
  sections 1.1, 2, and 3.2.
- [SAML HTTP POST-SimpleSign 1.0, Committee Draft 04, 1 December 2008](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html):
  sections 1.4 and 2.4-2.7.2. The
  [ODT version](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.odt)
  is declared authoritative.

POST-SimpleSign CD04 postdates the base SAML V2.0 document set and is not a
final OASIS Standard. Conformance section 1.1 lists the base standard
documents, and POST-SimpleSign is not among them. The table of possible
implementations in Conformance section 2 lists Redirect, POST, Artifact, and
SOAP for SLO; the matrix in section 3.2 requires HTTP-Redirect for IdP- and
SP-initiated SLO in the IdP and SP modes. SimpleSign is therefore an
additional capability and must be described with its Committee Draft status;
it does not independently broaden a general SAML V2.0 conformance claim.

## Requirements by actor, direction, and binding

### Cross-cutting Core and profile rules

| Actor and direction | Rule | Required outcome |
| --- | --- | --- |
| Producer of any `LogoutRequest` | Core section 3.7.1 | Should sign the message, or authenticate it and protect its integrity through the binding. This is a producer `SHOULD`. |
| Receiving participant, normally the SP in IdP-to-SP | Core section 3.7.3.1 | Must authenticate the message. |
| Receiving session authority, normally the IdP in SP-to-IdP | Core section 3.7.3.2 | Must authenticate the issuer. |
| Requester in any SLO profile exchange | Profiles section 4.4.4.1 | Must authenticate to the responder and ensure integrity by signing or using a binding-specific mechanism. |
| Participant producing SP-to-IdP over HTTP-Redirect or HTTP-POST | Profiles section 4.4.3.1 | The `LogoutRequest` must be signed. |
| IdP producing IdP-to-participant | Profiles section 4.4.3.3 | Does not contain the specific “`LogoutRequest` MUST be signed” wording from section 4.4.3.1; the general authentication and integrity rule in section 4.4.4.1 and the receiver `MUST` in Core section 3.7.3.1 still apply. |

These rules do not imply that every unsigned `LogoutRequest` is invalid in
every parser. The normative scope is the SLO flow, role, direction, and
authentication mechanism. They do prevent a typed flow from claiming
authenticated SLO reception when no valid mechanism is available.

### HTTP-Redirect

Bindings section 3.4.4.1 defines the signature in URL parameters, not as a
`ds:Signature` inside the XML. An embedded XML signature is removed before
compression; when the transmitted message is signed, `Signature` covers the
ordered `SAMLRequest`, optional `RelayState`, and `SigAlg` string. The verifier
must use the original URL-encoded values and normative order.

The isolated binding permits signing (`MAY`). The SP-to-IdP requirement comes
from Profiles section 4.4.3.1, while the receiver authentication requirement
comes from Core sections 3.7.3.1 and 3.7.3.2 and Profiles section 4.4.4.1.

When a message is signed, Bindings section 3.4.5.2 requires the producer to
include `Destination` and the receiver to verify it against the actual
location. Core section 3.2.1 additionally requires comparing any
`Destination` present in a request and discarding the request on mismatch.

### HTTP-POST with XML Signature

HTTP-POST transports the XML as base64. Bindings section 3.5.5.2 permits the
message to be signed with XML Signature and, when signed, requires
`Destination` and comparison against the receiving location.

Core section 3.2.1 requires a responder to verify a present `ds:Signature`.
When it is invalid, the responder cannot rely on the content and should return
an error; when it is valid, the responder should evaluate the signer's
identity and suitability. Absence of `ds:Signature` does not by itself violate
the schema or generic binding, but for SP-to-IdP over POST it violates the
producer requirement in Profiles section 4.4.3.1 and leaves the flow's
authentication requirement unsatisfied when no other applicable mechanism
exists.

### HTTP-POST-SimpleSign CD04

SimpleSign CD04 section 2.4 permits XML Signature as well as a separate
SimpleSign signature. With SimpleSign, `Signature` and `SigAlg` are form
controls; `RelayState`, when present, is included in the signed content. The
producer signs the raw XML rather than its base64 representation, concatenated
in the order defined by section 2.5.

Under section 2.6, a receiver of a SimpleSign message must extract the
controls, reconstruct the string, and verify `Signature` using `SigAlg`. The
specific response to a signature that does not verify is implementation
dependent. When the message instead carries an embedded XML Signature, Core
section 3.2.1 applies, including the rule not to rely on content with an
invalid signature.

When SimpleSign is used, section 2.4 requires `Destination` and requires the
receiver to compare the location. CD04 section 2.7.2 makes cryptographic
security optional at the binding level. That optionality does not remove the
authentication and integrity requirements when the binding is composed with
the SLO profile. Profiles section 4.4.3.1 names only Redirect and POST because
POST-SimpleSign did not yet exist, so that section must not be cited as a
literal SimpleSign-signature `MUST`; the applicable obligation comes from the
general rule in Profiles section 4.4.4.1 and Core.

## Nature of the requested fixtures

| Issue element | Classification |
| --- | --- |
| Authenticate a `LogoutRequest` received in a typed SLO flow | Normative requirement scoped by role, direction, and binding. |
| Verify a present XML Signature and do not rely on it when invalid | Normative requirement from Core section 3.2.1. |
| Reconstruct and verify a Redirect or SimpleSign signature according to its binding | Requirement of the mechanism when present or selected; the requirement to use authentication in SLO also comes from Core and Profiles. |
| Frozen Shibboleth, SimpleSAMLphp, or samlify fixture | Not required by OASIS; interoperability evidence. |
| Three-producer by three-binding matrix | Project QA convention, not an OASIS conformance matrix. |
| Alter a timestamp or field and confirm that signature verification precedes semantics | Fail-closed ordering regression test; not an OASIS-prescribed test artifact. |
| Record version, command, key, license, and provenance | Project reproducibility and provenance requirement, not a protocol requirement. |
| Cover fractional timestamps emitted by third parties | Lexical interoperability evidence. XML Schema permits fractions but does not require a specific external fixture to contain them. |

The local `docs/standards-conformance.md` policy does require focused positive
and negative tests for mandatory requirements. That is a repository
development obligation. It does not require those tests to use external
fixtures or these specific producers.

## Actual producer support and feasibility

### Shibboleth

The official documentation for
[Shibboleth IdP 5](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199511587/ProtocolsAndInterfaces)
and
[Shibboleth SP 3](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067400007/ProtocolsAndInterfaces)
lists SLO interfaces for HTTP-Redirect, HTTP-POST, HTTP-POST-SimpleSign, and
SOAP. The specific
[SP 3 SingleLogoutService documentation](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334844)
also lists these bindings and notes that the incoming message can be a
`LogoutRequest` or `LogoutResponse`.

| Target binding | Observed official support | Factual fixture feasibility |
| --- | --- | --- |
| Signed Redirect | Yes | A test IdP 5 or SP 3 installation can participate in SLO and produce capturable traffic. |
| POST with XML Signature | Yes | The POST SLO interface is documented; an installation with signing credentials can produce a capturable form and XML. |
| POST-SimpleSign | Yes | IdP 5 and SP 3 publish POST-SimpleSign SLO endpoints. Capturing the form is feasible, though a full installation is heavier than a library generator. |

The cited pages document interface support and endpoints, not a standalone
fixture-generation command that avoids deploying the product. A fixture
attributed to Shibboleth must additionally identify whether the producer was
the IdP or SP and record the exact version.

### SimpleSAMLphp

The stable documentation identifies HTTP-Redirect as the default SLO binding
and documents `sign.logout` for signing logout messages:

- [Metadata endpoints](https://simplesamlphp.org/docs/stable/simplesamlphp-metadata-endpoints.html);
- [`sign.logout` and SingleLogoutService](https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-remote.html).

The official SimpleSAMLphp code at commit
[`7e0e645`](https://github.com/simplesamlphp/simplesamlphp/tree/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad)
selects only Redirect and POST for outbound `LogoutRequest` messages:

- [SP `startSLO2`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/Auth/Source/SP.php#L1073-L1123);
- [IdP `sendLogoutRequest`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/IdP/SAML2.php#L542-L568);
- [`Message::buildLogoutRequest` and `sign.logout`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/Message.php#L99-L128).

The official lower-level `simplesamlphp/saml2` library at commit
[`f4bb3d1`](https://github.com/simplesamlphp/saml2/tree/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c)
includes:

- [`HTTPRedirect`](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/src/Binding/HTTPRedirect.php);
- [`HTTPPost`](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/src/Binding/HTTPPost.php);
- an
  [executable `LogoutRequest` constructor](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/tests/bin/logoutrequest.php).

| Target binding | Observed official support | Factual fixture feasibility |
| --- | --- | --- |
| Signed Redirect | Yes | `sign.logout` and the Redirect binding can produce the request in a test deployment. |
| POST with XML Signature | Yes | Outbound selection includes POST, and `HTTPPost` serializes the message's XML Signature. |
| POST-SimpleSign | Not observed | Neither the product's SLO selection nor the cited binding classes include SimpleSign. The matrix can record this absence without synthesizing a message. |

### samlify

The official `v2.13.1` tag points to commit
[`b1ff880`](https://github.com/tngan/samlify/tree/b1ff880ab40a4b4768b3afb53ef8b88c3437079b).
At that commit:

- [`Entity::createLogoutRequest`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/entity.ts#L168-L211)
  explicitly routes Redirect, POST, and SimpleSign;
- [`binding-post.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-post.ts#L281-L360)
  creates a POST `LogoutRequest` and adds XML Signature when required by the
  receiver;
- [`binding-simplesign.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-simplesign.ts#L245-L356)
  creates the SimpleSign request and calculates the separate signature;
- [`binding-redirect.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-redirect.ts#L312-L382)
  creates the Redirect request and signs the query string when applicable;
- the
  [official tests](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/test/units.ts#L482-L627)
  exercise all three generators, including a signed SimpleSign
  `LogoutRequest`.

The public
[Signed SAML Request guide](https://samlify.js.org/signed-saml-request.html)
explicitly describes Redirect and POST signatures, but does not document
SimpleSign on that page. The code and tests are the most specific primary
evidence for that third capability.

| Target binding | Observed official support | Factual fixture feasibility |
| --- | --- | --- |
| Signed Redirect | Yes | Direct API, with no full product deployment. |
| POST with XML Signature | Yes | Direct API and an official signed-request test. |
| POST-SimpleSign | Yes | Direct API; returns base64 XML, `Signature`, and `SigAlg`. |

For all three bindings, a fixture can freeze the output from a controlled
`createLogoutRequest` call together with the tag or commit, inputs, test key,
and metadata. The correct attribution is to the samlify library, not to an
independent IdP or SP installation.

## Exact repository gap

1. **Implemented surface.** `Saml<Sp>::receive_slo` receives IdP-to-SP and
   `Saml<Idp>::receive_slo` receives SP-to-IdP in
   [`src/api/slo.rs`](../../src/api/slo.rs). Both reach `receive_slo_impl`,
   which determines `LogoutBinding`, calls `parse_logout_request_at`,
   materializes the typed value, validates `Destination` against local
   metadata, and applies replay protection.

2. **Signature policy.** Strict SP and IdP configuration uses
   `LogoutSignaturePolicy::RequireSigned`; compatibility uses the explicit
   `AllowUnsignedForCompatibility` exception in
   [`src/config/policies.rs`](../../src/config/policies.rs). That policy is
   converted into `want_logout_request_signed` in
   [`src/config/builders.rs`](../../src/config/builders.rs).

3. **Mechanisms by binding.**
   [`src/logout/parsing.rs`](../../src/logout/parsing.rs) passes the signature
   requirement and peer certificates into the shared flow.
   [`src/flow.rs`](../../src/flow.rs) verifies detached signatures for Redirect
   and SimpleSign, confirms that the octet string corresponds exactly to the
   consumed fields, and verifies XML Signature for POST. The signed result is
   authenticated before the typed model is built.

4. **Existing signed but symmetric tests.**
   [`tests/flow_conformance.rs`](../../tests/flow_conformance.rs) contains
   signed Redirect and POST `LogoutRequest` round trips, plus SimpleSign
   acceptance, RelayState, and tampering coverage. Every request is generated
   at runtime by this crate's `create_logout_request` and received with
   `parse_logout_request`. [`tests/typed_slo.rs`](../../tests/typed_slo.rs)
   uses the `receive_slo` facade with clocks, replay policies, and all three
   bindings, but also produces requests with `saml-rs`.

5. **Existing external fixture.**
   [`tests/fixtures/misc/logout_request.xml`](../../tests/fixtures/misc/logout_request.xml)
   is a historical `LogoutRequest` without `ds:Signature`; it does not contain
   the Redirect envelope, POST controls, or a SimpleSign signature. No current
   test references that file with `include_str!` or `include_bytes!`.
   [`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)
   attributes the historical group to samlify 2.13.1, but that does not make
   the XML a signed wire-level test.

6. **Concrete absences before this change.** There were no immutable,
   externally signed `LogoutRequest` fixtures; no external certificate or
   metadata associated with such fixtures; no successful typed `receive_slo`
   test against external output; and no mutation of those external fixtures
   demonstrating that cryptographic verification precedes semantic
   validation. There was also no provenance matrix by producer,
   role/direction, and binding.

The observed gap was therefore one of external evidence and reproducibility.
This analysis did not find an absence of the basic signed reception mechanism
for Redirect, POST XML Signature, or POST-SimpleSign.
