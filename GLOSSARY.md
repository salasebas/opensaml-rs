# Glossary

Names for the SAML roles, flows, and receiver boundaries whose protocol
obligations saml-rs models. Each entry is the term to use, then the term to
avoid when that distinction matters.

## Language

**Session Authority**:
The SAML provider that issued the authentication statement for a current
session and coordinates that session's termination.
_Avoid_: Identity Provider, when the actor-specific protocol role matters

**Session Participant**:
A SAML provider whose local session was established from an authentication
statement issued by a Session Authority.
_Avoid_: Service Provider, when the actor-specific protocol role matters

**Session-authority logout**:
A logout operation in which the Session Authority constructs the outbound
`LogoutRequest`; its obligations are narrower than those of generic logout.
_Avoid_: IdP-initiated logout, when the producer role is what matters

**Raw compatibility parser**:
A low-level SAML operation whose guarantees are limited to the protocol context
explicitly supplied by its caller.
_Avoid_: Raw receiver, conformant raw flow

**Typed SLO receiver**:
An inbound Single Logout flow that carries the role, binding, local endpoint,
peer, and transaction context of the actual SAML recipient.
_Avoid_: Typed parser, checked raw parser

**Actual recipient**:
The protocol participant operating the endpoint at which a SAML message was
received.
_Avoid_: Parser, XML consumer

**Outstanding logout**:
A `LogoutRequest` the actual recipient has accepted and that is still before
its `NotOnOrAfter`, for one principal and session. A later assertion for that
same principal and session is not accepted.
_Avoid_: session store, revoked cookie

**Validation preset**:
A named bundle of validation choices. The presets are Compatibility and
Recommended.
_Avoid_: profile, strict

**Library hardening**:
An extra rejection the SAML specifications do not require, selected by name
on top of a validation preset.
_Avoid_: strict, profile

**Claimed feature**:
A SAML behaviour saml-rs already implements, bounded by role, direction,
profile or flow, and binding. An operational mode is a role in
[SAML V2.0 Conformance Requirements](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
§3.1: IdP, IdP Lite, SP, SP Lite, ECP, and the SAML authorities. Table 2 is
the feature matrix for the IdP and SP columns. A claimed feature is one cell
of that matrix, a profile or message exchange plus a binding. The cells this
crate records are in `docs/conformance/`.
_Avoid_: SAML V2.0 as a whole, an operational-mode column

**Recommended**:
The validation preset for claimed features. For the obligated actor, mandatory
requirements stay in force. Recommendations start enabled and can be relaxed
only by an explicit named option. A producer recommendation does not by itself
become a receiver rejection.
_Avoid_: default, full SAML conformance, profile

**Compatibility**:
The legacy permissive preset. It is the samlify-port behaviour kept for a
caller leaving the raw API. It does not claim standards conformance, and it
does not name a relaxation of an OASIS recommendation.
_Avoid_: OASIS relaxation, recommended, default

**Raw settings**:
Historical configuration that predates the validation presets. Its defaults
are independent of Compatibility.
_Avoid_: compatibility, recommended
