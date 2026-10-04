# SAML Protocol

This context names the SAML roles, flows, and receiver boundaries whose
protocol obligations are modeled by saml-rs.

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
