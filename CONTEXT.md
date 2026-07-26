# SAML Protocol Support

This context describes the boundaries between low-level SAML compatibility
primitives and feature-scoped protocol flows.

## Language

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
