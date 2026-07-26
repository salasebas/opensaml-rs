# SAML Protocol

This context names the SAML roles and flows whose protocol obligations are
modeled by saml-rs.

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
