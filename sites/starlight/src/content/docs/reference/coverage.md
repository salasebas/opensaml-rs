---
title: "Coverage"
description: "`Saml<Sp>` and `Saml<Idp>` implement this surface."
---

`Saml<Sp>` and `Saml<Idp>` implement this surface.

| Area | Support |
| --- | --- |
| Web SSO | Signed `AuthnRequest` and `Response` over HTTP-POST, HTTP-Redirect, and HTTP-POST-SimpleSign |
| Metadata | Parse peer metadata, generate SP and IdP descriptors, verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` on the same three bindings |
| Artifact resolution | SOAP `ArtifactResolve` and `ArtifactResponse` through `resolve_artifact` and `answer_artifact_resolve`. The deployment sends the HTTP request |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through bergshamra |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

HTTP-Artifact browser delivery, ECP/PAOS, SAML query protocols, NameID management, and metadata federation are outside the typed `Saml` API. Artifact resolution over SOAP does not claim the IdP or SP operational mode.

A request for one of them needs the profile, the binding, the peer product, and a minimal expected flow on [an issue](https://github.com/salasebas/saml-rs/issues).

Claimed rules for the flows that do exist are the [conformance records](conformance.md). Method signatures are on [docs.rs](https://docs.rs/saml-rs).
