# Fixture Provenance

Some committed fixtures were derived from the npm `samlify` project during the
original conformance work.

| Field | Value |
| --- | --- |
| Source project | npm `samlify` |
| Repository | https://github.com/tngan/samlify |
| Version | `2.13.1` |
| Tag | `v2.13.1` |
| Commit | `b1ff880ab40a4b4768b3afb53ef8b88c3437079b` |
| npm tarball | https://registry.npmjs.org/samlify/-/samlify-2.13.1.tgz |
| npm integrity | `sha512-vdYr/zohDGBbfWNU4miEzc1jmWOtkLySPViapC6nfGkv9KxzLq4UlGkKyryzwLw4jVlZk88Rw93HaCRVpe+t+g==` |

These files are historical regression and provenance inputs. They are not an
active compatibility promise, and future behavior should be justified by SAML
specifications, interoperability evidence, or focused local tests.

Fixture key material is test-only and must not be used outside tests.

## External SLO HTTP-Redirect fixtures

The fixtures under `tests/fixtures/interop/` are immutable interoperability
and regression inputs. They are not a conformance certification, an OASIS
requirement to test these products, or a release gate. Tests consume the
committed query strings verbatim and never regenerate them with `saml-rs`.

All private keys and certificates in this fixture group are intentionally
public, test-only material. They must never be trusted or used outside tests.
The metadata files are minimal documents assembled from the generation
configuration and the corresponding public test certificate; they are not
claims about a production deployment.

### Shibboleth IdP 5.2.3 → saml-rs SP

| Field | Value |
| --- | --- |
| Producer and role | Shibboleth Identity Provider, IdP-initiated `LogoutRequest` |
| Product version | Shibboleth Identity Provider `5.2.3` |
| Distribution | https://shibboleth.net/downloads/identity-provider/latest/shibboleth-identity-provider-5.2.3.tar.gz |
| Distribution SHA-256 | `8d7a43e8e2698cf06dbefec20d98bba4eb15d27b4dd1af4e63f367e8597311ff` (matches the adjacent published `.sha256`) |
| Runtime | Eclipse Temurin `17.0.19+10` |
| Binding and encoder | HTTP-Redirect via the distribution's `org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder` |
| Direction under test | `Saml<Sp>::receive_slo` |
| Entity ID | `https://idp.example.test/idp/shibboleth` |
| Destination | `https://sp.example.test/slo/redirect` |
| Signature | RSA-SHA256 detached Redirect signature |
| RelayState | `shibboleth-idp5-state` |
| License/source note | Shibboleth IdP is distributed under Apache License 2.0; only emitted test data and locally generated test credentials are committed |

Generation used the unmodified JARs in the published IdP distribution's
`webapp/WEB-INF/lib/` directory. After OpenSAML
`InitializationService.initialize()`, a SAML 2.0 `LogoutRequest` was populated
with the committed ID, timestamp, issuer, destination, persistent NameID, and
SessionIndex. A `BasicX509Credential` backed by the test key below and
RSA-SHA256 `SignatureSigningParameters` were placed in the message context.
The distribution's `HTTPRedirectDeflateEncoder` emitted the captured redirect
URL; the part after `?` is committed unchanged as `logout-request.query`.

The generation-only Java source, downloaded distribution, and servlet API
provided by the temporary runtime were deleted and are not repository inputs.

| Artifact | SHA-256 |
| --- | --- |
| `shibboleth-idp-5.2.3/logout-request.query` | `382ff30a8f4b98ce4d53184b6f27839d074c6802b077351cf86c9194f4123c48` |
| `shibboleth-idp-5.2.3/idp-metadata.xml` | `0c1914dd93653575f119845e2187f15f024b527c45198fa2fb34ee632a74079a` |
| `shibboleth-idp-5.2.3/idp-signing-cert.pem` | `f5cdbeb656b8de4461c5d68b0a0a7ea09ea04521179e19c26550ab011824e80f` |
| `shibboleth-idp-5.2.3/idp-signing-key.pem` | `8e77fad5bb74cc9caf781fdf9f7aee9ac0bb7f15f2f1cde55a1c0c006e4dee00` |

The RSA-2048 key and self-signed certificate were generated with OpenSSL
`3.6.2` using `genpkey` and `req -new -x509 -sha256 -days 3650`. The
certificate SHA-256 fingerprint is
`83:3D:0F:9A:1D:24:AE:3B:18:69:45:29:BD:AA:0D:2A:83:A5:D8:F0:DA:0E:32:FA:A3:12:34:97:CF:90:C5:63`.

### SimpleSAMLphp 2.5.2 SP → saml-rs IdP

| Field | Value |
| --- | --- |
| Producer and role | SimpleSAMLphp configured as a Service Provider, SP-initiated `LogoutRequest` |
| Product version | SimpleSAMLphp `2.5.2`, release commit `e04c29a` |
| Distribution | https://github.com/simplesamlphp/simplesamlphp/releases/download/v2.5.2/simplesamlphp-2.5.2-full.tar.gz |
| Distribution SHA-256 | `1394883cc15fb532b9cbac899377caac72163aaab964c0c67a793a69142a8902` (published on the `v2.5.2` release page) |
| SLO implementation dependency | `simplesamlphp/saml2-legacy` `v4.20.3`, commit `b43d5d10ea1180f478ddcd677ff13bb324cfa866` from the release's `composer.lock` |
| Runtime | PHP `8.3.32`, container image digest `sha256:2a3f699b6cb31e5638c5432e4d37d4047853ba6351a692c91e0a073af00a55cc` |
| Binding and encoder | HTTP-Redirect via `SAML2\HTTPRedirect::getRedirectURL` |
| Direction under test | `Saml<Idp>::receive_slo` |
| Entity ID | `https://sp.example.test/saml2` |
| Destination | `https://idp.example.test/slo/redirect` |
| Signature | RSA-SHA256 detached Redirect signature |
| RelayState | `simplesamlphp-sp-state` |
| License/source note | SimpleSAMLphp and `saml2-legacy` are LGPL-2.1-or-later; only emitted test data and locally generated test credentials are committed |

The full release archive was run without modifying its source or vendor tree.
The SimpleSAMLphp global configuration set `certdir=/fixtures`. The hosted SP
metadata set `entityid`, `privatekey`, `certificate`, `sign.logout=true`, and
`signature.algorithm` to RSA-SHA256. The remote IdP metadata set its entity ID
and `sign.logout=true`. Production helper
`SimpleSAML\Module\saml\Message::buildLogoutRequest` created and signed the
request; the test ID, timestamp, destination, RelayState, persistent NameID,
and two SessionIndex values were then set before production
`SAML2\HTTPRedirect::getRedirectURL` emitted the URL. The part after `?` is
committed unchanged as `logout-request.query`.

The generation-only PHP script, downloaded release archive, and PHP container
are not repository inputs.

| Artifact | SHA-256 |
| --- | --- |
| `simplesamlphp-2.5.2/logout-request.query` | `e2aba02abd802a6b14f392ca05d52693223324956fa5cd680a48193d1ffc3688` |
| `simplesamlphp-2.5.2/sp-metadata.xml` | `6a328f1fb906df715b13c408e8b79300a5f0971cc4c1832edaa497f907567719` |
| `simplesamlphp-2.5.2/sp-signing-cert.pem` | `5d716dea2429aacbe29b750f5680e8276d7d71e7a4b1498c96aab46dd8245408` |
| `simplesamlphp-2.5.2/sp-signing-key.pem` | `37b34025f8f0550c2013944db90d91c87a06f4b6f79e265dd528a30215ace306` |

The RSA-2048 key and self-signed certificate were generated with OpenSSL
`3.6.2` using `genpkey` and `req -new -x509 -sha256 -days 3650`. The
certificate SHA-256 fingerprint is
`51:69:56:63:DC:8D:51:FA:6A:42:37:F2:4B:D2:08:15:24:A7:1A:70:91:84:FF:12:7F:02:9F:DF:78:7A:8F:6D`.

## Fixture Groups

- `tests/fixtures/misc/**` - historical XML request, response, and metadata
  cases.
- `tests/fixtures/key/**` - test certificates and keys.
- `tests/fixtures/interop/**` - immutable external interoperability inputs and
  associated public test-only keys and metadata.
