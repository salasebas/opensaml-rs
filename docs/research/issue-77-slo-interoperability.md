# Issue #77: fixtures externos de interoperabilidad SLO

Fecha de investigación: 2026-07-23.

## Pregunta y alcance

El [issue #77](https://github.com/salasebas/opensaml-rs/issues/77) pide
fixtures inmutables de `LogoutRequest` firmados por Shibboleth,
SimpleSAMLphp y samlify para:

- HTTP-Redirect;
- HTTP-POST con XML Signature;
- HTTP-POST-SimpleSign, cuando el productor lo soporte.

Esta nota contrasta esa petición con la política local de
[conformidad](../standards-conformance.md), las especificaciones OASIS y el
código oficial de los tres productores. El alcance es recepción de
`LogoutRequest` en el perfil Single Logout (SLO), tanto SP → IdP como IdP →
SP. No evalúa `LogoutResponse`, SOAP ni Artifact.

## Resultado factual

La autenticación e integridad de un `LogoutRequest` recibido dentro del perfil
SLO sí tienen requisitos normativos. En particular, Profiles §4.4.3.1 dice
explícitamente que un participante que envía el `LogoutRequest` al IdP por
HTTP-Redirect o HTTP-POST debe firmarlo. Core y Profiles también obligan al
receptor a autenticar el mensaje o al emisor, según su rol.

OASIS no exige que una implementación conserve fixtures producidos por
terceros, que use esos tres productos ni que tenga una matriz de pruebas con
mensajes congelados. Los fixtures externos y las pruebas de alteración son
evidencia de interoperabilidad y controles de regresión del proyecto. La
política local exige pruebas enfocadas para los límites normativos, pero no
prescribe que deban provenir de implementaciones externas.

El repositorio ya implementa recepción firmada para los tres bindings y ambos
roles, pero sus pruebas firmadas de SLO generan y consumen los mensajes con
`saml-rs`. No existe actualmente una prueba de `receive_slo` que consuma un
`LogoutRequest` firmado y congelado de un productor externo.

## Decisión resultante

La brecha se tratará como evidencia adicional de interoperabilidad, no como un
defecto de conformidad ni como un gate de release. El primer incremento queda
delimitado al feature SLO `LogoutRequest` por HTTP-Redirect en las dos
direcciones de recepción tipada:

- Shibboleth IdP 5 → `Saml<Sp>::receive_slo`;
- SimpleSAMLphp SP → `Saml<Idp>::receive_slo`.

Cada dirección tendrá un fixture wire-level externo e inmutable, una prueba
positiva con reloj y replay deterministas, validación de los campos consumidos
y una prueba negativa que altere un campo firmado y falle en la frontera
criptográfica. La procedencia debe registrar productor, rol, versión o commit,
configuración o comando de generación, binding, certificado y clave de prueba,
y licencia o fuente. No se incorporarán clones, árboles vendor ni generadores
externos.

HTTP-POST queda fuera de este primer incremento. HTTP-POST-SimpleSign requiere
un tratamiento posterior separado que declare explícitamente su estatus CD04.
Samlify tampoco será el productor inicial porque parte del comportamiento y de
la suite histórica de `saml-rs` fue portado desde ese proyecto, lo que reduce
su valor como implementación independiente para esta prueba.

## Resultado de implementación

El incremento acordado quedó implementado con dos fixtures HTTP-Redirect
firmados e inmutables:

- Shibboleth Identity Provider 5.2.3 como IdP hacia
  `Saml<Sp>::receive_slo`;
- SimpleSAMLphp 2.5.2 configurado como SP hacia
  `Saml<Idp>::receive_slo`.

Las pruebas consumen el query wire-level conservado, usan política estricta
para firmas de logout, reloj y replay explícitos, y verifican issuer,
destination, ID, `IssueInstant`, todos los SessionIndex, binding Redirect y
algoritmo de firma. El vector SimpleSAMLphp también verifica NameID y
RelayState. El flujo completo de Shibboleth emitió, de forma predeterminada,
`EncryptedID` y no envió RelayState; la prueba afirma esa forma wire y
documenta que el modelo tipado actual autentica y consume la request pero
todavía no expone el identificador cifrado. Para cada productor, una segunda
ejecución altera un campo dentro del mensaje firmado sin volver a firmar y
comprueba que la verificación criptográfica falla antes de escribir en replay.
La procedencia exacta, hashes, receta reproducible y advertencia de claves
públicas de prueba están en `tests/fixtures/PROVENANCE.md`.

## Fuentes normativas y estatus

- [SAML Core 2.0, OASIS Standard, 15-03-2005](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf):
  §§3.2.1, 3.7.1, 3.7.3.1, 3.7.3.2 y 5.2.
- [SAML Profiles 2.0, OASIS Standard, 15-03-2005](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf):
  §§4.4.3.1, 4.4.3.3 y 4.4.4.1.
- [SAML Bindings 2.0, OASIS Standard, 15-03-2005](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf):
  §§3.4.4.1, 3.4.5.2 y 3.5.5.2.
- [SAML Conformance Requirements 2.0, OASIS Standard, 15-03-2005](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf):
  §§1.1, 2 y 3.2.
- [SAML HTTP POST-SimpleSign 1.0, Committee Draft 04, 01-12-2008](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.html):
  §§1.4 y 2.4–2.7.2. La
  [versión ODT](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign-cd-04.odt)
  se declara autoritativa.

POST-SimpleSign CD04 es posterior al conjunto base SAML V2.0 y no es un OASIS
Standard final. Conformance §1.1 enumera los documentos del estándar base y
POST-SimpleSign no aparece. La tabla de implementaciones posibles de
Conformance §2 enumera Redirect, POST, Artifact y SOAP para SLO; la matriz de
§3.2 exige HTTP-Redirect para SLO iniciado por IdP y por SP en los modos IdP y
SP. Por ello, SimpleSign es una capacidad adicional y debe declararse con su
estatus de Committee Draft; no amplía por sí sola una afirmación general de
conformidad SAML V2.0.

## Requisitos por actor, dirección y binding

### Reglas transversales de Core y del perfil

| Actor y dirección | Regla | Resultado exigido |
| --- | --- | --- |
| Productor de cualquier `LogoutRequest` | Core §3.7.1 | Debería firmar el mensaje o autenticarlo y proteger su integridad mediante el binding. Es un `SHOULD` del productor. |
| Participante receptor, normalmente SP en IdP → SP | Core §3.7.3.1 | Debe autenticar el mensaje. |
| Autoridad de sesión receptora, normalmente IdP en SP → IdP | Core §3.7.3.2 | Debe autenticar al emisor. |
| Requester en cualquier intercambio del perfil SLO | Profiles §4.4.4.1 | Debe autenticarse ante el responder y asegurar la integridad, firmando o usando un mecanismo específico del binding. |
| Participante productor en SP → IdP por HTTP-Redirect o HTTP-POST | Profiles §4.4.3.1 | El `LogoutRequest` debe estar firmado. |
| IdP productor en IdP → participante | Profiles §4.4.3.3 | No contiene la frase específica “`LogoutRequest` MUST be signed” de §4.4.3.1; siguen aplicando la autenticación/integridad general de §4.4.4.1 y el `MUST` del receptor en Core §3.7.3.1. |

Esto no crea una regla correcta del tipo “todo `LogoutRequest` sin firma es
inválido en cualquier parser”. El alcance normativo es el flujo SLO, el rol,
la dirección y el mecanismo de autenticación. Sí impide que un flujo tipado
declare recepción SLO autenticada cuando no dispone de un mecanismo válido.

### HTTP-Redirect

Bindings §3.4.4.1 define la firma en los parámetros de la URL, no como una
`ds:Signature` dentro del XML. Antes de comprimir se elimina una firma XML
embebida; cuando se firma el mensaje transmitido, `Signature` cubre la cadena
ordenada `SAMLRequest`, `RelayState` si existe y `SigAlg`. El verificador debe
usar los valores URL-encoded originales recibidos y el orden normativo.

El binding aislado permite firmar (`MAY`); la obligatoriedad para SP → IdP
proviene de Profiles §4.4.3.1, y la obligación del receptor de autenticar
proviene de Core §§3.7.3.1/3.7.3.2 y Profiles §4.4.4.1.

Si el mensaje está firmado, Bindings §3.4.5.2 obliga al productor a incluir
`Destination` y al receptor a comprobar que coincide con la ubicación real.
Además, Core §3.2.1 obliga a comparar cualquier `Destination` presente en una
request y descartar la request cuando no coincide.

### HTTP-POST con XML Signature

HTTP-POST transporta el XML en base64. Bindings §3.5.5.2 permite que el
mensaje esté firmado mediante XML Signature y, cuando lo está, exige
`Destination` y su comparación con la ubicación de recepción.

Core §3.2.1 obliga al responder a verificar una `ds:Signature` presente. Si no
es válida, no puede confiar en el contenido y debería responder con error; si
es válida, debería evaluar la identidad y la idoneidad del firmante. La
ausencia de `ds:Signature` no viola por sí sola el schema o el binding
genérico, pero en SP → IdP por POST incumple el requisito del productor de
Profiles §4.4.3.1 y deja sin satisfacer la autenticación requerida del flujo
si no existe otro mecanismo aplicable.

### HTTP-POST-SimpleSign CD04

SimpleSign CD04 §2.4 permite XML Signature y también la firma SimpleSign
separada. Con SimpleSign, `Signature` y `SigAlg` son controles del formulario;
`RelayState`, cuando existe, forma parte del contenido firmado. El productor
firma el XML crudo, no su representación base64, concatenado en el orden de
§2.5.

Según §2.6, el receptor de un mensaje SimpleSign debe extraer los controles,
reconstruir la cadena y comprobar `Signature` con `SigAlg`. La respuesta
concreta a una firma que no verifica queda como dependiente de la
implementación. Si el mensaje lleva XML Signature embebida, aplica en cambio
Core §3.2.1, incluido el requisito de no confiar en contenido con una firma
inválida.

Si se usa SimpleSign, §2.4 exige `Destination` y obliga al receptor a comparar
la ubicación. CD04 §2.7.2 declara opcional la seguridad criptográfica al nivel
del binding. Esa opcionalidad no elimina los requisitos de autenticación e
integridad cuando el binding se compone con el perfil SLO. Como Profiles
§4.4.3.1 nombra únicamente Redirect y POST —POST-SimpleSign todavía no
existía— no debe atribuirse a esa sección un `MUST` literal de firma
SimpleSign; la obligación aplicable proviene de la regla general de Profiles
§4.4.4.1 y Core.

## Naturaleza de los fixtures solicitados

| Elemento del issue | Clasificación |
| --- | --- |
| Autenticar un `LogoutRequest` recibido en un flujo SLO tipado | Requisito normativo, acotado por rol, dirección y binding. |
| Verificar una XML Signature presente y no confiar en ella si es inválida | Requisito normativo de Core §3.2.1. |
| Reconstruir y comprobar una firma Redirect o SimpleSign conforme a su binding | Requisito del mecanismo cuando existe/ha sido seleccionado; el requisito de usar autenticación en SLO proviene además de Core/Profiles. |
| Fixture congelado de Shibboleth, SimpleSAMLphp o samlify | No requerido por OASIS; evidencia de interoperabilidad. |
| Matriz de tres productores por tres bindings | Convención de QA del proyecto, no matriz de conformidad OASIS. |
| Alterar timestamp/campo y comprobar que la firma falla antes de la semántica | Prueba de regresión de orden fail-closed; no artefacto de prueba prescrito por OASIS. |
| Registrar versión, comando, clave, licencia y procedencia | Requisito de reproducibilidad/provenance del proyecto, no requisito del protocolo. |
| Cubrir timestamps fraccionarios emitidos por terceros | Evidencia de interoperabilidad léxica. XML Schema admite fracciones; no exige que un fixture externo concreto las contenga. |

La política local de `docs/standards-conformance.md` sí pide pruebas positivas
y negativas enfocadas para requisitos obligatorios. Esa es una obligación de
desarrollo del repositorio. No especifica que las pruebas deban usar fixtures
externos ni esos productores.

## Soporte real y viabilidad de productores

### Shibboleth

La documentación oficial de
[Shibboleth IdP 5](https://shibboleth.atlassian.net/wiki/spaces/IDP5/pages/3199511587/ProtocolsAndInterfaces)
y de
[Shibboleth SP 3](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2067400007/ProtocolsAndInterfaces)
enumera interfaces SLO para HTTP-Redirect, HTTP-POST,
HTTP-POST-SimpleSign y SOAP. La documentación específica del
[SingleLogoutService de SP 3](https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065334844)
también enumera esos bindings y señala que el mensaje entrante puede ser un
`LogoutRequest` o `LogoutResponse`.

| Binding objetivo | Soporte oficial observado | Viabilidad factual del fixture |
| --- | --- | --- |
| Redirect firmado | Sí | Una instalación de prueba IdP 5 o SP 3 puede participar en el flujo SLO y producir tráfico capturable. |
| POST con XML Signature | Sí | La interfaz SLO POST está documentada; una instalación con credenciales de firma puede producir el formulario y XML capturables. |
| POST-SimpleSign | Sí | IdP 5 y SP 3 publican endpoint SLO POST-SimpleSign. Es viable capturar el formulario, aunque la instalación completa es más pesada que un generador de biblioteca. |

Las páginas citadas documentan el soporte de la interfaz y sus endpoints, no
un comando autónomo para generar fixtures sin desplegar el producto. Un
fixture atribuido a “Shibboleth” tendría que identificar además si el
productor fue IdP o SP y la versión concreta.

### SimpleSAMLphp

La documentación estable declara HTTP-Redirect como binding SLO por defecto y
documenta `sign.logout` para firmar mensajes de logout:

- [Metadata endpoints](https://simplesamlphp.org/docs/stable/simplesamlphp-metadata-endpoints.html);
- [`sign.logout` y SingleLogoutService](https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-remote.html).

El código oficial de SimpleSAMLphp en el commit
[`7e0e645`](https://github.com/simplesamlphp/simplesamlphp/tree/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad)
selecciona exclusivamente Redirect y POST para `LogoutRequest` salientes:

- [SP `startSLO2`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/Auth/Source/SP.php#L1073-L1123);
- [IdP `sendLogoutRequest`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/IdP/SAML2.php#L542-L568);
- [`Message::buildLogoutRequest` y `sign.logout`](https://github.com/simplesamlphp/simplesamlphp/blob/7e0e6454fe5eb46e2bdd429a6bb60ad9214b15ad/modules/saml/src/Message.php#L99-L128).

La biblioteca oficial de bajo nivel `simplesamlphp/saml2` en el commit
[`f4bb3d1`](https://github.com/simplesamlphp/saml2/tree/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c)
incluye:

- [`HTTPRedirect`](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/src/Binding/HTTPRedirect.php);
- [`HTTPPost`](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/src/Binding/HTTPPost.php);
- un
  [constructor ejecutable de `LogoutRequest`](https://github.com/simplesamlphp/saml2/blob/f4bb3d15db55ec9a32ea08996c1fb24d6e37d01c/tests/bin/logoutrequest.php).

| Binding objetivo | Soporte oficial observado | Viabilidad factual del fixture |
| --- | --- | --- |
| Redirect firmado | Sí | `sign.logout` y el binding Redirect permiten producir la request en un despliegue de prueba. |
| POST con XML Signature | Sí | La selección saliente incluye POST y `HTTPPost` serializa la firma XML del mensaje. |
| POST-SimpleSign | No observado | Ni la selección de SLO del producto ni las clases de binding citadas incluyen SimpleSign. La matriz puede documentar esta ausencia sin sintetizar un mensaje. |

### samlify

El tag oficial `v2.13.1` apunta al commit
[`b1ff880`](https://github.com/tngan/samlify/tree/b1ff880ab40a4b4768b3afb53ef8b88c3437079b).
En ese commit:

- [`Entity::createLogoutRequest`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/entity.ts#L168-L211)
  enruta explícitamente Redirect, POST y SimpleSign;
- [`binding-post.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-post.ts#L281-L360)
  crea `LogoutRequest` POST y añade XML Signature cuando el receptor la
  exige;
- [`binding-simplesign.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-simplesign.ts#L245-L356)
  crea la request SimpleSign y calcula la firma separada;
- [`binding-redirect.ts`](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/src/binding-redirect.ts#L312-L382)
  crea la request Redirect y firma la cadena de query cuando procede;
- los
  [tests oficiales](https://github.com/tngan/samlify/blob/b1ff880ab40a4b4768b3afb53ef8b88c3437079b/test/units.ts#L482-L627)
  ejercitan los tres generadores, incluida la firma de LogoutRequest
  SimpleSign.

La guía pública de
[Signed SAML Request](https://samlify.js.org/signed-saml-request.html)
describe de forma explícita las firmas Redirect y POST, pero no documenta allí
SimpleSign. El código y sus tests son la evidencia primaria más específica
para esa tercera capacidad.

| Binding objetivo | Soporte oficial observado | Viabilidad factual del fixture |
| --- | --- | --- |
| Redirect firmado | Sí | API directa, sin desplegar un producto completo. |
| POST con XML Signature | Sí | API directa y test oficial de request firmada. |
| POST-SimpleSign | Sí | API directa; devuelve XML en base64, `Signature` y `SigAlg`. |

Para los tres bindings, el fixture puede congelar la salida de una llamada
controlada a `createLogoutRequest`, junto con el tag/commit, inputs, clave de
prueba y metadata. La atribución correcta es a la biblioteca samlify, no a una
instalación IdP/SP independiente.

## Brecha exacta del repositorio

1. **Superficie implementada.** `Saml<Sp>::receive_slo` recibe IdP → SP y
   `Saml<Idp>::receive_slo` recibe SP → IdP en
   [`src/api/slo.rs`](../../src/api/slo.rs). Ambos llegan a
   `receive_slo_impl`, que determina el `LogoutBinding`, llama a
   `parse_logout_request_at`, materializa el tipo, valida `Destination` contra
   metadata local y aplica replay.

2. **Política de firma.** La configuración estricta de SP e IdP usa
   `LogoutSignaturePolicy::RequireSigned`; la compatibilidad usa la excepción
   explícita `AllowUnsignedForCompatibility` en
   [`src/config/policies.rs`](../../src/config/policies.rs). Esa política se
   convierte en `want_logout_request_signed` en
   [`src/config/builders.rs`](../../src/config/builders.rs).

3. **Mecanismos por binding.**
   [`src/logout/parsing.rs`](../../src/logout/parsing.rs) pasa la exigencia de
   firma y los certificados del peer al flujo común.
   [`src/flow.rs`](../../src/flow.rs) verifica firma separada en Redirect y
   SimpleSign, comprueba que el octet string corresponde exactamente con los
   campos consumidos, y verifica XML Signature para POST. El resultado firmado
   se autentica antes de construir el modelo tipado.

4. **Pruebas firmadas existentes, pero simétricas.**
   [`tests/flow_conformance.rs`](../../tests/flow_conformance.rs) tiene
   round-trips firmados de LogoutRequest Redirect y POST, más aceptación,
   RelayState y alteración de SimpleSign. Todos se crean en runtime mediante
   `create_logout_request` de este mismo crate y se reciben con
   `parse_logout_request`. [`tests/typed_slo.rs`](../../tests/typed_slo.rs)
   usa la fachada `receive_slo`, relojes/políticas de replay y los tres
   bindings, pero también produce las requests con `saml-rs`.

5. **Fixture externo actual.**
   [`tests/fixtures/misc/logout_request.xml`](../../tests/fixtures/misc/logout_request.xml)
   es un `LogoutRequest` histórico sin `ds:Signature`; no contiene el
   envelope Redirect, los controles POST ni una firma SimpleSign. No existe
   una referencia `include_str!`/`include_bytes!` a ese archivo en las pruebas
   actuales. [`tests/fixtures/PROVENANCE.md`](../../tests/fixtures/PROVENANCE.md)
   atribuye el grupo histórico a samlify 2.13.1, pero no convierte ese XML en
   una prueba wire-level firmada.

6. **Ausencias concretas.** No hay fixtures inmutables de `LogoutRequest`
   firmados externamente, no hay certificado/metadata externa asociada a ellos,
   no hay test exitoso de la fachada tipada `receive_slo` contra una salida
   externa, y no hay alteración de esos fixtures externos que pruebe la
   precedencia criptográfica sobre la validación semántica. Tampoco existe una
   matriz de procedencia por productor, rol/dirección y binding.

La brecha observada es, por tanto, de evidencia externa y reproducibilidad.
No se observó en este análisis una ausencia del mecanismo básico de recepción
firmada para Redirect, POST XML Signature o POST-SimpleSign.
