# Rutas de Ataque por Stack

No todos los stacks ni tecnologías se atacan igual: cada uno tiene “shortcuts”, errores clásicos y vectores TOP para bug bounty y pentesting. Esta guía te da, de forma directa y táctica, las principales rutas de ataque y focos por stack web, móvil, cloud, y supply chain. Úsala como checklist para priorizar pruebas y no dejar low-hanging fruit.

---

## Web App clásicos (LAMP, Node.js, Java, .NET, Python)

- **LAMP/PHP:**
  - Include/Require remotos (RFI/LFI)
  - Uploads “soft check” (bypasseo de extensiones/tipo MIME)
  - SQLi legacy (filtros parciales/bypass, mysql_real_escape_string)
  - Serialización vulnerable (`unserialize()` puro, __wakeup tricks)
  - .git/.env y backups en docroot
- **Node.js:**
  - Inyección en eval(), exec(), spawn
  - Prototype pollution (`__proto__` en JSON/payloads)
  - Express misconfig (routers “catch-all”, open CORS)
  - JWT manual con HS256/JWK mal validados
  - Directory traversal con path.join y strings sin normalizar
- **Java/JSP:**
  - Deserialización (CommonsCollections, ysoserial payloads)
  - Struts/Spring route injection/param pollution
  - SSRF a beans/RMI (localhost, cloud metadata)
  - Mal uso de sesiones/JSF ViewState sin criptografía
  - Configs con passwords en .properties
- **.NET (ASP):**
  - ViewState no firmado/no cifrado (decodear y modificar)
  - Deserialización XML/JSON no segura
  - Fuga de API internos/panel dev en rutas de trace/debug
  - Configuraciones legacy en web.config
  - IDOR/BOLA en endpoints OData
- **Python/Django/Flask:**
  - SSTI/Jinja2 injections vía plantillas
  - Pickle deserializable por usuarios
  - Debug panels y Werkzeug access sin protección
  - Imports/exec de payloads remotos por Flask apps DIY
  - Settings.py o archivos *.pyc expuestos

---

## Mobile (iOS/Android/API)

- **Android:**
  - Backups .apk/config sueltos en servidores
  - API keys embebidas y endpoints comentados
  - Exported activities y “deeplink” handlers sin filtrar
  - Cert pinning débil o saltado por tráfico interceptable
  - Inyección a WebView/JavaScript
- **iOS:**
  - Exposición de API keys en Info.plist
  - Universal Links no restringidos / AASA expuesto
  - Debug builds y backdoors activos en prod
  - Uso de Keychain sin restricciones NSAppTransportSecurity
  - APIs internas sin autenticación
- **Mobile API:**
  - Versionado flojo (acepta v0/v1/v2)
  - JWT o sesiones “heredadas” por apps antiguas
  - Falta de rate limit, abuso por scripts
  - Validaciones sólo en frontend móvil

---

## Cloud (AWS, GCP, Azure)

- Buckets públicos world-readable o world-writable (S3, GCS, Azure Blob)
- Key leaks en GitHub/repos/archivos de build
- Pre-signed URLs sin expiración
- IAM overly permissive (star policies, admin/owner a todo)
- Cloud metadata open (ssrf a `http://169.254.169.254/`)
- Cloud Functions/Lambdas invokables por cualquier usuario
- Webhooks y endpoints de integración sin autenticación

---

## Supply Chain / CI/CD

- Dependencias sin pin (npm, pip, gem) → typosquatting, dependency confusion
- Secretos en scripts YAML, GitHub Actions, pipelines
- Imágenes Docker con herramientas “forgotten”/SSH claves
- Exposición de builds anteriores/configs/artefactos
- Artefactos/pipelines propagando credenciales a envs/hijos sin rotación

---

## API (REST, GraphQL, SOAP)

- Bypass auth via method confusion: GET vs POST vs PATCH
- Mutation abuse en GraphQL (query introspection, batch requests)
- Filtro insuficiente de parámetros (overposting)
- Rutas “no documentadas” pero funcionales por versionado
- Default CRUD sin eliminar en endpoints generados automáticos
- Expansiones automáticas (`expand=*`) abriendo datos internos

---

## SaaS/OAuth/SSO

- OAuth misconfig: Accepts “open redirects”, redirect_uri trick
- IDP Bypass (SSO con mail custom, invitaciones, puede añadir cualquier correo)
- Magic link a correo externo/no controlado
- SAML Assertion manipulation
- Tokens con vida excesiva/jwk rotas

---

## Recursos rápidos y cheatlists

- [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists/Technologies](https://github.com/danielmiessler/SecLists/tree/master/Technologies)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [HackerOne VRT](https://www.hackerone.com/vulnerability-rating-taxonomy)

---

**TIP:** Antes de empezar, revisa la tecnología real del target y prioriza los vectores clásicos de ese stack. Ahorra energía en ruido, maximiza cobertura rentable y demuestra conocimiento del entorno: eso marca el diferencial real en bug bounty y pentesting top.
