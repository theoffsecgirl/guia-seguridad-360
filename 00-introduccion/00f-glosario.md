# Glosario

Nota de uso

- Definiciones pensadas para trabajo de campo; se prioriza claridad sobre formalismo.
- Acrónimos en inglés conservan su forma habitual; se añade traducción cuando aporta.

## General y legales

- Alcance (Scope): activos, técnicas y ventanas permitidas para probar; todo lo demás está prohibido.
- VDP (Vulnerability Disclosure Program): política pública para reportar fallos, normalmente sin recompensas.
- Divulgación coordinada: publicar tras parche o fecha acordada; nunca antes.
- PII (Personally Identifiable Information): datos personales identificables; deben redactarse en evidencias.
- Stop-test: pausa inmediata ante daño o degradación accidental.

## Metodología y evidencias

- Timebox: bloque de tiempo máximo por objetivo antes de rotar.
- Hipótesis: suposición explotable que guía pruebas (qué puede romperse y por qué).
- PoC (Proof of Concept): prueba mínima, determinista y reproducible que demuestra impacto.
- Reproducibilidad: capacidad de repetir un hallazgo en entorno limpio con pasos breves.
- GO/NO‑GO: decisión de continuar o rotar según señales objetivas.

## Red y protocolos

- DNS: sistema de nombres; superficie para subdominios, registros y CT logs.
- HTTP/1.1 vs HTTP/2: versiones con semántica y parsing distintos; relevantes en desync/smuggling.
- TLS/ALPN: negociación de protocolo de aplicación; útil para fingerprinting.
- CDN: red de distribución; afecta cache, headers y visibilidad de origen.

## Servidor (back-end)

- LFI/RFI (Local/Remote File Inclusion): inclusión de ficheros locales/remotos por entrada controlada.
- Path Traversal: navegación fuera del directorio permitido mediante patrones ../.
- SQLi/NoSQLi: inyección en SQL/NoSQL por concatenación o parsers débiles.
- SSTI (Server-Side Template Injection): ejecución en motores de plantillas del servidor.
- SSRF (Server-Side Request Forgery): el servidor realiza peticiones a destinos controlados por atacante.
- XXE (XML External Entity): entidades externas en XML que exfiltran/impactan.
- Deserialización insegura: ejecución/instanciación de objetos manipulados.
- Upload bypass: subida de ficheros peligrosos mediante polyglots, confusión MIME/extensión.
- Cache Poisoning: envenenamiento del caché (edge/origen) alterando claves de cacheo.
- Request Smuggling/Desync: desincronización entre front/back por discrepancias de parsing.

## Cliente (navegador)

- XSS (Cross-Site Scripting): ejecución de JS en contexto de víctima (reflected/stored/DOM).
- CSRF: acción no autorizada desde sesión autenticada de la víctima.
- Clickjacking: UI redirigida/oculta para inducir clicks.
- XS‑Leaks: filtrado lateral por tiempos/recursos que revelan estado/privacidad.
- CSP (Content Security Policy): política para restringir recursos/ejecución en cliente.
- Trusted Types: mecanismo para mitigar XSS DOM mediante “tipos de confianza”.
- Service Worker: worker de navegador con control de caché/rutas (riesgo de secuestro).

## Autenticación y sesiones

- JWT (JSON Web Token): token firmado (HS/RS/ES) para identidad; riesgo en verificación parcial/confusión de claves.
- OAuth 2.0 / OIDC: autorización/identidad delegada; vectores en redirect_uri, scopes, PKCE, CSRF.
- SAML: intercambio de aserciones XML; sensible a firma y canonicalización.
- SameSite: atributo de cookie (Lax/Strict/None) que condiciona envío cross-site.
- Device binding: vinculación de sesión a factores del dispositivo.

## APIs

- REST: interfaz sobre HTTP con recursos; vulnerabilidades típicas en BOLA/BFLA/Mass Assignment/HPP.
- GraphQL: endpoint único con esquema; riesgos de introspección, field-level auth, alias/batching.
- gRPC: RPC sobre HTTP/2; fuzzing vía reflexión o conversión a JSON/HTTP.
- BOLA (Broken Object Level Authorization): acceso a objetos ajenos por ID válido.
- BFLA (Broken Function Level Authorization): ejecución de funciones no autorizadas.
- Mass Assignment: asignación masiva a campos sensibles no intencionados.
- HPP (HTTP Parameter Pollution): colisión/duplicidad de parámetros para alterar lógica.

## Cache/CDN

- WCD (Web Cache Deception): servir contenido sensible como estático para cachearlo.
- Vary/Key: cabeceras que determinan claves de cache; mal configuración → envenenamiento.
- Edge vs Origen: caché en borde/CDN frente a servidor de aplicación.

## Cloud e infraestructura

- Buckets (S3/GCS/Azure Blob): almacenamiento de objetos; exposición/listing/ACLs débiles.
- Pre‑signed URL: URL con firma/expiración; riesgos en control de expiración/alcance.
- IMDS/Metadata: endpoints de metadatos de instancia; objetivos típicos de SSRF.
- Secret scanning: búsqueda de claves/tokens en artefactos (JS, repos, logs).

## Móvil/iOS

- ATS (App Transport Security): políticas de red seguras en iOS.
- Keychain: almacenamiento seguro de secretos; revisar protección/claves.
- TLS Pinning: validación estricta de certificado/clave pública en cliente.
- Frida: framework de hooking dinámico para instrumentación.
- AASA (apple‑app‑site‑association): fichero para Universal Links; verificar control y rutas.

## Recon/OSINT

- CT Logs (Certificate Transparency): fuentes para descubrir subdominios.
- ASN: sistema autónomo; útil para mapear rangos IP de una organización.
- Favicon hash: huella de favicon para correlacionar superficies.
- Analytics/Ads IDs: correlación por IDs (GA/GTAG, Segment, etc.).
- .well-known: endpoints estandarizados (security.txt, apple-app-site-association, etc.).

## Seguridad de código/CI‑CD

- Dependency Confusion: dependencias públicas con mismo nombre que privadas.
- Typosquatting: paquetes con nombres similares para engañar la resolución.
- Lockfiles: archivos de bloqueo de dependencias; críticos para integridad.
- SBOM: lista de materiales de software; inventario de componentes.

## Severidad y clasificación

- CVSS: sistema para puntuar severidad técnica (base/temporal/contextual).
- VRT: taxonomía de vulnerabilidades para priorización en bug bounty.
- Impacto: efectos sobre confidencialidad/integridad/disponibilidad/privacidad/finanzas.
- Alcance (Blast radius): número de usuarios/tenants/sistemas afectados.

## Detección y defensa

- WAF: cortafuegos de aplicación; puede alterar/parchear tráfico y generar falsos positivos/negativos.
- Ratelimit: límites de frecuencia; relevantes en automatización/race conditions.
- IDS/IPS: detección/prevención de intrusiones en red o host.
- CSP/Headers de seguridad: X‑Frame‑Options, HSTS, X‑Content‑Type‑Options, etc.

## Condiciones de carrera y lógica

- Race Condition (TOCTOU): discrepancia entre comprobación y uso → efectos duplicados o inconsistentes.
- Idempotency Key: clave para evitar ejecución duplicada de operaciones.
- Jitter: variación temporal intencional para desincronizar defensa y prueba.
- Canary request: petición de control para detectar cambios/ban/ratelimits.

## Herramientas y formatos (mención rápida)

- Burp Suite: proxy/interceptación y extensión de pruebas web.
- ffuf: fuzzing HTTP ultra rápido.
- subfinder/httpx: descubrimiento de subdominios y verificación HTTP.
- nuclei: ejecución de plantillas de detección/explotación light.
- Arjun: descubrimiento de parámetros.
- HAR: formato de captura de tráfico HTTP para reproducibilidad.

## Placeholders y convenciones en evidencias

- IDs sintéticos: USER_A, USER_B, ORDER_123.
- Timestamps: UTC ISO‑8601 (ej. 2025‑09‑08T13:15:30Z).
- Redacción: ocultar correos, teléfonos, tokens y PII; conservar original cifrado.
- Nomenclatura de archivos: poc-<categoria>-<recurso>.md (ej. poc-idor-orders.md).

## Abreviaturas rápidas

- RCE: ejecución remota de código.
- LFI/RFI: inclusión local/remota de ficheros.
- DoS/DDoS: denegación de servicio (simple/distribuida).
- MITM: ataque de intermediario.
- C2: comando y control (no aplicable en bug bounty salvo laboratorios).
- E2E: extremo a extremo (cifrado/procesos).

## Consejos de uso del glosario

- Preferir términos en inglés cuando sean estándar de la industria; añadir traducción si reduce ambigüedad.
- Mantener coherencia de términos en reportes y mapear a categorías VRT/CVSS cuando corresponda.
- Ampliar este glosario con términos de dominio específicos (fintech, health, telco) según targets frecuentes.
  <span style="display:none">[^10][^3][^5][^7][^9]</span>

<div style="text-align: center">Glosario</div>

[^1]: https://www.youtube.com/watch?v=Sbf_zokpR1w
    
[^2]: https://www.tiktok.com/@hackavis/video/7515119578746260758
    
[^3]: https://seoxan.es/glosario/bug-bounty
    
[^4]: https://www.incibe.es/sites/default/files/contenidos/guias/doc/guia_glosario_ciberseguridad_2021.pdf
    
[^5]: https://www.dragonjar.org/bugbounty.xhtml
    
[^6]: https://www.welivesecurity.com/la-es/2020/01/21/bug-bounty-como-funciona-hacking-etico-caceria-vulnerabilidades/
    
[^7]: https://cyscope.io/es/bug-bounties-la-defensa-que-tus-activos-digitales-necesitan/
    
[^8]: https://www.dragonjar.org/diccionarios-con-passwords-de-sitios-expuestos.xhtml
    
[^9]: https://www.instagram.com/reel/DKuiBMBsfF3/
    
[^10]: https://www.tiktok.com/@ekopartyok/video/7509598462120381752
