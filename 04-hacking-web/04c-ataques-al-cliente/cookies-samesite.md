# Cookies y SameSite – Guía Completa

## Resumen

Las cookies son el pilar de la autenticación y persistencia de sesión en la web, pero su manejo incorrecto sigue siendo fuente de vulnerabilidades graves, desde robo de sesión (session hijacking) hasta chain de ataques CSRF y tracking cross-site. La directiva `SameSite` representa un estándar moderno para mitigar riesgos de CSRF y limitar el envío de cookies en contextos cross-site, pero tiene matices, bypasses y detalles críticos que todo pentester y desarrollador debe dominar.[^2]

---

## Fundamentos de Cookies

- **Cookie:** Par clave-valor almacenado en el navegador y enviado automáticamente en todas las peticiones al mismo dominio y ruta correspondiente.
- **Atributos clave:**
  - **Domain / Path:** Define el (sub)dominio y rutas válidas.
  - **Expires / Max-Age:** Controla el lifetime.
  - **Secure:** Solo se envía bajo HTTPS.
  - **HttpOnly:** Inaccesible desde JavaScript (protección XSS).
  - **SameSite:** Controla el envío cross-site.

---

## Tipos y Comportamiento de SameSite

### 1. **SameSite=None**

- Cookie se envía SIEMPRE en requests cross-site y third-party, solo si además tiene el flag `Secure`.
- **Uso:** OAuth, SSO, aplicaciones embebidas.
- **Peligro:** Exposición máxima a CSRF, XSS, leak en iframes y tracking.

### 2. **SameSite=Lax**

- Cookie se envía en peticiones del top-level navigation (GET) y ciertos métodos “seguros”.
- Es el valor **default** en navegadores modernos (2024+).
- **Mitiga:** CSRF en la mayoría de casos normales.
- **Bypass:** submissions via GET/common methods, métodos override, algunos flows OAuth y redirecciones.

### 3. **SameSite=Strict**

- Cookie solo se envía si el sitio origen coincide exactamente con el destino.
- **Más seguro contra CSRF, menos compatible con flows SSO, widgets y federaciones.**

---

## Ejemplo de Envío de Cookies

```http
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=victima.com; Expires=Wed, 10 Sep 2025 23:59:00 GMT
```

---

## Ejemplos de Ataque y Bypass

### 1. Session Fixation y Hijacking

- Cookies sin `HttpOnly` pueden ser leídas por JavaScript tras XSS (robo de sesión).
- Sin `Secure`, expuestas incluso en conexiones HTTP, MITM o proxies.

### 2. CSRF por falta de SameSite

- Sin SameSite, peticiones cross-domain pueden llevar la cookie y ejecutar acciones bajo la sesión de la víctima.
- **PoC básico:**

```html
<img src="https://victima.com/change_email?email=atacante@evil.com">
```

### 3. Bypasses Comunes de SameSite

- **Method override:** Aplicaciones que permiten GET → POST via `_method`.
- **First 2 minutes after authentication:** Chrome permite cross-site cookies durante los primeros 2 minutos tras setearlas.
- **Subdomain cookie injection:** Ataques desde subdominios laxos (ver CVE y chains con `document.domain`).
- **Legacy browsers:** Ignoran o no soportan flag SameSite.

### 4. OAuth y SSO

- OAuth y federaciones suelen invalidarse o requerir cookies `SameSite=None; Secure`, abriéndose a ataques de transferencia e impersonation.

---

## Metodología de Testing

### 1. Enumeración y Análisis con DevTools

- Revisar en Application → Storage → Cookies: atributos, domain, path.
- ¿Cookies compartidas entre subdominios?
- ¿Tokens sensibles expuestos sin flags?

### 2. Manipulación en PoCs

- Modificar cookies vía JavaScript (`document.cookie`), si falta `HttpOnly`.
- Forzar envío cross-origin vía tags HTML (`img`, `iframe`, `form`) y monitorear qué cookies llegan al backend.
- Simular navegaciones y flujos OAuth, midiendo cuándo cae el flag.

### 3. Automatización

**Burp Suite / ZAP:** Plugins para testing/fuzzing de cookies (inclusión/cadena, scope)
**Nuclei templates:**

```bash
nuclei -u https://victima.com -t misconfig/cookies-samesite.yaml
```

**Scripting:**

```python
import requests
r = requests.get('https://victima.com', cookies={'session': 'test'})
print(r.cookies)
```

---

## Detección de Problemas Comunes

- Cookies sin Secure en producción.
- Tokens de sesión sin HttpOnly y/o SameSite.
- Cookies de autenticación accesibles en rutas de uploads, subdominios no confiables, legacy hostnames.
- Cookies “persistent” en flows SSO no segregadas y con Secure.

---

## Ejemplo de Reporte

```markdown
## Cookie Misconfiguration: No SameSite/HttpOnly/Secure flags

**Severidad:** Alta  
**PoC:** Inyectar una request cross-site y observar envío de cookie no protegida  
**Impacto:** Session fixation, CSRF, data exfiltration mediante XSS o MITM  
**Mitigación:**  
- Añadir `Secure; HttpOnly; SameSite=Strict` para cookies de autenticación  
- Limitar domain/path a lo absolutamente necesario  
- Revisar afectación en flujos SSO y widgets federados  
```

---

## Mejores Prácticas y Mitigación

1. **Siempre** usar `Secure; HttpOnly; SameSite=Strict` por defecto para sesiones y tokens.
2. **Evaluar excepciones:** para OAuth, integrar control de flujo y expiración corta en cookies SameSite=None.
3. **Limitar scope domain/path:** a un subdominio y ruta específicos.
4. **Segmentar cookies:** separar autenticación, tracking, preferencias, CSRF.
5. **Auditoría continua:** en CI/CD y producción.

---


La gestión de cookies y SameSite es la base de toda seguridad web moderna. Una pequeña omisión puede permitir ataques críticos que pasan por alto controles más sofisticados. Audita, revisa y automatiza la configuración de cookies en todos los endpoints y servicios expuestos.

<div style="text-align: center">⁂</div>


[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
