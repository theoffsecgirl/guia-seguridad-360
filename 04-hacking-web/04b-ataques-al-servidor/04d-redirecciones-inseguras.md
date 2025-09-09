# ¿Qué es una Redirección Web?

Una redirección web es un mecanismo que envía automáticamente a un usuario (y a su navegador) de una URL a otra URL diferente. Esto es una funcionalidad común y legítima.

- **Ejemplo Cotidiano:** Cuando inicias sesión en un servicio usando "Login con Google", después de autenticarte en Google, este te redirige de vuelta a la aplicación original.
- **Códigos de Estado HTTP Comunes para Redirecciones:**
  - `301 Moved Permanently`: La URL ha cambiado permanentemente.
  - `302 Found` (o `307 Temporary Redirect`): La URL ha cambiado temporalmente.
- **Métodos de Redirección:**
  - **Basada en Cabecera HTTP:** El servidor envía una cabecera `Location: nueva-url.com` con un código de estado 3xx.
  - **Basada en JavaScript:** El código del lado del cliente ejecuta `window.location.href = "nueva-url.com";` o similar.
  - **Basada en Meta Tags HTML:** `<meta http-equiv="refresh" content="0; url=http://nueva-url.com/">`

### ¿Qué es un Open Redirect (Redirección Abierta)?

Un Open Redirect es una vulnerabilidad que ocurre cuando una aplicación web redirige a un usuario a una URL externa que es controlada total o parcialmente por un atacante. La aplicación toma un parámetro suministrado por el usuario (en la URL o en el cuerpo de una petición) y lo usa como destino de la redirección sin una validación adecuada.

**Usos Maliciosos Principales:**

1. **Phishing:** Los atacantes usan un dominio de confianza (el vulnerable al Open Redirect) para redirigir a las víctimas a un sitio de phishing. La URL inicial parece legítima, aumentando la probabilidad de que la víctima confíe en ella.
   - Ej: `https://banco-confiable.com/redirect?url=http://sitio-phishing-del-atacante.com`
2. **Robo de Tokens (especialmente en flujos OAuth/OIDC):** Si un `redirect_uri` en un flujo de autenticación es vulnerable a Open Redirect, un atacante podría redirigir a la víctima (y su token de autorización o acceso) a un dominio controlado por él.
3. **Bypass de Listas Negras o Controles de Navegación:** Usar el dominio confiable como un "trampolín" para acceder a sitios que de otro modo estarían bloqueados.
4. **Facilitar otros ataques:** Como la entrega de payloads XSS o el intento de realizar SSRF si la redirección se procesa del lado del servidor de forma insegura.

**Ejemplo Básico de Parámetro Vulnerable:** La aplicación tiene un enlace o funcionalidad así: `https://sitio-vulnerable.com/login?redirect_url=/dashboard`

Un atacante podría intentar manipularlo: `https://sitio-vulnerable.com/login?redirect_url=https://sitio-atacante.com`

Si la aplicación no valida `redirect_url` correctamente, redirigirá al usuario al sitio del atacante después del login.

**Parámetros Comunes a Investigar para Open Redirects:** `url`, `r`, `u`, `redirect`, `redirect_uri`, `redirect_url`, `return`, `returnTo`, `return_to`, `next`, `goto`, `dest`, `destination`, `continue`, `path`, `target`, `image_url`, `checkout_url`, `feed_url`.

### Bypass de Restricciones y Validaciones

Las aplicaciones a menudo intentan restringir las redirecciones a dominios permitidos, pero estas validaciones pueden ser defectuosas.

1. **Abuso de Validación Débil de Nombres de Host/Dominio:**

   - **El servidor solo comprueba que el parámetro _contiene_ el dominio permitido:**
     - Política: Solo permitir redirecciones a `google.com`.
     - Payload Atacante: `?redirect=http://www.google.com.sitio-atacante.com`
     - La validación ingenua (`if param.includes("google.com")`) falla.
   - **El servidor solo comprueba que el parámetro _empieza con_ el dominio permitido:**
     - Política: Solo permitir `https://confiable.com`.
     - Payload Atacante: `?redirect=https://confiable.com.sitio-atacante.com`
   - **El servidor solo comprueba que el parámetro _termina con_ el dominio permitido:**
     - Política: Solo permitir `.confiable.com`.
     - Payload Atacante: `?redirect=https://sitio-atacante.com/pagina.confiable.com` (si la validación es muy pobre) o `?redirect=https://malicioso.confiable.com` (si el atacante puede controlar un subdominio o si la validación no es estricta sobre el punto).
   - **Uso del carácter `@` para engañar al usuario y a algunas validaciones:**
     - Payload: `?redirect=https://dominio-confiable.com@sitio-atacante.com`
     - El navegador interpretará `sitio-atacante.com` como el host real, y `dominio-confiable.com` como información de usuario (userinfo). La URL puede parecer legítima para el usuario.
2. **Manipulación de Esquemas y Protocolos:**

   - **URLs Relativas de Protocolo (`//`):**
     - Payload: `?redirect=//sitio-atacante.com`
     - Si la aplicación simplemente antepone `http:` o `https:` a esto, o si el navegador lo interpreta en un contexto que lo permite, se redirigirá al atacante. Útil si la validación busca `http://` o `https://` explícitamente al inicio.
   - **Esquema `javascript:` (conduce a XSS):**
     - Payload: `?redirect=javascript:alert(document.domain)`
     - Si el valor del redirect se usa directamente en un `href` de un `<a>` o en `window.location.href` sin sanitizar.
   - **Esquema `data:` (conduce a XSS):**
     - Payload: `?redirect=data:text/html,<script>alert(document.domain)</script>`
     - Menos común para redirects directos, pero puede ser un vector si el contenido se maneja de forma insegura.
3. **Manipulación de Rutas y Caracteres Especiales:**

   - **Carácter `#` (Fragmento):**
     - Payload: `?redirect=https://dominio-confiable.com/pagina#sitio-atacante.com` o `?redirect=https://dominio-confiable.com/pagina#//sitio-atacante.com`
     - El navegador irá a `dominio-confiable.com/pagina`. Sin embargo, si JavaScript en esa página usa `location.hash` de forma insegura para realizar una redirección del lado del cliente, puede ser explotable.
   - **Carácter `?` (Query):**
     - Payload: `?redirect=https://dominio-confiable.com?sitio-atacante.com`
     - Si la aplicación toma `dominio-confiable.com` como host y `?sitio-atacante.com` como la query string, pero luego reconstruye la URL de forma insegura o una validación falla.
   - **Path Traversal (`../`, `..%2F`):**
     - Payload: `?redirect=/otra-ruta/../../sitio-atacante.com/` (si la aplicación está construyendo rutas relativas y no normaliza bien).
   - **Codificación de URL (URL Encoding / Doble Encoding):**
     - Codificar caracteres como `.`, `/`, `:`, `#`, `?` para intentar saltar filtros.
     - Ej: `.` -> `%2E`, `/` -> `%2F`. `?redirect=http%3A%2F%2Fsitio-atacante%2Ecom`
   - **Punycode:** Usar dominios que se parecen a dominios legítimos usando caracteres Unicode (IDN Homograph Attack).
     - Ej: `google.com` vs `xn--ggle-0nda.com` (que podría parecer `gọogle.com`).
4. **Encadenamiento de Redirecciones (Chaining Redirects):**

   - A veces, un flujo de autenticación (como OAuth) implica múltiples redirecciones.
   - Ejemplo: `https://auth.sitio.com/auth?client_id=1&redirect_url=https://app.sitio.com/callback?url=PARAM_CONTROLABLE&response_type=token`
   - Si `PARAM_CONTROLABLE` en el segundo redirect es vulnerable a Open Redirect, un atacante podría secuestrar el flujo.
   - El token de sesión o autorización podría ser enviado al sitio del atacante si la redirección final controlada por el atacante lo recibe.
5. **Bypass de Validaciones con Expresiones Regulares (RegEx):**

   - Una RegEx mal implementada es una fuente común de bypass.
   - **Ejemplo 1: Falta de anclaje o delimitación estricta.**
     - RegEx: `/^https:\/\/confiable\.com\/.*$/` (valida el inicio, pero no el final de forma estricta antes de una posible query o fragmento).
     - Payload: `?redirect_url=https://confiable.com/x//sitio-atacante.com` (el `//` puede ser interpretado por el navegador como inicio de autoridad si la RegEx no es cuidadosa).
     - Payload: `?redirect_url=https://confiable.com%5C@sitio-atacante.com` (si `\` es un carácter permitido por la regex antes de `@`).
   - **Ejemplo 2: Demasiado permisiva con caracteres especiales.**
     - Ver el ejemplo del `@` arriba.

### Conexión: Open Redirect + XSS

Un Open Redirect a veces puede ser escalado a un Cross-Site Scripting (XSS) si el valor del parámetro de redirección se refleja en la página de una manera insegura antes de que la redirección ocurra, o si la redirección es a un esquema `javascript:`.

**Escenario 1: Reflejo en Atributo `href` (XSS por Atributo):**

- URL vulnerable: `https://sitio.com/aviso_salida?destino=https://externo.com`
- HTML generado en `aviso_salida` antes de una posible redirección por JS o si el usuario hace clic:

  ```html
  <p>Estás a punto de salir. ¿Continuar a <a href="https://externo.com">este sitio</a>?</p>
  ```
- **Explotación con XSS:**

  - Payload: `https://sitio.com/aviso_salida?destino=" onclick="alert('XSS Ejecutado')`
  - HTML resultante (vulnerable):

```html
 <p>Estás a punto de salir. ¿Continuar a <a href="" onclick="alert('XSS Ejecutado')">este sitio</a>?</p>
```

Al hacer clic en el enlace (que ahora tiene un `href` vacío), se ejecuta el `onclick`.

- Payload alternativo para auto-ejecución (si el `href` se procesa inmediatamente por JS): `https://sitio.com/aviso_salida?destino=javascript:alert('XSS Inmediato')` Resultado: `<a href="javascript:alert('XSS Inmediato')">este sitio</a>` (si se hace clic o si JS lo usa).

**Escenario 2: Redirección JavaScript con `javascript:` URI:**

- Código JavaScript vulnerable en el cliente:

```javascript
    const urlParams = new URLSearchParams(window.location.search);
    const redirectUrl = urlParams.get('next');
    if (redirectUrl) {
      window.location.href = redirectUrl; // Sink peligroso si redirectUrl no está validado
    }
    ```
  
- **Explotación con XSS:**
    - Payload: `https://sitio.com/pagina?next=javascript:alert(document.cookie)`
    - El script del cliente ejecutará `window.location.href = "javascript:alert(document.cookie)"`, disparando el XSS.

### Impacto Detallado de los Open Redirects

- **Phishing Avanzado:** La víctima ve una URL inicial de un sitio en el que confía.
- **Robo de Tokens de Sesión/OAuth:** Si la redirección pasa tokens en la URL (práctica insegura en sí misma) o si el atacante puede controlar el `redirect_uri` en un flujo OAuth para que apunte a su servidor.
- **Aumento de la Credibilidad de Estafas:** Usar un dominio conocido para redirigir a encuestas falsas, descargas de malware, etc.
- **Bypass de Controles de Seguridad Perimetrales:** Si un firewall o proxy permite el acceso a un dominio confiable, un Open Redirect en ese dominio puede usarse para redirigir al usuario a un sitio malicioso fuera del perímetro.
- **Facilitar Ataques SSRF (Server-Side Request Forgery):** En escenarios donde una aplicación interna realiza peticiones HTTP y confía en URLs que parecen seguras, si esa URL es un Open Redirect, podría usarse para hacer que el servidor haga peticiones a sistemas internos no deseados.

### Metodología de Testeo Sistemática

1. **Identificar Puntos de Entrada:** Busca parámetros en URLs (GET) y cuerpos de peticiones (POST) que parezcan controlar destinos de redirección (ver lista de parámetros comunes arriba).
2. **Prueba Básica:** Intenta redirigir a un dominio externo que controles (e.g., `https://tu-dominio-de-pruebas.com`).
3. **Analizar Respuesta:**
    - ¿Se produce una redirección HTTP 3xx con la cabecera `Location` apuntando a tu dominio?
    - ¿La página realiza una redirección mediante JavaScript (`window.location`) o meta tag? (Inspecciona el código fuente y el tráfico de red).
4. **Si hay Filtros, Intentar Bypasses:**
    - Prueba todas las técnicas listadas en la sección "Bypass de Restricciones". Sé sistemático.
    - Usa herramientas como Burp Suite Repeater para modificar rápidamente los payloads.
5. **Verificar Conexión con XSS:** Si el parámetro se refleja en la página antes de la redirección, o si la redirección es por JS, prueba payloads `javascript:`.
6. **Herramientas:**
    - **Manual con Burp Suite/ZAP:** Intercepta y modifica peticiones.
    - **Burp Intruder/Scanner:** Para fuzzing de parámetros y detección automática (limitada).
    - **Scripts personalizados:** Para probar listas de payloads contra múltiples parámetros.
    - Listas de payloads para Open Redirect (e.g., de SecLists en GitHub).

### Mitigaciones Clave

1. **Evitar Redirecciones Controladas por el Usuario:** Siempre que sea posible, no uses input del usuario directamente en destinos de redirección. En su lugar, usa un índice o mapeo interno: `?redirect_id=1` donde `1` mapea a `/dashboard_seguro`.
2. **Lista Blanca (Whitelist) de Dominios y URLs:**
    - Si se deben permitir redirecciones a URLs externas, mantener una lista blanca estricta de dominios/URLs permitidos y validar contra ella. La validación debe ser exacta (esquema, host, puerto, ruta si es necesario).
3. **Validación Estricta de URLs:**
    - Si se permite cualquier subdominio de un dominio, asegurarse de que la validación ancla correctamente el dominio base (e.g., no solo `endsWith(".confiable.com")`).
    - Parsear la URL en sus componentes (esquema, host, puerto, ruta) y validarlos individualmente.
4. **Notificación al Usuario (Interstitial Page):**
    - Antes de redirigir a un sitio externo, mostrar una página intermedia que advierta al usuario que está abandonando el sitio actual y muestre claramente la URL de destino.
5. **Tokens de Seguridad (si la redirección es parte de una acción crítica):** Aunque no previene el Open Redirect per se, puede evitar que la _acción_ asociada a la redirección sea explotada si el token es específico de esa acción.
```
