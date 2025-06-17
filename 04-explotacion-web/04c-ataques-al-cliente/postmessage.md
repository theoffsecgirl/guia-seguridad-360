# PostMessage

### ¿Qué es un `iframe`?

Un `iframe` (Inline Frame) es un elemento HTML que permite incrustar otro documento HTML (otra página web) dentro del documento HTML actual. La página embebida en el `iframe` puede ser de un origen completamente diferente al de la página que la aloja.

Esto crea una barrera natural debido a la Same-Origin Policy (SOP).

### ¿Qué es `window.postMessage`?

La API `window.postMessage()` proporciona un mecanismo para que objetos `Window` (como una página y un `iframe` embebido en ella, o dos ventanas/pestañas del navegador) puedan **comunicarse de forma segura entre sí incluso si provienen de orígenes diferentes**.

Antes de `postMessage`, intentar acceder al contenido de un `iframe` de un origen distinto (o viceversa) resultaría en un error de seguridad en la consola del navegador, como: `Uncaught DOMException: Blocked a frame with origin "http://origen-a.com" from accessing a cross-origin frame.`

**Componentes Clave de `postMessage` y la Comunicación Cross-Origin:**

- **Origen (Origin):** Se define por la combinación de:

  - Protocolo (e.g., `http`, `https`)
  - Dominio (e.g., `ejemplo.com`, `sub.ejemplo.com`)
  - Puerto (e.g., `80` para HTTP, `443` para HTTPS, `8080` para desarrollo) Si cualquiera de estos tres componentes difiere entre dos ventanas, se consideran de orígenes distintos.
- **Sintaxis de Envío (`targetWindow.postMessage`)**:
- ```javascript

  ```

targetWindow.postMessage(message, targetOrigin, [transfer]);

```

- `targetWindow`: Referencia al objeto `window` al que se enviará el mensaje (e.g., `iframeElement.contentWindow`, `window.parent`, `window.opener`, o una ventana abierta con `window.open`).
    - `message`: El dato a enviar. Puede ser cualquier objeto JavaScript que pueda ser clonado estructuralmente (strings, números, arrays, objetos simples, etc.).
    - `targetOrigin`: Especifica el origen que `targetWindow` debe tener para que el mensaje sea enviado. Es una medida de seguridad crucial.
        - Si se establece un URI específico (e.g., `"https://ejemplo-seguro.com"`), el mensaje solo se enviará si el `targetWindow` coincide con ese origen.
        - Si se establece `"*"` (wildcard), el mensaje se enviará sin importar el origen del `targetWindow`. **Esto es peligroso si el `message` contiene datos sensibles.**
    - `[transfer]` (Opcional): Una secuencia de objetos `Transferable` cuya propiedad se transfiere al destino.
- **Recepción de Mensajes (`window.addEventListener`)**:
   
    ```javascript
    window.addEventListener("message", receiveMessage, false);
  
    function receiveMessage(event) {
      // event.origin: El origen de la ventana que envió el mensaje. ¡SIEMPRE VALIDARLO!
      // event.source: Referencia al objeto window que envió el mensaje.
      // event.data: El objeto (mensaje) enviado por postMessage.
  
      // Ejemplo de validación de origen
      if (event.origin !== "https://origen-esperado.com") {
        console.warn("Mensaje recibido de origen no confiable:", event.origin);
        return; // No procesar el mensaje
      }
  
      // Procesar event.data de forma segura
      console.log("Mensaje recibido:", event.data);
    }
    ```
  
    **Seguridad en la Recepción:**
  
    1. **Siempre validar `event.origin`**: Asegurarse de que el mensaje proviene de un origen esperado y confiable.
    2. **Siempre validar y sanitizar `event.data`**: Tratar los datos recibidos como cualquier otra entrada de usuario no confiable. No usarlos directamente en funciones peligrosas (sinks) como `innerHTML`, `eval()`, etc.

### Ejemplo: Enviar Mensaje del `iframe` al Padre

**Código del `iframe` (e.g., `http://iframe-origin.com/pagina-iframe.html`):**

```html
<button id="btnSendMessage">Enviar Mensaje al Padre</button>
<script>
  document.getElementById("btnSendMessage").addEventListener("click", () => {
    const mensaje = { info: "Hola desde el iframe!" };
    // IMPORTANTE: Especificar el targetOrigin del padre para seguridad.
    // Usar '*' solo si el mensaje no es sensible y el padre puede ser cualquier página.
    window.parent.postMessage(mensaje, "https://parent-origin.com"); 
    // Si el padre estuviera en http://localhost:3000, sería:
    // window.parent.postMessage(mensaje, "http://localhost:3000");
  });
</script>
```

**Página Principal (Padre) (e.g., `https://parent-origin.com/pagina-principal.html`):**

```html
<iframe src="http://iframe-origin.com/pagina-iframe.html" id="miIframe"></iframe>
<div id="respuesta">Esperando mensaje...</div>
<script>
  window.addEventListener("message", (event) => {
    // 1. Validar el origen del mensaje
    if (event.origin !== "http://iframe-origin.com") {
      console.warn("Origen no permitido:", event.origin);
      return;
    }

    // 2. Opcional: Validar que la fuente sea el iframe esperado
    // if (event.source !== document.getElementById('miIframe').contentWindow) {
    //   console.warn("Fuente no esperada.");
    //   return;
    // }

    // 3. Procesar los datos de forma segura
    console.log("Datos recibidos del iframe:", event.data);
    document.getElementById("respuesta").textContent = "Mensaje del iframe: " + JSON.stringify(event.data);
  });
</script>
```

### Ejemplo: Enviar Mensaje del Padre al `iframe`

**Página Principal (Padre):**

```html
<button id="btnEnviarAIframe">Enviar a Iframe</button>
<iframe src="https://iframe-target.com/receptor.html" id="frameReceptor"></iframe>

<script>
document.getElementById("btnEnviarAIframe").addEventListener("click", () => {
  const iframeWindow = document.getElementById('frameReceptor').contentWindow;
  if (iframeWindow) {
    const mensaje = { comando: 'ACTUALIZAR_DATOS', valor: 'Nuevos datos desde el padre' };
    // IMPORTANTE: Especificar el targetOrigin del iframe.
    iframeWindow.postMessage(mensaje, 'https://iframe-target.com');
  }
});
</script>
```

**Página del `iframe` (Receptor):**

```html
<div id="mensajeRecibido">Esperando mensaje del padre...</div>
<script>
  window.addEventListener("message", (event) => {
    // 1. Validar origen del padre
    if (event.origin !== "https://parent-origin.com") { // Asumiendo que el padre está en parent-origin.com
      console.warn("Origen del padre no permitido:", event.origin);
      return;
    }

    // 2. Procesar datos de forma segura
    console.log("Datos recibidos del padre:", event.data);
    if (event.data && event.data.hasOwnProperty('comando')) {
      document.getElementById("mensajeRecibido").textContent = 
        `Comando: ${event.data.comando}, Valor: ${event.data.valor}`;
    }
  });
</script>
```

### Explotando `postMessage` para XSS (Cross-Site Scripting)

Una vulnerabilidad `postMessage` ocurre cuando un receptor (listener) no valida correctamente el `event.origin` y/o procesa el `event.data` de forma insegura.

**Escenario Vulnerable:**

**Página Principal (Padre) (e.g., `https://vulnerable-parent.com`):**

```html
<iframe src="https://vulnerable-iframe.com/iframe_content.html" id="frame"></iframe><br>
<input type="text" id="msgInput" value="<img src=x onerror=alert('XSS en iframe desde el padre')>">
<button id="btnRun">Enviar al Iframe</button>
<script>
document.getElementById("btnRun").addEventListener("click", () => {
  const iframe = document.getElementById('frame').contentWindow;
  const mensaje = { tipo: 'htmlDinamico', contenido: document.getElementById('msgInput').value };
  // VULNERABILIDAD EN EL EMISOR: Usa targetOrigin = '*'
  // Si vulnerable-iframe.com fuera secuestrado o el iframe se redirigiera, se enviaría info a un sitio malicioso.
  iframe.postMessage(mensaje, '*'); 
});
</script>
```

**`iframe` Vulnerable (e.g., `https://vulnerable-iframe.com/iframe_content.html`):**

```html
<div id="messageContainer">Contenido inicial</div>
<script>
  window.addEventListener("message", (event) => {
    // VULNERABILIDAD EN EL RECEPTOR (Falta de validación de event.origin):
    // Acepta mensajes de cualquier origen.
    // if (event.origin !== "https://vulnerable-parent.com") return; // ESTA VALIDACIÓN FALTA

    // VULNERABILIDAD EN EL RECEPTOR (Uso inseguro de event.data):
    // Inserta HTML directamente desde event.data sin sanitizar.
    if (event.data && event.data.tipo === 'htmlDinamico') {
      document.getElementById('messageContainer').innerHTML = event.data.contenido; // SINK PELIGROSO
    }
  });
</script>
```

**Explotación:**

1. Un atacante crea su propia página (`https://attacker.com/exploit.html`) que embebe el `iframe` vulnerable:

```html
 <iframe src="https://vulnerable-iframe.com/iframe_content.html" id="targetIframe"></iframe>
  <script>
  window.onload = () => {
  const iframeWin = document.getElementById('targetIframe').contentWindow;
   const xssPayload = "<img src=x onerror=alert('XSS en iframe por attacker.com: ' + document.domain)>";
  const maliciousMessage = { tipo: 'htmlDinamico', contenido: xssPayload };

 // El atacante envía el mensaje malicioso. Como el iframe no valida event.origin, lo acepta.
 iframeWin.postMessage(maliciousMessage, "https://vulnerable-iframe.com"); // targetOrigin es el del iframe
   };
 </script>
```

2. Cuando una víctima visita `https://attacker.com/exploit.html`, el script del atacante envía el payload XSS al `iframe` vulnerable.
3. El `iframe` recibe el mensaje, no valida el origen (`attacker.com`), y usa `innerHTML` para insertar el payload, ejecutando el XSS en el contexto de `vulnerable-iframe.com`.

**Otros Sinks Peligrosos para `event.data`:**

- `document.write(event.data.html)`
- `element.setAttribute("href", event.data.url)` (si `event.data.url` es `javascript:...`)
- `eval(event.data.codigoJs)`
- `new Function(event.data.codigoJs)()`
- Pasar `event.data` a librerías que dinámicamente crean HTML (e.g., jQuery `$(...).html(event.data)`).

### Problemas Comunes en la Validación de Origen

Incluso cuando los desarrolladores intentan validar `event.origin`, pueden cometer errores:

1. **No Validar en Absoluto:** Aceptar mensajes de cualquier origen (como en el ejemplo anterior).
2. **Uso Incorrecto de `startsWith`, `endsWith`, o `includes` (`indexOf`):**
   - `if (event.origin.startsWith("https://confiable.com"))`
     - Bypass: `https://confiable.com.atacante.com` (el atacante crea este dominio).
   - `if (event.origin.endsWith(".confiable.com"))`
     - Bypass: `https://cualquiercosa.confiable.com` (si el atacante puede controlar/registrar un subdominio) o `https://otrodominio.confiable.com.atacante.com`.
   - `if (event.origin.includes("confiable.com"))`
     - Bypass: `https://atacante-confiable.com.net`
3. **Expresiones Regulares (RegEx) Débiles o Mal Formadas:**
   - Ejemplo del usuario: `if (/(http:|https:)\/\/([a-z0-9.]{1,}).ctfio.com/.test(event.origin)) {}`
     - Problema: Falta el anclaje de fin de string (`$`). La regex busca que el origen _contenga_ un subdominio de `.ctfio.com`, pero no que _termine_ exactamente ahí.
     - Bypass: `http://sub.ctfio.com.atacante.com` (coincide con la regex porque "https://www.google.com/search?q=sub.ctfio.com" está presente).
     - Regex más segura: `if (/^https?:\/\/([a-z0-9-]+\.)*ctfio\.com$/i.test(event.origin)) {}` (con anclajes `^` y `$`, y `i` para case-insensitive si es necesario).
4. **Validación de Esquema o Puerto Incorrecta:**
   - Olvidar validar el protocolo (permitiendo `http` cuando solo se espera `https`) o el puerto.
5. **Confiar en `event.source` sin validar `event.origin`:** `event.source` puede ser útil para verificar si el mensaje proviene de un iframe específico que la página padre creó, pero `event.origin` sigue siendo la principal fuente de verdad para la seguridad del origen.

### Otros Escenarios de Explotación

- **Robo de Mensajes Sensibles:** Si una ventana padre escucha mensajes y actualiza su DOM o estado, pero no valida `event.origin` correctamente, un iframe malicioso podría enviar mensajes falsos. O, si una ventana hija envía datos sensibles al padre usando `targetOrigin = '*'`, una página padre maliciosa (o una página padre comprometida) podría interceptarlos.
- **Disparar Acciones No Deseadas:** Si el manejador de mensajes (`message handler`) realiza acciones privilegiadas o modifica el estado de la aplicación basándose en el `event.data` sin validar suficientemente el origen y los datos.
- **Clickjacking con `postMessage`:** Un atacante podría usar un iframe invisible sobre una página de la víctima y, mediante `postMessage`, enviar información sobre la interacción del usuario (como coordenadas del ratón) a un iframe malicioso de origen diferente para realizar acciones no deseadas.

### Metodología de Descubrimiento y Testeo

1. **Identificar Uso de `postMessage`:**
   - Buscar en el código JavaScript (frontend):
     - `window.addEventListener("message", ...)` o `$(window).on("message", ...)` (para listeners).
     - `targetWindow.postMessage(...)` (para emisores).
2. **Analizar los Listeners (`addEventListener("message", handlerFunction)`):**
   - **¿Se valida `event.origin`?** ¿Cómo? ¿Es la validación robusta?
   - **¿Se valida `event.source`?** (Menos común, pero puede ser relevante).
   - **¿Qué se hace con `event.data`?** ¿Se pasa a sinks peligrosos (`innerHTML`, `eval`, `document.write`, `setAttribute` con `javascript:`, etc.)? ¿Se usa para tomar decisiones de lógica de negocio?
3. **Analizar los Emisores (`postMessage(message, targetOrigin)`):**
   - **¿Se usa `targetOrigin = '*'`?** Si es así, ¿es el `message` sensible? Si lo es, esto es una fuga de información si la ventana receptora puede ser controlada por un atacante (e.g., si el `src` de un iframe es controlable).
   - ¿Es el `targetOrigin` específico y correcto?
4. **Pruebas Dinámicas con Herramientas de Desarrollador del Navegador:**
   - **Consola:** Puedes seleccionar un iframe (`document.getElementById('miIframe').contentWindow`) y enviarle mensajes de prueba:

```javascript
  // Desde la consola del padre, enviar al iframe:
   let iframeWin = document.getElementById('miIframe').contentWindow;
iframeWin.postMessage({test: "hola iframe"}, "https://origen-del-iframe.com");
   
  // Desde la consola del iframe, enviar al padre:
  window.parent.postMessage({test: "hola padre"}, "https://origen-del-padre.com");
```

- **pestaña "Sources" (Fuentes):** Poner breakpoints dentro de los manejadores de eventos `message` para inspeccionar `event.origin`, `event.source`, y `event.data` en tiempo real.

5. **Uso de Extensiones de Navegador o Proxies:**
   - Extensiones como "Posta" (Chrome) o "PMHook" (integrable con Burp) pueden ayudar a interceptar, visualizar y modificar mensajes `postMessage`.

### Buenas Prácticas y Mitigaciones

**Para el Emisor (quien llama a `postMessage`):**

1. **Siempre especificar un `targetOrigin` lo más preciso posible.** Evitar `"*"` si el mensaje contiene cualquier información sensible o si la acción que desencadena es privilegiada. Si el mensaje es verdaderamente público y no sensible, `"*"` puede ser aceptable, pero es mejor ser específico.

**Para el Receptor (quien escucha el evento `message`):**

1. **Validar `event.origin` rigurosamente:** Mantener una lista blanca de orígenes permitidos y comparar `event.origin` exactamente con esta lista. No usar `startsWith`, `endsWith`, o `includes` de forma laxa. Validar esquema, dominio y puerto.
2. **(Opcional) Validar `event.source`:** Si se espera un mensaje de un iframe específico que la página actual ha creado, se puede comparar `event.source` con `miIframeElement.contentWindow`. Esto añade una capa extra, pero la validación de `event.origin` es la principal.
3. **Tratar `event.data` como input no confiable:**
   - **No insertar HTML directamente:** Usar `element.textContent = event.data.texto` en lugar de `element.innerHTML = event.data.textoSiConfiaraEnEl`.
   - Si se debe insertar HTML, sanitizarlo usando una librería robusta y bien probada (e.g., DOMPurify).
   - Si se espera JSON, parsearlo de forma segura (e.g., `JSON.parse(event.data)` dentro de un try-catch) y luego validar la estructura y los tipos de datos del objeto resultante.
   - Nunca pasar `event.data` directamente a `eval()`, `new Function()`, `setTimeout("string")`, `setAttribute("href", "javascript:...")`, etc.
4. **Ser explícito sobre el formato del mensaje esperado:** Verificar que `event.data` tenga la estructura y los campos esperados (e.g., `if (event.data && event.data.type === 'accionEspecifica' && typeof event.data.payload === 'string') { ... }`).
