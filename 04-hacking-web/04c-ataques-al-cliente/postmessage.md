# PostMessage –  Comunicación Cross-Origin

## Resumen

`window.postMessage()` es el método estándar y seguro para la comunicación entre diferentes ventanas, iframes o workers de orígenes distintos en el navegador. Su uso es fundamental en aplicaciones web modernas, pero una implementación deficiente puede comprometer completamente la seguridad del usuario y del sistema[^2]. Errores en la validación de origen, en el tratamiento de los datos recibidos y en el valor de `targetOrigin` han generado vulnerabilidades críticas en grandes plataformas tecnológicas.

## Fundamentos de postMessage y iframes

### ¿Qué es un iframe?

Un iframe permite incrustar contenido de otro documento y origen en la página actual, aislando contextos por Same-Origin Policy (SOP):[^3]

```html
<iframe src="https://victima.com/content.html" id="miFrame"></iframe>
```

Los iframes son esenciales para integrar pagos, chat, publicidad o contenido embebido de terceros, pero aumentan la superficie de ataque.

### ¿Qué es window.postMessage()?

Permite enviar mensajes cross-origin entre ventanas o iframes:

#### Sintaxis de Envío:

```javascript
targetWindow.postMessage(message, targetOrigin, [transfer]);
```

- `targetWindow`: objeto Window al que se envía el mensaje.
- `message`: datos a transferir (clonables estructuralmente).
- `targetOrigin`: origen exacto esperado (no usar '*', salvo si la información es pública).
- `[transfer]`: objetos transferibles opcionales.

#### Recepción:

```javascript
window.addEventListener("message", (event) => {
  // SIEMPRE validar event.origin
  if (event.origin !== "https://origen-esperado.com") return;
  // Procesar data de forma segura
});
```

- **Origen**: defined by protocolo, dominio y puerto.[^4]
- SIEMPRE validar origen y estructura de datos antes de usar la información recibida.

## Ejemplos de Comunicación Cross-Origin

### Desde iframe al padre:

**iframe (`iframe-origin.com`):**

```javascript
window.parent.postMessage({info: "Hola desde el iframe!"}, "https://victima.com");
```

**Padre (`victima.com`):**

```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "https://iframe-origin.com") return;
  // Procesar mensaje
});
```

### Desde padre al iframe:

```javascript
const iframeWin = document.getElementById('frame').contentWindow;
iframeWin.postMessage({ comando: 'ACTUALIZAR', valor: 'Nuevos datos' }, 'https://iframe-destino.com');
```

---

## Vulnerabilidades Críticas

### Falta de validación de origen

Enviar mensajes sin especificar el `targetOrigin` concreto:

```javascript
iframe.postMessage(mensaje, '*');
```

Recibir mensajes y procesar datos sin validar `event.origin`:

```javascript
window.addEventListener("message", (event) => {
  // FALTA validación de event.origin
  process(event.data);
});
```

### Uso de sinks peligrosos (sink XSS)

- Inserción directa de `event.data` en `innerHTML`, `eval`, `document.write`, `setAttribute` con valores interpretados como URI/JS.
- Ejemplo vulnerable:

```javascript
element.innerHTML = event.data.html; // PELIGROSO
```

### Validaciones incorrectas[^4]

- Uso de `startsWith`, `includes`, `endsWith`, regexes sin anclaje.
- Un atacante puede usar subdominios, encoding o dominios parecidos para evadir controles triviales.

---

## Técnicas y PoCs de Explotación

### XSS por postMessage sin validación de origen

```html
<iframe src="https://vulnerable-frame.com/content" id="frame"></iframe>
<script>
const iframe = document.getElementById('frame').contentWindow;
iframe.postMessage({tipo: "htmlDinamico", contenido: "<img src=x onerror=alert(1)>"}, "*");
</script>
```

### Robo de tokens OAuth/autenticación

En aplicaciones con autenticación delegada, enviar tokens por postMessage sin validar origen permite que cualquier origin escuche el mensaje y robe el token:[^6]

```javascript
// Ejemplo vulnerable:
window.postMessage({accessToken: token}, "*");
```

### Window Name Hijacking[^5]

Si las ventanas tienen nombre predecible o controlado, otro sitio puede tomar ese nombre y robar postMessages enviados al nombre confiable.

---

## Casos Reales

- **Microsoft Teams y Bing:** Vulnerabilidades postMessage permitieron robo de sesión/OAuth, XSS, escalada de privilegios y bounties de alto impacto.[^1]
- **Zoho, SaaS, banking:** Widgets de terceros donde event.origin no fue validado, generando XSS y filtrado de datos críticos.[^7]

---

## Metodología de Descubrimiento

1. **Buscar emisores y listeners:**
   - `window.postMessage`, `window.addEventListener('message', ...)`, jQuery `.on('message', ...)`
   - Revisar si se usa `'*'` o strings muy amplias como `targetOrigin`
2. **Analizar validación de origen:**
   - Validación directa, lista blanca, regexes estrictos
3. **Inspeccionar uso de event.data:**
   - Se usa en sinks peligrosos? JSON.parse antes de procesar?
   - Policy de CSP protege los sinks?
4. **Probando payloads personalizados:**
   - Inyectar mensajes desde iframes/ventanas controladas por el atacante
   - Probar subdominios y variantes de encoding en `event.origin`

---

## Técnicas de Mitigación

### Emitiendo mensajes (postMessage)

- Establecer SIEMPRE un targetOrigin específico, NUNCA usar '*', salvo que el dato sea público.
- No enviar información sensible por postMessage sin cifrado ni handshake.

### Recibiendo mensajes

- Validar `event.origin` contra una lista blanca estricta (array de strings exactos/locales, nunca substring).
- Validar la ESTRUCTURA de los datos recibidos (type, payload esperado).
- Sanitizar SIEMPRE cualquier dato que vaya a un sink de DOM (usar DOMPurify o asignar `textContent`).
- Reforzar protección con CSP.

### Ejemplo seguro:

```javascript
window.addEventListener("message", (event) => {
  const TRUSTED = ["https://trusted.com"];
  if (!TRUSTED.includes(event.origin)) return;
  if (!event.data || typeof event.data.type !== "string") return;
  // Procesar SOLO tipos de mensaje esperados
});
```

### Otras protecciones

- **iframe sandboxing:**

```html
<iframe src="..." sandbox="allow-scripts allow-same-origin"></iframe>
```

- **CSP restrictiva:**
  `Content-Security-Policy: default-src 'self'; frame-src 'self' https://trusted.com`
- **Limitar window.name y evitar nombres predecibles**

---

## Testing y Herramientas

- **Burp Suite DOM Invader:** pruebas automáticas de postMessage sinks/flows
- **PMHook, Posta:** extensiones de navegador para interceptar y manipular postMessages.
- **Testing manual con DevTools:** enviando mensajes manualmente a frames abiertos.

---

## Reporte

**Título:** Falta de Validación en Comunicación Cross-Origin via postMessage
**Resumen:** Un atacante puede enviar o recibir mensajes maliciosos e inyectar código arbitrario o robar datos sensibles debido a falta de validación estricta de origen y datos en listeners postMessage.
**PoC:**

1. Controlar un frame/ventana secundaria o engañar al emisor.
2. Enviar payload XSS o escuchar tokens de autenticación.
3. Obtener ejecución/arbitrar datos del usuario objetivo.

**Mitigación:** Validar SIEMPRE `event.origin`, lista blanca, estructura rígida de mensaje, evitar send/receive de datos sensibles sin handshake/clave, CSP restrictiva y sandbox en iframes.

[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
    
[^3]: https://infosecwriteups.com/️-hunting-idor-a-deep-dive-into-insecure-direct-object-references-b550a9f77333
    
[^4]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
    
[^5]: https://limpiatuweb.com/blog/referencias-de-objetos-directos-inseguras-idor/
    
[^6]: https://www.legitsecurity.com/aspm-knowledge-base/insecure-direct-object-references/
    
[^7]: https://spyboy.blog/2024/09/19/idor-vulnerabilities-finding-exploiting-and-securing/
    
[^8]: https://www.youtube.com/watch?v=jvDFiIyNW_o
    
[^9]: https://authenticone.com/idor-the-silent-gateway-to-data-breaches/
    
[^10]: https://osintteam.blog/understanding-cvss-scoring-with-a-real-world-idor-example-in-e-commerce-fbb885db932f
    
[^11]: https://github.com/AyemunHossain/IDORD
