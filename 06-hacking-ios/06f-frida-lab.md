# Laboratorio de Hooking con Frida

## Resumen

**Qué es:** Frida es un framework de instrumentación dinámica que permite inyectar JavaScript en procesos en vivo para interceptar, manipular y analizar funciones, clases y flujos de datos en aplicaciones iOS.
**Por qué importa:** Facilita el bypass de protecciones client-side, extracción de datos sensibles, análisis de lógica de negocio oculta y desarrollo de exploits sin necesidad de recompilar la aplicación objetivo.
**Cuándo aplicarlo:** Fundamental en pentesting iOS, análisis de malware, reverse engineering, bypass de jailbreak detection y validación de controles de seguridad en apps nativas.

---

## Contexto

**Supuestos:**

- Dispositivo iOS con jailbreak o simulador de iOS.
- Frida instalado tanto en el dispositivo como en el host de desarrollo.
- App objetivo instalada y ejecutándose.
- Conocimientos básicos de Objective-C/Swift y estructura de apps iOS.
- Herramientas: frida-tools, objection, Hopper/IDA Pro para análisis estático.

**Límites:**

- Requiere jailbreak para dispositivos físicos (o simulador para desarrollo).
- No cubre técnicas de bypass de anti-Frida ni protecciones avanzadas.

---

## Metodología

1. **Setup del entorno:**
   - Instalar Frida en el dispositivo iOS (`frida-server`).
   - Configurar herramientas cliente (`frida-tools`, `objection`).
   - Verificar conectividad entre host y dispositivo.
2. **Reconocimiento de la aplicación:**
   - Identificar procesos, clases y métodos objetivo.
   - Usar `frida-ps`, `objection explore` y análisis estático.
3. **Desarrollo de scripts de hooking:**
   - Interceptar métodos específicos (autenticación, validación, crypto).
   - Modificar parámetros, valores de retorno y flujo de ejecución.
   - Extraer datos sensibles y credenciales.
4. **Pruebas avanzadas:**
   - Bypass de SSL pinning, jailbreak detection.
   - Manipulación de funciones de seguridad y controles de acceso.
   - Análisis de comunicación con backends y APIs.
5. **Documentación y explotación:**
   - Crear PoCs reproducibles.
   - Desarrollar exploits automatizados.

**Checklist de verificación:**

- Frida conecta correctamente al proceso objetivo.
- Scripts de hooking ejecutan sin errores.
- Modificaciones tienen el efecto esperado en la app.
- Datos sensibles son extraíbles de forma confiable.
- Bypasses funcionan en diferentes versiones de la app.

---

## Pruebas Manuales

### 1. Setup básico y conexión

```bash
# En el dispositivo iOS (via SSH)
frida-server &

# En el host
frida-ps -U  # Listar procesos en dispositivo USB
frida -U -f com.example.app -l script.js  # Spawn e instrumentar app
```

### 2. Análisis básico con objection

```bash
objection -g "com.example.app" explore
ios info binary  # Información del binario
ios hooking list classes  # Listar clases disponibles
ios hooking search methods login  # Buscar métodos relacionados con login
```

### 3. Hook básico de método

```javascript
// script.js - Hook método de login
Java.perform(function() {
    var LoginViewController = ObjC.classes.LoginViewController;
  
    LoginViewController["- validateCredentials:password:"].implementation = function(username, password) {
        console.log("[+] validateCredentials llamado:");
        console.log("    Username: " + username);
        console.log("    Password: " + password);
    
        // Llamar al método original
        var result = this["- validateCredentials:password:"](username, password);
        console.log("    Resultado original: " + result);
    
        // Forzar resultado exitoso
        return true;
    };
});
```

### 4. Bypass de SSL Pinning

```javascript
// ssl-bypass.js
var NSURLSession = ObjC.classes.NSURLSession;
var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

NSURLSessionConfiguration["+ defaultSessionConfiguration"].implementation = function() {
    var config = this["+ defaultSessionConfiguration"]();
    config.setTLSMinimumSupportedProtocol_(0);
    config.setTLSMaximumSupportedProtocol_(999);
    return config;
};

// También hook NSURLConnection
var NSURLConnection = ObjC.classes.NSURLConnection;
NSURLConnection["+ canHandleRequest:"].implementation = function(request) {
    console.log("[+] NSURLConnection canHandleRequest: " + request.URL().absoluteString());
    return true;
};
```

### 5. Hook de funciones criptográficas

```javascript
// crypto-hook.js - Interceptar operaciones de cifrado
var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");

Interceptor.attach(CCCrypt, {
    onEnter: function(args) {
        console.log("[+] CCCrypt llamado:");
        console.log("    Operación: " + args[0]);
        console.log("    Algoritmo: " + args[1]);
        console.log("    Opciones: " + args[2]);
    
        // Capturar clave
        var keyLength = args[4];
        var key = Memory.readByteArray(args[3], keyLength.toInt32());
        console.log("    Clave: " + hexdump(key));
    },
  
    onLeave: function(retval) {
        console.log("    Resultado: " + retval);
    }
});
```

---

## PoC Automatizada

### Script completo de análisis

```javascript
// comprehensive-hook.js
console.log("[+] Iniciando análisis comprehensivo...");

// 1. Enumerar clases cargadas
ObjC.enumerateLoadedClasses({
    onMatch: function(className) {
        if (className.toLowerCase().indexOf("login") !== -1 ||
            className.toLowerCase().indexOf("auth") !== -1) {
            console.log("[+] Clase interesante encontrada: " + className);
        }
    },
    onComplete: function() {}
});

// 2. Hook automático de métodos sospechosos
function hookSecurityMethods() {
    var suspiciousMethods = [
        "isJailbroken",
        "isDebugged", 
        "validateSignature",
        "checkIntegrity"
    ];
  
    suspiciousMethods.forEach(function(methodName) {
        var classes = ObjC.classes;
        Object.keys(classes).forEach(function(className) {
            try {
                var cls = classes[className];
                var methods = cls.$ownMethods;
            
                methods.forEach(function(method) {
                    if (method.toLowerCase().indexOf(methodName.toLowerCase()) !== -1) {
                        console.log("[+] Hooking: " + className + "." + method);
                    
                        cls[method].implementation = function() {
                            console.log("[!] " + method + " interceptado - retornando false");
                            return false;  // Bypass security check
                        };
                    }
                });
            } catch(e) {}
        });
    });
}

setTimeout(hookSecurityMethods, 1000);

// 3. Monitor network calls
var NSURLRequest = ObjC.classes.NSURLRequest;
NSURLRequest["- URL"].implementation = function() {
    var url = this["- URL"]();
    console.log("[+] Network request: " + url.absoluteString());
    return url;
};
```

### Automatización con Python

```python
#!/usr/bin/env python3
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(f"[!] Error: {message}")

def main():
    device = frida.get_usb_device()
  
    # Cargar script de hooking
    with open('comprehensive-hook.js', 'r') as f:
        script_content = f.read()
  
    try:
        # Attach al proceso o spawn la app
        session = device.attach("com.example.app")
        script = session.create_script(script_content)
        script.on('message', on_message)
        script.load()
    
        print("[+] Script cargado. Presiona Ctrl+C para salir...")
        sys.stdin.read()
    
    except KeyboardInterrupt:
        print("\n[+] Finalizando...")
        session.detach()

if __name__ == "__main__":
    main()
```

---

## Explotación y Automatización

### Bypass automatizado de protecciones

```javascript
// auto-bypass.js
function bypassJailbreakDetection() {
    // Hook file system checks
    var NSFileManager = ObjC.classes.NSFileManager;
    NSFileManager["- fileExistsAtPath:"].implementation = function(path) {
        var jailbreakPaths = ["/usr/sbin/sshd", "/bin/bash", "/Applications/Cydia.app"];
        if (jailbreakPaths.some(jbPath => path.toString().indexOf(jbPath) !== -1)) {
            console.log("[!] Jailbreak path blocked: " + path);
            return false;
        }
        return this["- fileExistsAtPath:"](path);
    };
  
    // Hook fork/exec
    var libc = Module.findExportByName("libSystem.B.dylib", "fork");
    Interceptor.replace(libc, new NativeCallback(function() {
        console.log("[!] fork() blocked");
        return -1;
    }, 'int', []));
}

function extractCredentials() {
    // Hook keychain operations
    var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            console.log("[+] Keychain access detected");
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) {
                console.log("[+] Keychain data retrieved successfully");
            }
        }
    });
}

bypassJailbreakDetection();
extractCredentials();
```

---

## Impacto

- **Bypass completo de protecciones client-side:** Jailbreak detection, SSL pinning, anti-debugging.
- **Extracción de datos sensibles:** Credenciales, tokens, claves criptográficas.
- **Manipulación de lógica de negocio:** Bypass de validaciones, modificación de flujos.
- **Análisis profundo:** Comprensión completa de funcionamiento interno de la app.

**Mapeo OWASP:** M10 Extraneous Functionality, M4 Insecure Authentication, M2 Insecure Data Storage.

---

## Detección

- Monitoreo de procesos sospechosos (`frida-server`).
- Detección de comportamientos anómalos en la app.
- Análisis de patrones de tráfico de red modificados.
- Validación de integridad del binario en runtime.

---

## Mitigación

- Implementar anti-Frida protections y obfuscación.
- Validaciones server-side para todos los controles críticos.
- Certificate pinning robusto con múltiples capas.
- Runtime Application Self-Protection (RASP).
- Detección de instrumentación y terminación de la app.

---

## Errores Comunes

- No verificar que el script se carga correctamente.
- Hook de métodos incorrectos o inexistentes.
- No manejar excepciones en los hooks.
- Asumir que los bypasses funcionan en todas las versiones.
- No limpiar recursos al finalizar la instrumentación.

---

## Reporte

**Título:** Instrumentación con Frida permite bypass completo de protecciones y extracción de datos sensibles
**Impacto:** Compromiso total de la seguridad client-side, acceso a credenciales y manipulación de lógica
**Pasos:**

1. Conectar Frida al proceso de la aplicación
2. Inyectar scripts de hooking para bypass de protecciones
3. Extraer datos sensibles y manipular flujo de ejecución
4. Demostrar acceso no autorizado a funcionalidades
   **Evidencias:** Scripts de hooking funcionales, logs de extracción de datos, screenshots de bypasses
   **Mitigación:** Implementar controles server-side, anti-tampering y validación de integridad continua
