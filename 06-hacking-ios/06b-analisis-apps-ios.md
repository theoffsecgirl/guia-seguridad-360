# Análisis de Apps iOS

El análisis de aplicaciones iOS es un proceso fundamental para identificar vulnerabilidades y evaluar la postura de seguridad de una app. Este análisis se divide en dos enfoques complementarios: **análisis estático** (sin ejecutar la aplicación) y **análisis dinámico** (durante la ejecución). Dominar ambos métodos es clave para un bug bounty hunter efectivo en iOS.

---

## Preparación del Entorno de Testing

### Requisitos del Sistema Host

- **macOS con privilegios administrativos** (preferible)
- **Xcode y Xcode Command Line Tools** instalados
- **Red Wi-Fi** que permita comunicación cliente-a-cliente
- **Herramientas de proxy** como Burp Suite, OWASP ZAP o Charles Proxy

### Dispositivos de Testing

- **Dispositivo iOS jailbreakeado** (recomendado para análisis completo)
- **iOS Simulator** (limitado, solo para pruebas básicas)
- **Emulador Corellium** (solución empresarial)

### Herramientas Esenciales

- **Estático**: `class-dump`, `otool`, `nm`, `strings`, IDA Pro, Ghidra, Hopper
- **Dinámico**: Frida, LLDB, Cycript, Objection
- **Frameworks**: MobSF, OWASP MASTG
- **Jailbreak**: checkra1n, unc0ver

---

## Análisis Estático de Apps iOS

El análisis estático examina el código y recursos de la aplicación sin ejecutarla, revelando información valiosa sobre su estructura interna.

### Extracción del Archivo IPA

Los archivos `.ipa` son esencialmente archivos ZIP que contienen el binario de la aplicación y sus recursos.

```bash
# Cambiar extensión y extraer
mv MyApp.ipa MyApp.zip
unzip MyApp.zip
cd Payload/MyApp.app/
```

### Análisis de la Estructura del Binario

**Verificar información básica del binario:**

```bash
file MyApp
# Output: MyApp: Mach-O 64-bit executable arm64
```

**Detectar si la app está encriptada (FairPlay DRM):**

```bash
otool -l MyApp | grep crypt
# cryptid 1 = encriptada, cryptid 0 = no encriptada
```

### Herramientas de Análisis Estático

#### class-dump

Extrae interfaces de clases Objective-C desde binarios Mach-O:

```bash
class-dump MyApp > classes.h
class-dump -H MyApp  # Genera archivos .h separados
```

#### otool

Herramienta versátil para examinar binarios Mach-O:

```bash
# Listar librerías vinculadas
otool -L MyApp

# Buscar funciones criptográficas débiles
otool -tv MyApp | grep -E "(MD5|SHA1|DES)"

# Analizar segmentos y secciones
otool -l MyApp
```

#### nm

Muestra símbolos del binario:

```bash
# Mostrar todos los símbolos
nm MyApp

# Buscar funciones específicas
nm MyApp | grep -i "password\|token\|secret"
```

#### strings

Extrae cadenas de texto del binario:

```bash
strings MyApp | grep -E "(api|key|password|token)"
```

### Análisis con MobSF

**Mobile Security Framework** automatiza gran parte del análisis estático:

1. **Instalación y ejecución:**

```bash
docker run -it --rm -p 8000:8000 opensecurity/mobsf:latest
```

2. **Subir archivo IPA** y ejecutar análisis automático
3. **Revisar resultados** buscando:
   - Esquemas URL inseguros
   - Configuraciones ATS incorrectas
   - Información sensible hardcodeada
   - Permisos excesivos

---

## Análisis Dinámico de Apps iOS

El análisis dinámico permite observar el comportamiento de la aplicación en tiempo real, interceptar comunicaciones y manipular la ejecución.

### Configuración en Dispositivo Jailbreakeado

**Instalar herramientas básicas via Cydia:**

```bash
# Repositorio necesario
http://apt.thebigboss.org/repofiles/cydia/

# Paquetes recomendados:
- OpenSSH
- Big Boss Recommended Tools (incluye otool)
- Darwin CC Tools
- Frida
```

### Análisis con Frida

Frida es la herramienta más potente para instrumentación dinámica:

**Instalación:**

```bash
pip install frida-tools
```

**Conexión al dispositivo:**

```bash
# Listar aplicaciones
frida-ps -U

# Conectar a una app específica
frida -U "App Name"
```

**Ejemplos de scripts Frida:**

**Bypass autenticación biométrica:**

```javascript
Java.perform(function() {
    var LAContext = ObjC.classes.LAContext;
    LAContext["- evaluatePolicy:localizedReason:reply:"].implementation = function(policy, reason, reply) {
        console.log("[+] Biometric authentication bypassed");
        var success = ObjC.classes.NSNumber.numberWithBool_(true);
        reply(success, null);
    };
});
```

**Interceptar llamadas de red:**

```javascript
var NSURLRequest = ObjC.classes.NSURLRequest;
var originalMethod = NSURLRequest["- initWithURL:"];
originalMethod.implementation = function(url) {
    console.log("[+] URL Request: " + url.toString());
    return originalMethod.call(this, url);
};
```

### Debugging con LLDB

Para análisis de bajo nivel y debugging:

```bash
# Conectar al proceso
debugserver *:2345 -a "MyApp"

# En el host
lldb
(lldb) process connect connect://device-ip:2345

# Establecer breakpoints
(lldb) b [ClassName methodName]
```

### Runtime Analysis con Cycript

Cycript permite manipulación en tiempo real:

```bash
# Conectar al proceso
cycript -p "MyApp"

# Acceder al objeto UIApplication
UIApplication.sharedApplication

# Explorar jerarquía de vistas
UIApp.keyWindow.recursiveDescription().toString()
```

---

## Análisis de Red y Comunicaciones

### Configuración de Proxy

**Instalar certificado Burp/ZAP:**

1. Configurar proxy en dispositivo iOS
2. Navegar a `http://burp` o dirección del proxy
3. Descargar e instalar certificado CA
4. Habilitar certificado en Configuración > General > Acerca de > Configuración de certificados

**Bypass certificate pinning con Frida:**

```javascript
// Script para deshabilitar SSL pinning
setTimeout(function() {
    Java.perform(function() {
        // Implementación específica según el framework usado
        var NSURLSession = ObjC.classes.NSURLSession;
        // ... código de bypass
    });
}, 1000);
```

---

## Inspección del Sandbox

En dispositivos jailbreakeados, puedes acceder directamente al sandbox de la app:

```bash
# Localizar directorio de la app
find /var/mobile/Containers/Data/Application/ -name "*AppName*"

# Buscar datos sensibles
find /path/to/app/sandbox -type f -exec grep -l "password\|token\|key" {} \;

# Examinar archivos plist
plutil -p app.plist

# Revisar UserDefaults
defaults read /path/to/app/Library/Preferences/com.company.app.plist
```

---

## Análisis Automatizado vs Manual

### Ventajas del Análisis Automatizado

- Rápido y eficiente para detección inicial
- Cubre vulnerabilidades conocidas sistemáticamente
- Genera informes estructurados

### Ventajas del Análisis Manual

- Mayor precisión en la detección
- Capacidad de encontrar vulnerabilidades lógicas complejas
- Análisis contextual detallado

### Flujo de Trabajo Recomendado

1. **Análisis automatizado inicial** con MobSF u OWASP MASTG
2. **Análisis estático manual** con class-dump, otool, strings
3. **Análisis dinámico** con Frida para validar hallazgos
4. **Testing de red** con proxies para comunicaciones
5. **Exploración del sandbox** para verificar almacenamiento seguro

---

## Casos de Uso Comunes

### Búsqueda de Credenciales Hardcodeadas

```bash
strings MyApp | grep -E "(api_key|secret|password|token)" > sensitive_strings.txt
```

### Detección de Librerías Vulnerables

```bash
otool -L MyApp | grep -v "/System/Library"
```

### Identificación de Funciones Criptográficas Débiles

```bash
nm MyApp | grep -E "(MD5|SHA1|DES|RC4)"
```

### Análisis de Entitlements

```bash
codesign -d --entitlements - MyApp
```

---

## Mejores Prácticas

- **Combina siempre análisis estático y dinámico** para obtener una visión completa
- **Usa dispositivos jailbreakeados** para análisis profundo cuando sea posible
- **Documenta todos los hallazgos** con evidencia reproducible
- **Verifica hallazgos automatizados** manualmente antes de reportar
- **Mantén actualizadas las herramientas** para detectar las últimas vulnerabilidades

El análisis efectivo de apps iOS requiere paciencia, metodología y uso combinado de múltiples herramientas. Esta base te permitirá identificar vulnerabilidades tanto obvias como sutiles en aplicaciones iOS.
