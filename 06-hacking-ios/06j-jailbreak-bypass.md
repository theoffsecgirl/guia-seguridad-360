# Jailbreak Detection Bypass

## Resumen

**Qué es:**
Bypass de Jailbreak Detection es el conjunto de técnicas y herramientas para neutralizar los mecanismos que las apps iOS usan para identificar si se ejecutan en un dispositivo liberado (jailbroken), permitiendo eludir restricciones, manipular lógica de seguridad y habilitar análisis dinámicos en pentesting/bug bounty.

**Por qué importa:**
Muchas apps bloquean funciones críticas, acceso o ejecución completa en entornos jailbroken. Bypassear estos controles es clave para auditar, examinar y explotar aplicaciones en profundidad.

**Cuándo aplicarlo:**
En pentesting, análisis forense, debugging avanzado, ingeniería inversa, validación de protecciones y análisis anti-fraude o malware.

---

## Contexto

**Supuestos:**

- Acceso a dispositivo jailbroken o emulador/simulador avanzado.
- App implementando controles de jailbreak detection estándar o avanzados.
- Herramientas: Frida, objection, lldb, Cycript, Flex, SSL Kill Switch, tweaks (Liberty Lite, tsProtector), Hopper/Class-dump para análisis estático.

**Límites:**

- No cubre mecanismos kernel-level o hardware (Secure Enclave).
- Algunas técnicas requieren acceso root o tweak avanzado.

---

## Metodología

1. **Reconocimiento y mapeo del control**
   - Identifica llamadas/ficheros API típicos de detección (chequeo de banderas, paths /bin/bash, Cydia, etc).
   - Busca métodos como: `isJailbroken`, `jailbreakCheck`, `fileExistsAtPath:`.
   - Usa Hopper, class-dump, Frida introspection, o Cycript para ubicar rutas.
2. **Bypass dinámico (Frida/objection)**
   - Hookear métodos sospechosos para forzar retorno benigno.
   - Interceptar calls a NSFileManager, open, stat, fork, getenv.
   - Modificar el resultado (false, nil, -1, etc).
3. **Parcheo estático**
   - Patch binario (strings “jailbreak”, rutas, comparaciones).
   - Flex patches: sobrescribir retorno de métodos de detección.
   - Uso de tweaks: Liberty Lite, tsProtector modifican system-wide.
4. **Obfuscación y anti-detección**
   - Esconder valores esperados (renombrar Cydia.app, camuflar procesos).
   - Borrar rutas o binarios sensibles (o simular fallo de acceso).
   - Spoofear llamadas a la system API.

---

## Pruebas Manuales

### 1. Frida simple (hook método de check)

```javascript
ObjC.enumerateLoadedClasses({
  onMatch: function(className) {
    if (className.toLowerCase().indexOf("jailbreak") !== -1) {
      console.log("[+] Clase posible:", className);
    }
  },
  onComplete: function() {}
});

var clase = ObjC.classes.<ClaseJailbreak>;
clase["- isJailbroken"].implementation = function() {
  console.log("[!] Jailbreak detection interceptada, devolviendo false");
  return 0; // NO jailbroken
};
```

### 2. Hook NSEFileManager y fork

```javascript
var NSFileManager = ObjC.classes.NSFileManager;
NSFileManager["- fileExistsAtPath:"].implementation = function(path) {
  var jb = ["/Applications/Cydia.app","/bin/bash","/usr/sbin/sshd"];
  if (jb.some(x=>path.toString().indexOf(x)!=-1)) { return false; }
  return this["- fileExistsAtPath:"](path);
};

var fork = Module.findExportByName("libSystem.B.dylib", "fork");
Interceptor.replace(fork, new NativeCallback(function() { return -1; }, 'int', []));
```

### 3. objection

```bash
objection -g com.example.app explore
ios jailbreak disable
```

### 4. Parche binario (Hopper/lldb)

- Buscar cadenas/restantes y cambiar comparaciones/returns por zeros.
- Usar “nop”/patching en ARM64 para saltar checks.

### 5. Tweaks de Cydia

- Instala Liberty Lite, tsProtector.
- Añade la app objetivo a la whitelist.

---

## PoC Automatizada

**Script de Frida universal:**

```javascript
// Bypass de llamadas comunes para detección jailbreak
function patchJailbreakChecks() {
  var checks = [
    "isJailbroken", "jailbreakCheck", "isDeviceJailbroken",
    "cydiaPath", "fileExistsAtPath:", "canOpenURL:",
    "fork", "stat", "open"
  ];
  for (var c in ObjC.classes) {
    for (var m in ObjC.classes[c].$ownMethods) {
      var method = ObjC.classes[c].$ownMethods[m];
      checks.forEach(function(check){
        if (method.indexOf(check)!=-1) {
          try {
            ObjC.classes[c][method].implementation = function(){ return 0; }
            console.log("Bypassed:", c, method);
          } catch(e){}
        }
      });
    }
  }
}
patchJailbreakChecks();
```

---

## Explotación y Automatización

- Cargar script en Frida/objection en CI/CD/local.
- Integrar varios hooks para apps con detección multi-capa/multi-path.
- Automatizar con Flex en dispositivos jailbroken para persistencia del patch.

---

## Impacto

- **Acceso a apps y funcionalidades bloqueadas:** Pentesting y debugging profundo.
- **Derrota de controles anti-fraude y análisis anti-malware:** Permite examinar lógica protegida.
- **Ejecución de PoCs y hooks avanzados:** Manipulación libre para fuzzing, explotación y análisis dinámico.

**Mapeo OWASP:** M8 Code Tampering, M4 Insecure Authentication, M2 Insecure Data Storage.

---

## Detección

- Monitoreo de procesos (frida-server, objection).
- Integridad de rutas y archivos tras cambios.
- Análisis de logs por patching, fallos anómalos en detección jailbreak.
- Detección de tweaks activos y hooks en memoria/appcode.

---

## Mitigación

- Detección multi-capa (kernel, rutas, procesos, APIs combinadas).
- Validación server-side de lógica crítica.
- Responder ante presencia de hooks/patches/tweaks activos.
- Bloquear ejecución ante anormalidades/fake returns.
- Logs de integridad de app y entorno.

---

## Errores Comunes

- Hookear sólo un método, cuando hay detección en muchos sitios.
- Parchear sin revisar efectos colaterales en la lógica.
- No restaurar estado tras pruebas o dejar tweaks activos.
- Omitir validación en server-side para funciones críticas.

---

## Reporte

**Título:** Bypass de Jailbreak Detection permite acceso y manipulación avanzados a lógica protegida
**Impacto:** Acceso a funciones restringidas, bypass de controles anti-fraude/anti-análisis, ampliación de ataque
**Pasos:**

1. Identificar métodos/paths de detección
2. Hookear/parchear retorno de checks
3. Confirmar acceso/función sin bloqueo
   **Mitigación:** Hardening multi-capa, validación server, detección activa de hooking/patches
