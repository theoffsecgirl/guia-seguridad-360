# Jailbreak y Seguridad en iOS

El jailbreak es un proceso que elimina las restricciones de iOS impuestas por Apple, proporcionando acceso de superusuario (root) al sistema y permitiendo ejecutar código no firmado. Para un bug hunter, disponer de un dispositivo jailbreak ofrece un entorno de pruebas ampliado, donde analizar el comportamiento de las aplicaciones, inspeccionar el sandbox y evadir protecciones estándar.

## 1. Tipos de Jailbreak

1. **Untethered**: el dispositivo permanece jailbreakeado tras cada reinicio sin necesidad de conectar al equipo.
2. **Tethered**: requiere conexión al ordenador para arrancar en modo jailbreak cada vez que se reinicia.
3. **Semi-untethered**: el jailbreak persiste tras reinicio, pero la reactivación de funciones de jailbreak necesita ejecución de una app o herramienta en el dispositivo.
4. **Semi-tethered**: el dispositivo arranca sin jailbreak tras un reinicio; para reactivar, debe conectarse a un ordenador.

## 2. Herramientas Populares

- **checkra1n**: usa vulnerabilidad de bootrom basada en checkm8; soporta dispositivos A5–A11.
- **unc0ver**: compatible con versiones recientes de iOS (12–15.x); semi-untethered.
- **Taurine**: jailbreak semi-untethered para iOS 14–15, basado en Odyssey Team.
- **Chimera**: soporta iOS 12, con Sileo como gestor de paquetes.

## 3. Beneficios de Jailbreak para Pentesting

- **Acceso completo al sistema de archivos**: permite inspeccionar carpetas de aplicación, preferences y bases de datos.
- **Desactivación de protecciones**: bypass de code signing, deshabilitar ASLR y desactivar SIP en dispositivos de desarrollo.
- **Instalación de herramientas nativas**: Frida-server, Cycript, tcpdump, mitmproxy directamente en iOS.
- **Inspección de procesos**: uso de LLDB o lsof para listar procesos y puertos abiertos.

## 4. Configuración del Entorno Jailbreakeado

1. Instalar Cydia o Sileo como gestor de paquetes.
2. Añadir repositorios necesarios (por ejemplo, `https://apt.thebigboss.org/repofiles/cydia/`).
3. Instalar herramientas:
   - **OpenSSH**: acceso remoto al dispositivo.
   - **Darwin CC Tools**: incluye otool, nm, strings.
   - **Frida-server**: instrumentación dinámica.
   - **ldid**: firma de binarios en el dispositivo.
4. Transferir Frida-server:

```bash
scp frida-server root@<IP>:/usr/sbin/
ssh root@<IP> "chmod +x /usr/sbin/frida-server && /usr/sbin/frida-server &"
```

## 5. Inspección del Sandbox y Sistema de Archivos

- **Ruta de sandbox de la app**:
  `/var/mobile/Containers/Data/Application/<APP-UUID>/`
- **Buscar datos sensibles**:

```bash
find /var/mobile/Containers/Data/Application/<APP-UUID>/ -type f \
  -exec grep -Il "password\|token\|key" {} \;
```

- **Examinar preferencias**:

```bash
plutil -p /var/mobile/Containers/Data/Application/<APP-UUID>/Library/Preferences/*.plist
```

- **Listar puertos abiertos y procesos**:

```bash
lsof -i
ps aux | grep <AppName>
```

## 6. Evadiendo Protecciones en iOS

- **Bypass de Code Signing**: usar `ldid` para resignar binarios modificados.
- **Deshabilitar ASLR**: parchear dyld_shared_cache o usar tweak con MobileSubstrate.
- **Desactivar Sandbox**: instalar tweak como `sandbox-patcher` disponible en Cydia.
- **Saltar certificate pinning**: con Frida inyectar hook en `NSURLSession` o librerías de pinning.

## 7. Uso de Frida para Privilegios Elevados

- **Iniciar Frida-server** en modo root.
- **Conectar desde el host**:

```bash
frida-ps -U             # listar procesos
frida -U -n MyApp       # inyectar script en MyApp
```

- **Ejemplo de script** (bypass SSL pinning):

```javascript
ObjC.classes.NSURLSessionConfiguration.sharedSessionConfiguration. \
  setAllowsExpensiveNetworkAccess.implementation = function(flag) {
    return true;
};
```

## 8. Consideraciones de Seguridad y Legalidad

- **Uso responsable**: realizar jailbreak únicamente en dispositivos de prueba o con autorización.
- **Impacto de actualizaciones**: Apple corrige vulnerabilidades que usan jailbreak; mantén herramientas actualizadas.
- **Riesgos iniciales**: el jailbreak puede desestabilizar el dispositivo; realizar backups antes de empezar.

---

Este apunte ofrece una guía práctica para configurar y explotar un entorno jailbreak en iOS, esencial para un análisis profundo y la identificación de vulnerabilidades que no son accesibles en un dispositivo estándar.
