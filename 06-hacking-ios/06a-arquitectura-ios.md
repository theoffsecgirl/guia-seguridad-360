# Arquitectura de iOS para Bug Bounty Hunting

Comprender la arquitectura de iOS es fundamental para cualquier investigación de seguridad o bug bounty. Este conocimiento permite identificar posibles vectores de ataque, comprender cómo están protegidas las aplicaciones y saber en qué puntos puede fallar el sistema.

---

## Kernel Darwin y XNU

iOS está basado en **Darwin**, un sistema operativo de código abierto que combina elementos de FreeBSD con el kernel **XNU** (X is Not Unix). El kernel XNU es híbrido y se compone de:

* **OSFMK 7.3 (Mach Kernel)**: proporciona multitarea y comunicación entre procesos.
* **Elementos de FreeBSD**: gestionan procesos, permisos y el stack de red.
* **I/O Kit**: framework basado en C++ para controladores de dispositivos.

---

## Arquitectura ARM64

Desde el iPhone 5s (2013), todos los dispositivos iOS utilizan procesadores **ARM64 (ARMv8 / AArch64)**.
Apple eliminó el soporte a 32 bits a partir de iOS 11 (2017).

Implicaciones para el bug bounty:

* Cualquier exploit o herramienta debe estar compilada para ARM64.
* Los binarios de App Store solo contienen la arquitectura necesaria, ya no empaquetan múltiples versiones.
* El análisis con herramientas como `lipo` ayuda a extraer arquitecturas específicas.

---

## Capas de la Arquitectura iOS

La arquitectura se organiza en capas jerárquicas que van desde el nivel más bajo hasta el más cercano al usuario:

1. **Kernel Darwin** → base del sistema operativo.
2. **Core OS** → servicios de bajo nivel como acceso a hardware, hilos y comunicación.
3. **Core Services** → servicios comunes como networking, bases de datos o seguridad.
4. **Media Layer** → frameworks multimedia (gráficos, audio, video).
5. **Cocoa Touch** → APIs y frameworks de interacción con apps.

---

## Core Services

En esta capa se encuentran varios frameworks esenciales para el análisis de seguridad:

* **Foundation Framework**: gestión de memoria y programación orientada a objetos.
* **Core Foundation**: API de bajo nivel en C.
* **CFNetwork**: gestión de enlaces de red (HTTP/HTTPS).
* **Security Framework**: criptografía, certificados y autenticación.
* **SQLite**: base de datos embebida en muchas apps.

---

## Modelo de Seguridad de iOS

## Sandboxing

* Cada aplicación funciona en un entorno aislado con su propio contenedor.
* Usa el **Mandatory Access Control Framework (MACF)** en el kernel.
* El módulo **Sandbox.kext** valida permisos antes de permitir syscalls.

## Entitlements

* Definen qué recursos del sistema puede usar una app.
* Se especifican en un archivo plist dentro de la firma del binario.
* Controlan acceso a **iCloud, Siri, notificaciones push, etc.**
* Validados en tiempo de ejecución con **AppleMobileFileIntegrity.kext**.

## Code Signing

* Toda app debe estar firmada digitalmente.
* Garantiza integridad del código y define los entitlements.
* Previene modificaciones tras la instalación.

---

## Formato Binario: Mach-O

Todas las apps iOS se ejecutan en **binarios Mach-O (Mach Object)**.

## Estructura

* **Header**: contiene tipo de CPU, flags, comandos de carga.
* **Load Commands**: información sobre librerías dinámicas, encriptación y firmas.
* **Segments/Data**: dividen código y datos en memoria.

## Características

* Soporte para **FAT binaries** (múltiples arquitecturas).
* El App Store solo distribuye la necesaria para el dispositivo.
* Se pueden extraer o modificar con **lipo**.

---

## Runtime de Objective-C

Aunque Swift es dominante, el runtime de Objective-C se sigue utilizando:

* **Method Swizzling**: permite reemplazar métodos en tiempo de ejecución.
* **Introspección**: examinar clases y métodos dinámicamente.
* Posibles vulnerabilidades por acceso a métodos/variables privadas.

---

## Comunicación Inter-Proceso (IPC)

## Mach IPC

* Base de la comunicación en iOS.
* Usa `mach_sendmsg` para pasar mensajes entre procesos.
* **MIG (Mach Interface Generator)** simplifica interfaces.

## XPC

* Capa de abstracción sobre Mach IPC.
* Serializa objetos y los pasa entre procesos.
* Usado en muchos frameworks y servicios de sistema.
* Herramienta de análisis: **xpcspy**.

---

## Mecanismos de Seguridad Críticos

* **ASLR (Address Space Layout Randomization)**: aleatoriza la memoria en cada ejecución.
* **SIP (System Integrity Protection / rootless)**: protege ficheros y procesos del sistema.
* **Secure Enclave**: chip interno que hace operaciones criptográficas sensibles.
* **Boot ROM**: solo permite cargar kernels firmados.

---

## Conclusión

La arquitectura de iOS combina capas rígidas de seguridad con mecanismos en hardware y software. Para bug bounty hunting, entender estas capas es esencial:

* El **sandbox y entitlements** son claves al analizar limitaciones de apps.
* **Mach-O, runtime Objective-C y XPC** son puntos comunes de entrada para vulnerabilidades.
* El conocimiento de ARM64 y del **kernel Darwin/XNU** es indispensable al analizar exploits.

Estudiar estos fundamentos permitirá identificar dónde buscar errores de configuración, vulnerabilidades lógicas o bugs de memoria explotables en iOS.
