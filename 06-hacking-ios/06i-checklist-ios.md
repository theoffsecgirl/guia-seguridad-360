# Checklist de Seguridad iOS para Pentesting y Bug Bounty

## Resumen

**Qué es:** Lista estructurada de aspectos críticos, pruebas y controles a revisar en apps iOS para auditoría, pentest o bug bounty, cubriendo arquitectura, protección client-side, networking, almacenamiento y lógica de negocio.
**Por qué importa:** Permite maximizar hallazgos, evitar falsos negativos y reportar vulnerabilidades reproducibles y con impacto real.
**Cuándo aplicarlo:** En cualquier test de apps iOS, revisiones DevSecOps, revisiones de releases y bug bounty hunting.

---

## Métodología y Estructura

**1. Arquitectura y App Info**

- [ ]  ¿Está segmentada la app móvil de la lógica backend?
- [ ]  ¿Se declaran correctamente los esquemas de URL y Universal Links en el Info.plist?
- [ ]  ¿El AASA sólo permite rutas estrictamente necesarias?
- [ ]  ¿Se limita la exposición de funcionalidades informativas/sensibles por esquema/Universal Link?

**2. Protecciones Client-side**

- [ ]  ¿Hay jailbreak detection activa y robusta? ¿Es sólo visual?
- [ ]  ¿Se implementa TLS pinning y se valida severamente? ¿Qué ocurre ante MITM?
- [ ]  ¿ATS está configurado para forzar HTTPS y no usar NSAllowsArbitraryLoads innecesario?
- [ ]  ¿Se usa Certificate Transparency y backup pins si aplica?
- [ ]  ¿La app detecta hooks, instrumentación con Frida/objection/r2frida?
- [ ]  ¿Existe validación server-side para todas las protecciones client-side?

**3. Networking y APIs**

- [ ]  ¿Todas las conexiones usan HTTPS con TLS ≥ 1.2?
- [ ]  ¿Se evita hardcodear endpoints, tokens o keys en el bundle/app?
- [ ]  ¿Se restringen las redirecciones y validaciones en requests internos?
- [ ]  ¿Se limita la exposición de datos sensibles en tráfico?
- [ ]  ¿Se han probado bypass de TLS pinning y manipulación de ATS vía Frida/objection?

**4. Autenticación, Sessions y Links**

- [ ]  ¿Sessions y tokens se almacenan sólo en Secure Enclave/Llavero?
- [ ]  ¿Hay rotación y expiración de tokens, y logs de acceso?
- [ ]  ¿Se blindan flows con Magic/Universal Link? ¿Solo se autorizan operaciones con validación server-side?
- [ ]  ¿Se testean enlaces de reset, login, privilegios contra abuso/bypass?
- [ ]  ¿Los entitlements son mínimos y revisados en cada release?

**5. Almacenamiento y Datos Locales**

- [ ]  ¿Solo datos mínimos y no sensibles en user defaults/CoreData?
- [ ]  ¿Se audita SQLite en busca de credenciales, tokens o datos sensitive?
- [ ]  ¿Se auditan rutas de exportación/backups de datos?
- [ ]  ¿Se usa adecuadamente el sandbox y permisos iOS?
- [ ]  ¿Datos sensibles en KeyChain y cifrados correctamente?

**6. Lógica de Negocio y Objetos**

- [ ]  ¿Se revisan estados, validaciones y workflows multi-paso?
- [ ]  ¿El runtime de Objective-C/Swift expone métodos/variables privadas?
- [ ]  ¿Se testean race conditions, replay y manipulación de requests via Turbo Intruder/threads?
- [ ]  ¿Se controlan duplicidad, idempotencia y respuestas tras condiciones raras o concurrentes?

**7. Binarios y Reverse Engineering**

- [ ]  ¿El binario no contiene data, logs, secrets ni rutas sensibles?
- [ ]  ¿Se analizan Mach-O, FAT binaries y signos de packing/obfuscation?
- [ ]  ¿Se testean hooks, method swizzling y introspección Objective-C?
- [ ]  ¿El análisis estático destaca acceso a clases, métodos y flujos no expuestos?

**8. Reporte y Evidencias**

- [ ]  ¿Se documentan reproducibilidad de las pruebas (videos, logs, scripts)?
- [ ]  ¿Se incluyen PoCs manuales y automatizadas, capturas y logs de red/binary?
- [ ]  ¿Se da contexto de impacto y recomendación concreta por cada hallazgo?

---

## Pruebas Clave Recomendadas

- Instrumentación y hooks en runtime con Frida/objection.
- Replay/bypass de TLS pinning y Universal Link/Magic Link.
- Fuzz de parámetros/links/métodos con Turbo Intruder/Burp/ZAP.
- Auditoría de almacenamiento local, KeyChain, SQLite.
- Validación exhaustiva de flows críticos (login, reset, compra, privilegios).
- Revisar entitlements y permisos en plist.
- Renderizar y manipular AASA, deep/universal links.

---

## Fuentes Clave y Herramientas

- OWASP MSTG iOS Requirements
- Frida, objection, Burp Suite, mitmproxy, r2frida
- Hopper, class-dump, lipo, plutil
- iOS App Security (Thiel), Apple Platform Security
- Labs: PentesterLab, Objective-See, O0Ninja

---

**Un pentest iOS de calidad sólo es posible con un checklist adaptado y exhaustivo antes, durante y después de cada campaña. Guarda esta guía como base de control mínimo para tus bug bounty y auditorías.**
