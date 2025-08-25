# OWASP Mobile Top 10 2024

El **OWASP Mobile Top 10 2024** identifica las vulnerabilidades más críticas en aplicaciones móviles basadas en datos reales del ecosistema. Para un bug hunter en iOS, estas categorías sirven como checklist priorizado para orientar el análisis y maximizar la eficacia de las pruebas.

## M1: Improper Credential Usage

Criticidad: Muy Alta | Explotabilidad: Fácil | Detección: Fácil
Qué buscar:

- Credenciales hardcodeadas en binarios IPA o código fuente
- API keys embebidas en el código
- Tokens en texto plano en Keychain o UserDefaults
- Certificados SSL sin protección
  Técnicas: `grep` strings, `class-dump`, revisión de plist, análisis runtime con LLDB

## M2: Inadequate Supply Chain Security

Criticidad: Alta | Explotabilidad: Variable
Qué buscar:

- Dependencias de terceros desactualizadas o comprometidas
- CocoaPods vulnerables
- Frameworks no oficiales o sin verificación de integridad
  Herramientas: `pod outdated`, análisis de `Podfile.lock` y `Package.resolved`, validación de firmas

## M3: Insecure Authentication/Authorization

Criticidad: Alta | Explotabilidad: Fácil
Vectores:

- Bypass de Face ID/Touch ID con Frida
- JWT sin validación server-side
- Gestión deficiente de sesiones
- Deep links sin autenticación
  Ejemplo Frida:

```javascript
Java.perform(function() {
  var LAContext = ObjC.classes.LAContext;
  LAContext["- evaluatePolicy:localizedReason:reply:"].implementation = 
    function(policy, reason, reply) {
      reply(ObjC.classes.NSNumber.numberWithBool_(true), null);
    };
});
```

## M4: Insufficient Input/Output Validation

Criticidad: Alta | Explotabilidad: Moderada
Qué buscar:

- SQLi en Core Data/SQLite
- XSS en WebViews (`WKWebView`/`UIWebView`)
- Command injection en llamadas al sistema
- Path traversal en manejo de archivos

## M5: Insecure Communication

Criticidad: Alta | Explotabilidad: Moderada
Qué buscar:

- Falta o mal implementación de certificate pinning
- Uso de HTTP para datos sensibles
- TLS obsoletos (<1.2)
  Herramientas: Burp Suite, OWASP ZAP, Charles Proxy

## M6: Inadequate Privacy Controls

Criticidad: Media-Alta | Explotabilidad: Variable
Qué buscar:

- Permisos excesivos en `Info.plist`
- Tracking sin consentimiento
- Transmisión innecesaria de PII
- Analytics con datos sensibles

## M7: Insufficient Binary Protections

Criticidad: Moderada | Explotabilidad: Fácil
Qué buscar:

- Ausencia de anti-debugging
- Falta de ofuscación de código
- Runtime tampering sin detección
- Class dumping sin restricción
  Herramientas: IDA Pro, Ghidra, Hopper, `class-dump`

## M8: Security Misconfiguration

Criticidad: Variable | Explotabilidad: Fácil
Qué buscar:

- Flags de debug en producción
- Logging excesivo con datos sensibles
- Schemes URL no validados
- Entitlements innecesarios

## M9: Insecure Data Storage

Criticidad: Alta | Explotabilidad: Fácil
Qué buscar:

- Keychain mal configurado (sin `kSecAttrAccessibleWhenUnlocked`)
- UserDefaults con datos sensibles
- Archivos sin cifrar en sandbox
- Core Data sin protección
  Técnicas: inspección de sandbox en dispositivo jailbreakeado

## M10: Insufficient Cryptography

Criticidad: Alta | Explotabilidad: Moderada
Qué buscar:

- AES con claves estáticas
- Hashes inseguros (MD5, SHA1)
- RNG débil
- Derivación de claves insegura
  Referencias: OWASP MASVS y MASTG para controles criptográficos

---

### Cómo usar este listado

1. **Checklist inicial**: revisa cada M1–M10 durante análisis estático y dinámico.
2. **Priorización**: comienza por M1–M3 dada su alta criticidad y facilidad de explotación.
3. **Herramientas y técnicas**: combina `class-dump`, LLDB/Frida y proxies para cubrir todas las categorías.
4. **Validación manual**: confirma hallazgos de herramientas automáticas con pruebas específicas.

Este marco te permitirá enfocar tus pruebas de bug bounty en iOS de forma estructurada y efectiva, asegurando que cubres los riesgos más críticos del año 2024.
