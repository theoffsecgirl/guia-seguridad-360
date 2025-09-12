# Deep/Universal Links y AASA

## Resumen

**Qué es:**

- **Deep Links:** URLs que abren directamente una vista o funcionalidad interna de la app.
- **Universal Links:** Deep links avanzados introducidos por Apple, que asocian dominios HTTPS a apps mediante archivo AASA (Apple App Site Association) y permiten abrir la app directamente desde un enlace sin confirmación del usuario.
- **AASA:** Archivo JSON que reside en el dominio web y define qué paths pueden invocar la app para Universal Links.

**Por qué importa:** Malas implementaciones posibilitan bypass de autenticación, ejecución de acciones indebidas, trampas de phishing y abuso de funcionalidades sensibles con solo un enlace.
**Cuándo aplicarlo:** Al pentestear apps que manejan autenticación por enlaces, workflows combo web+app, integraciones profundas (OAuth, reset, Magic Link), y apps con esquemas URI o soporte Universal Links.

---

## Contexto

**Supuestos:**

- App que declara deep links en `Info.plist`/schemes y Universal Links con AASA.
- Acceso a los archivos de configuración, la app y el dominio relacionado.
- Posibilidad de probar enlaces, parámetros y fallback a navegador.
- Herramientas: Burp, `plutil`, mitmproxy, introspección con Frida/objection, app/site scanner para AASA.

**Límites:**

- No cubre ataques a link handlers en Android ni a sistemas web-only.

---

## Metodología

### 1. Reconocimiento de Deep Links

- Revisar `Info.plist` (`CFBundleURLTypes`, `CFBundleURLSchemes`).
- Enumerar y probar esquemas: `myapp://`, `bankapp://transfer?...`
- Identificar rutas internas que permitan saltarse validaciones, cambiar estados, trigger acciones críticas.

### 2. Universal Links y AASA

- Verificar `applinks` en `Info.plist` (`com.apple.developer.associated-domains`).
- Localizar y descargar `/.well-known/apple-app-site-association`:

```bash
curl https://dominio.com/.well-known/apple-app-site-association
```

- Analizar el AASA: rutas permitidas, exclusiones, controles de autenticidad.

### 3. Prueba de abuso o bypass

- Construir enlaces Universal:
  `https://dominio.com/path/autenticacion?token=1234`
- Probar si links abren app con usuario no validado, saltan pantallas intermedias o acceden a funciones restringidas.
- Manipular parámetros para Account Takeover, password reset, sesión, compra, etc.
- Testear fallback (si app no instalada, debe ir al navegador/App Store).

### 4. Explotación real

- Phishing: envío de Universal Link malicioso que abusa las rutas permitidas.
- Ataques de fuerza bruta en Magic Links/access links.
- Explorar las rutas y parámetros definidos para identificar lógica vulnerable (IDOR, lógica rota).

**Checklist:**

- ¿El deep/universal link permite saltar autenticación o acceder directo a recursos?
- ¿Los parámetros críticos van cifrados, firmados?
- ¿El AASA sólo incluye paths seguros y necesarios?
- ¿Se valida ownership en backend y precondiciones de lógica de negocio?

---

## Pruebas Manuales

### Deep links

- Lanzar enlaces:
  `myapp://admin`, `myapp://transaccion?id=123`
- Observar si acceden, sin login, a recursos/funcionalidades no autorizadas.

### Universal links / AASA

- Probar Universal Link:
  `https://dominio.com/sensitivepath?uid=123`
- Revisar la respuesta con y sin la app instalada.

### Manipulación de AASA

- Modificar el archivo (en entorno controlado) e incluir paths peligrosos:
  `/admin/*`, `/reset/*`
- Observar si el cambio afecta el funcionamiento.

### Phishing/abuso

- Construir email con link:
  `https://dominio.com/app/autorizar-transferencia?importe=10000&to=attacker`
- Validar si la app procesa la acción sin controles.

---

## PoC Automatizada

```python
import requests
aasa = requests.get('https://dominio.com/.well-known/apple-app-site-association').json()
for details in aasa.get('applinks', {}).get('details', []):
    for path in details.get('paths', []):
        print("[+] Universal Link permitido:", path)
```

- Probar cada path con múltiples parámetros críticos.

---

## Explotación y Automatización

- Recolectar y automatizar pruebas sobre todos los Universal Links del AASA.
- Automatizar brute-force/fuzzing de parámetros en rutas expuestas.
- Integrar tracking de tráfico y respuesta, búsqueda de bypass y lógica floja.

---

## Impacto

- **Account Takeover/Privilege Escalation:** Reset de password, login directo, acceso a recursos de otro usuario.
- **Phishing avanzado:** Captura de credenciales, transferencias, cambios de configuración con click único.
- **Abuso de business logic:** Saltos en flujos, creación de recursos, ejecución de acciones irrestrictas.
- **Exposure de datos:** Acceso directo a recursos individuales/sensibles vía enlace.

**Mapeo OWASP:** M1 - Improper Platform Usage, M7 - Client Code Quality, API3 - Excessive Data Exposure.

---

## Detección

- Log de accesos y auditoría de Universal/Deep Link usage.
- Alertas por accesos anómalos vía paths definidos en AASA.
- Monitoreo de intents disparados por links y patrones de phishing.

---

## Mitigación

- Limitar paths en AASA a los estrictamente necesarios.
- Validación server-side de todas las operaciones disparadas por links.
- Firmar y expirar tokens/params críticos en enlaces.
- Revisar workflows sensibles: reset, login, pagos sólo si hay precondiciones estrictas.
- Revisión/monitorización continua de archivos AASA y cambios.

---

## Errores Comunes

- Incluir paths demasiado amplios (`/*`, `/admin/*`) en AASA.
- No verificar autenticidad/log de requests disparados por enlaces.
- Permitir acciones críticas solo por link, sin comprobaciones extra (PIN, TouchID).
- No proteger la app ante uso de links maliciosos o repetidos.

---

## Reporte

**Título:** Deep/Universal Links y mala configuración AASA permiten bypass y abuso de lógica crítica
**Impacto:** Account takeover, ejecución de acciones indebidamente, exfiltración y abuso de negocio
**Pasos:**

1. Descargar y auditar archivo AASA, enumerar paths
2. Construir enlaces con parámetros críticos y lanzarlos sobre la app
3. Evidenciar acceso/acción sin autenticación o salto de flujos
   **Mitigación:** Paths mínimos, validación server, logs y tokens seguros/expirados
