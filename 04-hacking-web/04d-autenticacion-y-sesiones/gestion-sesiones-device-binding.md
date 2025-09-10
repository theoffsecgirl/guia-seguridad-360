<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Gestión de Sesiones y Device Binding

## Resumen

**Qué es:** La gestión de sesiones controla el ciclo de vida de la autenticación tras el login, y el **device binding** asocia una sesión o token a un dispositivo específico.
**Por qué importa:** Una gestión deficiente permite el secuestro de sesión, la reutilización de tokens en dispositivos no autorizados y ataques de *replay*.
**Cuándo aplicarlo:** Vital en aplicaciones web y móviles que requieran asegurar que los tokens de sesión solo funcionen en dispositivos legítimos.

## Contexto

**Supuestos:**

- La aplicación utiliza cookies de sesión, tokens JWT o tokens de acceso persistentes.
- Existen mecanismos de *device fingerprinting* o identificadores de dispositivo (`device_id`, UUID, certificados de cliente).
- Acceso para interceptar tráfico y modificar cabeceras o cookies (Burp Suite, DevTools).
- Entorno: aplicaciones móviles (iOS/Android) y web.

**Límites:**

- No cubre autenticación biométrica ni MFA.
- Se enfoca en *device binding* a nivel de aplicación, no en hardware TPM.

## Metodología

1. Identificar el mecanismo de sesión: cookies, JWT o tokens en almacenamiento local.
2. Detectar si existe *device binding* (claims `device_id`, huella digital).
3. Probar la reutilización de tokens en otro dispositivo o navegador.
4. Forzar un cambio de identificador de dispositivo modificando `device_id` en payload o cabeceras.
5. Test de **session fixation**: fijar la cookie antes del login y verificar si persiste tras autenticarse.
6. Realizar ataques de *replay* con tokens caducados o revocados.
7. Intentar bypass de *device binding* respondiendo con un identificador falso en la API.

**Checklist de verificación:**

- Tokens vinculados a un `device_id` o fingerprint verificable.
- Invalidación de la sesión cuando cambia el `device_id`.
- Cookies configuradas con flags `Secure`, `HttpOnly` y `SameSite`.
- Regeneración del identificador de sesión tras el login.
- Expiración adecuada de sesiones y mecanismo de refresh controlado.

## Pruebas Manuales

### 1. Session Fixation

1. Solicitar una página antes de login para obtener una cookie vacía.
2. Interceptar y alterar la cookie a `session=FIXEDSESSIONID`.
3. Realizar login. Si `FIXEDSESSIONID` permanece válido, existe vulnerabilidad de session fixation.

### 2. Reutilización de Token en Otro Dispositivo

1. Obtener un token JWT desde Chrome.
2. En Firefox, usar:

```
Authorization: Bearer <token_obtenido>
```

3. Si la API responde 200, no hay *device binding* efectivo.

### 3. Modificación de Device ID

1. Identificar el claim `device_id` en el payload del token.
2. Modificarlo a otro valor (`device_id: "otroDevice"`) y resignar el JWT.
3. Si el servidor acepta el token, no verifica el `device_id`.

### 4. Replay de Tokens Caducados

1. Interceptar un JWT con `exp` pasado.
2. Reenviar la petición. Si la API responde 200, no valida la expiración.

## PoC Manual

```bash
# Session Fixation
curl -c cookies.txt https://victima.com/login   # obtiene cookie
# Editar cookies.txt: cambiar session a FIXEDSESSIONID
curl -b cookies.txt -d "user=alice&pass=secret" https://victima.com/login
# Verificar acceso con FIXEDSESSIONID
curl -b cookies.txt https://victima.com/dashboard

# Token Reuse
TOKEN="eyJhbGciOi..."
curl -H "Authorization: Bearer $TOKEN" https://victima.com/api/data
```

## PoC Automatizada

```python
import requests

API_URL = "https://victima.com/api/data"
TOKENS = ["token_device_1", "token_device_2"]

for token in TOKENS:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Device-ID": "dispositivo_falso"
    }
    r = requests.get(API_URL, headers=headers)
    print(token, r.status_code)
```

## Explotación y Automatización

- **Bypass con header spoofing:** Modificar `X-Device-ID` a uno permitido.
- **Replay attacks con proxys:** Reenviar tokens simultáneamente.
- **Inyección de device_id:** En *localStorage* para aplicaciones web.

## Impacto

- **Account Takeover:** Hijacking de sesión sin credenciales.
- **Escalado de privilegios:** Uso de tokens de servicio en dispositivos no autorizados.
- **Acceso persistente:** Tokens no invalidan tras cambio de dispositivo.

**Mapeo OWASP/CWE:** A2 Broken Authentication; CWE-384 Session Fixation; CWE-345 Improper Verification of Data Authenticity.

## Detección

- Logs de *device_id* inusuales o cambios de sesión.
- Fallos en validación de expiración de tokens.
- Múltiples logins concurrentes con mismo token desde diferentes IPs.

## Mitigación

- Regenerar el identificador de sesión tras el login.
- Verificar el `device_id` o fingerprint en cada petición.
- Configurar cookies con `Secure`, `HttpOnly` y `SameSite`.
- Establecer expiración corta de sesión y refresh tokens seguros.

## Errores Comunes

- No regenerar sesión tras autenticación.
- Generar `device_id` predecibles.
- No validar expiración de token en backend.

## Reporte

**Título:** Session Fixation y Device Binding insuficiente permiten secuestro de sesiones
**Impacto:** Secuestro de sesiones válidas en dispositivos no autorizados.

**Pasos:**

1. Fijar cookie de sesión antes de login.
2. Realizar login con cookie fijada.
3. Verificar acceso con cookie predefinida.
4. Modificar `X-Device-ID` y comprobar acceso con token válido.

**Evidencias:** Logs de servidor mostrando sesión `FIXEDSESSIONID` activa para el usuario víctima.
**Mitigación:** Regenerar sesión, validar `device_id` y establecer flags de cookie seguros.

---



[^1]:

https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/0f2fad86bd054dd6ca23d8ede0430158/55edaabf-2d24-4ffd-803d-35b67d664a10/b7db4d1d.md
