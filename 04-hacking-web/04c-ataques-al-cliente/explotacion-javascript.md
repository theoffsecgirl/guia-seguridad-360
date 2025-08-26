# Explotación de JavaScript

## 1. Por qué los archivos JavaScript son críticos

Los archivos JavaScript son **la superficie de ataque más subestimada** en aplicaciones web modernas. Todo lo que ve el navegador, lo ve también el atacante.

### Qué puedes encontrar en JS:

- **Endpoints ocultos** que nunca aparecen en el frontend (`/api/v1/admin`, `/internal/debug`)
- **Claves API y tokens expuestos** (AWS keys, Stripe tokens, JWT secrets)
- **Lógica de negocio sensible** (validaciones de precios, reglas de acceso, roles)
- **Vulnerabilidades directas**:
  - XSS via `innerHTML`, `document.write()`, `eval()`
  - JWT mal implementados o con secrets hardcodeados
  - CSRF tokens predecibles
  - Bypass de autenticación client-side

> **Regla de oro:** Si está en el frontend, está para el atacante. Si está en JavaScript, es tuyo para romper.

---

## 2. Metodología Completa de Recolección

### A. Tráfico Activo (Burp Suite)

**Objetivo:** Capturar JS que se cargan durante navegación activa.

1. Configura proxy en Burp Suite
2. Navega **victima.com** extensivamente (todas las secciones)
3. En **Target → Site map**, filtra por MIME type `script/javascript`
4. Exporta URLs a `burp_js.txt`

**Limitación:** Solo JS activos en esa sesión.

### B. Recolección Histórica (Wayback Machine)

**Objetivo:** Encontrar JS antiguos y olvidados.

```bash
# Un dominio específico
echo victima.com | waybackurls | grep '\.js$' | sort -u > wayback_js.txt

# Con subdominios
subfinder -d victima.com -silent > subs.txt
cat subs.txt | waybackurls | grep '\.js$' | sort -u > allsubs_js.txt
```

### C. Extracción Quirúrgica (CDX API)

**Objetivo:** Búsqueda profunda en Archive.org con filtros específicos.

```bash
# Extracción con filtro MIME
curl -s "http://web.archive.org/cdx/search/cdx?url=victima.com/*&output=txt&fl=original&filter=mime:application/javascript" > cdx_js.txt

# Filtrar solo los vivos
cat cdx_js.txt | httpx -mc 200 > js_vivos.txt
```

### D. Crawlers Modernos

**Katana (recomendado):**

```bash
katana -u https://victima.com -d 5 -silent | grep '\.js$' | sort -u > katana_js.txt
```

**GAU (Get All URLs):**

```bash
gau victima.com | grep '\.js$' | sort -u > gau_js.txt
```

---

## 3. Análisis Estático Avanzado

### A. Grep Manual (siempre primero)

```bash
# Búsqueda básica de secretos
while read url; do
  echo "[*] Escaneando: $url"
  curl -s $url | grep -iE 'key|token|secret|api|aws|password|bearer|jwt';
done < js_vivos.txt

# Búsqueda específica de patrones críticos
while read url; do
  curl -s $url | grep -iE 'aws_access_key|aws_secret_key|stripe_|sk_live|sk_test'
done < js_vivos.txt
```

### B. LinkFinder - Endpoints Ocultos

```bash
# Instalación
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt

# Uso en un archivo específico
python3 linkfinder.py -i https://victima.com/app.js -o cli

# Escaneo de dominio completo
python3 linkfinder.py -i https://victima.com -d -o cli
```

### C. JSLeak - Credenciales y Secretos

```bash
# Instalación
go install github.com/channyein1337/jsleak@latest

# Uso
jsleak -l js_vivos.txt -k
```

### D. Nuclei - Detección Masiva

```bash
# Escaneo de exposiciones
nuclei -l js_vivos.txt -t exposures/ -o js_exposures.txt

# Templates específicos de JS
nuclei -l js_vivos.txt -t exposures/configs/ -t exposures/tokens/
```

### E. Análisis Offline Avanzado

```bash
# Descarga masiva
while read url; do 
  wget -q $url -O "$(basename $url .js)_$(date +%s).js"
done < js_vivos.txt

# Búsqueda masiva local
find . -name "*.js" -exec grep -l "aws\|secret\|token\|api" {} \;
```

---

## 4. Análisis Dinámico (Runtime Exploitation)

### A. DevTools - Tu Arma Principal

**Configuración inicial:**

1. F12 → **Sources** para debugging
2. **Application** para storage
3. **Console** para manipulación

### B. Técnicas de Breakpoint y Manipulación

#### 4.1 Bypass de Autenticación

```javascript
// Encontrar función de validación (ej: validateAdminPassword)
// Agregar breakpoint en la línea de validación
// En consola, cuando pare en el breakpoint:
password = "valorEsperado"; // Modificar variable
// Continuar ejecución
```

#### 4.2 Manipulación de Roles y Flags

```javascript
// Buscar variables de estado
isAdmin = true;
isPremium = true;
userRole = "administrator";
isDevMode = true;
```

#### 4.3 Bypass de Validaciones Client-side

```javascript
// Deshabilitar validaciones
document.querySelectorAll("input[readonly]").forEach(el => el.readOnly = false);
document.querySelectorAll("button:disabled").forEach(b => b.disabled = false);

// Modificar valores críticos
document.querySelector("input[name='amount']").value = 1;
document.querySelector("input[name='price']").value = 0;
```

#### 4.4 Send Message Exploitation

```javascript
// Interceptar con breakpoint en función sendMessage()
// En consola, modificar el contenido antes de envío:
message.content = "<img src=x onerror=alert('XSS_by_atacante.com')>";
```

### C. Local Overrides (Modificaciones Persistentes)

1. **DevTools → Sources → Overrides**
2. **Enable Local Overrides** y seleccionar carpeta
3. Modificar archivo JS:

```javascript
// Original
if (!user.premium) { return false; }
// Modificado
if (true) { return true; }
```

4. **Ctrl+S** para guardar cambios

---

## 5. Técnicas Avanzadas de Explotación

### A. Activación de Funciones Ocultas

```javascript
// Buscar comentarios en código fuente:
// "Hidden endpoints revealed when in dev mode"

// Activar modo desarrollo
toggleDevMode(); 
// o directamente:
isDevMode = true;

// Acceder a endpoints ocultos
fetch('/api/internal/admin').then(r => r.json()).then(console.log);
```

### B. Manipulación de JWT

```javascript
// Buscar JWT hardcodeados o mal validados
// En localStorage/sessionStorage:
localStorage.getItem('auth_token');

// Modificar payload JWT (si no está bien validado)
token = btoa('{"alg":"none","user":"admin","role":"administrator"}');
```

### C. Descubrimiento de Endpoints Secretos

```javascript
// Funciones comunes a probar:
resetUserPassword(userId, newPassword);
grantAdminAccess();
enableDebugMode();
accessSecretPanel();

// Buscar en objeto window:
console.log(Object.keys(window));
```

---

## 6. Manejo de Ofuscación

### A. Identificación de Código Ofuscado

- Variables con nombres como `_0x1234`, `a`, `b`, `c`
- Strings codificados en hexadecimal
- Uso excesivo de `eval()`, `Function()` constructor

### B. Técnicas de Deofuscación

```javascript
// Usar beautifiers
// Chrome DevTools → {} (Pretty print)
// O herramientas online: js-beautify, unminify.com

// Para ofuscación avanzada, usar AI:
// "Explica qué hace este código JavaScript ofuscado: [código]"
```

---

## 7. Patrones de Naming Críticos

### Archivos de Alto Valor:

- `config.js`, `env.js`, `settings.js`
- `admin.js`, `internal.js`, `debug.js`
- `auth.js`, `token.js`, `secret.js`
- `keys.js`, `credentials.js`

### Variables Críticas:

```javascript
// Buscar patrones:
api_key, apiKey, API_KEY
secret, SECRET_KEY, secretKey
token, auth_token, bearer_token
password, pass, pwd
aws_access_key, aws_secret_access_key
stripe_key, stripe_secret
```

---

## 8. Metodología Completa (Workflow)

```
1. Recolección Multi-fuente
   ├── Burp Suite (activos)
   ├── Wayback/Katana/GAU (históricos)
   └── CDX API (quirúrgico)

2. Filtrado y Validación
   ├── httpx para filtrar vivos
   └── Deduplicación (sort -u)

3. Análisis Estático
   ├── Grep manual (secretos)
   ├── LinkFinder (endpoints)
   ├── JSLeak (credenciales)
   └── Nuclei (templates)

4. Análisis Dinámico
   ├── DevTools inspection
   ├── Breakpoint manipulation
   ├── Local Overrides
   └── Runtime exploitation

5. Validación de Hallazgos
   ├── Verificar impacto real
   ├── Probar en producción
   └── Cross-validation con múltiples herramientas

6. Reporting
   ├── PoC paso a paso
   ├── Screenshots/videos
   └── Impacto de negocio
```

---

## 9. Scripts de Automatización

### Script de Recolección Completa:

```bash
#!/bin/bash
TARGET=$1

echo "[+] Recolectando JS de $TARGET"

# Subdominios
subfinder -d $TARGET -silent > subs.txt

# Wayback
cat subs.txt | waybackurls | grep '\.js$' | sort -u > wayback_js.txt

# CDX
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=txt&fl=original&filter=mime:application/javascript" > cdx_js.txt

# Katana
katana -u https://$TARGET -d 5 -silent | grep '\.js$' | sort -u > katana_js.txt

# Fusionar y filtrar vivos
cat wayback_js.txt cdx_js.txt katana_js.txt | sort -u | httpx -mc 200 > js_final.txt

echo "[+] $(wc -l < js_final.txt) archivos JS encontrados"
```

### Script de Análisis:

```bash
#!/bin/bash
JS_FILE=$1

echo "[+] Analizando $JS_FILE"

# Análisis estático
echo "[*] Buscando secretos..."
grep -iE 'key|token|secret|api|aws|password|bearer' $JS_FILE

echo "[*] Buscando endpoints..."
grep -oE '/[a-zA-Z0-9_/.-]+' $JS_FILE | grep -E '^/api|^/admin|^/internal'

echo "[*] Buscando funciones críticas..."
grep -oE 'function [a-zA-Z0-9_]+|[a-zA-Z0-9_]+\s*=\s*function' $JS_FILE
```

---

## 10. Casos de Explotación Reales

### Ejemplo 1: Account Takeover via Endpoint Oculto

1. **Descubrimiento:** LinkFinder encuentra `/api/v1/admin/users`
2. **Validación:** Endpoint accesible sin autenticación
3. **Explotación:** Modificar cualquier usuario
4. **Impacto:** Full account takeover

### Ejemplo 2: AWS Keys Expuestas

1. **Descubrimiento:** `config.js` contiene `aws_access_key_id`
2. **Validación:** Keys válidas en AWS
3. **Explotación:** Acceso a S3 buckets sensibles
4. **Impacto:** Data breach masivo

### Ejemplo 3: Premium Bypass via JavaScript

1. **Descubrimiento:** Función `isPremiumUser()` siempre retorna `false`
2. **Explotación:** Local Override para retornar `true`
3. **Validación:** Acceso a contenido premium sin pagar
4. **Impacto:** Business logic bypass

---

> **Mindset clave:** Si el frontend lo expone, el atacante lo puede abusar. El truco es recoger, filtrar, analizar y **manipular** hasta que algo se rompa.
