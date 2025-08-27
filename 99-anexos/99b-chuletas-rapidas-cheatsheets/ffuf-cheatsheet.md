# Cheatsheet : ffuf (Fuzz Faster U Fool)

## Introducción

**ffuf** es una herramienta de fuzzing web ultrarrápida escrita en Go que se ha convertido en el estándar de facto para el descubrimiento de contenido web. Su velocidad, flexibilidad y capacidad de personalización la hacen indispensable para pentesters, bug bounty hunters y profesionales de ciberseguridad.[^2][^3]

## Uso Básico: Fuzzing de Directorios y Archivos

### Comandos Fundamentales

```bash
# Escaneo básico de directorios
ffuf -w wordlist.txt -u https://victima.com/FUZZ

# Con verbosidad para ver estructura de directorios
ffuf -w wordlist.txt -u https://victima.com/FUZZ -v

# Fuzzing de archivos con múltiples extensiones
ffuf -w wordlist.txt -u https://victima.com/FUZZ -e .php,.txt,.html,.bak,.config,.old

# Fuzzing recursivo con control de profundidad
ffuf -w wordlist.txt -u https://victima.com/FUZZ -recursion -recursion-depth 2 -v

# Control de tiempo máximo por proceso
ffuf -w wordlist.txt -u https://victima.com/FUZZ -maxtime 300

# Control de tiempo máximo por trabajo (útil con recursión)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -recursion -maxtime-job 60
```

### Listas de Palabras Recomendadas

```bash
# SecLists - Colección esencial para fuzzing
# Instalación en Kali Linux
sudo apt install seclists

# Ubicaciones principales en SecLists
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

## Personalización Avanzada de Peticiones

### Uso de Archivos de Petición

```bash
# 1. Crear archivo de petición (peticion_api.txt):
POST /api/v2/users HTTP/1.1
Host: victima.com
Content-Type: application/json
Authorization: Bearer FUZZ
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0 (compatible; ffuf/2.1.0)

{"username": "testuser", "action": "create"}

# 2. Ejecutar fuzzing con la petición personalizada
ffuf -request peticion_api.txt -w tokens.txt -request-proto https

# 3. Combinar con modificaciones dinámicas
ffuf -request peticion_api.txt -w wordlist.txt \
     -H "Host: FUZZ.victima.com" \
     -X GET
```

### Fuzzing de Métodos HTTP

```bash
# Fuzzing de métodos HTTP poco comunes
ffuf -w http_methods.txt -X FUZZ -u https://victima.com/admin

# Lista de métodos para probar:
# GET,POST,PUT,DELETE,HEAD,OPTIONS,TRACE,PATCH,CONNECT,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK
```

## Descubrimiento de Parámetros

### Parámetros GET y POST

```bash
# Fuzzing de parámetros GET
ffuf -w params.txt -u https://victima.com/search?FUZZ=test

# Fuzzing de valores de parámetros conocidos
ffuf -w values.txt -u https://victima.com/search?category=FUZZ

# Fuzzing de parámetros POST
ffuf -w params.txt -u https://victima.com/login \
     -X POST -d "username=admin&FUZZ=test" \
     -H "Content-Type: application/x-www-form-urlencoded"

# Fuzzing combinado de parámetros y valores (Clusterbomb)
ffuf -w params.txt:PARAM -w values.txt:VALUE \
     -u https://victima.com/api?PARAM=VALUE -mode clusterbomb

# Fuzzing paralelo (Pitchfork) - útil cuando tienes pares conocidos
ffuf -w users.txt:USER -w ids.txt:ID \
     -u https://victima.com/profile?user=USER&id=ID -mode pitchfork
```

### Fuzzing de APIs JSON

```bash
# Fuzzing de endpoints de API REST
ffuf -w api_endpoints.txt -u https://victima.com/api/v1/FUZZ \
     -H "Accept: application/json"

# Fuzzing de parámetros JSON
ffuf -w json_params.txt -u https://victima.com/api/login \
     -X POST -H "Content-Type: application/json" \
     -d '{"username": "admin", "FUZZ": "test"}'

# Fuzzing de valores en estructuras JSON complejas
ffuf -w payloads.txt -u https://victima.com/api/user \
     -X PUT -H "Content-Type: application/json" \
     -d '{"user": {"profile": {"role": "FUZZ"}}}'
```

## Fuzzing de DNS y Virtual Hosts

### Enumeración de Subdominios

```bash
# Fuerza bruta de subdominios via DNS
ffuf -w subdominios.txt -u http://FUZZ.victima.com

# Con resolvedores DNS personalizados
ffuf -w subdominios.txt -u http://FUZZ.victima.com \
     -r 8.8.8.8:53,1.1.1.1:53

# Permutaciones de subdominios
ffuf -w prefijos.txt -u http://FUZZ-api.victima.com
ffuf -w sufijos.txt -u http://api-FUZZ.victima.com
```

### Descubrimiento de Virtual Hosts

```bash
# Técnica básica de VHost fuzzing
ffuf -w vhosts.txt -u http://192.168.1.100 \
     -H "Host: FUZZ.victima.com" -fs 1234

# VHost fuzzing con múltiples IPs
ffuf -w vhosts.txt -u http://FUZZ \
     -H "Host: victima.com" -mc 200,403

# Fuzzing de hosts internos comunes (sin wordlist externa)
ffuf -u http://192.168.1.100 \
     -H "Host: FUZZ" \
     -w - << EOF
localhost
127.0.0.1
internal
admin
api
dev
staging
test
kubernetes
docker
EOF
```

**¿Por qué funciona el VHost fuzzing?** Los servidores web modernos pueden alojar múltiples aplicaciones en una sola IP usando la cabecera `Host` para determinar qué sitio servir. Muchas aplicaciones de staging, paneles administrativos o APIs están "ocultos" usando esta técnica, siendo accesibles solo cuando se especifica el virtual host correcto.[^4]

## Sistema de Filtrado y Matching Avanzado

### Filtros por Tamaño y Contenido

```bash
# Filtrado por tamaño de respuesta (útil para eliminar páginas 404 personalizadas)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -fs 1337,0

# Filtrado por número de líneas
ffuf -w wordlist.txt -u https://victima.com/FUZZ -fl 404

# Filtrado por número de palabras (muy útil para detectar diferencias sutiles)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -fw 57,78

# Combinación de filtros
ffuf -w wordlist.txt -u https://victima.com/FUZZ -fs 0 -fw 3 -fl 1
```

### Matching por Códigos de Estado

```bash
# Mostrar solo códigos específicos
ffuf -w wordlist.txt -u https://victima.com/FUZZ -mc 200,403,500

# Mostrar todo excepto códigos específicos
ffuf -w wordlist.txt -u https://victima.com/FUZZ -fc 404,301

# Matching por rangos de códigos
ffuf -w wordlist.txt -u https://victima.com/FUZZ -mc 200-299,400-499
```

### Filtros de Expresiones Regulares

```bash
# Filtrar respuestas que contienen patrones específicos
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -fr "error|forbidden|not found"

# Mostrar solo respuestas que contienen patrones específicos  
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -mr "admin|dashboard|panel|login"

# Filtros regex complejos para APIs
ffuf -w wordlist.txt -u https://victima.com/api/FUZZ \
     -mr '"success":\s*true|"error":\s*null'
```

### Filtros de Tiempo de Respuesta

```bash
# Filtrar por tiempo de respuesta (nuevo en versiones recientes)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -ft ">2000"

# Mostrar solo respuestas rápidas
ffuf -w wordlist.txt -u https://victima.com/FUZZ -mt "<500"

# Útil para detectar diferencias en el procesamiento (ej: blind SQL injection)
ffuf -w payloads.txt -u https://victima.com/search?q=FUZZ -mt ">5000"
```

## Control de Rendimiento y Optimización

### Control de Velocidad y Concurrencia

```bash
# Limitar velocidad de peticiones (ser amable con el servidor)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -rate 50

# Pausa entre peticiones (evitar detección de WAF)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -p 0.1-2.0

# Control de hilos concurrentes
ffuf -w wordlist.txt -u https://victima.com/FUZZ -t 20

# Timeout personalizado para peticiones lentas
ffuf -w wordlist.txt -u https://victima.com/FUZZ -timeout 30
```

### Configuración de Proxies

```bash
# Proxy HTTP básico (útil para análisis con Burp Suite)
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -x http://127.0.0.1:8080

# Proxy SOCKS
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -x socks5://127.0.0.1:9050

# Replay-proxy: enviar solo matches exitosos al proxy
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -mc 200,403 -replay-proxy http://127.0.0.1:8080
```

## Manejo de Salida y Reportes

### Formatos de Salida

```bash
# Salida en JSON para post-procesamiento
ffuf -w wordlist.txt -u https://victima.com/FUZZ -o resultados.json -of json

# Múltiples formatos simultáneamente
ffuf -w wordlist.txt -u https://victima.com/FUZZ -o resultados -of all

# Salida en CSV para análisis
ffuf -w wordlist.txt -u https://victima.com/FUZZ -o resultados.csv -of csv

# Modo silencioso (solo resultados, sin banner)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -s

# Log de debug detallado
ffuf -w wordlist.txt -u https://victima.com/FUZZ -debug-log debug.log
```

## Características Avanzadas y Nuevas

### Auto-Calibración Inteligente

```bash
# Auto-calibración para detectar respuestas "normales" automáticamente
ffuf -w wordlist.txt -u https://victima.com/FUZZ -ac

# Auto-calibración con estrategias específicas (nueva característica)
ffuf -w wordlist.txt -u https://victima.com/FUZZ -ac -acc custom
```

### Modo Interactivo

```bash
# Modo interactivo para revisión de resultados en tiempo real
ffuf -w wordlist.txt -u https://victima.com/FUZZ -interactive

# Comandos disponibles en modo interactivo:
# - show: mostrar todos los matches actuales
# - savejson: guardar resultados en JSON
# - resume: continuar fuzzing pausado
```

### Uso de Archivo de Configuración

```bash
# Crear archivo de configuración ~/.config/ffuf/ffufrc
[General]
verbose = true
colors = true
maxtime = 600

[HTTP]
timeout = 30
threads = 50
rate = 100

[Output]
outputformat = json
outputfile = /tmp/ffuf-results.json

# Usar la configuración
ffuf -w wordlist.txt -u https://victima.com/FUZZ -config ~/.config/ffuf/ffufrc
```

## Casos de Uso Especializados

### Bypassing de WAFs y Protecciones

```bash
# Evasión básica de WAF con User-Agents rotatorios
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -p 1-3 -rate 5

# Fuzzing con cabeceras personalizadas para bypass
ffuf -w payloads.txt -u https://victima.com/search?q=FUZZ \
     -H "X-Originating-IP: 127.0.0.1" \
     -H "X-Forwarded-For: 127.0.0.1" \
     -H "X-Remote-IP: 127.0.0.1" \
     -rate 10

# Encoding de payloads para evasión
ffuf -w sqli_payloads.txt -u https://victima.com/search?q=FUZZ \
     -enc FUZZ:urlencode
```

### Fuzzing de Autenticación

```bash
# Fuzzing de tokens de autenticación
ffuf -w tokens.txt -u https://victima.com/api/user \
     -H "Authorization: Bearer FUZZ" \
     -mc 200,403

# Fuzzing de cookies de sesión
ffuf -w session_ids.txt -u https://victima.com/admin \
     -b "PHPSESSID=FUZZ" \
     -mc 200

# Brute force de credenciales (clusterbomb)
ffuf -w users.txt:USER -w passwords.txt:PASS \
     -u https://victima.com/login \
     -X POST -d "username=USER&password=PASS" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fc 401 -mode clusterbomb
```

### Análisis de Aplicaciones de una sola página (SPA)

```bash
# Fuzzing de endpoints de API en SPAs
ffuf -w api_endpoints.txt -u https://victima.com/api/v1/FUZZ \
     -H "Accept: application/json" \
     -H "X-Requested-With: XMLHttpRequest"

# Fuzzing de recursos estáticos en SPAs
ffuf -w js_files.txt -u https://victima.com/static/js/FUZZ \
     -e .js,.min.js,.map
```

## Estrategias Avanzadas de Wordlists

### Creación de Wordlists Personalizadas

```bash
# Combinar múltiples wordlists eliminando duplicados
cat /usr/share/seclists/Discovery/Web-Content/*.txt | sort -u > custom_wordlist.txt

# Generar wordlists basadas en el target
echo "victima" | unfurl keys | sort -u > target_specific.txt

# Wordlists específicas por tecnología detectada
# Para aplicaciones Django
echo -e "admin/\nadmin/login/\napi/\nstatic/\nmedia/" > django_paths.txt
```

### Fuzzing Inteligente con Comandos de Entrada

```bash
# Generar payloads dinámicamente con comandos
ffuf -input-cmd "seq 1 1000" -input-num 1000 \
     -u https://victima.com/user?id=FUZZ

# Combinado con herramientas externas
ffuf -input-cmd "curl -s https://wordlist-service.com/api/get" \
     -u https://victima.com/FUZZ
```

## Mejores Prácticas y Consejos Pro

### Metodología de Fuzzing Eficiente

1. **Reconocimiento Inicial**: Siempre inicia con un escaneo básico usando wordlists pequeñas para entender el comportamiento del target.[^6]
2. **Calibración de Filtros**: Realiza peticiones a recursos que sabes que no existen para identificar el patrón de respuesta 404.[^5]
3. **Fuzzing Progresivo**: Comienza con directorios principales, luego profundiza recursivamente en los hallazgos interesantes.[^8]
4. **Monitoreo de Patrones**: Observa cambios en tiempos de respuesta, tamaños y códigos de estado que puedan indicar comportamientos especiales.[^2]

### Optimización de Rendimiento

```bash
# Fuzzing optimizado para targets rápidos
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -t 100 -rate 500 -timeout 10

# Fuzzing sigiloso para targets sensibles
ffuf -w wordlist.txt -u https://victima.com/FUZZ \
     -t 5 -rate 2 -p 2-5 -timeout 30 \
     -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)"
```

### Integración en Workflows

```bash
# Pipeline completo de fuzzing
#!/bin/bash
TARGET="https://victima.com"

# 1. Fuzzing de directorios principales
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u $TARGET/FUZZ -mc 200,403,301,302 -o dirs.json -of json -s

# 2. Fuzzing recursivo en directorios encontrados
cat dirs.json | jq -r '.results[].url' | \
while read url; do
    ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
         -u $url/FUZZ -e .php,.html,.txt -mc 200 -o files_$(basename $url).json -of json -s
done

# 3. Fuzzing de parámetros en endpoints encontrados
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u $TARGET/search.php?FUZZ=test -fs $(curl -s $TARGET/search.php?nonexistent=test | wc -c)
```

## Troubleshooting y Limitaciones

### Problemas Comunes y Soluciones

```bash
# Error de conectividad - usar HTTP/1.1 forzado
ffuf -w wordlist.txt -u https://victima.com/FUZZ -http2=false

# Problemas con TLS - ignorar certificados
ffuf -w wordlist.txt -u https://victima.com/FUZZ -k

# Rate limiting - detectar y adaptar automáticamente
ffuf -w wordlist.txt -u https://victima.com/FUZZ -rate 10 -ac

# Memoria insuficiente con wordlists grandes
ffuf -w huge_wordlist.txt -u https://victima.com/FUZZ -maxtime 3600 -s
```

### Monitoreo de Progreso

```bash
# Seguimiento en tiempo real de fuzzing largo
ffuf -w wordlist.txt -u https://victima.com/FUZZ -v | tee ffuf_progress.log

# Estadísticas periódicas
watch -n 30 'tail -10 ffuf_progress.log'
```
