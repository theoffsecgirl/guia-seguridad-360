# Favicon Hash y huellas CDN/Edge

Bienvenido/a a Favicon Hash y Huellas CDN/Edge. Aquí aprenderás a usar el hash del favicon para agrupar y priorizar objetivos, y a reconocer CDNs/Edges por cabeceras, CNAME y patrones de red para decidir cómo pivotar hacia origen.

## Objetivo

- Calcular el hash del favicon (mmh3) para clusterizar activos que comparten misma app/plantilla y priorizar paneles y rutas “jugosas”.
- Identificar huellas de CDN/Edge (Cloudflare, Akamai, Fastly, CloudFront, Azure Front Door, Vercel, Netlify, etc.) para ajustar pruebas, buscar el origen y evitar falsos positivos.

## Cuándo usarlo

- Cuando hay cientos/miles de hosts y necesitas agrupar por tecnología/stack rápidamente.
- Cuando sospechas que hay CDN/WAF y necesitas decidir si pivotar a IP de origen o validar solo lógica de aplicación.

## Flujo rápido (20–30 min)

1) Saca hash de favicons a escala.
2) Agrupa por hash y prioriza clusters con títulos/login/admin/docs.
3) Detecta CDN/Edge por cabeceras y CNAME; si aplica, intenta localizar origen (legal y dentro de scope).
4) Lanza validaciones dirigidas en el cluster prioritario (no brute force ciego).

## Comandos prácticos

Hash del favicon (a escala con httpx)

```bash
# Hosts vivos (ej. de httpx/dnsx previos)
cat hosts.txt | httpx -silent -status-code -title -favicon -json -o httpx_fav.json

# Ver hashes únicos y sus URLs
jq -r 'select(.favicon_hash!=null) | "\(.favicon_hash) \(.url) \(.title) \(.status_code)"' httpx_fav.json | sort -u > fav_map.txt
```

Hash puntual en una URL (Python one‑liner)

```bash
python3 - <<'PY' https://target.tld/favicon.ico
import mmh3, requests, base64, sys
u=sys.argv[^1]; r=requests.get(u, timeout=10, verify=False)
print(mmh3.hash(base64.b64encode(r.content)))
PY
```

Búsquedas externas con el hash (OSINT)

- Shodan: http.favicon.hash:HASH
- Censys: services.http.response.favicons.mmh3_hashes: HASH
- FOFA/ZoomEye: campos equivalentes para icon_hash

Detección de CDN/Edge (headers y CNAME)

```bash
# Cabeceras reveladoras
curl -skI https://target.tld | egrep -i 'server|via|x-.*(cf|akamai|fastly|vercel|netlify|cloudfront|azure|cdn)'

# CNAME del host (pistas de proveedor)
dig +short CNAME target.tld
```

httpx “todo en uno” (cname/ip/headers)

```bash
httpx -l hosts.txt -silent -status-code -title -tech-detect -ip -cname -json -o httpx_meta.json
```

## Huellas de CDN/Edge (prácticas)

- Cloudflare: server: cloudflare, cf-ray, cf-cache-status; IPs de Cloudflare; sin CNAME público al proveedor.
- AWS CloudFront: via: 1.1 … cloudfront, x-amz-cf-pop, x-amz-cf-id; CNAME a .cloudfront.net.
- Fastly: via: 1.1 varnish, x-served-by, x-cache, x-timer.
- Akamai: CNAME a *.edgekey.net / *.edgesuite.net; a veces x-akamai-transformed, ak_bmsc.
- Azure Front Door/CDN: x-azure-ref, x-cache; CNAME a *.azureedge.net / *.trafficmanager.net.
- Vercel: server: Vercel, x-vercel-id, x-vercel-cache.
- Netlify: server: Netlify, x-nf-request-id.

Nota: no todas las instalaciones exponen las mismas cabeceras; correlaciona siempre headers + CNAME + IP.

## Qué hacer si hay CDN/WAF

- Validar lógica de app con normalidad (autorización, exposición, negocio).
- Si el programa lo permite, intenta localizar origen:
  - Buscar DNS “paralelos” (otro FQDN que apunte a la misma app sin proxy).
  - Revisar subdominios legacy (dev/staging) sin CDN.
  - Consultar documentación pública o CT para FQDN “origin”.
- Evitar fuerza bruta/DoS contra CDN; ajustar tasa y seguir límites del programa.

## Triage por clusters (favicon)

- Cluster grande + títulos que contengan login/admin/console/docs → alta prioridad.
- Hash compartido con panel conocido o software vulnerable documentado → investigar versiones/paths comunes.
- Hash “exótico” único → posible app custom; triage manual.

## Ejemplos de uso

- Filtrar cluster y listar candidatos

```bash
# HASH objetivo
HASH=123456789
awk -v h="$HASH" '$1==h{print $2,$3,$4}' fav_map.txt | sort -u > cluster.txt
```

- Validar endpoints comunes en el cluster

```bash
ffuf -w cluster.txt:URL -w endpoints.txt:EP -u URL/EP -mr "Login|Sign in|Swagger|OpenAPI" -mc 200,401,403
```

## Errores comunes a evitar

- Asumir que mismo hash = misma vulnerabilidad sin validar ruta/versión.
- Concluir que no hay origen solo porque hay CDN; muchas veces existen bypasses “legales” (otros FQDN, entornos, IPs internas vía VPN autorizada).
- Fuzzing agresivo contra Edge; siempre ajustar tasa y profundidad.

## Definition of Done (DoD)

- Mapa hash→URLs con al menos un cluster priorizado y justificación.
- Detección (o descarte razonado) de CDN/Edge para los hosts del cluster.
- Lista corta de objetivos con siguiente acción clara (validar login/admin/docs, probar autorización, buscar origen permitido).

## Checklist rápido

- ¿Hashes de favicon extraídos y clusterizados?
- ¿Cabeceras y CNAME revisados para huellas de CDN/Edge?
- ¿Se definió si se busca origen (y cómo) dentro de scope?
- ¿Se priorizaron clusters por títulos/patrones y puertos alternativos?
- ¿Comandos y evidencias mínimas registrados para reproducibilidad?
  <span style="display:none">[^4][^8][^9]</span>


[^1]: https://learn.microsoft.com/es-es/microsoft-edge/web-platform/tracking-prevention
    
[^2]: https://es.proxyscrape.com/blog/guía-definitiva-para-la-toma-de-huellas-dactilares-en-lienzo
    
[^3]: https://www.aepd.es/guias/estudio-fingerprinting-huella-digital.pdf
    
[^4]: https://mylead.global/es/blog/anonimato-en-linea-huella-digital
    
[^5]: https://woted2.com/2025/08/25/caza-de-huellas-digitales-desmitificando-el-rastreo-web-con-fingerprinting/
    
[^6]: https://www.avast.com/es-es/c-what-is-browser-fingerprinting
    
[^7]: https://achirou.com/huella-digital-del-navegador-que-es-y-como-puedes-evitar-ser-rastreado/
    
[^8]: https://www.nstbrowser.io/es/blog/tls-fingerprinting
    
[^9]: https://mamel.es/que-es-y-como-funciona-el-device-fingerprinting/
    
[^10]: https://zma.la/browser-fingerprinting-privacidad-rastreo/
