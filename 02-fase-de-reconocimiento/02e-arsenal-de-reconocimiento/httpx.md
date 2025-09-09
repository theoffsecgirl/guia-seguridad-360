# Introducción a httpx

httpx es un toolkit HTTP rápido y multi‑propósito para “probar” hosts/URLs/CIDR a escala, extrayendo estado, títulos, tecnologías, hashes y metadatos útiles; mantiene fiabilidad con alto paralelismo y retrocede de HTTPS a HTTP de forma inteligente salvo que se indique lo contrario.[^3]

## Instalación y ejecución[^4]

- Go (recomendado):

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
httpx -h
```

- Docker oficial:

```bash
docker run -it --rm projectdiscovery/httpx -h
```

## Uso básico y flujos típicos[^5]

- Leer de archivo o stdin y sacar hosts vivos:

```bash
httpx -l lista_de_subdominios.txt -silent
# o encadenado:
subfinder -d ejemplo.com -silent | httpx -silent
```

- Recopilación “rica” en una pasada:

```bash
httpx -l lista.txt -status-code -content-length -location -favicon -title -tech-detect -ip -ports 80,443,8080,8000 -probe-all-ips -follow-redirects -o salida.txt
```

Notas

- httpx acepta hosts, URLs y CIDR como entrada y puede probar múltiples puertos y rutas por host en la misma ejecución.[^3]

## Probes y metadatos útiles[^3]

- Estado/códigos y tamaño: -status-code, -content-length, -content-type.[^3]
- Redirecciones y destino: -location y -follow-redirects (con -max-redirects).[^3]
- Título y servidor: -title, -web-server.[^3]
- Tecnologías (Wappalyzer): -tech-detect.[^3]
- Favicon mmh3: -favicon para clustering por hash.[^3]
- TLS/cert y JARM: -tls-grab, -jarm, -tls-probe.[^3]
- IP, CNAME, ASN, CDN: -ip, -cname, -asn, -cdn para mapear proveedores/edge.[^3]
- HTTP/2, pipeline y vhost: -http2, -pipeline, -vhost.[^3]
- Paths y puertos: -path /ruta o -path rutas.txt, -ports http:1,2-10,https:443.[^3]

## Matchers, filtros y extracción[^3]

- Match por código/tamaño/cadenas/regex/hash/favicon: -mc/-ml/-ms/-mr/-mfc.[^3]
- Filter por códigos, error‑pages, duplicados, CDN, tiempos, DSL: -fc/-fep/-fd/-fcdn/-frt/-fdc.[^3]
- Extract regex y presets (ipv4, mail, url): -er/-ep para sacar datos del body sin herramientas extra.[^3]

## Output y almacenamiento[^3]

- Texto: -o salida.txt.[^3]
- JSONL: -json con opciones para incluir cabeceras/requests/bodies (-irh/-irr/-irrb) y cadenas de redirección (-include-chain).[^3]
- CSV: -csv con -csvo para codificación.[^3]
- Respuestas completas: -store-response y -store-response-dir para guardar cuerpo/cadena (-store-chain) y clusters visuales (-svrc con -ss).[^3]

## Concurrencia y límites de tasa[^3]

- Concurrencia: -threads N (por defecto 50).[^3]
- Rate limit: -rate-limit N (segundos) o -rate-limit-minute N.[^3]
- Retries/timeout/delay: -retries, -timeout, -delay 200ms|1s. [^3]
- Evitar fallback HTTP/HTTPS doble: -no-fallback o -no-fallback-scheme.[^3]

## Ajustes de entorno y cabeceras[^3]

- Random User‑Agent: -random-agent (por defecto true).[^3]
- Cabeceras personalizadas: -H 'Header: Value' múltiples veces.[^3]
- Proxy y SNI: -proxy http://127.0.0.1:8080, -sni nombre.[^3]
- Respecto HSTS y redirecciones: -rhsts, -follow-host-redirects.[^3]

## Ejemplos prácticos (copiar/pegar)[^5]

- Subfinder → httpx con fingerprint mínimo:

```bash
subfinder -d ejemplo.com -silent -all \
| httpx -silent -status-code -title -tech-detect -json -o httpx.json
```

- Favicon clustering y extracción de hashes:

```bash
httpx -l hosts.txt -silent -favicon -json -o fav.json
jq -r 'select(.favicon_hash!=null) | "\(.favicon_hash) \(.url)"' fav.json | sort -u
```

- Detección de CDN y CNAME en una pasada:

```bash
httpx -l hosts.txt -silent -status-code -title -ip -cname -cdn -json -o meta.json
```

- HTTP/2 y TLS/cert para huellas:

```bash
httpx -l hosts.txt -silent -http2 -tls-grab -jarm -json -o tls_h2.json
```

- Paths y puertos alternativos con límites de tasa:

```bash
httpx -l hosts.txt -silent -ports 80,443,8080,8443 -path /,/login,/swagger.json -rate-limit 200 -json -o probe.json
```

## Buenas prácticas[^2]

- Empezar con -silent y salida JSON para triage reproducible y fácil de filtrar con jq/grep/awk.[^2]
- Ajustar -threads/-rate-limit según políticas del programa y respuestas del edge/WAF; usar -fep para quitar páginas de error.[^3]
- Usar -probe-all-ips cuando existan múltiples A/AAAA para el mismo host (Anycast/Geo) y evitar falsos negativos.[^3]
- Conservar -store-response de casos interesantes para evidencias y análisis offline; redactar datos sensibles si se incluyen en reportes.[^3]

## Resumen operativo[^1]

- Entrada masiva (hosts/URLs/CIDR), probes seleccionados, match/filter precisos y output JSON/CSV con respuestas guardadas cuando importe.[^1]
- Encadenado con subfinder/naabu/nuclei permite pasar de lista teórica a superficie viva y priorizada en minutos con mínimo ruido.[^1]
  <span style="display:none">[^11][^13][^15][^17][^6][^8][^9]</span>

<div style="text-align: center">Introducción a httpx</div>

[^1]: https://docs.projectdiscovery.io/tools/httpx
    
[^2]: https://github.com/projectdiscovery/httpx
    
[^3]: https://docs.projectdiscovery.io/tools/httpx/usage
    
[^4]: https://docs.projectdiscovery.io/opensource/httpx/install
    
[^5]: https://docs.projectdiscovery.io/tools/httpx/running
    
[^6]: httpx.md
    
[^7]: https://pkg.go.dev/github.com/projectdiscovery/httpx/common/httpx
    
[^8]: https://hub.docker.com/r/projectdiscovery/httpx
    
[^9]: https://projectdiscovery.io/blog/introducing-httpx-dashboard-2
    
[^10]: https://github.com/projectdiscovery/httpx/labels
    
[^11]: https://github.com/projectdiscovery/httpx/discussions/categories/general
    
[^12]: https://www.kali.org/tools/httpx-toolkit/
    
[^13]: https://highon.coffee/blog/httpx-cheat-sheet/
    
[^14]: https://infosecwriteups.com/httpx-troubleshooting-issue-38b61549126b
    
[^15]: https://lipsonthomas.com/httpx/
    
[^16]: https://www.hackingarticles.in/a-detailed-guide-on-httpx/
    
[^17]: https://www.python-httpx.org/quickstart/
    
[^18]: https://stackoverflow.com/questions/54865824/return-json-with-an-http-status-other-than-200-in-rocket
