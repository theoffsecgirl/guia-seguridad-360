# Playbooks de Pivot (host→IP→vecinos→buckets)

Bienvenido/a a los Playbooks de Pivot. Esta sección encadena pivotes prácticos para multiplicar superficie: partir de un host, obtener su IP, descubrir vhosts vecinos en la misma IP y terminar correlacionando buckets públicos (S3/GCS/Azure) asociados. Todo con bajo ruido, pasos reproducibles y evidencias mínimas.

## Objetivo

- Pasar de un FQDN a sus IPs reales, detectar CDN/Edge y, si está permitido, validar origen con overrides controlados.
- Mapear vhosts vecinos en la misma IP mediante TLS/SAN, PTR, vhost brute y probing.
- Derivar nombres de buckets desde patrones de naming y verificar, sin escritura, si existe exposición pública.

## Cuándo usarlo

- Cuando DNS/CDN devuelve poca señal y se necesita contexto real de infraestructura.
- Cuando se detectan IPs de origen o rangos del objetivo/proveedor y hay que exprimir vecinos y artefactos estáticos.

---

## Playbook 1 — Host → IP → posible origen (con cuidado)

Pasos

1) Resolver A/AAAA y CNAME del host y registrar IPs y cadenas de CNAME.
2) Capturar headers iniciales para detectar CDN/Edge (cf-ray, via, x-amz-cf, x-azure-ref, x-vercel-id, etc.).
3) Si el alcance lo permite y conoces la IP de origen, usar override puntual solo para validar lógica sin el intermediario.

Comandos

```bash
# DNS y metadatos rápidos
dig A www.objetivo.tld +short
dig AAAA www.objetivo.tld +short
dig CNAME www.objetivo.tld +short

# Headers reveladores
curl -skI https://www.objetivo.tld | egrep -i 'server|via|cf-|x-(akam|amz|azure|fastly|vercel|netlify|cdn)'

# Override puntual (no tocar /etc/hosts)
curl --resolve "www.objetivo.tld:443:IP_ORIGEN" -skI https://www.objetivo.tld/
```

Evidencias mínimas

- IPs y CNAME, primer bloque de cabeceras, y si procede, respuesta del override con timestamp.

---

## Playbook 2 — IP → vhosts vecinos (SAN/PTR/vhost brute)

Pasos

1) Extraer CN/SAN del certificado en la IP para obtener nombres “conocidos” en el mismo servicio.
2) Obtener PTR (reverse DNS) de la IP.
3) Probar vhosts con Host header directo contra la IP para detectar virtual hosts no publicados por DNS.
4) Probing HTTP de candidatos y priorización por título/código/tecnología.

Comandos

```bash
# Cert → CN/SAN desde IP (443)
echo "IP_OBJETIVO:443" | sed 's/$/\n/' > ip_port.txt
tlsx -l ip_port.txt -san -cn -silent -resp-only > san.txt

# PTR de la IP
dig -x IP_OBJETIVO +short

# Vhost brute contra la IP (derivado de SAN + wordlist semilla)
cat san.txt | awk '{print $1}' | sort -u > vhosts.txt
ffuf -w vhosts.txt -H "Host: FUZZ" -u https://IP_OBJETIVO/ -mc 200,301,302,401,403 -fs 0 -t 40

# Probing masivo (si hay varias IPs de interés)
httpx -l vhosts.txt -silent -status-code -title -tech-detect -json -o httpx_vhosts.json
```

Heurísticas

- Subir prioridad si hay títulos con login/admin/docs, 401/403 en rutas sensibles, o tecnologías con versiones en banner.

---

## Playbook 3 — Vecinos → endpoints/artefactos útiles

Pasos

1) Crawling ligero y fuzzing de rutas comunes para artefactos: /swagger.json, /openapi, /docs, /.git, /.env, /backup.zip.
2) Analizar JS estáticos para extraer endpoints y dominios auxiliares (CDN/static).
3) Capturas rápidas para triage visual.

Comandos

```bash
# Fuzzing base controlado
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://VHOST/FUZZ -mc 200,204,301,302,401,403 -fs 0

# Endpoints desde JS
python3 linkfinder.py -i https://VHOST/app.js -o cli | tee endpoints.txt

# Screenshots a escala (sobre 200/401/403)
gowitness file -f urls.txt --threads 8 --timeout 10 -P out_shots
```

Notas

- Ajustar tasa/profundidad; registrar filtros (-fs/-fw/-fc) para reproducibilidad.

---

## Playbook 4 — Host/vecinos → Buckets (S3/GCS/Azure) sin escribir

Idea

- Derivar candidatos de bucket a partir de subdominios, marcas, regiones y patrones típicos; verificar existencia y permisos con GET/HEAD y CLIs en modo sin credenciales. Nada de escritura.

Patrones comunes

- S3: bucket.s3.amazonaws.com, s3.amazonaws.com/bucket, bucket.s3-website-REGION.amazonaws.com
- GCS: storage.googleapis.com/bucket, gs://bucket
- Azure Blob: https://ACCOUNT.blob.core.windows.net/CONTAINER, static website: https://ACCOUNT.zX.web.core.windows.net/

Generación de candidatos

```bash
# Derivar nombres desde FQDN (simplista; ajusta a tu PSL)
awk -F. '{print $(NF-1)}' vhosts.txt | sort -u > bases.txt
# Añadir sufijos/prefijos frecuentes
while read b; do
  for s in static assets media cdn files uploads downloads public content; do
    echo "$b-$s"; echo "$s-$b"; echo "$b.$s"; 
  done
done < bases.txt | tr '[:upper:]' '[:lower:]' | sort -u > buckets.txt
```

Verificación S3 (solo lectura)

```bash
# HEAD/GET sin firma
while read b; do
  echo "s3://$b"
  curl -skI "https://$b.s3.amazonaws.com/" | head -n 1
  curl -sk "https://$b.s3.amazonaws.com/?list-type=2&max-keys=1" | head -n 5
  aws s3 ls "s3://$b" --no-sign-request --region us-east-1 2>&1 | head -n 2
done < buckets.txt
```

Verificación GCS

```bash
while read b; do
  echo "gs://$b"
  curl -skI "https://storage.googleapis.com/$b" | head -n 1
  gsutil ls -b "gs://$b" 2>&1 | head -n 3
done < buckets.txt
```

Verificación Azure Blob (listing de contenedor)

```bash
# Para cada cuenta candidata, probar website público y listing de contenedor común "public"
while read acct; do
  curl -skI "https://$acct.z6.web.core.windows.net/" | head -n 1
  curl -sk "https://$acct.blob.core.windows.net/public?restype=container&comp=list" | head -n 5
done < accounts.txt
```

Evidencias mínimas

- Código de estado y primeras líneas de respuesta; si hay listing, capturar solo 1–3 entradas y redactar nombres sensibles.

---

## Playbook 5 — Buckets → correlación y riesgos

Pasos

1) Si el bucket lista contenido, identificar archivos estáticos que referencien dominios del objetivo (JS, mapas, logos).
2) Revisar permisos: lectura anónima del bucket/objeto, CORS permisivo, configuración de website público.
3) Si hay escritura habilitada (raro), no escribir; reportar de inmediato como crítico con pruebas mínimas no destructivas (HEAD/OPTIONS).

Comandos

```bash
# CORS en S3 (si el endpoint lo expone)
curl -skI -X OPTIONS "https://BUCKET.s3.amazonaws.com/obj.txt" -H "Origin: https://tu.dominio" -H "Access-Control-Request-Method: GET"

# Comprobación de website S3
curl -skI "http://BUCKET.s3-website-us-east-1.amazonaws.com/"
```

Mitigaciones (para informe)

- Cerrar listing público, bloquear ACLs anónimas y políticas de bucket, mover artifacts sensibles fuera del bucket público, deshabilitar website si no es necesario.

---

## Scoring y priorización

Puntúa alto si:

- Vhosts con login/admin/docs en la misma IP y headers coherentes con origen común.
- Buckets que listan contenido o devuelven 200/403 con claves reveladoras (website activo, CORS permisivo).
- Artefactos en JS/HTML que referencian rutas internas o dominios auxiliares del mismo propietario.

---

## OPSEC y límites

- Ejecutar desde VPS propio y con límites de tasa; documentar alcance y excluir terceros no permitidos.
- En buckets, nunca escribir ni borrar; solo HEAD/GET/OPTIONS y listados mínimos.
- Redactar cualquier identificador sensible en evidencias.

---

## Definition of Done (DoD)

- Host → IP(s) + CNAME + headers con indicios de CDN/Edge u origen.
- Lista de vhosts vecinos confirmados (por SAN/PTR/vhost brute) con estado/título/tecnología.
- Conjunto de buckets candidatos verificados (existencia/estado/listing) con evidencias mínimas.
- 3–5 candidatos priorizados con “siguiente acción” clara (validar auth, revisar docs, reporte de exposición).

---

## Checklist rápido

- ¿Resueltas A/AAAA/CNAME y capturados headers iniciales?
- ¿Extraídos CN/SAN y PTR; probado vhost brute contra IP?
- ¿Hecho crawling/fuzzing ligero y análisis de JS en vecinos?
- ¿Generados y verificados buckets S3/GCS/Azure sin escritura?
- ¿Evidencias mínimas, timestamps y comandos guardados para reproducibilidad?

¿Quieres una versión “solo comandos” en un playbook separado para ejecutar por bloques y volcar CSVs/JSON listos para triaje?
<span style="display:none">[^10][^3][^5][^7][^9]</span>

<div style="text-align: center">Playbooks de Pivot (host→IP→vecinos→buckets)</div>

[^1]: https://www.youtube.com/watch?v=E4eUdAd6tAM
    
[^2]: https://es.scribd.com/document/585305851/The-Hacker-Playbook-3-Practical-Guide-to-Penetration-Testing-Peter-Kim-Z-lib-org-1
    
[^3]: https://www.youtube.com/watch?v=Kimrp9WZPTU
    
[^4]: https://www.zerolynx.com/en/blogs/news/ligolo-ng
    
[^5]: https://www.youtube.com/watch?v=zGm7kUvC31M
    
[^6]: https://www.youtube.com/watch?v=qXvkRfMJAtw
    
[^7]: https://www.youtube.com/watch?v=_7b_GQDfA5M
    
[^8]: https://achirou.com/osint-32-600-herramientas-osint-academico-y-papers/
    
[^9]: https://www.youtube.com/watch?v=l3IEnXYVjWw
    
[^10]: https://0xword.com/libros/160-empire-hacking-avanzado-en-el-red-team.html
