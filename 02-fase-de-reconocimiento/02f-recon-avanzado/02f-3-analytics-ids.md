# Correlación por Analytics/Ads IDs

Bienvenido/a a Correlación por Analytics/Ads IDs. Aquí aprenderás a extraer identificadores de analítica/publicidad desde HTML/JS para agrupar dominios, descubrir relaciones entre activos, priorizar superficies y, a veces, detectar entornos (dev/staging/prod) por separación de contenedores.

## Objetivo

- Extraer IDs de analítica/ads para clusterizar hosts y descubrir dominios relacionados no evidentes por DNS.
- Priorizar por clusters con logins/paneles/docs y decidir próximos pasos de verificación sin ruido innecesario.

## Cuándo usarlo

- Cuando hay muchos hosts y falta contexto de pertenencia/vertical.
- Cuando el DNS/CDN no aporta relaciones claras y se necesita un grafo de “misma organización” o “mismo producto”.

## Qué IDs buscar (patrones útiles)

- Google Analytics Universal: UA-XXXXXXXX-X
- Google Analytics 4 (gtag): G-[A-Z0-9]{8,10}
- Google Tag Manager: GTM-[A-Z0-9]+
- Google Ads/Conversion: AW-[A-Z0-9]+ o gtag('config','AW-…')
- Facebook Pixel: fbq('init','[0-9]{8,16}')
- Hotjar: hotjar-(\d+)\.js o hjid:\s*(\d+)
- Segment: analytics.load('WRITE_KEY') o window.analytics.load('…')
- Mixpanel: mixpanel.init('TOKEN')
- Amplitude: amplitude.getInstance().init('API_KEY')
- Intercom: app_id:\s*"[a-z0-9]+"
- Sentry: DSN https://<key>@o<num>.ingest.sentry.io/<project>
- Matomo: _paq.push(['setSiteId','\d+'])
- Microsoft Clarity: clarity.ms/tag/([a-z0-9]+)
- HubSpot: hubspot.setPortalId\$\$['"]?(\d+)
- New Relic Browser: NREUM… o licenseKey/xpid en bootstrap

Nota: los nombres de clave varían por integración; el objetivo es capturar el identificador estable que persiste entre entornos.

## Flujo rápido (30–45 min)

1) Obtener cuerpo HTML de portada y principales rutas (/, /login, /app, landing públicas) por host.
2) Extraer IDs con regex, y opcionalmente descargar JS estáticos y repetir extracción.
3) Generar un mapeo host→IDs y su inversión ID→hosts para crear clusters.
4) Priorizar clusters con títulos “admin/login/console/docs” y puertos alternativos.

## Extracción mínima (copy/paste)

Recolectar HTML base por host

```bash
# hosts.txt contiene FQDN o URLs (https://…)
while read h; do
  url=$(echo "$h" | sed 's#/$##')
  [ -z "$(echo "$url" | grep -E '^https?://')" ] && url="https://$url"
  echo "### $url"
  curl -skL --max-time 10 "$url" | tr -d '\r' > "html/$(echo "$url" | sed 's#https\?://##;s#/##g').html"
done < hosts.txt
```

Extraer IDs desde HTML

```bash
grep -Eoh 'UA-[0-9]{4,}-[0-9]+' html/*.html     | awk '{print $1" UA"}'
grep -Eoh 'G-[A-Z0-9]{8,10}' html/*.html        | awk '{print $1" GA4"}'
grep -Eoh 'GTM-[A-Z0-9]+' html/*.html           | awk '{print $1" GTM"}'
grep -Eoh "fbq\('init','[0-9]{8,16}'\)" html/*.html | sed "s/.*'\\([0-9]\\{8,16\\}\\)'.*/\\1 FBPIX/"
grep -Eoh 'hotjar-[0-9]+\.js' html/*.html       | sed 's/.*hotjar-\([0-9]\+\).*/\1 HOTJAR/'
grep -Eoh 'hjid[[:space:]]*:[[:space:]]*[0-9]+' html/*.html | awk '{print $NF" HOTJAR"}'
grep -Eoh "analytics\.load\('([A-Za-z0-9]+)'\)" html/*.html | sed "s/.*'\\([A-Za-z0-9]\\+\\)'.*/\\1 SEGMENT/"
grep -Eoh "mixpanel\.init\('([A-Za-z0-9]+)'\)" html/*.html  | sed "s/.*'\\([A-Za-z0-9]\\+\\)'.*/\\1 MIXPANEL/"
grep -Eoh "amplitude\.getInstance\(\)\.init\('([A-Za-z0-9]+)'\)" html/*.html | sed "s/.*'\\([A-Za-z0-9]\\+\\)'.*/\\1 AMPLITUDE/"
grep -Eoh 'app_id"[[:space:]]*:[[:space:]]*"([a-z0-9]+)' html/*.html | sed 's/.*"\([a-z0-9]\+\).*/\1 INTERCOM/'
grep -Eoh 'ingest\.sentry\.io/[0-9]+' html/*.html | sed 's/.*sentry\.io\/\([0-9]\+\).*/\1 SENTRY_PROJ/'
grep -Eoh "_paq\.push\(\['setSiteId',[[:space:]]*'([0-9]+)'\]\)" html/*.html | sed "s/.*'\([0-9]\+\)'.*/\1 MATOMO/"
grep -Eoh 'clarity\.ms/tag/([a-z0-9]+)' html/*.html | sed 's/.*tag\/\([a-z0-9]\+\).*/\1 CLARITY/'
```

Descargar JS referenciados y repetir extracción (opcional)

```bash
# Extraer src de scripts y descargar de forma simple
for f in html/*.html; do
  base=$(head -n1 "$f" | sed 's/^### //')
  grep -Eo 'src=["'\'']([^"'\''?+#]+(\.js))' "$f" | cut -d'"' -f2 | while read s; do
    case "$s" in
      http* ) js="$s" ;;
      /*    ) js="$base$s" ;;
      *     ) js="$base/$s" ;;
    esac
    out="js/$(echo "$js" | sed 's#https\?://##;s#[/?&=#]#_#g')"
    curl -skL --max-time 10 "$js" -o "$out"
  done
done
# Repetir los grep anteriores sobre js/*
```

## Agrupar por ID (clusters)

Invertir host→ID a ID→hosts

```bash
# suponiendo salida en formato: <ID> <TIPO> desde los grep (añade prefijo archivo para saber host)
# mejor construir CSV: host,id,tipo
echo "host,id,tipo" > ids.csv
for f in html/*.html; do
  host=$(basename "$f" .html)
  for id in $(grep -Eoh 'UA-[0-9]{4,}-[0-9]+' "$f"); do echo "$host,$id,UA" >> ids.csv; done
  # … añade aquí el resto de capturas por tipo …
done

# ID -> lista de hosts
awk -F, 'NR>1{print $2","$1","$3}' ids.csv | sort -u > id_to_hosts.csv
```

Priorizar clusters con títulos/login

```bash
# Unir con títulos de httpx (si los tienes en json/csv) o reconsultar headers rápidos
while IFS=, read id host tipo; do
  code=$(curl -skI --max-time 6 "https://$host/" | awk 'NR==1{print $2}')
  title=$(curl -skL --max-time 8 "https://$host/" | grep -Eo '<title>[^<]+' | sed 's/<title>//' | head -n1)
  printf "%-20s %-60s %-6s %s %s\n" "$id" "$host" "$tipo" "$code" "$title"
done < id_to_hosts.csv | tee cluster_triage.txt
```

## Heurísticas de priorización

- Mismo ID en múltiples dominios/sous: alta probabilidad de misma organización o mismo producto/SaaS tenanted.
- Clusters con titles que contengan “login”, “admin”, “console”, “swagger”, “docs” suben prioridad.
- Diferentes IDs por entorno (ej. GTM distinto en dev/prod) revelan rutas paralelas útiles para encontrar staging.
- IDs de herramientas de sesión/soporte (Intercom/Hotjar) suelen estar también en subdominios “menos cuidados”.

## Qué NO hacer

- Asumir propiedad solo por compartir ID: trátalo como heurística, confirma con otras señales (NS, CT, banners).
- Cruzar a dominios fuera de alcance solo por coincidencia de ID sin que el programa lo permita.
- Volcar claves o DSNs completos en el reporte: redacta y demuestra impacto con mínimos datos.

## Definition of Done (DoD)

- Mapa host→IDs y clusters ID→hosts con al menos un cluster priorizado y justificación.
- Evidencias mínimas: capturas de título/códigos y líneas de HTML/JS con el ID (redactadas cuando aplique).
- Siguiente acción clara por cluster (validar login, buscar docs, seguir a staging, revisar autorización).

## Checklist rápido

- ¿Extraída y normalizada la lista de IDs por host (HTML y JS principales)?
- ¿Clusterizados los IDs e identificados los hosts más prometedores por títulos/patrones?
- ¿Validado el alcance antes de pivotar a dominios correlacionados?
- ¿Evidencias y comandos registrados para reproducibilidad?

Si lo deseas, se puede añadir una versión “solo comandos” en un playbook independiente para ejecutar por bloques y volcar CSVs listos para triaje.
<span style="display:none">[^10][^3][^5][^7][^9]</span>

<div style="text-align: center">Correlación por Analytics/Ads IDs</div>

[^1]: https://www.maximaformacion.es/blog-dat/que-es-la-correlacion-estadistica-y-como-interpretarla/
    
[^2]: https://datatab.es/tutorial/correlation
    
[^3]: https://personal.us.es/vararey/adatos2/correlacion.pdf
    
[^4]: https://revistes.ub.edu/index.php/REIRE/article/download/reire2018.11.221733/23728/51454
    
[^5]: https://hackernoon.com/lang/es/canaliza-a-tu-hacker-interno-entrando-en-un-sistema-sin-nada-mas-que-un-nombre
    
[^6]: https://gurudelainformatica.es/motor-de-codigo-abierto-de-enumeracion-de-superficie-de-ataque-para-uso-ofensivo-y-defensivo
    
[^7]: https://www.agilent.com/cs/library/usermanuals/public/CS-LTS_01.11_Reference_es.pdf
    
[^8]: https://learn.microsoft.com/es-es/azure/expressroute/get-correlation-id
    
[^9]: https://www.ibm.com/docs/es/iococ?topic=analytics-mapping-content-types-properties
    
[^10]: https://blog.estudiocontar.com/2023/12/22/coeficiente-de-correlacion-de-pearson/
