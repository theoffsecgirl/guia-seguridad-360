# TLS/HTTP2 Fingerprinting y .well-known

Cómo usar fingerprints de TLS/HTTP2 para identificar stacks, CDNs/Edges y clientes, y cómo extraer señales de endpoints .well-known para mapear identidad, auth y políticas sin ruido.

## Objetivo

- Clusterizar hosts por huellas de TLS (JA3/JA3S), ALPN y rasgos HTTP/2; detectar CDN/Edge y decidir si buscar origen.
- Extraer metadatos de /.well-known para descubrir endpoints de autenticación, móviles, correo y políticas de seguridad.

## TLS fingerprinting (server y cliente)

- JA3 (cliente) y JA3S (servidor) permiten identificar librerías/proxies y agrupar superficies por misma pila TLS.
- Señales: versión TLS negociada, orden de cipher suites y extensiones, SNI, ALPN y JA3/JA3S repetidos entre hosts.

Comandos prácticos

```bash
# Negociación TLS + ALPN (confirmar h2/h3)
openssl s_client -alpn h2 -connect objetivo.tld:443 -servername objetivo.tld </dev/null 2>/dev/null | egrep -i 'ALPN|Protocol|Cipher|Verify'

# TLS scan (JA3/JA3S/ALPN) a escala con salida simple
tlsx -l hosts.txt -ja3 -ja3s -alpn -cn -sni -silent -resp-only > tls_meta.txt
```

Uso en recon

- Agrupar por mismo JA3S/ALPN y cert chain para detectar apps clonadas en múltiples dominios o el mismo origin detrás de distintos nombres.
- Diferencias de ALPN/ciphers entre subdominios suelen delatar saltos de proveedor (p. ej., app vs estáticos/CDN).

## HTTP/2 fingerprinting (client/protocol)

- Rasgos útiles: orden de pseudo‑headers (:method, :scheme, :authority, :path), orden y valores de SETTINGS, PRIORITY/WINDOW_UPDATE y ALPN.
- Anti‑bot modernos distinguen navegadores reales de librerías HTTP/2 por estos detalles; en recon sirve para entender dónde habrá fricción.

Comandos prácticos

```bash
# Confirmar soporte h2 y cabeceras de respuesta
curl -skI --http2 https://objetivo.tld/

# Ver frames/SETTINGS detallados (nghttp2)
nghttp -v https://objetivo.tld/ 2>&1 | sed -n '1,120p'
```

Uso en recon

- Si ciertos hosts responden peculiar (h2 obligado, prioridades específicas), priorizar prueba manual en navegador/Proxy para evitar falsos negativos por tooling.
- Clusters con misma “firma h2” + mismo JA3S suelen compartir mismo edge/origen.

## Detección rápida de CDN/Edge

- Señales: cabeceras (cf-ray, via, x-amz-cf, x-akamai, x-azure-ref, x-vercel-id), CNAME a proveedores (*.cloudfront.net, *.edgekey.net, *.azureedge.net, etc.), y rangos IP del proveedor.
- Decisión: validar lógica vía Edge o, si el alcance lo permite, buscar origen paralelo (subdominios legacy/dev sin CDN).

Comandos prácticos

```bash
# Cabeceras y CNAME en lote
httpx -l hosts.txt -silent -status-code -title -tech-detect -ip -cname -json -o httpx_meta.json

# Headers reveladores (spot-check)
curl -skI https://objetivo.tld | egrep -i 'server|via|cf-|x-(akam|amz|azure|fastly|vercel|netlify|cdn)'
```

## Endpoints .well-known que importan

- security.txt: contacto e incluso alcance; ruta: /.well-known/security.txt
- mta-sts: política de MTA‑STS (correo); /.well-known/mta-sts.txt y host mta-sts.dominio
- openid-configuration: descubrimiento OIDC; /.well-known/openid-configuration
- apple-app-site-association (AASA): Universal Links iOS; /.well-known/apple-app-site-association
- assetlinks.json: Android App Links; /.well-known/assetlinks.json
- change-password: URL de cambio de contraseña; /.well-known/change-password
- dnt-policy/gpc.json: políticas de privacidad/señales; /.well-known/dnt-policy.txt, /.well-known/gpc.json
- pki-validation/acme-challenge: validaciones de CA; /.well-known/pki-validation/, /.well-known/acme-challenge/
- host-meta/webfinger: federación/identidad; /.well-known/host-meta, /.well-known/webfinger

Comandos (lote)

```bash
# Consultar .well-known clave en todos los hosts
while read h; do
  for p in security.txt mta-sts.txt openid-configuration apple-app-site-association assetlinks.json change-password dnt-policy.txt gpc.json; do
    url="https://$h/.well-known/$p"
    code=$(curl -skI --max-time 8 "$url" | awk 'NR==1{print $2}')
    [ -n "$code" ] && printf "%-40s %3s\n" "$url" "$code"
  done
done < hosts.txt | tee wellknown_scan.txt
```

Cómo explotar señales

- OIDC: endpoints de auth/token/jwks, issuer y audiencias; pivot directo a pruebas de flujo y configuración.
- AASA/AssetLinks: bundle IDs, package names y hashes de cert; correlación con apps móviles del mismo propietario.
- MTA‑STS: dominios MX y políticas de correo; enumeración de proveedores y exposición colateral.
- security.txt: contactos, ventanas, políticas; base para disclosure y para entender límites reales.

## Pipelines listos (clustering y triage)

TLS/HTTP2 → clusters

```bash
# TLS meta + soporte h2
tlsx -l hosts.txt -ja3s -alpn -cn -sni -silent > tls.txt
httpx -l hosts.txt -silent -http2 -status-code -title -json -o http2.json

# Cluster por (JA3S, ALPN, CN)
awk '{print $1,$2,$3,$4}' tls.txt | sort | uniq -c | sort -nr | head -n 50
```

.well-known → señales de negocio

```bash
# Extraer OIDC y endpoints útiles
grep -E '/\.well-known/openid-configuration' wellknown_scan.txt | awk '{print $1}' | while read u; do
  curl -sk "$u" | jq -r '.issuer,.authorization_endpoint,.token_endpoint,.jwks_uri'
done
```

## Heurísticas de priorización

- Mismo JA3S + misma cadena de certificado + mismo ALPN → alta probabilidad de misma app/origen; priorizar título/login/APIs.
- .well-known OIDC/AASA/AssetLinks presentes → activos maduros con superficies móviles y auth documentada.
- Edge detectado con cabeceras y CNAME claros → validar lógica; si el alcance lo permite, buscar origen paralelo para pruebas específicas.

## OPSEC y límites

- Mantener tasas moderadas; evitar cargar endpoints .well-known repetidamente sin utilidad.
- No abusar de nghttp/openssl en bucle con tiempos agresivos; tomar muestras representativas.
- Validar alcance antes de pivotar a dominios correlacionados por .well-known (apps móviles o MX de terceros).

## Definition of Done (DoD)

- Clusters TLS/HTTP2 con justificante (JA3S/ALPN/cadena) y lista corta priorizada.
- Matriz de .well-known detectados por host con enlaces a endpoints críticos (OIDC, AASA/AssetLinks, security.txt, MTA‑STS).
- Próximas acciones objetivas por cluster (auth/flows, mobile links, origen, pruebas lógicas).

## Checklist rápido

- ¿Recogidos JA3S/ALPN y confirmada compatibilidad h2 por host?
- ¿Detectadas huellas de CDN/Edge (headers/CNAME/IP)?
- ¿Consultados .well-known clave y extraídas rutas OIDC/móviles/políticas?
- ¿Clusters y candidatos con títulos/login/API priorizados?
- ¿Comandos y salidas guardadas (JSON/CSV) para reproducibilidad?
  <span style="display:none">[^3][^7][^9]</span>


[^1]: https://www.scrapeless.com/en/blog/bypass-https2
    
[^2]: https://www.adspower.com/es/blog/tls-fingerprinting-techniques-and-bypassing-methods
    
[^3]: https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2020-04-1/NET-2020-04-1_04.pdf
    
[^4]: https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html
    
[^5]: https://www.trickster.dev/post/understanding-http2-fingerprinting/
    
[^6]: https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
    
[^7]: https://www.ids-sax2.com/mastering-tls-fingerprint-blocking-techniques-for-bypassing-fingerprint-recognition-and-anti-crawling-shields/
    
[^8]: https://www.peakhour.io/learning/fingerprinting/what-is-http2-fingerprinting/
    
[^9]: https://httptoolkit.com/blog/tls-fingerprinting-node-js/
    
[^10]: https://blog.cloudflare.com/id-id/ja4-signals/
