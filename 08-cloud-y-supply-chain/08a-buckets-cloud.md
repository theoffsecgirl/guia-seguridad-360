# S3/GCS/Azure: Exposición y URLs Firmadas

## Resumen

**Qué es:** Los buckets de almacenamiento en la nube (S3 de AWS, GCS de Google, Azure Blob) permiten guardar archivos accesibles vía HTTP(s) o APIs, y pueden generar URLs firmadas para acceso temporal o controlado.
**Por qué importa:** La mala configuración expone datos críticos, fugas masivas y facilita evasión de controles. Las URLs firmadas son un objetivo para abuso de tiempo/caducidad, phishing, privilege escalation y persistencia.
**Cuándo aplicarlo:** Especialmente relevante en pentests cloud, revisiones de supply chain y despliegues CI/CD donde apps usan buckets para recursos estáticos y dinámicos.

---

## Contexto

**Supuestos:**

- El entorno usa buckets públicos/privados y URLs generadas dinámicamente.
- El atacante puede buscar endpoints, rutas, leaks en JS, headers, logs, comprobar permisos y manipular URLs firmadas.
- Herramientas: AWS CLI, gsutil, AzCopy, s3scanner, GCPBucketBrute, Burp Suite, ffuf, Google Dorks.
- Variables en juego: Settings cross-region, roles IAM, scope de acceso (public, private, auth).

**Límites:**

- Foco en buckets web, no en el backend IAM ni scripting intra-cloud.
- No cubre vulnerabilidades de infra interna fuera de storage cloud.

---

## Metodología

1. **Reconocimiento de buckets y endpoints:**
   - Buscar rutas tipo `/storage`, `/s3`, `/bucket`, `/media`, `/static`.
   - Dorkear en Google y Github:
     `site:target.com inurl:s3`, `site:target.com inurl:storage`, `ext:json bucket`
   - Revisar JS y configuraciones expuestas: claves, endpoints, policies.
2. **Enumeración y fuerza bruta:**
   - Usar s3scanner, ffuf o GCPBucketBrute para probar listas de nombres sobre el target.
   - Probar variaciones:
     `bucket.target.com`, `target.s3.amazonaws.com`, `storage.googleapis.com/target`
3. **Revisión de URLs firmadas:**
   - Capturar URLs tipo:
     - AWS: `https://bucket.s3.amazonaws.com/file?X-Amz-Signature=...&X-Amz-Expires=...`
     - GCS: `https://storage.googleapis.com/bucket/file?GoogleAccessId=...&Expires=...&Signature=...`
     - Azure: `https://account.blob.core.windows.net/container/file?sv=...&sig=...`
   - Revisar timeout/expiration, scope, privilegios concedidos.
   - Extraer y analizar tokens, parámetros, caducidad real vs. declarada.
4. **Pruebas de acceso y abuso:**
   - Acceder a URLs firmadas y evaluar restricciones temporales, rangos de IP, scope.
   - Probar con horarios caducados, manipulación de timestamps y repetidos.
   - Compartir URL firmada entre usuarios y validar si el acceso puede persistir.
5. **Explotación de configuración y leaks:**
   - Descubrir archivos `.env`, `.bak`, config.json en buckets abiertos.
   - Revisar permisos de escritura, listar contenido (`list`), modificar archivos (`put`).
   - Evidenciar leaks mediante links directos o URLs firmadas publicadas en JS o foros.

**Checklist rápida:**

- Buckets públicos/no autenticados.
- URLs firmadas con scope inapropiado, caducidad ausente o ampliable.
- Permisos de escritura/listado sin controles de rol.
- Archivos confidenciales accesibles por GET o brute-force.

---

## Pruebas Manuales

### 1. Acceso directo a bucket

```bash
curl https://bucket.s3.amazonaws.com/
curl https://storage.googleapis.com/bucket/
curl https://account.blob.core.windows.net/container/
```

- Analiza respuestas: ¿Se puede listar, escribir, acceder sin login?

### 2. Análisis de URL firmada

```bash
curl "https://bucket.s3.amazonaws.com/confidential.pdf?X-Amz-Signature=FAKE&X-Amz-Expires=86400"
```

- Reintenta acceso tras caducidad, comparte la URL.

### 3. Dorking y búsqueda de leaks

- Buscar claves/API secrets expuestas en JS o archivos leaks:
  `site:target.com ext:env | ext:bak | ext:json"

### 4. Prueba de upload/write/list

- Usar AWS CLI/AzCopy/gsutil con credenciales obtenidas o buckets públicos:

```bash
aws s3 cp archivo.txt s3://bucket/archivo.txt
aws s3 ls s3://bucket/
gsutil cp archivo.txt gs://bucket/archivo.txt
azcopy copy archivo.txt "https://account.blob.core.windows.net/container/archivo.txt?[SAS]"
```

---

## PoC Automatizada

**Python - Comprobación masiva de URLs firmadas:**

```python
import requests
urls = [line.strip() for line in open('signed_urls.txt')]
for url in urls:
    r = requests.get(url)
    print(url, r.status_code)
```

**Script brute-force buckets:**

```bash
while read bucket; do
  aws s3 ls s3://$bucket/ && echo "ABIERTO: $bucket"
done < buckets.txt
```

**Extraer URLs firmadas en JS:**

```bash
grep -o 'https://[[:alnum:]/_.-]*[?&]X-Amz-Signature=[^"\']*' *.js
```

---

## Explotación y Automatización

- Compartir URLs firmadas para acceso persistente.
- Automatizar acceso masivo para enumeración/listado.
- Manipular timestamps y firmas para reusar/abusar permisos.
- Crear archivos maliciosos en buckets con escritura permitida.
- Monitoring de URLs en JS/front para leaks repetidos.

---

## Impacto

- **Data breach masivo:** Acceso y extracción de datos confidenciales.
- **Persistent access:** Uso repetido de URLs firmadas sin caducidad real.
- **Privilege escalation:** Escritura, borrado o modificación de archivos críticos.
- **Supply chain abuse:** Subida de malware en artefactos o repositorios.
- **Phishing:** Uso de URLs como trampas temporales/engañosas.

**Mapeo OWASP/CWE:** API3 Excessive Data Exposure, CWE-284 Improper Access Control, API7 Security Misconfiguration.

---

## Detección

- Logs de acceso no autorizado a buckets y archivos.
- Requests masivos a URLs firmadas fuera de ventana aceptada.
- Alertas por intentos de escritura/listado.
- Registro de compartición de URLs entre cuentas/dominios.
- Análisis de leaks en JS/HTML/static deploys.

---

## Mitigación

- Configurar buckets como privados salvo requerimiento expreso.
- Válida expiración y scope en URLs firmadas (mínimo viable).
- Aplicar roles IAM estrictos y segregación de permisos de escritura/listado.
- Rotar claves, limpiar leaks y definir política de saneamiento de artefactos.
- Monitorizar y auditar logs de acceso y cambios en buckets.

---

## Errores Comunes

- Confiar en autenticación client-side para buckets públicos.
- Caducidad inadecuada en URLs firmadas (excesiva o renovable).
- Permitir `list`/`write` sin roles/escopos robustos.
- Publicar artefactos o config en buckets sin saneamiento.
- No auditar leaks periódicamente ni revisar JS después de deploys.

---

## Reporte

**Título:** Bucket cloud expuesto y URLs firmadas mal gestionadas permiten fuga masiva, persistencia y abuso
**Impacto:** Acceso no autorizado, data breach, supply chain, persistencia y privilege escalation
**Pasos:**

1. Enumerar/accder bucket, probar URL firmada y manipular/build artefactos
2. Evidencias de acceso/reuse y extracción de contenido
3. Impacto en datos, recursos y supply chain
   **Mitigación:** Privacidad y roles estrictos, URLs temporales/caducas, saneamiento y auditoría exhaustiva
