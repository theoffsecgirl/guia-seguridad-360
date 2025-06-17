# Técnica Profunda: Certificate Transparency

**Certificate Transparency (CT)** es un sistema de registros (logs) públicos, abiertos y auditables que almacenan todos los certificados SSL/TLS emitidos por las Autoridades de Certificación (CAs) confiables. El objetivo principal de CT es mejorar la seguridad del ecosistema SSL/TLS haciendo que la emisión de certificados sea transparente y detectable, ayudando a identificar certificados emitidos erróneamente o de forma maliciosa.

Para nosotros, los que estamos en seguridad ofensiva y bug bounty, estos logs son una **fuente de información valiosísima para el reconocimiento**. Como cada certificado emitido para un dominio o subdominio se registra, podemos consultar estos logs para descubrir una gran cantidad de subdominios de una organización, incluyendo aquellos que podrían no estar públicamente enlazados, que son nuevos, o que se usan para entornos de desarrollo o staging.

### Usando `crt.sh` (Interfaz Web)

`crt.sh` es un motor de búsqueda web muy popular que permite consultar los logs de Certificate Transparency.

1. **Acceso y Búsqueda Básica:**
   * Ve a `https://crt.sh/`
   * En el campo de búsqueda, puedes introducir un dominio raíz, por ejemplo, `paypal.com`.
   * Esto te mostrará los certificados donde `paypal.com` aparece en el "Common Name" (CN) o en las "Subject Alternative Names" (SANs).
2. **Búsqueda Amplia por Organización (Wildcard `%`):** Para descubrir todos los subdominios de una organización, necesitas usar el carácter comodín `%` antes del dominio raíz.
   * **Modifica la Búsqueda:** En el campo de búsqueda de `crt.sh`, introduce `%.paypal.com`.
     * `%`: Actúa como un wildcard que puede representar cero o más caracteres.
     * `%.paypal.com`: Buscará todos los certificados emitidos para `paypal.com` y cualquier subdominio de `paypal.com` (e.g., `www.paypal.com`, `api.paypal.com`, `dev.internal.paypal.com`, etc.).
   * **Resultados:** Obtendrás una lista mucho más extensa que incluye una gran cantidad de subdominios.

### Consultando `crt.sh` desde la Terminal (Programáticamente)

Aunque la interfaz web es útil, para automatizar el proceso es mucho más eficiente consultar `crt.sh` mediante su API (que devuelve JSON) usando herramientas de línea de comandos. Muchas herramientas de reconocimiento de subdominios como `amass` o `subfinder` ya integran la consulta a los logs de CT.

**Ejemplo de Script Conceptual para Consultar `crt.sh`:**

Un script básico para buscar todos los subdominios de `ejemplo.com` podría verse así:

```bash
#!/bin/bash
# Script conceptual para consultar crt.sh para un dominio dado ($1)

TARGET_DOMAIN="$1"

if [ -z "$TARGET_DOMAIN" ]; then
  echo "Uso: <span class="math-inline">0 <dominio\_raiz\>"
exit 1
fi
echo "\[\*\] Consultando crt\.sh para %\.</span>{TARGET_DOMAIN}..."
curl -s "[https://crt.sh/?q=%.<span class="math-inline">\]\(https\://crt\.sh/?q\=%\.</span>){TARGET_DOMAIN}&output=json" \
| jq -r '.[] | .name_value' \
| sed 's/\*\.//g' \
| tr '[:upper:]' '[:lower:]' \
| sort -u
```

Este script hace una petición a `crt.sh` pidiendo la salida en formato JSON, extrae los nombres de host, elimina prefijos `*.`, convierte a minúsculas y elimina duplicados.

### Truco Adicional: Extraer el Dominio Raíz de Listas de Subdominios (`rev | cut | rev`)

A menudo querrás procesar una lista de subdominios para extraer el dominio "raíz" (e.g., de `test.dev.ejemplo.com` obtener `ejemplo.com`).


echo "zone-sec-prod.us-central1.gcp.dev.paypalinc.com" | rev | cut -d "." -f 1,2 | rev
**Desglose del Truco:**

1. `rev`: Invierte la cadena (`moc.cnilapyap...`).
2. `cut -d "." -f 1,2`: Corta la cadena usando el punto como delimitador y se queda con los dos primeros campos.
3. `rev`: Vuelve a invertir el resultado para obtener `paypalinc.com`.


```
