# Técnica profunda: Certificate Transparency

Certificate Transparency (CT) es un ecosistema de logs públicos y auditables, de solo append, que registran certificados TLS/SSL emitidos por las CAs para permitir verificación y detección de emisiones erróneas o maliciosas mediante estructuras tipo Merkle tree y comprobaciones criptográficas (SCT, MMD, STH).[^2]
Para recon pasivo, CT permite descubrir dominios y subdominios incluidos en CN/SAN de certificados actuales e históricos sin tocar la infraestructura objetivo, aunque un nombre aparezca en CT no implica que el host esté vivo ni accesible.[^3]

## Por qué CT sirve en recon[^3]

- Los logs muestran todos los certificados públicos emitidos para un dominio/organización, lo que aflora FQDN de entornos dev/staging, SaaS/CDN y activos “olvidados” que no salen en buscadores.[^3]
- Navegadores y CAs exigen/usan CT desde hace años, por lo que la cobertura de DV/OV/EV es amplia y útil para mapear superficie real.[^3]

## Uso web con crt.sh (rápido)[^4]

- Búsqueda básica: introducir el dominio raíz (ej. ejemplo.com) y revisar CN/SAN de cada certificado emitido para extraer FQDN relevantes.[^4]
- Búsqueda amplia con comodín: utilizar %.ejemplo.com para listar certificados del dominio y de cualquier subdominio; recuerda que en URLs el % se codifica como %25.[^1]

Ejemplo de URL

- https://crt.sh/?q=%.ejemplo.com devuelve resultados amplios para subdominios bajo ejemplo.com en formato HTML por defecto.[^1]

## Uso programático (API JSON)[^1]

- crt.sh soporta salida JSON añadiendo el parámetro output=json a la consulta, lo que facilita automatizar extracción y limpieza.[^1]
- Ejemplo: https://crt.sh/?q=%.ejemplo.com\&output=json devuelve un array de objetos con campos como name_value, issuer_ca_id y entry_timestamp.[^1]

Notas prácticas

- name_value puede contener varias entradas separadas por saltos de línea y comodines (*.sub), por lo que conviene dividir por líneas, normalizar a minúsculas y eliminar el prefijo *. antes de deduplicar.[^5]

## Script robusto (bash + jq)[^1]

```bash
#!/usr/bin/env bash
# Uso: ./crt_dump.sh ejemplo.com
set -euo pipefail
domain="${1:?Uso: ./crt_dump.sh <dominio_raiz>}"

curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
| jq -r '.[].name_value' \
| tr '[:upper:]' '[:lower:]' \
| sed 's/^\*\.\(.*\)$/\1/' \
| tr '\r' '\n' \
| tr '|' '\n' \
| awk 'NF' \
| sort -u
```

Este pipeline obtiene JSON, extrae name_value, quita comodines, separa entradas múltiples y deduplica, generando una lista limpia de FQDN para usar en resolución/probing posterior.[^1]

## Extra: raíz/ápex rápido en shell (truco)[^6]

- Para extraer el dominio raíz de un FQDN en bash sin librerías, se puede usar rev|cut|rev sabiendo que no maneja TLD compuestos de forma perfecta (mejor usar PSL en tooling cuando importe). [^6]

```bash
echo "zone-sec-prod.us-central1.gcp.dev.paypalinc.com" \
| rev | cut -d '.' -f1,2 | rev
```

Este ejemplo devuelve paypalinc.com como ápex para listas rápidas, pero para precisión en TLD complejos conviene usar librerías con Public Suffix List.[^6]

## Integración en pipelines OSINT[^7]

- Herramientas como Amass/Subfinder consumen CT como fuente pasiva, por lo que integrar su salida con permutadores/resolución acelera la ampliación de superficie sin generar ruido activo.[^7]
- Flujos recomendados: CT → limpieza/dedupe → resolución DNS → httpx/nuclei para títulos/tech y detección de takeovers en CNAME a SaaS.[^7]

## Limitaciones y matices[^8]

- Búsquedas “contains” antiguas con %palabra% en crt.sh han cambiado soporte con el tiempo, por lo que conviene ceñirse a %.dominio y filtros post-proceso propios para text‑matching.[^8]
- CT refleja certs emitidos, no vivacidad ni alcance; siempre validar con DNS/HTTP y respetar políticas de programa antes de pasar a activo.[^2]

## Checklist operativo[^1]

- Consultar %.dominio con output=json y normalizar name_value eliminando comodines y entradas repetidas antes de resolver.[^1]
- Anotar first_seen/last_seen (cuando aparezcan) y CAs emisoras para detectar actividad reciente y proveedores/infra externas asociadas.[^1]
- Volcar FQDN limpios a la siguiente etapa de resolución/probing y etiquetar candidatos a takeover por CNAME a terceros no reclamados.[^1]
  <span style="display:none">[^13][^17][^21][^9]</span>


[^1]: https://groups.google.com/g/crtsh/c/sCpRljHP4dw
    
[^2]: https://en.wikipedia.org/wiki/Certificate_Transparency
    
[^3]: https://www.digicert.com/faq/public-trust-and-certificates/what-are-ct-logs
    
[^4]: https://crt.sh
    
[^5]: https://github.com/ur-passwd-hash/crt.sh-JSON-Parser
    
[^6]: 02b-2-certificate-transparency.md
    
[^7]: https://github.com/OWASP/Amass/wiki/User-Guide
    
[^8]: https://groups.google.com/g/crtsh/c/awLktSGX7bY
    
[^9]: https://www.reddit.com/r/bugbounty/comments/kqw0zd/here_is_a_tool_i_created_for_querying_crtsh_to/
    
[^10]: https://pkg.go.dev/github.com/dsggregory/crt.sh
    
[^11]: https://certificate.transparency.dev/howctworks/
    
[^12]: https://script.hashnode.dev/certificate-search-via-dumpcrt-crtsh-for-wide-recon
    
[^13]: https://stackoverflow.com/questions/14560393/ssl-certificate-to-json
    
[^14]: https://gist.github.com/bbhunter/0e0c5d325e1c344062fc85795e661f02
    
[^15]: https://groups.google.com/g/crtsh/c/EyRzH1IfXBM
    
[^16]: https://letsencrypt.org/docs/ct-logs/
    
[^17]: https://certificate.transparency.dev/logs/
    
[^18]: https://github.com/projectdiscovery/subfinder/issues/230
    
[^19]: https://httpie.io/docs/cli/json
    
[^20]: https://www.digicert.com/faq/certificate-transparency/what-is-certificate-transparency
    
[^21]: https://www.reddit.com/r/selfhosted/comments/11uyw5s/psa_unless_you_are_using_wildcard_certificates/
    
[^22]: https://stackoverflow.com/questions/50482326/how-to-replace-string-with-certificate-string-in-json-file-shell
