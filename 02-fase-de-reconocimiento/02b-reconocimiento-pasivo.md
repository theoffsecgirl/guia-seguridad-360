# Reconocimiento Pasivo (OSINT)

El reconocimiento pasivo reúne información desde fuentes públicas sin enviar tráfico al objetivo, construyendo un mapa de activos y dependencias con “ruido cero” y bases sólidas para las siguientes fases.[^1]
El foco práctico: extraer dominios/subdominios, proveedores, rangos IP/ASN, endpoints históricos y secretos expuestos en repositorios, priorizando señales de alto valor.[^1]

## Fuentes clave[^1]

- Certificate Transparency (CT): los logs de CT exponen todos los certificados emitidos (actuales e históricos), útiles para descubrir FQDN y subdominios “ocultos” con fecha de emisión y CA.[^1]
- Motores de búsqueda (dorking): permiten filtrar contenido indexado (JS, backup, listados) y hallar pistas de endpoints o configuraciones por texto y operadores avanzados.[^1]
- ASN/BGP y rangos IP: con ASN y prefijos se descubren activos fuera de DNS y superficies perimetrales; útiles los toolkits públicos de BGP y vistas por país/organización.[^1]
- Repositorios de código: rastrear secretos y rutas internas en GitHub/GitLab con buscadores y escáneres de secretos de propósito general.[^1]
- Web histórica y rastreadores: Wayback/CommonCrawl y crawlers pasivos extraen rutas y JS históricos sin tocar el objetivo, revelando endpoints y parámetros.[^1]

## CT logs en la práctica[^1]

- crt.sh: buscador sobre CT para dominios, organizaciones, fingerprints o IDs, con datos históricos y utilidad directa para subdominios y monitorización.[^1]
- Qué mirar: CN/SAN con subdominios, fechas (primer/último visto), CAs y patrones de naming para sembrar permutaciones y priorizar superficies.[^1]

## ASN y rangos (BGP)[^1]

- Toolkits BGP: listan prefijos anunciados, peers, rutas y métricas por ASN; permiten pivotar hacia rangos infra expuestos que no aparecen en DNS.[^1]
- Vistas por país/operador: agregan ASNs y rutas por país/operador para localizar holdings y subsidiarias con prefijos relevantes.[^1]

## Repositorios y secretos[^1]

- TruffleHog: descubrimiento, clasificación y validación de secretos, con detectores amplios y verificación activa de credenciales para priorizar riesgo.[^1]
- Gitleaks: escáner de secretos OSS para repos y ficheros, con reglas configurables y salidas JSON/SARIF para integrar en pipelines o análisis local.[^1]

## Web histórica y crawlers pasivos[^1]

- Katana: crawler rápido que puede combinar crawling pasivo con fuentes como Internet Archive/CommonCrawl/OTX para mapear rutas sin golpear el objetivo.[^1]
- Qué extraer: URLs, parámetros, referencias a APIs y artefactos estáticos que contengan rutas y dominios auxiliares para pivotar.[^1]

## Flujo operativo reproducible (solo pasivo)[^1]

- CT primero: consultar crt.sh por dominio/organización y volcar FQDN y patrones de nombres para sembrar permutaciones.[^1]
- ASN/BGP: identificar ASN y prefijos con toolkits, anotando rangos v4/v6 y proveedores/peers para investigar activos no ligados a DNS.[^1]
- Repositorios: ejecutar un barrido de secretos en repos públicos relevantes y búsquedas dirigidas por organización y palabra clave.[^1]
- Web histórica: extraer URLs históricas y JS de Wayback/CommonCrawl vía herramientas de crawling pasivo para ampliar endpoints sin tráfico al target.[^1]

## Ejemplos de comandos (pasivo puro)[^1]

- Amass (intel): pivot por dominios/ASN/WHOIS sin toques activos al target, generando base para posteriores etapas.[^1]

```bash
# Descubrir dominios relacionados vía WHOIS pasivo y listar fuentes
amass intel -whois -d ejemplo.com -src -o out.txt
# Pivot por ASN y CIDR (sin tocar objetivo)
amass intel -asn 13374,14618 -cidr 104.154.0.0/15 -o asn.txt
```

- TruffleHog/Gitleaks (repos públicos): escaneo de secretos en repos accesibles para identificar credenciales/URLs internas.[^1]

```bash
# TruffleHog OS (repos públicos o paths locales)
trufflehog git https://github.com/org/repo --json > secrets.json
# Gitleaks (formato JSON para integrar)
gitleaks detect -s . -f json -o gitleaks.json
```

- Katana (pasivo): crawling con fuentes externas sin tocar el dominio objetivo directamente, útil para inventariar rutas.[^1]

```bash
# Uso pasivo combinando fuentes externas
katana -u https://ejemplo.com -passive -o urls.txt
```

## Señales de alto valor[^1]

- Subdominios “dev/staging/qa/uat” y CNAME a SaaS/CDN detectados en CT que sugieren superficie auxiliar y posibles takeovers si el recurso destino no existe.[^1]
- Prefijos/ASN con servicios perimetrales expuestos que no aparecen en DNS (VPN, paneles, almacenamiento) para investigar en fases activas posteriores.[^1]

## Checklist rápido[^1]

- CT consultado con extracción de FQDN y patrones de naming para permutaciones y priorización.[^1]
- ASN y rangos v4/v6 identificados con BGP toolkits, incluyendo peers/proveedores relevantes.[^1]
- Repos públicos analizados con escáneres de secretos y dorks de organización/tecnologías.[^1]
- URLs históricas/JS extraídos de fuentes públicas sin enviar tráfico al objetivo.[^1]

Aviso: mantener todo tráfico en esta fase dentro de fuentes públicas; cualquier interacción con el objetivo (p. ej., HTTP probing) trasládala a reconocimiento activo cumpliendo alcance y límites del programa.[^1]
<span style="display:none">[^13][^15][^17][^19][^21][^23][^25][^27][^29][^31][^33][^35][^37][^39][^41][^42]</span>

<div style="text-align: center">Reconocimiento Pasivo (OSINT)</div>

[^1]: 02b-reconocimiento-pasivo.md
    
[^2]: https://github.com/OWASP/Amass/wiki/User-Guide
    
[^3]: https://hackdb.com/item/crtsh
    
[^4]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview
    
[^5]: https://bgp.he.net
    
[^6]: https://docs.trufflesecurity.com
    
[^7]: https://docs.projectdiscovery.io/tools/katana/overview
    
[^8]: https://www.sectigo.com/resource-library/root-causes-216-what-is-crt-sh
    
[^9]: https://bgp.he.net/country/es
    
[^10]: https://github.com/gitleaks/gitleaks
    
[^11]: https://www.trickster.dev/post/katana-web-crawler-for-offensive-security-and-web-exploration/
    
[^12]: https://crt.sh
    
[^13]: https://github.com/crtsh
    
[^14]: https://keepcoding.io/blog/extraer-subdominios-con-crt-sh/
    
[^15]: https://www.reddit.com/r/PKI/comments/1m6i530/crtsh_alternatives/
    
[^16]: https://bgp.he.net/AS44570
    
[^17]: https://devguide.owasp.org/en/06-verification/02-tools/02-amass/
    
[^18]: https://bgp.he.net/irr/as-set/AS-ASN
    
[^19]: https://www.sslmarket.es/blog/certificate-transparency-registro-de-todos-los-certificados
    
[^20]: https://devguide.owasp.org/es/06-verification/02-tools/02-amass/
    
[^21]: https://www.youtube.com/shorts/d6WkHUbj7QQ
    
[^22]: https://cyberxsociety.com/complete-guide-to-amass-tool-2025-edition-from-beginner-to-pro-in-bug-bounty-recon/
    
[^23]: https://hub.steampipe.io/plugins/turbot/crtsh
    
[^24]: https://raw.githubusercontent.com/OWASP/Amass/master/doc/user_guide.md
    
[^25]: https://bgp.he.net/report/peers
    
[^26]: https://www.reddit.com/r/golang/comments/1egkhyh/made_a_subdomain_finder_using_crtsh/
    
[^27]: https://github.com/trufflesecurity/trufflehog
    
[^28]: https://trufflesecurity.com
    
[^29]: https://github.com/truffle-hog/documentation
    
[^30]: https://hexdocs.pm/truffle_hog/TruffleHog.html
    
[^31]: http://devsecopsschool.com/blog/gitleaks-a-comprehensive-devsecops-tutorial/
    
[^32]: https://docs.trunk.io/code-quality/linters/supported/trufflehog
    
[^33]: https://docs.axonius.com/docs/trufflehog
    
[^34]: https://gitleaks.io
    
[^35]: https://github.com/projectdiscovery/katana
    
[^36]: https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/trufflehog/
    
[^37]: https://www.jit.io/resources/appsec-tools/the-developers-guide-to-using-gitleaks-to-detect-hardcoded-secrets
    
[^38]: https://docs.projectdiscovery.io/opensource/katana/usage
    
[^39]: https://docs.datadoghq.com/security/default_rules/def-000-f2a/
    
[^40]: https://github.com/gitleaks
    
[^41]: https://github.com/projectdiscovery/katana/discussions/1123
    
[^42]: https://www.securecodebox.io/docs/scanners/gitleaks
