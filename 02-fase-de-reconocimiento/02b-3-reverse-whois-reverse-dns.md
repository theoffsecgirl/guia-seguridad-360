# Reverse WHOIS y Reverse DNS

El objetivo es descubrir dominios relacionados por un mismo registrante/contacto y mapear qué nombres están o han estado alojados detrás de una IP concreta, ampliando superficie de forma pasiva y con bajo ruido operacional. Estas técnicas ayudan a encontrar marcas, entornos paralelos, proveedores y activos “olvidados” que no aparecen en búsquedas web tradicionales.[^9]

## Reverse WHOIS en corto[^9]

Reverse WHOIS agrupa dominios por atributos de registro como email, organización, teléfono o dirección, permitiendo pivotar desde un dato de contacto a todos los dominios asociados histórica o actualmente. Es útil para descubrir holdings, subsidiarias, dominios de campañas, entornos de test y compras recientes antes de que existan enlaces públicos o indexación completa. Las protecciones de privacidad y GDPR limitan datos visibles en muchos TLDs, por lo que conviene combinar atributos, históricos y otras fuentes pasivas para mejorar cobertura.[^9]

## Reverse DNS en corto[^9]

Reverse DNS (rDNS) resuelve una IP a su PTR principal y, complementado con fuentes pasivas, ayuda a listar hostnames que apuntan o apuntaron a esa IP en el tiempo. En producción es habitual encontrar CDNs y balanceadores compartidos, por lo que hay que distinguir el PTR “canónico” de la IP de los múltiples FQDN que resuelven hacia ella. Este pivotado es ideal para cazar paneles, edge services y dominios “huérfanos” cuando ya se conoce un bloque o un origen detrás de un CDN/WAF.[^9]

## Cuándo usar cada uno[^9]

- Reverse WHOIS: cuando existe un contacto, nombre de organización o patrón de correo y se desea el conjunto de dominios asociados a esa entidad para ampliar el grafo de activos.[^9]
- Reverse DNS: cuando se conoce una IP de origen, un rango ASN o una IP de proveedor y se desea listar hostnames alojados allí para priorizar exposición directa y paneles perimetrales.[^9]

## Limitaciones y matices[^9]

- WHOIS moderno tiene datos enmascarados y requiere correlación con históricos, NS, MX, registros CT y huellas técnicas para ser efectivo.[^9]
- rDNS solo da un PTR “principal”; para obtener el set de dominios que terminan en esa IP hace falta apoyo de fuentes pasivas y cruce con resoluciones previas del propio recon.[^9]

## Flujo operativo recomendado[^9]

- Paso 1 — Sembrado: obtener WHOIS/registrante del dominio conocido y recopilar variantes de nombre legal, emails corporativos y patrones de contacto para pivotar por atributos múltiples sin depender de un único campo.[^9]
- Paso 2 — Reverse WHOIS: agrupar dominios por email/organización/teléfono y añadirlos al inventario; cruzar con NS/MX para detectar proveedores y familias tecnológicas.[^9]
- Paso 3 — Reverse DNS: para IPs de origen o rangos identificados, consultar PTR y enriquecer con resoluciones previas/CT para enumerar FQDN que apuntan a la IP.[^9]
- Paso 4 — Validación: resolver A/AAAA de los nuevos FQDN y pasar un probing HTTP pasivo/ligero priorizando admin/api/dev/staging y puertos alternativos si el alcance lo permite más tarde.[^9]

## Señales de alto valor[^9]

- Cambios recientes de registrador/NS o dominios con misma organización pero en TLDs distintos que apunten a proveedores diferentes sugieren entornos paralelos y migraciones en curso.[^9]
- PTR con nomenclatura de orígenes (origin, backend, app, api) o footprints de proveedores cloud sin CDN delante suelen indicar superficies menos endurecidas.[^9]

## Comandos útiles (pasivo)[^9]

```bash
# WHOIS de dominio/IP (titularidad, fechas, NS/MX)
whois ejemplo.com
whois 203.0.113.10
```

```bash
# PTR (reverse DNS) de una IP
dig -x 203.0.113.10 +short
host 203.0.113.10
nslookup -type=PTR 203.0.113.10
```

```bash
# Extraer apex de una lista (simple, no PSL-aware)
awk -F. '{print $(NF-1)"."$NF}' subs.txt | sort -u
```

Estas consultas no tocan aplicaciones del objetivo y sirven para construir el grafo inicial de dominios, contactos, IPs y hostnames de manera reproducible y con bajo ruido.[^9]

## Heurísticas de correlación[^9]

- Coincidencia de email corporativo en WHOIS + coincidencia de NS/MX y mismas regiones cloud puntúa alto para pertenencia a la misma entidad.[^9]
- Dominios con mismo patrón de naming + mismos proveedores de CDN/DNS + CT reciente elevan prioridad para exploración posterior.[^9]

## Tabla rápida de diferencias[^9]


| Técnica      | Entrada                       | Salida esperada             | Uso típico                              |
| :------------ | :---------------------------- | :-------------------------- | :--------------------------------------- |
| Reverse WHOIS | Email/organización/teléfono | Lista de dominios asociados | Expandir holdings y marcas[^9]           |
| Reverse DNS   | IP/ rango                     | PTR y hostnames vinculados  | Localizar hostnames en una IP origen[^9] |

## Checklist rápido[^9]

- Se normalizaron variantes de nombre/empresa y correos para buscar dominios por múltiples atributos en reverse WHOIS.[^9]
- Se consultó PTR para IPs de origen y se cruzó con resoluciones y CT previas para listar FQDN históricos y actuales.[^9]
- Se clasificaron los hallazgos por probabilidad de exposición (admin/api/dev/staging y puertos alternativos) para fases activas posteriores.[^9]

## Plantillas de notas[^9]

- Reverse WHOIS
  - Atributo: email/organización/teléfono → dominios encontrados → NS/MX/registrador → decisión GO/NO‑GO y próximos pasos.[^9]
- Reverse DNS
  - IP/rango → PTR → FQDN correlacionados → resoluciones actuales → prioridad y puerto objetivo para validación posterior.[^9]

## Consejos de calidad[^9]

- Documentar fuentes y timestamps de cada pivot para reproducibilidad y para diferenciar cambios legítimos de señales de riesgo.[^9]
- No asumir propiedad solo por coincidencia de proveedor; requerir al menos dos evidencias independientes antes de atribuir un dominio a una organización.[^9]

Con este módulo, el pivot entre contactos de registro e infraestructura de red queda sistematizado para ampliar el inventario sin generar tráfico hacia el objetivo, manteniendo trazabilidad y priorización orientadas a hallazgos accionables en fases activas.[^9]
<span style="display:none">[^4][^8]</span>


[^1]: https://whoisfreaks.com/resources/blog/mastering-whois-osint-for-effective-domain-and-ip-investigations
    
[^2]: https://osinttraining.net/guide/how-do-we-find-out-about-who-is-behind-a-website/reverse-whois-searching/
    
[^3]: https://hatless1der.com/osint-quick-tips-beyond-whois/
    
[^4]: https://securedebug.com/mastering-passive-information-gathering-an-ultra-extensive-guide-to-open-source-intelligence-osint-and-reconnaissance/
    
[^5]: https://www.authentic8.com/blog/OSINT-techniques-and-tools-guide
    
[^6]: https://www.cyberquizzer.com/blog/osint-domain-intelligence-gathering
    
[^7]: https://www.alphabin.co/blog/guide-to-open-source-intelligence-osint
    
[^8]: https://osintteam.blog/dns-whois-osint-applications-2f186ed2cd97
    
[^9]: 02b-2-certificate-transparency.md
