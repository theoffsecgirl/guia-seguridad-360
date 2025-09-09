# Técnica profunda: Google Dorking

Google Dorking usa operadores avanzados de búsqueda para filtrar resultados y encontrar señales útiles (docs expuestos, endpoints, paneles) sin tocar la infraestructura del objetivo, porque las peticiones las hace Google, no el auditor.[^1]
Es ideal para reconocimiento pasivo de alto valor cuando se combinan operadores con lógica y fechas para acotar ruido y ganar actualidad.[^2]

## Operadores esenciales (con propósito)[^1]

- site: limita resultados a un dominio o subdominio, permitiendo explorar la huella indexada por Google con foco quirúrgico.[^1]
- "frase exacta": obliga a que aparezca exactamente la cadena indicada, reduciendo drásticamente el ruido en consultas sensibles.[^1]
- -término: excluye palabras o dominios para depurar resultados y evitar falsos positivos.[^1]
- OR: combina alternativas en una misma consulta sin perder precisión cuando se buscan variantes de un concepto.[^1]
- inurl: busca texto en la URL para detectar rutas, parámetros y tecnologías expuestas útiles para pruebas posteriores.[^3]
- intitle: busca en el título HTML de la página, excelente para localizar paneles o listados “Index of”.[^3]
- filetype: o ext: filtra por tipo de archivo (pdf, xls, log, sql, env, conf) para encontrar documentos y artefactos sensibles.[^1]
- allintitle:/allinurl: obliga a que múltiples términos estén todos en título/URL, afinando aún más las coincidencias.[^4]
- before:/after:: filtra por fecha en formato YYYY-MM-DD para recortar a ventanas temporales concretas o contenido reciente.[^2]

Notas de sintaxis: no dejes espacios entre el operador y el valor (ej. site:ejemplo.com), y combina comillas, OR y exclusiones para controlar el conjunto resultante.[^5]

## Plantillas rápidas por objetivo[^6]

- Subdominios y endpoints
  - site:ejemplo.com -www inurl:/ api OR dev OR test OR staging para rastrear superficies más allá de la portada y localizar rutas de API.[^1]
  - site:*.ejemplo.com -site:www.ejemplo.com inurl:/ intitle:login para listar subdominios con login, asumiendo soporte de comodín en algunos casos.[^7]
- Archivos y secretos
  - site:ejemplo.com (filetype:pdf OR filetype:xls OR filetype:docx) "confidencial" para documentos sensibles indebidamente indexados.[^1]
  - site:ejemplo.com (ext:env OR ext:ini OR ext:conf) (intext:"password" OR intext:"secret") -site:github.com para localizar configuración con secretos expuestos.[^6]
- Parámetros interesantes
  - site:ejemplo.com inurl:"id=" OR inurl:"user=" para pivotar hacia IDOR/BOLA en fases activas posteriores.[^3]
  - site:ejemplo.com inurl:"redirect=" OR inurl:"next=" OR inurl:"returnUrl=" para sospecha de open redirect a validar luego.[^3]
  - site:ejemplo.com inurl:"file=" OR inurl:"path=" para posibles LFI/Traversal si la app resuelve rutas del lado servidor.[^3]
- Paneles y listados
  - site:ejemplo.com (intitle:"login" OR inurl:"login") -intext:"empleados" -intext:"clientes" para login no corporativos comunes.[^3]
  - site:ejemplo.com intitle:"index of" -intext:"Parent Directory" para listados de directorios simples con menor ruido.[^3]
- Recencia y cambios
  - site:ejemplo.com after:2025-01-01 "token" para detecciones recientes relevantes a flujos de autenticación.[^2]
  - site:ejemplo.com "privacidad" before:2024-12-31 para versiones anteriores de políticas o páginas legales.[^2]

## GHDB como catálogo de inspiración[^6]

- La Google Hacking Database (GHDB) compila dorks por categorías (footholds, files containing passwords, error messages, etc.) y permite aprender patrones que luego se adaptan a cada objetivo.[^6]
- Revisar GHDB agiliza la creación de consultas fiables para localizar “juicy info” sin reinventar la rueda, manteniendo el trabajo en pasivo.[^8]

## Flujo operativo en 10 minutos (pasivo puro)[^1]

- Paso 1: mapa base con site: y exclusiones (-www, -blog) para abarcar subdominios y reducir ruido de la portada.[^1]
- Paso 2: barrido de archivos con filetype:/ext: combinando OR y comillas para palabras clave sensibles.[^1]
- Paso 3: caza de parámetros con inurl: y, si procede, intitle:"error" para mensajes útiles que revelen stack o SQL.[^3]
- Paso 4: recencia con after:/before: para priorizar hallazgos recientes o localizar “pistas” en versiones antiguas.[^2]
- Paso 5: catalogar dorks efectivos por target y etiquetar por categoría (archivos, paneles, parámetros) para repetir en futuros objetivos.[^6]

## Buenas prácticas y límites[^1]

- Legal y alcance: usar dorks es pasivo, pero descargar o interactuar con contenido sensible puede salir del espíritu de OSINT; documentar y tratar como indicios hasta validar en fases activas dentro de scope.[^1]
- Ruido y precisión: combinar comillas, exclusiones y OR para bajar ruido, y usar allintitle:/allinurl: cuando el dominio devuelva demasiados resultados genéricos.[^4]
- Fecha y frescura: aplicar before:/after: en investigaciones vivas para no perder tiempo con contenido obsoleto.[^2]
- Operadores soportados: Google mantiene una lista viva de operadores y sus matices; validar si un operador sigue activo y cómo se interpreta.[^9]

## Cheats de combinación (copiar/pegar)[^1]

- Archivos sensibles recientes: site:ejemplo.com (ext:pdf OR ext:xlsx OR ext:csv) ("confidencial" OR "solo uso interno") after:2024-01-01.[^2]
- Paneles no corporativos: site:ejemplo.com (intitle:"login" OR inurl:"login") -intext:"empleados" -intext:"clientes" -intext:"SSO".[^3]
- Parámetros peligrosos: site:ejemplo.com (inurl:"redirect=" OR inurl:"returnUrl=" OR inurl:"next=") -inurl:"/logout".[^3]
- Endpoints de API: site:ejemplo.com (inurl:"/api/" OR inurl:"/v1/" OR inurl:"/v2/") -inurl:"swagger".[^3]
- Tecnología en título: site:ejemplo.com (intitle:"index of" OR intitle:"status") ("nginx" OR "apache").[^3]

## Registro y triaje de hallazgos[^1]

- Guardar consultas y primeros diez resultados con fecha para reproducibilidad y priorización en activo posterior.[^1]
- Etiquetar cada hallazgo con categoría (archivo, panel, parámetro) y con “acción siguiente” (validar en activo, descartar, vigilar con after:).[^2]

Con esto se obtiene un módulo de dorking pragmático: operadores que importan, plantillas accionables y flujo en pasivo listo para encadenar con recon activo sin perder tiempo ni violar alcance.[^1]
<span style="display:none">[^11][^13][^15][^17][^19][^21]</span>

<div style="text-align: center">Técnica profunda: Google Dorking</div>

[^1]: https://support.google.com/websearch/answer/35890?hl=en\&co=GENIE.Platform%3DDesktop
    
[^2]: https://searchengineland.com/search-google-by-date-with-new-before-and-after-search-commands-315184
    
[^3]: https://www.davidhodder.com/google-advanced-search-operators/
    
[^4]: https://serpstat.com/blog/google-search-operators-making-advanced-search-easier/
    
[^5]: https://support.google.com/websearch/answer/2466433?hl=en
    
[^6]: https://www.exploit-db.com/google-hacking-database
    
[^7]: https://ahrefs.com/blog/google-advanced-search-operators/
    
[^8]: https://www.welivesecurity.com/es/recursos-herramientas/google-hacking-averigua-informacion-aparece-resultados/
    
[^9]: https://developers.google.com/search/docs/monitor-debug/search-operators
    
[^10]: 02b-1-google-dorking.md
    
[^11]: https://support.google.com/websearch/thread/285402637/advanced-google-search-techniques-to-master?hl=en
    
[^12]: https://www.google.es/advanced_search
    
[^13]: https://github.com/readloud/Google-Hacking-Database
    
[^14]: https://www.osintux.org/documentacion/google-hacking-database
    
[^15]: https://marketingsyrup.com/new-google-search-commands-before-after/
    
[^16]: https://ondigitals.com/google-advanced-search/
    
[^17]: https://indjst.org/articles/google-hacking-database-attributes-enrichment-and-conversion-to-enable-the-application-of-machine-learning-techniques
    
[^18]: https://www.searchenginejournal.com/before-after-search-commands/302695/
    
[^19]: https://www.revolgy.com/insights/blog/power-of-google-search-use-advanced-search-operators-like-a-pro
    
[^20]: https://www.reddit.com/r/google/comments/11uenhp/google_search_date_range_apparently_gone_there_is/
    
[^21]: https://www.nasuwt.org.uk/sitewide-search/using-google-s-advanced-search-operators.html
