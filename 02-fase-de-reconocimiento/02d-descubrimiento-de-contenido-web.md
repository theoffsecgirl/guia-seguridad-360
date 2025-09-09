# Descubrimiento de contenido web

Tras identificar hosts web activos, el objetivo es aflorar rutas, endpoints y artefactos no enlazados que amplíen la superficie explotable, priorizando directorios sensibles, APIs, paneles y ficheros clave como .git o .env.[^1]
La combinación de crawling selectivo, fuzzing de rutas con buenas wordlists y análisis de JavaScript suele ofrecer el mayor retorno con bajo ruido si se configura correctamente.[^1]

## Objetivos ofensivos clave[^1]

- Directorios/archivos sensibles (/admin, /backup, /config, .git, .env) que habiliten acceso o filtración directa.[^1]
- Endpoints de API no documentados y documentación técnica (Swagger/OpenAPI/Postman) para pivotar a pruebas lógicas.[^1]
- Paneles de administración y páginas de debug con trazas o toggles de modo desarrollo.[^1]

## Métodos principales[^1]

### 1) Crawling/Spidering dirigido

Mapea enlaces visibles y descubre rutas internas enlazadas desde HTML/JS, evitando golpes profundos a contenido irrelevante.[^1]

- Herramientas: Burp (Crawler), katana, hakrawler, gospider; priorizar include de mismos orígenes y límites de profundidad para no generar ruido inútil.[^1]

### 2) Fuerza bruta de rutas (fuzzing)

Descubre recursos no enlazados probando listas de palabras con filtros por código, tamaño y firmas, apoyándose en exclusiones para 404 “blandos”.[^1]

- Herramientas: ffuf, dirsearch, wfuzz, gobuster dir; la configuración precisa marca la diferencia entre ruido y señal.[^1]
- Ejemplo ffuf básico:

```bash
ffuf -w /path/SecLists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403
```

Este patrón cubre códigos habituales y descubre recursos accesibles o protegidos que deben revisarse con sesión/roles adecuados.[^1]

- Extensiones y recursividad con ffuf:

```bash
# Probar extensiones típicas
ffuf -w /path/SecLists/Discovery/Web-Content/web-extensions.txt:EXT -u https://target.tld/indexEXT -fc 404
# Recursivo por descubrimientos
ffuf -w /path/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://target.tld/FUZZ -recursion -recursion-depth 2 -fc 404
```

Ajustar -fc/-fs y profundidad para controlar falsos positivos y coste temporal.[^2]

- Dirsearch alternativo:

```bash
dirsearch -u https://target.tld -w /path/wordlist.txt --recursion --exclude-status=404
```

Dirsearch incorpora filtros, recursión, prefijos/sufijos y reportes, útil para barridos rápidos reproducibles.[^4]

### 3) Análisis de JavaScript

Extrae endpoints, parámetros y rutas de APIs desde JS, incluidos artefactos “huérfanos” no enlazados.[^1]

- Herramientas: LinkFinder/xnLinkFinder, extensiones de Burp, y utilidades similares para enumerar endpoints a partir de JS.[^1]
- Uso típico: descargar JS estáticos, pasar el parser y volcar rutas candidatas a un fuzzing/validación HTTP posterior.[^6]

### 4) Visual recon

Captura pantallas a escala para priorizar logins, errores o software legacy antes de profundizar, ahorrando tiempo de análisis manual.[^1]

- Herramientas: aquatone, gowitness, webscreenshot; ejecutar sobre hosts de httpx con status 200/401/403 para eficiencia.[^1]

## Comandos prácticos (copy/paste)[^1]

- Fuzzing base con ffuf (filtrando 404 blandos por tamaño)

```bash
ffuf -w /path/SecLists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -fs 0 -mc 200,204,301,302,307,401,403
```

Ajustar -fs/-fw según firmas específicas del target para evitar listados falsos.[^2]

- Fuzzing de extensiones y php/js:

```bash
ffuf -w /path/SecLists/Discovery/Web-Content/web-extensions.txt:EXT -u https://target.tld/FUZZ.EXT -fc 404
```

Cubre rutas que requieren extensión para resolver contenido real.[^3]

- Dirsearch con reporte:

```bash
dirsearch -u https://target.tld -w /path/SecLists/Discovery/Web-Content/common.txt -x 404,400 -r -o report.txt
```

Genera un reporte consumible para triaje y seguimiento.[^4]

- LinkFinder (JS → endpoints):

```bash
python3 linkfinder.py -i https://target.tld/app.js -o cli
```

Volcar endpoints a una lista para validación con httpx/ffuf en un siguiente paso.[^5]

## Prioridades y señales[^1]

- 401/403 en rutas sensibles indica control de acceso; revalidar con sesión/roles y pruebas de autorización (IDOR/BOLA/BFLA) antes que XSS/SQLi.[^1]
- Documentación expuesta (swagger.json, /docs, /openapi) y backups/logs (.zip, .bak, .log) suelen ser atajos a hallazgos de impacto.[^1]
- .git/.env o “config” accesibles son críticos y requieren manejo responsable y reporte inmediato según alcance.[^1]

## Buenas prácticas operativas[^1]

- Ajustar tasa y profundidad según respuesta del sitio para no activar WAF/ratelimits, y registrar filtros usados (-fc/-fs/-fw) para reproducibilidad.[^1]
- Combinar crawling ligero con fuzzing focalizado por tecnología detectada (PHP, Node, Java) para reducir el espacio de búsqueda.[^1]
- Integrar resultados en un pipeline con httpx para títulos/tecnologías y con un checklist de “ficheros más buscados” para validar rápido el impacto.[^1]

## Siguiente paso[^1]

- Pasar a la técnica profunda de ficheros sensibles expuestos y validar inmediatamente hallazgos críticos con evidencia mínima, severidad estimada y mitigación clara.[^1]
  <span style="display:none">[^13][^17][^21][^9]</span>


[^1]: 02d-descubrimiento-de-contenido-web.md
    
[^2]: https://github.com/ffuf/ffuf
    
[^3]: https://ffuf.hashnode.dev/basic-fuzzing
    
[^4]: https://github.com/maurosoria/dirsearch
    
[^5]: https://github.com/GerbenJavado/LinkFinder
    
[^6]: https://www.geeksforgeeks.org/linux-unix/linkfinder-script-to-search-endpoints-in-javascript-files/
    
[^7]: https://hackviser.com/tactics/tools/ffuf
    
[^8]: https://ffuf.hashnode.dev/fuzzing-using-ffuf
    
[^9]: https://www.hackercoolmagazine.com/beginners-guide-to-ffuf-tool/
    
[^10]: https://github.com/evilsocket/dirsearch
    
[^11]: https://github.com/ligurina/JS-LinkFinder
    
[^12]: https://hackzapsecurity.in/Blogs/blogCardPages/blogs/fuzz-hidden-directories.html
    
[^13]: https://www.kali.org/tools/ffuf/
    
[^14]: https://github.com/dirsearch
    
[^15]: https://github.com/nirsarkar/dirsearch-master
    
[^16]: https://github.com/xnl-h4ck3r/xnLinkFinder
    
[^17]: https://github.com/topics/dirsearch
    
[^18]: https://github.com/topics/linkfinder?l=javascript
    
[^19]: https://www.kali.org/tools/dirsearch/
    
[^20]: https://github.com/Raunaksplanet/LinkFinder-Web-Version
    
[^21]: https://gist.github.com/hax0rgb/505b5de6be0a78fbd9dd0f46efbe754d
