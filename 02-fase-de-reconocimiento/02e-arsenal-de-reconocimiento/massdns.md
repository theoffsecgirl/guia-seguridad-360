# Introducción a massdns

MassDNS es un resolvedor DNS de alto rendimiento pensado para validar listas enormes de dominios/subdominios en paralelo, filtrando rápidamente cuáles resuelven y a qué registros, ideal tras la fase de enumeración pasiva/activa.[^2]
Este paso depura ruido y deja un set de objetivos reales sobre los que continuar con HTTP probing o escaneos, reduciendo costes y falsos positivos posteriores.[^1]

## Instalación

- Compilación desde el repositorio oficial

```bash
git clone https://github.com/blechschmidt/massdns
cd massdns && make
```

- Paquetes conocidos
  - Kali Linux: paquete massdns disponible en repos de herramientas.[^3]
  - Homebrew (macOS/Linux): fórmula “massdns” para instalación rápida.[^4]

## Requisitos: resolvers

- Usa una lista de resolvers DNS fiable y actualizada, ya que la incluida en el repositorio está desactualizada y muchos resolvers pueden fallar o no ser de confianza.[^2]
- Recomendación: emplear listas “fresh resolvers” actualizadas de forma horaria y validadas automáticamente para mejorar tasa de aciertos y estabilidad.[^5]

## Flujo lógico: enumeración → resolución

- Enumeración: genera la lista de candidatos con subfinder, amass o CT logs antes de resolver, guardando un dominio por línea para procesado eficiente.[^1]
- Resolución: pasa ese listado por massdns para confirmar registros válidos y separar NXDOMAIN/SERVFAIL del conjunto útil de objetivos.[^1]

## Códigos DNS clave y qué hacer

- NOERROR: respuesta válida del punto de vista del servidor; puede devolver datos o NODATA si el tipo consultado no existe para ese nombre, por lo que conviene verificar si hay answers antes de clasificar como vivo.[^1]
- NXDOMAIN: el nombre no existe; descartar del set activo a menos que haya un error de entrada o wildcard que debas gestionar.[^1]
- SERVFAIL/REFUSED: error del servidor o política que rechaza la consulta; reintentar con otros resolvers o más tarde, y tomarlo como señal a vigilar sin concluir.[^1]
- massdns permite filtrar/ignorar por códigos de respuesta para producir salidas más limpias y centradas en lo útil.[^2]

## Uso básico

- Resolver A/AAAA y volcar en NDJSON (líneas JSON)

```bash
massdns -r resolvers.txt -t A -o J -w resultados.jsonl dominios.txt
```

Este comando usa resolvers personalizados, consulta registros A y escribe NDJSON, óptimo para procesado con jq o pipelines posteriores.[^2]

- Ejemplos con otros tipos

```bash
massdns -r resolvers.txt -t AAAA -o J -w v6.jsonl dominios.txt
massdns -r resolvers.txt -t CNAME -o J -w cname.jsonl dominios.txt
massdns -r resolvers.txt -t MX -o J -w mx.jsonl dominios.txt
```

La bandera -t controla el tipo de registro por consulta, permitiendo pivotes por correo o alias según necesidad.[^2]

## Parsing a escala (NDJSON)

- Extraer nombres que resolvieron y normalizar el punto final

```bash
jq -r '.name' resultados.jsonl | sed 's/\.$//' | sort -u > subs_resueltos.txt
```

Este patrón produce una lista única de FQDN con resolución confirmada, lista para HTTP probing o correlaciones posteriores.[^1]

- Evitar “slurp” con ficheros grandes

```bash
# ejemplo simple de streaming por línea (sin -s) para no cargar todo en memoria
jq -r 'select(.resp_type=="A") | "\(.name) \(.data)"' resultados.jsonl | sed 's/\.$//' > nombre_ip.txt
```

Con input masivo conviene procesar línea a línea en NDJSON para no agotar memoria, usando selectores y evitando -s/--slurp salvo que sea imprescindible.[^7]

## Buenas prácticas de rendimiento

- Ajustar concurrencia y “interval” para no saturar autoritativos: parámetros como -s (hashmap-size), --socket-count, --processes y -i (interval ms) ayudan a controlar carga y estabilidad.[^2]
- Sé conservador con la tasa y el tamaño de wordlists cuando hagas brute force directo de subdominios, empleando scripts incluidos como subbrute.py/ct.py con responsabilidad.[^2]

## Wildcard y filtrado

- El wildcard DNS puede hacer que “todo resuelva” y contamine resultados; usa herramientas que integran filtrado de wildcard como shuffledns o pipelines que verifiquen respuestas contra nombres aleatorios para descartar comodines.[^9]
- Al validar resultados, prioriza registros coherentes con los NS/autoridad y descarta respuestas sospechosas de resolvers problemáticos, ayudándote de la información de resolver incluida en salidas de massdns cuando sea relevante.[^2]

## Pipeline recomendado

- Pasivo → massdns → HTTP

```bash
# 1) Enumeración pasiva
subfinder -d ejemplo.com -silent -all > subs.txt
# 2) Resolución masiva con massdns (A)
massdns -r resolvers.txt -t A -o J -w a.jsonl subs.txt
jq -r 'select(.resp_type=="A") | .name' a.jsonl | sed 's/\.$//' | sort -u > vivos_dns.txt
# 3) HTTP probing y fingerprint
httpx -l vivos_dns.txt -silent -status-code -title -tech-detect -json -o httpx.json
```

Este pipeline depura candidatos a subdominios con resolución efectiva y obtiene estado/título/tecnologías para priorizar con bajo ruido y evidencia reproducible.[^2]

## Trucos útiles

- NDJSON con fallos terminales: añade la flag “e” en -o J para registrar errores terminales por consulta y depurar mejor resolvers o dominios problemáticos.[^2]
- PTR masivo: el script scripts/ptr.py genera las consultas invertidas .in-addr.arpa para alimentar directamente a massdns en modo PTR, útil para mapeo inverso controlado.[^2]
- Salidas alternativas: -o S/F para texto simple o detallado, y -o L para volcar solo lista de dominios con opciones avanzadas como incluir NOERROR sin answers si interesa un inventario más completo.[^2]

## Alternativas y wrappers

- shuffledns: wrapper en Go que usa massdns para validar subdominios y hace brute force con filtrado de wildcard integrado, agilizando pipelines activos con menor tasa de falsos positivos.[^8]
- Integración con ecosistema: combinar massdns con generadores de permutaciones y validadores pasivos/activos mejora cobertura y precisión sin multiplicar ruido innecesario.[^9]

## Checklist rápido

- ¿Lista de resolvers fresca y validada antes de lanzar consultas masivas para minimizar errores y tiempos muertos?[^5]
- ¿Salida NDJSON parseada sin slurp y con filtros claros por tipo/answer para trabajar a escala sin agotar memoria?[^6]
- ¿Wildcard gestionado con verificación aleatoria o wrappers que filtran, evitando datasets inflados?[^8]
- ¿Pipeline hacia httpx para quedarte solo con superficie web viva y priorizable por título/código/tecnología?[^10]

## Definition of Done (DoD)

- Conjunto de subdominios resueltos con evidencia mínima (registro/tipo/IP) listo para probing HTTP o escaneo selectivo, sin entries espurias por wildcard o resolvers defectuosos.[^1]
- Scripts/mandatos y timestamps archivados para reproducibilidad, con resolvers utilizados y parámetros de concurrencia/interval documentados para futura auditoría.[^2]
  <span style="display:none">[^14][^18][^22]</span>


[^1]: massdns.md
    
[^2]: https://github.com/blechschmidt/massdns
    
[^3]: https://www.kali.org/tools/massdns/
    
[^4]: https://formulae.brew.sh/formula/massdns
    
[^5]: https://github.com/proabiral/Fresh-Resolvers
    
[^6]: https://stackoverflow.com/questions/55499300/handle-a-very-large-input-file-without-slurp
    
[^7]: https://www.linode.com/docs/guides/using-jq-to-process-json-on-the-command-line/
    
[^8]: https://github.com/projectdiscovery/shuffledns
    
[^9]: https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/dns-bruteforcing
    
[^10]: https://docs.projectdiscovery.io/tools/httpx
    
[^11]: https://github.com/topics/massdns
    
[^12]: https://github.com/Den1al/pymassdns
    
[^13]: https://hayageek.com/massdns-tutorial-dns-resolver-for-bulk-lookups-reconnaissance/
    
[^14]: https://www.geeksforgeeks.org/linux-unix/massdns-high-performance-dns-stub-resolver-tool/
    
[^15]: https://stackoverflow.com/questions/49342129/jq-to-output-results-as-json
    
[^16]: https://codesandbox.io/p/github/tehmasta/resolvers/resolvers.txt
    
[^17]: https://github.com/topics/massdns?l=jupyter+notebook\&o=desc\&s=forks
    
[^18]: https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2024-09-1/NET-2024-09-1_07.pdf
    
[^19]: https://osintteam.blog/do-you-struggle-finding-internal-hidden-subdomains-recon-part-5-b06c99a11364
    
[^20]: https://github.com/topics/bulk-dns
    
[^21]: https://www.github-zh.com/topics/dns-resolver
    
[^22]: https://navendu.me/posts/jq-interactive-guide/
