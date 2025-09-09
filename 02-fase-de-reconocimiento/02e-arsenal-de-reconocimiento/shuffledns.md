# Introducción a shuffledns

shuffledns es un wrapper de MassDNS escrito en Go para enumerar subdominios válidos mediante fuerza bruta activa y para resolver listas a escala, con detección inteligente de wildcard y soporte limpio de stdin/stdout para pipelines.[^1]
Su fortaleza es simplificar la resolución masiva y el bruteforce sobre un dominio con listas grandes, delegando la velocidad a MassDNS y filtrando falsos positivos por wildcard.[^2]

## Prerrequisitos[^1]

- MassDNS instalado y accesible en PATH o referenciado con -massdns, ya que shuffledns lo invoca por debajo para resolver a alta velocidad.[^1]
- Lista de resolvers DNS fiable y fresca en un archivo (por ejemplo resolvers.txt), porque la calidad y estabilidad de las respuestas dependen de esos servidores.[^1]
- Wordlist de subdominios para bruteforce (por ejemplo de SecLists) cuando se use el modo de fuerza bruta con -w.[^1]

## Instalación[^2]

- Binario precompilado desde Releases: descargar, extraer y mover al PATH.[^3]

```bash
tar -xzvf shuffledns-linux-amd64.tar && sudo mv shuffledns-linux-amd64 /usr/local/bin/shuffledns && shuffledns -h
```

- Compilación con Go: requiere Go reciente y compila el comando desde el repositorio.[^2]

```bash
GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
```

## Modos de uso[^2]

shuffledns opera en dos modos principales: “resolve” (resolver una lista existente) y “bruteforce” (generar y resolver permutaciones a partir de una wordlist).[^2]

- Resolve (lista → válidos)

```bash
# Lista en archivo y resolvers
shuffledns -d ejemplo.com -list subdomains.txt -r resolvers.txt -o validos.txt
# O por stdin encadenado a subfinder (pasivo → resolve)
subfinder -d ejemplo.com -silent | shuffledns -d ejemplo.com -r resolvers.txt -silent -o validos.txt
```

- Bruteforce (wordlist → válidos)

```bash
shuffledns -d ejemplo.com -w subdominios_wordlist.txt -r resolvers.txt -silent -o bruteforce.txt
```

Notas de targeting: el flag -d espera el dominio base sobre el que construir los nombres, por lo que para probar api.dev.site.com se debe pasar -d dev.site.com y una wordlist que genere api.dev.site.com, no un patrón *.dev.site.com.[^2]

## Flags útiles y comportamiento[^2]

- -d dominio, -w wordlist, -list archivo, -r resolvers, -o salida para los parámetros básicos de dominio, entradas, resolvers y archivo de resultados.[^2]
- -massdns /ruta/al/binario para indicar una ruta específica del binario MassDNS si no está en PATH.[^2]
- -retries N para controlar reintentos de consultas DNS en caso de fallos transitorios en resolvers.[^2]
- -silent para suprimir banners y logs no esenciales y obtener una salida limpia solo con subdominios válidos.[^2]
- -directory DIR para indicar un directorio temporal de trabajo si se requiere controlar espacio o rutas en entornos específicos.[^2]

## Manejo de wildcard (multi‑nivel)[^2]

shuffledns detecta y filtra wildcard contando cuántos subdominios nuevos apuntan a la misma IP y, al superar umbrales, verifica comodines iterativamente por niveles del host para evitar inflar resultados válidos con coincidencias falsas.[^2]
La versión v1.1.0 añadió filtrado de wildcard multi‑dominio, lo que mejora el rendimiento y la precisión cuando se procesan varios dominios en una misma ejecución.[^3]

## Pipelines recomendados[^2]

- Pasivo → resolve → HTTP probing

```bash
subfinder -d ejemplo.com -silent \
| shuffledns -d ejemplo.com -r resolvers.txt -silent \
| httpx -silent -status-code -title -tech-detect -json -o httpx.json
```

- Bruteforce focalizado → probing

```bash
shuffledns -d ejemplo.com -w wordlist.txt -r resolvers.txt -silent \
| httpx -silent -status-code -title -tech-detect -o vivos.txt
```

- Permutaciones previas → resolve

```bash
# Generar permutaciones con la herramienta preferida y resolver con shuffledns
gotator -sub base.txt -perm perms.txt -depth 1 -numbers 10 -mindup -adv -md > perm.txt
shuffledns -d ejemplo.com -list perm.txt -r resolvers.txt -silent -o validos_perm.txt
```

## Buenas prácticas[^1]

- Usar resolvers frescos y estables para minimizar SERVFAIL y respuestas envenenadas, ya que el rendimiento real depende de la salud de esos servidores.[^1]
- Mantener wordlists razonables y segmentadas por caso (admin/api/dev/geo) para reducir ruido en bruteforce y acelerar validación posterior.[^1]
- Encadenar con httpx y guardar salidas en JSON cuando se requiera triage a escala y reproducibilidad de evidencias.[^2]

## Ejemplos adicionales[^2]

- Resolve con stdin desde subfinder y salida a httprobe/httpx posteriormente para validación HTTP.[^2]

```bash
echo ejemplo.com | subfinder -silent \
| shuffledns -d ejemplo.com -r resolvers.txt -silent \
| httpx -silent -status-code -title
```

- Especificar MassDNS explícito si no está en PATH y volcar a archivo.[^2]

```bash
shuffledns -d ejemplo.com -w wordlist.txt -r resolvers.txt -massdns /usr/bin/massdns -o salida.txt
```

## Checklist rápido[^1]

- ¿MassDNS instalado y ruta valida (-massdns) si no está en PATH, y resolvers frescos cargados (-r resolvers.txt)?[^1]
- ¿Modo correcto elegido (bruteforce con -w, resolve con -list o stdin) y -silent para salida limpia en pipelines?[^2]
- ¿Wildcard gestionado implícitamente por shuffledns y verificado cuando el volumen de subdominios por IP indica comodín?[^2]
- ¿Resultados encadenados a httpx para estado/título/tecnologías y priorización efectiva de superficie viva?[^2]

## Definition of Done (DoD)[^2]

- Lista de subdominios válidos deduplicada y filtrada de wildcard, proveniente de bruteforce o resolución masiva, con comandos y parámetros documentados.[^2]
- Pipeline reproducible hacia httpx u otra herramienta de probing con salida JSON/archivo organizada para triaje y siguientes pasos.[^2]
  <span style="display:none">[^13][^17][^21][^7][^9]</span>


[^1]: https://github.com/projectdiscovery/shuffledns
    
[^2]: https://pkg.go.dev/github.com/0xJeti/shuffledns
    
[^3]: https://github.com/projectdiscovery/shuffledns/releases
    
[^4]: shuffledns.md
    
[^5]: https://github.com/projectdiscovery/shuffledns/actions
    
[^6]: https://github.com/projectdiscovery/shuffledns/activity
    
[^7]: https://offsec.tools/tool/shuffledns
    
[^8]: https://pkg.go.dev/github.com/d3mondev/puredns/v2
    
[^9]: https://github.com/projectdiscovery/shuffledns/discussions
    
[^10]: https://docs.projectdiscovery.io/opensource
    
[^11]: https://www.youtube.com/watch?v=UXcE_lOEVjM
    
[^12]: https://deps.dev/project/github/projectdiscovery%2Fshuffledns
    
[^13]: https://www.youtube.com/watch?v=9S5Dmlc4Wpg
    
[^14]: https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/dns-bruteforcing
    
[^15]: https://github.com/projectdiscovery
    
[^16]: https://pentestguy.com/subdomain-enumeration-a-complete-guide/
    
[^17]: https://nirajkharel.com.np/posts/web-pentest-recon/
    
[^18]: https://github.com/projectdiscovery/shuffledns/issues
    
[^19]: https://rashahacks.com/guide-to-permutations-subdomain-enumeration/
    
[^20]: https://notes.m4lwhere.org/offensive/recon/dns/domain-discovery
    
[^21]: https://davidtancredi.gitbook.io/pentesting-notes/r3dcl1ff/tools/shuffledns
