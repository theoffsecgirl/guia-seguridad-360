# Introducción a subfinder

subfinder es una herramienta pasiva de descubrimiento de subdominios de ProjectDiscovery, rápida, modular y con decenas de fuentes OSINT; es ideal como primer paso de recon para ampliar superficie sin tocar la infra del objetivo de forma directa.[^1]

## Instalación y ayuda[^3]

- Go (binario):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc && source ~/.bashrc
subfinder -h
```

- Docker oficial:

```bash
docker run -it --rm projectdiscovery/subfinder -h
```

## Configuración de API keys (máximo rendimiento)[^3]

- Archivo de proveedores: ~/.config/subfinder/provider-config.yaml (se crea al primer uso).[^3]
- Añadir claves (p. ej., VirusTotal, SecurityTrails, Shodan, Censys, FOFA, ZoomEye, WhoisXML, FullHunt, etc.) para mejorar cobertura; algunas requieren claves compuestas separadas por “:”.[^3]
- Listar fuentes disponibles:

```bash
subfinder -ls
```

## Uso básico y fuentes[^5]

- Un dominio (fuentes por defecto y las que tengan clave):

```bash
subfinder -d ejemplo.com
```

- Todas las fuentes (incluye las que requieren API):

```bash
subfinder -d ejemplo.com -all
```

- Múltiples dominios:

```bash
# desde archivo
subfinder -dL dominios.txt
# varios -d
subfinder -d ejemplo1.com -d otraweb.org
```

- Filtrar fuentes:

```bash
# solo algunas
subfinder -d ejemplo.com -s crtsh,github
# excluir específicas
subfinder -d ejemplo.com -es virustotal,securitytrails
```

## Salidas y formatos[^5]

- Texto a archivo:

```bash
subfinder -d ejemplo.com -o subs.txt
```

- JSON newline (-oJ), ideal para pipelines:

```bash
subfinder -d ejemplo.com -o subs.json -oJ
```

- Directorio por dominio (-oD) con -dL:

```bash
subfinder -dL dominios.txt -oD resultados/
```

- Incluir fuente en JSON (-cs) para trazabilidad:

```bash
subfinder -d ejemplo.com -o subs.json -oJ -cs
```

## Resolución integrada y modos silencioso/verbose[^5]

- Solo subdominios “activos” (resueltos):

```bash
subfinder -d ejemplo.com -nW
```

- Silencioso/verbose:

```bash
subfinder -d ejemplo.com -silent
subfinder -d ejemplo.com -v
```

## Rendimiento y control[^4]

- Tiempos y límite global:

```bash
# timeout por petición y tiempo máximo total
subfinder -d ejemplo.com -timeout 30 -max-time 10
```

- Resolvers personalizados (archivo o lista) para mejorar resolución posterior/activa si se usa:

```bash
subfinder -d ejemplo.com -resolvers 1.1.1.1,8.8.8.8
subfinder -d ejemplo.com -rL resolvers.txt
```

- Config principal opcional (-config) y provider (-pc):

```bash
subfinder -config ~/.config/subfinder/config.yaml -pc ~/.config/subfinder/provider-config.yaml
```

## Integraciones típicas en workflow[^6]

- Descubrimiento pasivo → probing HTTP con httpx:

```bash
subfinder -d ejemplo.com -silent -all \
| httpx -silent -title -status-code -tech-detect -o vivos.txt
```

- Pasivo → vivos → nuclei (detecciones):

```bash
subfinder -d ejemplo.com -silent -all \
| httpx -silent -status-code -json -o httpx.json
jq -r 'select(.status_code==200) | .url' httpx.json \
| nuclei -silent -t http/exposures/ -o findings.txt
```

- Lista de dominios → salida por directorio y activos (-nW) + JSON:

```bash
subfinder -dL dominios.txt -oD out -nW
```

## Buenas prácticas y notas[^5]

- -all mejora cobertura pero es más lento; úsalo en timeboxes largos o cuando el alcance lo permita.[^5]
- Configurar API keys tempranamente multiplica resultados, incluso con planes gratuitos; mantener provider-config.yaml bajo control (no subirlo a repos).[^3]
- JSON (-oJ) + -cs facilita auditoría de fuentes y deduplicación en pipelines grandes.[^5]

## Ejemplos rápidos de valor[^5]

- Top combo “rápido y útil”:

```bash
subfinder -d ejemplo.com -silent -all \
| httpx -silent -status-code -title -tech-detect -json -o httpx.json
```

- Multi-dominio, con salida organizada y activos:

```bash
subfinder -dL dominios.txt -oD resultados -nW -silent
```

Con esto queda una guía operativa y actualizada de subfinder: desde instalación y claves a salidas ricas y encadenamientos que aceleran el triaje de superficies vivas en recon pasivo.[^5]
<span style="display:none">[^13][^17][^9]</span>


[^1]: https://docs.projectdiscovery.io/opensource/subfinder/overview
    
[^2]: https://github.com/projectdiscovery/subfinder
    
[^3]: https://docs.projectdiscovery.io/tools/subfinder/install
    
[^4]: https://highon.coffee/blog/subfinder-cheat-sheet/
    
[^5]: https://projectdiscovery.io/blog/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced
    
[^6]: https://docs.projectdiscovery.io/tools/subfinder/running
    
[^7]: https://iha089.org.in/subfinder/
    
[^8]: subfinder.md
    
[^9]: https://systemweakness.com/mastering-subfinder-for-bug-bounty-ultimate-guide-to-subdomain-enumeration-and-api-configuration-18c36599c8a8
    
[^10]: https://netlas.io/blog/netlas_and_subfinder/
    
[^11]: https://hackviser.com/tactics/tools/subfinder
    
[^12]: https://hub.docker.com/r/projectdiscovery/subfinder
    
[^13]: https://linuxcommandlibrary.com/man/subfinder
    
[^14]: https://github.com/projectdiscovery/subfinder/issues/245
    
[^15]: https://pkg.go.dev/github.com/projectdiscovery/subfinder
    
[^16]: https://lipsonthomas.com/subfinder-subdomain-enumeration-tool/
    
[^17]: https://infosecwriteups.com/integrating-shodan-and-censys-api-keys-into-subfinder-c28452af2efb
    
[^18]: https://blog.fikara.io/subdomain-enumeration
    
[^19]: https://github.com/projectdiscovery/subfinder/pulls
