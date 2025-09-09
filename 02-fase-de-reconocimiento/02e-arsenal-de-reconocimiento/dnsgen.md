# # Introducción a `dnsgen`

`dnsgen` es una herramienta escrita en Python que genera una lista de posibles subdominios a partir de una lista de entrada. A diferencia de la fuerza bruta simple, que solo prueba palabras de un diccionario, `dnsgen` crea **permutaciones inteligentes** basadas en los subdominios que ya conoces.

**¿Cómo funciona?** Toma un subdominio como `app.sitio.com` y aplica varias transformaciones para generar variaciones lógicas, como:

- Añadir prefijos y sufijos comunes: `dev-app.sitio.com`, `api.app.sitio.com`.
- Reemplazar palabras clave: si encuentra `dev.sitio.com`, también probará `staging.sitio.com`, `prod.sitio.com`, etc.
- Añadir números: `app01.sitio.com`, `app02.sitio.com`.

El objetivo es descubrir subdominios que siguen un patrón de nomenclatura lógico pero que no son fácilmente adivinables o no están públicamente enlazados.

### Instalación

Al ser una herramienta de Python, normalmente se instala con `pip`:

Bash

```
pip3 install dnsgen
```

### Uso Básico y Conceptual

`dnsgen` está diseñado para leer desde la entrada estándar (`stdin`). Puedes probar su funcionamiento con un solo dominio para ver qué tipo de permutaciones genera:

Bash

```
echo "app.sitio.com" | dnsgen -
```

**Salida de ejemplo (conceptual):**

```
dev.app.sitio.com
test.app.sitio.com
staging.app.sitio.com
api.app.sitio.com
api-app.sitio.com
app-dev.sitio.com
app-test.sitio.com
app1.sitio.com
... y muchas más ...
```

### Flujos de Trabajo de Reconocimiento con `dnsgen`

La verdadera potencia de `dnsgen` se desata cuando la encadenas con otras herramientas en un flujo de trabajo. El proceso general es:

1. **Obtener una lista inicial de subdominios** (con `subfinder`, `amass`, etc.).
2. **Generar permutaciones** de esa lista con `dnsgen`.
3. **Resolver** la nueva y enorme lista de permutaciones para ver cuáles existen realmente.

Veamos los dos flujos de trabajo principales que has mencionado:

#### Workflow 1: `dnsgen` + `massdns` (Enfoque DNS primero)

Este enfoque es muy completo. Primero genera y resuelve todas las posibles permutaciones a nivel de DNS, y luego, si quieres, puedes probar conectividad web en los resultados.

**Comando de Ejemplo:**

Bash

```
# Paso 1: Obtener subdominios iniciales (ej: con shuffledns o subfinder)
# shuffledns -d sitio.com -w wordlist.txt -r resolvers.txt -o sitio.com/subs_encontrados.txt

# Paso 2 y 3: Generar permutaciones y resolverlas con massdns
cat sitio.com/subs_encontrados.txt | dnsgen - | massdns -r resolvers.txt -t A -o J > sitio.com/permutaciones_resueltas.json
```

**Desglose del Pipeline:**

1. **`cat sitio.com/subs_encontrados.txt`**: Suministra la lista inicial de subdominios conocidos a `dnsgen`.
2. **`| dnsgen -`**: Lee los subdominios y genera miles de nuevas permutaciones.
3. **`| massdns ...`**: Toma la enorme lista de permutaciones y las resuelve a toda velocidad para ver cuáles tienen un registro `A` (una IP). La salida en JSON (`-o J`) es útil para un procesamiento posterior.

**Paso 4 Opcional: Probar conectividad web en los resultados:** Una vez tienes los subdominios que sí existen (resuelven a una IP), puedes pasarlos a `httpx`.

Bash

```
# Extraer los nombres de la salida JSON de massdns y pasarlos a httpx
cat sitio.com/permutaciones_resueltas.json | jq -r '.name' | sed 's/\.$//' | httpx -title -sc -o sitio.com/hosts_web_permutados.txt
```

**Ventaja de este workflow:** Tienes una lista de todos los subdominios que existen a nivel de DNS, no solo los que tienen un servidor web.

#### Workflow 2: `dnsgen` + `httpx` (Enfoque Web directo)

Este enfoque es más directo y rápido si **solo te interesan los servidores web**. Omite el paso intermedio de `massdns`.

**Comando de Ejemplo:**

Bash

```
cat sitio.com/subs_encontrados.txt | dnsgen - | httpx -title -sc -tech-detect --silent -o sitio.com/hosts_web_permutados.txt
```

**Desglose del Pipeline:**

1. **`cat sitio.com/subs_encontrados.txt`**: Suministra la lista inicial.
2. **`| dnsgen -`**: Genera las permutaciones.
3. **`| httpx ...`**: En lugar de resolver solo con DNS, `httpx` intenta directamente conectarse a los puertos web de cada permutación generada. Si un servidor web responde, guarda el resultado.

**Ventaja de este workflow:** Es más rápido y va directo al grano si tu objetivo son las aplicaciones web. Te ahorras el paso de `massdns` y `jq`. **Desventaja:** Te perderás subdominios que podrían existir pero que no tienen un servidor web en los puertos por defecto (e.g., servidores de correo, FTP, etc.).

### Opciones Adicionales de `dnsgen`

- **`-w <wordlist.txt>`**: Permite proporcionar tu propia lista de palabras para generar las permutaciones (en lugar de la que `dnsgen` trae por defecto). Útil si has identificado palabras clave específicas de la organización objetivo.
- **`-f <archivo_de_entrada.txt>`**: Para leer los subdominios iniciales de un archivo, en lugar de `stdin`.
- **`-l <numero>`**: Establece la longitud mínima que debe tener una palabra de un subdominio para ser utilizada en las transformaciones (e.g., para ignorar palabras como "a", "mx", etc.).

Aquí tienes la versión arreglada y mejorada de “Introducción a dnsgen”, con instalación, usos correctos, pipelines robustos y consejos de señal/ruido para recon real. [^1]

# Introducción a dnsgen [^1]

dnsgen genera subdominios candidatos aplicando permutaciones inteligentes sobre una lista de subdominios reales, superando la simple fuerza bruta de diccionario y siguiendo patrones típicos de naming de equipos y entornos. [^1]
El objetivo es destapar hosts coherentes con el naming de la organización (prefijos/sufijos, reemplazos, numeración) que no están enlazados ni salen en fuentes pasivas. [^2]

## Instalación [^3]

- Pip: pip3 install dnsgen para un entorno Python estándar con dependencias resueltas. [^3]
- Paquetes: disponible en Kali y Homebrew como “dnsgen”, útil para entornos reproducibles. [^4]

## Uso básico [^2]

- Entrada por stdin para una vista rápida:

```bash
echo "app.sitio.com" | dnsgen -
```

Genera variaciones lógicas como dev.app.sitio.com, api.app.sitio.com o app01.sitio.com que luego deben resolverse/validarse. [^2]

- Entrada desde archivo o stdin “-” para listas grandes:

```bash
dnsgen subdominios.txt > perms.txt
# o
cat subdominios.txt | dnsgen - > perms.txt
```

Crea un conjunto amplio de candidatos listo para la fase de resolución. [^2]

## Workflows de recon recomendados

### DNS primero: dnsgen → massdns → httpx [^5]

Ideal si se desea validar existencia DNS antes de tocar capa web, reduciendo ruido y costes posteriores. [^5]

- Generar y resolver con salida de “lista válida” para evitar parseos complejos:

```bash
cat sitio.com/subs_iniciales.txt \
| dnsgen - \
| massdns -r resolvers.txt -t A -o L -w sitio.com/perms_validos.txt
```

-o L produce nombres válidos directamente, simplificando el pipeline y evitando depender de jq. [^5]

- Probar conectividad web y extraer metadatos:

```bash
cat sitio.com/perms_validos.txt \
| httpx -silent -status-code -title -tech-detect -o sitio.com/web_perms.txt
```

Permite priorizar por estado/título/tecnologías de forma inmediata. [^6]

### Web directo: dnsgen → httpx [^6]

Si solo interesan servicios web activos, se puede omitir la resolución DNS explícita y validar directamente vía HTTP/HTTPS. [^6]

```bash
cat sitio.com/subs_iniciales.txt \
| dnsgen - \
| httpx -silent -status-code -title -tech-detect -o sitio.com/web_perms.txt
```

Más rápido, pero no verá hosts que resuelven sin servicio web en puertos probados. [^6]

## Opciones útiles de dnsgen [^2]

- -w WORDLIST: aporta una wordlist propia para incluir vocabulario del target y mejorar la calidad de permutaciones. [^2]
- -f FILE: lee subdominios iniciales desde archivo en lugar de stdin para pipelines programados. [^2]
- -l N: ignora palabras demasiado cortas (p. ej., -l 3) para bajar ruido en las transformaciones. [^2]

## Consejos de señal/ruido

- Sembrado realista: usa subdominios de fuentes pasivas (subfinder/CT) para que las permutaciones reflejen naming real del objetivo. [^1]
- Resolución fiable: emplea massdns con resolvers frescos y salida -o L para minimizar falsos positivos y parsing costoso. [^5]
- Priorización web: httpx con -status-code -title -tech-detect en JSON o texto para triage reproducible y rápido. [^6]

## Ejemplos listos

- DNS-first mínimo con enriquecimiento web:

```bash
cat subs.txt | dnsgen - \
| massdns -r resolvers.txt -t A -o L -w vivos.txt \
&& httpx -l vivos.txt -silent -status-code -title -tech-detect -o web.txt
```

Combina generación, validación DNS y probing web con bajo ruido operativo. [^6]

- Solo web para discovery temprano:

```bash
cat subs.txt | dnsgen - \
| httpx -silent -status-code -title -tech-detect -o web_perms.txt
```

Útil en timeboxes cortos centrados en superficie HTTP viva. [^6]

Con esto queda una guía pragmática de dnsgen: instalación, uso correcto, pipelines robustos y heurísticas para aumentar cobertura sin inflar el ruido del recon. [^1]
<span style="display:none">[^17][^9]</span>


[^1]: https://github.com/AlephNullSK/dnsgen
    
[^2]: https://rashahacks.com/guide-to-permutations-subdomain-enumeration/
    
[^3]: https://www.kali.org/tools/dnsgen/
    
[^4]: https://formulae.brew.sh/formula/dnsgen
    
[^5]: https://github.com/blechschmidt/massdns
    
[^6]: https://lipsonthomas.com/httpx/
    
[^7]: https://gitlab.com/kalilinux/packages/dnsgen
    
[^8]: https://pypi.org/project/dnspython/
    
[^9]: https://www.isc.org/blogs/dnsgen-a-dns-packet-generator/
    
[^10]: https://stackoverflow.com/questions/51005045/performing-a-masscan-on-an-input-file-containing-domain-names
    
[^11]: https://raw.githubusercontent.com/cybersecvillage/onehit/master/Onehit.sh
    
[^12]: https://www.youtube.com/watch?v=gHmgk7mwAjk
    
[^13]: https://bugzilla.redhat.com/show_bug.cgi?id=1808259
    
[^14]: https://raw.githubusercontent.com/Homebrew/homebrew-core/master/Formula/d/dnsgen.rb
    
[^15]: https://discourse.pi-hole.net/t/i-concatenated-every-blocklist-i-could-find/5184?page=3
    
[^16]: https://crates.io/crates/ripgen
    
[^17]: https://gitlab.com/kalilinux/packages/dnsgen/-/blob/kali/master/README.md
    
[^18]: https://github.com/DmitryFillo/berserker_resolver
    
[^19]: https://bugzilla.redhat.com/show_bug.cgi?id=1840711
    
[^20]: https://0xpatrik.com/subdomain-enumeration-smarter/
    
[^21]: https://www.greatheart.io/post/the-hunt-for-subdomains-a-guide-to-subdomain-enumeration
    
[^22]: https://www.hackerone.com/blog/guide-subdomain-takeovers-20
