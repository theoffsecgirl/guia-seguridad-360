# Introducción a `dnsgen`

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
