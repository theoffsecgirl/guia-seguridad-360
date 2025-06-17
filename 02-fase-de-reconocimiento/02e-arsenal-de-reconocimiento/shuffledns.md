# Introducción a `shuffledns`

`shuffledns` es otra herramienta del arsenal de ProjectDiscovery, diseñada específicamente para **manejar la enumeración y resolución masiva de subdominios**. Su principal ventaja es que actúa como un "envoltorio" (wrapper) inteligente para `massdns`, simplificando el proceso de fuerza bruta, manejando la detección de subdominios wildcard, y permitiendo una fácil integración con otras herramientas.

Es la herramienta a la que recurres cuando tienes una buena lista de palabras (wordlist) y quieres probarlas contra un dominio para ver cuáles existen.

### Prerrequisitos

Para usar `shuffledns` de forma efectiva, necesitarás dos cosas:

1. **Una Wordlist de Subdominios:** Una lista de nombres de subdominios comunes para probar (e.g., `admin`, `api`, `dev`, `test`, `blog`). La colección de **SecLists** en GitHub es un recurso excelente para esto.
2. **Una Lista de Resolvers DNS:** Un archivo de texto con una lista de servidores DNS públicos, válidos y rápidos. Esto es crucial para que `massdns` (que `shuffledns` usa por debajo) pueda hacer las consultas de forma masiva y fiable.

### Uso Básico y Opciones Clave

El comando que propones es un excelente ejemplo de un uso estándar para la fuerza bruta. Vamos a desglosarlo.

**Comando Principal de Fuerza Bruta:**

```bash
shuffledns -d ejemplo.com -w subdominios_wordlist.txt -r resolvers.txt -m /ruta/a/massdns --silent
```

**Desglose de las Opciones (Flags):**

- **`-d ejemplo.com`**: Especifica el dominio objetivo (`-domain`) contra el que se realizará la fuerza bruta. `shuffledns` probará `palabra.ejemplo.com` para cada "palabra" en tu wordlist.
- **`-w subdominios_wordlist.txt`**: La lista de palabras (`-wordlist`) que se usará para generar los subdominios a probar.
- **`-r resolvers.txt`**: El archivo (`-resolvers`) que contiene la lista de servidores DNS públicos.
- **`-m /ruta/a/massdns`**: (Opcional si `massdns` está en tu PATH) La ruta (`-massdns`) al binario de `massdns`. `shuffledns` lo necesita para funcionar.
- **`--silent`**: Modo silencioso, para obtener una salida limpia solo con los subdominios válidos encontrados.

### Integración en un Flujo de Trabajo

La verdadera potencia de estas herramientas se ve al encadenarlas (`piping`). Una vez que `shuffledns` encuentra subdominios válidos, lo más lógico es pasarlos a `httpx` para ver cuáles tienen un servidor web activo.

```bash
shuffledns -d ejemplo.com -w wordlist.txt -r resolvers.txt --silent | httpx -title -sc -tech-detect --silent
```

Este comando:

1. Realiza la fuerza bruta de subdominios para `ejemplo.com` con `shuffledns`.
2. La salida (los subdominios que existen) se pasa directamente (`|`) a `httpx`.
3. `httpx` comprueba cada subdominio y, si tiene un servidor web, muestra su título, código de estado y tecnologías detectadas.

### Aclaración sobre el Targeting de Subdominios Específicos

En tu ejemplo ponías: `shuffledns ... *.dev.site.com`. Hay que tener cuidado aquí. `shuffledns` en su modo de fuerza bruta (`-w`) no acepta un patrón como `*.dev.site.com` como dominio `-d`. El flag `-d` espera un dominio raíz sobre el que construir las permutaciones (e.g., `dev.site.com`).

Si quisieras hacer fuerza bruta sobre un subdominio de tercer nivel como `dev.site.com`, el comando sería:

```bash
# Probará cosas como api.dev.site.com, test.dev.site.com, etc.
shuffledns -d dev.site.com -w wordlist.txt -r resolvers.txt --silent
```

Si lo que buscas es generar permutaciones más complejas, normalmente usarías otra herramienta como `gotator` o un script para generar la lista de posibles subdominios y luego pasar esa lista a `shuffledns` en modo de resolución (sin el flag `-w`).

### Organización: Guardando los Resultados

Como bien apuntas, ser organizado es clave para no volverse loco. Es una práctica excelente crear un directorio para cada objetivo y guardar ahí todos los resultados.

Puedes usar el flag `-o` para especificar un archivo de salida:

```bash
# Crear un directorio para el objetivo
mkdir ejemplo.com

# Ejecutar el escaneo y guardar la salida en un archivo dentro de ese directorio
shuffledns -d ejemplo.com -w wordlist.txt -r resolvers.txt --silent -o ejemplo.com/shuffledns_output.txt
```

De esta forma, mantienes todos tus hallazgos de un mismo programa de bug bounty bien ordenados y localizables.
