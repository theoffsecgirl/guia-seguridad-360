# Introducción a `httpx`

`httpx` es un toolkit HTTP rápido y multifuncional desarrollado por el equipo de ProjectDiscovery. Su principal función en la fase de reconocimiento es tomar una lista de dominios o subdominios y **probar (probe) cuáles tienen un servidor web activo**, para luego extraer una gran cantidad de información útil sobre ellos.

Es la herramienta perfecta para "filtrar" las enormes listas de subdominios que obtienes de herramientas como `subfinder` o `amass`, permitiéndote centrarte solo en los activos que están realmente vivos y tienen una superficie de ataque web.

### Flujo de Trabajo Común

`httpx` está diseñado para funcionar perfectamente con la entrada estándar (`stdin`), lo que lo hace ideal para encadenar comandos en la terminal.

**Uso básico (leyendo de un archivo):**

```bash
httpx -l lista_de_subdominios.txt
```

**Uso encadenado (workflow típico):**

```bash
# La salida de subfinder se pasa directamente a httpx
subfinder -d ejemplo.com -silent | httpx -silent
```

### Análisis de un Comando Completo para Recopilación de Información

El siguiente comando es un ejemplo muy completo y práctico de cómo usar `httpx` para recopilar una gran cantidad de información de una lista de subdominios.

**Comando de Ejemplo:**

```bash
httpx -l lista.txt -cl -sc -location -favicon -title -tech-detect -ip -ports 80,443,8080,8000 -probe-all-ips -follow-redirects -o lista-httpx.txt
```

**Desglose de las Opciones (Flags):**

- **`-l lista.txt`**:
  - Especifica el archivo de entrada (`-list`) que contiene la lista de hosts (dominios/subdominios) a probar, uno por línea.
- **`-cl`**:
  - Muestra el tamaño de la respuesta (`Content-Length`) en la salida. Útil para identificar rápidamente páginas vacías o de tamaños anómalos.
- **`-sc`**:
  - Muestra el código de estado HTTP (`Status Code`) de la respuesta (e.g., `200`, `302`, `403`, `404`).
- **`-location`**:
  - Si la respuesta es una redirección (3xx), muestra la URL a la que redirige (el valor de la cabecera `Location`).
- **`-favicon`**:
  - Descarga el favicon.ico de la página y calcula su hash (mmh3). Es extremadamente útil para el fingerprinting, ya que muchas plataformas (Jira, Confluence, etc.) usan favicons por defecto. Puedes buscar estos hashes en bases de datos online o en tus propios registros para identificar tecnologías.
- **`-title`**:
  - Extrae y muestra el contenido de la etiqueta `<title>` de la página HTML. Te da una idea rápida del propósito de la página. (Corregido de "tittle" a "title").
- **`-tech-detect`**:
  - Intenta detectar las tecnologías web utilizadas en el host (servidor web, frameworks, librerías JavaScript, CMS, etc.).
- **`-ip`**:
  - Muestra la dirección o direcciones IP a las que resuelve el host.
- **`-ports 80,443,8080,8000`**:
  - Especifica una lista de puertos a probar en cada host. Por defecto, `httpx` prueba puertos comunes (como 80 y 443), pero con esto puedes ampliar la búsqueda.
- **`-probe-all-ips`**:
  - Si un dominio resuelve a múltiples direcciones IP, `httpx` probará todas ellas en lugar de detenerse en la primera que responda.
- **`-follow-redirects`**:
  - Sigue las redirecciones HTTP y muestra la información de la página final.
- **`-o lista-httpx.txt`**:
  - Guarda la salida (`-output`) en el archivo especificado (`lista-httpx.txt`).

### Otras Opciones Útiles que Debes Conocer

- **`-silent`**: Modo silencioso. Elimina el banner de inicio y otra información de estado, mostrando solo los resultados. Imprescindible para encadenar comandos y para salidas limpias.
- **`-threads <numero>`**: Ajusta el número de hilos concurrentes para aumentar o disminuir la velocidad del escaneo.
- **`-vhost`**: Indica si el host es un host virtual. Puede ayudar a identificar si un mismo servidor aloja múltiples sitios web.
- **`-path <ruta>`**: Permite probar una ruta específica en todos los hosts de la lista (e.g., `-path /admin.php`).
- **`-x <metodo>`**: Permite probar métodos HTTP específicos (e.g., `-x GET,POST,OPTIONS`).
- **`-json`**: Guarda la salida en formato JSON, que es ideal para ser procesada posteriormente por otros scripts o herramientas.
- **`-H "Header: Value"`**: Permite añadir cabeceras personalizadas a las peticiones.
- **`-status-code` y `-content-length`**: Son los nombres completos de `-sc` y `-cl`.
- **`-tls-probe`**: Fuerza a probar el puerto TLS (HTTPS) y extraer datos del certificado si es posible.
- **`-csp-probe`**: Extrae la cabecera Content-Security-Policy.
- **`-cname`**: Extrae los registros CNAME del host.

### Ejemplo de Workflow Integrado

El verdadero poder se ve al encadenar herramientas. Este es el flujo de trabajo básico que usarás una y otra vez en bug bounty:

```bash
# 1. Descubrir subdominios con subfinder
# 2. Filtrar los que están vivos y recopilar info con httpx
# 3. Guardar el resultado en un archivo

subfinder -d ejemplo.com -silent -all | httpx -silent -title -sc -tech-detect -o hosts_vivos_ejemplo.com.txt
```

Este simple one-liner te da una lista limpia de subdominios activos con su título, código de estado y tecnologías detectadas, lista para empezar a analizar más a fondo.
