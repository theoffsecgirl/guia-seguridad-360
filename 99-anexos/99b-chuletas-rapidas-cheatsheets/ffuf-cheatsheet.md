`ffuf` (Fuzz Faster U Fool) es la navaja suiza para el fuzzing web. Es rapidísima, súper flexible y esencial para el descubrimiento de contenido, hosts virtuales, y parámetros. Aquí tienes una guía de referencia rápida con los comandos y opciones más útiles.

### Uso Básico (Fuzzing de Directorios y Archivos)

La tarea más común: encontrar directorios y archivos ocultos.

```bash
# Escaneo de directorios básico - ¡Empieza por aquí!
ffuf -w wordlist.txt -u https://target.com/FUZZ

# Añade verbosidad para ver más detalles del proceso (-v)
ffuf -w wordlist.txt -u https://target.com/FUZZ -v

# Escanear por archivos con múltiples extensiones (-e)
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.txt,.html,.bak

# Usar recursión para explorar directorios que se encuentren (-recursion)
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -v
# La salida con -v muestra una estructura de árbol:
# /admin/
# ├── /panel.php
# └── /users/
#     └── /list.php
```

### Personalización de Peticiones

Para escenarios complejos, como APIs o peticiones con cabeceras específicas.

```bash
# Usar una petición HTTP guardada en un fichero (¡brutal para APIs!)

# 1. Guarda la petición en un fichero (ej: peticion.txt):
#    Asegúrate de marcar el punto de fuzzing con la palabra clave FUZZ.

POST /api/v1/users HTTP/1.1
Host: target.com
Content-Type: application/json
X-API-KEY: clave_secreta

{"username": "FUZZ"}

# 2. Lanza ffuf con la petición guardada:
ffuf -request peticion.txt -w wordlist_usuarios.txt -request-proto http

# 3. Puedes sobreescribir partes de la petición si es necesario:
ffuf -request peticion.txt -w wordlist.txt \
     -H "Host: nuevo-dominio.com" \  # Cambia la cabecera Host
     -X GET                          # Cambia el método HTTP a GET
```

### Descubrimiento de Parámetros (Finding Hidden Inputs)

Para encontrar parámetros GET o POST que la aplicación procesa pero que no son obvios.

```bash
# Fuzzing de parámetros GET
ffuf -w params_wordlist.txt -u https://target.com/api?FUZZ=test

# Fuzzing de parámetros POST
ffuf -w params_wordlist.txt -u https://target.com/api \
     -X POST -d "FUZZ=test"

# Fuzzing en múltiples posiciones (ej: nombre de parámetro y valor)
ffuf -w params.txt:FUZZ1 -w values.txt:FUZZ2 \
     -u https://target.com/api?FUZZ1=FUZZ2
```

### Fuzzing DNS y Virtual Hosts (VHosts)

Para descubrir subdominios o aplicaciones ocultas en un mismo servidor.

```bash
# Enumeración de subdominios (fuerza bruta de DNS)
ffuf -w subdominios.txt -u http://FUZZ.ejemplo.com

# Permutaciones de DNS (ej: app-dev, app-staging, etc.)
ffuf -w permutaciones.txt -u http://app-FUZZ.ejemplo.com

# Descubrimiento de Virtual Hosts (¡para encontrar sitios ocultos!)
# Apuntas a la IP y cambias la cabecera Host. Filtra por tamaño para ocultar la respuesta por defecto.
ffuf -w vhosts.txt -u http://<IP_DEL_TARGET> \
     -H "Host: FUZZ.target.com" -fs <tamaño_pagina_defecto>

# Comprobación rápida de vhosts con valores comunes
# (-w /dev/null porque los payloads van en -mode clusterbomb con -H)
ffuf -w /dev/null -u http://<IP_DEL_TARGET> \
     -H "Host: FUZZ" \
     -mode clusterbomb -w "localhost,127.0.0.1,default,kubernetes,kubernetes.default"
```

**¿Por qué funciona el VHost fuzzing?** Porque los servidores web pueden alojar múltiples sitios en una única IP. El servidor decide qué sitio mostrar basándose en la cabecera `Host`. Muchos sitios de staging o administración están "ocultos" de esta manera.

### Filtrado de Respuestas (¡Esencial para no volverse loco!)

Filtrar el ruido es clave para que los resultados sean útiles.

```bash
# Filtrado por Tamaño (para ignorar respuestas genéricas de "No Encontrado")
-fs 1234  # Filtrar (ignorar) respuestas con este tamaño en bytes (Filter Size)
-fl 12    # Filtrar por número de líneas (Filter Lines)
-fw 77    # Filtrar por número de palabras (Filter Words)

# Filtrado por Códigos de Estado
-fc 404,403,302 # Filtrar (ignorar) estos códigos de estado (Filter Codes)
-mc 200,301     # Mostrar solo respuestas con estos códigos (Match Codes)

# Filtrado por Número de Palabras (muy útil para bypass de autenticación)
-fw 57   # Filtrar (ignorar) respuestas con 57 palabras
-mw 57   # Mostrar solo respuestas con 57 palabras (Match Words)

# Filtrado con Expresiones Regulares (RegEx)
-fr "error|forbidden"     # Filtrar si la respuesta contiene este patrón (Filter Regex)
-mr "success|authenticated" # Mostrar solo si la respuesta contiene este patrón (Match Regex)
```

### Control de Rendimiento y Salida

Para ser sigiloso, rápido y organizado.

```bash
# Limitar la velocidad (para ser amable con el servidor o evitar WAFs)
-rate 50  # 50 peticiones por segundo
-p 0.1    # Pausa de 0.1 segundos entre cada petición

# Guardar los resultados
-o resultados.json      # Guardar salida en un fichero
-of json                # Especificar el formato de salida (json, csv, html, etc.)

# Modo silencioso (sin banner ni estadísticas, solo resultados)
-s
```

### Consejos Prácticos (Pro Tips)

- **Empieza lento:** Comienza con un `-rate` bajo (ej: `-rate 10`) y auméntalo si el servidor es estable.
- **Usa `-v`:** La verbosidad ayuda a visualizar la estructura de directorios, especialmente con la recursión.
- **Combina filtros:** Usa `-mc 200 -fs <TAMAÑO_DEL_404>` para una precisión máxima.
- **Guarda peticiones complejas:** Usa `-request` para APIs y peticiones con muchas cabeceras o cookies. Es reutilizable y limpio.
- **Calibra tus filtros:** Antes de un fuzzing masivo, haz unas cuantas peticiones a directorios que no existen para identificar el tamaño, número de palabras/líneas y patrones de la respuesta de "No Encontrado" y así poder filtrarla bien.
- **Monitoriza patrones de respuesta:** Fíjate si el servidor responde de forma diferente a distintos tipos de entradas antes de configurar los filtros.

### Casos de Uso Comunes

- **Descubrimiento de endpoints de API:** Usa `-request` con un cuerpo JSON y fuzzing en diferentes partes.
- **Paneles de administración ocultos:** `ffuf` con `-recursion` y una buena lista de palabras de directorios y extensiones (`-e .php,.html,.bak`).
- **Bypass de WAFs:** `ffuf` con un `-rate` bajo, pausas (`-p`), y cabeceras personalizadas (`-H`) para imitar a un navegador normal.
- **Endpoints de desarrollo:** Fuzzing de VHosts con listas de palabras comunes (`dev`, `staging`, `test`, `uat`, `api-dev`, etc.).
