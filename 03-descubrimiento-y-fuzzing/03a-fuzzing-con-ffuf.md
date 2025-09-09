# # Fuzzing con ffuf: Descubriendo lo Oculto

`ffuf` (Fuzz Faster U Fool) es una herramienta de fuzzing web escrita en Go, extremadamente rápida y diseñada para ser muy flexible. "Fuzzing", en este contexto, significa probar una gran cantidad de payloads (normalmente de un diccionario o "wordlist") contra un endpoint web para descubrir contenido oculto, parámetros vulnerables, o hosts virtuales.
Es una herramienta esencial en la fase de reconocimiento y análisis de vulnerabilidades para casi cualquier objetivo web.
--------------------------------------------------------------------------------------------------------------------------

## 1. Fuzzing de Directorios y Archivos

Este es el caso de uso más común: encontrar directorios y archivos que no están enlazados públicamente en un sitio web.
**Comando Básico:**

```bash
# Escaneo de directorios básico - ¡Empieza por aquí!
ffuf -w wordlist.txt -u [https://target.com/FUZZ](https://target.com/FUZZ)
```

* **`-w wordlist.txt`**: Especifica la lista de palabras (el diccionario) que se usará para el fuzzing. `ffuf` reemplazará la palabra clave `FUZZ` con cada línea de este archivo.
* **`-u https://target.com/FUZZ`**: La URL (`-url`) objetivo. La palabra clave **`FUZZ`** es el marcador de posición donde `ffuf` inyectará cada palabra de la wordlist.
  **Ampliando el escaneo:**
* **Múltiples extensiones (`-e`):** Para buscar archivos como `.php`, `.txt`, `.html,.bak`. **Bash**

```
ffuf -w wordlist.txt -u [https://target.com/FUZZ](https://target.com/FUZZ) -e .php,.txt,.html,.bak
```

* **Recursión (`-recursion`):** Para explorar automáticamente los directorios que se encuentren. **Bash**

```
ffuf -w wordlist.txt -u [https://target.com/FUZZ](https://target.com/FUZZ) -recursion -recursion-depth 2 -v
```

---

## 2. Descubrimiento de Virtual Hosts (VHosts)

Un servidor web en una única dirección IP puede alojar múltiples sitios web. El servidor sabe qué sitio mostrar basándose en la cabecera `Host` de la petición HTTP. Con `ffuf`, podemos descubrir estos sitios "ocultos".
**Comando Clave:**
**Bash**

```
# Apuntas a la IP del target y cambias la cabecera Host
ffuf -w vhosts.txt -u http://<IP_DEL_TARGET> -H "Host: FUZZ.target.com"
```

* **`-H "Host: FUZZ.target.com"`**: La cabecera (`-Header`) `Host` se modifica en cada petición. `FUZZ` será reemplazado por cada palabra de tu wordlist. Es crucial filtrar la respuesta por defecto (con `-fs` o `-fw`) para ver solo los VHosts que devuelven contenido diferente.

---

## 3. Descubrimiento de Parámetros

Puedes usar `ffuf` para encontrar parámetros GET o POST que la aplicación procesa pero que no son obvios.
**Comandos de Ejemplo:**
**Bash**

```
# Fuzzing de parámetros GET
ffuf -w params_wordlist.txt -u [https://target.com/api?FUZZ=test](https://target.com/api?FUZZ=test)
# Fuzzing de parámetros POST
ffuf -w params_wordlist.txt -u [https://target.com/api](https://target.com/api) -X POST -d "FUZZ=test"
```

---

## 4. Filtrado de Respuestas (¡Esencial!)

Filtrar el ruido es clave para que los resultados sean útiles.

* **Por Códigos de Estado:**
  * **`-mc 200,301,403`**: Mostrar solo respuestas con estos códigos (Match Codes).
  * **`-fc 404`**: Filtrar (ignorar) los códigos 404 (Filter Codes).
* **Por Tamaño de Respuesta:**
  * **`-fs 1234`**: Filtrar respuestas con este tamaño exacto en bytes (Filter Size).
  * **`-fl 12`**: Filtrar por número de líneas (Filter Lines).
  * **`-fw 57`**: Filtrar por número de palabras (Filter Words).
* **Por Expresiones Regulares (RegEx):**
  * **`-fr "error|forbidden"`**: Filtrar si la respuesta contiene este patrón (Filter Regex).
  * **`-mr "success|authenticated"`**: Mostrar solo si la respuesta contiene este patrón (Match Regex).

---

## 5. Fuzzing Avanzado con Ficheros de Petición

Para escenarios complejos como APIs con cabeceras específicas o cuerpos JSON, puedes guardar una petición HTTP en un archivo y decirle a `ffuf` que la use como plantilla.

1. **Guarda la petición en `peticion.txt`**, marcando el punto de fuzzing con `FUZZ`: **HTTP**

```
POST /api/v1/users HTTP/1.1
Host: target.com
Content-Type: application/json
X-API-KEY: clave_secreta
{"username": "FUZZ"}
```

2. **Lanza `ffuf` con la opción `-request`**: **Bash**

```
ffuf -request peticion.txt -w wordlist_usuarios.txt -request-proto http

```

Aquí tienes tu guía sobre ffuf, mejorada y aclarada según los estándares actuales, alineada con buenas prácticas, casos reales y extracción de señal. Incluyo filtros avanzados y organización de resultados según flujo profesional.[^4]

---

# Fuzzing con ffuf: Descubriendo lo Oculto

`ffuf` (Fuzz Faster U Fool) es una herramienta de fuzzing web escrita en Go, extremadamente rápida y flexible. Permite probar miles de payloads (de una wordlist) contra endpoints web para descubrir contenido oculto, parámetros o virtual hosts, y es esencial en recon y pentest web.[^3]

---

## 1. Fuzzing de Directorios y Archivos (Descubrimiento de contenido)

**Uso básico:**

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ
```

- **-w wordlist.txt:** Wordlist con posibles directorios/archivos.
- **-u .../FUZZ:** La palabra FUZZ será reemplazada por cada entrada de la wordlist.

**Extensiones múltiples:**

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.txt,.html,.bak
```

- Usa -e para añadir posibles extensiones y encontrar ficheros interesantes.

**Recursivo:**

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2 -v
```

- Usar recursion para descubrir subdirectorios automáticamente. Controla profundidad para evitar ruido.[^2]

---

## 2. Descubrimiento de Virtual Hosts (VHost fuzzing)

Descubre “sitios ocultos” alojados en la misma IP/servidor usando el header Host.

**Básico:**

```bash
ffuf -w vhosts.txt -u http://<IP_TARGET>/ -H "Host: FUZZ.target.com"
```

- -H personaliza la cabecera Host y FUZZ la sustituye por cada entrada.
- Indispensable filtrar la respuesta por defecto del vhost o el valor de tamaño/código con -fs/-fw/-fc para quedarse solo con los cambios reales.[^7]

---

## 3. Descubrimiento de Parámetros (GET y POST)

**Fuzz GET:**

```bash
ffuf -w params_wordlist.txt -u "https://target.com/api?FUZZ=test"
```

**Fuzz POST:**

```bash
ffuf -w params_wordlist.txt -u https://target.com/api -X POST -d "FUZZ=test"
```

- Reemplaza FUZZ por cada posible nombre de parámetro; combina con matchers y filtros para centrar la búsqueda.[^5]

---

## 4. Filtrado de Respuestas (Esencial)

Clave para reducir el ruido.

- **-mc 200,301,403**: Solo muestra estos códigos de respuesta.
- **-fc 404**: Filtra respuestas con 404 (habitual en carpetas/archivos inexistentes).
- **-fs 1234**: Filtra por tamaño de respuesta (en bytes).
- **-fw 57, -fl 12**: Por número de palabras o líneas.
- **-mr 'success|authenticated'**: Solo muestra si el body contiene patrones (Match Regex).
- **-fr 'error|forbidden'**: Filtra resultados que contengan estos patrones (Filter Regex).
  Combina varios según caso para depurar falsos positivos, especialmente cuando la app responde igual a múltiples paths.[^10]

---

## 5. Fuzzing avanzado: Peticiones personalizadas y modos múltiples

- **-request (modo raw):** Usa una petición HTTP completa como plantilla. Pon “FUZZ” donde quieras variar el dato.

1. Guarda la petición en un archivo (por ejemplo, `peticion.txt`):

```
POST /api/v1/users HTTP/1.1
Host: target.com
Content-Type: application/json
X-API-KEY: clave_secreta

{"username": "FUZZ"}
```

2. Ejecuta:

```bash
ffuf -request peticion.txt -w wordlist_usuarios.txt -request-proto http
```

- **Modos avanzados:**
  - **Sniper (por defecto):** Fuzzea con una sola wordlist/un solo FUZZ.
  - **Pitchfork:** Fuzzea varias posiciones en paralelo (listas alineadas).
  - **Clusterbomb:** Combina todas las listas posibles (explosión combinatoria).

```bash
# Múltiples params y listas
ffuf -w users.txt:USER -w pwds.txt:PASS -u "https://target.com/login?user=USER&pwd=PASS" -mode clusterbomb
```

- Fuzz de headers, verbos HTTP y otros elementos avanzados:

```bash
ffuf -w headers.txt -u https://target.com/ -H "X-api-token: FUZZ"
ffuf -w verbs.txt -X FUZZ -u https://target.com/resource
```

---

## Consejos y mejores prácticas

- Filtra y revisa resultados con -fs/-fw/-fc y combinaciones con regex (-mr/-fr) para centrarte en lo relevante.
- Ajusta rate y concurrency (-t <num>) según respuesta del servidor para no provocar bloqueos.
- Guarda siempre tus hallazgos en archivos organizados por target/caso.
- Usa wordlists especializadas para fuzzing más profundo en aplicaciones concretas.
- Los resultados con 401/403 o códigos anómalos pueden requerir más análisis: prueba distintos usuarios, sesiones, cabeceras y roles.

---

## Pipeline típico en pentesting

```bash
# Fuzz de rutas + filtrado + priorización rápida
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
-u https://target.com/FUZZ -mc 200,204,301,302,307,401,403 -fs 0 -o rutas_validas.txt
```

---

Recuerda: ffuf es tan poderosa como la wordlist y los filtros que le pongas. Testea, filtra y prioriza para descubrir lo que otros dejan pasar.[^1]
<span style="display:none">[^17]</span>


[^1]: https://hackviser.com/tactics/tools/ffuf
    
[^2]: https://www.reddit.com/r/bugbounty/comments/1f8mhjd/ultimate_ffuf_cheatsheet_advanced_fuzzing_tactics/
    
[^3]: https://www.kali.org/tools/ffuf/
    
[^4]: https://www.hackercoolmagazine.com/beginners-guide-to-ffuf-tool/
    
[^5]: https://ffuf.hashnode.dev/fuzzing-using-ffuf
    
[^6]: http://ffuf.me/sub/vhost
    
[^7]: https://gist.github.com/shollingsworth/9e765031ab98681900d399709549f1e1
    
[^8]: https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/
    
[^9]: https://infosecwriteups.com/content-discovery-with-ffuf-5bc81d2d8db6
    
[^10]: https://www.acceis.fr/ffuf-advanced-tricks/
    
[^11]: https://github.com/ffuf/ffuf
    
[^12]: https://hackzapsecurity.in/Blogs/blogCardPages/blogs/fuzz-hidden-directories.html
    
[^13]: https://groups.google.com/g/zaproxy-users/c/x4sem9l6_dI
    
[^14]: https://www.thehacker.recipes/web/recon/virtual-host-fuzzing
    
[^15]: https://amrelsagaei.com/fuzz-everything
    
[^16]: https://security.packt.com/fuzzing-faster-with-ffuf/
    
[^17]: https://web.mrw0l05zyn.cl/reconocimiento-y-recoleccion-de-informacion/subdominios-y-virtual-host-vhost
