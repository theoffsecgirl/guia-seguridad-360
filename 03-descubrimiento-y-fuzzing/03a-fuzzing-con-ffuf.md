# Fuzzing con ffuf: Descubriendo lo Oculto

`ffuf` (Fuzz Faster U Fool) es una herramienta de fuzzing web escrita en Go, extremadamente rápida y diseñada para ser muy flexible. "Fuzzing", en este contexto, significa probar una gran cantidad de payloads (normalmente de un diccionario o "wordlist") contra un endpoint web para descubrir contenido oculto, parámetros vulnerables, o hosts virtuales.

Es una herramienta esencial en la fase de reconocimiento y análisis de vulnerabilidades para casi cualquier objetivo web.

---

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
