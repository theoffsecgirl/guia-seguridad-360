# Introducción

Muchas aplicaciones web necesitan que los usuarios suban archivos: una foto de perfil, un DNI para verificación, un documento de trabajo, etc. Si esta funcionalidad no se implementa con una seguridad férrea, se convierte en un vector de ataque muy potente.

Explotar una vulnerabilidad en la subida de archivos puede llevar a:

- **Ejecución Remota de Código (RCE):** El impacto más alto. Subir una "webshell" (un script malicioso) y tomar control del servidor.
- **Cross-Site Scripting (XSS):** Atacar a otros usuarios que vean el archivo o su nombre.
- **Path Traversal:** Sobrescribir archivos críticos del servidor o colocar archivos en ubicaciones no deseadas.
- **XML External Entity (XXE):** Si se suben y procesan archivos basados en XML.
- **Denegación de Servicio (DoS):** Subir archivos que colapsen el servidor.

### Anatomía de una Petición de Subida de Archivo

Para entender cómo atacar, primero hay que entender cómo funciona una petición de subida. Suelen usar `POST` con `Content-Type: multipart/form-data`. Aquí tienes un ejemplo capturado con Burp o Caido:

```http
POST /cuenta/subir_imagen.php HTTP/1.1
Host: mibanco-seguro.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryePkpFF7tjBAqx29L
Content-Length: 184

------WebKitFormBoundaryePkpFF7tjBAqx29L
Content-Disposition: form-data; name="user_file"; filename="test.jpg"
Content-Type: image/jpeg

[...contenido binario de la imagen...]
------WebKitFormBoundaryePkpFF7tjBAqx29L--
```

**Puntos clave a manipular:**

1. **`filename="test.jpg"`:** El nombre del archivo. Podemos cambiarlo para probar diferentes extensiones, path traversal o XSS.
2. **`Content-Type: image/jpeg`:** El tipo de archivo que el navegador dice que está enviando. Podemos cambiarlo para intentar engañar a los filtros del servidor.
3. **`[...contenido binario...]`:** El contenido real del archivo. Aquí es donde iría el código de nuestra webshell o nuestro payload XSS.

### Técnicas de Explotación y Bypasses

#### 1. RCE mediante Subida de Webshells

Este es el objetivo principal. Consiste en subir un archivo con código ejecutable (PHP, ASP, etc.) y luego acceder a él a través de su URL para que el servidor lo interprete y nos dé una shell.

**A. Bypass de Filtros de Extensión:**

- **Doble Extensión:** Si el filtro es simple, puede que solo mire la última parte.
  - `shell.php.jpg`
  - `shell.php.123`
- **Extensiones Alternativas:** Los servidores web a veces están configurados para ejecutar otras extensiones además de `.php`.
  - Prueba con: `.php5`, `.phtml`, `.phar`
- **Variaciones de Mayúsculas/Minúsculas:** Si el servidor corre en Windows (que no distingue mayúsculas de minúsculas en nombres de archivo) pero el filtro sí lo hace.
  - `shell.PhP`, `shell.pHp`
- **Null Byte (`%00`):** En aplicaciones antiguas (PHP < 5.3.4), el null byte puede terminar la cadena del nombre de archivo, haciendo que el servidor ignore lo que viene después.
  - `shell.php%00.jpg`

**B. Bypass de Filtros de `Content-Type`:**

A veces el servidor comprueba que el `Content-Type` sea de una imagen (e.g., `image/jpeg`) pero no comprueba la extensión de forma robusta.

- **Estrategia:** Intercepta la petición con Burp. Sube un archivo `shell.php` pero cambia la cabecera `Content-Type` de la petición a `image/jpeg`. El servidor podría aceptar el archivo y guardarlo con la extensión `.php`.

**C. Bypass de Validación de Contenido (Magic Bytes):**

Algunos filtros más avanzados leen los primeros bytes del archivo (los "magic bytes") para verificar que realmente es una imagen.

- **Estrategia:** Añade los magic bytes de un tipo de imagen permitido al principio de tu archivo de webshell.
  - Ejemplo para un GIF:

```php
  GIF89a;
 <?php system($_GET['cmd']); ?>
```

- El servidor lee "GIF89a;", piensa que es un GIF válido, y guarda el archivo. Si lo guarda con extensión `.php`, el código se ejecutará.

#### 2. XSS mediante Subida de Archivos

- **XSS en el Nombre de Archivo:** Si la aplicación muestra el nombre del archivo subido en algún sitio sin codificarlo correctamente.
  - **Payload en `filename`:**

```http
Content-Disposition: form-data; name="file"; filename="<img src=x onerror=alert(document.domain)>.png"
```

- **XSS en el Contenido del Archivo:**
  - **Estrategia:** Sube un archivo que contenga un payload XSS (e.g., `<script>alert(1)</script>`) y manipula la petición para que el `Content-Type` sea `text/html`.
  - Si tienes éxito, cuando alguien acceda a la URL del archivo "subido", el navegador lo renderizará como HTML y ejecutará el script. Esto puede funcionar incluso si la extensión es `.png` o `.jpg`, si el servidor se fía de la cabecera `Content-Type` que tú le envías al servir el archivo.
- **XSS en Archivos SVG:** Los archivos SVG son XML y pueden contener JavaScript. Son un vector de XSS muy común si se permite su subida.
  - **Payload (`payload.svg`):**

```xml
 <svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"/>
```

#### 3. Path Traversal en la Subida

Si la aplicación usa el `filename` para construir la ruta donde se guarda el archivo, se puede intentar usar `../` para salir del directorio de subidas.

- **Objetivo:** Sobrescribir archivos importantes o colocar un archivo en una ubicación inesperada.
- **Payload en `filename`:**

```http
 Content-Disposition: form-data; name="upload"; filename="../../.ssh/authorized_keys"
Content-Type: text/plain
[... tu clave pública SSH ...]
```

Si funciona, podrías obtener acceso SSH al servidor. Otro objetivo podría ser sobrescribir un `.htaccess` para permitir la ejecución de ciertos tipos de archivo, o un `index.php` para poner tu propia puerta trasera.

### Mitigaciones (Cómo Deberían Defenderse)

Entender las defensas te ayuda a saber cómo romperlas.

- **Lista Blanca de Extensiones:** Solo permitir un conjunto cerrado de extensiones seguras (e.g., `jpg`, `png`, `pdf`). Rechazar todo lo demás. Es mucho más seguro que usar una lista negra.
- **Renombrar Archivos al Guardar:** La mejor práctica. La aplicación debería generar un nombre de archivo aleatorio y seguro, ignorando completamente el nombre proporcionado por el usuario.
- **Validar el Contenido del Archivo:** No fiarse de la extensión ni del `Content-Type`. Verificar los magic bytes y, si es una imagen, re-procesarla con una librería segura (esto puede eliminar metadatos y código malicioso).
- **Almacenar Archivos Fuera del Web Root:** Guardar los archivos en un directorio que no sea accesible directamente desde una URL. Servirlos a través de un script que verifique los permisos del usuario.
- **Forzar `Content-Disposition: attachment`:** Al servir los archivos, usar esta cabecera para indicar al navegador que debe descargar el archivo, no intentar mostrarlo.
