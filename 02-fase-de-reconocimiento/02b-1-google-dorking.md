# Técnica Profunda: Google Dorking

El **Google Dorking** (también conocido como Google Hacking) es una técnica que utiliza operadores de búsqueda avanzada de Google para encontrar información específica que normalmente no sería visible a través de una navegación web simple. Es una herramienta fundamental en la fase de reconocimiento pasivo para descubrir información sensible, archivos expuestos, vulnerabilidades potenciales, subdominios, y mucho más, todo ello sin enviar ni un solo paquete directamente al objetivo (lo hace Google por ti).

La idea es usar la inmensa capacidad de indexación de Google a nuestro favor para "pescar" (dorking) información relevante.

### Operadores y Técnicas Clave de Google Dorking

Aquí te explico los operadores que has mencionado, que son de los más útiles:

1. **`site:` - Filtrar por un Sitio Específico**
   * **Uso:** Restringe la búsqueda a un dominio o subdominio concreto.
   * **Ejemplo:**
     * `site:ejemplo.com` (Busca solo dentro de `ejemplo.com` y todos sus subdominios)
     * `site:blog.ejemplo.com` (Busca solo dentro del subdominio `blog.ejemplo.com`)
     * `site:ejemplo.com -www` (Busca en `ejemplo.com` pero excluye el subdominio `www.ejemplo.com`, útil para encontrar otros subdominios).
   * **Para qué sirve:** Para enfocar tu búsqueda en el objetivo y descubrir toda la información que Google ha indexado sobre él.
2. **`-` (Signo Menos) - Excluir Términos o Sitios**
   * **Uso:** Excluye resultados que contengan un término específico o un filtro `site:`.
   * **Ejemplo:**
     * `site:ejemplo.com -site:desarrollo.ejemplo.com` (Busca en `ejemplo.com` pero excluye el subdominio `desarrollo.ejemplo.com`)
     * `site:ejemplo.com "login" -empleados` (Busca páginas de login en `ejemplo.com` que no contengan la palabra "empleados")
   * **Para qué sirve:** Para refinar tus búsquedas y eliminar ruido o resultados irrelevantes.
3. **`filetype:` o `ext:` - Especificar Extensiones de Archivo**
   * **Uso:** Busca archivos con una extensión específica. Son sinónimos.
   * **Ejemplo:**
     * `site:ejemplo.com filetype:pdf` (Busca archivos PDF en `ejemplo.com`)
     * `site:ejemplo.com ext:xls "confidencial"` (Busca archivos Excel que contengan la palabra "confidencial")
     * `site:ejemplo.com ext:log` (Busca archivos de log)
     * `site:ejemplo.com ext:sql` (Busca volcados SQL, ¡mucho ojo con esto!)
     * `site:ejemplo.com (ext:doc OR ext:docx OR ext:odt)` (Busca múltiples tipos de documentos)
   * **Para qué sirve:** Para encontrar documentos internos, backups, logs, bases de datos exportadas, código fuente, o cualquier archivo sensible que haya sido indexado por error.
4. **`inurl:` - Buscar Texto en la URL**
   * **Uso:** Busca páginas cuyas URLs contengan un término específico.
   * **Ejemplo:**
     * `site:ejemplo.com inurl:admin` (Busca páginas en `ejemplo.com` que tengan "admin" en su URL, e.g., `ejemplo.com/admin/login.php`)
     * `site:ejemplo.com inurl:login.php`
     * `site:ejemplo.com inurl:id=` (Busca URLs que contengan el parámetro "id=", potencial punto de entrada para SQLi o IDOR)
     * `inurl:".git" site:ejemplo.com -github.com` (Busca directorios `.git` expuestos en el dominio, excluyendo los de GitHub)
   * **Para qué sirve:** Para encontrar paneles de administración, páginas de login, parámetros específicos en URLs que puedan ser vulnerables, o tecnologías usadas (e.g., `inurl:.php`, `inurl:.aspx`).
5. **`intitle:` - Buscar Texto en el Título de la Página**
   * **Uso:** Busca páginas que contengan un término específico en su etiqueta `<title>` HTML.
   * **Ejemplo:**
     * `site:ejemplo.com intitle:"panel de administración"`
     * `site:ejemplo.com intitle:"index of"` (Busca listados de directorios habilitados)
     * `intitle:"VNC viewer" port` (Busca VNCs expuestos, ¡con precaución y solo si está en scope!)
   * **Para qué sirve:** Para encontrar páginas con títulos reveladores, como paneles de login, directorios con listado activado, o páginas de error que puedan filtrar información.
6. **Búsqueda de Parámetros (usando `inurl:` y otros operadores):**
   * **Uso:** Como vimos con `inurl:`, puedes buscar patrones de parámetros.
   * **Ejemplo:**
     * `site:ejemplo.com inurl:"id="`
     * `site:ejemplo.com inurl:"redirect_url="` (Potenciales Open Redirects)
     * `site:ejemplo.com inurl:"file="` (Potenciales LFI/Path Traversal)
   * **Para qué sirve:** Identificar puntos de entrada para diversas vulnerabilidades web que dependen de la manipulación de parámetros.
7. **`intext:` - Buscar Texto en el Cuerpo de la Página**
   * **Uso:** Busca páginas que contengan un término específico en el contenido visible del cuerpo de la página (excluyendo título, URL, y enlaces).
   * **Ejemplo:**
     * `site:ejemplo.com intext:"contraseña olvidada"`
     * `site:ejemplo.com intext:"error connecting to database"` (Puede revelar mensajes de error)
     * `intext:"Powered by WordPress" intext:"versión 5.2"` (Busca versiones específicas de software)
   * **Para qué sirve:** Encontrar texto específico, mensajes de error, versiones de software, comentarios de desarrolladores, etc.

### Combinando Operadores (Dorks Avanzados)

La verdadera potencia del Google Dorking reside en combinar estos operadores para crear consultas muy específicas.

* **Ejemplo: Buscar archivos de configuración (`.env`, `.ini`, `.conf`) en un dominio que contengan la palabra "password" o "secret", excluyendo GitHub:** `site:ejemplo.com (ext:env OR ext:ini OR ext:conf) (intext:"password" OR intext:"secret") -site:github.com`
* **Ejemplo: Buscar paneles de login que no sean los típicos de "empleados" o "clientes":** `site:ejemplo.com (intitle:"login" OR inurl:"login") -intext:"empleados" -intext:"clientes"`
* **Ejemplo: Buscar posibles SQL errors en páginas PHP:** `site:ejemplo.com inurl:.php intext:"SQL syntax error"`
