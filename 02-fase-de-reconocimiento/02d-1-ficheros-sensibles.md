# Técnica Profunda: Ficheros Sensibles Expuestos

### Introducción

En el fragor del desarrollo y los despliegues, es muy común que los desarrolladores dejen accidentalmente archivos y directorios sensibles expuestos en los servidores web. Estos archivos no forman parte de la aplicación visible, pero contienen información crítica sobre la infraestructura, el código fuente, las credenciales y los procesos internos de la organización.

Para un pentester o un bug hunter, encontrar estos archivos es una de las formas más rápidas de escalar privilegios o encontrar vulnerabilidades de alto impacto. La técnica principal para encontrarlos es el **descubrimiento de contenido** mediante fuerza bruta con diccionarios.

### La Joya de la Corona: El Directorio `.git` Expuesto

Cuando encuentras un directorio `.git` accesible públicamente en la raíz de una aplicación web, has encontrado una auténtica mina de oro. El directorio `.git` es donde el sistema de control de versiones Git almacena toda la información de un repositorio de código.

**¿Qué hay dentro y por qué nos interesa?**

* **`.git/HEAD`**: Es un simple puntero que nos dice en qué rama se está trabajando actualmente (e.g., `ref: refs/heads/master`). Nos da una primera pista sobre la estructura del repositorio.
* **`.git/config`**: Contiene la configuración del repositorio. Para nosotros, lo más interesante es la URL del repositorio remoto (`[remote "origin"]`). Esto nos puede llevar al repositorio en GitHub, GitLab, Bitbucket, etc., que podría ser privado.
* **`.git/index`**: Es una base de datos binaria (el "staging area") que contiene una lista de todos los archivos del repositorio, sus permisos y los IDs de los objetos asociados. Es fundamental para reconstruir el código.
* **`.git/objects/`**: El corazón del repositorio. Aquí se guardan todos los objetos de Git (blobs, trees, commits, tags) comprimidos y hasheados. Contiene **todas las versiones de todos los archivos que han existido en el repositorio**.
* **`.git/refs/`**: Contiene los hashes de los commits para cada rama (`heads/`) y etiqueta (`tags/`), lo que nos permite saber cuáles son los commits más recientes.

**¿Por qué es tan Peligroso?**

Si un directorio `.git` está expuesto, un atacante puede **reconstruir el repositorio completo en su máquina local**, incluyendo todo el historial de cambios. Esto significa que no solo se obtiene el código fuente actual, sino también cualquier secreto, contraseña o clave API que un desarrollador haya subido por error en el pasado, **incluso si lo borró en un commit posterior**.

**Herramientas para Explotarlo:**

* **`git-dumper`**: Una herramienta de Python que automatiza la descarga de un directorio `.git` expuesto.
* **GitTools (`Finder`, `Dumper`, `Extractor`):** Un conjunto de herramientas en Perl y Bash para encontrar, descargar y extraer el contenido de repositorios Git expuestos.
* **Manualmente (con `curl` o `wget`):** Si las herramientas no funcionan, se puede intentar descargar los archivos clave (`HEAD`, `index`, `config`, `refs/heads/master`) y luego los objetos uno a uno.

### Otros Archivos Expuestos Comunes y su Propósito (Ofensivo)

Aquí tienes una lista de otros archivos y directorios que deberías buscar siempre.

#### Ficheros de Contenedores y Orquestación

* **`docker-compose.yml`**:
  * **Propósito Legítimo:** Define un entorno multi-contenedor para Docker.
  * **Por qué nos interesa:** A menudo contiene contraseñas en texto plano, claves API en variables de entorno, nombres de servicios internos, mapeos de puertos y rutas de volúmenes que revelan la estructura de la aplicación.
* **`Dockerfile`**:
  * **Propósito Legítimo:** Instrucciones para construir una imagen de Docker.
  * **Por qué nos interesa:** Nos dice la imagen base (que puede tener vulnerabilidades conocidas), qué software y versiones están instaladas, cómo se configura el entorno, si se copian archivos sensibles a la imagen, y qué usuario ejecuta la aplicación. Es un manual de instrucciones para replicar su entorno.

#### Ficheros de Configuración

* **`.env`**:
  * **Propósito Legítimo:** Almacenar variables de entorno para una aplicación (común en frameworks como Laravel, Node.js, etc.).
  * **Por qué nos interesa:** **¡Es el santo grial!** Suele contener credenciales de bases de datos, claves API de servicios de terceros (AWS, Stripe, etc.), claves de cifrado y otros secretos en texto plano.
* **`wp-config.php`**:
  * **Propósito Legítimo:** Fichero de configuración de WordPress.
  * **Por qué nos interesa:** Contiene el nombre de la base de datos, el usuario, la contraseña y las "authentication unique keys and salts". Con esto, a menudo tienes control total sobre el sitio.

#### Ficheros de Construcción y Dependencias

* **`package.json` (Node.js)** / `composer.json` (PHP) / `requirements.txt` (Python) / `Gemfile` (Ruby):
  * **Propósito Legítimo:** Listan las dependencias del proyecto.
  * **Por qué nos interesa:** Nos da una lista exacta de todas las librerías y sus versiones. Podemos buscar vulnerabilidades conocidas (CVEs) para esas versiones específicas y atacar una dependencia vulnerable.
* **`.npmrc`**:
  * **Propósito Legítimo:** Fichero de configuración para NPM (el gestor de paquetes de Node.js).
  * **Por qué nos interesa:** Puede contener tokens de autenticación (`_authToken`) para acceder a registros privados de NPM. Un hallazgo muy valioso.

#### Ficheros de Entornos de Desarrollo (IDE) y Temporales

* **`.vscode/`, `.idea/`**:
  * **Propósito Legítimo:** Carpetas de configuración para los editores Visual Studio Code e IntelliJ IDEA.
  * **Por qué nos interesa:** Pueden filtrar rutas del sistema de ficheros del desarrollador, configuraciones de lanzamiento y depuración, o listas de archivos del proyecto.
* **`.swp`**:
  * **Propósito Legítimo:** Fichero de intercambio (swap file) del editor Vim. Se crea cuando se edita un archivo para poder recuperarlo si el editor se cierra inesperadamente.
  * **Por qué nos interesa:** Si un desarrollador estaba editando un fichero de configuración y el proceso se interrumpió, el fichero `.swp` podría haber quedado en el servidor, conteniendo cambios no guardados o el contenido completo del fichero original (e.g., `wp-config.php.swp`).

### ¿Cómo Encontrar Estos Archivos?

La técnica principal es la **fuerza bruta de contenido** con diccionarios.

1. **Uso de Herramientas de Fuzzing:**
   * **`ffuf`**, **`gobuster`**, **`dirsearch`**, **`feroxbuster`**.
2. **Uso de Wordlists Específicas:**
   * Utiliza listas de palabras de alta calidad como las de **SecLists**. Hay listas específicas para buscar este tipo de archivos y directorios.
   * **Comando Ejemplo (`ffuf`):**
     ```bash
     ffuf -w /ruta/a/SecLists/Discovery/Web-Content/common.txt -u [https://objetivo.com/FUZZ](https://objetivo.com/FUZZ) -mc 200,403
     ```
3. **Google Dorking:** A veces Google indexa estos archivos si no están protegidos por `robots.txt`.
   * `site:objetivo.com ext:env intext:"DB_PASSWORD"`
   * `inurl:".git" site:objetivo.com -github.com`
