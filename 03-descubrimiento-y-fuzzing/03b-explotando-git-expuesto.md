# Explotando Repositorios .git Expuestos

Cuando encuentras un directorio `.git` accesible en un servidor web, tu objetivo principal es **descargar el repositorio completo para reconstruir el código fuente y, lo más importante, su historial de commits**. El verdadero tesoro no siempre está en el código actual, sino en las contraseñas, claves API y otros secretos que los desarrolladores subieron por error y luego "borraron" en un commit posterior. El historial de Git no olvida.

---

## Herramientas para la Descarga del Repositorio

### Herramienta 1: `git-dumper`

`git-dumper` es una herramienta muy popular y directa. Es un script de Python que se especializa en una sola cosa: descargar un repositorio `.git` expuesto de un servidor web.

**Instalación:**

```bash
# Clona el repositorio de la herramienta
git clone [https://github.com/arthaud/git-dumper.git](https://github.com/arthaud/git-dumper.git)

# Entra en el directorio
cd git-dumper/

# Instala las dependencias
pip3 install -r requirements.txt
```

**Uso:** El uso es súper sencillo. Solo necesitas la URL del directorio `.git` y una carpeta donde quieras guardar el resultado.


```
# Sintaxis: python3 git-dumper.py <URL_DEL_.GIT> <CARPETA_DE_SALIDA>
python3 git-dumper.py [http://sitio-vulnerable.com/.git/](http://sitio-vulnerable.com/.git/) ./repo-descargado
```

**Resultado:** La herramienta intentará descargar todos los objetos, el índice, la configuración y demás archivos necesarios para reconstruir el repositorio en la carpeta de salida.

### Herramienta 2: La Suite GitTools

GitTools es un conjunto de scripts (en Bash y Python) aún más completo, no solo para descargar, sino también para encontrar y analizar repositorios Git expuestos.

**Instalación:**


```
git clone [https://github.com/internetwache/GitTools.git](https://github.com/internetwache/GitTools.git)
```

La suite se compone de tres herramientas principales en sus respectivas subcarpetas: `Finder`, `Dumper` y `Extractor`.

#### `Finder/gitfinder.py`

* **Propósito:** Escanea una lista de sitios web para ver si tienen un directorio `.git` expuesto. Útil para pruebas a gran escala.
* **Uso:** Le pasas un archivo con una lista de URLs. **Bash**

  ```
  # Desde el directorio de GitTools/Finder/
  python3 gitfinder.py -i /ruta/a/lista_de_urls.txt
  ```

#### `Dumper/gitdumper.sh`

* **Propósito:** Similar a la herramienta `git-dumper`, este script de Bash también descarga el repositorio.
* **Uso:****Bash**

  ```
  # Desde el directorio de GitTools/Dumper/
  ./gitdumper.sh [http://sitio-vulnerable.com/.git/](http://sitio-vulnerable.com/.git/) ./repo-descargado
  ```

#### `Extractor/extractor.sh`

* **Propósito:****Esta es la verdadera joya de la suite.** Una vez que has descargado el repositorio, usas `extractor.sh` para **recorrer todo el historial de commits y extraer todas las versiones de todos los archivos** a una carpeta limpia. Esto es crucial para encontrar secretos que fueron eliminados.
* **Uso:**
  1. Primero, descarga el repo con `gitdumper.sh`.
  2. Luego, ejecuta el extractor sobre el directorio resultante. **Bash**

     ```
     # Desde el directorio de GitTools/Extractor/
     ./extractor.sh /ruta/al/repo-descargado /ruta/a/codigo-extraido
     ```

---

## Analizando el Código Fuente Recuperado: La Caza de Secretos

Una vez tienes el código, empieza la verdadera caza.

### ¿Dónde Suelen Estar los Archivos Interesantes?

* **Ficheros de Configuración:** Es el primer sitio donde hay que mirar. Aquí se suelen definir las conexiones a bases de datos y las claves API. Ejemplos: `config.php`, `database.yml`, `settings.py`, `.env`, `wp-config.php`.
* **Código Fuente Principal:** A veces, las credenciales están "hardcodeadas" directamente en el código.
* **Logs y Commits del Repositorio `.git`:**
  * **`.git/config`**: Contiene la URL del repositorio remoto, una información valiosísima.
  * **`.git/logs/HEAD`** o `git log`: Revisa los mensajes de los commits. Mensajes como "Fix: remove hardcoded password" te dicen exactamente dónde buscar en el historial.

### Técnicas de Búsqueda de Secretos

1. **Manual con `grep`:** Puedes usar `grep` para buscar palabras clave en todos los archivos extraídos.
   **Bash**

   ```
   # Busca 'password' de forma recursiva e insensible a mayúsculas/minúsculas
   grep -r -i "password" /ruta/a/codigo-extraido
   ```
2. **Herramientas Automatizadas:**

   * **`truffleHog`** y **`gitleaks`**: Estas herramientas están diseñadas específicamente para escanear repositorios Git (incluyendo todo su historial) en busca de secretos y patrones de claves API conocidas. Son mucho más efectivas que un `grep` manual. **Bash**

     ```
     # Ejemplo con truffleHog sobre el directorio .git descargado
     truffleHog git file:///ruta/al/repo-descargado/.git/
     ```
