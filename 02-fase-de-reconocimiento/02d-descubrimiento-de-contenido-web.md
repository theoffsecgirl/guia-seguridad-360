# Descubrimiento de Contenido Web

Una vez que hemos identificado los servidores web activos en la fase de reconocimiento, el siguiente paso es descubrir el contenido y la funcionalidad que albergan. A menudo, las partes más interesantes de una aplicación no están enlazadas desde la página principal.

### Objetivos del Descubrimiento de Contenido

El objetivo de esta fase es encontrar:

* Directorios y archivos sensibles (`/admin`, `/backup`).
* Endpoints de API ocultos o no enlazados directamente.
* Documentación técnica (Swagger, OpenAPI, Postman collections).
* Paneles de administración.
* Archivos de diagnóstico, debug o logs expuestos.
* **Y, con suerte, ficheros que lleven a un compromiso directo, como `.git/config` o `.env`**.

---

## Métodos Principales

Existen varias técnicas clave para descubrir este contenido oculto.

### 1. Crawling / Spidering

Este método consiste en explorar sistemáticamente un sitio web siguiendo todos los enlaces que encuentra, de la misma forma que lo hace un motor de búsqueda. Es una excelente manera de mapear rápidamente toda la funcionalidad visible de una aplicación.

* **Herramientas Comunes:** Burp Suite (función "Spider"), `gospider`, `hakrawler`, `katana`.

### 2. Fuerza Bruta de Directorios y Archivos (Fuzzing)

Esta es una de las técnicas más importantes. Consiste en utilizar diccionarios (listas de palabras) para intentar "adivinar" rutas y nombres de archivos o directorios que existen en el servidor pero que no están enlazados.

* **Wordlists (Diccionarios):** La calidad de tu lista de palabras es crucial. Se recomienda usar colecciones de alta calidad como **SecLists**.
* **Herramientas Comunes:** `dirsearch`, `ffuf`, `wfuzz`, `gobuster dir`.
* **Comando Ejemplo con `ffuf`:**
  ```bash
  ffuf -w /ruta/a/SecLists/Discovery/Web-Content/common.txt -u [https://target.com/FUZZ](https://target.com/FUZZ) -mc 200,204,301,302,307,401,403
  ```

### 3. Análisis de Archivos JavaScript

El código JavaScript que se ejecuta en el navegador del cliente es una mina de oro. A menudo contiene rutas a endpoints de API, lógica de la aplicación, y comentarios con información sensible.

* **Herramientas Comunes:** `LinkFinder`, `JSScanner` (Extensión de Burp), `SecretFinder`.

### 4. Visual Recon

Esta técnica consiste en tomar capturas de pantalla de un gran número de sitios web para identificar visualmente aquellos que parecen más interesantes (páginas de login, aplicaciones desactualizadas, errores, etc.).

* **Herramientas Comunes:** `aquatone`, `webscreenshot`, `gowitness`.

---

## Próximo Paso: Los Archivos Más Buscados

Hemos visto las técnicas para encontrar contenido, pero ¿qué tipo de archivos son los más valiosos?

> **➡️ Para una guía detallada sobre los tipos de archivos más valiosos que buscamos, consulta nuestra página dedicada: [Técnica Profunda: Ficheros Sensibles Expuestos](./02d-1-ficheros-sensibles.md)**
>
