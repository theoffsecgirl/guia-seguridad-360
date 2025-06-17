# Fase de Reconocimiento

### Escuchar Antes de Hablar

Hemos llegado a la fase inicial y, posiblemente, la más crucial en cualquier test de intrusión o programa de bug bounty: el **Reconocimiento** (o "Recon"). El objetivo es simple: recopilar la mayor cantidad de información posible sobre un objetivo para descubrir su superficie de ataque potencial. Un buen reconocimiento es la base de un hackeo exitoso.

En esta fase, somos detectives digitales. Dividiremos nuestras técnicas en dos grandes categorías:

* **Reconocimiento Pasivo:** Recopilar información usando únicamente fuentes públicas, sin interactuar directamente con los sistemas del objetivo.
* **Reconocimiento Activo:** Interactuar directamente con la infraestructura del objetivo para obtener información más precisa, por ejemplo, escaneando puertos o servicios.

### En este capítulo, construiremos nuestro mapa del tesoro:

* **[Conceptos Clave y Anatomía de Dominio](./02a-conceptos-clave.md):** Entenderemos la estructura de un dominio y por qué los subdominios son un objetivo tan valioso para un atacante.
* **[Reconocimiento Pasivo (OSINT)](./02b-reconocimiento-pasivo.md):** Aprenderemos a usar fuentes de información abiertas (OSINT) como repositorios de código y archivos históricos de internet para encontrar activos sin ser detectados.
  * **[Técnica Profunda: Google Dorking](./02b-1-google-dorking.md):** Dominaremos los operadores de búsqueda avanzada para encontrar archivos y vulnerabilidades que Google ha indexado por error.
  * **[Técnica Profunda: Certificate Transparency](./02b-2-certificate-transparency.md):** Usaremos los registros públicos de certificados SSL/TLS para descubrir subdominios ocultos a través de herramientas como `crt.sh`.
* **[Reconocimiento Activo](./02c-reconocimiento-activo.md):** Pasaremos a la acción, interactuando con los sistemas del objetivo para validar subdominios, escanear puertos e identificar las tecnologías que utilizan.
* **[Descubrimiento de Contenido Web](./02d-descubrimiento-de-contenido-web.md):** Nos centraremos en encontrar directorios y endpoints que no están enlazados públicamente en las aplicaciones web, usando técnicas como el fuzzing.
  * **[Técnica Profunda: Ficheros Sensibles Expuestos](./02d-1-ficheros-sensibles.md):** La caza del tesoro definitiva: buscaremos archivos como `.git`, `.env` y `Dockerfile` que pueden contener secretos, credenciales y la lógica interna de la aplicación.
* **[Resumen de Herramientas](./02e-resumen-de-herramientas.md):** Una chuleta rápida con todo el arsenal mencionado en el capítulo, categorizado por su función.

¡Ponte tu sombrero de detective, empezamos a investigar!
