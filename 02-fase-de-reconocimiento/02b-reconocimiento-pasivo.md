# Reconocimiento Pasivo (OSINT)

### Recopilando Información sin Ser Visto

El **Reconocimiento Pasivo** consiste en recolectar información sobre nuestro objetivo utilizando únicamente fuentes de información públicas. La característica principal es que **nunca interactuamos directamente con la infraestructura del objetivo**, por lo que nuestras actividades son, en teoría, indetectables. Somos como un detective que investiga leyendo periódicos, registros públicos y hablando con testigos, en lugar de entrar en la casa del sospechoso.

Este proceso también se conoce como **OSINT (Open Source Intelligence)**.

El objetivo es construir un mapa detallado de la huella digital del objetivo para descubrir la mayor cantidad posible de activos.

---

## Fuentes de Información Pasiva

A continuación, exploraremos las fuentes de información más valiosas para un pentester en la fase de reconocimiento pasivo.

### 1. Transparencia de Certificados (Certificate Transparency - CT)

Los registros públicos de certificados SSL/TLS son una mina de oro para descubrir subdominios. Como cada certificado emitido para un dominio se registra públicamente, podemos consultar estos logs para encontrar subdominios de desarrollo, preproducción u olvidados que de otra manera serían difíciles de encontrar.

* **Herramientas/Servicios Clave:** `crt.sh`, `censys.io`.

> **➡️ Para una guía detallada sobre esta técnica, consulta nuestra página dedicada: {% content-ref page="02-fase-de-reconocimiento/02b-2-certificate-transparency.md" %}**

### 2. OSINT y Motores de Búsqueda (Google Dorking)

Utilizar la información públicamente disponible en internet es la esencia del OSINT. Los motores de búsqueda como Google, Bing o DuckDuckGo han indexado una cantidad masiva de información que podemos filtrar con búsquedas avanzadas para encontrar subdominios, archivos sensibles, errores de configuración y mucho más.

> **➡️ Para aprender a dominar esta técnica, ve a nuestra guía completa: {% content-ref page="02-fase-de-reconocimiento/02b-1-google-dorking.md" %}**

### 3. Descubrimiento de ASN y Rangos de IP

Identificar los Sistemas Autónomos (ASN) y los rangos de direcciones IP que pertenecen a una organización nos ayuda a descubrir activos que podrían no estar vinculados directamente por DNS a los dominios principales. Esto amplía enormemente el alcance de nuestra auditoría.

* **Herramientas/Servicios Clave:**
  * `whois` (para obtener información de registro de dominios e IPs).
  * Sitios como `bgp.he.net` para explorar la información de BGP.
  * Registros Regionales de Internet como ARIN, RIPE, APNIC, etc.
  * `amass intel` es una herramienta excelente para automatizar esta investigación.

### 4. Repositorios Públicos de Código

A menudo, el código fuente o los archivos de configuración de una empresa se filtran o se publican por error en repositorios públicos como GitHub o GitLab. Estos repositorios pueden contener información crítica como subdominios, rutas internas y, en el peor de los casos, claves API o credenciales.

* **Técnicas y Herramientas:**
  * Búsquedas avanzadas en GitHub (dorks de GitHub) como `org:nombre_empresa api_key`.
  * Herramientas automatizadas para buscar secretos en código, como `truffleHog` o `gitleaks`.

### 5. Archivos Históricos de Internet

Servicios como la Wayback Machine archivan versiones antiguas de sitios web. Estos archivos pueden revelar URLs, endpoints de API, parámetros y archivos JavaScript que ya no están activos pero que pueden darnos pistas sobre tecnologías usadas o funcionalidades ocultas.

* **Herramientas para Automatizar la Búsqueda:** `gau` (getallurls), `waybackurls`, `katana`.
