# Patrones de Subdominios y Generación de Permutaciones

### Introducción

En la fase de reconocimiento, uno de los objetivos principales es **descubrir la mayor cantidad posible de activos digitales** de una organización. Comprender la estructura de los nombres de dominio y cómo se utilizan los subdominios es fundamental para esta tarea. Cada subdominio puede albergar una aplicación, un servicio o una API diferente, cada uno con sus potenciales vulnerabilidades.

### Anatomía de un Nombre de Dominio

Un nombre de dominio es la dirección legible por humanos que se utiliza para acceder a los sitios web y otros recursos en Internet. Veamos su estructura:

- **Ejemplo Básico:** `www.dominio.com`

  - **`dominio.com`**: Este es el **dominio raíz** (root domain) o **dominio ápex** (apex domain). Es el nombre principal que la organización registra.
  - **`.com`**: Esto es el **Dominio de Nivel Superior** o **TLD** (Top-Level Domain). Hay muchos tipos de TLDs:
    - **Genéricos (gTLDs):** `.com`, `.org`, `.net`, `.info`, etc.
    - **De Código de País (ccTLDs):** `.es` (España), `.uk` (Reino Unido), `.de` (Alemania).
    - **Nuevos gTLDs:** En los últimos años han surgido muchos TLDs nuevos, a veces específicos de marcas o industrias, como `.google`, `.uber`, `.online`, `.shop`, `.dev`.
  - **`www`**: Esto es un **subdominio** común, que tradicionalmente se usaba para el servidor web principal del dominio.

### Subdominios: Expandiendo el Dominio

Un **subdominio** es una subdivisión de un dominio principal. Las organizaciones los utilizan para organizar y separar diferentes secciones, servicios o aplicaciones de su presencia online.

- **Ejemplos:**
  - `blog.dominio.com` (para el blog de la empresa)
  - `tienda.dominio.com` (para la tienda online)
  - `api.dominio.com` (para una Interfaz de Programación de Aplicaciones)
  - `mail.dominio.com` (para el servidor de correo)

Cada subdominio es, a efectos prácticos, un host distinto que puede tener su propia dirección IP y ejecutar aplicaciones completamente diferentes a las del dominio raíz u otros subdominios.

### Permutaciones y Entornos en Subdominios

Durante el reconocimiento, es muy común encontrar patrones en los nombres de los subdominios. Estos patrones a menudo revelan diferentes **entornos de desarrollo** (development, testing, staging, production) o **permutaciones** de nombres de servicios. Identificar estos patrones puede ayudarte a descubrir subdominios que no son públicos o que no están enlazados.

- **Indicadores de Entorno:**

  - `dev.api.dominio.com` (API de desarrollo)
  - `test.tienda.dominio.com` (Tienda en entorno de pruebas)
  - `uat.portal.dominio.com` (User Acceptance Testing para el portal)
  - `staging.app.dominio.com` (Entorno de pre-producción)
  - A veces se usan nombres de proyecto o equipo: `proyectoX.dev.dominio.com`
- **Permutaciones Comunes:** Los atacantes y pentesters a menudo generan listas de posibles subdominios combinando palabras clave comunes (como `api`, `app`, `dev`, `test`, `staging`, `uat`, `vpn`, `mail`, `ftp`, `admin`, nombres de servicios, etc.) con el dominio raíz y otros subdominios conocidos.

  - Si encuentras `app.dominio.com` y `api.dominio.com`, podrías probar permutaciones como:
    - `app-dev.dominio.com`
    - `dev-app.dominio.com`
    - `api-test.dominio.com`
    - `test-api.dominio.com`
  - Subdominios anidados que indican estructura o entorno:
    - `app-api.dev.dominio.com` (La API de la aplicación `app` en el entorno `dev`)
    - `site.com.dominio.com` (A veces se usa para indicar un cliente específico o una instancia, donde `site.com` es el nombre del cliente o proyecto, funcionando como un sub-subdominio de `dominio.com`)
    - `site-dev.corp.dominio.com` (La versión de desarrollo del sitio `site`, dentro de la infraestructura corporativa `corp` de `dominio.com`)

La clave es observar los patrones existentes en los subdominios que ya has descubierto y usar esa lógica para generar nuevas permutaciones y buscar más activos. Herramientas como `dnsgen` o `gotator` pueden ayudar a automatizar la generación de estas permutaciones basadas en subdominios ya conocidos.
