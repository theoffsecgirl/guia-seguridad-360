### Introducción: Más Allá de los Puertos 80 y 443

Cuando pensamos en la web, los puertos **80 (HTTP)** y **443 (HTTPS)** son los reyes. Son los estándares por los que se sirve la gran mayoría del tráfico web. Históricamente, el puerto 80 era la norma, con tráfico en texto plano, pero la necesidad de seguridad (cifrado de datos, privacidad) hizo que HTTPS en el puerto 443 se convirtiera en el estándar de facto.

Sin embargo, en el reconocimiento y pentesting, limitar nuestra búsqueda a estos dos puertos es un error de novato. Las aplicaciones modernas son sistemas complejos, a menudo compuestos por múltiples servicios (microservicios) que se ejecutan en una variedad de puertos no estándar, especialmente en entornos de desarrollo, pre-producción (staging) o incluso en producción debido a errores de configuración.

Cada puerto abierto es una nueva puerta que tocar, y muchas de ellas no tienen el mismo nivel de seguridad que la puerta principal (puerto 443).

### Puertos Comunes, Sus Usos y Nuestra Perspectiva Ofensiva

Aquí tienes una tabla con puertos comunes, su uso legítimo y, lo más importante, **qué debemos buscar nosotros como profesionales de la seguridad ofensiva**.


| Puerto    | Servicio Común / Tecnología                                | Qué Buscar (Perspectiva Ofensiva)                                                                                                                                                                                                                                                               |
| :-------- | :----------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **80**    | **HTTP**                                                     | Tráfico en texto plano (posibilidad de ataques MitM en redes no seguras), aplicaciones legacy (antiguas) con vulnerabilidades conocidas, redirecciones mal configuradas a HTTPS, hosts virtuales mal configurados.                                                                              |
| **443**   | **HTTPS**                                                    | El objetivo principal. Buscar todo el espectro de vulnerabilidades web (XSS, SQLi, IDOR, etc.). Además, buscar misconfigurations de SSL/TLS (certificados débiles, protocolos antiguos como SSLv3/TLSv1.0), cabeceras de seguridad ausentes o mal configuradas.                                |
| **3000**  | **Servidores de desarrollo Node.js** (React, Express, etc.)  | **¡Objetivo de alto valor!** Entornos de desarrollo expuestos, posibles endpoints de debug, source maps que revelan código fuente, Hot Module Reloading (HMR) que puede filtrar información, CORS mal configurados (`*`), posible ejecución con privilegios elevados dentro de contenedores. |
| **4200**  | **Servidor de desarrollo Angular**                           | Similar al puerto 3000. Identifica el uso de Angular. Buscar endpoints de API a los que se conecta la aplicación, lógica de negocio en el código fuente del cliente, posibles fugas de información.                                                                                          |
| **5000**  | **Servidores de desarrollo Python** (Flask, Django) / Docker | **¡Objetivo de alto valor!** Flask en modo debug (Werkzeug debugger, que puede llevar a RCE), APIs expuestas sin autenticación, servicios internos de contenedores Docker expuestos por error a Internet.                                                                                      |
| **8000**  | Alternativo HTTP / Django dev server / Python http.server    | A menudo se usa para servicios rápidos o temporales. Puede albergar aplicaciones sencillas con menos seguridad, APIs internas, o un simple servidor de archivos que exponga el contenido de un directorio.                                                                                      |
| **8080**  | **HTTP Alternativo / Proxy / Apache Tomcat**                 | Paneles de administración con credenciales por defecto (`admin:admin`, `tomcat:tomcat`), aplicaciones Java vulnerables a deserialización, versiones de Tomcat antiguas con exploits públicos, posible acceso a AJP (puerto 8009, vulnerabilidad Ghostcat).                                    |
| **8443**  | **HTTPS Alternativo**                                        | Similar a 8080 pero con SSL/TLS. Común en aplicaciones empresariales (e.g., VMware, software de Atlassian). Buscar paneles de login, software desactualizado con CVEs conocidas, credenciales por defecto para estas aplicaciones específicas.                                                 |
| **8888**  | **Jupyter Notebooks / HTTP Alternativo**                     | **¡Muy crítico!** Si un Jupyter Notebook está expuesto sin contraseña, a menudo permite crear una terminal o ejecutar código Python directamente en el servidor, lo que equivale a RCE.                                                                                                     |
| **9000**  | Herramientas de desarrollo /**SonarQube** / Portainer        | Herramientas de CI/CD o calidad de código. Buscar acceso anónimo, credenciales por defecto, exposición de código fuente y vulnerabilidades detectadas por la propia herramienta. Un SonarQube abierto puede ser una mina de oro de vulnerabilidades.                                         |
| **5432**  | **PostgreSQL** (Base de Datos)                               | **No debería estar expuesto a Internet.** Si lo está, es un hallazgo en sí mismo. Intentar login con credenciales por defecto (`postgres:postgres`, `postgres:password`), enumerar bases de datos, comprobar si permite conexiones desde cualquier host.                                      |
| **27017** | **MongoDB** (Base de Datos)                                  | **No debería estar expuesto.** Comprobar acceso sin autenticación (por defecto en versiones antiguas), enumerar bases de datos y colecciones, posible fuga masiva de datos.                                                                                                                    |
| **6379**  | **Redis** (Almacén de datos en memoria)                     | **No debería estar expuesto.** Comprobar acceso sin autenticación. Si es accesible, se puede leer/escribir en la caché, lo que puede llevar a RCE o manipulación de datos de la aplicación. Usar `redis-cli` para conectar.                                                                 |

### ¿Por Qué Nos Importan Tantos Puertos? (La Perspectiva del Atacante)

El texto original lo explica bien desde el punto de vista del desarrollo: las aplicaciones modernas son modulares (microservicios). Para nosotros, esto significa que **la superficie de ataque se multiplica**. Cada servicio en su propio puerto es una nueva oportunidad para encontrar una vulnerabilidad.

En un entorno de producción ideal, un **proxy inverso (reverse proxy)** como Nginx o un balanceador de carga debería ocultar todos estos puertos internos y canalizar todo el tráfico público a través del puerto 443. Sin embargo, en el mundo real, los errores de configuración son comunes:

- Un desarrollador puede exponer un puerto de debug a Internet por error.
- Una regla de firewall puede ser demasiado permisiva.
- Un entorno de staging, que se supone que es interno, puede acabar siendo accesible públicamente.

**Encontrar un puerto de desarrollo (3000, 5000, etc.) en un dominio de producción es, a menudo, un hallazgo crítico por sí mismo.**

### Metodología de Descubrimiento

La forma de encontrar estos puertos abiertos es mediante un **escaneo de puertos** en la fase de reconocimiento activo.

- **Herramientas Clave:** `nmap`, `masscan`, `naabu` (de ProjectDiscovery).
- **Estrategia:**
  1. Obtener las direcciones IP de tus objetivos (subdominios resueltos).
  2. Lanzar un escaneo rápido con `masscan` o `naabu` sobre los puertos más comunes (top 1000, top 10000).
  3. Para las IPs que muestren puertos interesantes, lanzar un escaneo más profundo y detallado con `nmap` para identificar las versiones de los servicios y ejecutar scripts de enumeración.

**Ejemplo de Comando `nmap`:**

```bash
# Escanea los 1000 puertos más comunes, detecta versiones y ejecuta scripts por defecto en un host
nmap -sV -sC -T4 -v mi-objetivo.com

# Escanea un puerto específico, como el 3000
nmap -p 3000 -sV -sC mi-objetivo.com
```

Recuerda siempre **respetar el scope del programa de bug bounty**. El escaneo de puertos agresivo puede estar prohibido.
