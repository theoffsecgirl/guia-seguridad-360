# Conceptos Clave y Anatomía de Dominio

El **reconocimiento (o recon)** es la fase inicial y, posiblemente, la más crucial en cualquier test de intrusión, auditoría de seguridad o programa de bug bounty. Su objetivo principal es identificar y recopilar la mayor cantidad posible de información sobre los **activos (assets)** de una organización. Cuantos más activos se descubran (dominios, subdominios, direcciones IP, aplicaciones, APIs, etc.), mayor será la **superficie de ataque potencial**, lo que incrementa significativamente las probabilidades de encontrar vulnerabilidades.

Este proceso es especialmente vital en el bug bounty, donde un mayor alcance y un conocimiento profundo del objetivo suelen traducirse en más oportunidades de recompensa y en hallazgos de mayor impacto. Un buen recon es un trabajo de paciencia, metodología y combinación de técnicas y herramientas.

## Reconocimiento Pasivo vs. Activo: Los Dos Sabores del Espionaje

Antes de sumergirnos en la técnica, es fundamental entender las dos filosofías principales del reconocimiento:

* **Reconocimiento Pasivo:** Consiste en recolectar información **sin interactuar directamente** con los sistemas del objetivo. Se utilizan fuentes públicas como motores de búsqueda, registros de certificados o redes sociales. Es sigiloso y no deja rastro.
* **Reconocimiento Activo:** Implica **interactuar directamente** con la infraestructura del objetivo. Esto incluye actividades como el escaneo de puertos o la interacción con sus aplicaciones web. Es más "ruidoso" pero a menudo proporciona información más precisa y detallada.

En la práctica, un buen reconocimiento combina ambas metodologías de forma estratégica.

---

## Anatomía de un Activo Digital: El Dominio

En la fase de reconocimiento, uno de los objetivos principales es **descubrir la mayor cantidad posible de activos digitales** de una organización. Comprender la estructura de los nombres de dominio y cómo se utilizan los subdominios es fundamental para esta tarea.

### Estructura de un Nombre de Dominio

Un nombre de dominio es la dirección legible por humanos que se utiliza para acceder a los sitios web. Analicemos su estructura con un ejemplo como `www.dominio.com`:

* **`.com`**: Es el **Dominio de Nivel Superior** o **TLD** (Top-Level Domain). Existen muchos tipos, como los genéricos (gTLDs: `.com`, `.org`, `.dev`) y los de código de país (ccTLDs: `.es`, `.mx`, `.ar`).
* **`dominio.com`**: Este es el **dominio raíz** (root domain) o **dominio ápex** (apex domain). Es el nombre principal que la organización registra.
* **`www`**: Esto es un **subdominio**, una subdivisión del dominio principal.

### El Poder de los Subdominios

Cada subdominio es, a efectos prácticos, un host distinto que puede tener su propia dirección IP y ejecutar aplicaciones completamente diferentes a las del dominio raíz. Las organizaciones los usan para separar servicios:

* `blog.dominio.com` (para el blog)
* `tienda.dominio.com` (para la tienda online)
* `api.dominio.com` (para una API)
* `mail.dominio.com` (para el servidor de correo)

Estos subdominios son un tesoro para nosotros porque a menudo albergan aplicaciones antiguas, entornos de desarrollo o paneles de administración olvidados que suelen ser menos seguros que la aplicación principal.

### Patrones, Permutaciones y Entornos

Durante el reconocimiento, es muy común encontrar patrones en los nombres de los subdominios que revelan diferentes **entornos de desarrollo** o **permutaciones** de nombres de servicios.

* **Indicadores de Entorno Comunes:**
  * `dev.api.dominio.com` (Desarrollo)
  * `test.tienda.dominio.com` (Pruebas)
  * `uat.portal.dominio.com` (Pruebas de Aceptación de Usuario)
  * `staging.app.dominio.com` (Entorno de pre-producción)
* **Lógica de Permutaciones:** Si encuentras `app.dominio.com` y `api.dominio.com`, un buen instinto es probar permutaciones como `dev-app.dominio.com`, `app-dev.dominio.com`, `api-test.dominio.com`, etc. Observar los patrones existentes es clave para descubrir nuevos activos.

---

## Investigación Práctica: Comandos Fundamentales

Entender la teoría es una cosa, pero necesitamos herramientas para investigar estos activos. Aquí tienes los comandos más básicos para empezar a tirar del hilo.

### `whois`: ¿Quién es el dueño de este dominio?

El comando `whois` consulta bases de datos públicas para obtener información de registro sobre un dominio o una dirección IP. Puede revelar el nombre del registrante, fechas de creación y expiración, y los servidores de nombres (NS) que gestionan el dominio.

```bash
# Uso básico del comando whois
whois ejemplo.com
```

### `dig` y `nslookup`: ¿Qué IP hay detrás de este nombre?

Estas herramientas realizan consultas DNS para traducir un nombre de dominio a su dirección IP correspondiente. `dig` (Domain Information Groper) es más moderno y potente, pero `nslookup` también es muy común.


# Usando dig para obtener la dirección IP (registro A) de un dominio
dig ejemplo.com

# Usando nslookup para el mismo propósito
nslookup ejemplo.com
El resultado de estos comandos nos da la dirección IP del servidor al que nos conectaremos, nuestro primer objetivo técnico real.
