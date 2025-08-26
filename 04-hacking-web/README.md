# Hacking Web

¡Bienvenido/a al campo de batalla principal! En los capítulos anteriores aprendimos a encontrar nuestros objetivos; en este capítulo, aprenderemos a encontrar sus debilidades y a explotarlas.

Una vulnerabilidad web es un fallo o una debilidad en el código o la configuración de una aplicación web que puede ser utilizado por un atacante para realizar acciones no deseadas, como robar datos, tomar el control de la cuenta de otro usuario o incluso del servidor completo.

### Nuestra Metodología

Para abordar este vasto mundo, hemos organizado las vulnerabilidades en tres grandes familias, siguiendo una metodología profesional:

* **Control de Acceso:** Fallos en el sistema que decide "quién puede hacer qué". Aquí buscaremos formas de acceder a datos o funciones que no nos corresponden.
* **Ataques al Servidor:** Vulnerabilidades que nos permiten atacar directamente la lógica del backend, la base de datos o el sistema de ficheros del servidor.
* **Ataques al Cliente:** Fallos que nos permiten usar la aplicación web como un arma para atacar a otros usuarios, normalmente ejecutando código en sus navegadores.

### Mapa de Vulnerabilidades

* **[Control de Acceso](04a-control-de-acceso\README.md):** Exploraremos las formas de saltarnos las restricciones de permisos.
  * **[IDOR (Insecure Direct Object References)](04-hacking-web\04a-control-de-acceso\idor.md):** Aprende a acceder a recursos que no te pertenecen cambiando un simple número en la URL.
  * **[CORS (Cross-Origin Resource Sharing)](04-hacking-web\04a-control-de-acceso\cors.md):** Descubre cómo las malas configuraciones de CORS pueden permitir el robo de datos entre dominios.
* **[Ataques al Servidor](04-hacking-web\04b-ataques-al-servidor\README.md):** Nos centraremos en las vulnerabilidades que comprometen la infraestructura del backend.
  * **[LFD y Path Traversal](04-hacking-web\04b-ataques-al-servidor\lfd-y-path-traversal.md):** Veremos cómo leer archivos locales del servidor a los que no deberíamos tener acceso.
  * **[Inyección SQL (SQLi)](04-hacking-web\04b-ataques-al-servidor\sqli.md):** La vulnerabilidad clásica para atacar y extraer información de bases de datos.
* **[Ataques al Cliente](04-hacking-web\04c-ataques-al-cliente\README.md):** El objetivo aquí son los navegadores de otros usuarios de la aplicación.
  * **[Cross-Site Scripting (XSS)](04-hacking-web\04c-ataques-al-cliente\xss.md):** Aprenderemos a inyectar JavaScript en el navegador de las víctimas.
  * **[Cross-Site Request Forgery (CSRF)](04-hacking-web\04c-ataques-al-cliente\csrf.md):** Descubre cómo hacer que un usuario autenticado realice acciones en su nombre sin que se dé cuenta.
  * **[Explotación de PostMessage](04-hacking-web\04c-ataques-al-cliente\postmessage.md):** Una técnica más avanzada para atacar la comunicación entre ventanas del navegador.
* **[Redirecciones Inseguras](04-hacking-web\04d-redirecciones-inseguras.md):** Analizaremos cómo se puede abusar de las redirecciones para dirigir a los usuarios a sitios maliciosos.
