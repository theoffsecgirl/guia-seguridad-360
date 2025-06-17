# Introducción

La documentación de una API es esencial para que los desarrolladores puedan consumirla y trabajar con ella. Sin embargo, cuando esta documentación, especialmente en formatos detallados como **Swagger/OpenAPI**, queda expuesta públicamente en entornos de producción, se convierte en un manual de instrucciones para un atacante.

Encontrar un fichero de documentación de API expuesto transforma un test de caja negra (donde no sabes nada) en uno de caja gris o blanca, dándote un conocimiento profundo de la superficie de ataque, los endpoints, los parámetros esperados y la lógica de negocio.

### Formatos Comunes de Documentación de API

El estándar de facto para documentar APIs REST es **Swagger / OpenAPI**. Estos ficheros describen de forma estructurada toda la API.

- **Formatos de Fichero Comunes:**
  - `swagger.json`
  - `openapi.json`
  - `openapi.yaml` (o `.yml`)
- **Interfaces de Usuario Comunes (que renderizan estos ficheros):**
  - **Swagger UI:** La más popular. Crea una interfaz web interactiva a partir de un fichero de definición.
  - **ReDoc:** Otra alternativa popular para generar documentación visual.

### Cómo Encontrar la Documentación Expuesta

Antes de poder analizarla, hay que encontrarla. Estas son las técnicas principales:

1. **Fuerza Bruta de Directorios y Archivos:** Es el método más efectivo. Usa una buena wordlist con herramientas como `ffuf`, `dirsearch`, o `gobuster`.

   - **Rutas Comunes a Buscar:**

     ```
     /swagger/index.html
     /swagger-ui/
     /swagger-ui.html
     /api-docs/
     /api/docs/
     /docs/
     /api/swagger/
     /api/swagger-ui/
     /redoc/
     /redoc.html
     ```
   - **Archivos de Definición Comunes:**

     ```
     /swagger.json
     /openapi.json
     /openapi.yaml
     /api.json
     /api.yaml
     /api-docs.json
     ```
   - **Pro Tip (¡Muy Importante!):** No te olvides de probar con prefijos de versiones (`/v1/`, `/v2/`, `/v3/`, `/api/v1/`, etc.). `https://target.com/api/v1/swagger-ui.html`
2. **Google Dorking:** A veces Google indexa lo que no debe.

   - `site:target.com inurl:swagger`
   - `site:target.com inurl:api-docs`
   - `site:target.com ext:json inurl:swagger`
3. **Análisis de Archivos JavaScript:** Revisa los ficheros JS de la aplicación en busca de rutas que apunten a la documentación de la API.

### Qué Joyas Encontramos y Cómo las Explotamos

Una vez que tienes el fichero de documentación, empieza la verdadera caza.

#### 1. Mapeo de Entornos (Desarrollo vs. Producción)

- **El Hallazgo:** Encuentras documentación de un entorno de desarrollo (`dev`) o pre-producción (`staging`) expuesta, pero estás atacando el entorno de producción (`prod`).
- **Por qué es Oro Puro:** La documentación de `dev` suele ser mucho más completa y descriptiva. Puede incluir endpoints de debug, notas de desarrolladores y funcionalidades que están ocultas o limitadas en producción.
- **Vector de Ataque:**
  1. Documenta todos los endpoints y parámetros de la documentación de `dev`.
  2. Asume que la estructura de la API en producción es similar (e.g., si en `dev` es `/api/v1/`, en `prod` probablemente también lo sea).
  3. Prueba cada endpoint "secreto" de `dev` directamente en el entorno de producción. Busca diferencias en la autenticación, manejo de errores o validación de parámetros.

#### 2. Descubrimiento de Endpoints Ocultos, Internos o "Secretos"

- **El Hallazgo:** La documentación revela endpoints que no están pensados para el público.
  - **Endpoints Beta:** Funcionalidades nuevas, a menudo con menos pruebas de seguridad.
  - **Interfaces Administrativas Internas:** e.g., `/api/v1/admin/users`.
  - **Endpoints Obsoletos (Deprecated):** Funcionalidades antiguas que se mantienen por compatibilidad pero que ya no reciben mantenimiento de seguridad.
- **Vector de Ataque:** Estos endpoints son objetivos prioritarios. Suelen tener controles de acceso más débiles, más bugs lógicos o vulnerabilidades conocidas que no han sido parcheadas porque se consideran "fuera de uso".

#### 3. Análisis de Parámetros y Respuestas (Buscar el Punto Débil)

- **El Hallazgo:** La documentación te da un mapa detallado de cada endpoint.
  - **Parámetros:** Nombres, si son opcionales o requeridos, tipos de datos esperados (`string`, `integer`, `boolean`), y a veces, **ejemplos de valores válidos**.
  - **Respuestas:** La estructura de los datos que devuelve el servidor, incluyendo los modelos de datos y los códigos de error.
- **Vector de Ataque:**
  - **Ejemplos de Valores:** Si un parámetro `filter` tiene como ejemplo `"status='active'"` (como en tu texto), ¡te está gritando que ahí puede haber una **SQL Injection**!
  - **Tipos de Datos:** ¿Qué pasa si envías un string donde se espera un integer? ¿O un array donde se espera un objeto? Puedes provocar errores 500 que filtren información.
  - **Parámetros Opcionales:** Prueba a enviar peticiones sin ellos o con valores inesperados para buscar fallos en la lógica.

#### 4. Oportunidades de Bypass de Autenticación

- **El Hallazgo:** La documentación especifica que un endpoint requiere autenticación (e.g., `security: [bearerAuth: []]`), pero la implementación real puede tener fallos.
- **Vector de Ataque (probando si la puerta está realmente cerrada con llave):**
  1. Intenta acceder al endpoint **sin ningún token de autenticación**. A veces se les olvida aplicar el `middleware` de seguridad.
  2. Prueba con un token expirado o inválido.
  3. Prueba a cambiar el método HTTP (e.g., de `POST` a `GET`). A veces la protección solo se aplica a un método.
  4. Busca inconsistencias entre entornos. Un endpoint que requiere auth en `prod` podría estar abierto en `staging`.

#### 5. Análisis de la Lógica de Negocio (Romper el Flujo)

- **El Hallazgo:** La documentación describe el flujo de trabajo esperado de la aplicación (e.g., "Paso 1: crear usuario. Paso 2: verificar email. Paso 3: establecer contraseña").
- **Vector de Ataque:** Conociendo el flujo correcto, puedes intentar romperlo.
  - ¿Puedo saltarme el paso 2 y establecer una contraseña sin verificar el email?
  - ¿Puedo llamar a un endpoint del "Paso 3" con datos del "Paso 1" para encontrar una **race condition**?
  - ¿Puedo abusar de un endpoint de "añadir al carrito" para poner precios negativos?

### Análisis de un Caso Real (Poniéndolo todo junto)

Imaginemos que encontramos este `openapi.yaml`:

```YAML
openapi: 3.0.0
info:
  title: API Interna de la Empresa
  version: 1.0.0
paths:
  /api/v1/users/import:
    post:
      description: "Importación masiva de usuarios desde CSV"
      parameters:
        - name: file
          in: formData
          type: file
      security:
        - apiKey: []
  /api/v1/users/{id}/permissions:
    put:
      description: "Actualizar permisos de usuario"
      parameters:
        - name: id
          in: path
          required: true
        - name: roles
          in: body
          schema:
            type: array
```

**Puntos a Atacar Inmediatamente:**

- **Endpoint `/api/v1/users/import`:**
  - **Subida de Archivos:** ¿Hay vulnerabilidades en la subida? (CSV Injection, Path Traversal, bypass de tipo de fichero para subir una webshell).
  - ¿Qué pasa si el CSV está malformado? ¿Provoca un DoS?
- **Endpoint `/api/v1/users/{id}/permissions`:**
  - **IDOR Clásico:** ¿Puedo, como usuario normal, cambiar el `{id}` al de un administrador y usar el parámetro `roles` para darme a mí mismo permisos de admin?
  - **Escalada de Privilegios:** ¿Qué roles se pueden asignar? ¿Puedo asignar un rol que no debería estar disponible para mi nivel de acceso?
- **Autenticación (`security: [apiKey: []]`):**
  - ¿Es esta `apiKey` la misma para todos los usuarios? ¿Es fácil de adivinar?
  - ¿Qué pasa si realizo la petición sin la `apiKey`? ¿Funciona?
