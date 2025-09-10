# Explotando Documentación Swagger y OpenAPI

## Introducción

La documentación de una API es esencial para que los desarrolladores la consuman y trabajen con ella. Sin embargo, cuando archivos de Swagger/OpenAPI quedan expuestos en producción, se convierten en manuales de instrucciones para atacantes. Encontrar un fichero de definición transforma un test de caja negra en uno de caja gris o blanca, pues proporciona conocimiento preciso de rutas, parámetros y lógica de negocio.

## Formatos de Documentación

El estándar de facto para documentar APIs REST es **Swagger/OpenAPI**, que define la API de forma estructurada.

- Formatos de fichero:
  - swagger.json
  - openapi.json
  - openapi.yaml o .yml
- Interfaces que renderizan estas definiciones:
  - **Swagger UI:** interfaz interactiva web.
  - **ReDoc:** alternativa popular para documentación visual.

## Técnicas para Encontrar Documentación Expuesta

1. Fuerza bruta de directorios y archivos
   Utiliza wordlists con `ffuf`, `dirsearch` o `gobuster`.
   Rutas comunes a probar:

```text
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

Ficheros de definición frecuentes:

```text
/swagger.json
/openapi.json
/openapi.yaml
/api.json
/api.yaml
/api-docs.json
```

Probar también con prefijos de versión: `/v1/swagger-ui.html`, `/api/v2/openapi.json`, etc.
2. Google Dorking

```text
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com ext:json inurl:swagger
```

3. Análisis de JavaScript
   Revisa los scripts de la aplicación para rutas que apunten a documentación de API (p. ej., llamadas a `/openapi.json`).

## Aprovechamiento de la Documentación

### 1. Mapeo de Entornos (dev vs. prod)

- **Hallazgo:** Documentación de `dev` o `staging` expuesta.
- **Valor:** Suele incluir endpoints de debug y notas que no aparecen en prod.
- **Ataque:**

1. Anotar endpoints y parámetros de `dev`.
2. Probarlos en `prod` suponiendo estructuras similares.
3. Buscar diferencias en autenticación y validaciones.

### 2. Descubrimiento de Endpoints Ocultos

- **Hallazgo:** Endpoints internos, beta u obsoletos.
- **Valor:** Controles de acceso más débiles y vulnerabilidades sin parchear.
- **Ataque:** Priorizar pruebas en esos endpoints (`/api/v1/admin/...`, `/api/v1/beta/...`).

### 3. Análisis de Parámetros y Respuestas

- **Hallazgo:** Detalle de parámetros (tipos, opcionalidad) y ejemplos de valores.
- **Ataque:**
  - **SQL Injection:** Ejemplo de filtro `status='active'`.
  - **Input tampering:** Enviar string en lugar de integer o formatos inesperados.
  - **Lógica rota:** Omitir parámetros opcionales para provocar errores y filtrar datos.

### 4. Bypass de Autenticación

- **Hallazgo:** Documentación especifica `security: [bearerAuth: []]`.
- **Ataque:**

1. Acceder sin token.
2. Usar token inválido o expirado.
3. Cambiar método HTTP (POST→GET).
4. Probar inconsistencias entre entornos.

### 5. Ruptura de la Lógica de Negocio

- **Hallazgo:** Flujo descrito paso a paso en la documentación.
- **Ataque:**
  - Saltarse la verificación de email antes de establecer contraseña.
  - Llamar al paso de añadir al carrito con valores negativos para afectar el total.
  - Forzar race conditions entre pasos secuenciales.

## Ejemplo de Caso Real

```yaml
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

- **`/api/v1/users/import`:**
  - Subida de archivos: CSV Injection, Path Traversal, carga de webshell.
  - CSV malformado: DoS o filtrado de rutas internas.
- **`/api/v1/users/{id}/permissions`:**
  - IDOR: cambiar `{id}` a un administrador y asignarse roles privilegiados.
  - Escalada de privilegios: añadir roles no permitidos.
- **Autenticación (`apiKey`):**
  - ¿Es compartida o predecible?
  - ¿Funciona sin enviar `apiKey`?

---

La exposición de Swagger/OpenAPI en producción acelera enormemente el reconocimiento, revela vectores directos de ataque y reduce el tiempo necesario para encontrar vulnerabilidades críticas. Siempre que se despliegue documentación, restringir el acceso a entornos autenticados o eliminar estos ficheros de producción.
