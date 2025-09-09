# ¿Qué es un IDOR (Insecure Direct Object Reference)?

Un **IDOR (Insecure Direct Object Reference)**, o Referencia Insegura Directa a Objetos, es una vulnerabilidad de control de acceso que ocurre cuando una aplicación utiliza un identificador suministrado por el usuario para acceder directamente a objetos (como registros en una base de datos, archivos, etc.) sin realizar una comprobación de autorización adecuada.

Esto permite a un atacante manipular estos identificadores para leer, modificar o eliminar datos de otros usuarios, o incluso acceder a funcionalidades a las que no debería tener permiso.

**La Causa Raíz:** La aplicación confía en que el usuario solo solicitará los objetos a los que tiene acceso, pero **falla al verificar en el lado del servidor si el usuario autenticado tiene realmente los permisos necesarios para acceder o manipular el objeto específico solicitado.**

### Ejemplo Básico de IDOR (Lectura no Autorizada)

Imagina una API para ver la dirección de un usuario:

**Petición Normal (Usuario Legítimo):** Un usuario con `ID=167865` solicita su propia dirección. `GET https://example.com/api/user/167865/address`

**Respuesta del Servidor:**

```json
{
  "id": 167865,
  "username": "usuario_legitimo",
  "address": "123 Calle Falsa, Ciudad Verdad"
}
```

**Manipulación por un Atacante:** El atacante, autenticado con su propia cuenta (o a veces incluso sin autenticar si el endpoint es público pero debería filtrar por sesión), cambia el ID en la URL al de otra víctima (e.g., el ID `1` que podría ser el del administrador o un usuario temprano). `GET https://example.com/api/user/1/address`

**Respuesta Vulnerable (Si hay IDOR):**

```json
{
  "id": 1,
  "username": "admin_o_victima",
  "address": "Calle Privilegiada 777, Adminlandia"
}
```

El servidor no verificó si el usuario que hizo la petición tenía permiso para ver la dirección del usuario con `ID=1`. Simplemente usó el ID proporcionado.

### Tipos de Referencias a Objetos y Dónde Buscar IDORs

Los IDORs pueden ocurrir con varios tipos de identificadores y en múltiples partes de una petición HTTP:

1. **En la URL (Path o Parámetros Query):**
   - `GET /user_profile?user_id=123`
   - `GET /orders/456/details`
   - `GET /download_file.php?filename=report_user_A.pdf`
2. **En el Cuerpo de la Petición (JSON, XML, Formularios):**
   - Especialmente común en peticiones `POST`, `PUT`, `DELETE`.
   - Ejemplo (JSON en cuerpo POST para actualizar ajustes):

```http
 POST /api/settings/update HTTP/1.1
 Host: vulnerable-site.com
 Content-Type: application/json
 
 {
  "user_id": 101,  // Atacante podría cambiar esto al ID de otra víctima
"preferences": {
  "theme": "dark",
 "notifications_enabled": true
 }
}
```

3. **En Cabeceras HTTP:**
   - Menos común, pero a veces se usan cabeceras personalizadas para pasar identificadores.
   - Ejemplo: `X-User-ID: 101`
4. **En Cookies:**
   - Si un valor de cookie se usa directamente para referenciar un objeto sin la debida autorización (e.g., `user_profile_id=101`).

**Tipos de Identificadores a Investigar:**

- **Numéricos Secuenciales:** `1, 2, 3, ...` (Los más fáciles de enumerar).
- **Numéricos No Secuenciales:** (e.g., IDs de base de datos auto-incrementales pero con saltos).
- **GUIDs/UUIDs:** `a1b2c3d4-e5f6-7890-1234-567890abcdef` (Más difíciles de adivinar, pero si un atacante obtiene uno de otra víctima, la lógica de autorización sigue siendo la clave).
- **Nombres de Usuario, Emails.**
- **Nombres de Archivo, Rutas de Archivo.**
- **Identificadores Ofuscados:**
  - **Base64:** Si ves un ID como `dXNlcj0xMDE=`, prueba a decodificarlo (`user=101`).
  - **Hashes (MD5, SHA1, etc.):** A veces los IDs son hashes de valores predecibles (e.g., MD5 de un ID numérico secuencial: `md5(1)`, `md5(2)`). Si el espacio de entrada es pequeño, se pueden precalcular. Herramientas como HashID pueden ayudar a identificar el tipo de hash.
  - **Cifrado Débil o Clave Conocida.**

### Impacto Detallado de los IDORs

El impacto varía según la acción que se pueda realizar y la sensibilidad de los datos:

- **Lectura No Autorizada de Datos (Confidencialidad):**
  - Acceso a información personal de otros usuarios (PII).
  - Acceso a mensajes privados, historiales de compra, informes financieros.
  - Descarga de archivos privados de otros.
- **Modificación No Autorizada de Datos (Integridad):**
  - Cambiar el email, contraseña o detalles del perfil de otro usuario (puede llevar a Account Takeover).
  - Modificar configuraciones, como desactivar 2FA para otra cuenta.
  - Alterar pedidos, precios, o saldos.
- **Eliminación No Autorizada de Datos (Disponibilidad):**
  - Borrar la cuenta de otro usuario.
  - Eliminar archivos, posts, o cualquier otro recurso.
- **Ejecución No Autorizada de Funciones (Privilege Escalation):**
  - Si un ID controla el acceso a una función administrativa (e.g., `?action=admin_delete_user&user_id_to_delete=X`).
  - Un usuario normal podría escalar privilegios para realizar acciones de administrador.

### Consejos y Metodología para Encontrar IDORs

1. **Mapear la Aplicación:**
   - Entiende cómo la aplicación maneja los datos: creación, lectura, actualización, eliminación (CRUD).
   - Identifica todos los endpoints que interactúan con objetos específicos de usuario o recursos.
2. **Identificar Referencias a Objetos:**
   - Busca en todas las partes de las peticiones HTTP (URLs, cuerpo, cabeceras, cookies) cualquier parámetro que parezca un identificador.
3. **Crear Dos Cuentas (o Más):**
   - Registra dos cuentas de usuario (Usuario A y Usuario B) con diferentes niveles de privilegio si es posible.
   - Realiza las mismas acciones con ambas cuentas y compara las peticiones. Observa cómo cambian los IDs.
4. **Testeo Horizontal (Mismo Nivel de Privilegio):**
   - Autentícate como Usuario A.
   - Realiza una acción sobre un recurso de Usuario A (e.g., ver perfil, `GET /profile?id=ID_A`).
   - Reemplaza `ID_A` con `ID_B` (el ID del Usuario B) e intenta acceder al recurso de Usuario B.
   - Si tienes éxito, es un IDOR horizontal.
5. **Testeo Vertical (Distinto Nivel de Privilegio):**
   - Autentícate como Usuario A (privilegios bajos).
   - Intenta acceder a recursos o funciones de Usuario C (privilegios altos, e.g., un administrador) manipulando los IDs.
   - Si tienes éxito, es un IDOR vertical y una escalada de privilegios.
6. **Probar Todos los Métodos HTTP:**
   - Si encuentras un ID en una petición `GET` (e.g., `GET /api/items/123`), prueba el mismo ID y endpoint con `POST`, `PUT`, `DELETE` para ver si puedes modificar o borrar el objeto.
   - A veces, un endpoint `POST /api/items` (para crear) podría tener un IDOR si permite especificar el ID del propietario en el cuerpo, o `PUT /api/items/123` podría permitir cambiar el propietario a otro usuario.
7. **Buscar IDs "Fugas" (Leaked IDs):**
   - **Código Fuente del Cliente (HTML, JS):** A veces los IDs de otros usuarios se exponen en comentarios, variables JS, atributos de elementos HTML (e.g., `<img src="/user_avatar?id=OTRO_USER_ID">`).
   - **Respuestas de API:** Una API podría devolver más IDs de los necesarios.
   - **URLs Predecibles:** Si los perfiles públicos usan URLs predecibles, puedes obtener IDs de otros usuarios.
8. **Manejar IDs Ofuscados:**
   - Decodificar Base64.
   - Intentar identificar algoritmos de hashing (HashID) y ver si puedes generar hashes para IDs conocidos/secuenciales.
   - A veces "ofuscado" solo significa no secuencial (como UUIDs). La lógica de explotación sigue siendo la misma: obtener un ID válido de otra víctima y probarlo.

### Herramientas y Técnicas de Explotación

1. **Herramientas de Desarrollador del Navegador (DevTools):**
   - Pestaña "Network" (o "Red"): Filtra por Fetch/XHR para ver las peticiones a APIs.
   - Inspecciona URLs, cabeceras y cuerpos de peticiones.
   - Puedes editar y reenviar peticiones (aunque un proxy es más potente para esto).
2. **Proxies de Interceptación (Burp Suite, OWASP ZAP, Caido):**
   - **Repeater (o equivalente):** La herramienta fundamental. Envía una petición legítima al Repeater, modifica el ID, y observa la respuesta. Repite para diferentes IDs.
   - **Intruder/Fuzzer (o equivalente):** Para automatizar la prueba de un rango de IDs.
     1. Identifica el endpoint vulnerable y la petición (e.g., `GET /api/user/{USER_ID}/data`).
     2. Envía la petición a Intruder.
     3. Marca el `USER_ID` como posición de payload (`§USER_ID§`).
     4. Configura el tipo de payload: "Numbers" (para IDs numéricos), especificando un rango (e.g., de 1 a 1000, con saltos de 1).
     5. Ejecuta el ataque.
     6. **Analiza las Respuestas:** Busca cambios en:
        - **Código de Estado HTTP:** `200 OK` para IDs válidos de otros, `401/403` para los tuyos si el ID es incorrecto, `404` si el ID no existe. ¡Pero un `200 OK` no siempre significa éxito si la aplicación devuelve una página de error genérica con estado 200!
        - **Longitud de la Respuesta (Content-Length):** Diferencias pueden indicar acceso a datos diferentes.
        - **Contenido de la Respuesta:** La forma más fiable. Busca datos que no deberían pertenecer a tu cuenta. Puedes usar "Grep - Extract" en Intruder para extraer partes específicas de la respuesta (e.g., nombre de usuario, email).
   - **Precaución con la Automatización:**
     - Usa pausas (throttling) entre peticiones para evitar bloqueos por WAFs o rate limiting.
     - Sé consciente del impacto: si estás probando con `DELETE`, ¡no borres datos de otros usuarios sin permiso explícito! Limita tus pruebas a IDs de cuentas que controles.

### IDORs en APIs (REST, GraphQL)

- **REST APIs:** Son muy susceptibles. Buscar IDs en paths (`/api/resource/{id}`), query params (`?id=`), y cuerpos JSON.
- **GraphQL APIs:**
  - Las queries pueden solicitar objetos por ID.
  - Ejemplo: `query { user(id: "123") { username email } }`
  - Se debe verificar la autorización para cada campo y objeto solicitado.
  - La introspección de GraphQL (si está habilitada) puede revelar todos los tipos y campos, facilitando la búsqueda de objetos accesibles por ID.

### Mitigaciones Clave Contra IDOR

La mitigación fundamental es aplicar **controles de acceso del lado del servidor** en cada petición que acceda a un recurso.

1. **Verificación de Permisos en el Servidor:**
   - Para cada objeto al que se accede, el servidor DEBE verificar que el usuario autenticado actual tiene los permisos necesarios para la acción solicitada (leer, escribir, borrar) sobre ESE objeto específico.
   - No confíes en los IDs enviados por el cliente sin validarlos contra la sesión del usuario.
2. **Usar Referencias Indirectas a Objetos por Usuario (Indirect Object Reference Maps):**
   - En lugar de exponer IDs directos de la base de datos (`1`, `2`, `3`), la aplicación puede usar IDs que son específicos para la sesión del usuario.
   - Ejemplo: El usuario ve `/mis_pedidos/1`, `/mis_pedidos/2`. Internamente, `1` para el Usuario A podría mapear al ID de base de datos `1278`, mientras que `1` para el Usuario B podría mapear al ID de base de datos `3409`.
3. **Evitar Exponer IDs Directos si es Posible:**
   - Usar UUIDs puede hacer la enumeración más difícil, pero NO previene IDOR si la lógica de autorización es defectuosa. La seguridad por oscuridad no es una solución real.
4. **Centralizar la Lógica de Control de Acceso:**
   - Implementar una capa o módulo de control de acceso robusto y reutilizable que sea invocado por todos los endpoints.
5. **Principio de Mínimos Privilegios:**
   - Asegurarse de que los usuarios solo tengan los permisos estrictamente necesarios para sus roles.
