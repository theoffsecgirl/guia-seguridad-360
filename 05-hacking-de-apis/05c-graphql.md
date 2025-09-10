# GraphQL: Introspección y Abusos

## Resumen

**Qué es:** GraphQL es un lenguaje de consulta para APIs que permite a los clientes solicitar exactamente los datos que necesitan.
**Por qué importa:** La introspección y flexibilidad de GraphQL facilitan la enumeración profunda, acceso a datos sensibles y explotación de lógica interna.
**Cuándo aplicarlo:** Crucial donde apps exponen `/graphql` y ofrecen introspección o carecen de controles finos.

---

## Contexto

**Supuestos:**

- El endpoint `/graphql` es público o accesible, aceptando queries POST (y a veces GET).
- Herramientas como Burp Suite, Postman, GraphQL Voyager, Altair, Insomnia, InQL.
- Usuarios de distinto rol para contraste entre respuestas y validación de autorizaciones.
- API implementada en stacks populares (Apollo, Graphene, express-graphql, graphql-java, Hasura).

**Límites:**

- Foco en APIs RESTful extendidas con GraphQL.
- No cubre protecciones de WAF que inspeccionan payloads GraphQL.

---

## Metodología

1. **Reconocimiento del endpoint:**
   - Localizar `/graphql`, `/graphiql`, `/playground`.
   - Inspeccionar si hay consola interactiva expuesta.
2. **Enumeración por introspección:**
   - Lanzar queries introspectivas (`__schema`, `__type`).
   - Obtener tipos, queries, mutations y sus argumentos.
   - Usar herramientas: InQL, GraphQL Voyager.
3. **Mapeo de operaciones y tipos:**
   - Identificar queries, mutations, subscriptions.
   - Enumerar campos ocultos, tipos no documentados, argumentos sensibles.
4. **Pruebas de parámetros y abuso de lógica:**
   - Pruebas de privilegios cruzados (consultar/alterar datos ajenos).
   - Fuzzing de argumentos, envío de tipos inadecuados.
   - Intentos de acceso a campos internos (`isAdmin`, `passwordHash`, etc).
5. **Exploración de errores y respuestas:**
   - Explotar mensajes de error detallados.
   - Forzar fragmentos no válidos, queries excesivas o recursivas.
6. **Análisis de profundidad/recursividad:**
   - Usar queries anidadas para obtener grandes volúmenes de información.
   - Intentar DoS por queries recursivas o deep nesting.

**Checklist de verificación:**

- Introspección habilitada (¿se puede obtener el esquema?).
- Autorizaciones a nivel de campo y tipo.
- Protección frente a queries recursivas/deeply nested.
- Limitación en el tamaño y complejidad de las queries.
- Control de errores (sin filtración de stacktraces o detalles internos).

---

## Pruebas Manuales

### 1. Introspección básica

```json
{
  "query": "{ __schema { types { name fields { name type { name } } } } }"
}
```

Respuesta: El esquema completo, incluyendo tipos ocultos y endpoints no documentados.

### 2. Enumeración de Mutations y Queries

```json
{
  "query": "{ __type(name: \"Mutation\") { fields { name args { name type { name } } } } }"
}
```

### 3. Prueba de acceso a datos sensibles

```json
{
  "query": "{ users { id email isAdmin passwordHash } }"
}
```

Evaluar si campos internos están expuestos.

### 4. Bypass de autenticación/autorización

- Repetir queries como user regular y admin.
- Modificar IDs sin autorización.

```json
{
  "query": "{ user(id: \"2\") { email role } }"
}
```

### 5. Query para DoS/Exfiltración masiva

```json
{
  "query": "query { users { posts { comments { author { email } } } } }"
}
```

Consultar objetos recursivos aumenta la carga del backend y posibilita extracción masiva.

---

## PoC Automatizada

**Enumeración general (usando InQL):**

```bash
inql -t https://victima.com/graphql
```

**Fuzzing de campos y argumentos (Python):**

```python
import requests

endpoint = 'https://victima.com/graphql'
payload = { "query": "{ __schema { types { name fields { name } } } }" }

r = requests.post(endpoint, json=payload)
print(r.json())
```

**DoS recursivo:**

```json
{
  "query": "{ a { b { c { d { e { f { g } } } } } } }"
}
```

---

## Explotación y Automatización

- **Introspección total:** Descubrir todos los tipos, queries y mutations posibles.
- **Abuso de queries recursivas/anidadas:** Extraer grandes volúmenes o saturar el backend.
- **IDOR y escalada de privilegios:** Acceso a recursos de otros usuarios usando argumentos manipulados.
- **Filtrado de lógica y configuración interna:** Stacktraces, rutas internas, credenciales por errores.

---

## Impacto

- **Data breach multiperfil:** Acceso a toda la información no segregada por role.
- **Bypass de controles:** Ataques IDOR y privilege escalation si no hay validación granular.
- **Denegación de servicio:** Queries anidadas sobrecargan el servidor.
- **Exposición de lógica interna:** Esquema revela flujos y modelos de negocio ocultos.

**Mapeo:**

- OWASP API Security Top 10 (API1, API3, API5)
- CWE-639, CWE-522, CWE-200

---

## Detección

- Revisar logs de:
  - Queries `__schema`, `__type` por usuarios no admin.
  - Excesivo anidamiento o recursividad en queries.
  - Accesos a campos sensibles por usuarios no autorizados.
  - Errores 500 con stacktraces o detalles técnicos.
- Audit trail de operaciones sensibles vía GraphQL.

---

## Mitigación

- Deshabilitar introspección en producción o filtrar por roles.
- Validar autorización a nivel de campo/mutation.
- Limitar profundidad y tamaño de queries (depth limit, complexity limit).
- Sanear mensajes de error y filtrar información sensible en respuestas.
- Endpoint GraphQL tras autenticación (no público).

---

## Errores Comunes

- Dejar introspección activa sin control.
- Falta de validación de autorización en cada campo/operación.
- No aplicar limits de complejidad o tamaño de queries.
- Explicar lógica del modelo/negocio en mensajes de error.

---

## Reporte

**Título:** Introspección y abuso de GraphQL permiten exfiltración y escalada en la API
**Impacto:** Acceso y extracción masiva de datos, bypass de controles y denegación de servicio.
**Pasos:**

1. Enumerar esquema y tipos vía introspección.
2. Acceso a campos/queries/mutations críticos.
3. Explotar queries recursivas o profundas hasta saturar el backend.

**Evidencias:**

- Resultados de queries con datos internos.
- Log de errores detallados tras manipulación de payloads.
- PoC de queries no documentadas/privadas ejecutadas desde usuario básico.

**Mitigación:**
Limitar introspección, autorización granular, depth/complejidad y sanear errores.

---
