# gRPC: Reflexión, Conversión y Fuzzing

## Resumen

**Qué es:** gRPC es un framework de comunicación eficiente basado en Protobuf, ideal para microservicios y APIs de alto rendimiento.
**Por qué importa:** La reflexión y las conversiones expuestas facilitan mapeo rápido y ataques dirigidos, mientras que las pruebas de fuzzing revelan vulnerabilidades ocultas en la lógica binaria.
**Cuándo aplicarlo:** Indispensable en pentests y bug bounty sobre APIs internas o de alto rendimiento con arquitectura microservicios.

---

## Contexto

**Supuestos:**

- Acceso a endpoints gRPC en HTTP/2, TCP o sockets Unix (`:50051`, `/grpc`).
- Herramientas: grpcurl, gRPCui, Burp Extension gRPC, protobuf decoders, boofuzz, radamsa.
- Definiciones de servicios en ficheros `.proto` accesibles o recuperables por reflexión.
- Tests en infraestructuras modernas: Go, Python, Java, Node.js.

**Límites:**

- No cubre servicios expuestos solo vía API Gateway.
- Enfoque en gRPC/Protobuf, no en Thrift o SOAP Binario.

---

## Metodología

1. **Reconocimiento del endpoint:**
   - Identificar puertos y rutas gRPC expuestas.
   - Probar con `grpcurl` si el servicio soporta reflexión.
2. **Enumeración con reflexión:**
   - Lanzar `grpcurl -plaintext <host>:<port> list` y `grpcurl -plaintext <host>:<port> describe <Service>`.
   - Exfiltrar nombres de métodos, tipos, mensajes y comentarios útiles.
3. **Conversión y crafting de payloads:**
   - Compilar `.proto` con `protoc` para obtener estructuras de mensajes.
   - Generar ejemplos válidos y valores borde para cada campo.
   - Convertir binarios a JSON para manipulación rápida.
4. **Pruebas de fuzzing:**
   - Automatizar pruebas enviando valores extremos, nulos, sobre/underflows en campos Protobuf.
   - Usar radamsa, boofuzz o scripts Python para fuzzear mensajes.
   - Comparar respuestas y analizar errores (desbordamiento, parsing, DoS).

**Checklist de verificación:**

- Servicio permite reflexión e introspección.
- Validación binaria estricta en backend.
- Timeout y límite de tamaño configurados.
- Errores gestionados sin filtración de lógica interna.
- Autorización a nivel de método/campo.

---

## Pruebas Manuales

### 1. Reflexión con grpcurl

```sh
grpcurl -plaintext atacante.com:50051 list
grpcurl -plaintext atacante.com:50051 describe NombreServicio
```

Obteniendo todos los comandos, métodos y tipos.

### 2. Generación de payloads válidos/atípicos

```proto
message Usuario {
  string nombre = 1;
  int32 edad = 2;
  bool isAdmin = 3;
}
```

```sh
grpcurl -d '{ "nombre": "A", "edad": -1, "isAdmin": true }' \
  -plaintext atacante.com:50051 Servicio/Metodo
```

### 3. Fuzzing de campos Protobuf

```python
from boofuzz import *
session = Session(target=Target(connection=SocketConnection('atacante.com',50051,proto='tcp')))
s_initialize("gRPC Fuzz")
s_string("usuario", fuzzable=True)
s_int32(-2147483648, fuzzable=True)  # edge case
session.connect(s_get("gRPC Fuzz"))
session.fuzz()
```

### 4. Manipulación en JSON → Protobuf → gRPC

- Convertir binarios usando `protoc --decode_raw`.
- Pruebas manuales con parámetros incorrectos, arrays enormes o campos omitidos.

---

## PoC Automatizada

**Ataque de reflexión y fuzzing con grpcurl:**

```sh
grpcurl -plaintext atacante.com:50051 list
for m in $(grpcurl -plaintext atacante.com:50051 list Servicio); do
   grpcurl -d '{}' -plaintext atacante.com:50051 Servicio/$m
done
```

**Fuzz con radamsa:**

```sh
echo '{"nombre":"A", "edad":30}' | radamsa | grpcurl -d @ -plaintext atacante.com:50051 Servicio/Metodo
```

---

## Explotación y Automatización

- *Conversión masiva:* Generar combinaciones extremas de campos usando conversión JSON-binario-protobuf.
- *Replay y brute force* en métodos sensibles (`CreateUser`, `SetPermission`, `ImportData`).
- *Fuzzing avanzado* con boofuzz y radamsa para saturar parsing binario.
- *Null value/overflows:* Envío repetido de binarios truncados, oversized o tipos erróneos.

---

## Impacto

- **Full domain enumeration:** Descubres todos los métodos y tipos internos.
- **Data manipulation:** Creación, modificación y destrucción de objetos internos.
- **Denegación/overflow:** Saturación del backend por parsing defectuoso.
- **Logic bypass:** Acceso a métodos críticos vía crafting binario.

**CWE/OWASP:** A03 Excessive Data Exposure, CWE-119 Memory Corruption, CWE-20 Input Validation.

---

## Detección

- Logs de errores binarios: parsing, stacktraces, invalid type.
- Acceso repetido/fuzzing de métodos por usuarios anónimos.
- Análisis de picos inusuales en memory o CPU tras fuzzing.
- Correlación de errores en campos y mensajes.

---

## Mitigación

- Deshabilitar reflexión en producción.
- Validar y sanear payloads binarios antes de procesarlos.
- Autorización granular a nivel de método y campo.
- Configurar límites estrictos de tamaño y complejidad en los mensajes.
- Manage errors: stacktraces y detalles internos fuera de respuestas al cliente.

---

## Errores Comunes

- No filtrar métodos expuestos por reflexión.
- Falta de validación de tipos/nulos/extremos en toda la lógica Protobuf.
- Mensajes de error con detalles de infraestructura.

---

## Reporte

**Título:** Reflexión y fuzzing en gRPC permiten exfiltración y denegación de servicio en APIs internas
**Impacto:** Enumeración total, manipulación binaria y DoS.
**Evidencias:**

- Salidas de grpcurl mostrando métodos y tipos expuestos.
- Payloads extremos generando errores y entrada no validada.
- Fuzzing automatizado con resultados críticos.

**Mitigación:**

- Deshabilitar reflexión, validar binarios y aplicar authorization granular por método.

---
