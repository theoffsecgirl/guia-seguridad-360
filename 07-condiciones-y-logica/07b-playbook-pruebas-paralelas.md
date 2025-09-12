# Playbook de Pruebas Paralelas

## Resumen

**Qué es:** Las pruebas paralelas consisten en lanzar múltiples peticiones simultáneamente para identificar condiciones de carrera, fallos lógicos, validaciones insuficientes y fraudes en aplicaciones y APIs.
**Por qué importa:** Detecta vulnerabilidades que no pueden encontrarse en pruebas secuenciales (fraudes multi-pago, duplicidad, privilegios, DoS lógico) y expone falta de atomicidad en el backend o base de datos.
**Cuándo aplicarlo:** En todas las funcionalidades críticas — compras, pagos, transferencias, creación de recursos, registro, generación de tokens/códigos — especialmente bajo entornos multiusuario y microservicios.

---

## Contexto

**Supuestos:**

- Acceso a endpoints de la aplicación o API (HTTP(s), gRPC).
- Capacidad para lanzar peticiones concurrentes mediante scripting, herramientas o extensiones de pentesting.
- Herramientas: Turbo Intruder (Burp), ffuf, OWASP ZAP, Postman Runner, Python multithreading, Bash loops, JMeter.
- Pruebas con múltiples cuentas y/o credenciales (cuando sea posible).

**Límites:**

- No cubre pruebas concurrentes a nivel bajo (kernel, threads internos).
- Foco en ataque black/grey box; sin instrumentación en código fuente o backend.

---

## Metodología

1. **Selección del objetivo:** Elige endpoints críticos (pagos, creación, actualización de estado, login, registro, uso de tokens).
2. **Diseño del payload:** Prepara la petición a manipular; define datos únicos si es posible (IDs, tokens, referencias).
3. **Automatización:** Usa herramientas para disparar ráfagas de peticiones:
   - Scripts Python (threading, async)
   - Turbo Intruder en Burp Suite
   - ffuf o ZAP para RESTful
   - JMeter o Postman Runner para secuencias complejas
4. **Ejecución de la prueba:** Lanza entre 10 y 500+ peticiones en paralelo, variando tiempos, parámetros o cabeceras si es relevante.
5. **Observación y recolección de resultados:** Analiza respuestas, verifica duplicidad, inconsistencias, balance, recursos creados/modificados.
6. **Repetición en variantes:** Cambia usuarios, tipos de datos, o condiciones (token válido/expirado).

**Checklist rápida de paralelismo efectivo:**

- El backend maneja atomicidad correctamente.
- No se producen duplicidades al crear recursos (cuentas, pagos, cupones).
- Respuestas HTTP coherentes (no hay 500/502/404 inesperados).
- Saldo, inventario o estado no se afecta negativamente por ráfagas.
- Si hay tokens/códigos, nunca se genera más de uno con misma clave.

---

## Pruebas Manuales

**1. Turbo Intruder (Burp Suite):**

```python
from turbo_intruder import Request, Engine

def queue_requests(target, engine):
    for _ in range(50):
        engine.queue(Request('POST /api/buy HTTP/1.1...\n\nitem=1&units=1'))

def handle_response(req, interesting):
    if 'Success' in req.response.text:
        interesting.append(req)
```

**2. Python y threading:**

```python
import requests, threading

def attack():
    requests.post('https://victima.com/api/buy', json={'item':1, 'units':1})

threads = [threading.Thread(target=attack) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()
```

**3. ffuf para endpoints REST:**

```bash
ffuf -w ids.txt -u https://victima.com/api/resource/FUZZ -t 20 -d '{"data":"test"}'
```

**4. JMeter/Postman Runner:**

- Configura escenarios de ráfaga de requests con parámetros paralelos y observa integridad en los resultados.

---

## PoC Automatizada

**Compra paralela de item único:**

```python
import requests, threading

item_id = 101
def comprar():
    requests.post('https://victima.com/api/cart', json={'item':item_id})

threads = [threading.Thread(target=comprar) for _ in range(100)]
for t in threads: t.start()
for t in threads: t.join()
```

- Verifica que solo se acepta una compra y las demás fallan/cancelan.

---

## Explotación y Automatización

- *Multi-pago*: Duplicidad de compras/pagos en milisegundos.
- *Race para registro*: Creación múltiple de cuentas o recursos únicos.
- *Canje doble de token/cupón*: Validaciones simultáneas permiten abuso.
- *Trashing de inventario*: Consumo/bloqueo simultáneo de stock.

---

## Impacto

- **Fraude:** Duplicidad de pagos, productos, canje de cupones.
- **DoS lógico:** Saturación de recursos, inconsistencias de datos.
- **Manipulación:** Creación/actualización incoherente de registros o estados.
- **Pérdida de integridad:** Balance, inventario o tokens inconsistentes.

**OWASP/CWE:** API7 Security Misconfiguration, API3 Excessive Data Exposure, CWE-362 Race Condition.

---

## Detección

- Logs de múltiples operaciones en el mismo recurso en milisegundos.
- Alertas de duplicidad de registros, pagos, códigos.
- Errores 500/502/409 en respuestas bajo estrés.
- Balance/inventario y estado de objetos inconsistentes tras la prueba.

---

## Mitigación

- Implementar locks, transacciones y atomicidad en backend y base de datos.
- Validación y respuesta única en elementos configurados como únicos.
- Idempotencia en endpoints críticos.
- Pruebas regulares de ráfagas en QA/post-fix.
- Alertas y monitoreo en logs de concurrencia.

---

## Errores Comunes

- Mezclar pruebas secuenciales y asumir protección.
- No controlar duplicidad in-memory/in-disk.
- Falta de logs detallados por milisegundos.
- Omitir balance, stock o tokens en pruebas de bulk.

---

## Reporte

**Título:** Race condition y pruebas paralelas permiten duplicidad y fraude en endpoint crítico
**Impacto:** Multi-pago, multi-cuenta, canje/código duplicado, pérdida de integridad
**Pasos:**

1. Ejecutar ráfaga de peticiones paralelas contra operación crítica
2. Analizar respuestas/logs/balance/recursos tras ataque
3. Evidenciar duplicidad, DoS lógico o inconsistencias
   **Mitigación:** Refuerzo de atomicidad, locks, idempotencia y logging fino
