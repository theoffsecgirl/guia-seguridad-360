# Webhooks, Colas e Idempotencia

## Resumen

**Qué es:**

- **Webhooks**: callbacks HTTP generalmente usados para notificaciones o integración entre sistemas.
- **Colas de mensajes**: sistemas asincrónicos para desacoplar tareas (ej: RabbitMQ, SQS, Kafka).
- **Idempotencia**: propiedad que asegura que la misma petición ejecutada múltiples veces produce un solo efecto.
  **Por qué importa:** La falta de controles en webhooks y colas permite ataques de request forgery, replay, race conditions y abuso de lógica.
  **Cuándo aplicarlo:** En pruebas de APIs con eventos, workflows de integración entre sistemas, pagos, tareas programadas o notificaciones.

---

## Contexto

**Supuestos:**

- Webhooks configurados como endpoints HTTP públicos en `/webhook` o `/api/callback`.
- Colas expuestas mediante HTTP, AMQP, MQTT, SQS o puntos RESTful.
- Acceso para forjar peticiones y modificar payloads, con visibilidad del tráfico (Burp, mitmproxy).
- Pruebas sobre APIs que manejan pagos, creación de órdenes o procesamiento batch.

**Límites:**

- Foco en lógica de aplicación y mecanismos estándar, no exploitación de infra interna (broker-level).
- No cubre colas internas del kernel ni notificaciones push propietarias.

---

## Metodología

1. **Reconocimiento del endpoint de webhook/cola:**
   - Enumerar rutas `/webhook`, `/callbacks`, `/notify`, `/queue`.
   - Revisar la documentación o ejecución de eventos para capturar el flujo.
2. **Pruebas de abuso en webhooks:**
   - Reenvío manual de la misma petición para comprobar duplicidad.
   - Modificación de payloads para cambio de destinatarios, estados, importes.
   - Omisión o forjado de parámetros de autenticación/hmac/signature.
3. **Análisis de idempotencia:**
   - Repetir la misma petición webhook (con mismo/IDempotency-Key).
   - Observar si el sistema duplica la acción (ej: dobles pagos, doble alta).
4. **Ataques sobre colas:**
   - Enviar mensajes manipulados a la cola (inserción maliciosa, replay).
   - Forzar consumo múltiple del mismo mensaje (lack of ack/nack control).
   - Saturar la cola para DoS (flood de trabajos falsos).

**Checklist de verificación:**

- Validación de autenticidad del origen (IP, token, signature).
- Implementación segura de la idempotencia (clave por petición, hash de body).
- Cola con control de duplicidad y acknowledgment robusto.
- Logs claros de eventos procesados, recibidos y descartados.
- Tiempos de expiración y retries controlados.

---

## Pruebas Manuales

### Webhooks

1. **Replay Attack:**
   - Capturar petición legítima de webhook (ej: de Stripe o GitHub).
   - Reenviarla varias veces desde Burp Repeater o curl.
   - Observar si cada replay procesa la acción de nuevo (cobros duplicados, multi-login, etc).
2. **Signature Tampering:**
   - Modificar payload y dejar la misma signature/HMAC.
   - Enviar al endpoint y buscar bypass en la verificación de origen.
3. **Cambio de destino:**
   - Clonar payload pero cambiar destinatario, importe o identificador de recurso.

### Colas

1. **Bulk Submit/Flood:**
   - Enviar 100+ mensajes a la cola sin validación.
   - Comprobar si el sistema se degrada o repite procesamientos.
2. **Queue Poisoning:**
   - Inyectar un mensaje malicioso para manipular una lógica downstream (objeto con claves inusuales).
3. **Double Consumption:**
   - Forzar condiciones donde el mismo mensaje es consumido y procesado 2+ veces.

### Idempotencia

1. **Repetición con misma clave:**
   - Repetir requests con y sin cabecera `Idempotency-Key`.
   - Revisar si sólo una petición tiene efecto.
2. **Prueba sin control:**
   - Misma petición repetida genera varios cambios/creaciones (vulnerabilidad).

---

## PoC Automatizada

**Replay Attack Webhook:**

```bash
# Reenviar webhook 5 veces
for i in {1..5}; do
  curl -X POST https://victima.com/webhook/receive -d @payload.json -H "X-Signature: ..."</code>
done
```

**Ataque de duplicación en cola:**

```python
import requests
payload = {"action":"transfer","amount":100,"account_id":"123"}
for i in range(10):
    requests.post("https://victima.com/api/queue", json=payload)
```

**Idempotencia:**

```bash
curl -X POST https://victima.com/api/orders -d '{"item":"X"}' -H 'Idempotency-Key: TESTKEY'
curl -X POST https://victima.com/api/orders -d '{"item":"X"}' -H 'Idempotency-Key: TESTKEY'
```

Verificar que sólo hay un pedido creado.

---

## Explotación y Automatización

- Automatizar flood de webhooks para DoS/ECS.
- Generar variaciones de payload buscando IDs del mismo recurso.
- Manipular y combinar peticiones para romper la lógica idempotente.
- Forzar condiciones de race al enviar múltiples peticiones en paralelo.

---

## Impacto

- **Doble procesamiento:** Pagos duplicados, creación masiva de recursos no controlados.
- **Forzado de lógica:** Cambios de estado, overriding vía race condition.
- **Denegación de servicio:** Flood de jobs webhooks, saturación de colas, procesamiento innecesario.
- **Fuga y manipulación:** Envío de datos a endpoints no controlados (SSRF/webhook chaining).

**CWE/OWASP:** CWE-294 Authentication Bypass, CWE-664 Race Condition, API4: Lack of Resources \& Rate Limiting, API7: Security Misconfiguration.

---

## Detección

- Logs de eventos duplicados o con la misma Idempotency-Key.
- Alertas de repetición inusual de webhooks.
- Detección de patrones en payloads (hash/body) y flujos no esperados.
- Métricas de saturación en colas y tiempos de proceso.
- Alertas de tráfico elevado en endpoints de callback.

---

## Mitigación

- Validar autenticidad de cada webhook (IP Allow, signature, shared secret, HMAC).
- Implementar lógica de idempotencia robusta con clave única y almacenamiento temporal.
- Limitar número de retries y tiempos de vida de los mensajes de cola.
- Controlar tamaño y frecuencia de peticiones entrantes.
- Alertar y bloquear patrones repetitivos.

---

## Errores Comunes

- No validar la fuente de las peticiones de webhook.
- No implementar ningún control de idempotencia.
- Ausencia de acknowledgment correcto en consumidor de colas.
- Recrear recursos para cada recepción idéntica.
- No loggear duplicidades ni abuso operativo.

---

## Reporte

**Título:** Falta de control en webhooks/colas permite duplicidad, abuso y lógica incorrecta
**Impacto:** Pagos duplicados, DoS, exfiltración y manipulación de eventos críticos
**Pasos:**

1. Reenviar petición de webhook sin cambios
2. Observar duplicidad/abuso en lógica de negocio
3. Modificar payloads para manipulación o inyección
4. Verificar falta de validación o logs
   **Evidencias:** Logs de duplicación, respuestas múltiples, recursos múltiple veces creados
   **Mitigación:** Validación robusta de fuente, idempotencia por clave, control de colas, alertas y cierre de abuse patterns

---
