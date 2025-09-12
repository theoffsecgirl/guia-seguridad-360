# Casos de Negocio Explotables

## Resumen

**Qué es:** Los casos de negocio explotables son escenarios donde la lógica de la aplicación puede ser abusada para lograr fraude, duplicidad, escalado de privilegios o denegación de servicio, sin depender de bugs técnicos tradicionales.
**Por qué importa:** El conocimiento y explotación de fallos en los flujos de negocio permite ataques de alto impacto: compras sin pago, transferencias doble, privilegios indebidos, manipulación de estados, abusos de inventario, y subversión de validaciones.
**Cuándo aplicarlo:** Crucial en pentests o bug bounty sobre plataformas transaccionales, financieras, de gestión de usuarios, e-commerce, SaaS y APIs expuestas con gran lógica de negocio.

---

## Contexto

**Supuestos:**

- Aplicaciones web/API con procesos críticos: compras, pagos, transferencias, gestión de privilegios, uso/canje de códigos, asignación de inventarios, workflows multi-paso.
- Acceso para manipular parámetros, tiempos y simular multiusuario/multipetición.
- Herramientas: Burp Suite, Turbo Intruder, scripts en Python, ffuf, OWASP ZAP.

**Límites:**

- Enfoque en el abuso lógico, no en vulnerabilidades de bajo nivel o exploits técnicos.
- No incluye ataques de infraestructura o bypass de autenticación directa.

---

## Metodología

1. **Identificar procesos críticos/recurrentes:**
   - Compras, pagos, registro de usuarios, transferencias, asignación/canje de cupones, validación multi-paso.
2. **Reconstruir flujo típico de negocio:**
   - Revisar la documentación de la app/API para mapear el paso a paso.
   - Observar requisitos, parámetros y controles visibles.
3. **Diseñar escenarios de manipulación:**
   - Ejecutar flujos completos, omitir pasos, alterar orden, repetir peticiones clave.
   - Modificar parámetros (ej: precios negativos, cantidades excesivas, saltar validaciones).
   - Automatizar procesos simultáneos para identificar condiciones de carrera.
4. **Ejecutar y analizar:**
   - Observar respuestas, cambios de estado, logs, registros creados, transacciones contabilizadas.
   - Confirmar el impacto: duplicidad, privilegio, abuso, DoS lógico.

---

## Pruebas Manuales

### Ejemplo 1: Compra sin pago

- Omitir el paso de confirmación de pago y enviar petición de “crear pedido” directamente.
- Modificar payload para colocar estado `paid: true` antes del workflow real.

### Ejemplo 2: Transferencia doble/duplicada

- Ejecutar dos transferencias simultáneas con el mismo saldo.
- Revisar si ambas se procesan y el saldo final es negativo o inconsistente.

### Ejemplo 3: Abuso de privilegios

- Usar endpoints de gestión para asignar roles/privilegios indebidos (ej: `PUT /users/{id}/roles` con `admin` como parámetro).
- Probar si existe validación real de permisos o sólo del front.

### Ejemplo 4: Cupones/códigos de un solo uso

- Intentar canje múltiple en simultáneo usando scripts y race conditions.

### Ejemplo 5: Manipulación de inventario

- Registrar múltiples compras en paralelo de un item limitado.
- Observar si se venden más productos que el stock disponible.

### Ejemplo 6: Workflow multi-paso subvertido

- Saltar pasos de validación de email, captcha, o ID.
- Revisar si es posible completar el registro/proceso sin los pasos obligatorios.

---

## PoC Manual y Automatizada

**Automatización de compra sin pago:**

```python
import requests
payload = {'item_id': 42, 'quantity': 1, 'paid': True}
r = requests.post('https://victima.com/api/order', json=payload)
print(r.json())
```

**Race condition para transferencia:**

```python
import requests, threading
def transfer():
    r = requests.post('https://victima.com/api/transfer', json={'from':'A','to':'B','amount':100})

threads = [threading.Thread(target=transfer) for _ in range(2)]
for t in threads: t.start()
for t in threads: t.join()
```

**Canje múltiple de cupón:**

```python
for i in range(10):
    requests.post('https://victima.com/api/coupon/redeem', json={'code':'UNIQUE2025'})
```

---

## Explotación y Automatización

- Automatizar manipulación y secuencias de pasos para maximizar el abuso (pagos, compras, roles, registros).
- Lanzar ráfagas simultáneas en endpoints sensibles para evidenciar duplicidad y condiciones de carrera.
- Manipular parámetros ocultos en el payload para forzar estados no permitidos.

---

## Impacto

- **Fraude financiero:** Compras/servicios sin pago, transferencias falsificadas.
- **Escalada de privilegios:** Acceso admin/managers desde usuarios básicos.
- **DoS lógico:** Saturación de inventario, generación masiva de registros.
- **Pérdida de integridad:** Estados, balances, inventarios y registros incoherentes.
- **Bypass de workflow:** Usuarios/compras creadas saltando controles.

**Mapeo:**
API3 Excessive Data Exposure, API7 Security Misconfiguration, CWE-284 Improper Access Control, CWE-640 Weak Workflow.

---

## Detección

- Logs de compras/pagos/acciones sin los pasos requeridos.
- Duplicidad en registros, transacciones y canjes en milisegundos.
- Alertas por saldo negativo o cambios estrictos de privilegio.
- Eventos de asignación de estados/roles fuera del flujo controlado.

---

## Mitigación

- Implementar validadores de negocio en backend para todos los pasos críticos.
- Control de atomicidad y duplicidad en registros y transacciones.
- Validación estricta de privilegios a nivel de API.
- Rate limiting y controles de concurrencia.
- Pruebas automatizadas post-fix con escenarios de abuso.

---

## Errores Comunes

- Confiar en el frontend para controlar flujo de negocio.
- Validar sólo parámetros "visibles" en el payload.
- No proteger contra operaciones duplicadas o simultáneas.
- Omitir logs/análisis de condiciones multiusuario.

---

## Reporte

**Título:** Lógica de negocio explotable permite fraude, duplicidad y escalado de privilegios
**Impacto:** Compras/transferencias sin pago, doble uso de cupón, privilegios indebidos, saturación e inconsistencia de datos
**Pasos:**

1. Manipular flujo, omitir pasos, lanzar requests paralelas en operación crítica
2. Confirmar duplicidad/abuso/privilegios en respuesta y logs
3. Evidenciar registros o transacciones incoherentes
   **Mitigación:** Validación y atomicidad en backend, control de privilegios y rate limiting
