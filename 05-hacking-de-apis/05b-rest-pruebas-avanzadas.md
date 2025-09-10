# REST: BOLA/BFLA, Mass Assignment, HPP y Rate Limiting

## Resumen

**Qué es:**

- **BOLA/BFLA:** Fallos de autorización que permiten acceso/operaciones indebidas mediante manipulación de IDs (BOLA) o funciones (BFLA).
- **Mass Assignment:** Permite modificar propiedades sensibles enviando campos no esperados en el cuerpo de la petición.
- **HPP:** Uso de parámetros HTTP duplicados para forzar comportamientos inesperados o burlar validaciones.
- **Rate Limiting:** Debilidad en el control de frecuencia de petición, permitiendo DoS, brute-force o abuso.

**Por qué importa:** Combinan vectores de acceso indebido, escalado de privilegios, manipulación de información crítica y denegación de servicio.

**Cuándo aplicarlo:** Pruebas avanzadas de APIs REST, pentesting en aplicaciones que exponen endpoints internos, parametrización compleja o usuarios concurrentes.

---

## Contexto

**Supuestos:**

- API RESTful documentada y con endpoints identificados.
- Permiso para fuzzear rutas, manipular cuerpos y cabeceras de requests.
- Entorno de pruebas con usuarios de diferente privilegio.

**Límites:**

- Foco en API REST, no SOAP o GraphQL.
- No cubre WAF o IDS externos, solo lógica de backend y parsing.

---

## Metodología

1. **Reconocimiento de endpoints:** Enumerar rutas y métodos, analizar parámetros.
2. **Identificación de IDs y roles:** Documentar parámetros (`id`, `user_id`, `role`).
3. **Manipulación de requests:** Cambios en IDs, envío de campos extra y repetidos, ráfagas de peticiones.
4. **Observación de resultados:** Acceso a datos ajenos, errores de parsing, respuestas inesperadas.
5. **Comparación multiusuario:** Testear diferencias de permisos y funciones según perfil.
6. **Monitoreo de respuestas de rate-limiting y errores al forzar límites.

### Ejemplo de Checklist

- Los endpoints filtran el acceso por identidad/rol real de usuario.
- El backend ignora campos inesperados en el payload.
- El parsing de parámetros QUERY/POST maneja correctamente los repetidos.
- Rate limiting efectivo aunque haya cabeceras, proxies o cambios de IP.

---

## Pruebas Manuales

### BOLA (Broken Object Level Authorization)

- Modificar rutas:
  `GET /api/v1/users/123` → Cambiar a `GET /api/v1/users/124`
- Probar acceso/acción sobre IDs ajenos desde cuentas distintas.
- Detectar recursos expuestos sin comprobación de ownership.

### BFLA (Broken Function Level Authorization)

- Enviar llamadas a rutas ADMIN o métodos no documentados con usuarios normales:
  `POST /api/v1/admin/users – X-Role: user`
- Cambiar métodos (GET→PUT→DELETE) y observar si el permiso falla.

### Mass Assignment

- Ampliar el JSON enviado:

```json
{ "username": "attacker", "isAdmin": true }
```

- Revisar cambios de privilegio tras respuesta HTTP.

### HPP (HTTP Parameter Pollution)

- Duplicar parámetros en QUERY/POST:
  `/api/items?id=1&id=2`
- Observar variaciones en la respuesta, exploits de lógica y bypass de validaciones.

### Rate Limiting

- Enviar 100+ peticiones/segundo.
- Cambiar IP, user-agent o cabeceras (X-Forwarded-For).
- Fijarse si el endpoint aplica limitación real o permite brute force/scraping.

---

## PoC Automatizada

**Tools recomendados:**

- Burp Intruder y Param Miner
- ffuf y gatling
- Scripts en Python con requests y threading
- ZAP ActiveScan y plugins de fuzzing

**Ejemplo BOLA mediante Python:**

```python
for i in range(1,100):
    r = requests.get(f'https://victima.com/api/orders/{i}', headers={'Authorization':'Bearer ...'})
    print(i, r.status_code)
```

**Payloads Mass Assignment:**

```python
data = {'username':'victim', 'isAdmin':True}
r = requests.post('https://victima.com/api/users', json=data)
print(r.text)
```

---

## Explotación y Automatización

- *BOLA/BFLA*: Repetir la manipulación en masa para extraer/alterar todos los objetos posibles.
- *Mass Assignment*: Automatizar creación/alteración de usuarios con privilegios elevados.
- *HPP*: Fuzzing de todo endpoint y método con parámetros múltiples.
- *Rate Limiting*: Distribuir requests en diferentes IPs/proxies y analizar respuestas.

---

## Impacto

- **BOLA:** Fuga de datos, account takeover, modificaciones destructivas masivas.
- **BFLA:** Escalada de privilegios, acceso a operaciones críticas.
- **Mass Assignment:** Obtención de roles altos, manipulación financiera o administrativa.
- **HPP:** Lógica de negocio rota, bypass de controles de seguridad.
- **Rate Limiting:** DoS, abuso de recursos, fuerza bruta de autenticación o scraping total.

---

## Detección

- Logs de acceso a IDs ajenos o acciones fuera del perfil.
- Notificaciones de parsing ambiguo y repetido de parámetros.
- Picos de peticiones por usuarios/IPs con mismo token o patrón.
- Monitorización de errores 500/403/429 tras fuzzing avanzado.

---

## Mitigación

- Revisar y reforzar controles de autorización a nivel de objeto y función.
- Definir listas blancas de campos aceptados (DTO), nunca procesar campos inesperados.
- Parsing seguro y estricto de parámetros: rechazar valores múltiples para claves donde no corresponde.
- Implementar rate limiting real que contemple evasión por headers/IP/user.
- Pruebas post-mitigación automáticas con tests negativos (fuzzers, Burp automation).

---

## Errores Comunes

- Asumir que endpoints internos no requieren controles de acceso.
- Ignorar campos extra en payloads de usuarios.
- No auditar logs de parsing ambigüo ni pico de requests.
- Basar limitación solo en IP, sin fingerprinting ni token de usuario.

---

## Reporte

**Título:** Exposición de datos y lógica crítica por BOLA/BFLA, Mass Assignment, HPP y Rate Limiting insuficiente
**Impacto:** Escalado de privilegios, fuga masiva de datos, DoS y manipulación de lógica interna.
**Pasos:**

1. Manipulación de IDs/campos/parámetros repetidos/requests concurrentes en los endpoints afectados.
2. Evidencia por logs, respuestas HTTP y acciones no autorizadas.
   **Mitigación:**

- Controles robustos de autorización, parsing estricto y rate limiting real a nivel de usuario.

**Comparativa de vulnerabilidades REST:**

![Comparativa avanzada de vulnerabilidades REST: técnicas, pruebas y mitigaciones.](https://ppl-ai-code-interpreter-files.s3.amazonaws.com/web/direct-files/a68f4016ed28d3bbb9ebe5206f4f7b88/7beed50d-ffeb-4936-a574-c9fec3ec859b/567f2065.png)

Comparativa avanzada de vulnerabilidades REST: técnicas, pruebas y mitigaciones.
