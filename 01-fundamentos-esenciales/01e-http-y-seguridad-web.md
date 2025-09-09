# HTTP y seguridad web

HTTP define métodos de petición, códigos de estado y cabeceras que determinan cómo cliente y servidor intercambian recursos y controlan seguridad en navegadores modernos.[^1]
En la práctica conviven proxies, balanceadores y caches en el camino, por lo que conviene entender métodos, estados y cabeceras antes de auditar lógica o aplicar bypasses.[^2]

## Métodos HTTP

Los métodos indican la intención de la petición y algunas propiedades (seguro, idempotente, cacheable), lo que condiciona cómo deben procesarse y qué riesgos evaluar.[^3]


| Método | Descripción                                                        | Relevancia ofensiva                                                                                                    |
| :------ | :------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------- |
| GET     | Recupera representación del recurso; no debe modificar estado.[^3] | Parámetros en URL, trazables y cacheables; vector típico para IDOR y XSS reflejado si hay reflejo sin sanitizar.[^3] |
| HEAD    | Igual que GET pero sin cuerpo; útil para metadatos.[^3]            | Fingerprinting de servidor, existencia de recursos y validación de control de acceso sin descargar cuerpos.[^3]       |
| POST    | Envía contenido que puede cambiar estado del servidor.[^3]         | IDOR en cuerpo, CSRF si no hay protección y XSS almacenado si se refleja en respuestas posteriores.[^3]               |
| PUT     | Reemplaza la representación del recurso objetivo.[^3]              | Riesgo de subida/escritura arbitraria si no hay autorización estricta y validación de rutas/paths.[^3]               |
| DELETE  | Elimina el recurso especificado.[^3]                                | Borrado no autorizado si falla autorización a nivel de objeto o función.[^3]                                         |
| OPTIONS | Describe opciones de comunicación del recurso.[^3]                 | Enumeración de métodos permitidos y detección de endpoints CORS/métodos peligrosos expuestos.[^3]                  |
| PATCH   | Modifica parcialmente el recurso.[^3]                               | Riesgos de Mass Assignment/IDOR si se aceptan campos sensibles sin whitelisting.[^3]                                   |
| TRACE   | Bucle de eco de la petición; diagnóstico.[^3]                     | Riesgo de XST si se habilita en producción junto a cookies no protegidas.[^3]                                         |
| CONNECT | Establece túnel al servidor de destino.[^3]                        | Abuso de túneles si hay proxies inseguros o políticas laxas.[^3]                                                     |

Nota: la semántica de “seguro” e “idempotente” no impide usos inseguros; valida siempre autorización y validación de entrada por recurso y método.[^3]

## Códigos de estado HTTP

Los estados se agrupan por clases 1xx–5xx, y ayudan a interpretar control de flujo, errores y comportamientos a explotar o endurecer.[^4]


| Código | Significado                                                                     | Nota de prueba                                                                   |
| :------ | :------------------------------------------------------------------------------ | :------------------------------------------------------------------------------- |
| 200     | OK: éxito según método (GET devuelve cuerpo, HEAD solo cabeceras, etc.).[^4] | Base para comparar tamaños y firmas entre respuestas durante fuzzing.[^4]       |
| 201     | Created: recurso creado tras POST/PUT.[^4]                                      | Señal de escritura efectiva; confirma impacto en endpoints de creación.[^4]    |
| 301/302 | Redirección permanente/temporal.[^4]                                           | Cadena de redirecciones y open redirects si Location es manipulable.[^4]         |
| 400     | Bad Request: petición mal formada.[^4]                                         | Útil para detección de validaciones débiles/errores de parsing.[^4]           |
| 401     | Unauthorized: requiere autenticación.[^4]                                      | Diferenciar de 403 para descubrir existencia de recursos o auth faltante.[^4]    |
| 403     | Forbidden: denegado pese a estar autenticado.[^4]                               | Buscar bypass por método, cabeceras, casing o variaciones de ruta.[^4]          |
| 404     | Not Found: recurso no existe.[^4]                                               | Enumeración de rutas y detección de wildcard/404 blandos.[^4]                  |
| 405     | Method Not Allowed.[^4]                                                         | Probar otros métodos habilitados vía OPTIONS o verb tampering.[^4]             |
| 500     | Internal Server Error.[^4]                                                      | Stack traces, filtrado de rutas internas y diferencias de error reveladoras.[^4] |
| 503     | Service Unavailable.[^4]                                                        | Señal de rate limit/mantenimiento; ajustar carga y tiempos.[^4]                 |

## Cabeceras HTTP

Las cabeceras gobiernan negociación, autenticación y políticas de navegador; su presencia/ausencia es clave para riesgos y bypasses.[^5]

- Host: selecciona vhost de destino; manipulación útil en pruebas de Host header injection.[^5]
- User-Agent: identifica cliente; puede influir en contenido y caché.[^5]
- Authorization: credenciales (Basic/Bearer, etc.); verificar validaciones parciales.[^5]
- Cookie / Set-Cookie: sesión y flags (Secure, HttpOnly, SameSite) que afectan explotación y mitigaciones.[^5]
- Content-Type / Accept: negociación de formatos; confusiones de parser/MIME pueden abrir vectores.[^5]
- Location: destino en redirecciones; comprobar open redirect.[^5]

### Cabeceras de seguridad (recomendadas)

El proyecto OWASP Secure Headers documenta cabeceras que elevan seguridad del lado cliente y deben revisarse/bloquearse en auditorías.[^6]

- Content-Security-Policy (CSP): restringe fuentes de script/recursos para mitigar XSS; revisar políticas y bypass comunes.[^6]
- Strict-Transport-Security (HSTS): fuerza HTTPS y protege frente a downgrade/mitm; validar max‑age/includeSubDomains.[^6]
- X-Frame-Options o frame-ancestors en CSP: mitiga clickjacking; comprobar si permite embedding donde no procede.[^6]
- Referrer-Policy, X-Content-Type-Options, Permissions-Policy: reducen filtraciones y comportamientos peligrosos; verificar ausencia o valores laxos.[^6]

## Infraestructura típica

En camino hay servidores web, proxies, balanceadores y caches que pueden reescribir cabeceras, variar métodos soportados y alterar claves de cacheo, afectando explotación y detección.[^2]
Entender el rol de cada salto ayuda a diferenciar fallos de aplicación de políticas perimetrales y a elegir vectores como smuggling/desync o cache poisoning cuando proceda.[^2]

## Práctica rápida (cURL)

```bash
# Ver cabeceras y estado
curl -i -s https://objetivo.tld/ -H 'Accept: text/html'

# Descubrir métodos permitidos
curl -i -s -X OPTIONS https://api.objetivo.tld/v1/recurso

# Probar contenido y caché
curl -i -s https://objetivo.tld/pagina?x=1
curl -i -s https://objetivo.tld/pagina?x=1 -H 'Cache-Control: no-cache'
```

Estas pruebas de bajo impacto permiten trazar métodos, estados y políticas iniciales antes de fuzzing intensivo o pruebas intrusivas.[^2]

## Checklist ofensivo

- Métodos: ¿expuestos más allá de GET/POST (PUT/DELETE/PATCH/TRACE/CONNECT)? Confirmar con OPTIONS y variaciones.[^3]
- Estados: ¿diferencias 401/403/404 revelan existencia/autorización? Capturar firmas de respuesta.[^4]
- Cabeceras: ¿faltan CSP/HSTS/XFO u otras de OWASP Secure Headers o están mal configuradas? Anotar valores exactos.[^6]
- Infraestructura: ¿comportamientos distintos por proxy/balanceador que alteren parsing/caché? Documentar rutas y saltos.[^2]

Si se desea, se puede añadir una tabla de mapeo método→propiedades (seguro, idempotente, cacheable) y plantillas de pruebas específicas por cabecera de seguridad.[^6]
<span style="display:none">[^13][^17][^21][^9]</span>


[^1]: https://developer.mozilla.org/en-US/docs/Web/HTTP
    
[^2]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview
    
[^3]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods
    
[^4]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status
    
[^5]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers
    
[^6]: https://owasp.org/www-project-secure-headers/
    
[^7]: https://owasp.org/www-community/Security_Headers
    
[^8]: 01e-http-y-seguridad-web.md
    
[^9]: https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Methods
    
[^10]: https://developer.mozilla.org/en-US/docs/Web/API/Request
    
[^11]: https://es.scribd.com/document/421297347/Metodos-de-Peticion-HTTP-HTTP-MDN
    
[^12]: https://devdoc.net/web/developer.mozilla.org/en-US/docs/Web/HTTP/Methods.html
    
[^13]: https://developer.mozilla.org.cach3.com/en/HTTP/HTTP_response_codes
    
[^14]: https://github.com/OWASP/www-project-secure-headers
    
[^15]: https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status
    
[^16]: https://www.youtube.com/watch?v=N4F3VWQYU9E
    
[^17]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference
    
[^18]: https://developer.mozilla.org/en-US/docs/Web/API/Response/status
    
[^19]: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
    
[^20]: https://owasp.org/www-project-developer-guide/release-es/implementación/librerías_seguras/oshp/
    
[^21]: https://nodejs.org/api/http.html
