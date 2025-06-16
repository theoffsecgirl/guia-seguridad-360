### Métodos HTTP


| Método | Descripción                      | Relevancia Ofensiva                                              |
| :------ | :-------------------------------- | :--------------------------------------------------------------- |
| GET     | Solicita datos de un recurso.     | Parámetros visibles, vulnerabilidades tipo IDOR, XSS reflejado. |
| POST    | Envía datos al servidor.         | IDOR en cuerpo, CSRF, XSS almacenado.                            |
| PUT     | Crea o reemplaza un recurso.      | Posible subida arbitraria de archivos.                           |
| DELETE  | Elimina un recurso.               | Borrado no autorizado si no hay control adecuado.                |
| HEAD    | Solicita solo las cabeceras.      | Fingerprinting de servidores.                                    |
| OPTIONS | Lista métodos permitidos.        | Puede exponer métodos habilitados peligrosos.                   |
| PATCH   | Modifica parcialmente un recurso. | Riesgos similares a PUT.                                         |
| TRACE   | Devuelve la petición enviada.    | Riesgo de Cross-Site Tracing (XST).                              |

### Códigos de Estado HTTP


| Código | Significado General   | Relevancia                                          |
| :------ | :-------------------- | :-------------------------------------------------- |
| 200     | OK                    | Petición exitosa.                                  |
| 201     | Created               | Recurso creado (POST/PUT).                          |
| 301     | Moved Permanently     | Redirección permanente.                            |
| 302     | Found                 | Redirección temporal.                              |
| 400     | Bad Request           | Parámetros mal formados, útil para fuzzing.       |
| 401     | Unauthorized          | Requiere autenticación.                            |
| 403     | Forbidden             | Restringido, buscar bypasses.                       |
| 404     | Not Found             | Enumeración de rutas.                              |
| 405     | Method Not Allowed    | Probar otros métodos HTTP.                         |
| 500     | Internal Server Error | Revelación de información sensible, stack traces. |
| 503     | Service Unavailable   | Servidor saturado o en mantenimiento.               |

### Cabeceras HTTP Relevantes

- **Host**: Indica el dominio destino.
- **User-Agent**: Identifica el cliente.
- **Cookie**: Gestiona sesiones.
- **Authorization**: Envía credenciales.
- **Content-Type**: Tipo de contenido enviado.
- **Set-Cookie**: Establece cookies de sesión.
- **Location**: Redirecciones.
- **Security Headers**:
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `Strict-Transport-Security` (HSTS)

### Frontend vs Backend


| Parte    | Tecnologías                   | Vulnerabilidades comunes                         |
| :------- | :----------------------------- | :----------------------------------------------- |
| Frontend | HTML, CSS, JS (React, Angular) | XSS, Open Redirect, exposición de información. |
| Backend  | PHP, Python, Node.js, Java     | SQLi, LFI/RFI, SSRF, IDOR, XXE.                  |

### Infraestructura Web

- **Servidor Web**: Nginx, Apache, IIS.
- **Balanceadores de carga**: Distribución de tráfico.
- **WAF (Web Application Firewall)**: Filtrado de tráfico malicioso.
- **Bases de datos**: MySQL, PostgreSQL, MongoDB.

**Notas Ofensivas**:

- Identificación de WAFs.
- Técnicas de bypass.
- Detección de configuraciones débiles en servidores y bases de datos.
