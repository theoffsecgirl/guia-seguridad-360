El **Domain Name System (DNS)** traduce nombres de dominio legibles por humanos (e.g., `www.google.com`) en direcciones IP numéricas que entienden las máquinas.

### Jerarquía de DNS


| Tipo  | Descripción                  | Ejemplo                  |
| :---- | :---------------------------- | :----------------------- |
| Root  | `.` implícito                |                          |
| TLD   | Top-Level Domain              | `.com`, `.org`           |
| ccTLD | Country Code Top-Level Domain | `.es`, `.uk`             |
| sTLD  | Sponsored TLD                 | `.gov`, `.edu`           |
| SLD   | Second-Level Domain           | `google` en `google.com` |

### Registros DNS comunes


| Tipo  | Descripción                              |
| :---- | :---------------------------------------- |
| A     | Mapea un dominio a una dirección IPv4.   |
| AAAA  | Mapea un dominio a una dirección IPv6.   |
| MX    | Servidores de correo electrónico.        |
| CNAME | Alias de otro dominio.                    |
| TXT   | Información adicional (SPF, DKIM, etc.). |
| NS    | Servidores de nombre autorizados.         |
| SRV   | Servicios específicos en el dominio.     |

### Técnicas de Reconocimiento y Ataques sobre DNS

- **Enumeración de Subdominios**:

  - Fuerza bruta con diccionarios.
  - OSINT y Google Dorks (`site:*.dominio.com`).
- **Transferencias de Zona (AXFR)**:

  - Malas configuraciones permiten listar todos los registros DNS.
- **Tipos de Ataques**:

  - **DNS Rebinding**: Manipulación de resoluciones para bypassear firewalls.
  - **DNS Cache Poisoning**: Inyectar datos falsos en la caché de un servidor DNS.
  - **DNS Tunneling**: Exfiltración de datos a través de consultas DNS.

### Herramientas Comunes para DNS

- `dig`
- `nslookup`
- `host`
- `dnsrecon`
- `fierce`
- `sublist3r`
- `Amass`

### Ejemplos de uso de `dig`

```bash
# Obtener el registro A
dig A www.ejemplo.com +short

# Obtener registros MX
dig MX ejemplo.com

# Intentar transferencia de zona
dig AXFR ejemplo.com @ns1.ejemplo.com
```

### Códigos de Estado DNS comunes


| Código  | Significado                              |
| :------- | :--------------------------------------- |
| NOERROR  | Respuesta correcta.                      |
| NXDOMAIN | El dominio consultado no existe.         |
| SERVFAIL | Error en el servidor DNS.                |
| REFUSED  | Petición rechazada por el servidor DNS. |
