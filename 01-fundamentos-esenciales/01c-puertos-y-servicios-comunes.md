Un **puerto** es un número (0-65535) que identifica un punto de comunicación en un dispositivo de red.

### Puertos típicos y relevancia ofensiva


| Puerto  | Servicio                   | Relevancia Ofensiva                                           |
| :------ | :------------------------- | :------------------------------------------------------------ |
| 21      | FTP                        | Login anónimo, credenciales débiles, versiones vulnerables. |
| 22      | SSH                        | Fuerza bruta, versiones antiguas vulnerables.                 |
| 23      | Telnet                     | Comunicación en texto plano, captura de credenciales.        |
| 25      | SMTP                       | Open relay, verificación de usuarios.                        |
| 53      | DNS                        | Transferencias de zona mal configuradas.                      |
| 80      | HTTP                       | Vulnerabilidades web (XSS, SQLi, IDOR).                       |
| 110     | POP3                       | Credenciales en texto plano.                                  |
| 139/445 | SMB/NetBIOS                | Enumeración de recursos, ataques tipo EternalBlue.           |
| 143     | IMAP                       | Credenciales en texto plano.                                  |
| 443     | HTTPS                      | Vulnerabilidades web con capa SSL/TLS.                        |
| 3306    | MySQL                      | Credenciales por defecto, ataques a bases de datos.           |
| 3389    | RDP                        | Acceso remoto, fuerza bruta, vulnerabilidades críticas.      |
| 5432    | PostgreSQL                 | Acceso a bases de datos.                                      |
| 5900    | VNC                        | Escritorio remoto, frecuentemente sin autenticación.         |
| 8080    | HTTP alternativo / Proxies | APIs y servidores de aplicaciones (Tomcat, etc.).             |

### Técnicas de Escaneo de Puertos

**Herramienta principal: `nmap`**

```bash
# Escaneo rápido de puertos TCP comunes
nmap -sT --top-ports 20 target.com

# Escaneo de todos los puertos TCP + detección de versiones y scripts por defecto
nmap -sV -sC -p- -T4 target.com

# Escaneo UDP (más lento)
nmap -sU --top-ports 20 target.com
```

**Notas:**

- Escanear UDP es más lento y propenso a falsos positivos.
- Asegúrate de combinar técnicas para mapear bien los servicios expuestos.
