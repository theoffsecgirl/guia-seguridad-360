# Puertos y servicios comunes

Un puerto es un número de 0 a 65535 asociado a un protocolo de transporte (TCP/UDP) que identifica puntos lógicos de comunicación en un host. Los rangos oficiales son: Well‑Known 0–1023, Registered 1024–49151 y Dynamic/Private 49152–65535.[^1]

## Puertos típicos (mapa rápido)[^5]


| Puerto  | Protocolo | Servicio               | Nota de uso                                                                  |
| :------ | :-------- | :--------------------- | :--------------------------------------------------------------------------- |
| 21      | TCP/UDP   | FTP                    | Transferencia de ficheros y control; a veces coexiste con 20 para datos[^5]. |
| 22      | TCP/UDP   | SSH                    | Acceso remoto seguro y túneles; base de SCP/SFTP[^5].                       |
| 23      | TCP       | Telnet                 | Acceso remoto sin cifrar; legado[^5].                                        |
| 25      | TCP       | SMTP                   | Envío de correo entre servidores[^5].                                       |
| 53      | TCP/UDP   | DNS                    | Resolución de nombres; TCP para transferencias/paquetes grandes[^5].        |
| 67/68   | UDP       | DHCP                   | Asignación dinámica de IP (servidor/cliente)[^5].                          |
| 69      | UDP       | TFTP                   | Transferencia trivial de ficheros[^5].                                       |
| 80      | TCP       | HTTP                   | Tráfico web clásico; HTTP/3 usa QUIC (sobre UDP)[^5].                      |
| 110     | TCP       | POP3                   | Recepción de correo (legacy)[^4].                                           |
| 143     | TCP/UDP   | IMAP                   | Acceso a buzones en servidor[^5].                                            |
| 389     | TCP/UDP   | LDAP                   | Directorio ligero[^5].                                                       |
| 443     | TCP       | HTTPS                  | Web cifrada; HTTP/3 sobre QUIC/UDP cuando aplica[^5].                        |
| 445     | TCP       | SMB                    | Compartición de ficheros/AD en Windows[^4].                                 |
| 993/995 | TCP       | IMAPS/POP3S            | IMAP/POP3 sobre TLS[^4].                                                     |
| 3306    | TCP       | MySQL                  | Servicio de base de datos[^4].                                               |
| 3389    | TCP       | RDP                    | Escritorio remoto de Windows[^4].                                            |
| 5432    | TCP       | PostgreSQL             | Servicio de base de datos[^6].                                               |
| 5900    | TCP       | VNC                    | Escritorio remoto multiplataforma[^6].                                       |
| 8080    | TCP       | HTTP alternativo/Proxy | Servidores apps y proxies web[^4].                                           |

Sugerencia: priorizar primero los puertos bien conocidos (0–1023) y luego expandir por Registered/Dynamic según tecnología detectada en fingerprinting.[^1]

## Estrategia de escaneo moderna[^8]

- Nmap hace por defecto un escaneo de los ~1000 puertos más usados para una primera visión rápida del host, mostrando PORT/STATE/SERVICE en la salida estándar.[^7]
- Optimiza tiempos con plantillas de “timing” y controles de rendimiento (-T0…-T5, --max-retries, --scan-delay), evitando resultados engañosos por firewalls o rate limits cuando el objetivo es sensible.[^8]

Comandos base (usar con cabeza)

```bash
# Top puertos TCP (overview rápido)
nmap -sT --top-ports 20 target

# Escaneo completo TCP + versión + scripts base
nmap -sS -sV -sC -p- -T3 target

# UDP (selectivo por ser más costoso)
nmap -sU --top-ports 20 target

# Descubrimiento ARP en LAN (rápido y fiable en redes locales)
nmap -sn -PR 192.168.1.0/24
```

Nota: en LAN, Nmap usa ARP para descubrimiento por ser más rápido/fiable; forzar IP en lugar de ARP empeora tiempos y fiabilidad en ese contexto.[^9]

NSE y detección

- -sV activa detección de versiones; -sC lanza scripts “safe” por defecto; combinar ambos acelera clasificación sin ser intrusivo en exceso.[^10]
- Si se requiere rendimiento extra, separar discovery (host vivos) y service scan posterior reduce ruido y tiempo total en redes grandes.[^8]

## Escaneo masivo y verificación[^12]

- masscan envía SYN a gran escala y detecta puertos abiertos por respuestas SYN‑ACK, siendo idóneo para barridos enormes con control de tasa (--max-rate) y salida interoperable con Nmap para enumeración profunda posterior.[^11]
- Ejemplo: escanear puertos 22,80,445 en una subred con masscan, luego pasar IPs abiertas a Nmap para fingerprinting detallado.[^14]

Ejemplo combinado

```bash
# Descubrir rápido con masscan
masscan -p22,80,445 192.168.1.0/24 --max-rate 5000 -oL masscan.out

# Extraer IPs y profundizar con Nmap
grep open masscan.out | awk '{print $4}' | sort -u > alive.txt
nmap -sS -sV -sC -p22,80,445 -iL alive.txt -T3
```

## Consejos operativos y rangos[^1]

- Mapear primero Well‑Known (0–1023), luego ampliar a Registered (1024–49151) según tecnología observada y contexto del objetivo, controlando tiempos con plantillas de -T y límites de reintentos.[^1]
- Evitar “todo a la vez” en UDP: seleccionar puertos probables (DNS 53, NTP 123, SNMP 161, TFTP 69) y validar con consultas específicas del protocolo para reducir falsos positivos de “open|filtered” [^5].

## Recordatorios de calidad[^8]

- Firewalls/IDS pueden alterar estados reportados; validar hallazgos críticos con técnicas alternativas (conectar al servicio, banner grab, curl/nc) antes de concluir.[^7]
- Documentar puertos, protocolos, versiones y banners con timestamps y comandos exactos para reproducibilidad y posterior explotación controlada cuando aplique.[^8]

Si quieres, añado una tabla extendida de puertos por vertical (web, correo, Windows/AD, bases de datos, VoIP, IoT) y plantillas Nmap/NSE por familia de servicios.[^4]
<span style="display:none">[^18][^21]</span>

<div style="text-align: center">Puertos y servicios comunes</div>

[^1]: https://arubanetworking.hpe.com/techdocs/AOS-S/16.10/ATMG/KB/content/kb/tcp-por-num-ran.htm
    
[^2]: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    
[^3]: https://www.iana.org/assignments/service-names-port-numbers
    
[^4]: https://blog.netwrix.com/common-ports
    
[^5]: https://www.stationx.net/common-ports-cheat-sheet/
    
[^6]: https://scadahacker.com/library/Documents/Cheat_Sheets/Networking%20-%20Common%20TCP-UDP%20Ports.pdf
    
[^7]: https://www.ceos3c.com/security/nmap-tutorial-series-1-nmap-basics/
    
[^8]: https://nmap.org/book/performance.html
    
[^9]: https://linuxhint.com/nping_nmap_arp_scan/
    
[^10]: https://www.wiz.io/academy/nmap-overview
    
[^11]: https://awjunaid.com/kali-linux/masscan-mass-ip-scanner-with-fast-scanning-speed/
    
[^12]: https://github.com/robertdavidgraham/masscan
    
[^13]: https://www.techtarget.com/searchsecurity/tutorial/How-to-use-Masscan-for-high-speed-port-scanning
    
[^14]: https://www.kali.org/tools/masscan/
    
[^15]: 01c-puertos-y-servicios-comunes.md
    
[^16]: https://gist.github.com/cihanmehmet/2e383215ea83e08d01478446feac36d8
    
[^17]: https://www.examcollection.com/certification-training/network-plus-overview-of-common-tcp-and-udp-default-ports.html
    
[^18]: https://www.cbtnuggets.com/common-ports
    
[^19]: https://scanitex.com/blog/en/masscan-the-worlds-fastest-port-scanner-how-to-use-and-configure-it/
    
[^20]: https://www.webasha.com/blog/most-commonly-used-tcp-and-udp-ports-list-with-services-for-ethical-hacking-networking-and-cybersecurity
    
[^21]: https://linuxhint.com/nmap_idle_scan_tutorial/
