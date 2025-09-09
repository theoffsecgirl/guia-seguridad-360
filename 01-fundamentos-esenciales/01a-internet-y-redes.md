# Internet y redes (pentesting)

## Internet vs Web

- Internet: red de redes basada en TCP/IP que transporta tráfico de múltiples servicios (DNS, correo, SSH, VoIP, P2P, etc.).
- Web (WWW): solo uno de esos servicios, accesible vía HTTP/HTTPS con URLs, navegadores y servidores; no es sinónimo de Internet.

Puntos ofensivos

- Muchas superficies críticas no son “web” (DNS, correo, VPN, buckets, Git/SSH). Mapear servicios por puerto/protocolo, no solo vhosts.

## Qué es una red

- Conjunto de dispositivos que comparten un medio (cable, Wi‑Fi) y protocolos para intercambiar datos.

Tipos y relevancia


| Tipo    | Descripción                        | Relevancia en auditorías                        |
| :------ | :---------------------------------- | :----------------------------------------------- |
| PAN     | Personal (dispositivos cercanos)    | Exfil local, tethering, Bluetooth/Hotspot.       |
| LAN     | Local (casa/oficina)                | Pivot tras acceso inicial, descubrimiento L2/L3. |
| WLAN    | LAN inalámbrica (Wi‑Fi)           | WPA/WPA2/WPA3, Evil Twin, portales cautivos.     |
| VLAN    | LAN lógica segmentada              | Saltos entre segmentos, mal etiquetado/trunking. |
| MAN/WAN | Redes de área metropolitana/amplia | Exposición, latencias, SD‑WAN, rutas a cloud.  |
| VPN     | Túneles cifrados                   | Split‑tunnel, fuga de rutas/DNS.                |

Conceptos críticos

- Segmentación: VLAN/ACL/Firewall/DMZ para limitar movimiento lateral.
- NAT/PAT/CGNAT: traducción de direcciones (impacta en rastreo y atribución).
- SD‑WAN: políticas dinámicas; ojo a orquestadores expuestos.

## Topologías y componentes

- Topologías: estrella (habitual), malla (alta disponibilidad), árbol (jerárquica).
- Componentes: switch (L2), switch L3, router/gateway, AP, firewall, IDS/IPS, proxy.
- DMZ: zona expuesta (web, SMTP, VPN); objetivo común para pivot al interior.

Ofensiva (rápido)

```bash
# Descubrimiento L2 (ARP) en segmento actual
sudo arp-scan -l

# Ping sweep L3 (descubrimiento básico)
nmap -sn 192.168.1.0/24

# Servicios y versiones (cuidado con ruido)
nmap -sS -sV -T3 -Pn -p- 192.168.1.0/24
```

Notas

- ARP solo ve tu broadcast domain (no cruza VLANs).
- Port mirroring/Hub: si existe, MITM es trivial; si no, usar técnicas activas (ARP spoof) solo en laboratorio.

## Direcciones IP

- IPv4: 32 bits (ej. 192.168.1.10).
- IPv6: 128 bits (ej. 2001:db8::1), abundan direcciones link‑local (fe80::/10).

CIDR y rangos útiles


| Tipo        | IPv4                                      | IPv6          | Notas                                  |
| :---------- | :---------------------------------------- | :------------ | :------------------------------------- |
| Privadas    | 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16 | ULA: fd00::/8 | No enrutan en Internet.                |
| Link‑Local | 169.254.0.0/16                            | fe80::/10     | Sin DHCP/ruta, útil en diagnósticos. |
| Loopback    | 127.0.0.0/8                               | ::1           | Pruebas locales.                       |
| Multicast   | 224.0.0.0/4                               | ff00::/8      | Descubrimiento/servicios.              |

Cálculo rápido

- Hosts en /24: $2^{32-24} - 2 = 254$.
- Cambia 24 por la máscara para otras redes.

Inventario local

```bash
ip addr; ip route; ip neigh
nslookup example.com; dig +short A example.com
traceroute 8.8.8.8
```

## Protocolos clave en redes locales

### ARP (Address Resolution Protocol)

- Mapea IP→MAC en L2; imprescindible para comunicación local.

Ataques

- ARP Spoof/Poison: MITM, sniffing, secuestro de sesión.

Mitigación (defensiva)

- DAI (Dynamic ARP Inspection), ARP cache estática en entornos críticos, segmentación.

Herramientas

- bettercap, ettercap, arpspoof, arpwatch.

### DHCP (Dynamic Host Configuration Protocol)

- Asigna IP, gateway, DNS, máscara.

Ataques

- DHCP Spoofing: gateway/DNS malicioso para redirección.
- DHCP Starvation: agotamiento del pool → DoS.

Mitigación

- DHCP Snooping, IP Source Guard, puertos de confianza en switches.

### DNS (Domain Name System)

- Traduce nombres a IP (y más: MX, TXT, SRV).

Ataques

- Cache poisoning, subdominio huérfano, NXDOMAIN hijack, exfil por DNS.

Práctica

```bash
dig A api.objetivo.com
dig ANY objetivo.com @ns-autoritativo
dig -x 192.0.2.123   # PTR
```

### ICMP

- Diagnóstico (echo, time‑exceeded). Filtrado frecuente en perímetros.

Uso ofensivo

- Descubrimiento básico; tunelización en laboratorios.

### HTTP/HTTPS y TLS (apunte)

- La Web viaja sobre TCP (y HTTP/2 multiplexado). CDN/edge afecta cache/headers.
- Señales de parsing (CL/TE, h2) abren puerta a desync/smuggling (tratar en capítulo web).

## Wi‑Fi (WLAN) en dos líneas

- WPA2‑PSK/WPA3, ataques a handshakes/PMKID (laboratorio).
- Rogue AP/Evil Twin y portales cautivos para captura de credenciales (solo en entorno controlado).

## Checklist de reconocimiento de red (rápido)

- Identificar segmento local (ip addr) y gateway/máscara (ip route).
- Enumerar hosts (arp-scan/nmap -sn) y priorizar por TTL/latencia/puertos abiertos.
- Clasificar por sistema/servicio (nmap -sV) con cautela en producción.
- Revisar resolución y dependencias (DNS, mDNS/SSDP/LLDP).
- Registrar todo en notas con timestamps para reproducibilidad.

## Mini‑labs sugeridos (seguro y legal)

- MITM controlado entre dos VMs en una red NAT de VirtualBox usando bettercap; observar ARP y tráfico HTTP de Juice Shop.
- DHCP spoof en laboratorio con dnsmasq y detección con DHCP Snooping simulado.
- Mapear una red /24 de VMs, etiquetar sistemas por fingerprint y preparar un plan de hardening básico (defensiva cruza con ofensiva).

## Snippets útiles

```bash
# Barrido rápido con tamaños de respuesta (detección de "404/200 falsos")
for h in $(cat hosts.txt); do curl -skI https://$h/ | awk 'NR==1{print FILENAME,$0}' FILENAME=$h; done

# Detección de IPv6 locales
ip -6 addr | grep -E 'inet6 (fd|fe80)'

# DNS rápido (A/AAAA) en lote
while read d; do echo -n "$d "; dig +short A $d | head -n1; done < dominios.txt
```

## Errores comunes a evitar

- Confundir “Web” con todo Internet y perder superficies no HTTP.
- Escanear agresivamente producción sin límites de tasa.
- Asumir que ARP‑scan ve toda la organización (no cruza VLANs).
- No registrar rutas ni DNS al inicio (rompe reproducibilidad).

Con esto, la nota queda robusta para una base de “Internet y Redes” adaptada a auditorías ofensivas y preparación de laboratorios sin ruido innecesario.
<span style="display:none">[^3][^7][^9]</span>


[^1]: https://es.wikipedia.org/wiki/World_Wide_Web
    
[^2]: https://developer.mozilla.org/es/docs/Glossary/World_Wide_Web
    
[^3]: https://concepto.de/www/
    
[^4]: https://taniaizquierdo.com/world-wide-web/
    
[^5]: https://www.significados.com/www/
    
[^6]: https://prehost.com/es/web-mundial/
    
[^7]: http://ific.uv.es/wop/SABER_MAS/internet.html
    
[^8]: https://dominiozero.es/blog/que-significa-www/
    
[^9]: https://www.youtube.com/watch?v=cpcI_fqX4zY
    
[^10]: https://niaxus.com/2024/05/20/que-es-world-wide-web/
