# Cheatsheet: Nmap (Network Mapper)

## Introducción

**Nmap** (Network Mapper) es la herramienta de escaneo de redes más potente y versátil disponible en ciberseguridad. Con más de 25 años de desarrollo continuo, Nmap ha evolucionado desde un simple escáner de puertos hasta una suite completa de descubrimiento de redes, detección de servicios, escaneo de vulnerabilidades y evasión de sistemas de seguridad.[^2][^3]

La versión más reciente, **Nmap 7.96**, lanzada en mayo de 2025, introduce mejoras revolucionarias en velocidad con resolución DNS paralela, actualizaciones de bibliotecas core, y 612 scripts NSE para automatización avanzada.[^3][^1]

## Instalación y Configuración Básica

### Instalación en Diferentes Sistemas

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap

# Red Hat/CentOS/Fedora
sudo yum install nmap  # CentOS 7/RHEL 7
sudo dnf install nmap  # Fedora/CentOS 8+

# Arch Linux
sudo pacman -S nmap

# macOS con Homebrew
brew install nmap

# Verificar instalación y versión
nmap --version
```

### Configuración de Rendimiento Inicial

```bash
# Verificar capacidades del sistema
ulimit -n  # Verificar límite de descriptores de archivo

# Aumentar límites para scans grandes (temporal)
ulimit -n 65536

# Configuración permanente en /etc/security/limits.conf
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

## Fundamentos de Escaneo

### Escaneo Básico de Hosts

```bash
# Escaneo básico - top 1000 puertos
nmap victima.com

# Escaneo de host único con detección de OS y servicios
nmap -A victima.com

# Escaneo de múltiples hosts
nmap victima.com atacante.com
nmap 192.168.1.1-10
nmap 192.168.1.0/24

# Escaneo desde archivo de hosts
nmap -iL hosts.txt

# Ping scan - solo verificar hosts activos
nmap -sn 192.168.1.0/24

# Escaneo sin ping (útil si ICMP está bloqueado)
nmap -Pn victima.com
```

### Especificación de Puertos

```bash
# Puerto específico
nmap -p 80 victima.com

# Múltiples puertos
nmap -p 22,80,443,8080 victima.com

# Rangos de puertos
nmap -p 1-1000 victima.com
nmap -p- victima.com  # Todos los puertos (1-65535)

# Puertos por protocolo
nmap -p T:80,443,U:53,161 victima.com  # T=TCP, U=UDP

# Top puertos más comunes
nmap --top-ports 100 victima.com
nmap --top-ports 1000 victima.com
```

## Tipos de Escaneo Avanzado

### Técnicas de Escaneo TCP

```bash
# SYN Scan (stealth) - por defecto para root
nmap -sS victima.com

# TCP Connect scan - para usuarios no privilegiados
nmap -sT victima.com

# TCP ACK scan - detección de firewall
nmap -sA victima.com

# TCP Window scan - más sigiloso que ACK
nmap -sW victima.com

# TCP FIN scan - evasión de firewall
nmap -sF victima.com

# TCP NULL scan - sin flags TCP
nmap -sN victima.com

# TCP Xmas scan - flags FIN, PSH, URG
nmap -sX victima.com
```

### Técnicas de Escaneo UDP

```bash
# UDP scan básico (lento pero esencial)
nmap -sU victima.com

# UDP scan optimizado - puertos más comunes
nmap -sU --top-ports 100 victima.com

# Combinado TCP SYN + UDP
nmap -sS -sU -p T:80,443,U:53,161 victima.com

# UDP scan con detección de versión
nmap -sU -sV --version-intensity 0 victima.com
```

### Técnicas de Escaneo Sigiloso

```bash
# Idle scan usando zombie host
nmap -sI zombie.atacante.com:80 victima.com

# FTP Bounce scan (obsoleto pero útil en sistemas legacy)
nmap -b ftp.atacante.com victima.com

# Scan con source port específico
nmap --source-port 53 victima.com
nmap -g 20 victima.com  # Simular FTP data connection
```

## Sistema de Timing y Templates

### Templates de Timing (-T0 a -T5)

```bash
# T0: Paranoid - 1 paquete cada 5 minutos (evasión extrema)
nmap -T0 victima.com

# T1: Sneaky - 1 paquete cada 15 segundos (evasión de IDS)
nmap -T1 victima.com

# T2: Polite - Escaneo cortés, menos agresivo
nmap -T2 victima.com

# T3: Normal - Por defecto, balance entre velocidad y sigilosidad
nmap -T3 victima.com

# T4: Aggressive - Recomendado para redes modernas
nmap -T4 victima.com

# T5: Insane - Máxima velocidad, puede perder precisión
nmap -T5 victima.com
```

**Recomendación**: Usar `-T4` como estándar para redes modernas, `-T1` o `-T2` para evasión de IDS, y `-T5` solo para redes locales de alta velocidad.[^5][^7]

### Control de Timing Granular

```bash
# Control de timeouts
nmap --min-rtt-timeout 100ms --max-rtt-timeout 2s victima.com

# Control de reintentos
nmap --max-retries 3 victima.com

# Control de velocidad de escaneo
nmap --min-rate 100 --max-rate 1000 victima.com

# Paralelismo de hosts
nmap --min-hostgroup 50 --max-hostgroup 100 192.168.1.0/24

# Timeout total por host
nmap --host-timeout 5m victima.com

# Delays entre paquetes
nmap --scan-delay 1s --max-scan-delay 10s victima.com
```

## Nmap Scripting Engine (NSE)

### Categorías de Scripts NSE

El NSE cuenta con **612 scripts** organizados en 14 categorías principales:[^9][^2]

```bash
# Scripts por defecto (safe, útiles, rápidos)
nmap -sC victima.com
nmap --script default victima.com

# Scripts de autenticación
nmap --script auth victima.com

# Scripts de descubrimiento de broadcast
nmap --script broadcast 192.168.1.0/24

# Scripts de fuerza bruta
nmap --script brute victima.com

# Scripts de descubrimiento
nmap --script discovery victima.com

# Scripts de detección de DoS
nmap --script dos victima.com

# Scripts de explotación (usar con cuidado)
nmap --script exploit victima.com

# Scripts de detección de malware
nmap --script malware victima.com

# Scripts de vulnerabilidades (más importantes)
nmap --script vuln victima.com

# Scripts seguros para uso en producción
nmap --script safe victima.com
```

### Scripts de Vulnerabilidades Específicas

```bash
# Escaneo completo de vulnerabilidades
nmap -sV --script vuln victima.com

# Vulnerabilidades específicas por servicio
nmap --script smb-vuln* victima.com        # SMB vulnerabilities
nmap --script ssl-* victima.com            # SSL/TLS vulnerabilities
nmap --script http-vuln* victima.com       # HTTP vulnerabilities

# Scripts de vulnerabilidades críticas
nmap --script "vuln and safe" victima.com

# Vulners database integration
nmap -sV --script vulners victima.com

# Vulscan integration (requiere instalación adicional)
nmap -sV --script vulscan victima.com
```

### Scripts Especializados Nuevos en 7.96

```bash
# Detección de versión MikroTik RouterOS
nmap --script mikrotik-routeros-version victima.com

# Brute force para MikroTik (CVE-2024-54772)
nmap --script mikrotik-routeros-username-brute victima.com

# Generación de objetivos IPv6 desde MAC
nmap --script targets-ipv6-eui64 --script-args targets-ipv6-eui64.interface=eth0
```

### Scripts Personalizados y Gestión

```bash
# Actualizar base de datos de scripts
nmap --script-updatedb

# Buscar scripts por funcionalidad
ls /usr/share/nmap/scripts/ | grep -i ftp
nmap --script-help ftp-*

# Ejecutar múltiples scripts
nmap --script "http-* and not brute" victima.com

# Scripts con argumentos específicos
nmap --script http-enum --script-args http-enum.basepath=/admin/ victima.com

# Timeout para scripts lentos
nmap --script vuln --script-timeout 5m victima.com
```

## Detección de Servicios y Versiones

### Detección Básica de Servicios

```bash
# Detección de versión básica
nmap -sV victima.com

# Intensidad de detección (0-9, donde 9 es máximo)
nmap -sV --version-intensity 9 victima.com
nmap -sV --version-intensity 0 victima.com  # Solo probes ligeros

# Detección de versión con scripts seguros
nmap -sV -sC victima.com

# Detección aggressive completa
nmap -A victima.com  # Equivale a -sV -sC -O --traceroute
```

### Técnicas Avanzadas de Fingerprinting

```bash
# Detección de OS con confianza
nmap -O victima.com
nmap -O --osscan-guess victima.com  # Intentar guess cuando no hay certeza

# Detección de OS agresiva
nmap -O --osscan-limit victima.com  # Solo si encuentra al menos 1 puerto abierto

# IPv6 OS detection (nueva característica)
nmap -6 -O victima.com

# Detección de firewall/NAT
nmap -sA -T4 victima.com

# Traceroute integrado
nmap --traceroute victima.com
```

## Evasión de Firewalls e IDS

### Técnicas de Fragmentación

```bash
# Fragmentación de paquetes IP
nmap -f victima.com              # Fragmentos de 8 bytes
nmap -ff victima.com             # Fragmentos de 16 bytes
nmap --mtu 24 victima.com        # MTU personalizado (múltiplo de 8)

# Fragmentación con otros scans
nmap -f -sS -T1 victima.com
```

### Técnicas de Decoy y Spoofing

```bash
# Decoy scan - ocultar IP real entre señuelos
nmap -D 192.168.1.100,192.168.1.101,ME,192.168.1.102 victima.com

# Decoys aleatorios
nmap -D RND:10 victima.com       # 10 decoys aleatorios

# Spoofing de IP source
nmap -S 192.168.1.50 victima.com

# Spoofing de MAC address
nmap --spoof-mac 00:11:22:33:44:55 victima.com
nmap --spoof-mac Dell victima.com  # MAC de fabricante específico
nmap --spoof-mac 0 victima.com     # MAC aleatoria

# Combinación de técnicas de evasión
nmap -f -T2 -D RND:5 --randomize-hosts --spoof-mac 0 victima.com
```

### Evasión de Rate Limiting y DPI

```bash
# Source port spoofing (común en DNS=53, FTP=20)
nmap --source-port 53 victima.com

# Datos aleatorios en paquetes
nmap --data-length 25 victima.com

# Banderas TCP personalizadas
nmap --scanflags SYNFIN victima.com

# Bypass de RST rate limiting
nmap --defeat-rst-ratelimit victima.com

# Uso de proxies
nmap --proxies http://proxy.atacante.com:8080 victima.com
nmap --proxies socks4://proxy.atacante.com:1080 victima.com
```

### Evasión Específica por Firewall

```bash
# Bypass común para firewalls stateless
nmap -sA -p 80 victima.com       # ACK scan para detectar filtrado

# FIN scan para bypass de conexiones establecidas
nmap -sF -p 80 victima.com

# Window scan más sigiloso
nmap -sW victima.com

# Combinación para máxima evasión
nmap -T1 -f --source-port 53 --data-length 10 -D RND:3 -sF victima.com
```

## Optimización de Rendimiento

### Configuración para Redes Grandes

```bash
# Escaneo optimizado para redes grandes
nmap -T4 --min-rate 1000 --max-retries 2 192.168.0.0/16

# Configuración para máximo rendimiento
nmap -T5 --min-rate 5000 --max-rate 10000 --max-retries 1 \
     --min-hostgroup 256 --max-hostgroup 512 192.168.1.0/24

# Escaneo paralelo con GNU parallel
echo "192.168.1.{1..254}" | tr ' ' '\n' | \
parallel -j 50 nmap -T4 --max-retries 2 {}

# Control de memoria y CPU
nmap --max-os-tries 1 --max-rtt-timeout 500ms victima.com
```

### Técnicas de Optimización Específicas

```bash
# DNS resolution paralela (nueva en 7.96)
nmap --dns-servers 8.8.8.8,1.1.1.1 victima.com

# Desactivar DNS reverso para velocidad
nmap -n victima.com

# Solo ping scan para discovery rápido
nmap -sn --min-rate 1000 192.168.1.0/24

# Escaneo de puertos más probables primero
nmap --top-ports 1000 --open victima.com

# Configuración balanceada velocidad/precisión
nmap -T4 --min-rate 100 --max-rate 1000 --max-retries 3 \
     --min-rtt-timeout 100ms --max-rtt-timeout 2s victima.com
```

## Casos de Uso Especializados

### Auditoría de Infraestructura

```bash
# Descubrimiento completo de red corporativa
nmap -sn --send-ip 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12

# Inventario de servicios críticos
nmap -p 22,23,53,80,135,139,443,445,993,995,3389,5432,3306 \
     -sV --script banner 192.168.1.0/24

# Detección de servicios inseguros
nmap --script "banner and not brute" -p 21,23,25,53,69,161 192.168.1.0/24

# Auditoria de certificados SSL
nmap --script ssl-cert,ssl-enum-ciphers -p 443,993,995 victima.com
```

### Pentesting y Red Team

```bash
# Reconnaissance sigiloso inicial
nmap -sS -T2 --randomize-hosts -D RND:5 -p 80,443 192.168.1.0/24

# Enumeración de servicios Windows
nmap -p 135,139,445 --script smb-protocols,smb-security-mode,smb-enum-sessions victima.com

# Detección de vulnerabilidades críticas
nmap --script "vuln and not dos" -sV victima.com

# Bypass de NAC/802.1X
nmap --spoof-mac cisco --data-length 1500 victima.com

# Pivoting através de proxies
nmap --proxies socks4://compromised.atacante.com:1080 internal.victima.com
```

### Blue Team y Monitoreo

```bash
# Simulación de ataques para detección
nmap -T5 -A -v victima.com       # Escaneo ruidoso para alertas

# Verificación de reglas de firewall
nmap -sA -p 1-65535 victima.com

# Monitoreo de servicios expuestos
nmap -sV --version-all -T3 --script discovery external.victima.com

# Detección de honeypots
nmap --script unusual-port victima.com
```

## Salida y Reportes

### Formatos de Salida

```bash
# Salida normal (por defecto)
nmap victima.com

# Salida verbose para debugging
nmap -v victima.com               # Verbose nivel 1
nmap -vv victima.com              # Verbose nivel 2

# Salida en XML (parseable)
nmap -oX scan_results.xml victima.com

# Salida grepable
nmap -oG scan_results.gnmap victima.com

# Salida normal a archivo
nmap -oN scan_results.nmap victima.com

# Todos los formatos simultáneamente
nmap -oA scan_results victima.com  # Crea .xml, .gnmap, .nmap

# Solo mostrar puertos abiertos
nmap --open victima.com
```

### Post-procesamiento de Resultados

```bash
# Extraer solo hosts con puertos abiertos de XML
nmap --stylesheet https://nmap.org/svn/docs/nmap.xsl -oX - victima.com

# Convertir XML a HTML
xsltproc -o report.html /usr/share/nmap/nmap.xsl scan_results.xml

# Extraer IPs activas de grepable output
grep "Up" scan_results.gnmap | cut -d ' ' -f 2 > active_hosts.txt

# Estadísticas rápidas
nmap --stats-every 30s victima.com  # Stats cada 30 segundos

# Resume de escaneo interrumpido
nmap --resume scan_results.gnmap
```

## Integración con Otras Herramientas

### Pipelines de Automatización

```bash
# Integración con masscan para pre-filtering
masscan -p1-65535 192.168.1.0/24 --rate=1000 | \
grep "Discovered" | awk '{print $4}' | cut -d'/' -f1 | sort -u | \
xargs -I {} nmap -sV -A {}

# Integración con nuclei para vulnerabilidades
nmap -sV --script http-enum victima.com -oX nmap_results.xml
nuclei -t exposures/ -target victima.com

# Export a Metasploit
nmap -oX msf_import.xml -sV victima.com
# En msfconsole: db_import msf_import.xml
```

### Scripts de Automatización

```bash
#!/bin/bash
# Script de escaneo automático con escalación
TARGET=$1

echo "[+] Iniciando discovery de hosts..."
nmap -sn $TARGET | grep "Nmap scan report" | cut -d' ' -f5 > live_hosts.txt

echo "[+] Escaneo de puertos comunes..."
nmap -iL live_hosts.txt -T4 --top-ports 1000 --open -oA quick_scan

echo "[+] Escaneo detallado de hosts interesantes..."
grep -l "open" quick_scan.gnmap | cut -d' ' -f2 | \
xargs -I {} nmap -sV -sC -A {} -oA detailed_{}

echo "[+] Escaneo de vulnerabilidades..."
nmap -iL live_hosts.txt --script vuln -oA vuln_scan

echo "[+] Generando reporte final..."
xsltproc -o final_report.html /usr/share/nmap/nmap.xsl vuln_scan.xml
```

## Mejores Prácticas y Consideraciones Legales

### Metodología de Escaneo Profesional

1. **Preparación**: Obtener autorización explícita por escrito antes de cualquier escaneo.[^11]
2. **Reconnaissance Pasivo**: Comenzar con técnicas pasivas (DNS lookup, WHOIS) antes del escaneo activo.
3. **Escaneo Progresivo**:
   - Host discovery (`-sn`)
   - Port scanning básico (`--top-ports`)
   - Service detection (`-sV`)
   - Vulnerability scanning (`--script vuln`)
4. **Documentación**: Mantener logs detallados de todos los escaneos realizados.

### Configuración de Seguridad

```bash
# Crear usuario específico para escaneos
sudo useradd -m -s /bin/bash nmap-scanner
sudo usermod -aG nmap-scanner $USER

# Limitar capacidades de red (ejemplo con iptables)
sudo iptables -A OUTPUT -m owner --uid-owner nmap-scanner -j ACCEPT
sudo iptables -A OUTPUT -j DROP

# Configurar logging de actividades
nmap --log-errors error.log --verbose victima.com
```

### Límites y Consideraciones Éticas

```bash
# Rate limiting responsable
nmap -T3 --max-rate 100 victima.com  # Máximo 100 pps

# Timeouts conservadores
nmap --host-timeout 5m victima.com

# Evitar scripts intrusivos en producción
nmap --script "safe and not intrusive" victima.com

# Notificación previa (donde sea apropiado)
echo "Iniciando escaneo autorizado en $(date)" | logger
```

## Troubleshooting y Limitaciones

### Problemas Comunes y Soluciones

```bash
# Error de permisos (raw sockets)
sudo nmap -sS victima.com
# O cambiar a TCP connect scan
nmap -sT victima.com

# Problemas de DNS
nmap -n victima.com               # Desactivar DNS
nmap --dns-servers 8.8.8.8 victima.com  # DNS específico

# Timeouts en redes lentas
nmap --max-rtt-timeout 2s --max-retries 3 victima.com

# Problemas de fragmentación
nmap --mtu 1500 victima.com       # MTU estándar
nmap --send-eth victima.com       # Envío a nivel Ethernet

# Debugging de conectividad
nmap --packet-trace victima.com   # Ver todos los paquetes
nmap --reason victima.com         # Mostrar razón del estado del puerto
```

### Optimización para Diferentes Escenarios

```bash
# Red local de alta velocidad
nmap -T5 --min-rate 10000 192.168.1.0/24

# Conexión limitada por ancho de banda
nmap -T2 --max-rate 50 victima.com

# Target detrás de CDN/Load Balancer
nmap --source-port 80 --data-length 1400 victima.com

# IPv6 networks
nmap -6 2001:db8::/32
```

## Recursos Adicionales y Extensiones

### Herramientas Complementarias

```bash
# Zenmap - GUI gráfica (ahora con dark mode en 7.96)
zenmap

# Ncat - Swiss Army knife de networking
ncat -l -p 4444                  # Listener
ncat victima.com 80              # Cliente

# Ndiff - Comparación de escaneos
ndiff scan1.xml scan2.xml

# Nping - Packet generation y análisis
nping --tcp -p 80,443 victima.com
```

### Bases de Datos y Referencias

- **Nmap Scripting Engine**: `/usr/share/nmap/scripts/` - 612 scripts disponibles[^2]
- **Service Fingerprints**: `nmap-service-probes` - 12,089 signatures[^12]
- **OS Fingerprints**: `nmap-os-db` - 6,036 signatures[^12]
- **Documentación oficial**: https://nmap.org/book/
- **NSE Documentation**: https://nmap.org/nsedoc/

Este cheatsheet incorpora las características más recientes de Nmap 7.96, técnicas avanzadas de evasión, optimizaciones de rendimiento, y mejores prácticas profesionales desarrolladas por la comunidad de ciberseguridad. Nmap continúa siendo la herramienta estándar para reconocimiento de redes y auditorías de seguridad, con mejoras constantes en velocidad, precisión y capacidades de automatización.[^14][^16][^11][^19][^10][^2]
<span style="display:none">[^21][^23][^25][^27][^29][^31][^33][^35][^37]</span>

<div style="text-align: center">⁂</div>

[^1]: https://cybersecuritynews.com/nmap-7-96-released/
    
[^2]: https://gbhackers.com/nmap-7-96-launches/
    
[^3]: https://www.linkedin.com/pulse/nmap-796-launches-enhanced-scanning-features-upgraded-5izre
    
[^4]: https://www.linkedin.com/pulse/understanding-nmap-timing-templates-rikunj-sindhwad-0x7vf
    
[^5]: https://www.cyberxchange.in/post/explain-all-nmap-timing-templates-like-t1-t2-etc
    
[^6]: https://www.educative.io/answers/what-are-nmap-timing-templates
    
[^7]: https://nmap.org/book/performance-timing-templates.html
    
[^8]: https://www.stationx.net/nmap-scripting-engine/
    
[^9]: https://hackwithhusnain.com/how-to-use-nmap-for-vulnerability-scanning/
    
[^10]: https://levelblue.com/blogs/security-essentials/advanced-nmap-scanning-techniques
    
[^11]: https://www.hackthebox.com/blog/nmap-commands
    
[^12]: https://nmap.org/changelog.html
    
[^13]: https://www.recordedfuture.com/threat-intelligence-101/tools-and-techniques/nmap-commands
    
[^14]: https://www.infosecinstitute.com/resources/hacking/nmap-evade-firewall-scripting/
    
[^15]: https://blog.readyforquantum.com/posts/nmapperformancetuningoptimizingscansforlargenetworks
    
[^16]: https://linuxsecurity.com/features/nmap-firewall-evasion-techniques
    
[^17]: https://nmap.org/book/performance.html
    
[^18]: https://dev.to/baptistsec/improve-nmap-performance-with-these-brilliant-scripts-2kc0
    
[^19]: https://www.geeksforgeeks.org/ethical-hacking/types-of-evasion-technique-for-ids/
    
[^20]: https://simplificandoredes.com/en/nmap-advanced-scan/
    
[^21]: https://www.redhat.com/en/blog/nmap-scripting-engine
    
[^22]: https://cybervie.com/nmap-and-useful-nse-scripts/
    
[^23]: https://nmap.org/book/man-port-scanning-techniques.html
    
[^24]: https://www.reddit.com/r/hacking/comments/185q2ic/best_way_to_use_nmap_scripts/
    
[^25]: https://www.youtube.com/watch?v=WAxEciITLF0
    
[^26]: https://nmap.org/book/vscan-technique.html
    
[^27]: https://www.hackingarticles.in/understanding-nmap-scan-wireshark/
    
[^28]: https://www.digitalregenesys.com/blog/what-is-steganography
    
[^29]: https://nmap.org/book/man-performance.html
    
[^30]: https://insanecyber.com/threat-hunting-techniques-for-apt34-and-apt39-identifying-network-scanning-behavior/
    
[^31]: https://www.stationx.net/nmap-vulnerability-scan/
    
[^32]: https://labex.io/tutorials/nmap-evade-firewalls-and-ids-with-nmap-530178
    
[^33]: https://www.blackhillsinfosec.com/vulnerability-scanning-with-nmap/
    
[^34]: https://nmap.org/book/man-bypass-firewalls-ids.html
    
[^35]: https://routezero.security/2024/12/07/nmap-exploring-nse-scripts-for-pentesters/
    
[^36]: https://nmap.org/book/subvert-ids.html
    
[^37]: https://netlas.io/blog/cves_with_nmap/
