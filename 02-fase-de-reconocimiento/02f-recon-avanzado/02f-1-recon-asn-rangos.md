# Recon por ASN y Rangos IP

Bienvenido/a a Recon por ASN y Rangos IP. Aquí se trabaja fuera de DNS: se pivota por Sistemas Autónomos (ASN) y prefijos CIDR para descubrir hosts y servicios expuestos que no están enlazados ni resueltos por nombres, con foco en señal alta y bajo ruido operativo.

## Objetivo

- Identificar los ASN del objetivo, extraer todos sus rangos IPv4/IPv6 y priorizar qué IPs y puertos investigar.
- Correlacionar certificados TLS, servicios y PTR para aflorar hostnames y superficies reales (paneles, APIs, puertos alternativos) sin depender de subdominios iniciales.

## Cuándo usarlo

- Cuando DNS está “quemado” (wildcard, CDN/WAF) o devuelve muy poca señal.
- Cuando hay una IP origen, proveedor o rango “sospechoso” y se necesita expandir por infraestructura de red.

## Flujo recomendado (90 min)

1) Identifica ASN y rangos

- WHOIS de IPs conocidas para extraer organización y ASN.
- Saca prefijos del/los ASN y normaliza a un listado CIDR deduplicado.

2) TTL/Cert/Hostnames pasivos

- Escanea TLS en 443/8443 para extraer CN/SAN y nombres útiles.
- Obtén PTR (reverse DNS) de IPs vivas y cruza con CN/SAN.

3) Probing HTTP a escala

- Testea HTTP/HTTPS en IP:puerto para estado, título y tecnología.
- Prioriza puertos alternativos típicos (3000, 4200, 5000, 8000, 8080, 8443, 8888, 9000).

4) Puertos y servicios

- Descubre puertos abiertos con barrido rápido y tasa controlada.
- Enumera versiones con nmap sobre lo abierto (scripts “safe”).

5) Triage

- Puntúa alto: títulos con “admin”, banners/versiones, certificados por defecto, HTTP en puertos no estándar, RDP/SSH/DB expuestos.
- Cierra ciclo: marca GO/NO‑GO y documenta próximos pasos.

## Comandos (copiar/pegar)

Identificar ASN y rangos

```bash
# WHOIS de IP para ver org/ASN
whois 203.0.113.10

# Listar prefijos de un ASN (ej.: AS13335)
echo AS13335 | asnmap | sort -u > asn_cidrs.txt
```

TLS → hostnames (CN/SAN)

```bash
# Sonda TLS de IPs/puertos para extraer CN/SAN
cat asn_cidrs.txt | naabu -top-ports 100 -rate 1500 -silent -o ip_open.txt
cut -d: -f1 ip_open.txt | sort -u > ips.txt
tlsx -l ips.txt -san -cn -silent -resp-only > certs.txt
```

Reverse DNS (PTR)

```bash
# PTR por lote (guardar “ip ptr”)
for ip in $(cat ips.txt); do echo -n "$ip "; dig -x $ip +short; done | awk 'NF' > ptr.txt
```

HTTP probing y fingerprint

```bash
# Puertos web comunes + alternativos
httpx -l ip_open.txt -silent -status-code -title -tech-detect -json -o httpx.json
```

Puertos y servicios (dos pasos)

```bash
# Descubrimiento rápido con tasa conservadora
naabu -list ips.txt -top-ports 1000 -rate 1500 -silent -o ports.txt

# Enumeración profunda solo sobre lo abierto
cut -d: -f1 ports.txt | sort -u > alive_ips.txt
nmap -sS -sV -sC -p22,80,443,445,3000,5000,8000,8080,8443,8888,9000,5432,27017,6379 \
     -iL alive_ips.txt -T3 -oN services.txt
```

VHosts rápidos (si conoces el FQDN y la IP)

```bash
# Fuerza resolución/Host para probar vhosts en IP concreta
curl --resolve "admin.ejemplo.com:443:203.0.113.10" https://admin.ejemplo.com/ -I
```

## Heurísticas de priorización

- Alto valor:
  - Títulos “admin”, “console”, “dashboard”, “login”
  - Certificados con CN/SAN de entornos dev/qa/staging o SaaS terceros
  - HTTP(s) en 3000/4200/5000/8000/8080/8443/8888/9000
  - Servicios críticos expuestos: RDP (3389), SSH (22), DB (5432/27017/3306), Redis (6379)
- Señales fuertes:
  - PTR que contenga origin/backend/api
  - Certificados por defecto o autofirmados en producción
  - Mismatches entre CN/SAN y Host virtual esperado

## Buenas prácticas (OPSEC)

- Ejecuta barridos desde VPS propio, no desde red corporativa.
- Controla tasa (--rate en descubrimiento; -T3 y reintentos bajos en nmap).
- Mantén un archivo exclude.txt con rangos fuera de scope.
- Registra comandos, timestamps y salidas JSON/CSV para reproducibilidad.

## Definition of Done (DoD)

- Lista de ASN y CIDR deduplicados con fuente.
- Conjunto de IPs vivas con: estado HTTP, título, tecnología y puertos abiertos.
- Candidatos priorizados con evidencia mínima (captura de título/banner/cert) y siguiente acción (validar auth, probar lógica, reportar exposición).

## Checklist rápido

- ¿ASN(s) y rangos completos deduplicados?
- ¿CN/SAN y PTR extraídos y cruzados con IPs vivas?
- ¿HTTP probing y puertos alternativos cubiertos?
- ¿Servicios críticos identificados y priorizados?
- ¿Todo dentro de scope y con límites de tasa documentados?

Si quieres, preparo una versión “sólo comandos” en 02f-1-recon-asn-rangos-playbook.md para pegar y ejecutar por bloques sin explicación.
<span style="display:none">[^7]</span>


[^1]: https://www.creadpag.com/2025/04/explorando-el-asn-recon-profesional.html
    
[^2]: https://pentest-tools.com/blog/modern-network-reconnaissance
    
[^3]: https://infosecwriteups.com/day-17-web-reconnaissance-or-information-gathering-part-2-100daysofhacking-323ecea7f0a3
    
[^4]: https://github.com/topics/ip-range
    
[^5]: https://www.youtube.com/watch?v=6rKHTPp_kgk
    
[^6]: https://systemweakness.com/network-infrastructure-recon-3d5741eec73b
    
[^7]: https://www.youtube.com/watch?v=I5aAi96dnw0
