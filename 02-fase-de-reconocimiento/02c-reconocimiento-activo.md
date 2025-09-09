# Reconocimiento activo: interactuando con el objetivo

El reconocimiento activo interactúa con la infraestructura para obtener señales precisas de servicios, tecnologías y superficies vivas, a cambio de mayor detectabilidad y necesidad estricta de respetar alcance y límites de tasa.[^1]
Antes de ejecutar, revisar políticas del programa; algunos prohíben escaneos agresivos o limitan puertos, rangos y automatización.[^2]

## Subdominios activos

La meta es pasar de “lista teórica” a hosts que resuelven y responden, con resolución, HTTP probing y verificación de vida.[^3]

- Brute‑forcing y permutaciones
  - Herramientas: amass enum (activo), gotator/dnsgen para permutaciones, ffuf para vhost brute con Host header.[^5]
  - Wordlists: listas curadas por tecnología/entorno; mantener tamaño razonable para no disparar ruido.[^4]
- VHost brute con ffuf (ejemplo)

```bash
ffuf -w wordlist.txt -H 'Host: FUZZ.target.com' -u https://target.com -fs 0
```

Este patrón prueba virtual hosts en la misma IP cambiando Host, útil cuando DNS no expone todos los nombres.[^4]

- Resolución y filtro de wildcard
  - dnsx soporta A/AAAA/CNAME/PTR/NS/MX/TXT/SRV/SOA, resolvers TCP/UDP/DoH/DoT y manejo de wildcard para reducir falsos positivos.[^7]

```bash
dnsx -l subs.txt -silent -a -aaaa -cname -retries 2 -o resolved.txt
```

- HTTP probing y fingerprint
  - Con httpx, obtener estado, títulos y tecnologías para priorizar endpoints útiles.[^3]

```bash
httpx -l resolved.txt -silent -status-code -title -tech-detect -json -o httpx.json
```

## Escaneo de puertos y servicios

Objetivo: identificar servicios más allá de web (SSH, DBs, RDP, etc.) con estrategia de dos pasos: descubrimiento rápido y enumeración profunda.[^1]

- Paso 1: descubrimiento rápido (grandes rangos)
  - masscan envía SYN a alta velocidad y detecta puertos abiertos; controlar --rate y limitar puertos para cumplir políticas.[^8]

```bash
masscan -p80,443,8080,22,445 203.0.113.0/24 --max-rate 2000 -oL m.out
```

- Paso 2: enumeración profunda (targets abiertos)
  - Nmap con -sS -sV -sC sobre los puertos hallados para versión y scripts “safe”; ajustar timing (-T3) y reintentos para no disparar IDS.[^1]

```bash
grep open m.out | awk '{print $4}' | sort -u > alive.txt
nmap -sS -sV -sC -p22,80,443,445,8080 -iL alive.txt -T3 -oN enum.txt
```

- UDP selectivo
  - Probar UDP solo en puertos probables (DNS 53, SNMP 161, NTP 123) por coste y falsos positivos; confirmar con consultas específicas de protocolo.[^1]

## Fingerprinting de tecnologías

- Cabeceras y contenido
  - Revisar Server, X‑Powered‑By, Set‑Cookie y rutas o comentarios reveladores; combinar con titles y tech‑detect de httpx.[^3]
- Favicon hashing y patrones
  - El hash del favicon puede correlacionarse con stacks conocidos; usar junto con títulos y headers para priorizar apps y paneles.[^3]
- Herramientas complementarias
  - whatweb/Wappalyzer para identificación por firmas; integrar tras httpx para evitar tocar hosts no vivos.[^3]

## Alternativas y soporte

- dnsx (PD) para resolución masiva con wildcard‑aware y múltiples resolvers, ideal tras permutaciones y antes de httpx.[^6]
- assetfinder para dominios y subdominios relacionados (pasivo+rápido), útil como semilla antes de activo.[^11]

## Pipelines listos

- De subdominios a servicios

```bash
# 1) Semilla pasiva (assetfinder) y dedupe
assetfinder --subs-only ejemplo.com | sort -u > subs.txt
# 2) Resolución activa (dnsx) con gestión de wildcard
dnsx -l subs.txt -silent -a -cname -retries 2 -o hosts.txt
# 3) Probing web (httpx) y tecnologías
httpx -l hosts.txt -silent -status-code -title -tech-detect -json -o httpx.json
# 4) Puertos alternativos con masscan + nmap
masscan -p3000,5000,8000,8080,8443,8888,9000 -iL hosts.txt --max-rate 2000 -oL m2.out
grep open m2.out | awk '{print $4}' | sort -u > ip2.txt
nmap -sS -sV -sC -p3000,5000,8000,8080,8443,8888,9000 -iL ip2.txt -T3 -oN alt.txt
```

- VHost brute en un único host

```bash
ffuf -w vhosts.txt -H 'Host: FUZZ.target.com' -u https://target.com -mc all -fw 0
```

Permite descubrir sitios virtuales no listados en DNS sirviendo desde la misma IP.[^4]

## Buenas prácticas

- Ajustar timing y límites: usar -T3 en nmap, --max-rate en masscan y wordlists razonables en ffuf para no gatillar bloqueos tempranos.[^8]
- Verificar “vida real”: no basta con resolver DNS; validar HTTP, códigos, tamaños y títulos para evitar perder tiempo en hosts señuelo o aparcados.[^3]
- Registrar comandos y timestamps: imprescindible para reproducibilidad y para responder a triage si se requiere detalle de metodología.[^1]

## Recordatorio de alcance

Muchos programas aceptan enumeración y probing ligero, pero restringen barridos de puertos masivos y UDP; leer política y, ante duda, reducir tasa y limitar a hosts confirmados web.[^2]
<span style="display:none">[^13][^15][^17][^19][^21][^23][^25][^26]</span>

<div style="text-align: center">Reconocimiento activo: interactuando con el objetivo</div>

[^1]: https://www.ceos3c.com/security/nmap-tutorial-series-1-nmap-basics/
    
[^2]: https://nmap.org/book/performance.html
    
[^3]: https://docs.projectdiscovery.io/tools/httpx/running
    
[^4]: https://github.com/ffuf/ffuf
    
[^5]: https://github.com/OWASP/Amass/wiki/User-Guide
    
[^6]: https://github.com/projectdiscovery/dnsx
    
[^7]: https://docs.projectdiscovery.io/tools/dnsx
    
[^8]: https://github.com/robertdavidgraham/masscan
    
[^9]: https://docs.projectdiscovery.io/tools/dnsx/running
    
[^10]: https://www.kali.org/tools/assetfinder/
    
[^11]: https://github.com/tomnomnom/assetfinder
    
[^12]: 02c-reconocimiento-activo.md
    
[^13]: https://github.com/OctaYus/Wordlists
    
[^14]: https://www.kali.org/tools/ffuf/
    
[^15]: https://github.com/sw33tLie/uff
    
[^16]: https://gist.github.com/santosadrian/6c8f03f893154ec6575d84fe705c44fe
    
[^17]: https://dev.to/vabro/how-to-install-assetfinder-tool-on-any-linunx-distro-353d
    
[^18]: https://es.linkedin.com/posts/kike-gandia-27576416a_github-ffufffuf-fast-web-fuzzer-written-activity-7180960072192188417-4pnx
    
[^19]: https://book.h4ck.cl/metodologia-y-fases-de-hacking-etico/recopilacion-activa-de-informacion/ffuf
    
[^20]: http://ffuf.me/install
    
[^21]: https://docs.projectdiscovery.io/tools/dnsx/usage
    
[^22]: https://github.com/AdVdTools/AssetFinder
    
[^23]: https://github.com/Invicti-Security/brainstorm
    
[^24]: https://docs.projectdiscovery.io/opensource/dnsx/install
    
[^25]: https://github.com/zyairelai/subsubsui
    
[^26]: https://pkg.go.dev/github.com/projectdiscovery/dnsx/libs/dnsx
