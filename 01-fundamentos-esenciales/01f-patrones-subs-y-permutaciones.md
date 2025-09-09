# Patrones de subdominios y permutaciones

Entender cómo nombran los equipos sus entornos y servicios permite predecir subdominios “ocultos”, priorizar superficies débiles y automatizar permutaciones con alto retorno para bug bounty y pentesting.[^1]

## Convenciones habituales

- Entornos: dev, test, qa, uat, staging, pre, prod, canary, blue, green; variantes con guiones y subniveles (app.dev, app-dev, api.dev.eu) son frecuentes y combinables entre sí.[^1]
- Servicios: app, api, admin, dashboard, portal, auth, sso, billing, files, cdn, static, img, media, ws, mqtt, vpn, mail, mta-sts; añadir “internal”, “edge”, “backend”, “worker” aumenta cobertura realista.[^1]
- Geografía y DC: us, eu, ap, sa; regiones cloud (us-east-1, eu-west-1, centralus, asia-northeast1) y códigos de ciudad/país (mad, par, nyc) ayudan a derivar familias completas (api.eu-west-1.staging).[^1]
- Versionado y despliegue: v1, v2, vNext, 2025-09, build-1234, rc, beta; los equipos combinan versión+entorno (api-v2.staging, v3.api.dev).[^1]
- Multi‑tenant: t123, tenant-foo, customer‑id, partner‑name; buscar patrones “customer.<zona>.<entorno>” y “<tenant>-api.<entorno>”.[^1]

## Señales de naming por proveedor

- SaaS/CDN: alias CNAME a terceros (GitHub Pages, Netlify, Vercel, Heroku, S3/CloudFront, Azure Static Web Apps, Fastly) abren vectores de subdomain takeover si el recurso destino no existe.[^1]
- Cloud: subdominios con CNAME a buckets/objetos (s3-website-<region>, storage.googleapis.com, blob.core.windows.net) o a balanceadores (elb.amazonaws.com) delatan pipelines y activos paralelos.[^1]

## Detección de wildcard y control de ruido

- DNS wildcard rompe el “hit‑rate” de permutaciones; valida con consultas a nombres aleatorios y detecta si todo resuelve igual para filtrar antes de lanzar HTTP probing.[^1]
- Algunos frameworks y resolvers integran detección de wildcard o estrategias para excluir dominios con respuestas comodín en pipelines de permutación/resolución.[^3]

## Permutaciones inteligentes (herramientas)

- dnsgen: genera combinaciones a partir de subdominios existentes y wordlists, con buen rendimiento en Linux/macOS/Kali/Homebrew.[^5]
- gotator: crea wordlists/permutaciones a gran escala, con profundidad, numeración y deduplicación eficiente; ideal para expandir familias a partir de hallazgos iniciales.[^7]
- altdns: altera y muta subdominios conocidos con una lista de palabras (dev, test, staging…), resolviendo en paralelo si se desea.[^9]

## Fuentes pasivas para sembrar patrones

- Subfinder (pasivo) para sacar base de subdominios y alimentar permutadores; admite múltiples fuentes y se integra fácil vía CLI/Docker.[^11]
- Certificate Transparency (crt.sh) para descubrir FQDN emitidos y extraer vocabulario de naming (servicios, entornos, geos) aplicable a permutaciones.[^13]

## Flujo operativo recomendado

1) Sembrado pasivo → Subfinder + CT logs → lista base de subdominios “reales” para extraer patrones de naming.[^12]
2) Generación → dnsgen/gotator/altdns con wordlist corta curada por entorno/servicio/geo/versión; mantener profundidad y numeración moderadas para evitar explosión combinatoria.[^8]
3) Resolución → resolver masivo con resolvers fiables y descarte de wildcard antes de HTTP probing para ahorrar peticiones.[^3]
4) Probing HTTP → httpx para estados, títulos, tecnologías, HTTP/2 y TLS; priorizar dev/admin/APIs y puertos alternativos.[^15]
5) Takeover check → Nuclei con plantillas http/takeovers para SaaS/CDN típicos y añadir plantillas propias si aparece un proveedor nuevo.[^2]

## Pipelines reproducibles

Sembrado y enriquecido

```bash
# Base pasiva + probing ligero
subfinder -d ejemplo.com -silent | tee subs_base.txt | httpx -silent -title -tech-detect -status-code -json -o httpx.json
```

Permutaciones y resolución

```bash
# Expandir con gotator y resolver después (wildcard aware en el paso de resolución según herramienta usada)
gotator -sub subs_base.txt -perm perms.txt -depth 1 -numbers 10 -mindup -adv -md > subs_perm.txt
```

```bash
# Combinar, deduplicar, resolver y pasar a httpx
cat subs_base.txt subs_perm.txt | sort -u > subs_all.txt
# Resolver con tu herramienta preferida y alimentar a httpx
httpx -l subs_all.txt -silent -title -tech-detect -status-code -json -o httpx_all.json
```

Detección de takeover

```bash
# Comprobar plantillas de takeover sobre subdominios válidos
cut -d\" -f4 httpx_all.json | nuclei -t http/takeovers/ -silent
```

## Heurísticas de scoring y priorización

- “dev/test/qa/staging/uat” + “api/admin” + regiones cloud tienen prioridad alta por probabilidad de misconfiguración y datos sensibles.[^1]
- CNAME a terceros con 404/brand‑strings típicas de “no configurado” son candidatos inmediatos a takeover; automatizar con Nuclei o matcher propio.[^2]
- Cambios de TTL, NS inconsistentes o respuestas diferentes por geos sugieren split‑horizon o delegaciones parciales con activos olvidados.[^1]

## Wordlists curadas (punto de partida)

- Entornos: dev, test, qa, uat, staging, pre, prod, canary, blue, green.[^1]
- Servicios: app, api, admin, portal, sso, auth, billing, files, cdn, static, ws, mqtt, worker, scheduler.[^1]
- Geos/Regiones: us, eu, ap, sa; us‑east‑1, eu‑west‑1, centralus, asia‑northeast1.[^1]
- Versiones: v1, v2, v3, vNext, rc, beta, 2025‑09, build‑\#\#\#\#.[^1]

## Consejos anti‑ruido y límites

- Evitar profundidad>2 y numeración alta salvo que el dominio use explícitamente multi‑nivel; el coste crece exponencialmente.[^7]
- Filtrar wildcard antes de pasar a HTTP y cachear resoluciones para no martillar resolvers/objetivos ni romper políticas de los programas.[^3]
- Registrar comandos y tiempos para reproducibilidad; documentar false‑positives típicos (wildcard, parking, “catch‑all CDN”) en notas por dominio.[^14]

## Notas rápidas de herramienta

- subfinder/httpx: instalación y ejecución directa con Go/Docker, buena base para pipelines con flags -silent/-json.[^18]
- dnsgen/gotator/altdns: cubren permutación basada en subdominios existentes + “palabras” comunes, con control de duplicados y resolución integrada opcional.[^4]
- Nuclei (takeovers): carpeta http/takeovers en el repositorio de plantillas de la comunidad; crear matchers nuevos cuando el proveedor no esté cubierto aún.[^16]

¿Quieres que deje también una plantilla “perm‑playbook.md” con bloques de comandos y listas base por vertical (fintech/health/telco) para tenerlo como macro reutilizable?[^19]
<span style="display:none">[^23][^27][^31][^35][^39][^41]</span>


[^1]: 01f-patrones-subs-y-permutaciones.md
    
[^2]: https://www.hackerone.com/blog/guide-subdomain-takeovers-20
    
[^3]: https://github.com/Security-Tools-Alliance/rengine-ng/issues/122
    
[^4]: https://www.kali.org/tools/dnsgen/
    
[^5]: https://formulae.brew.sh/formula/dnsgen
    
[^6]: https://github.com/Josue87/gotator
    
[^7]: https://sidxparab.gitbook.io/subdomain-enumeration-guide/active-enumeration/permutation-alterations
    
[^8]: https://github.com/infosec-au/altdns
    
[^9]: https://www.kali.org/tools/altdns/
    
[^10]: https://docs.projectdiscovery.io/opensource/subfinder/overview
    
[^11]: https://docs.projectdiscovery.io/tools/subfinder/running
    
[^12]: https://crt.sh
    
[^13]: https://www.rediris.es/tcs/ct/
    
[^14]: https://docs.projectdiscovery.io/tools/httpx/running
    
[^15]: https://docs.projectdiscovery.io/tools/httpx
    
[^16]: https://github.com/projectdiscovery/nuclei-templates
    
[^17]: https://docs.projectdiscovery.io/tools/subfinder/install
    
[^18]: https://github.com/projectdiscovery/httpx
    
[^19]: https://projectdiscovery.io/blog/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced
    
[^20]: https://github.com/AlephNullSK/dnsgen
    
[^21]: https://github.com/isc-projects/dnsgen
    
[^22]: https://github.com/topics/dnsgen
    
[^23]: https://gitlab.com/kalilinux/packages/dnsgen
    
[^24]: https://www.youtube.com/watch?v=gHmgk7mwAjk
    
[^25]: https://github.com/Josue87
    
[^26]: https://www.geeksforgeeks.org/linux-unix/altdns-subdomain-discovery-through-alterations-and-permutations/
    
[^27]: https://packages.fedoraproject.org/pkgs/dnsgen/python3-dnsgen
    
[^28]: https://gist.github.com/1b3c657347e72977fbb9
    
[^29]: https://pkg.go.dev/github.com/kylemcc/dns-gen
    
[^30]: https://www.github-zh.com/projects/376033850-gotator
    
[^31]: https://github.com/subfinder/goaltdns
    
[^32]: https://pentestreports.com/command/gotator
    
[^33]: https://github.com/projectdiscovery/subfinder
    
[^34]: https://hackdb.com/item/crtsh
    
[^35]: https://riversecurity.eu/finding-attack-surface-and-fraudulent-domains-via-certificate-transparency-logs/
    
[^36]: https://hacklido.com/blog/205-how-i-found-1000-sub-domain-takeover-vulnerabilities-using-nuclei
    
[^37]: https://highon.coffee/blog/subfinder-cheat-sheet/
    
[^38]: https://github.com/projectdiscovery/nuclei-templates/issues/7415
    
[^39]: https://infosecwriteups.com/how-i-found-130-sub-domain-takeover-vulnerabilities-using-nuclei-39edf89d3c70
    
[^40]: https://cybersectools.com/tools/crt-sh
    
[^41]: https://docs.projectdiscovery.io/quickstart
