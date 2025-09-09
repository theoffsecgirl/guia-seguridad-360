# Puertos alternativos y superficie real

Limitar el reconocimiento a 80/443 es perder gran parte de la **superficie**: los entornos modernos exponen dev servers, paneles y microservicios en puertos no estándar, a menudo con menos endurecimiento y controles débiles. El objetivo aquí es priorizar puertos “jugosos”, qué buscar y cómo confirmarlo con una cadena rápida de herramientas sin salirse del scope.[^1]

## Más allá de 80/443

- 80/443 siguen siendo críticos, pero microservicios, entornos de staging y herramientas de CI/CD suelen vivir en 3000, 4200, 5000, 8000, 8080, 8443, 8888, 9000, 5432, 27017, 6379, entre otros, y suelen presentar menor madurez de seguridad que el reverse proxy público.[^1]
- En producción ideal, un reverse proxy o balanceador debería “tapar” todo salvo 443; en la práctica, una regla de firewall permisiva o un despliegue de dev “temporal” quedan expuestos y suelen convertirse en hallazgos de alto impacto por sí mismos.[^1]

## Tabla ofensiva de puertos alternativos


| Puerto | Servicio/Tecnología típica        | Qué buscar (alto valor)                                                                                                                                                                                  |
| :----- | :---------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3000   | Dev servers Node.js (React/Express) | sourcemaps, endpoints de debug, CORS “*”, credenciales y secretos en JS; enumerar APIs de backend a partir del código cliente[^1].                                                                     |
| 4200   | Dev server Angular                  | rutas y llamadas a API desde frontend, lógica de negocio en cliente y tokens en almacenamiento local[^1].                                                                                                |
| 5000   | Flask/Django dev, Docker internos   | Werkzeug Debug activo con consola remota (PIN reproducible) que deriva en RCE si es accesible o el PIN es recuperable desde ficheros legibles[^5].                                                        |
| 8000   | HTTP alternativo, django runserver  | listados de directorios, servidores simples “http.server”, APIs internas y artefactos de build expuestos[^1].                                                                                           |
| 8080   | HTTP alternativo, proxies y Tomcat  | paneles admin con credenciales por defecto, apps Java con deserialización, proxys mal encadenados[^1].                                                                                                   |
| 8443   | HTTPS alternativo                   | consolas empresariales (p. ej., devops) desactualizadas; validar TLS/ciphers y headers de seguridad[^1].                                                                                                  |
| 8888   | Jupyter Notebook                    | si no exige token/contraseña o está enlazado a 0.0.0.0, ejecución arbitraria de código desde el navegador; por defecto se liga a 127.0.0.1:8888 pero muchos despliegues lo exponen indebidamente[^7]. |
| 9000   | SonarQube/Portainer/devtools        | accesos anónimos o credenciales por defecto, filtrado de código y findings reutilizables para pivotar[^1].                                                                                              |
| 5432   | PostgreSQL                          | servicio expuesto a Internet; probar credenciales por defecto y políticas de bind-address/host all[^3].                                                                                                  |
| 27017  | MongoDB                             | exposición sin auth en versiones antiguas, fuga de colecciones completas[^3].                                                                                                                            |
| 6379   | Redis                               | acceso sin contraseña, escritura de claves que pueden llevar a RCE o manipular sesiones[^3].                                                                                                             |

Nota: el listado general de puertos y asignaciones IANA ayuda a ampliar el barrido según señales de fingerprinting y vertical del objetivo.[^2]

## Metodología de descubrimiento (rápida)

- Paso 1 — Descubrimiento de puertos: un escaneo SYN/CONNECT de alto rendimiento para obtener “qué está abierto” sin aún profundizar en servicios, priorizando top‑ports y un límite de tasa conservador para no romper políticas de los programas.[^1]
- Paso 2 — Enumeración de servicios: para lo abierto, fingerprint y versión con una pasada más lenta y segura, activando scripts “safe” únicamente y capturando títulos HTTP/TLS y banners para priorizar rutas de explotación.[^1]
- Paso 3 — Validación específica: comprobar comportamientos de debug (5000 Flask/Werkzeug), tokens/ACLs en 8888 Jupyter, credenciales por defecto o acceso anónimo en 8080/8443/9000, y exposición indebida en 5432/27017/6379.[^1]

Cadena de comandos

```bash
# 1) Detección explosiva de puertos (naabu): top 1000 + tasa controlada
naabu -list subs.txt -top-ports 1000 -rate 2000 -exclude-cdn -silent -o ports.txt
```

```bash
# 2) Profundizar con Nmap solo en lo abierto (fingerprint + scripts seguros)
cut -d: -f1 ports.txt | sort -u > ips.txt
nmap -sS -sV -sC -p 3000,4200,5000,8000,8080,8443,8888,9000,5432,27017,6379 -iL ips.txt -T3 -oN enum.txt
```

```bash
# 3) Verificación puntual
# Werkzeug debug (5000): buscar cabeceras/HTML característicos y probar consola/PIN si procede
curl -skI http://host:5000/ | cat
# Jupyter (8888): debe exigir token/contraseña y ligarse a 127.0.0.1; si expuesto en 0.0.0.0 sin control => crítico
curl -sk https://host:8888/ | head -n 20
```

Alternativa masiva

```bash
# masscan para barridos grandes y luego nmap para fingerprint
masscan -p3000,4200,5000,8000,8080,8443,8888,9000,5432,27017,6379 198.51.100.0/24 --max-rate 5000 -oL m.out
grep open m.out | awk '{print $4}' | sort -u > alive.txt
nmap -sS -sV -sC -p 3000,4200,5000,8000,8080,8443,8888,9000,5432,27017,6379 -iL alive.txt -T3
```

## Señales de alto impacto

- 5000 Flask con Werkzeug Debug: consola interactiva tras PIN; el PIN puede derivarse si existen lecturas de ficheros y, por tanto, habilita RCE.[^1]
- 8888 Jupyter expuesto: si no exige token o está accesible desde Internet, equivale a ejecución arbitraria de código; por diseño debería ligarse a localhost y requerir autenticación/token.[^1]
- 8080/8443 paneles admin: credenciales por defecto, versiones con CVEs conocidas y TLS/ciphers inseguros; combinar con enumeración de rutas y títulos para priorizar.[^1]
- 5432/27017/6379 abiertos a Internet: casi siempre misconfiguración; probar acceso mínimo, listar bases/keys y recomendar cierre/bind interno.[^1]

## Buenas prácticas y límites

- Respetar siempre el scope del programa antes de escanear y ajustar la tasa; algunos prohíben escaneos agresivos o puertos infra no listados.[^1]
- Registrar comandos, tiempos y resultados; repetir en sesión limpia para reproducibilidad y preparar reporte con impacto claro y mitigación directa (cerrar puerto, restringir bind, exigir auth, mover a 127.0.0.1, proteger con proxy).[^1]

## Referencias útiles

- Lista y rangos de puertos (IANA + listados comunes) para extender wordlists y detecciones.[^8]
- Naabu (ProjectDiscovery): port‑scanner rápido con integración hacia nmap y control de tasa/top‑ports.[^9]
- Riesgos específicos: Werkzeug Debug (RCE) y seguridad de Jupyter (token/localhost) para validar criticidad en 5000/8888.[^6]
  <span style="display:none">[^17][^21][^25][^26]</span>


[^1]: 01d-puertos-alternativos.md
    
[^2]: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    
[^3]: https://www.stationx.net/common-ports-cheat-sheet/
    
[^4]: https://www.exploit-db.com/exploits/43905
    
[^5]: https://book.jorianwoltjer.com/web/frameworks/flask
    
[^6]: https://jupyter-notebook.readthedocs.io/en/5.7.0/security.html
    
[^7]: https://stackoverflow.com/questions/51739199/error-unable-to-open-jupyter-notebook-port-8888-is-already-in-use/51739548
    
[^8]: https://www.iana.org/assignments/service-names-port-numbers
    
[^9]: https://docs.projectdiscovery.io/opensource/naabu/usage
    
[^10]: https://www.ceos3c.com/security/nmap-tutorial-series-1-nmap-basics/
    
[^11]: https://stackoverflow.com/questions/60133457/does-jupyter-notebook-or-lab-risk-exposing-data-via-the-web
    
[^12]: https://docs.projectdiscovery.io/tools/naabu/overview
    
[^13]: https://github.com/projectdiscovery/naabu
    
[^14]: https://github.com/projectdiscovery/naabu-action
    
[^15]: https://systemweakness.com/naabu-port-scanner-f3fd2e6b59b7
    
[^16]: https://osintteam.blog/best-port-scanner-for-bug-bounty-how-to-install-and-use-naabu-efficiently-4bffdab35ed5
    
[^17]: https://github.com/jupyter/notebook/issues/3495
    
[^18]: https://twitter.com/lo_security/status/1033726690034417665
    
[^19]: https://hub.docker.com/r/projectdiscovery/naabu
    
[^20]: https://raw.githubusercontent.com/projectdiscovery/naabu/v2.1.0/README.md
    
[^21]: https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/werkzeug
    
[^22]: https://ctftime.org/writeup/37019
    
[^23]: https://github.com/jupyter/help/issues/138
    
[^24]: https://www.youtube.com/watch?v=MVItEDBBcgg
    
[^25]: https://www.reddit.com/r/Python/comments/15b6j1n/my_firm_is_afraid_of_anacondajupyter_notebook/
    
[^26]: https://github.com/robertdavidgraham/masscan
