# Conceptos clave y anatomía de dominio

El reconocimiento es la fase inicial para identificar activos y ampliar superficie de ataque, combinando técnicas pasivas y activas con registro riguroso de evidencias reproducibles.[^1]
Cuantos más dominios, subdominios, IPs, aplicaciones y APIs se descubran con método, mayores serán las probabilidades de hallazgos de impacto en programas de bug bounty.[^1]

## Pasivo vs activo[^1]

- Recon pasivo: sin tocar la infraestructura objetivo, apoyado en buscadores, registros de certificados y fuentes OSINT, útil para sembrar listas con cero ruido y alta cobertura inicial.[^1]
- Recon activo: interacción directa (p. ej., escaneo de puertos o probing HTTP), aporta precisión de servicios/tecnologías pero requiere control de tasa y cumplimiento estricto de alcance.[^1]

## Anatomía de dominio[^1]

- TLD: dominio de nivel superior como .com/.org (gTLD) o ccTLD como .es/.mx, que define la zona raíz bajo la que se delega el registro del nombre.[^1]
- Dominio raíz/ápex: nombre principal registrado (ej. dominio.com) sobre el que se cuelgan servicios y subdominios.[^1]
- Subdominios: hosts lógicos independientes (ej. api.dominio.com, mail.dominio.com) que suelen separar servicios y entornos, y con frecuencia alojan software menos endurecido.[^1]

## Patrones y permutaciones útiles[^1]

- Entornos típicos: dev, test, qa, uat, staging, pre, prod, canary, combinados con servicio y geografía (ej. api.dev.eu‑west‑1.dominio.com).[^1]
- Heurística: si existen app.dominio.com y api.dominio.com, probar variantes app‑dev, dev.app, api‑test, api.staging para descubrir copias paralelas y pipelines de despliegue.[^1]

## Comandos fundamentales de OSINT técnico[^1]

### WHOIS: titularidad y registrador[^3]

- Qué hace: consulta bases WHOIS (RFC 3912) para obtener registrador, NS, fechas y contactos (a menudo anonimizados por privacidad/GDPR).[^3]
- Uso rápido:

```bash
whois ejemplo.com
whois 8.8.8.8
# Elegir servidor específico (ej. Verisign para .com)
whois -h whois.verisign-grs.com google.com
```

Buenas señales

- Cambios de registrador/NS, expiraciones cercanas, y nombres de servidores de terceros que revelan proveedores de hosting/CDN/SaaS.[^4]

### DNS con dig/nslookup: IPs, autoridad y trazas[^5]

- Qué hace: interroga servidores DNS para registros A/AAAA/MX/NS/SOA/TXT y permite +trace desde raíz a autoritativos para auditar la cadena de resolución.[^5]
- Uso rápido:

```bash
# A/AAAA y MX/NS/SOA/TXT
dig A ejemplo.com +short
dig AAAA ejemplo.com +short
dig MX ejemplo.com +short
dig NS ejemplo.com +short
dig SOA ejemplo.com
dig TXT ejemplo.com +short

# Trazado completo de resolución
dig +trace www.ejemplo.com
```

Señales

- NS inconsistentes, TTLs anómalos, wildcard, o SOA atípico sugieren superficies olvidadas o delegaciones parciales.[^6]

### Certificate Transparency (CT logs) con crt.sh: dominios y subdominios emitidos[^7]

- Qué es: registros públicos y apéndice‑único de certificados con SCTs para monitorizar emisión y descubrir FQDN históricos y actuales.[^7]
- Uso práctico: buscar por dominio/organización para extraer vocabulario de naming y subdominios que nunca aparecerán en buscadores.[^10]

## Flujo mínimo de arranque (reproducible)[^1]

- Paso 1 — WHOIS y CT: extraer registrador, NS y FQDN emitidos para sembrar lista base de dominios/subdominios y detectar proveedores terceros.[^4][^1]
- Paso 2 — DNS: validar A/AAAA/MX/NS/SOA y +trace para confirmar autoridad y coherencia, anotando TTLs y posibles wildcard.[^1]
- Paso 3 — Permutaciones: combinar patrones de entorno/servicio/geo sobre la lista base antes de pasar a resolución masiva y probing HTTP.[^1]

## Checklist rápido de recon[^1]

- ¿Se obtuvo WHOIS con registrador/NS y fechas, y hay terceros evidentes que sugieran superficies adicionales?[^1]
- ¿Se trazó la resolución con dig +trace y se verificó coherencia en NS/SOA/TTL?[^1]
- ¿Se consultó crt.sh/CT logs y se añadieron FQDN útiles a la lista de permutaciones?[^1]

## Notas de calidad[^1]

- Mantener timebox y registrar comandos exactos con timestamps para reproducibilidad, evitando ruido y repeticiones en ciclos posteriores.[^1]
- Respetar alcance y políticas de los programas antes de pasar de pasivo a activo, ajustando carga y tasa en pruebas de red/HTTP.[^1]
  <span style="display:none">[^12][^14][^16][^18][^20][^21]</span>

<div style="text-align: center">Conceptos clave y anatomía de dominio</div>

[^1]: 02a-conceptos-clave.md
    
[^2]: https://www.seoxan.es/articulo/guia-completa-del-comando-whois-en-linux-aprende-a-usarlo
    
[^3]: https://man.archlinux.org/man/whois.1.en
    
[^4]: https://linuxcommandlibrary.com/man/whois
    
[^5]: https://man.openbsd.org/dig.1
    
[^6]: https://phoenixnap.com/kb/linux-dig-command-examples
    
[^7]: https://www.sectigo.com/resource-library/what-is-certificate-transparency
    
[^8]: https://en.wikipedia.org/wiki/Certificate_Transparency
    
[^9]: https://hackdb.com/item/crtsh
    
[^10]: https://crt.sh
    
[^11]: https://www.baeldung.com/linux/whois-command
    
[^12]: https://www.geeksforgeeks.org/linux-unix/how-to-use-the-whois-command-on-ubuntu-linux/
    
[^13]: https://geek-university.com/whois-command/
    
[^14]: https://www.hostinger.com/tutorials/linux-dig-command
    
[^15]: https://labex.io/tutorials/linux-linux-whois-command-with-practical-examples-423010
    
[^16]: https://achirou.com/curso-de-linux-para-hackers-comandos-whois-iwconfig-y-wget/
    
[^17]: https://docs.oracle.com/cd/E88353_01/html/E37839/dig-1.html
    
[^18]: https://www.mankier.com/1/dig
    
[^19]: https://www.sectigo.com/resource-library/root-causes-216-what-is-crt-sh
    
[^20]: https://www.diggui.com/dig-command-manual.php
    
[^21]: https://riversecurity.eu/finding-attack-surface-and-fraudulent-domains-via-certificate-transparency-logs/
