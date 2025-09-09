# Introducción a DNS

El Domain Name System (DNS) traduce nombres legibles (www.ejemplo.com) a direcciones IP y mantiene caché con tiempos de vida (TTL), lo que acelera respuestas y abre vectores si hay mala configuración o envenenamiento.

## Jerarquía y flujo de resolución

- Raíz (.) → TLD (.com, .org) / ccTLD (.es, .uk) / sTLD (.gov, .edu) → SLD (ej. “google” en google.com) → subdominios (api.google.com).
- Resolución típica: cliente → resolvedor recursivo (ISP/empresa) → raíz → TLD → autoritativos del dominio → respuesta con TTL y caché intermedia.

## Registros DNS clave


| Tipo      | Uso práctico                                                        |
| :-------- | :------------------------------------------------------------------- |
| A / AAAA  | Nombre → IPv4 / IPv6.                                               |
| CNAME     | Alias a otro nombre (ojo a “dangling CNAME” y subdomain takeover). |
| MX        | Correo del dominio (prioridades); valida superficies SMTP.           |
| TXT       | Metadatos (SPF, DKIM, DMARC, verificación).                         |
| NS        | Autoritativos de la zona (delegación).                              |
| SOA       | Autoridad de zona (serie, refresh, retry, mínimo TTL).              |
| SRV       | Ubicación de servicios (_service._proto).                           |
| PTR       | Reverse DNS (IP → nombre).                                          |
| CAA       | Qué CAs pueden emitir certificados; útil para hardening.           |
| DS/DNSKEY | Registros de DNSSEC (firma/validación).                             |

## Zonas y delegación

- Zona: porción administrativa con sus registros y SOA; puede delegar subzonas vía NS.
- Split‑horizon: mismas zonas con respuestas distintas según origen (interno/externo).
- Transferencias: AXFR (completa) / IXFR (incremental) para secundarios; deben estar restringidas.

## Recon y enumeración (operativo)

- Pasivo: WHOIS, certificados públicos, históricos de DNS, dorks, leaks en repositorios.
- Activo: listar NS/SOA, obtener registros comunes, detectar wildcard, probar AXFR contra cada NS, brute force de subdominios, reversos sobre rangos.
- Señales de interés: TTLs anómalos, NS inconsistentes, open resolvers, CNAME a servicios huérfanos, políticas SPF/DMARC débiles.

## Ataques y vectores comunes

- Cache poisoning: introducir respuestas falsas en cachés recursivas para redirigir tráfico.
- DNS rebinding: alternar IPs en resoluciones para alcanzar recursos internos desde el navegador.
- DNS tunneling: exfiltración/CC dentro de consultas/respuestas (dominios controlados).
- Amplificación en open resolvers: abuso de recursión pública para DDoS.
- AXFR expuesto: listado completo de la zona por mala configuración.
- Subdomain takeover: CNAME apuntando a recurso eliminado (S3, Heroku, etc.).
- NS/Delegation hijack: dominios de NS caducados o controlados por terceros.

## Defensas a evaluar (y recomendar)

- DNSSEC en cadena (DS/DNSKEY válidos); valida origen e integridad.
- Restringir recursión/puertos aleatorios/IDs; cerrar “open resolvers”.
- Denegar AXFR a IPs no autorizadas; monitorear cambios de SOA/NS.
- CAA restrictivo; SPF/DMARC alineados; TTLs razonables y coherentes.

## Herramientas útiles

- Básicas: dig, host, nslookup.
- Enumeración: dnsrecon, dnsenum, fierce, amass, sublist3r, gobuster dns.
- Soporte: whois, traceroute, resolvers públicos para contraste.

## Ejemplos con dig (listos para copiar)

```bash
# A / AAAA
dig A www.ejemplo.com +short
dig AAAA www.ejemplo.com +short

# MX / NS / SOA / TXT
dig MX ejemplo.com +short
dig NS ejemplo.com +short
dig SOA ejemplo.com
dig TXT ejemplo.com +short
dig TXT _dmarc.ejemplo.com +short

# Trazado de resolución (desde raíz)
dig +trace www.ejemplo.com

# Consultar directamente a un autoritativo
dig A www.ejemplo.com @ns1.ejemplo.com

# Intentar AXFR contra cada NS (siempre permitido solo en laboratorio/permiso explícito)
for ns in $(dig NS ejemplo.com +short); do echo "== $ns =="; dig AXFR ejemplo.com @$ns; done

# Banner CHAOS (a veces muestra versión del servidor)
dig version.bind CHAOS TXT @ns1.ejemplo.com +short

# Detección rápida de wildcard (esperado NXDOMAIN si no hay wildcard)
random=$(tr -dc a-z0-9 </dev/urandom | head -c 12)
dig $random.ejemplo.com +short
```

## Códigos de estado (RCODE) frecuentes


| Código  | Significado                                           |
| :------- | :---------------------------------------------------- |
| NOERROR  | Respuesta válida (puede venir sin datos: NODATA).    |
| NXDOMAIN | El nombre no existe.                                  |
| SERVFAIL | Error del servidor (fallo de recursión/validación). |
| REFUSED  | Consulta rechazada por política.                     |
| FORMERR  | Formato de consulta inválido.                        |

## Checklist para informes (rápido)

- Coherencia A/AAAA/MX/NS/SOA entre autoritativos; diferencias documentadas.
- AXFR denegado en todos los NS; evidencias si alguno lo permite.
- Sin open resolvers ni recursión a terceros; política clara de rate limit.
- DNSSEC: presencia y validez de DS/DNSKEY; recomendaciones si falta.
- Riesgos detectados: wildcard erróneo, CNAME huérfanos, TTLs extremos, políticas de correo débiles (SPF “+all”, DMARC inexistente).

Con esto tienes una “Introducción a DNS” compacta, accionable y orientada a hallazgos reales sin perder el rigor técnico.
<span style="display:none">[^7]</span>


[^1]: https://medium.verylazytech.com/complete-guide-to-dns-and-dhcp-penetration-testing-fb4597e5d880
    
[^2]: https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-dns
    
[^3]: https://infosecwriteups.com/a-beginners-guide-to-dns-reconnaissance-part-1-6cd9f502db7d
    
[^4]: https://dns-pentesting.popdocs.net
    
[^5]: https://securedebug.com/mastering-dns-enumeration-and-attacks-an-ultra-extensive-guide/
    
[^6]: https://hackers-arise.com/network-basics-for-hackers-domain-name-service-dns-and-bind-how-it-works-and-how-it-breaks/
    
[^7]: https://www.jalblas.com/blog/dns-essentials-key-insights-for-pentesters/
