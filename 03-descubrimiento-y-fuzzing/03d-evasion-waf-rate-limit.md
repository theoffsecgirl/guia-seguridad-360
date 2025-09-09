# Evasión de WAF y Rate Limit

En entornos bug bounty/Pentesting, toparás con WAFs (Web Application Firewalls) y sistemas anti-abuso que limitan o bloquean tus pruebas. Evasión eficiente = menos ruido, más señal y mayor tasa de acierto en tus findings reales.

---

## ¿Qué buscan los WAF/Rate Limit?

- Patrones de payloads conocidos (XSS, SQLi, LFI…)
- Comportamiento repetitivo (misma IP, misma ruta, mismo header)
- Tasa de peticiones excesiva (requests por segundo/minuto)
- Faltas de legitimidad (headers obvios, ausencia de cookies/sesión, orden de headers no habitual)
- Origen geográfico
- User-Agents, ASN, proxies conocidos o "sospechosos"

---

## Estrategias y técnicas de evasión

### 1. Rotar IP, User-Agent y headers

- Usa **proxies**, **VPN** y **redes TOR** para cambiar de IP. Alterna con paciencia.
- Cambia el User-Agent con cada request:

```bash
ffuf ... -H "User-Agent: $(shuf -n1 user_agents.txt)"
```

- Rota cabeceras típicas y agrega otras habituales: Accept, Accept-Language, Referer, X-Requested-With, Connection, DNT, Cache-Control.

### 2. Gestionar la tasa y los patrones (Rate Limit)

- Ajusta threads y delays:

```bash
ffuf ... -t 3 -p 0.5
```

-t: baja concurrencia; -p: pausa entre peticiones.

- Haz lotes pequeños, espera entre rondas, monitoriza respuestas 429/403.
- Prueba “trenzar” (interleaving) URLs y no atacar endpoints únicos: reparte las pruebas en todo el dominio.

### 3. Burlar inspección de payload

- Encoding: URL encode, doble encode, unicode homoglyphs, case flipping (admin → AdMiN).
- Fragmentación o pequeños tweaks en el payload para saltar rules simples:
  - SQLi: `UNION SEL/**/ECT` en vez de `UNION SELECT`
  - XSS: `<sCript>`, `%3Cscript%3E`, SVG injection
- Cambia orden o presencia de parámetros, agrega noise válido.

### 4. Cabeceras proxy y bypass típicas

- Prueba X-Forwarded-For, X-Real-IP, X-Originating-IP, Forwarded para simular IP del cliente detrás de proxy.
- Algunos WAF permiten saltos pasando cabeceras X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization, X-Host, X-Forwarded-Host.

### 5. Header y cookie fuzz (WAF) avanzado

- Cambia nombres/casos: Authorization → authorization, Cookie → cookie.
- Incluye cookies legítimas si es posible (captura sesión propia/bot).
- Usa headers “ruido” (X-Nonsense) de otras apps populares.

### 6. Evasión vía Order/Extra headers (HTTP request smuggling)

- Reordena cabeceras, agrega duplicadas o valores inusuales.
- Variantes de Transfer-Encoding/Content-Length pueden romper parsers en WAF vulnerables.

---

## Automatización y pruebas

- Usa ffuf/gobuster con baja tasa y headers aleatorios.
- Burp Suite: configura “Resource Pool” y “Throttle” o plugins de “Turbo Intruder”.
- Tools de evasión adicionales:
  - [ftw (Framework for Testing WAFs)](https://github.com/fastly/ftw) para testear reglas.
  - [wafw00f](https://github.com/EnableSecurity/wafw00f) para fingerprint de WAF.

---

## Buenas prácticas

- Haz todas las pruebas primero autenticado/logueado; después, sin sesión, compara respuestas.
- Controla logs de respuesta: 403/429, lag en respuestas, CAPTCHAs, redirecciones inesperadas.
- Prueba todos estos trucos en entornos in-scope y respeta TOS/restricciones legales del programa.
- Documenta el bypass: qué cabeceras, delays y técnicas funcionaron (o no).

---

## Pipeline recomendado

```bash
ffuf -w wordlist.txt -u 'https://target.com/FUZZ' -t 2 -p 0.6 \
  -H "User-Agent: $(shuf -n1 user_agents.txt)" \
  -H "X-Forwarded-For: $(shuf -n1 ips.txt)" \
  -ac -mr "flag|token|access" -mc 200,403,429 -o bypass_results.txt
```

]

<div style="text-align: center">Evasión de WAF y Rate Limit</div>


[^1]: https://github.com/ffuf/ffuf
    
[^2]: https://www.reddit.com/r/bugbounty/comments/1f8mhjd/ultimate_ffuf_cheatsheet_advanced_fuzzing_tactics/
    
[^3]: https://infosecwriteups.com/content-discovery-with-ffuf-5bc81d2d8db6
    
[^4]: https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/
