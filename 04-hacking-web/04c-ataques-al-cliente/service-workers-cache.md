# Service Workers y Caché

## Resumen

Los Service Workers (SW) son piezas fundamentales de la arquitectura web moderna: permiten controlar la red, gestionar cachés y habilitar aplicaciones offline y PWA. Mal implementados, son una superficie de explotación privilegiada para ataques como cache poisoning persistente, XSS permanente, robo de secretos y takeover de todas las rutas de la aplicación. Su combinación con políticas laxas de CSP y rutas de registro mal protegidas ha dado lugar a vulnerabilidades críticas en plataformas reales.[^2]

---

## Conceptos Fundamentales

- **Service Worker:** Script en segundo plano que intercepta y manipula requests/fetchs de la página, controla el ciclo de vida de recursos, incluso offline.
- **Scope:** Ruta que controla el SW. Puede ser `/`, una carpeta específica o rutas profundas.
- **Cache API:** Permite guardar, servir y manipular recursos en el almacenamiento controlado por el SW (independiente de cache HTTP).
- **Interceptación Fetch:** Toda petición puede ser alterada, bloqueada, redirigida, modificada y respondida con lo que se quiera (cualquier payload, incluso ejecutable).

---

## Ataques Críticos y Técnicas de Explotación

### 1. Takeover de Service Worker

**Escenario:** Permitir scripts subidos/controlados en rutas donde el SW puede registrarse (`/`, `/api`, `/uploads`), o CSP que permite a un atacante cargar su SW desde subdominios/adyacentes.

**Exploit:**

```javascript
// POC: registro malicioso
navigator.serviceWorker.register('/uploads/sw.js', {scope: '/'});
```

- El atacante controla `/uploads` y ejecuta un SW en scope `/`, interceptando todo el tráfico web.

---

### 2. Persistent Cache Poisoning

- El SW intercepta requests y responde con contenido cacheado arbitrario aunque la aplicación se actualice en backend o el atacante quede fuera de la sesión.
- Puede entregar versiones antiguas, payloads XSS, backdoors o infecciones que persisten tras logout o incluso reinicios del navegador (hasta que el SW es eliminado).

**Ejemplo básico de SW malicioso:**

```javascript
self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request).then(function(response) {
      if (response) return response;
      // Inyecta respuesta falsa para /admin
      if (event.request.url.includes('/admin')) {
        return new Response('<script>alert("XSS Permanente")</script>', {headers: {'Content-Type': 'text/html'}});
      }
      return fetch(event.request);
    })
  );
});
```

---

### 3. XSS Persistente y Control de Todas las Rutas

- Un SW malicioso puede devolver scripts inyectados en cualquier petición a rutas bajo su scope, generando XSS imposible de limpiar para el usuario no avanzado.
- Rutas de login, pagos, paneles admin quedan bajo el control total del atacante.

### 4. Robo de JWT/Cookies/Tokens

- El SW intercepta y clona todas las peticiones, accediendo a cabeceras, cuerpos, respuestas, renovaciones de token y cualquier otro tráfico sensible.
- Permite exfiltrar credenciales y session tokens a dominios remotos.

### 5. Bloqueo de Updates y Actualizaciones

- Un SW no autorizado puede "fossilizar" una aplicación, impidiendo que los nuevos scripts, actualizaciones, CSP y controles sean descargados o ejecutados por el usuario víctima.
- Impide incluso intentos de desinfección si la revocación/cambio de path del SW no se maneja correctamente (el navegador sigue usando el viejo SW).

---

## Detección y Metodología de Testing

### 1. Descubrimiento de Service Workers

- Buscar registro de SW en JS (`navigator.serviceWorker.register`)
- Enumerar rutas y scopes permitidos por la aplicación (DevTools > Application > Service Workers)
- Revisar scripts en `/`, `/sw.js`, `/static/sw.js`, `/uploads/sw.js`, etc.

### 2. Headers de Protección

- Revisar CSP: ¿permite scripts de rutas controladas por el usuario/atacante?
- ¿Se permite registrar SW desde subdominios, uploads, rutas dinâmicas?
- Chequear `Service-Worker-Allowed` header: determina scope máximo permitido para SW.

```bash
curl -I https://victima.com/sw.js | grep -i service-worker-allowed
```

### 3. Testing Manual

- Intentar registrar tu propio SW desde rutas de uploads, subdominios, APIs.
- Publicar payloads XSS en rutas bajo el scope del SW.
- Manipular Cache API vía DevTools > Application > Cache Storage.
- Evaluar persistencia tras limpieza de cookies/localStorage; los SW pueden seguir activos.

---

## Automatización

**Automatización básica:**

```bash
# Detección de SW desde CLI
curl https://victima.com | grep -i 'serviceWorker.register'
# Fuzz de paths SW comunes
for path in /sw.js /static/sw.js /uploads/sw.js /js/sw.js; do
    curl -s -I https://victima.com$path | grep -i "200 OK"; 
done
```

**Automatización avanzada:**

- Nuclei templates `service-worker`, `cache-poisoning`
- Burp Suite extensions o ZAP scripts para descubrir scope/registers

---

## Explotación Real: Encadenamiento de Vulnerabilidades

1. **Uploadable SW:** Endpoint de upload sin validación permite subir `sw.js`
2. **Registro y takeover:** Atacante registra SW con scope global
3. **Persistent XSS/Backdoor:** SW responde con payload malicioso incluso tras logout/reset
4. **Account Takeover:** SW intercepta y reenvía tokens, cookies, incluso manipula UI para phishing persistente

---

## Mitigación

1. **CSP restrictiva:** No permitir scripts de rutas dinámicas o subdominios inseguros.
2. **Deshabilitar uploads en rutas bajo SW scope:** Bloquear uploads arbitrarios en `/`, `/js`, `/`, etc.
3. **Fijar Service-Worker-Allowed:** Limitar el scope solo al path seguro.

```http
Service-Worker-Allowed: /static/
```

4. **Revisar y auditar todos los scripts SW en producto:** Ninguno debe ser alterable por el usuario.
5. **Cache busting y limpieza forzada de SW y caches en cada actualización crítica.**
6. **Incluir controles de fingerprinting de SW y alertas de registro no autorizado.**
7. **Permitir al usuario remover/deshabilitar SW manualmente:** Instrucciones claras en soporte/términos.

---

## Ejemplo de Reporte

```markdown
## Vulnerable Service Worker y Cache Poisoning Persistente

**Severidad:** Crítica  
**Resumen:** 
El endpoint de uploads permite subir y registrar un Service Worker bajo el scope global. Atacantes pueden interceptar, persistir XSS y tomar control completo de la aplicación para cualquier usuario afectado.

**PoC:**
1. Subir `sw.js` a `/uploads`
2. Ejecutar `navigator.serviceWorker.register('/uploads/sw.js',{scope:'/'})`
3. Acceder a la app — cualquier petición puede responderse/controlarse mediante el SW
4. Una vez infectado, el XSS persiste incluso tras reload/logoff

**Mitigación:**  
- Bloquear rutas dinâmicas en script-src y Service-Worker-Allowed
- Sólo permitir registro de SW de rutas auditadas e inmutables
- Auditar scripts SW en producción regularmente
- Reset de Service Workers y caché tras incidente

```

---


---

Los Service Workers ofrecen enormes ventajas funcionales y de performance, pero una mala implementación puede ser el eslabón más débil de todo el ecosistema cliente. El pentesting sistemático de sus rutas, cabeceras y controles debe ser parte de cualquier análisis avanzado/bounty.

[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
