# Secret Scanning en Front y CI/CD

## Resumen

**Qué es:** El secret scanning consiste en detectar y analizar credenciales, claves API, tokens, contraseñas y secretos expuestos involuntariamente en frontend (JS/CSS/HTML estáticos) y pipelines de CI/CD (repositorios, logs, build artifacts).
**Por qué importa:** Los secretos filtrados pueden ser utilizados para acceso ilegítimo, privilege escalation, persistencia, exfiltración de datos y abuso de infraestructura cloud/backend.
**Cuándo aplicarlo:** De rigor en cualquier auditoría de apps, revisiones de cadena de suministro, bug bounty y validación DevSecOps, especialmente en despliegues cloud y microservicios.

---

## Contexto

**Supuestos:**

- El attacker busca secretos hardcodeados, expuestos en JS/Web/HTML, variables en configuraciones y leaks en logs de builds.
- Entorno típico: apps con pipelines CI/CD activos (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps), despliegues serverless y micros front/back.
- Herramientas: truffleHog, gitleaks, ggshield (GitGuardian), repo-supervisor, grep, Burp Suite, regex hunting scripts, Google Dorks.

**Límites:**

- Foco en exposición de secretos vía código/repo/artifact, no vulnerabilidades de lógica cloud o backend.
- No cubre leaks por XSS/SSRF/directos en endpoints internos.

---

## Metodología

1. **Reconocimiento de superficies:**
   - Analizar ficheros JS/CSS/HTML, archivos de config (`.env`, `config.js`, `settings.py`, `application.yml`), logs de CI/CD, github repos públicos/forks.
   - Revisar history completa (`git log -p`, tags, forks).
2. **Secret Scanning en Frontend:**
   - Buscar en bundles/Webpack/React/builds compactos.
   - Usar regexes comunes para API keys, tokens JWT, secrets AWS/GCP/Azure, claves privadas.
   - Instrumentar scripts de grep en dumps y archivos web.
   - Ejemplo:

```bash
grep -E 'AIza[0-9A-Za-z-_]{35}' *.js           # Google API
grep -E 'AKIA[0-9A-Z]{16}' *.js                # AWS Access Key
grep -E 'ghp_[A-Za-z0-9]{36}' *.js             # GitHub Token
```

3. **Secret Scanning en CI/CD:**
   - Ejecutar herramientas especializadas en commits, pipelines y artefactos:
     - `trufflehog --json --entropy=True git_url`
     - `gitleaks detect -v --source=.`
     - `ggshield scan repo .`
   - Revisar logs de ejecución/builds por env vars, output verbose, uploads de artefactos y objetos temporales.
4. **Google Dorking/OSINT:**
   - `site:github.com target org/repo key secret password`
   - `site:pastebin.com secret key password`
   - `ext:env | ext:json | ext:yaml | ext:bak password`
5. **Prueba de uso y impacto:**
   - Validar que el secreto es funcional (login, acceso API, creación/eliminación de recursos).
   - Testear con artefactos, apps clouds y roles expuestos para privilege escalation.

**Checklist rápida:**

- Análisis de frontend build estáticos y dinámicos.
- Scaneo de repositorios y logs de pipelines.
- Validación del impacto (¿el secreto permite acceso real?).
- Eliminación/rotación de secretos después de hallazgo.
- Alertas de leak continuo (hooks, bots, programas VCS).

---

## Pruebas Manuales

### En Frontend

- Descargar build/js desde `/_next/static/`, `/dist/`, `/static/`.
- Grepear en todos los assets:

```bash
grep -E "(key|secret|token|password)" . -R --include="*.js"
```

- Buscar en Service Workers y Webpack config.
- Revisar variables globales en ventana/browser (`window.apiKey`, etc).

### En CI/CD

- Escanear repo con trufflehog/gitleaks:

```bash
trufflehog --entropy=True --json .
gitleaks detect -v --source=.
```

- Buscar secrets en logs y artefactos:
  - Variables de entorno (exportadas o accidentalmente impresas).
  - Output de scripts (`console.log`, `print`, etc).
  - Recursos temporales subidos o cacheados.

### Dorking público

- Buscar leaks en pastebin/gist/github.
- Analizar forks/histórico de cambios y PRs.

---

## PoC Automatizada

**Python: Detectar Google API Key y AWS Key:**

```python
import re

for file in ['bundle.js', 'main.js']:
    with open(file) as f:
        content = f.read()
        google_keys = re.findall(r'AIza[0-9A-Za-z-_]{35}', content)
        aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', content)
        print("Google Keys:", google_keys)
        print("AWS Keys:", aws_keys)
```

**CI/CD Gitleaks:**

```bash
gitleaks detect -v --source=.
```

---

## Explotación y Automatización

- Automatización en pipelines, con bots/gitleaks para PRs y pushes.
- En discordancia, usar keys/leaks para acceder a APIs, escalar privilegios, persistir en cloud.
- Validar y usar claves funcionales en bug bounty.

---

## Impacto

- **Account Takeover:** Acceso total a cuentas, APIs privadas, recursos cloud, repos y entornos de producción.
- **Privilege escalation/persist:** Creación de recursos, manipulación, despliegues, abuso de billing.
- **Data breach:** Extracción masiva de datos, dumps y artefactos.
- **Supply chain attack:** Inyección de código/artefactos maliciosos por credenciales expuestas.

**Mapeo:** API3 Data Exposure, API7 Security Misconfiguration, CWE-798 Use of Hard-Coded Credentials.

---

## Detección

- Alertas de bots (GitGuardian, Gitleaks) en pushes y PRs.
- Notificaciones en repos conocidos y artefactos build.
- Logs de escaneo manual, rotación de claves tras hallazgo.

---

## Mitigación

- Rotar/eliminar secretos y credenciales expuestos inmediatamente.
- Implementar secret scanning como paso obligatorio en CI/CD.
- Uso de vault/secrets manager, jamás hardcodear en fuente/build.
- Borrar/invalidar artefactos con secrets y forzar login/claves nuevos.
- Monitorizar con alertas en tiempo real de leaks.

---

## Errores Comunes

- Confiar en “minify” o “obfuscate” para ocultar secretos.
- Versionar archivos de config sensibles por error.
- Exponer secrets en logs de entorno o output de CI/CD.
- No rotar claves tras exposición.
- Subir artefactos/bundles sin revisión post-build.

---

## Reporte

**Título:** Scanning revela secretos expuestos en frontend y pipelines CI/CD, permitiendo acceso y persistencia crítica
**Impacto:** Account takeover, privilege escalate, DoS/supply chain abuse, data breach
**Pasos:**

1. Descargar assets/repo/pipeline y escanear con gitleaks/trufflehog/regex/bots
2. Validar impacto del secreto hallado en API, cloud, backend
3. Reportar, eliminar y rotar inmediatamente, clean artefact y monitorizar leak continuo
