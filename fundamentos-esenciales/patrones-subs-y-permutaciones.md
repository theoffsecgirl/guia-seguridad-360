# Patrones de Subdominios y Generación de Permutaciones

### Introducción

Una de las técnicas más efectivas en el reconocimiento de activos es entender y predecir los **patrones de nomenclatura** que las organizaciones utilizan para sus subdominios. Los equipos de desarrollo y operaciones (DevOps) suelen seguir convenciones lógicas para separar diferentes **entornos** (desarrollo, pruebas, producción), **servicios** (aplicación principal, API, panel de administración) y **versiones**.

Al identificar estos patrones, puedes generar listas de posibles subdominios (permutaciones) y descubrir activos "ocultos" que a menudo son menos seguros que los sistemas de producción principales.

### Patrones Comunes por Entorno de Desarrollo

Las aplicaciones pasan por diferentes fases antes de llegar al usuario final. Cada fase suele tener su propio entorno y, por tanto, su propio subdominio.

- **Aplicación Base (Producción):**

  - `app.ejemplo.com`
  - Este suele ser el punto de partida, la aplicación principal accesible al público.
- **Entornos de Desarrollo (`dev`):**

  - Son instancias para que los desarrolladores prueben nuevas funcionalidades. Suelen ser inestables y, a veces, contienen configuraciones de depuración o información sensible.
  - **Patrón de Subdominio:** `app.dev.ejemplo.com`
  - **Patrón con Guiones:** `app-dev.ejemplo.com`
- **Entornos de Pruebas (`staging`, `qa`, `uat`):**

  - `staging`: Entorno de pre-producción, una réplica casi exacta de la producción para las pruebas finales.
  - `qa`: Quality Assurance, para el equipo de control de calidad.
  - `uat`: User Acceptance Testing, para que el cliente o usuarios finales validen las funcionalidades.
  - **Patrones:**
    - `app.staging.ejemplo.com`
    - `app-qa.ejemplo.com`
    - `api.uat.ejemplo.com`
- **Entornos de Producción (`prod`):**

  - A veces, incluso el entorno de producción se designa explícitamente para diferenciarlo de otros, o para gestionar despliegues geográficos o por versiones (blue-green deployments, canary releases).
  - **Patrones:**
    - `app.prod.ejemplo.com`
    - `app-prod.ejemplo.com`
    - `app.eu-west-1.prod.ejemplo.com` (designación geográfica)

### Patrones Comunes por Tipo de Servicio

Además de los entornos, los subdominios suelen identificar el propósito del servicio que albergan.

- **Aplicación Frontend:**

  - `app.dev.ejemplo.com`
  - `app.prod.ejemplo.com`
- **API Backend:**

  - `api.dev.ejemplo.com`
  - `api.prod.ejemplo.com`
- **Panel de Administración:**

  - `admin.dev.ejemplo.com`
  - `admin.prod.ejemplo.com`

### Combinando Patrones: El Juego de las Permutaciones

La verdadera potencia viene de combinar estos patrones. Si descubres un subdominio, puedes empezar a generar permutaciones lógicas para encontrar otros.

**Ejemplo de Patrón Complejo:**

- `app-api-dev.ejemplo.com`
  - Esto se puede desglosar como: La **API** para la aplicación **app**, en el entorno de **desarrollo (`dev`)**.

**Ejemplos de Versionado en APIs:** El versionado también es un patrón común, especialmente en APIs.

- **APIs de Desarrollo:**
  - `api-dev-v1.ejemplo.com`
  - `api.dev.v2.ejemplo.com`
- **APIs de Producción:**
  - `api-v1.ejemplo.com`
  - `api-v2.ejemplo.com`

### Estrategia Práctica para el Bug Hunter

La idea es pensar como el equipo de desarrollo o de DevOps. No te limites a la salida inicial de tus herramientas.

1. **Analiza los Subdominios Encontrados:** Ejecuta `subfinder` o una técnica similar para obtener una lista inicial de subdominios.
2. **Identifica los Patrones:** Revisa la lista y busca patrones recurrentes:
   - ¿Usan guiones (`app-dev`) o subdominios anidados (`app.dev`)?
   - ¿Qué palabras clave de entorno usan (`dev`, `staging`, `test`, `uat`, `prod`)?
   - ¿Qué nombres de servicios usan (`api`, `app`, `admin`, `internal`, `vpn`, etc.)?
   - ¿Hay patrones geográficos (`eu`, `us`, `asia`) o de versión (`v1`, `v2`)?
3. **Genera Permutaciones:** Usa los patrones identificados para generar una nueva lista de posibles subdominios que aún no has encontrado.
4. **Automatiza la Generación de Permutaciones:**
   - Existen herramientas específicas para esto que toman una lista de subdominios conocidos y generan permutaciones inteligentes.
   - **Herramientas recomendadas:**
     - **`dnsgen`**: Toma una lista de subdominios y genera permutaciones basadas en ellos.
     - **`gotator`**: Otra herramienta excelente para generar permutaciones de subdominios.

**Flujo de Trabajo Conceptual en la Terminal:**

```bash
# 1. Obtener una lista inicial de subdominios
subfinder -d ejemplo.com -silent > subs_iniciales.txt

# 2. Generar permutaciones a partir de la lista inicial
cat subs_iniciales.txt | dnsgen - > subs_permutaciones.txt

# 3. Combinar ambas listas, eliminar duplicados y resolverlos
cat subs_iniciales.txt subs_permutaciones.txt | sort -u | massdns -r resolvers.txt -t A -o J > subs_resueltos.json
```

Este flujo te permite expandir enormemente tu lista inicial de objetivos.
