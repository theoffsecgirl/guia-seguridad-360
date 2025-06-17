# Introducción a `subfinder`

`subfinder` es una herramienta de descubrimiento de subdominios pasiva, desarrollada por el equipo de ProjectDiscovery. Está escrita en Go y es conocida por su velocidad y la gran cantidad de fuentes de datos que utiliza para encontrar subdominios. Es una de las primeras herramientas que se suelen lanzar en la fase de reconocimiento para mapear la superficie de ataque de un objetivo.

Al ser pasiva, `subfinder` no envía tráfico directamente a los servidores del objetivo (o lo hace de forma muy limitada a través de las fuentes que consulta), lo que la hace relativamente sigilosa.

### Configuración de `subfinder` (API Keys para Máximos Resultados)

Para sacarle el máximo partido a `subfinder`, especialmente cuando se usa la opción `-all`, es **altamente recomendable configurar las claves API** de los diversos servicios online que utiliza como fuentes. Sin estas claves, muchas fuentes no devolverán resultados o lo harán de forma muy limitada.

- **Enumerar subdominios para un solo dominio:**

```bash
subfinder -d ejemplo.com
```

Esto usará las fuentes por defecto que no requieren claves API o cuyas claves ya están configuradas.

- **Usar TODAS las fuentes (incluyendo las que requieren API keys):**

```bash
 subfinder -d ejemplo.com -all
```

La opción `-all` le dice a `subfinder` que utilice todas las fuentes de enumeración que conoce, incluidas aquellas que has configurado con claves API y que podrían ser más lentas o tener límites de uso. **Es la forma recomendada para obtener la lista más completa de subdominios.**

- **Enumerar subdominios para múltiples dominios:**
  - **Desde un archivo (`-dL` Domain List):** Es la forma más cómoda si tienes muchos dominios. Crea un archivo de texto (e.g., `dominios_objetivo.txt`) con un dominio por línea:

```bash
ejemplo1.com
otraweb.org 
mas-targets.net
```

Luego ejecuta:

```bash
subfinder -dL dominios_objetivo.txt
```

- **Múltiples flags `-d`:** También puedes especificar varios dominios directamente en la línea de comandos:

```bash
subfinder -d ejemplo1.com -d otraweb.org -d mas-targets.net
```

_(**Nota:** `subfinder` no usa una lista separada por comas como `subfinder -d ejemplo1.com,otraweb.org`. Debes usar múltiples `-d` o el flag `-dL` para listas)._

- **Otras Opciones Útiles:**
  - **`-o <archivo.txt>`:** Guardar los resultados en un archivo.

```bash
 subfinder -d ejemplo.com -all -o subs_ejemplo.txt
```

- **`-silent`:** Mostrar solo los subdominios encontrados, sin banners ni información adicional. Ideal para encadenar con otras herramientas.
  - **`-v` (verbose):** Mostrar más información sobre el proceso, útil para depurar.
  - **`-recursive`:** Intenta realizar un descubrimiento recursivo sobre los subdominios encontrados para encontrar sub-subdominios (e.g., si encuentra `dev.ejemplo.com`, también buscará `api.dev.ejemplo.com`). Puede aumentar significativamente el tiempo de escaneo.
  - **`-sources`:** Lista todas las fuentes de datos disponibles que `subfinder` puede usar.
  - **`-list-sources` (o `-ls`):** Similar a `-sources`.
  - **`-source <fuente1,fuente2>` (o `-s`):** Usar solo las fuentes especificadas.
  - **`-exclude-source <fuente1,fuente2>` (o `-es`):** Excluir las fuentes especificadas.
  - **`-timeout <segundos>`:** Tiempo máximo de espera para las fuentes.
  - **`-max-time <minutos>`:** Tiempo máximo total para la ejecución.

### Integración con Otras Herramientas (Workflow Común)

`subfinder` brilla cuando se combina con otras herramientas del ecosistema de ProjectDiscovery u otras utilidades. Un flujo de trabajo muy común es:

1. **Descubrir subdominios con `subfinder`.**
2. **Filtrar y validar cuáles están vivos y responden vía HTTP/HTTPS con `httpx`.**
3. **(Opcional) Realizar fingerprinting tecnológico con `httpx` o `whatweb`.**
4. **(Opcional) Tomar capturas de pantalla con `gowitness` o `webscreenshot`.**
5. **(Opcional) Escanear puertos con `naabu` o `nmap`.**
6. **(Opcional) Pasar los subdominios vivos a escáneres de vulnerabilidades como `nuclei`.**

**Ejemplo de Encadenamiento Básico:**

```bash
subfinder -d ejemplo.com -silent -all | httpx -silent -title -status-code -tech-detect -o hosts_vivos_con_info.txt
```

Este comando:

1. Busca subdominios de `ejemplo.com` con `subfinder` usando todas las fuentes y en modo silencioso.
2. La salida (lista de subdominios) se pasa (`|`) a `httpx`.
3. `httpx` prueba cada subdominio, también en modo silencioso, y extrae el título de la página, el código de estado HTTP, y detecta tecnologías.
4. El resultado final se guarda en `hosts_vivos_con_info.txt`.
