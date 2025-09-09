# Sourcemaps y Artefactos de Build

Descubrir y analizar sourcemaps (`.map`) y otros artefactos de build públicos puede elevar el impacto de tu investigación: te permite acceder al código fuente (o su estructura) real, rutas internas, comentarios, objetos, y a veces credenciales, endpoints ocultos y mucho más.

---

## ¿Qué son los sourcemaps y artefactos de build?

- **Sourcemaps (`.map`)**: Archivos generados por transpiladores (Webpack, Babel, TypeScript...) que mapean el código ofuscado/minificado servible a su fuente original legible.
  - Ejemplo típico expuesto: `https://target.com/static/js/app.js.map`
- **Artefactos de build**: Archivos generados y expuestos del proceso de compilar/paquetizar la app web (servicios, configs, backups, archivos intermedios: `.env`, `.bak`, `.gz`, “previous version”, zips, etc).

---

## ¿Por qué importa exponerlos?

- Exponen nombres reales de funciones, clases, variables y rutas de API internas.
- Pueden incluir comentarios del desarrollador y TO-DO ocultos.
- Permiten “deofuscar” el código JS, facilitando la búsqueda de lógica oculta, bugs, endpoints fantasma, claves, tokens, algoritmos y rutas accesibles sólo desde frontend/API JS.
- A veces revelan paths internos de entorno, secretos, usuarios de CI/CD, mapeos a microservicios, etc.

---

## Cómo descubrirlos

### 1. Fuzzing de rutas comunes

```bash
ffuf -w seclists/Fuzzing/sourcemap.txt -u 'https://target.com/static/js/FUZZ' -mc 200,206
```

o prueba `/app.js.map`, `/main.js.map`, `/bundle.js.map`, etc.

- Wordlist útil:
  - [`SecLists/Fuzzing/sourcemap.txt`](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/sourcemap.txt)
  - Añade artefactos: `.env`, `.bak`, `.gz`, `.zip`, `config.old`, etc.

### 2. JS Asset Discovery + Prueba directa

- Descarga y revisa los imports/paths de los JS del frontend:
  - Busca en HTML/JS referencias a archivos `.map`, `.bak`, `.env`, etc.
- Probar las variantes manualmente puede revelar otros artefactos de build por naming pattern.

### 3. Google Dorking

```
site:target.com ext:map inurl:.js
site:target.com ext:env | ext:bak | ext:gz | ext:zip
```

---

## Análisis de sourcemaps

- Usa scripts deparseadores como [sourcemapper](https://github.com/s1l3nt78/sourcemapper), [smaplyze](https://github.com/linuswilson/smaplyze) o “source-map-explorer” para reconstruir la fuente y facilitar la búsqueda.
- Busca secretos, endpoints no utilizados, referencias a entornos (“dev”, “staging”, “private API”), rutas ocultas y módulos internos.
- Haz grep de API keys, JWT, referencias a S3, comments TODO/FIXME, hardcoded credentials, rutas curiosas, artefactos internos.

**Ejemplo mínimo para extraer rutas/endpoints:**

```bash
grep -Eo '(GET|POST|PUT|DELETE) [^"'\'' ]+' app.js.map | sort -u
grep -Eo '[A-Za-z0-9_\-\.]{8,}\.(js|php|asp|aspx|json|env|bak|zip|gz)' app.js.map | sort -u
```

---

## Visibilidad y reporte responsable

- Si encuentras datos realmente sensibles (claves, credenciales, tokens): **¡no los uses!** Simplemente evidencia el hallazgo, redacta las pruebas y recomienda la revocación/rotación.
- En informes, prueba el acceso sólo a nivel de lectura y cita sólo tanto como para demostrar el riesgo.

---

## Pipeline recomendado

```bash
# Descubrir artefactos típicos
ffuf -w seclists/Fuzzing/sourcemap.txt -u 'https://target.com/static/js/FUZZ' -mc 200,206 -o paths_validos.txt

# Descargar sourcemap y analizar
curl -s https://target.com/static/js/app.js.map -o app.js.map
grep -E 'secret|token|api|key|todo|fixme' app.js.map
```

<div style="text-align: center">Sourcemaps y Artefactos de Build</div>


[^1]: https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/
    
[^2]: https://www.reddit.com/r/bugbounty/comments/1f8mhjd/ultimate_ffuf_cheatsheet_advanced_fuzzing_tactics/
