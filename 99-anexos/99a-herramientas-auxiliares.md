# Herramientas y Habilidades Auxiliares

Hay ciertas herramientas y habilidades que no pertenecen a una única fase del hacking, sino que son transversales y se utilizan constantemente. En esta sección, repasaremos las más importantes.

## curl: La Navaja Suiza para Peticiones HTTP

`curl` es una herramienta de línea de comandos para transferir datos con URLs. Es fundamental para interactuar con servicios web de forma rápida y programática desde la terminal.

### Opciones Comunes de `curl`


| Opción   | Descripción                                        |
| :-------- | :-------------------------------------------------- |
| `-X`      | Método HTTP a usar (GET, POST, etc.).              |
| `-H`      | Añadir cabecera personalizada.                     |
| `-d`      | Enviar datos en el cuerpo de la petición.          |
| `-i`      | Incluir cabeceras de respuesta en la salida.        |
| `-I`      | Solo solicitar cabeceras (método HEAD).            |
| `-L`      | Seguir redirecciones (códigos 3xx).                |
| `-v`      | Modo detallado (verbose), para ver todo el proceso. |
| `-s`      | Modo silencioso, para ocultar el progreso.          |
| `-o`      | Guardar la salida en un archivo.                    |
| `--proxy` | Especificar un proxy para enviar el tráfico.       |

### Ejemplos Prácticos

```bash
# Realizar una petición GET simple y detallada
curl -v [https://ejemplo.com](https://ejemplo.com)

# Realizar un POST enviando datos de un formulario
curl -X POST [https://ejemplo.com/login](https://ejemplo.com/login) -d "username=admin&password=admin123"

# Enviar una petición con una cabecera personalizada
curl -H "X-Custom-Header: MiValor" [https://ejemplo.com](https://ejemplo.com)
```


# Proxy Tools: Tus Ojos en el Tráfico Web

Como profesional de la seguridad ofensiva, necesitas ser capaz de ver, analizar y modificar las peticiones HTTP/HTTPS que tu navegador (o cualquier otra herramienta) envía a los servidores web, así como las respuestas que estos devuelven. Las herramientas proxy actúan como un intermediario (Man-in-the-Middle) entre tu cliente y el servidor.

**¿Por qué son esenciales?**

- **Visibilidad:** Entender exactamente qué datos se envían y reciben.
- **Manipulación:** Modificar peticiones sobre la marcha para probar vulnerabilidades (cambiar parámetros, cabeceras, cuerpo de la petición).
- **Automatización:** Reenviar peticiones modificadas múltiples veces, fuzzing de parámetros.
- **Descubrimiento:** Identificar endpoints ocultos, parámetros no evidentes, o comportamientos extraños de la aplicación.

**Configuración Básica Conceptual:** El flujo típico es: `Navegador -> Herramienta Proxy (escuchando en localhost:puerto) -> Servidor Web Destino`. Para interceptar tráfico **HTTPS**, necesitarás instalar el certificado CA raíz de la herramienta proxy en tu navegador o sistema operativo. Esto permite al proxy descifrar y re-cifrar el tráfico HTTPS sin que el navegador lance alertas de certificado inválido.

**Herramientas Recomendadas:**

1. **Burp Suite (PortSwigger):**

   - **Descripción:** Considerada la herramienta estándar de la industria para el análisis y pentesting de aplicaciones web. Existe una versión gratuita (Community Edition) con funcionalidades básicas y una versión de pago (Professional) con muchas más características, incluyendo un escáner automatizado potente.
   - **Módulos Clave (muchos disponibles en la Community Edition):**
     - **Proxy:** El núcleo. Intercepta, visualiza y permite modificar tráfico HTTP/S en tiempo real. Tiene un historial de peticiones muy útil.
     - **Repeater:** Permite tomar una petición individual, modificarla y reenviarla múltiples veces, observando las diferentes respuestas. Indispensable para probar payloads.
     - **Intruder:** Automatiza el envío de peticiones con payloads modificados. Útil para fuzzing, enumeración, ataques de fuerza bruta (con cuidado de no bloquear cuentas o IPs).
     - **Decoder:** Herramienta para codificar y decodificar datos en varios formatos (URL, Base64, HTML, Hex, etc.).
     - **Comparer:** Compara dos piezas de datos (peticiones, respuestas, etc.) para identificar diferencias.
     - **Target (Site map):** Mapea la estructura de la aplicación a medida que navegas, mostrando todos los endpoints descubiertos.
     - **Logger:** (Professional) Registra todas las peticiones hechas por todas las herramientas de Burp.
     - **Scanner:** (Professional) Escáner de vulnerabilidades automatizado.
   - **Instalación:** Descargar desde el sitio oficial de PortSwigger. Requiere Java.
2. **OWASP ZAP (Zed Attack Proxy):**

   - **Descripción:** Una alternativa gratuita y de código abierto a Burp Suite, mantenida por OWASP. Es muy potente y cuenta con una gran comunidad.
   - **Funcionalidades Clave:** Similar a Burp, incluye proxy de intercepción, active/passive scanner, fuzzer, spider, y soporte para scripting.
   - **Instalación:** Descargar desde el sitio oficial de OWASP ZAP.
3. **Caido:**

   - **Descripción:** Una herramienta proxy más nueva, diseñada para ser ligera, rápida y con una interfaz de usuario moderna. Se está volviendo popular por su sencillez y rendimiento, especialmente para tareas rápidas o como alternativa menos pesada.
   - **Funcionalidades:** Ofrece intercepción, historial, repetición de peticiones y se está desarrollando activamente con más características.
   - **Instalación:** Descargar desde su sitio web oficial.

**Controlar Cuándo Interceptar Tráfico (Gestores de Proxy):**

Cambiar la configuración de proxy del navegador manualmente cada vez es un engorro. Extensiones como **FoxyProxy** (para Firefox, Chrome, etc.) facilitan enormemente este proceso:

- **FoxyProxy:**
  - Permite definir perfiles de proxy (e.g., uno para Burp en `127.0.0.1:8080`, otro para ZAP en `127.0.0.1:8090`).
  - Permite activar/desactivar el uso del proxy con un clic.
  - Permite crear reglas basadas en patrones de URL para usar automáticamente ciertos proxies para ciertos sitios.
  - **Instalación:** Buscar "FoxyProxy Standard" (o Basic) en la tienda de extensiones de tu navegador.

_Existen numerosos tutoriales y guías detalladas online que explican paso a paso cómo configurar Burp Suite, ZAP, Caido y FoxyProxy con diferentes navegadores._


# Entendiendo las Expresiones Regulares (RegEx)

Las Expresiones Regulares (o RegEx) son secuencias de caracteres que definen un patrón de búsqueda. Son extremadamente potentes para buscar, validar y manipular texto.

**¿Por qué son cruciales para un profesional de la ciberseguridad?**

- **Análisis de Logs:** Buscar patrones específicos (IPs, User-Agents maliciosos, códigos de error, rastros de ataques) en grandes volúmenes de logs del servidor o de aplicaciones.
- **Análisis de Código Fuente (Estático):** Identificar funciones potencialmente vulnerables, parámetros inseguros, o secretos hardcodeados en el código.
- **Desarrollo de Scripts (Automatización):** Parsear la salida de herramientas, extraer información específica de respuestas HTTP, o automatizar tareas que requieren encontrar patrones.
- **Web Scraping y Reconocimiento:** Extraer URLs, emails, comentarios, subdominios, o nombres de tecnologías de páginas web.
- **Bypass de WAFs/Filtros:** Entender cómo los WAFs usan RegEx para detectar payloads maliciosos puede ayudar a diseñar bypasses (aunque esto es avanzado).
- **Herramientas de Pentesting:** Muchas herramientas (incluyendo Burp Suite en su búsqueda, Intruder para extraer datos, etc.) permiten usar RegEx.

**Sintaxis y Componentes Clave de RegEx (Ejemplos Genéricos):**

- **Literales:** Caracteres que se buscan a sí mismos (e.g., `/abc/` busca "abc").
- **Metacaracteres (tienen significado especial):**
  - `.` : Cualquier carácter (excepto salto de línea, a menos que se especifique).
  - `^` : Inicio de una cadena o línea.
  - `$` : Fin de una cadena o línea.
  - `*` : Cero o más ocurrencias del carácter o grupo anterior.
  - `+` : Una o más ocurrencias.
  - `?` : Cero o una ocurrencia (hace que el anterior sea opcional).
  - `\` : Carácter de escape (e.g., `/\./` busca un punto literal).
  - `|` : Alternancia (OR). Ej: `/gato|perro/` busca "gato" o "perro".
  - `( )` : Agrupamiento (captura el grupo o aplica cuantificadores al grupo).
  - `[ ]` : Clase de caracteres (set). Ej: `/[aeiou]/` busca cualquier vocal. `/[0-9]/` busca cualquier dígito. `/[^0-9]/` busca cualquier cosa que NO sea un dígito.
  - `{n}` : Exactamente `n` ocurrencias.
  - `{n,}` : `n` o más ocurrencias.
  - `{n,m}` : Entre `n` y `m` ocurrencias.
- **Clases de Caracteres Abreviadas:**
  - `\d` : Dígito (equivalente a `[0-9]`).
  - `\D` : No dígito.
  - `\w` : Carácter de palabra (alfanumérico más guion bajo; `[a-zA-Z0-9_]`).
  - `\W` : No carácter de palabra.
  - `\s` : Carácter de espacio en blanco (espacio, tab, salto de línea, etc.).
  - `\S` : No carácter de espacio en blanco.
- **Modificadores (Flags) Comunes:**
  - `i` : Case-insensitive (ignora mayúsculas/minúsculas).
  - `g` : Global (encuentra todas las coincidencias, no solo la primera).
  - `m` : Multilínea (`^` y `$` coinciden con inicio/fin de línea, no solo de la cadena completa).

**Uso de RegEx en JavaScript (Ejemplos):**

```javascript
// Usando el constructor RegExp:
const regex1 = new RegExp('hola', 'i'); // Busca 'hola', case-insensitive

// Usando literales (forma más común y recomendada si la expresión es fija):
const regex2 = /mundo/g; // Busca 'mundo', globalmente

// Método test(): Devuelve true si hay coincidencia, false si no.
const regexTexto = /palabra_clave/;
console.log(regexTexto.test("Este texto contiene la palabra_clave secreta.")); // true
console.log(regexTexto.test("Otro texto sin ella."));                       // false

// Método exec(): Devuelve un array con la primera coincidencia (o null).
const regexEmail = /(\w+)@([\w.]+)/; // Grupo 1: usuario, Grupo 2: dominio
const resultadoEmail = regexEmail.exec("Mi email es usuario@ejemplo.com y otro es test@mail.net");
if (resultadoEmail !== null) {
  console.log("Coincidencia completa:", resultadoEmail[0]); // usuario@ejemplo.com
  console.log("Usuario:", resultadoEmail[1]);             // usuario
  console.log("Dominio:", resultadoEmail[2]);             // ejemplo.com
}

// Método match() (de String):
const textoLargo = "Encuentra la palabra error y también ERROR aquí.";
const coincidenciasError = textoLargo.match(/error/gi); // Busca "error", global, case-insensitive
console.log(coincidenciasError); // ["error", "ERROR"]

// Método replace() (de String):
const textoConEspacios = "Esto   tiene    muchos   espacios.";
const textoCorregido = textoConEspacios.replace(/\s+/g, ' '); // Reemplaza uno o más espacios por uno solo
console.log(textoCorregido); // "Esto tiene muchos espacios."
```

**Aplicaciones Prácticas de RegEx en Hacking (Conceptuales):**

- **Buscar IPs en un log:** `/\b(?:\d{1,3}\.){3}\d{1,3}\b/g`
- **Extraer URLs de un HTML:** `/<a\s+(?:[^>]*?\s+)?href="([^"]*)"/gi` (simplificado, puede fallar con HTML complejo)
- **Identificar comentarios en código JS que puedan tener secretos:** `/\/\/\s*TODO:.*|\/\*[\s\S]*?SECRET[\s\S]*?\*\//g`
- **En Burp Intruder (Grep - Extract):** Para extraer tokens CSRF, IDs de sesión, o datos específicos de las respuestas durante un fuzzing. Se define una RegEx que capture el dato deseado.

**Herramientas para Trabajar con RegEx:**

- **[regex101.com]():**
  - Plataforma online indispensable para construir, probar y depurar expresiones regulares.
  - Permite seleccionar diferentes "sabores" de RegEx (PCRE, Python, JavaScript, Go, etc.).
  - Muestra una explicación detallada de cómo funciona tu RegEx paso a paso.
  - Tiene un panel de referencia rápida (cheatsheet) y permite guardar y compartir tus expresiones.

Dominar RegEx lleva tiempo y práctica, pero la inversión merece la pena por la potencia que te da para analizar y manipular texto.
