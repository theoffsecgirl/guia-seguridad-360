# Reconocimiento Activo: Interactuando con el Objetivo

A diferencia del reconocimiento pasivo, el **Reconocimiento Activo** implica interactuar directamente con la infraestructura del objetivo. Estas técnicas son más "ruidosas" (pueden ser detectadas por firewalls o sistemas de detección de intrusos), pero a cambio nos proporcionan información mucho más precisa y en tiempo real.

> **⚠️ Advertencia si estas en un programa Bug Bounty:** ¡Ojo con el scope del programa! El escaneo de puertos agresivo y otras técnicas activas pueden estar prohibidas o limitadas en algunos programas de Bug Bounty. Revisa siempre las reglas antes de lanzar cualquier herramienta de reconocimiento activo.

---

## Descubrimiento Activo de Subdominios

Podemos buscar subdominios de forma activa para complementar los resultados de las fuentes pasivas.

### Fuerza Bruta de Subdominios

Esta técnica consiste en utilizar diccionarios para intentar "adivinar" subdominios válidos.

* **Herramientas Comunes:** `subfinder`, `assetfinder`, `amass enum`, `massdns`, y `ffuf` para fuerza bruta de VHosts.
* **Wordlists Esenciales:** Se recomienda usar listas de calidad como las de SecLists (ej. `Subdomains/top1mil-110000.txt`).
* **Ejemplo con `ffuf` (VHost Brute-Forcing):**
  ```bash
  ffuf -w wordlist.txt -H "Host: FUZZ.target.com" -u [https://target.com](https://target.com)
  ```

### Permutation Scanning

Consiste en generar posibles subdominios alterando los que ya conocemos (ej. si encuentras `dev-api.target.com`, la herramienta prueba variaciones como `test-api.target.com`).

* **Herramientas Comunes:** `gotator`, `dnsgen`.

### Validación y Resolución

Una vez generada una lista grande de posibles subdominios, es crucial verificar cuáles están realmente "vivos" y resuelven a una IP.

* **Herramientas Comunes:** `dnsx`, `massdns` y, para probar también conectividad web (HTTP/S), `httpx`.

---

## Escaneo de Puertos y Servicios

Esta técnica permite identificar qué servicios se están ejecutando en los servidores, más allá de los puertos web. Descubrir un puerto FTP, SSH o una base de datos expuesta puede abrir una nueva vía de ataque.

* **Herramientas Clave:** `nmap` y `masscan`.

### Ejemplos Prácticos con `nmap`

`nmap` es la navaja suiza para el escaneo de puertos.

* **Escaneo Básico y Potente:** Detecta versiones y ejecuta scripts básicos.

  ```bash
  nmap -sV -sC -T4 <IP_o_HOST>
  ```

  * `-sV`: Detección de versiones de los servicios.
  * `-sC`: Ejecuta scripts de enumeración por defecto.
  * `-T4`: Acelera el escaneo (puede ser más detectable).
* **Escaneo de Todos los Puertos TCP:** Para un análisis exhaustivo.

  ```bash
  nmap -p- <IP_o_HOST>
  ```
* **Escaneo de Puertos UDP:** Más lento, pero puede revelar servicios DNS o SNMP.

  ```bash
  nmap -sU -p 53,161 <IP_o_HOST>
  ```

### Escaneo Rápido con `masscan`

`masscan` es extremadamente rápido para escanear grandes rangos de IPs en busca de puertos específicos.

* **Ejemplo:**
  ```bash
  masscan -p80,443,8080 <RANGO_IP> --rate=1000
  ```

---

## Fingerprinting de Tecnologías y Servicios

Una vez identificados los puertos abiertos, necesitamos saber qué software y versión se está ejecutando.

* **Técnicas Manuales:**
  * **Análisis de Cabeceras HTTP:** Cabeceras como `Server`, `X-Powered-By`, o `Set-Cookie` pueden revelar el servidor web, el lenguaje y el framework.
  * **Análisis de Contenido Web:** Patrones en el HTML, comentarios o rutas (`/wp-content/`) delatan la tecnología.
  * **Favicon Hashing:** Comparar el hash del favicon de la web con bases de datos de hashes conocidos para identificar tecnologías.
* **Herramientas Automatizadas:**
  * **`httpx`:** Puede realizar fingerprinting tecnológico de forma masiva. El siguiente comando es un ejemplo de un pipeline completo:
    ```bash
    cat subdominios.txt | httpx -tech-detect -status-code -title -silent
    ```
  * **Otras Herramientas:** `whatweb`, Wappalyzer (extensión y CLI), y `nuclei` con plantillas de detección.
