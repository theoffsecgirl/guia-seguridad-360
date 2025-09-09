# Resumen de Herramientas de Reconocimiento

Aquí tienes una lista de referencia rápida, categorizada por objetivo, con todas las herramientas que hemos mencionado en el capítulo de Reconocimiento.

---

### Descubrimiento de Subdominios y Activos

* **Pasivo/OSINT:** `crt.sh`, `censys.io`, Google Dorks, `amass intel`, `gau`, `waybackurls`.
* **Activo/Fuerza Bruta:** `amass enum`, `subfinder`, `assetfinder`, `massdns` (para resolver), `ffuf` (para vhost).
* **Permutaciones:** `gotator`, `dnsgen`.
* **Validación:** `dnsx`.

### Fingerprinting de Tecnologías

* `httpx`
* `whatweb`
* Wappalyzer (extensión y CLI)
* `nuclei` (con plantillas de detección)

### Escaneo de Puertos

* `nmap`
* `masscan`

### Descubrimiento de Contenido Web

* **Crawlers:** Burp Suite Spider, `gospider`, `hakrawler`, `katana`.
* **Fuerza Bruta Dir/File:** `dirsearch`, `ffuf`, `wfuzz`, `gobuster`.
* **Análisis JS:** `LinkFinder`, `SecretFinder`, `relative-url-extractor`.
* **Visual Recon:** `aquatone`, `webscreenshot`, `gowitness`.

### Proxy General

* Burp Suite
* OWASP ZAP
* Caido
