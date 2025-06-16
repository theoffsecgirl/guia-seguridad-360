# Uso de /etc/hosts en Pentesting y Bug Bounty


### ¿Qué es el fichero `/etc/hosts`?

El fichero `/etc/hosts` es, básicamente, la agenda de contactos de tu ordenador para nombres de dominio. Es un simple archivo de texto que permite **mapear nombres de host (como `mi-web.local`) a direcciones IP (como `192.168.1.100`) directamente en tu máquina.**

Este fichero ha sido una parte fundamental del funcionamiento de las redes desde los inicios de ARPANET, antes incluso de que el sistema DNS (Domain Name System) que conocemos hoy existiera de forma masiva.

### ¿Por Qué Funciona y Cuál es su Mecanismo?

Cuando intentas acceder a un nombre de dominio (e.g., al escribir `ejemplo.com` en tu navegador), tu sistema operativo sigue una secuencia para resolver ese nombre a una IP. La clave está en el orden:

1. **Primera Parada: El Fichero `/etc/hosts`:** Tu ordenador mira **PRIMERO** en este fichero. Si encuentra una entrada que coincide con el nombre de host que buscas, usa la IP mapeada ahí y el proceso de resolución termina. No pregunta a nadie más.
2. **Anulación Local (Override):** Debido a que se comprueba primero, `/etc/hosts` tiene **prioridad sobre cualquier servidor DNS**. Actúa como un mecanismo de anulación local. Puedes hacer que `google.com` apunte a tu propia máquina (`127.0.0.1`) si te da la gana, y tu navegador te hará caso.
3. **Mapeo Directo e Instantáneo:** Proporciona una correspondencia directa, sin necesidad de realizar consultas de red a servidores DNS externos.
4. **Sin Caché DNS:** Los cambios que haces en `/etc/hosts` suelen tener efecto inmediato (o casi), sin tener que lidiar con la caché de DNS de tu sistema o de la red.

**¿Y por qué no funciona sin una entrada?** Si el nombre de host no está en tu fichero `/etc/hosts`, tu ordenador inicia el proceso estándar de resolución DNS: comprueba su caché local, luego pregunta a los servidores DNS que tiene configurados (los de tu router, los de tu proveedor de Internet, o los que hayas puesto tú como los de Google o Cloudflare), y espera una respuesta. Si el nombre no está registrado en el DNS público, la resolución fallará.

### Casos de Uso en Pentesting y Bug Bounty

Para nosotros, `/etc/hosts` es una herramienta de trabajo, no solo un archivo de configuración.

1. **Acceder a Aplicaciones Internas o No Públicas:**
   - Durante el reconocimiento, puedes encontrar subdominios como `internal-dev.empresa-objetivo.com` que resuelven a una IP privada (e.g., `10.0.5.20`). Si tienes acceso a esa red (e.g., a través de una VPN o un host comprometido), necesitas añadir esa entrada a tu `/etc/hosts` para que tu navegador y herramientas sepan cómo llegar.
2. **Pruebas de Hosts Virtuales (VHosts):**
   - A veces, una única dirección IP aloja múltiples sitios web. El servidor web sabe qué sitio mostrar basándose en la cabecera `Host` de la petición HTTP. Si descubres un VHost (e.g., `secreto.empresa-objetivo.com`) que apunta a una IP conocida, puedes añadirlo a tu `/etc/hosts` para que tu navegador envíe la cabecera `Host` correcta y te muestre el sitio oculto.
3. **Bypass de Protecciones Basadas en DNS (WAFs, etc.):**
   - Si un WAF o un CDN (como Cloudflare) se encuentra delante de la IP real del servidor web, puedes usar `/etc/hosts` para apuntar el dominio directamente a la IP del servidor de origen (si la descubres), permitiéndote bypassar estas protecciones perimetrales.
4. **Bloqueo de Dominios (Uso Defensivo/Práctico):**
   - Puedes redirigir dominios de telemetría, publicidad o malware a `127.0.0.1` para que no se pueda contactar con ellos desde tu máquina.

### Ejemplo Práctico: Configuración en un Entorno con VPS

Es una práctica muy común y recomendada en pentesting no lanzar herramientas directamente desde tu portátil personal. En su lugar, se usa un **VPS (Virtual Private Server)** en la nube como "máquina de ataque".

- **¿Por Qué Usar un VPS?:**
  - **Aislamiento y Seguridad:** Mantiene las herramientas y el tráfico del pentest separados de tu máquina personal.
  - **IP Pública Estática:** Te da una IP fija y una conexión a internet rápida y estable.
  - **Entorno Limpio:** Puedes tener un entorno Linux limpio y preparado solo para tus herramientas de hacking.

**Configuración de `/etc/hosts` en un Escenario con VPS:**

Imagina que descubres que el host `internal.agamemnon.ctfio.com` existe y, haciendo `ping`, descubres que apunta a una IP específica `[DIRECCIÓN_IP_DEL_PING]`.

Para poder interactuar con este host, necesitas configurar `/etc/hosts` en **DOS sitios**:

1. **En el VPS:**

   - Editas `/etc/hosts` en tu VPS para añadir la línea: `[DIRECCIÓN_IP_DEL_PING] internal.agamemnon.ctfio.com`
   - **¿Por qué?** Para que las herramientas que ejecutas en la terminal del VPS (como `curl`, `nmap`, `gobuster`, `sqlmap`) sepan cómo resolver ese nombre de host y dirigir el tráfico a la IP correcta.
2. **En tu Portátil Personal:**

   - Editas `/etc/hosts` en tu máquina local (Windows, macOS, Linux) para añadir la misma línea: `[DIRECCIÓN_IP_DEL_PING] internal.agamemnon.ctfio.com`
   - **¿Por qué?** Para que tu **navegador** sepa cómo llegar al sitio. Esto te permite navegar por la aplicación mientras el tráfico pasa por tu proxy local (Burp Suite, ZAP), que es donde harás la mayor parte del análisis manual.

**En resumen:** Tu portátil necesita la entrada para el navegador y Burp, y tu VPS la necesita para las herramientas de línea de comandos.

### Consejos Prácticos (Pro Tips)

1. **Haz Siempre una Copia de Seguridad:** Antes de editar el fichero, haz una copia: `sudo cp /etc/hosts /etc/hosts.bak`. Si la lías, puedes restaurarlo.
2. **Usa Comentarios:** Utiliza comentarios (líneas que empiezan con `#`) para documentar por qué añadiste cada entrada. Esto es muy útil cuando tienes mapeos para diferentes proyectos o programas de bug bounty.

   ```
   # --- Programa Bug Bounty Acme Corp ---
   10.10.20.5    intranet.acme.com  # Servidor interno descubierto
   10.10.20.6    dev-portal.acme.com
   ```
3. **Sintaxis Correcta:** La sintaxis es simple: `DIRECCION_IP nombredehost1 [nombredehost2 ...]` . Una IP por línea, seguida de uno o más nombres de host separados por espacios o tabulaciones.
4. **Privilegios de Administrador:** Necesitas privilegios de `sudo` (en Linux/macOS) o de Administrador (en Windows) para editar este fichero.
5. **Limpiar la Caché DNS (si es necesario):** Aunque los cambios suelen ser inmediatos, en algunos sistemas o situaciones puede ser necesario limpiar la caché de DNS para que los cambios se apliquen.

   - **Windows:** `ipconfig /flushdns`
   - **macOS:** `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
   - **Linux (systemd):** `sudo systemd-resolve --flush-caches`

### Alternativas Modernas para Casos de Uso Específicos

Aunque `/etc/hosts` es fundamental, para pruebas puntuales a veces es más cómodo usar opciones de tus herramientas:

- **`curl --resolve`:** Te permite especificar la resolución para una sola ejecución de `curl`.

  ```bash
  curl --resolve "ejemplo.com:443:1.2.3.4" https://ejemplo.com/
  ```
- **Burp Suite:** En `Project options -> Connections -> Hostname Resolution`, puedes añadir tus propias reglas de resolución que solo afectarán al tráfico que pase por Burp.
