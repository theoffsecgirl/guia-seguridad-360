# Configuración del Entorno: Tu Laboratorio Hacker

Para poder practicar las técnicas que veremos en esta guía, es absolutamente esencial que construyamos nuestro propio laboratorio de hacking. Empezaremos con un laboratorio local y virtualizado y luego exploraremos las plataformas de entrenamiento online.

**¿Por qué es tan importante un laboratorio local?**

* **Seguridad:** Mantiene los experimentos aislados de tu sistema principal.
* **Legalidad y Ética:** Nos permite atacar sistemas que hemos montado nosotros mismos.
* **Flexibilidad:** Nos permite probar, romper y restaurar sistemas a voluntad sin consecuencias reales.

---

## Paso 1: Elige tu Software de Virtualización

Necesitamos un programa que gestione nuestras máquinas virtuales (ordenadores dentro de nuestro ordenador).

#### **Opción A: VirtualBox (Gratuito y Open Source)**

* **Descripción:** La opción perfecta para empezar. Es potente, completamente gratuita y funciona en Windows, macOS y Linux.
* **➡️ Acción:** Descarga e instala la última versión de VirtualBox desde su [página web oficial](https://www.virtualbox.org/wiki/Downloads).

#### **Opción B: VMware (Estándar de la Industria)**

* **Descripción:** Muy utilizado en entornos corporativos. Sus versiones gratuitas para uso personal son muy robustas.
* **➡️ Acción:** Descarga e instala la versión gratuita correspondiente a tu sistema:
  * **Para Windows/Linux:** [VMware Workstation Player](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html)
  * **Para macOS:** [VMware Fusion Player](https://www.vmware.com/products/fusion/fusion-evaluation.html)

---

## Paso 2: Tu Máquina de Ataque (Kali Linux)

Necesitamos un sistema operativo cargado con herramientas de hacking. Usaremos Kali Linux.

**➡️ Acción: Descarga e Importa**

1. Ve a la [página oficial de descargas de Kali Linux para máquinas virtuales](https://www.kali.org/get-kali/#kali-virtual-machines) y descarga la imagen que corresponda a tu software de virtualización (VirtualBox o VMware).
2. **En VirtualBox:** Usa `Archivo > Importar servicio virtualizado...` con el archivo `.ova`.
3. **En VMware:** Usa `File > Open...` y selecciona el archivo `.vmx` de la carpeta descomprimida.

---

## Paso 3: Tus Máquinas Víctima Locales (El Gimnasio en Casa)

Necesitamos objetivos deliberadamente vulnerables para practicar en nuestro entorno local.

**➡️ Acción:** Descarga e importa al menos estas dos:

* **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/):** La mejor para hacking web.
* **[Metasploitable 2](https://information.rapid7.com/download-metasploitable-2.html):** Un clásico para vulnerabilidades de red.

---

## Paso 4: Plataformas de Entrenamiento Online (El Gimnasio en la Nube)

Además de tu laboratorio local, existen plataformas online increíbles para aprender y practicar.

#### **PortSwigger Web Security Academy**

* **Qué es:** La biblia del hacking web, creada por los desarrolladores de Burp Suite. Contiene laboratorios de altísima calidad para cada tipo de vulnerabilidad web.
* **Ideal para:** Aprender y dominar vulnerabilidades web específicas de forma aislada.
* **➡️ Acción:** [Accede a la academia aquí](https://portswigger.net/web-security). Es gratuita.

#### **TryHackMe**

* **Qué es:** Una plataforma muy popular con "habitaciones" (rooms) guiadas que te enseñan conceptos desde cero.
* **Ideal para:** Principiantes que buscan un camino de aprendizaje estructurado.
* **➡️ Acción:** [Empieza en TryHackMe](https://tryhackme.com/).

#### **Hack The Box (HTB)**

* **Qué es:** Una plataforma más desafiante con máquinas que simulan entornos reales. Hay menos guías y se espera que investigues más por tu cuenta.
* **Ideal para:** Poner a prueba tus habilidades y prepararte para certificaciones como el OSCP.
* **➡️ Acción:** [Únete a Hack The Box](https://www.hackthebox.com/).

#### **Laboratorios con Docker (Dockerlabs)**

* **Qué es:** Una forma moderna y ligera de levantar entornos vulnerables específicos usando contenedores de Docker, sin necesidad de una máquina virtual completa.
* **Ideal para:** Usuarios un poco más avanzados que quieren probar un exploit para una tecnología concreta rápidamente.
* **➡️ Acción:** Explora colecciones como [Vulhub en GitHub](https://github.com/vulhub/vulhub), un repositorio masivo de entornos vulnerables pre-configurados.

---

## Paso 5: Configuración de la Red Local

Esta configuración es para tus máquinas virtuales locales (Kali, Metasploitable, etc.).

**➡️ Acción:** Para cada una de tus máquinas virtuales, configúralas en modo **"Red NAT"** para mantenerlas en una red segura pero con acceso a internet.

* **En VirtualBox:** `Configuración > Red > Conectado a: Red NAT`.
* **En VMware:** `Virtual Machine > Settings > Network Adapter > NAT`.

---

## Paso 6: Herramientas Esenciales Adicionales

Instala estas herramientas **dentro de tu máquina virtual Kali**.

**➡️ Acción:**

1. **Burp Suite Community:** Descárgalo desde la [web de PortSwigger](https://portswigger.net/burp/communitydownload).
2. **VS Code:** Instálalo con `sudo apt update && sudo apt install code -y`.

---

## Paso 7 (Opcional): Personaliza tu Entorno con mis Dotfiles

Mis "dotfiles" son mi configuración personal para la terminal. Si los instalas, tu entorno se verá y comportará como el mío.

**➡️ Acción (dentro de tu máquina virtual Kali):**

```bash
# Clona el repositorio desde GitHub
git clone https://github.com/theoffsecgirl/dotfiles.git

# Entra en la nueva carpeta y ejecuta el script de instalación
cd dotfiles
# Consejo: Revisa siempre un script antes de ejecutarlo (ej. con 'cat install.sh')
./install.sh
```
