# Configuración del Entorno


Para practicar las técnicas de esta guía, montar un laboratorio es esencial. Empezaremos con un laboratorio local y virtualizado, y luego exploraremos plataformas online.

## Por qué un laboratorio local
- Seguridad: aislamos experimentos de nuestro sistema.
- Legalidad y ética: solo atacamos sistemas propios.
- Flexibilidad: probar, romper y restaurar sin riesgo.

***

## Paso 1: Software de virtualización
Elegimos un gestor de máquinas virtuales.

### Opción A: VirtualBox (gratuito)
- Compatible con Windows/macOS/Linux.
- Descarga oficial: https://www.virtualbox.org/wiki/Downloads

### Opción B: VMware (industria)
- Usados en entornos corporativos.
- Versiones gratuitas robustas.
- Descarga:
  - Windows/Linux: https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html
  - macOS: https://www.vmware.com/products/fusion/fusion-evaluation.html

***

## Paso 2: Máquina atacante (Kali Linux)
Sistema con herramientas de hacking.

- Descarga https://www.kali.org/get-kali/#kali-virtual-machines para tu virtualizador.
- En VirtualBox: Archivo > Importar servicio virtualizado (> .ova).
- En VMware: File > Open (> carpeta descomprimida).

***

## Paso 3: Máquinas víctimas vulnerables
Objetivos deliberadamente inseguros para practicar.

- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- Metasploitable 2: https://information.rapid7.com/download-metasploitable-2.html

***

## Paso 4: Plataformas online
Para complementar tu laboratorio.

- PortSwigger Web Academy: https://portswigger.net/web-security (gratuita)
- TryHackMe: https://tryhackme.com (guiado para principiantes)
- Hack The Box: https://www.hackthebox.com (avanzado, menos guías)
- Dockerlabs: https://github.com/vulhub/vulhub (contenedores docker vulnerables)

***

## Paso 5: Red local
Configura NAT para conectar VMs a internet sin riesgos.

- VirtualBox: Configuración > Red > NAT
- VMware: VM > Settings > Network Adapter > NAT

***

## Paso 6: Herramientas dentro de Kali

- Burp Suite Community: https://portswigger.net/burp/communitydownload
- VS Code: sudo apt update && sudo apt install code -y

***

## Paso 7: Personalización con dotfiles

Para replicar mi entorno:

```bash
# Clonar repo:
git clone https://github.com/theoffsecgirl/dotfiles.git
