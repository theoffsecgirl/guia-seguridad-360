# Qué es /etc/hosts

- El fichero /etc/hosts mapea nombres de host a direcciones IP de forma local y se consulta antes que el resolver DNS si así lo establece la política del sistema, permitiendo anular resoluciones sin depender de servidores externos.[^1]
- Esta capacidad de “override” es inmediata y muy útil para pruebas controladas de enrutamiento, vhosts y escenarios de laboratorio sin tocar DNS público.[^1]

## Precedencia y orden de resolución

- En Linux, el orden de búsqueda lo define /etc/nsswitch.conf en la directiva hosts, donde “files” representa /etc/hosts y “dns” el resolver configurado; colocando “files dns” se prioriza el fichero local frente a DNS.[^1]
- Cambiar ese orden explica por qué algunas herramientas resuelven por hosts y otras consultan DNS primero; ajustarlo evita sorpresas cuando se necesita override local.[^5]

## Rutas por sistema operativo

- Linux y macOS usan /etc/hosts (en macOS el fichero real reside en /private/etc/hosts, enlazado desde /etc).[^6]
- En Windows el fichero se encuentra en C:\Windows\System32\drivers\etc\hosts y requiere permisos de administrador para editarlo.[^6]

## Casos ofensivos frecuentes

- Acceder a apps internas o no publicadas: cuando se conoce la IP interna (VPN, salto), añadir el FQDN al hosts local permite que el navegador y herramientas apunten al destino correcto.[^1]
- Pruebas de vhosts: en IPs que alojan múltiples sitios, mapear dominio→IP fuerza a que el servidor devuelva el sitio correcto según la cabecera Host.[^1]
- Bypass de CDN/WAF hacia origin: si se descubre la IP de origen, mapear el dominio al origin permite probar controles de la aplicación sin el intermediario (siempre dentro de scope).[^1]

## Alternativas sin editar hosts

- cURL: usar --resolve para “anclar” host:puerto→IP solo en esa petición, poblando la caché DNS interna de cURL y evitando tocar el sistema.[^8]
- Burp Suite: en Project settings → DNS/Connections, “Hostname resolution overrides” mapea dominios a IPs a nivel de proyecto, ideal para navegadores en proxy y clientes no conscientes de proxy.[^10]

## Ejemplos prácticos

- cURL con --resolve

```bash
curl --resolve "ejemplo.com:443:1.2.3.4" https://ejemplo.com/
```

Este comando fuerza a cURL a conectar a 1.2.3.4 para ejemplo.com:443 sin editar el sistema.[^2]

- Burp: añadir una regla “Hostname resolution overrides” con Hostname=objetivo.tld e IP=origen para que todo el tráfico proxificado use esa IP.[^9]

## Flujo VPS + portátil (recomendado)

- VPS: añadir el FQDN al hosts del VPS para que herramientas CLI (curl, nmap, sqlmap) resuelvan al destino deseado desde una IP pública aislada.[^1]
- Portátil: añadir el mismo mapeo o usar overrides de Burp para navegar y capturar en proxy sin depender del DNS del sistema.[^9]

## Limpieza de caché DNS (cuando aplique)

- Linux con systemd-resolved/resolvectl: sudo systemd-resolve --flush-caches o sudo resolvectl flush-caches, y verificar con resolvectl statistics.[^12]
- macOS (versiones recientes): sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder.[^14]
- Windows: ipconfig /flushdns desde consola con privilegios elevados.[^13]

## Consejos y advertencias

- Hacer copia de seguridad antes de editar: sudo cp /etc/hosts /etc/hosts.bak en Unix o guardar una copia del hosts en Windows.[^6]
- Documentar entradas con comentarios y mantenerlas por proyecto para evitar conflictos y olvidos al cambiar de objetivo.[^6]
- Recordar que HSTS/SNI y políticas de TLS pueden afectar pruebas si el certificado no coincide con el nombre presentado; en esos casos, preferir --resolve o overrides de Burp para mantener la semántica de nombre.[^9]
  <span style="display:none">[^18][^22][^26][^30][^34][^38][^41]</span>


[^1]: https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html
    
[^2]: https://curl.se/libcurl/c/CURLOPT_RESOLVE.html
    
[^3]: https://www.computernetworkingnotes.com/linux-tutorials/the-etc-hosts-etc-resolv-conf-and-etc-nsswitch-conf-files.html
    
[^4]: https://forums.opensuse.org/t/precedence-of-etc-hosts-file/20360
    
[^5]: https://bbs.archlinux.org/viewtopic.php?id=280658
    
[^6]: https://www.liquidweb.com/blog/edit-host-file-windows-10/
    
[^7]: https://www.knownhost.com/blog/how-to-view-a-hosts-file-location-edit/
    
[^8]: https://everything.curl.dev/usingcurl/connections/name.html
    
[^9]: https://portswigger.net/burp/documentation/desktop/settings/network/dns
    
[^10]: https://portswigger.net/burp/documentation/desktop/settings/network/connections
    
[^11]: https://www.baeldung.com/linux/dns-cache-local-flushing
    
[^12]: https://github.com/systemd/systemd/issues/940
    
[^13]: https://kinsta.com/blog/flush-dns/
    
[^14]: https://www.freecodecamp.org/news/how-to-flush-dns-on-mac-macos-clear-dns-cache/
    
[^15]: 01g-uso-de-etc-hosts.md
    
[^16]: https://support.nagios.com/forum/viewtopic.php?t=48478
    
[^17]: https://www.linkedin.com/pulse/quick-guide-windows-host-file-location-access-1bytecom-halec
    
[^18]: https://www.reddit.com/r/24hoursupport/comments/k8ex8/what_is_the_difference_between_a_hosts_file/
    
[^19]: https://stackoverflow.com/questions/38086045/use-curl-resolve-with-http-proxy
    
[^20]: https://learn.microsoft.com/en-us/answers/questions/4310469/host-file
    
[^21]: https://acquia.my.site.com/s/article/360005257154-Use-cURL-s-resolve-option-to-pin-a-request-to-an-IP-address
    
[^22]: https://www.nublue.co.uk/guides/edit-hosts-file/
    
[^23]: https://curl.se/docs/manpage.html
    
[^24]: https://answers.microsoft.com/en-us/windows/forum/all/host-file/02799272-f9fc-4492-9060-315ed1f3e718
    
[^25]: https://man.archlinux.org/man/CURLOPT_RESOLVE.3.en
    
[^26]: https://support.norton.com/sp/es/mx/home/current/solutions/v72822654
    
[^27]: https://docs.pantheon.io/guides/launch/advanced-curls/
    
[^28]: https://discussions.apple.com/thread/255094690
    
[^29]: https://macpaw.com/how-to/clear-dns-cache-on-mac
    
[^30]: https://www.tp-link.com/es/support/faq/860/
    
[^31]: https://help.dreamhost.com/hc/en-us/articles/214981288-Flushing-your-DNS-cache-in-Mac-OS-X-and-Linux
    
[^32]: https://www.hoswedaje.com/web/como-hacer-un-flush-dns-en-mac/
    
[^33]: https://serveravatar.com/flush-dns-cache-on-any-system/
    
[^34]: https://github.com/TechSupportJosh/HostsLoader
    
[^35]: https://manage.accuwebhosting.com/knowledgebase/3672/How-to-Flush-DNS-Cache-on-Linux.html
    
[^36]: https://mwalkowski.com/post/resolving-hostnames-in-burp-how-to-avoid-editing-the-etc-hosts-file/
    
[^37]: https://www.siteground.es/kb/limpiar-cache-local-dns-linux/
    
[^38]: https://portswigger.net/burp/documentation/desktop/testing-workflow/mapping/hidden-content/hostname-discovery
    
[^39]: https://www.reddit.com/r/kde/comments/106ycil/how_to_i_flush_dns_in_plasma/
    
[^40]: https://portswigger.net/burp/documentation/desktop/settings/tools/proxy
    
[^41]: https://www.remoteutilities.com/support/kb/how-to-flush-the-dns-resolver-cache-on-windows-macos-and-linux/
