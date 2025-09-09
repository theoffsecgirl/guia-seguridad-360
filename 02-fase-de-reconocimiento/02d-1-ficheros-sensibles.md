# Técnica profunda: ficheros sensibles expuestos

Exponer archivos y directorios como .git, .env, docker-compose.yml o wp-config.php suele otorgar acceso directo a secretos, código y arquitectura, siendo de las rutas más rápidas hacia hallazgos críticos si se manejan con mínima intrusión y buena redacción de evidencias.[^1]
El vector típico nace en despliegues rápidos o configuraciones por defecto; priorizar detección con wordlists sólidas y herramientas de fuerza bruta/controlada es clave para reducir ruido y obtener señal útil.[^1]

## La mina de oro: .git expuesto[^1]

Qué contiene y por qué importa

- HEAD, config, index, refs y objects permiten reconstruir el repo completo, recuperar historial y secretos que incluso se “borraron” en commits posteriores.[^1]
- Con el repo reconstruido, se extraen tokens, endpoints internos, claves y credenciales históricas que a menudo siguen vigentes en otros entornos.[^1]

Herramientas y explotación segura

- git-dumper: descarga recursiva de .git con control de concurrencia y timeouts; ideal para automatizar extracción inicial.[^3]
- GitTools (Dumper/Extractor): pipeline clásico para volcar .git y reconstruir el árbol de trabajo en limpio.[^5]
- Alternativas: GitDump y variantes optimizadas que lidian mejor con packfiles y listados deshabilitados.[^7]

Ejemplo rápido

```bash
# Volcar el repo .git
git-dumper https://target.tld/.git ./dump
# Extraer árbol de trabajo (GitTools)
./Extractor/extractor.sh ./dump ./worktree
```

Buenas prácticas

- Limitarse a ficheros imprescindibles para PoC; no publicar repos completos en reportes, solo hashes/rutas redactadas y pruebas mínimas.[^1]
- Si solo hay packfiles sin listing, documentar limitación y aportar evidencia de acceso a HEAD/config/index como prueba suficiente.[^5]

## Otros ficheros críticos a cazar[^1]

Contenedores y orquestación

- docker-compose.yml: revela servicios, puertos, dependencias y variables sensibles en claro; base para entender arquitectura y pivotar.[^1]
- Dockerfile: muestra imagen base, paquetes y usuarios; útil para CVEs por versión y rutas a artefactos copiados.[^1]

Configuración y secretos

- .env: variables de entorno con credenciales de DB, tokens de terceros y claves de cifrado; tratarlo como “alto riesgo” y redactar en reportes.[^1]
- wp-config.php: parámetros DB_NAME/DB_USER/DB_PASSWORD y salts, acceso total a WordPress si expuesto.[^9]

Dependencias y builds

- package.json/composer.json/requirements.txt/Gemfile: inventario de librerías y versiones para correlacionar CVEs.[^1]
- .npmrc: tokens _authToken o registro privado; acceso a paquetes internos si siguen vigentes.[^1]

Entornos de desarrollo y temporales

- .vscode/.idea: rutas locales, configuraciones de debug y scripts de arranque, a veces con flags sensibles.[^1]
- .swp: restos de edición que pueden contener el contenido íntegro de ficheros críticos como wp-config.php.[^1]

## Cómo encontrarlos sin ruido[^1]

Wordlists de calidad

- SecLists (Discovery/Web-Content) como base; instalar vía sistema o clonar el repo para listas “common”, extensiones y rutas por tecnología.[^2]
- Ubicación típica en distros de pentest: /usr/share/seclists/Discovery/Web-Content/common.txt.[^12]

Fuerza bruta controlada

```bash
# Fuzzing base (códigos útiles)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403
```

Recursividad eficiente

```bash
# Recursivo con límites para descubrir subrutas
feroxbuster -u https://target.tld -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -x php,txt,zip,sql -s 200,204,301,302,307,401,403 -d 2
```

Dorks pasivos útiles

- site:target.tld inurl:.git -github.com y site:target.tld ext:env ("DB_PASSWORD" OR "AWS_SECRET") para indicios previos antes de tocar el objetivo.[^1]

## Validación mínima y reporte[^1]

Pruebas deterministas y breves

- .git: demostrar lectura de .git/HEAD y .git/config con curl y evidenciar repo remoto/branch; opcionalmente, un archivo inofensivo del worktree.[^5]
- .env/wp-config.php: mostrar solo claves redactadas y estructura; nunca volcar secretos en claro en el reporte.[^8]

Plantilla de PoC

```
Impacto: acceso a secretos/código (confidencialidad) con posibilidad de pivot a DB/infra.
Pasos: 1) URL exacta del fichero/directorio, 2) request/response mínima, 3) evidencia redactada (líneas/keys).
Severidad: Alta (exposición de credenciales/código).
Mitigación: restringir acceso, mover secretos a gestor (Vault/SSM), eliminar artefactos del docroot.
```

## Mitigaciones recomendadas (para el informe)[^1]

- Bloquear acceso a directorios de control y archivos de configuración vía servidor web (deny a .git, .env, wp-config.php y patrones equivalentes).[^1]
- Externalizar secretos a gestores (Vault, AWS/GCP/Azure Secrets) y evitar guardarlos en .env en producción; si se usan .env, restringir permisos y ubicación fuera del docroot.[^1]
- Rotar credenciales comprometidas y revisar uso de tokens (NPM/.npmrc); desactivar artefactos legacy y purgar backups/logs del docroot.[^1]
- Revisar imagen base y dependencias declaradas en Dockerfile/manifest para actualizar CVEs conocidos.[^1]

## Checklists rápidos[^1]

Detección

- ¿Existen .git, .env, docker-compose.yml, Dockerfile, wp-config.php, backups (.zip/.bak/.sql) o logs accesibles?[^1]
- ¿Se listaron endpoints de API y docs (swagger.json, /openapi, /docs) durante el crawling?[^1]

Evidencias

- Requests/Responses mínimas, datos sensibles redactados, timestamps, y rutas exactas; nada masivo ni dumps completos.[^1]

Cierre

- Severidad justificada por impacto/alcance, mitigación concreta y confirmación de cumplimiento de alcance del programa.[^1]

Referencias útiles

- git-dumper y GitTools para volcado/extracción de .git.[^5]
- feroxbuster para descubrimiento recursivo eficiente.[^15]
- SecLists (Discovery/Web-Content) para wordlists de alta calidad.[^16]
- wp-config.php: claves y estructura que justifican criticidad si quedan expuestas.[^8]
  <span style="display:none">[^20][^24][^28][^32][^36][^40][^42]</span>


[^1]: 02d-1-ficheros-sensibles.md
    
[^2]: https://github.com/danielmiessler/SecLists
    
[^3]: https://github.com/arthaud/git-dumper
    
[^4]: https://github.com/internetwache/GitTools
    
[^5]: https://exploit-notes.hdks.org/exploit/web/dump-git-repository-from-website/
    
[^6]: https://github.com/Ebryx/GitDump
    
[^7]: https://docs.rs/git-dumper/0.1.1
    
[^8]: https://developer.wordpress.org/apis/wp-config-php/
    
[^9]: https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
    
[^10]: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
    
[^11]: https://exploit-notes.hdks.org/exploit/web/method/web-content-discovery/
    
[^12]: https://www.kali.org/tools/seclists/
    
[^13]: https://news.ycombinator.com/item?id=40789353
    
[^14]: https://github.com/epi052/feroxbuster
    
[^15]: https://formulae.brew.sh/formula/feroxbuster
    
[^16]: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
    
[^17]: https://github.com/topics/git-dumper
    
[^18]: https://github.com/holly-hacker/git-dumper
    
[^19]: https://blog.pentesteracademy.com/mining-exposed-git-directory-in-3-simple-steps-b6cfaf80b89b
    
[^20]: https://www.geeksforgeeks.org/linux-unix/feroxbuster-recursive-content-discovery-tool-in-kali-linux/
    
[^21]: https://notes.benheater.com/books/web/page/git-dumper
    
[^22]: https://www.firecompass.com/how-do-attackers-utilize-git-for-fun-and-profit/
    
[^23]: https://github.com/topics/dumper
    
[^24]: https://dev.to/k1ven/how-to-explore-an-exposed-git-57m3
    
[^25]: https://github.com/Run0nceEx/feroxbuster-1
    
[^26]: https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure Source Code Management/Git/
    
[^27]: https://javascript.plainenglish.io/git-exposed-real-exploits-real-data-leaks-ccb994ce0dc8
    
[^28]: https://www.kali.org/tools/feroxbuster/
    
[^29]: https://security-tips.vincd.com/git/
    
[^30]: https://git.selfmade.ninja/zer0sec/SecLists/-/tree/eee1651de7906112719066540ca2c5bf688cf9f2/Discovery/Web-Content
    
[^31]: https://www.knownhost.com/kb/how-to-update-your-wp-config-php-file-with-a-new-database-password/
    
[^32]: https://dotenvx.com
    
[^33]: https://wiki.pentestlist.com/offensive-security/web-application/discovery/web-content-discovery
    
[^34]: https://www.reddit.com/r/docker/comments/sjjlzn/docker_compose_is_leaving_secrets_in_env_and/
    
[^35]: https://book.h4ck.cl/metodologia-y-fases-de-hacking-etico/recopilacion-activa-de-informacion/seclist
    
[^36]: https://thimpress.com/wp-config-php-connecting-wordpress-and-database/
    
[^37]: https://stackoverflow.com/questions/60360298/is-it-secure-way-to-store-private-values-in-env-file
    
[^38]: https://raw.githubusercontent.com/dsopas/MindAPI/main/MindAPI.md
    
[^39]: https://stackoverflow.com/questions/57761948/why-is-database-password-stored-in-plain-text-in-wp-config-php-in-wordpress-sec
    
[^40]: https://www.dotenv.org/docs/security
    
[^41]: https://www.reddit.com/r/HowToHack/comments/sv2ird/where_does_apt_y_install_seclists_install_to/
    
[^42]: https://github.com/ffuf/ffuf
