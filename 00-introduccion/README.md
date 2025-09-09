# Introducción

Esta guía es un manual práctico de bug bounty y pentesting aplicado, optimizado para pasar de cero a hallazgos reproducibles con foco en impacto y reporte sólido. El contenido prioriza técnicas modernas, metodologías repetibles y atajos de productividad sobre teoría extensa o genérica.

## Objetivos

- Ofrecer un flujo de trabajo completo: recon → descubrimiento → explotación → reporte, con decisiones claras en cada fase.
- Proveer checklists y plantillas reutilizables para reducir falsos positivos y rechazos por falta de pruebas.
- Estándares de calidad que aceleren la validación por parte de los programas y equipos de seguridad.

## Público objetivo

- Cazadores de bugs y pentesters que buscan guías accionables y minimización de fricción operativa.
- Perfiles técnicos que trabajan en Linux Mint/macOS/WSL y herramientas comunes del ecosistema de seguridad web y móvil [4][2].

## Cómo usar esta guía

- Leer “Start Here” y “Metodología y Flujo” para entender el mapa general y los criterios de avance entre fases.
- Elegir un “camino de ataque” por stack/tecnología y seguir los playbooks enlazados entre secciones.
- Utilizar las checklists de pre-envío y plantillas de reporte para cada hallazgo antes de enviar.

## Estructura y navegación

- Fundamentos, Recon, Descubrimiento/Fuzzing, Hacking Web/Cliente/Servidor, APIs, iOS, Lógica y Reporting, con anexos de herramientas y cheatsheets.
- Interlinking entre capítulos con “rutas de ataque” para reducir saltos y pérdida de contexto.
- Cada página incluye objetivos, pasos mínimos, señales de éxito y errores comunes a evitar.

## Convenciones del documento

- Entornos: se asume Linux Mint; cuando cambie el comando para macOS/WSL se indicará explícitamente.
- Snippets: prefijo con shell y comentarios breves; variables en MAYÚSCULAS y rutas relativas al repo por claridad¡.
- Terminología: español principal con términos estándar del sector cuando aporten precisión técnica¡.

## Legal y ética (resumen)

- Solo probar en programas y activos con permiso explícito y dentro del alcance publicado por el programa.
- Respetar límites de tasa, privacidad de datos y no explotación destructiva o persistente en producción.
- Mantener registros de evidencias y tiempos para auditoría y para facilitar la validación del hallazgo.

## Prerrequisitos rápidos

- Sistema actualizado con herramientas base: git, Go, Python3, jq, curl, nmap, y un proxy como Burp Suite.
- Cuenta(s) en plataformas de bug bounty y lectura del scope/descargos de responsabilidad de cada programa.

## Resultado esperado

- Obtener hallazgos de alto valor con una cadencia estable usando playbooks reproductibles y reporting consistente.
- Reducir el tiempo desde reconocimiento a PoC determinista con checklists y plantillas listas para usar.
