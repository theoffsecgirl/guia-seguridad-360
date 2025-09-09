# Legal y Ética


Marco mínimo para trabajar de forma segura, legal y profesional en pentesting, bug bounty y VDPs. El objetivo es reducir riesgo legal, proteger datos y asegurar que cada prueba aporta valor sin causar daño.

## Propósito y alcance
- Establecer reglas claras de actuación antes, durante y después de las pruebas.
- Unificar criterios sobre consentimiento, límites técnicos, manejo de datos y reporte responsable.

## Principios esenciales
- **Autorización** previa y por escrito para cada activo y técnica permitida.
- **Mínimo impacto**: pruebas graduales y no destructivas, sin degradar servicio.
- **Confidencialidad**: la información obtenida se usa solo para validar y reportar.
- **Trazabilidad**: todo queda documentado con fechas, parámetros y resultados.

## Consentimiento y límites (Scope)
- Documento de permiso con: activos, ventanas horarias, técnicas permitidas/prohibidas, contacto operativo y política de datos.
- Fuera de alcance salvo permiso expreso: DoS/DDoS, brute force masivo, spam, ingeniería social, phishing, acceso físico, pivoting lateral, persistencia, borrado/modificación de datos reales.

## Normas específicas en bug bounty/VDP
- Actuar exclusivamente sobre activos en scope respetando límites de tasa y automatización.
- Usar cuentas “canario” y datos sintéticos; detenerse al demostrar impacto suficiente.
- No acceder, copiar ni retener PII real salvo lo imprescindible y siempre redactado en evidencias.

## Manejo de datos y privacidad
- Minimización: recolectar solo lo necesario para probar la hipótesis.
- Almacenamiento cifrado de evidencias; control de acceso “need to know”.
- Retención limitada y borrado seguro al cierre o al vencer el plazo acordado.

## Seguridad de la prueba técnica
- Carga gradual, validación previa en entorno de laboratorio cuando sea posible.
- Usar payloads seguros y modos de solo lectura si existen; evitar acciones irreversibles.
- Nunca manipular fondos, inventario o contenidos productivos sin autorización expresa.

## Evidencias y reporte responsable
- Pasos mínimos reproducibles (5–10 líneas), tiempos y parámetros exactos.
- Requests/responses crudas y capturas del proxy con datos sensibles redactados.
- Severidad estimada (racional de impacto) y mitigación concreta y accionable.
- Compartir evidencias únicamente por el canal oficial del programa/cliente.

## Divulgación coordinada
- No publicar ni compartir hallazgos con terceros hasta parche o ventana acordada.
- Si afecta a múltiples terceros, coordinar notificación con el propietario del programa/activo.

## Daño accidental: plan de respuesta
- Stop-test inmediato ante signos de degradación o exposición no intencionada.
- Notificación rápida al contacto designado con un parte breve, factual y verificable.
- Conservar evidencias mínimas y no alterar sistemas fuera de lo autorizado.

## Conflictos de interés y conducta
- Declarar relaciones con la entidad o proveedores implicados; abstenerse si comprometen independencia.
- Comunicación profesional y puntual con triage/equipos técnicos; no aceptar incentivos que sesguen severidad o narrativa.

## Checklist pre‑prueba
- Consentimiento firmado con activos, ventanas, técnicas y exclusiones.
- Canal de reporte y contacto on‑call verificados.
- Plan de límites de carga, uso de datos sintéticos y criterio de stop‑test.
- Carpeta de caso creada, registro de timestamps y control de acceso a evidencias.

## Checklist pre‑envío
- PoC determinista y pasos mínimos reproducibles.
- Impacto y alcance en una frase; severidad y mitigación justificadas.
- Evidencias redactadas y cifradas; envío solo por canal oficial.
- Verificación final de cumplimiento de scope y políticas.

## Plantillas rápidas

### Plantilla de consentimiento (resumen)
- Activos y subdominios: …
- Ventanas horarias: …
- Técnicas permitidas: …
- Exclusiones: …
- Política de datos (retención, cifrado, borrado): …
- Contacto operativo (on‑call): …

### Plantilla de notificación de emergencia
- Qué ocurrió: …
- Cuándo (UTC): …
- Dónde (activo/endpoint): …
- Acciones ejecutadas y detenidas: …
- Riesgo estimado: …
- Próximos pasos propuestos: …

### Política de redacción de PII (evidencias)
- Sustituir identificadores por placeholders consistentes (USER_A, ORDER_123).
- Difuminar correos, teléfonos y tokens; no adjuntar dumps masivos.
- Guardar original cifrado; compartir solo la versión redactada.

## Descargo
Este contenido es operativo y no constituye asesoramiento legal. Toda prueba debe realizarse con permiso previo y conforme a la normativa aplicable del lugar donde se ejecuta.

<span style="display:none">[^2][^4][^6][^8][^9]</span>

<div style="text-align: center">Legal y Ética</div>

[^1]: https://salesystems.es/hacking-etico-que-es/
    
[^2]: https://es.linkedin.com/pulse/cómo-ser-un-hacker-ético-guía-para-principiantes-certiprof-itbde
    
[^3]: https://nebul4ck.wordpress.com/wp-content/uploads/2015/08/hacking-etico-carlos-tori.pdf
    
[^4]: https://s2grupo.es/hacking-etico-procedimiento-tecnicas-recomendaciones/
    
[^5]: https://www.hacksoft.com.pe/codigo-de-etica-hacker-navegando-el-mundo-del-hacking-etico/
    
[^6]: https://cibersafety.com/hacking-etico-ciberseguridad/
    
[^7]: https://thehackerway.es/2024/01/22/hacking-web-profesional-con-la-mejor-guia-de-owasp/
    
[^8]: https://biblioteca.ciencialatina.org/wp-content/uploads/2024/12/Libro-Hacking-Etico-Teoria-Practicas.pdf
    
[^9]: https://www.prometeo-fp.com/blog/hacking-etico-guia-para-empezar
