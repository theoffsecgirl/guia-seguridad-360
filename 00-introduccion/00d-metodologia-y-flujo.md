# Metodología y Flujo

Guía operativa para pasar de la idea al hallazgo verificable con el mínimo de pasos, maximizando impacto y reduciendo rechazos por falta de evidencia o fuera de alcance.

## Objetivo

- Establecer un flujo estándar de trabajo con entradas/salidas claras, timeboxes, y criterios GO/NO‑GO por fase.
- Alinear evidencias, calidad y reporting con prácticas aceptadas por programas y equipos de seguridad.

## Principios

- Legalidad y alcance primero: nada fuera de scope, sin DoS, sin datos personales reales en PoCs.
- Reproducibilidad por encima de todo: cada hallazgo debe poder repetirse en entorno limpio con pasos mínimos.
- Menos es más: empezar por hipótesis simples de gran retorno (control de acceso, exposición, configuración) antes que vectores complejos.

---

## Flujo de alto nivel

1) Preparación y lectura de alcance → 2) Reconocimiento → 3) Descubrimiento/Fuzzing → 4) Validación/Explotación controlada → 5) Post‑explotación limitada → 6) Evidencias y severidad → 7) Reporte y seguimiento.

- Timebox inicial por target: 2–4 h. Si no hay señales, rotar.
- Registrar decisiones y pivotes; evitar repetir trabajo en futuros ciclos.

---

## Fase 1. Preparación

- Entrada: programa elegido, alcance, reglas, límites de tasa, ambientes permitidos.
- Salida: lista de dominios/activos priorizados, hipótesis iniciales (3–5), plan de 2–4 h.

Checklist

- Leer y anotar: dominios, subdominios, apps móviles, APIs, entornos (prod/pre), PII, scraping, límites.
- Definir “no cruzar”: no creds reutilizados, no fuerza bruta masiva, no exfil real.
- Configurar registro: proxy, timestamp, carpeta de caso y naming.

---

## Fase 2. Reconocimiento

- Entrada: dominios/activos priorizados.
- Salida: mapa de superficie (hosts vivos, tecnologías, endpoints candidatos), señales de negocio.

Acciones mínimas

- Inventario de subdominios y filtrado por respuesta/tecnología.
- Fingerprinting: títulos, headers, frameworks, CSP, WAF, rutas “obvias” (/api, /.well-known, /docs).
- Recoger indicios de negocio: áreas con datos o cambios de estado.

GO si

- Hay endpoints con datos sensibles, auth laxa o documentación accesible.
  NO‑GO si
- Solo 403/429 persistente y sin rutas útiles tras el timebox.

---

## Fase 3. Descubrimiento/Fuzzing

- Entrada: hosts y rutas candidatas.
- Salida: endpoints y parámetros con potencial (lista corta priorizada).

Acciones mínimas

- Descubrimiento de contenido con lista curada por tecnología.
- Fuzzing de parámetros (GET/POST/JSON) para detectar parámetros ocultos/legacy.
- Búsqueda de artefactos (sourcemaps, .env, repos .git, backups).

Calidad

- Confirmar hallazgos con request “cruda” y análisis por tamaño/firma de respuesta.
- Reducir ruido: registrar solo diferencias significativas (estado, tamaño, comportamiento).

---

## Fase 4. Validación/Explotación controlada

- Entrada: hipótesis y endpoints candidatos.
- Salida: PoC determinista y evaluación de impacto.

Prioridad de pruebas

- Control de acceso: IDOR/BOLA/BFLA, diferencias 401/403/404, elevación horizontal/vertical.
- Configuración: CORS laxo, cabeceras de seguridad ausentes, desvíos abiertos.
- Servidor/API: SSRF/SSTI/XXE/SQLi/NoSQLi solo si hay señales claras; evitar ataques destructivos.
- Cliente: XSS, PostMessage, clickjacking, XS‑Leaks con mitigaciones evaluadas.

Reglas de seguridad

- Nunca automatizar carga agresiva; respetar límites de tasa.
- Sin exfil real: usar datos de prueba o redactar.
- Usar cuentas “canario” y limpiar trazas si procede.

---

## Fase 5. Post‑explotación limitada

- Entrada: PoC válida.
- Salida: confirmación de alcance/impacto, sin persistencia ni movimiento lateral prohibido.

Acciones

- Demostrar impacto mínimo suficiente (lectura/escritura, privilegios, alcance de datos).
- Verificar si afecta a múltiples tenants/usuarios.
- Parar antes de persistencia o daño real.

---

## Fase 6. Evidencias y severidad

- Entrada: PoC y validación.
- Salida: paquete de evidencias y severidad mapeada.

Definición de Done (hallazgo)

- Pasos mínimos reproducibles (5–10 líneas), con timestamps.
- Requests/responses crudas, identificadores sintéticos, capturas del proxy.
- Matriz de impacto: confidencialidad/integridad/disponibilidad, alcance (1 usuario, multiusuario, global), facilidad de explotación.
- Severidad estimada (VRT/CVSS) con rationale en una frase.
- Recomendación de mitigación breve.

---

## Fase 7. Reporte y seguimiento

- Entrada: paquete de evidencias.
- Salida: reporte enviado, conversación con triage, estado y aprendizaje.

Buenas prácticas

- Título preciso y atómico.
- Descripción corta (qué, dónde, por qué importa).
- Pasos reproducibles y PoC.
- Impacto y alcance.
- Mitigación recomendada.
- Anexos (logs, HAR, cURL).
- Seguir hilo de triage, responder rápido, aportar pruebas adicionales sin ruido.

---

## Criterios GO/NO‑GO por ciclo (2–4 h)

GO (profundizar)

- Datos sensibles sin auth o auth laxa.
- Señales claras de autorización insuficiente.
- Documentación/telemetría que revela estructuras internas.

NO‑GO (rotar target)

- Solo errores de acceso/ratelimit tras múltiples técnicas suaves.
- Superficie mínima sin indicios de negocio o datos de valor.
- Demasiada fricción operativa comparada con otras oportunidades.

---

## Trazabilidad y orden

Estructura de caso (sugerida)

```
cases/
  TARGET_YYYYMMDD/
    notes.md
    recon/
      subs.txt
      httpx.json
    fuzz/
      content.txt
      params.txt
    pocs/
      poc-idor-accounts.md
      poc-cors-userdata.md
    evidence/
      req-res/
      screenshots/
    report/
      draft.md
```

Convenciones

- Nombres atómicos por hallazgo: poc-<categoria>-<recurso>.md
- Timestamps UTC ISO‑8601 en todas las evidencias.

---

## Plantillas rápidas

Plantilla de notas (por hipótesis)

```
# HIPÓTESIS
Recurso/endpoint:
Supuesto:
Prueba rápida:
Resultados:
Decisión: GO | NO-GO (por qué)
```

Plantilla de PoC mínima reproducible

```
# PoC - <Título corto>
Objetivo/impacto:
Precondiciones:
Pasos (mínimos):
1) ...
2) ...
3) ...
Evidencias:
- Request/Response (adjunto)
- Capturas (adjunto)
Severidad estimada (VRT/CVSS) + justificación:
Mitigación breve:
```

Captura de request cruda (ejemplo)

```bash
curl -i -s -k -X GET \
  'https://api.ejemplo.com/v1/users/1234' \
  -H 'Authorization: Bearer <token_usuario_A>' \
  -H 'Accept: application/json' \
  --compressed
```

Registro de métrica simple (CSV)

```
fecha,target,fase,accion,resultado,notas
2025-09-08,example.com,recon,subdominios,432 vivos,priorizar *.api
```

---

## Calidad y control

- Reproducibilidad: verificada en sesión limpia/cuenta nueva si aplica.
- Reducción de ruido: no adjuntar escaneos masivos; solo evidencias pertinentes.
- Redacción: anonimizar IDs/datos personales; usar placeholders consistentes.
- Legal y ética: sin escalado de privilegios destructivo, sin persistencia, sin pivot no autorizado.

---

## Roles y enrutado

- Operador: ejecuta fases 2–5 y prepara evidencias.
- Revisor: valida reproducibilidad y severidad antes de envío.
- Redactor: arma reporte final y gestiona triage.
- Unipersonal: aplicar roles en secuencia con checklist y autoverificación.

---

## Atajos operativos

- Empezar por control de acceso y exposición de artefactos; suelen ofrecer el mayor retorno con menos fricción.
- Mantener wordlists por stack/tecnología; actualizar periódicamente.
- Reutilizar plantillas de reporte y PoC; estandariza el cierre.

---

## Definition of Done (DoD) del reporte

- Título claro y categoría correcta.
- Pasos mínimos y PoC determinista.
- Evidencias suficientes, redactadas.
- Severidad justificada y mitigación propuesta.
- Cumple alcance y límites del programa.

---

## Lecciones aprendidas

- Documentar pivotes fallidos y razones de NO‑GO para no repetirlos.
- Registrar cuánto tiempo costó cada hallazgo y qué señales lo anticiparon.
- Alimentar un “catálogo de señales” propio por vertical/stack para priorizar mejor los próximos ciclos.

---

Con este flujo, cada ciclo produce un resultado binario útil: hallazgo reportable con evidencias completas, o descarte consciente con motivos claros y aprendizaje reutilizable.
<span style="display:none">[^4][^8][^9]</span>


[^1]: https://achirou.com/la-mejor-manera-de-aprender-hacking-y-ciberseguridad/
    
[^2]: https://www.hacker-mentor.com/blog/metodologia-gamificada-para-ethical-hackers
    
[^3]: https://keepcoding.io/blog/metodologia-generica-en-hacking/
    
[^4]: https://www.youtube.com/watch?v=fUs1LM2b3JA
    
[^5]: https://extension.uned.es/actividad/idactividad/43355
    
[^6]: https://achirou.com/la-mejor-forma-de-aprender-hacking-y-ciberseguridad-en-2025/
    
[^7]: https://www.iceditorial.com/informatica-y-telecomunicaciones/10022-ciberseguridad-hacking-etico-ifcd072po-9788411037211.html
    
[^8]: https://www.conectasoftware.com/magazine/hacking-mentalidad-habilidad-y-metodologia/
    
[^9]: https://thebridge.tech/blog/que-es-hacking-etico-ciberseguridad/
