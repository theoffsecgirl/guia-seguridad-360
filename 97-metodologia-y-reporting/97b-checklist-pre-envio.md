# Checklist Pre-Envio de Reporte

Antes de enviar cualquier hallazgo a un programa de bug bounty o pentest profesional, repasa siempre este checklist. La diferencia entre un bounty bien pagado y uno ignorado casi siempre está en los detalles y en la claridad del reporte.

---

## ✔️ Checklist rápido y sin rodeos

- **Título claro y específico**
  - ¿El título describe el bug (tipo, endpoint, riesgo) en una frase?
- **Resumen ejecutivo**
  - ¿Incluyes un TL;DR de 1-3 líneas explicando el impacto real para negocio/usuarios?
- **Pasos de explotación reproducibles**
  - ¿Das comandos/scripts exactos y explícitos para lanzar la PoC, sin suposiciones ni pasos omisos?
  - ¿El flujo es paso a paso, sin saltos lógicos?
- **Evidencias limpias y suficientes**
  - ¿Incluyes request/response mínimas (redactadas si contienen PII/token)?
  - ¿Adjuntas screenshots recortadas (NO full screen borrosas)?
  - ¿Indicas entorno, usuario, timestamp y roles usados?
  - ¿Incluyes hash/firmas si se ha descargado algún artefacto/código?
- **Exploit NO destructivo y respetuoso con el scope**
  - ¿NO causa DoS real, ni afecta el negocio/otros usuarios/productivo?
  - ¿Indicas explicitamente que el test fue hecho bajo las condiciones del programa y sin saltarte las reglas?
- **Mitigación propuesta y concreta**
  - ¿Sugieres solución técnica factible (ej: “aplicar transacción atómica”, “chequear propiedad de recurso en backend”, “restringir bucket con policy stricta”) y no solo frases vagas (“validar mejor los datos”)?
- **Checklist clásicos de rookie errors**
  - [ ]  ¿No hay wall-of-text, logs inservibles ni nmap completo/copypaste sin filtrar?
  - [ ]  ¿No hay info/teoría innecesaria (ve directo al grano)?
  - [ ]  ¿No publicas secretos/token reales sin redactar?
  - [ ]  ¿El reporte es entendible tanto para desarrolladores como para triagers de bug bounty?

---

## Ejemplo de cómo debe verse al final

- [X]  Título: “Race Condition en /api/transfer permite doble gasto con múltiples requests paralelos”
- [X]  Resumen: “Permite transferir saldo varias veces con una sola reducción de balance”
- [X]  PoC: script Turbo Intruder + pasos logueado → POST → capturas saldo
- [X]  Evidencias: capturas saldo, request, response
- [X]  Mitigación: lock transaccional, validar idempotencia, rate limit
- [X]  Scope respetado y nada de producción alterado

---

## Recursos para checklist/reporting profesional

- [EdOverflow Bug Bounty Template](https://github.com/EdOverflow/bugbounty-report-template)
- [HackerOne Reporting Tips](https://www.hackerone.com/blog/how-write-good-vulnerability-report)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PlantUML para esquemas y diagramas](https://plantuml.com/markdown)

---

**TIP:** Hazte este repaso de memoria antes de darle a “enviar”. Si marcas todas las casillas, tu reporte será imbatible y tu ratio de aceptación/subida de recompensas aumentará (y tu reputación con los triagers también).
