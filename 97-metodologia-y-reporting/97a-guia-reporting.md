# Guía de Reporting y Evidencias

Un buen bug bounty/pentest NO termina al encontrar el bug: el verdadero impacto (y el reconocimiento) lo marca **cómo reportas y evidencias** lo que has hallado. Aquí aprendes cómo estructurar un informe impecable, qué logs y capturas importan, y cómo hacer que tu reporte sea convincente, reproducible y útil.

---

## 1. Principios clave para un buen reporting

- **Directo y claro**: Título descriptivo (“Race Condition en endpoint de transferencias permite doble gasto”) — evita frases genéricas.
- **Reproducible**: Cualquier miembro del equipo debe poder replicar el hallazgo con tu descripción, comandos y evidencias.
- **Impacto y contexto**: Deja claro el riesgo real para negocio/usuarios, distingue entre fallo teórico y ataque explotable.
- **Evidencias mínimas y limpias**: Sin “walls of text” ni mil líneas de logs. Lo justo: prueba/remedo, respuesta, timestamp, entorno/cuenta afectada.
- **Mitigación sugerida**: Contacta la solución concreta, no un “valida mejor los datos”.

---

## 2. Estructura de un reporte efectivo

**1. Título**

- Descriptivo, conciso y con lo grave primero:
  `IDOR en /api/user permite acceso a datos de terceros`

**2. Resumen ejecutivo**

- 1-3 líneas: qué permite el bug realmente, a quién, y el riesgo (“Un atacante autenticado puede descargar datos de cualquier usuario debido a...”).

**3. Descripción técnica (paso a paso)**

- Cómo se encontró, endpoint, roles implicados, payloads usados, manipulación realizada.
- Incluye comandos o scripts exactos (curl, Burp, ffuf, Turbo Intruder...).

**4. Evidencias**

- Trazas mínimas: request/response (sanitizado), capturas de pantalla recortadas (no toda la pantalla…), timestamp, IDs.
- Si explotaste lógica (race, bypass, escalada): muestra flujo completo y resultado observable (duplicidad, saldo, takeover, etc.).
- Anota qué usuario/entorno/test usaste y si es repetible.
- Incluye hashes relevantes/firmas si hay recursos descargados (archivos, repos, etc.).

**5. Mitigación sugerida**

- Qué debe hacer el equipo (“Controlar concurrencia en /api/transfer”, “Aplicar filtrado de autoregistro en POST /signup”, “Cerrar bucket S3 o restringir a VPC”).

**6. Checklist de calidad pre-envío**

- [ ]  Título claro y riesgo explícito.
- [ ]  Evidencias suficientes y redactadas.
- [ ]  Se indica entorno, usuario, URL exacta, hora.
- [ ]  Comandos/scripts exactos y reproducibles.
- [ ]  Reproducción sin tocar otros usuarios/productivos (NO destructivo).
- [ ]  Propuesta de mitigación concreta.
- [ ]  Disclaimer: no uso/o exfiltración de producción (cumplimiento del scope program).

---

## 3. Ejemplo real a seguir

### Título

**Race condition en /api/transfer permite duplicar saldo**

### Resumen

Un usuario autenticado puede ejecutar varias transferencias paralelas, provocando que el saldo sea decrementado solo una vez, pero se realicen N transferencias en total.

### Descripción técnica

1. Login normal en la app (usuario: user@c.com).
2. Con Burp “Turbo Intruder” se envían 20 POST a `/api/transfer` con los mismos datos en paralelo.
   - Payload: `{“to”:“victim@c.com”,“amount”:100}`
3. Respuesta: 15 son 200 OK, el saldo del atacante solo baja 100, pero el destinatario recibe 1500.

**Request/Response y capturas**:
Se adjuntan:

- Script de Turbo Intruder/curl.
- Captura antes/después del saldo y transfers recibidos.

### Mitigación sugerida

- Implementar lock/transacción atómica en el endpoint, evitar double-spending.

---

## 4. Herramientas y tips de evidencias

- **Comandos en bloque** (bash, curl, httpx, ffuf...)
  Copia solo lo importante:

```bash
curl -X POST -d '{"ID":5}' https://target/api/delete?user=1
```

- **Screenshots**
  - Recorta solo la zona relevante: resultado, mensaje, saldo, user...
  - Marca/tacha cualquier dato privado antes de enviar.
- **Extracción Hash/firmas**
  Si hay descargas/artefactos, incluye hash SHA1/SHA256 para trazabilidad.
- **Marcar usuario/entorno**
  `Entorno: preprod / Usuario: demo123 / TS: 2025-09-12T02:30:00Z`
- **NO publiques claves/token reales**
  Redacta el dato: `"secret": "REDACTED"`

---

## Recursos clave/reporting

- [Bug bounty reporting template (EdOverflow)](https://github.com/EdOverflow/bugbounty-report-template)
- [HackerOne - Cómo escribir reports bien](https://www.hackerone.com/blog/how-write-good-vulnerability-report)
- [Markdown guide](https://www.markdownguide.org/)
- [PlantUML para diagramación](https://plantuml.com/markdown)

---

**TIP:** El reporte NO es tema secundario. Un buen hallazgo mal explicado no vale nada. Un bug mediano, explicado de forma pro, vale oro y te hace destacar. Si dudas, revisa este checklist antes de cada envío.
