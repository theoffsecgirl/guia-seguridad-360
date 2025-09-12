# Matriz Impacto/Esfuerzo y VRT/CVSS

En bug bounty (y pentest pro) no basta con encontrar bugs: hay que **priorizar, justificar el impacto** y preparar el terreno para la máxima recompensa y aceptación del hallazgo. Aquí tienes cómo aplicar la matriz **Impacto/Esfuerzo** y cómo evaluar severidad usando estándares como **VRT** (HackerOne) y **CVSS** (común en la industria).

---

## Matriz Impacto/Esfuerzo

### ¿Para qué sirve?

- Decidir **qué bugs priorizar**: ataca primero lo de máximo impacto y bajo esfuerzo.
- Justificar (en el reporte o en planning propio) la criticidad para negociar recompensa/escalado interno.
- Identificar “quick wins” de alto valor (bajos en esfuerzo, alto impacto).


|                   |                      **Impacto Bajo**                      |                        **Impacto Alto**                        |
| :---------------- | :--------------------------------------------------------: | :-------------------------------------------------------------: |
| **Esfuerzo Bajo** |           NO perder tiempo salvo por score extra           | **TOP PRIORIDAD** (hallazgos “sweet spot”: rápidos y graves) |
| **Esfuerzo Alto** | SOLO si es pieza clave del flujo o para aumentar cobertura |   SOLO si buscas premio gordo/top ranking/lo exige el alcance   |

**¿Ejemplo?**

- Encontrar `.git` expuesto: bajo esfuerzo, impacto potencialmente altísimo.
- Explotar un race condition con scripting propio: más esfuerzo, pero puede ser report top si escala a takeover.
- Deserialización insegura en admin legacy con exploit largo: esfuerzo alto, pero si es RCE es prioridad.

---

## Cuantifica el Impacto: VRT (HackerOne) vs CVSS

### VRT (Vulnerability Rating Taxonomy)

- Usado en HackerOne para estandarizar la severidad y acelerar el pago de bounty.
- Categorías como: Critica, Alta, Media, Baja, Informativa.
- Ejemplos:
  - **Critical:** Account takeover sin interacción, RCE en producción, accesos global a datos de usuario.
  - **High:** SQLi blind, bypass auth, acceso legible a credenciales válidas.
  - **Medium:** Reflected XSS, fuga limitada de datos, IDOR con acceso restringido.
  - **Low:** Open redirect, fingerprinting de tecnologías, info disclosure no sensible.
  - **Informational:** Versiones en banners, DOS no explotable, brute force sin rate limit.
- Documentación:
  - [HackerOne VRT (live)](https://www.hackerone.com/vulnerability-rating-taxonomy)

---

### CVSS (Common Vulnerability Scoring System)

- Es el estándar industrial para puntuar riesgos, usado por prensa, bug bounty, y auditorías de seguridad.
- Pondera vector, complejidad ataque, privilegios requeridos, interacción usuario, alcance, impacto en C/I/D (Confidencialidad/Integridad/Disponibilidad).
- Score automático (0-10):
  - 9.0-10.0: Critical
  - 7.0-8.9: High
  - 4.0-6.9: Medium
  - 0.1-3.9: Low
- Herramientas útiles:
  - [CVSS Calculator (FIRST.org)](https://www.first.org/cvss/calculator/3.1)
  - [Exploit DB quick calculator](https://www.exploit-db.com/cvss/)

---

## ¿Cómo lo aplico en mis reportes?

1. **Evalúa impacto real:** ¿Da acceso crítico? ¿Permite chain con otros bugs? ¿Afecta a todos los usuarios/datos?
2. **Piensa en esfuerzo:** ¿Cuánto tiempo, recursos y repetibilidad implicó probar/explotar?
3. **Cita la severidad:** Añade al reporte:
   - “Este hallazgo corresponde a un riesgo *High* según [VRT](https://www.hackerone.com/vulnerability-rating-taxonomy) de HackerOne...”
   - “CVSS: 8.6 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) [enlace calculadora](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)”

---

## Ejemplo para el reporte

**Severidad:** Alta
**Justificación:**
Este bug permite un bypass de autenticación con impacto directo sobre datos de usuario, sin requerir interacción y con vector externo.

- VRT: High - Authentication bypass
- CVSS: 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

---

## Recursos rápidos

- [HackerOne VRT](https://www.hackerone.com/vulnerability-rating-taxonomy)
- [CVSS Calculator v3.1](https://www.first.org/cvss/calculator/3.1)
- [Prioritization matrix inspiration (OWASP)](https://owasp.org/www-project-risk-rating-methodology/)
- [Common bug bounty impact/effort matrix (Google)](https://sites.google.com/site/bughunteruniversity/)

---

**TIP:**
“No priorices por hype ni por lo que más grita Twitter. Calcula impacto real, cúmplelo, evidéncialo y ahorra energía donde el riesgo es solo teórico. Este enfoque es el que te hace escalar y ganar en bug bounty (y en consultoría).”
