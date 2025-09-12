# Condiciones de Carrera y Lógica de Negocio

Esta sección te enseña a explotar las auténticas “joyas” del bug bounty avanzado: **condiciones de carrera** (race conditions) y bugs de **lógica de negocio**. Aquí no vas a encontrar un escaneo automatizado que te lo resuelva: exige cerebro, análisis cuidadoso de los flujos y, sobre todo, creatividad.

---

## ¿Qué son?

* **Condiciones de carrera:** Ocurren cuando dos o más procesos acceden y manipulan recursos compartidos simultáneamente, generando inconsistencias exploitables. Suele implicar el envío de múltiples peticiones concurrentes para explotar una sincronización deficiente (ej: doble gasto/fuga de saldo/duplicación de recursos).
* **Errores de lógica de negocio:** Problemas en la propia “regla de negocio” de la aplicación (cómo debería funcionar), no necesariamente técnicos clásicos (SQLi, XSS...), sino formas inesperadas de saltarse límites, “escaleras” o restricciones del flujo normal para beneficio propio (o para anular restricciones/detención de operaciones).
