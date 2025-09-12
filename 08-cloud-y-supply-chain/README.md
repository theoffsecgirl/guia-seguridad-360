# Cloud y Supply Chain

En esta sección te metes de lleno en dos de los escenarios más explotables y menos testeados a fondo hoy: **seguridad en la nube (Cloud)** y **ataques a la cadena de suministro (Supply Chain)**. Aquí los bugs no se limitan a tu código, sino a configuraciones externas, dependencias de terceros y al ecosistema donde vive la app (SaaS, IaaS, APIs, imágenes, funciones “serverless”, integraciones CI/CD, etc.).

---

## ¿Por qué importa tanto?

* El 90% de los incidentes fuertes en empresas ahora implican alguna exposición cloud o abuso de una dependencia externa (S3, GCP, Azure, integraciones, paquetes supply chain, APIs SaaS, exfiltración por open buckets, etc.).
* Los ataques no solo vienen por bugs técnicos clásicos sino por **errores de configuración (misconfig)**, fuga de secretos, IAM mal definidos y problemas de gestión de la cadena de dependencias.
* El “escenario real” del atacante moderno no es el backend tradicional, sino el cloud, los pipelines y los proveedores SaaS.
