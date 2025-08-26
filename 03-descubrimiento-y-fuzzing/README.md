# Descubrimiento de Contenido y Fuzzing

### Encontrando las Puertas Ocultas

Si la fase de Reconocimiento nos dio el mapa de la ciudad (los dominios y servidores), la fase de Descubrimiento de Contenido es donde vamos edificio por edificio probando cada puerta y ventana para encontrar una entrada que no esté a la vista.

El objetivo de este capítulo es aprender las técnicas y herramientas para descubrir archivos, directorios, parámetros y endpoints que no son públicos o no están enlazados directamente en una aplicación web. Encontrar uno de estos recursos ocultos puede ser la vía de entrada directa a una vulnerabilidad crítica.

La técnica principal que usaremos es el **Fuzzing**: un método de fuerza bruta automatizado que utiliza diccionarios para "adivinar" estos recursos ocultos.
