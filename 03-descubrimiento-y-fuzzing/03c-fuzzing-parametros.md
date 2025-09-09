# Fuzzing de Parámetros

El fuzzing de parámetros es fundamental para encontrar rutas no documentadas, parámetros ocultos y vulnerabilidades lógicas (IDOR, BOLA, bypass de acceso, validaciones laxas) en aplicaciones web modernas.[^1]

---

## ¿Por qué fuzzear parámetros?

- Descubres endpoints y controles internos no documentados y funcionalidades solo accesibles por parámetros “secretos”.
- Detectas bypass de autenticación, problemas de lógica y control de acceso horizontal/vertical.[^3]
- Revelas parámetros usados “por costumbre” en frameworks, legacy y APIs internas clonadas en distintos endpoints.[^1]

---

## Técnicas más efectivas

### 1. Fuzz GET/POST directamente

GET:

```bash
ffuf -w /usr/share/seclists/Fuzzing/parameter-names.txt -u 'https://target.com/?FUZZ=valor' -mc 200,401,403,500 -mr 'error|token|jwt'
```

POST:

```bash
ffuf -w params.txt -u https://target.com/endpoint -X POST -d "FUZZ=valor" -mc 200,401,403,500
```

---

### 2. Múltiples posiciones/nombres y valores

Fuzz de diferentes posiciones/valores/payloads:

```bash
ffuf -w params.txt:PARAM -w vals.txt:VAL -u 'https://target.com/api?PARAM=VAL' -mode clusterbomb
```

---

### 3. Fuzz en cabeceras y cuerpos

Cabeceras:

```bash
ffuf -w headers.txt -u https://target.com/ -H 'FUZZ: test'
```

Cuerpo (JSON):

1. Guarda el payload con "FUZZ" en el sitio deseado.
2. Lanza:

```bash
ffuf -request req.json -w params.txt
```

---

## Wordlists recomendadas

- [SecLists](https://github.com/danielmiessler/SecLists): Discovery/Web-Content/burp-parameter-names.txt, fuzzing/parameter-names.txt
- Custom: Añade resultados de JS, historial, burp suite, dorks.[^1]

---

## Filtros y priorización

- **Filtra por códigos, longitud, palabras, coincidencias y contenido que cambie el flujo (flags, roles, redireccionamientos, tokens, etc).**
  - -mc 200,401,403,500
  - -fs XX, -fw XX
  - -mr 'token|flag|bypass|access|session'
    [^2]

---

## Pipeline real de pentest

```bash
ffuf -w /usr/share/seclists/Fuzzing/parameter-names.txt -u 'https://target.com/api?FUZZ=1' -mc 200,401,403,500 -mr 'flag|error|jwt|token|secret|access' -o params_interesantes.txt
```

- Revisa params que devuelven estados anómalos o mensajes únicos --> investiga más a fondo.[^2]

---

## Pro Tips

- No te limites a GET/POST: prueba PUT, PATCH y combinaciones en APIs REST.
- Fuzz en endpoints “admin”, “internal”, “v2/v3”, paneles o rutas móviles.
- Correlaciona cambios en cabeceras, cookies, longitud y respuesta.
- Rota roles y sesiones: compara respuestas logueado/deslogueado y con distintos permisos.[^2]

---

**Referencias/práctica:**

- [SecLists](https://github.com/danielmiessler/SecLists)
- [ffuf GitHub](https://github.com/ffuf/ffuf)[^5]
- [Ultimate ffuf cheatsheet: advanced tactics](https://www.reddit.com/r/bugbounty/comments/1f8mhjd/ultimate_ffuf_cheatsheet_advanced_fuzzing_tactics/)[^2]
- [Web Security Fuzzing with ffuf](https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/)[^3]
- [Bug bounty playbooks](https://www.kali.org/tools/ffuf/)[^4]


[^1]: https://hackviser.com/tactics/tools/ffuf
    
[^2]: https://www.reddit.com/r/bugbounty/comments/1f8mhjd/ultimate_ffuf_cheatsheet_advanced_fuzzing_tactics/
    
[^3]: https://www.freecodecamp.org/news/web-security-fuzz-web-applications-using-ffuf/
    
[^4]: https://www.kali.org/tools/ffuf/
    
[^5]: https://github.com/ffuf/ffuf
