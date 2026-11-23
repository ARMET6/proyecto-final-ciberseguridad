# OWASP ZAP · http://127.0.0.1:5000 (vulnerable)

| Riesgo | Alerta | Instancias | URL de ejemplo |
|---|---|---|---|
| High | Cross Site Scripting (Reflected) | 2 | `POST http://127.0.0.1:5000/avisos` |
| High | Cross Site Scripting XSS (Persistente) | 1 | `GET http://127.0.0.1:5000/avisos` |
| Medium | Ausencia de Tokens Anti-CSRF | 1 | `GET http://127.0.0.1:5000/avisos` |
| Medium | Cabecera Content Security Policy (CSP) no configurada | 13 | `GET http://127.0.0.1:5000/buscar?q=Laura` |
| Medium | Falta de cabecera Anti-Clickjacking | 6 | `GET http://127.0.0.1:5000/buscar?q=Laura` |
| Low | El servidor filtra información de versión a través del campo "Server" del encabezado de respuesta HTTP | 15 | `GET http://127.0.0.1:5000/` |
| Low | Falta encabezado X-Content-Type-Options | 7 | `GET http://127.0.0.1:5000/` |
| Informational | Atributo de elemento HTML controlable por el usuario (XSS potencial) | 2 | `GET http://127.0.0.1:5000/buscar?q=Laura` |
| Informational | Divulgación de información - Comentarios sospechosos | 1 | `GET http://127.0.0.1:5000/avisos` |
| Informational | User Agent Fuzzer | 24 | `GET http://127.0.0.1:5000/avisos` |
