# OWASP ZAP · http://127.0.0.1:5001 (corregida)

| Riesgo | Alerta | Instancias | URL de ejemplo |
|---|---|---|---|
| Medium | Ausencia de Tokens Anti-CSRF | 1 | `GET http://127.0.0.1:5001/avisos` |
| Medium | CSP: style-src unsafe-inline | 13 | `GET http://127.0.0.1:5001/` |
| Low | El servidor filtra información de versión a través del campo "Server" del encabezado de respuesta HTTP | 14 | `GET http://127.0.0.1:5001/` |
| Informational | Atributo de elemento HTML controlable por el usuario (XSS potencial) | 2 | `GET http://127.0.0.1:5001/buscar?q=Laura` |
| Informational | User Agent Fuzzer | 24 | `GET http://127.0.0.1:5001/avisos` |
