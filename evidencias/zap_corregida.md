# OWASP ZAP · http://127.0.0.1:5001 (corregida)

| Riesgo | Alerta | Instancias | URL de ejemplo |
|---|---|---|---|
| Medium | Absence of Anti-CSRF Tokens | 1 | `GET http://127.0.0.1:5001/avisos` |
| Medium | CSP: style-src unsafe-inline | 14 | `GET http://127.0.0.1:5001/buscar?q=Laura` |
| Low | Server Leaks Version Information via "Server" HTTP Response Header Field | 15 | `GET http://127.0.0.1:5001/` |
| Informational | User Agent Fuzzer | 24 | `POST http://127.0.0.1:5001/avisos` |
| Informational | User Controllable HTML Element Attribute (Potential XSS) | 2 | `GET http://127.0.0.1:5001/buscar?q=Laura` |
