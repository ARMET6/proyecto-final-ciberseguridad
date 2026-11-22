# OWASP ZAP · http://127.0.0.1:5000 (vulnerable)

| Riesgo | Alerta | Instancias | URL de ejemplo |
|---|---|---|---|
| High | Cross Site Scripting (Persistent) | 1 | `GET http://127.0.0.1:5000/avisos` |
| High | Cross Site Scripting (Reflected) | 2 | `POST http://127.0.0.1:5000/avisos` |
| High | SQL Injection - SQLite | 2 | `POST http://127.0.0.1:5000/avisos` |
| Medium | Absence of Anti-CSRF Tokens | 1 | `GET http://127.0.0.1:5000/avisos` |
| Medium | Content Security Policy (CSP) Header Not Set | 13 | `GET http://127.0.0.1:5000/` |
| Medium | Missing Anti-clickjacking Header | 7 | `GET http://127.0.0.1:5000/` |
| Low | Server Leaks Version Information via "Server" HTTP Response Header Field | 15 | `GET http://127.0.0.1:5000/` |
| Low | X-Content-Type-Options Header Missing | 8 | `GET http://127.0.0.1:5000/` |
| Informational | User Agent Fuzzer | 24 | `POST http://127.0.0.1:5000/avisos` |
| Informational | User Controllable HTML Element Attribute (Potential XSS) | 2 | `GET http://127.0.0.1:5000/buscar?q=Laura` |
