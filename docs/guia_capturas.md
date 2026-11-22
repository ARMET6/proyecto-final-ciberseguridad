# Guía de capturas para el informe

Los resultados de `evidencias/` vienen de una ejecución de referencia. **Cada equipo debe repetirlas en su
propia máquina (Kali) y tomar sus capturas**; los números deben coincidir o ser muy parecidos.
Etiqueta cada captura como en el avance: *Evidencia N · Actividad · Resultado · Explicación*.

| # | Actividad | Qué ejecutar | Qué debe verse en la captura |
|---|---|---|---|
| 13 | 1 | `python parte_a/init_db.py` y las dos apps | Terminal con "Base de datos creada" y las apps en 5000 y 5001 |
| 14 | 1 | `curl http://127.0.0.1:5000/salud` y `:5001/salud` | `{"estado":"ok","version":"vulnerable"}` y `"corregida"` |
| 15 | 1 | ZAP *Sites* | Endpoints descubiertos y contexto con `/logout` excluido |
| 16 | 2 | Navegador en `:5000/buscar?q=zzz' UNION SELECT usuario, rol, password_hash FROM usuarios--` | La tabla de alumnos muestra usuarios y hashes (puedes tapar los hashes) |
| 17 | 2 | Navegador en `:5000/avisos` publicando `<img src=x onerror=alert('XSS')>` | Ventana `alert` del navegador |
| 18 | 2 | Sesión de `al_laura` en `:5000/alumno/AL00000002` | Expediente de Diego visible siendo Laura |
| 19 | 2 | ZAP *Alerts* versión vulnerable | XSS persistente, XSS reflejado y SQLi-SQLite en High |
| 20 | 3 | `git diff` o editor con las dos versiones de `app.py` y `buscar.html` / `avisos.html` | Líneas del f-string vs `?`, filtro `safe` vs sin él, `puede_ver_alumno()` |
| 21 | 4 | `pruebas_seguridad.py` contra 5000 y 5001 | 7 VULNERABLE vs 0 VULNERABLE |
| 22 | 4 | Navegador en `:5001` con los mismos ataques | Búsqueda vacía; aviso escapado como texto; "Acceso denegado" (403) |
| 23 | 4 | ZAP *Alerts* versión corregida | Sin alertas High |
| 24 | 4 | `python -m pytest parte_a/tests -v` | 7 passed |
| 25 | 5 | `tail parte_a/logs/seguridad.log` | Eventos JSON `ACCESO_DENEGADO`, `LOGIN_FALLIDO`, `CUENTA_BLOQUEADA` |
| 26 | 5 | `python parte_a/pruebas/analisis_logs.py` | Alertas R1 fuerza bruta, R2 enumeración IDOR, R3 inyección |
| 27 | 7 | `sudo bash parte_b/laboratorio_red.sh todo` (parte "SIN firewall") | Laboratorios ve 18 puertos abiertos, incluido 445 de FS01 y 8007 de BK01 |
| 28 | 7 | `sudo ip netns exec fw nft list ruleset` | Reglas R01-R11 y bloqueos B01-B03 |
| 29 | 8 | Misma ejecución, parte "CON firewall" | Laboratorios solo ve los puertos del DC; resto `filtered` |
| 30 | 8 | Tabla de `probar` | "24 de 24 pruebas coinciden con lo esperado" |
| 31 | 8 | `contadores` y `sudo journalctl -k` filtrando FW-DROP | Paquetes bloqueados por regla y registro del kernel |
| 32 | 9 | `aislar adm` / `desaislar` | Administrativo bloqueado, TI conserva SSH |

Antes de entregar: tapa contraseñas, hashes y cookies de sesión en las capturas.
