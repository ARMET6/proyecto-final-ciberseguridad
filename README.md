# Proyecto final de Ciberseguridad · Campus Las Torres

Universidad Tecmilenio · Campus Las Torres (organización real, **datos 100 % ficticios**)
Equipo: Ariel Martínez López · Adrián Razo Mandujano · Mauricio López Gudiño · Fernanda Ximena García Salazar

Continuación del avance (arquitectura híbrida con Linux, escenario de ransomware). Este repositorio contiene:

| Carpeta | Contenido | Actividades |
|---|---|---|
| `parte_a/app_vulnerable/` | Portal Escolar en Flask con SQL Injection, XSS e IDOR/BOLA a propósito (puerto 5000) | 1, 2 |
| `parte_a/app_segura/` | Misma app con las tres correcciones, cabeceras de seguridad y bitácora (puerto 5001) | 3, 4, 5 |
| `parte_a/pruebas/` | `pruebas_seguridad.py` (ataques antes/después) y `analisis_logs.py` (detección en bitácoras) | 2, 4, 5 |
| `parte_a/zap/` | `escaneo_zap.py`: escaneo autenticado con OWASP ZAP vía API | 1, 2, 4 |
| `parte_a/tests/` | Pruebas unitarias con pytest de las correcciones | 4 |
| `parte_b/` | Laboratorio de red con nftables + Nmap (opción A, Seguridad de red) | 7, 8 |
| `docs/` | Guía de ZAP, procedimiento de respuesta a incidentes, guía de capturas | 1, 9 |
| `evidencias/` | Salidas reales de la última ejecución (ZAP, pruebas, bitácoras, Nmap, firewall) | 4, 5, 8 |

> ⚠️ Solo para laboratorio. Las apps escuchan únicamente en `127.0.0.1`. No hay credenciales en el
> repositorio: `init_db.py` genera contraseñas aleatorias en `parte_a/instance/credenciales_lab.json`,
> que está en `.gitignore`.

## Requisitos

- Python 3.10+ (Windows, macOS o Linux). Para la Parte B: Linux (Kali/Debian/Ubuntu) con `nmap`, `nftables` e `iproute2`.
- OWASP ZAP 2.14+ (para las Actividades 1, 2 y 4).

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python parte_a/init_db.py                                # crea la BD y las contraseñas de prueba
```

## Parte A · Aplicación web

```bash
# Terminal 1 y 2
python parte_a/app_vulnerable/app.py       # http://127.0.0.1:5000
python parte_a/app_segura/app.py           # http://127.0.0.1:5001

# Terminal 3: mismas pruebas contra cada versión
python parte_a/pruebas/pruebas_seguridad.py --url http://127.0.0.1:5000 --salida evidencias/resultados_vulnerable.json
python parte_a/pruebas/pruebas_seguridad.py --url http://127.0.0.1:5001 --salida evidencias/resultados_corregida.json

# Bitácora de la versión corregida
python parte_a/pruebas/analisis_logs.py    # lee parte_a/logs/seguridad.log

# Pruebas unitarias
python -m pytest parte_a/tests -v
```

Cuentas de prueba (contraseñas en `parte_a/instance/credenciales_lab.json`):

| Usuario | Rol | Puede |
|---|---|---|
| `al_laura` | alumno (AL00000001) | ver solo su expediente y calificaciones |
| `al_diego` | alumno (AL00000002) | ver solo su expediente y calificaciones |
| `doc_maria` | docente | buscar alumnos y consultar calificaciones |
| `se_carlos` | servicios escolares | buscar alumnos y consultar expedientes |

Endpoints: `/login`, `/buscar?q=`, `/avisos`, `/alumno/<matricula>`, `/api/alumnos/<matricula>/calificaciones`, `/salud`.

### OWASP ZAP

Ver [`docs/guia_zap.md`](docs/guia_zap.md). Versión automatizada:

```bash
zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true
python parte_a/zap/escaneo_zap.py --objetivo http://127.0.0.1:5000 --etiqueta vulnerable
python parte_a/zap/escaneo_zap.py --objetivo http://127.0.0.1:5001 --etiqueta corregida
```

## Parte B · Firewall y Nmap (opción A)

```bash
sudo bash parte_b/laboratorio_red.sh todo        # crea la red, escanea sin y con firewall, prueba 24 flujos
sudo bash parte_b/laboratorio_red.sh destruir    # elimina la red virtual
```

Crea 6 *network namespaces* (VLAN 10, 15, 20, 40, 99 e "Internet") enrutados por un namespace `fw` que
aplica [`parte_b/reglas_campus.nft`](parte_b/reglas_campus.nft). No modifica la red real del equipo.

## Resultados de la última ejecución

| Prueba | Versión vulnerable | Versión corregida |
|---|---|---|
| Pruebas manuales (`pruebas_seguridad.py`) | 7 de 7 ataques exitosos | 0 de 7 ataques exitosos |
| Alertas **High** de OWASP ZAP | 5 (XSS persistente, XSS reflejado ×2, SQLi-SQLite ×2) | 0 |
| Pruebas unitarias | — | 7/7 aprobadas |
| Flujos de red como se esperaba (Parte B) | 11/24 sin firewall | 24/24 con firewall |
