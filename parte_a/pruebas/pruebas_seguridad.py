"""
Pruebas manuales automatizadas de la Parte A (Actividades 2, 4 y 5).

Ejecuta los mismos ataques contra la versión vulnerable y la corregida y
reporta, para cada vulnerabilidad, si la aplicación resultó VULNERABLE o PROTEGIDA.
Al final genera eventos controlados (inicios de sesión fallidos, accesos no
autorizados, entradas inválidas) para el análisis de bitácoras.

Uso (con la app correspondiente ya ejecutándose):
    python parte_a/pruebas/pruebas_seguridad.py --url http://127.0.0.1:5000
    python parte_a/pruebas/pruebas_seguridad.py --url http://127.0.0.1:5001

Solo debe usarse contra la aplicación de laboratorio en 127.0.0.1.
"""
import argparse
import html
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

CRED = Path(__file__).resolve().parent.parent / "instance" / "credenciales_lab.json"
resultados = []


def registrar(vuln, prueba, vulnerable, detalle):
    estado = "VULNERABLE" if vulnerable else "PROTEGIDA"
    resultados.append({"vulnerabilidad": vuln, "prueba": prueba, "resultado": estado, "detalle": detalle})
    print(f"[{estado:10}] {vuln} · {prueba}\n             {detalle}")


def sesion(url, usuario, creds):
    s = requests.Session()
    r = s.post(f"{url}/login", data={"usuario": usuario, "password": creds[usuario]}, allow_redirects=False)
    if r.status_code != 302:
        sys.exit(f"No se pudo iniciar sesión como {usuario} (HTTP {r.status_code})")
    return s


def prueba_sqli(url, s):
    v = "SQL Injection"
    # a) Comilla simple: ¿la app rompe la consulta y muestra el error?
    r = s.get(f"{url}/buscar", params={"q": "'"})
    registrar(v, "Comilla simple en /buscar?q='", "Error de base de datos" in r.text,
              f"HTTP {r.status_code}; mensaje de error SQL visible: {'sí' if 'Error de base de datos' in r.text else 'no'}")
    # b) Condición siempre verdadera
    r = s.get(f"{url}/buscar", params={"q": "zzz' OR 1=1--"})
    filas = r.text.count("<tr>") - 1
    registrar(v, "Condición siempre verdadera  zzz' OR 1=1--", filas >= 4,
              f"HTTP {r.status_code}; filas devueltas: {filas} (la búsqueda 'zzz' no debería devolver ninguna)")
    # c) UNION para extraer la tabla de usuarios
    payload = "zzz' UNION SELECT usuario, rol, password_hash FROM usuarios--"
    r = s.get(f"{url}/buscar", params={"q": payload})
    filtrado = "al_laura" in r.text and ("scrypt:" in r.text or "pbkdf2:" in r.text)
    registrar(v, "UNION SELECT sobre la tabla usuarios", filtrado,
              f"HTTP {r.status_code}; usuarios y hashes de contraseña expuestos: {'sí' if filtrado else 'no'}")


def prueba_xss(url, s):
    v = "XSS"
    p_ref = "<script>alert('XSS-reflejado')</script>"
    r = s.get(f"{url}/buscar", params={"q": p_ref})
    crudo = p_ref in r.text.replace(f'value="{html.escape(p_ref)}"', "")
    csp = r.headers.get("Content-Security-Policy", "ausente")
    registrar(v, "XSS reflejado en /buscar", crudo,
              f"script sin escapar en la respuesta: {'sí' if crudo else 'no'}; CSP: {csp[:40]}")
    p_alm = "<img src=x onerror=alert('XSS-almacenado')>"
    s.post(f"{url}/avisos", data={"contenido": p_alm})
    r = s.get(f"{url}/avisos")
    crudo = p_alm in r.text
    registrar(v, "XSS almacenado en /avisos", crudo,
              "etiqueta <img onerror> guardada y servida como HTML" if crudo
              else "el aviso se muestra escapado como texto (&lt;img ...&gt;)")


def prueba_idor(url, s_alumno):
    v = "IDOR/BOLA"
    r = s_alumno.get(f"{url}/alumno/AL00000001")
    registrar(v, "Control positivo: al_laura abre SU expediente AL00000001", False,
              f"HTTP {r.status_code} (debe ser 200 en ambas versiones)")
    r = s_alumno.get(f"{url}/alumno/AL00000002")
    expuesto = r.status_code == 200 and "Diego" in r.text
    registrar(v, "al_laura abre el expediente de otro alumno AL00000002", expuesto,
              f"HTTP {r.status_code}; datos de Diego (CURP, teléfono, beca) visibles: {'sí' if expuesto else 'no'}")
    r = s_alumno.get(f"{url}/api/alumnos/AL00000003/calificaciones")
    expuesto = r.status_code == 200 and "Matem" in r.text
    registrar(v, "API: al_laura pide calificaciones de AL00000003 (menor de edad)", expuesto,
              f"HTTP {r.status_code}; cuerpo: {r.text.strip()[:80]}")


def eventos_controlados(url, creds):
    """Actividad 5: genera eventos para revisar en la bitácora."""
    print("\nGenerando eventos controlados para la bitácora...")
    for i in range(6):                                            # fuerza bruta -> bloqueo
        requests.post(f"{url}/login", data={"usuario": "se_carlos", "password": f"incorrecta{i}"})
    requests.get(f"{url}/api/alumnos/AL00000001/calificaciones")    # sin sesión -> 401
    s = sesion(url, "al_diego", creds)
    for n in range(1, 5):                                         # enumeración de matrículas
        s.get(f"{url}/api/alumnos/AL0000000{n}/calificaciones")
    s.get(f"{url}/alumno/AL123")                                  # matrícula inválida -> 400
    s.get(f"{url}/no-existe")                                     # 404
    print("Listo. Revise logs/seguridad.log (solo la versión corregida lo genera).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--salida", help="archivo JSON con los resultados")
    a = ap.parse_args()
    url = a.url.rstrip("/")
    if urlparse(url).hostname not in ("127.0.0.1", "localhost"):
        sys.exit("Por seguridad, este script solo se ejecuta contra 127.0.0.1/localhost.")
    creds = json.loads(CRED.read_text(encoding="utf-8"))
    version = requests.get(f"{url}/salud").json()["version"]
    print(f"== Pruebas contra {url} (versión {version}) ==\n")
    s_doc = sesion(url, "doc_maria", creds)
    prueba_sqli(url, s_doc)
    prueba_xss(url, s_doc)
    prueba_idor(url, sesion(url, "al_laura", creds))
    eventos_controlados(url, creds)
    vuln = sum(r["resultado"] == "VULNERABLE" for r in resultados)
    print(f"\nResumen: {vuln} pruebas vulnerables de {len(resultados)} (incluye 1 control positivo).")
    if a.salida:
        Path(a.salida).write_text(json.dumps({"url": url, "version": version, "resultados": resultados},
                                             indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
