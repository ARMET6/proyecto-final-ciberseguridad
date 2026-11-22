"""
Escaneo autenticado con OWASP ZAP mediante su API (Actividades 1, 2 y 4).

Requisitos:
  - ZAP iniciado con la API en 127.0.0.1:8090, por ejemplo:
        zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true
    (o en ZAP de escritorio: Tools > Options > API, desactivar la llave solo en laboratorio)
  - La app a escanear ejecutándose (5000 vulnerable / 5001 corregida).

Uso:
    python parte_a/zap/escaneo_zap.py --objetivo http://127.0.0.1:5000 --etiqueta vulnerable
    python parte_a/zap/escaneo_zap.py --objetivo http://127.0.0.1:5001 --etiqueta corregida

Qué hace: inicia sesión como doc_maria, inyecta la cookie de sesión en todas las
peticiones de ZAP (regla del Replacer), excluye /logout, ejecuta Spider + Active Scan
y guarda las alertas en evidencias/zap_<etiqueta>.json y un reporte HTML.
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import requests

RAIZ = Path(__file__).resolve().parents[2]
CRED = RAIZ / "parte_a" / "instance" / "credenciales_lab.json"
SIN_PROXY = {"http": None, "https": None}


def zap(api, ruta, **params):
    r = requests.get(f"{api}{ruta}", params=params, proxies=SIN_PROXY, timeout=120)
    r.raise_for_status()
    return r.json() if "/JSON/" in ruta else r.text


def esperar(api, componente, scan_id):
    while True:
        p = int(zap(api, f"/JSON/{componente}/view/status/", scanId=scan_id)["status"])
        print(f"  {componente}: {p}%", end="\r")
        if p >= 100:
            print()
            return
        time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--objetivo", required=True)
    ap.add_argument("--etiqueta", required=True)
    ap.add_argument("--zap", default="http://127.0.0.1:8090")
    a = ap.parse_args()
    obj, api = a.objetivo.rstrip("/"), a.zap
    if not obj.startswith(("http://127.0.0.1", "http://localhost")):
        sys.exit("Solo se permite escanear la aplicación de laboratorio local.")
    salida = RAIZ / "evidencias"
    salida.mkdir(exist_ok=True)

    # 1) Sesión autenticada (doc_maria tiene acceso a todas las funciones)
    creds = json.loads(CRED.read_text(encoding="utf-8"))
    s = requests.Session()
    s.post(f"{obj}/login", data={"usuario": "doc_maria", "password": creds["doc_maria"]}, proxies=SIN_PROXY)
    cookie = f"session={s.cookies.get('session')}"

    zap(api, "/JSON/core/action/newSession/", name=a.etiqueta, overwrite="true")
    zap(api, "/JSON/replacer/action/addRule/", description="cookie-lab", enabled="true",
        matchType="REQ_HEADER", matchRegex="false", matchString="Cookie", replacement=cookie, initiators="")
    # Política reforzada para inyección SQL: con la fuerza por defecto ZAP no prueba
    # suficientes variantes dentro de un LIKE '%...%'. 40018 = SQLi genérica, 40024 = SQLite.
    for regla in ("40018", "40024"):
        zap(api, "/JSON/ascan/action/setScannerAttackStrength/", id=regla, attackStrength="INSANE")
        zap(api, "/JSON/ascan/action/setScannerAlertThreshold/", id=regla, alertThreshold="LOW")
    for ex in (f"{obj}/logout.*", f"{obj}/login.*"):
        zap(api, "/JSON/spider/action/excludeFromScan/", regex=ex)
        zap(api, "/JSON/ascan/action/excludeFromScan/", regex=ex)

    # 2) Sembrar URLs a través del proxy de ZAP
    px = {"http": api, "https": api}
    for ruta in ("/", "/buscar?q=Laura", "/avisos", "/alumno/AL00000001",
                 "/api/alumnos/AL00000001/calificaciones"):
        requests.get(f"{obj}{ruta}", proxies=px, timeout=30)
    requests.post(f"{obj}/avisos", data={"contenido": "aviso de prueba ZAP"}, proxies=px, timeout=30)

    # 3) Spider y escaneo activo
    print("Spider...")
    esperar(api, "spider", zap(api, "/JSON/spider/action/scan/", url=obj, recurse="true")["scan"])
    print("Escaneo activo...")
    esperar(api, "ascan", zap(api, "/JSON/ascan/action/scan/", url=obj, recurse="true")["scan"])

    # 4) Resultados
    alertas = zap(api, "/JSON/core/view/alerts/", baseurl=obj, start=0, count=5000)["alerts"]
    resumen = Counter((x["risk"], x["alert"]) for x in alertas)
    (salida / f"zap_{a.etiqueta}.json").write_text(json.dumps(alertas, indent=2, ensure_ascii=False), encoding="utf-8")
    (salida / f"zap_{a.etiqueta}.html").write_text(zap(api, "/OTHER/core/other/htmlreport/"), encoding="utf-8")
    orden = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    lineas = [f"# OWASP ZAP · {obj} ({a.etiqueta})", "", "| Riesgo | Alerta | Instancias | URL de ejemplo |",
              "|---|---|---|---|"]
    for (riesgo, nombre), n in sorted(resumen.items(), key=lambda k: (orden.get(k[0][0], 9), k[0][1])):
        ej = next(x for x in alertas if x["alert"] == nombre and x["risk"] == riesgo)
        lineas.append(f"| {riesgo} | {nombre} | {n} | `{ej['method']} {ej['url'][:70]}` |")
    (salida / f"zap_{a.etiqueta}.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print("\n".join(lineas))
    zap(api, "/JSON/replacer/action/removeRule/", description="cookie-lab")


if __name__ == "__main__":
    main()
