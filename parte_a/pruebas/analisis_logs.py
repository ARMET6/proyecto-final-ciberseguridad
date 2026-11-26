"""
Actividad 5 — Análisis de la bitácora de seguridad (logs/seguridad.log).

Resume los eventos por tipo, usuario e IP y aplica reglas simples de detección,
parecidas a las que se configurarían en Wazuh (VM-MON01) en el diseño del campus:

  R1  Fuerza bruta: >= 5 LOGIN_FALLIDO de la misma cuenta en 5 minutos.
  R2  Enumeración IDOR/BOLA: >= 3 ACCESO_DENEGADO del mismo usuario en 5 minutos.
  R3  Intento de inyección: cualquier ENTRADA_SOSPECHOSA (SQLi / XSS).
  R4  Sondeo: >= 3 eventos ENTRADA_INVALIDA / RECURSO_NO_ENCONTRADO de la misma IP.
  R5  Escaneo automatizado: > 20 ENTRADA_SOSPECHOSA en 5 minutos (por ejemplo, OWASP ZAP).
  R6  CSRF: cualquier CSRF_RECHAZADO (formulario enviado sin token válido).
  R7  Uso de privilegios: toda ADMIN_CONSULTA se reporta para auditoría.

Uso:
    python parte_a/pruebas/analisis_logs.py [ruta_log]
"""
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

RUTA = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "logs" / "seguridad.log"
VENTANA = timedelta(minutes=5)


def cargar():
    eventos = []
    for linea in RUTA.read_text(encoding="utf-8").splitlines():
        if linea.strip():
            e = json.loads(linea)
            e["_t"] = datetime.fromisoformat(e["fecha"])
            eventos.append(e)
    return eventos


def rafagas(eventos, umbral):
    """Devuelve True si hay `umbral` eventos dentro de la ventana de tiempo."""
    tiempos = sorted(e["_t"] for e in eventos)
    return any(tiempos[i + umbral - 1] - tiempos[i] <= VENTANA for i in range(len(tiempos) - umbral + 1))


def main():
    ev = cargar()
    print(f"Bitácora: {RUTA}  ·  {len(ev)} eventos  ·  de {ev[0]['fecha']} a {ev[-1]['fecha']}\n")
    print("Eventos por tipo:")
    for tipo, n in Counter(e["evento"] for e in ev).most_common():
        print(f"  {tipo:24} {n}")
    print("\nEventos por nivel:", dict(Counter(e["nivel"] for e in ev)))

    alertas = []
    por_cuenta = defaultdict(list)
    for e in ev:
        if e["evento"] == "LOGIN_FALLIDO":
            por_cuenta[e["cuenta"]].append(e)
    for cuenta, lista in por_cuenta.items():
        if rafagas(lista, 5):
            alertas.append(f"R1 FUERZA BRUTA: {len(lista)} intentos fallidos contra la cuenta '{cuenta}' "
                           f"desde {sorted({x['ip'] for x in lista})}")
    if any(e["evento"] == "CUENTA_BLOQUEADA" for e in ev):
        alertas.append("R1 La aplicación bloqueó temporalmente la cuenta (control activo).")

    por_usuario = defaultdict(list)
    for e in ev:
        if e["evento"] == "ACCESO_DENEGADO":
            por_usuario[e["usuario"]].append(e)
    for usuario, lista in por_usuario.items():
        recursos = [x["recurso"] for x in lista]
        if rafagas(lista, 3):
            alertas.append(f"R2 ENUMERACIÓN IDOR: '{usuario}' intentó {len(lista)} recursos ajenos: {recursos}")
        else:
            alertas.append(f"R2 (aislado) '{usuario}' tuvo {len(lista)} acceso(s) denegado(s): {recursos}")

    sospechosas = [e for e in ev if e["evento"] == "ENTRADA_SOSPECHOSA"]
    if len(sospechosas) > 20 and rafagas(sospechosas, 20):
        alertas.append(f"R5 ESCANEO AUTOMATIZADO: {len(sospechosas)} entradas sospechosas en ráfaga "
                       f"(usuarios {sorted({e['usuario'] for e in sospechosas})}); se muestran 5 de ejemplo")
        sospechosas = sospechosas[:5]
    for e in sospechosas:
        alertas.append(f"R3 INYECCIÓN: '{e['usuario']}' envió en '{e['campo']}': {e['valor']}")

    for e in ev:
        if e["evento"] == "CSRF_RECHAZADO":
            alertas.append(f"R6 CSRF: solicitud sin token válido en {e['ruta']} (sesión de '{e['usuario']}')")
        if e["evento"] == "ADMIN_CONSULTA":
            alertas.append(f"R7 AUDITORÍA: '{e['usuario']}' consultó {e.get('recurso', '?')} a las {e['fecha'][11:]}")

    por_ip = Counter(e["ip"] for e in ev if e["evento"] in ("ENTRADA_INVALIDA", "RECURSO_NO_ENCONTRADO"))
    for ip, n in por_ip.items():
        if n >= 3:
            alertas.append(f"R4 SONDEO: {n} solicitudes inválidas desde {ip}")

    print(f"\nAlertas generadas ({len(alertas)}):")
    for a in alertas:
        print("  -", a)


if __name__ == "__main__":
    main()
