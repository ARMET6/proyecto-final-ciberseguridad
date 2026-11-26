"""
Prueba si una conexión TCP o UDP llega a su destino (la usa laboratorio_red.sh probar).

    python3 sonda.py tcp 10.10.10.20 445 [--origen 10.10.20.60]
    python3 sonda.py udp 10.10.10.10 53

TCP: intenta abrir la conexión. UDP: envía un datagrama y espera la respuesta del servicio.
Sale con código 0 si el destino respondió (PERMITIDO) y 1 si no (BLOQUEADO).
"""
import argparse
import socket
import sys

ap = argparse.ArgumentParser()
ap.add_argument("protocolo", choices=["tcp", "udp"])
ap.add_argument("destino")
ap.add_argument("puerto", type=int)
ap.add_argument("--origen", help="IP de origen (cuando el equipo tiene varias)")
ap.add_argument("--espera", type=float, default=1.5)
a = ap.parse_args()

tipo = socket.SOCK_STREAM if a.protocolo == "tcp" else socket.SOCK_DGRAM
with socket.socket(socket.AF_INET, tipo) as s:
    s.settimeout(a.espera)
    if a.origen:
        s.bind((a.origen, 0))
    try:
        if a.protocolo == "tcp":
            s.connect((a.destino, a.puerto))
        else:
            s.sendto(b"sonda", (a.destino, a.puerto))
            s.recvfrom(512)
        sys.exit(0)
    except OSError:
        sys.exit(1)
