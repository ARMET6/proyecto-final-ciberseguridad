"""
Levanta escuchas TCP que simulan los servicios de un servidor del campus.
Responde un banner con el nombre del servicio para que Nmap y las pruebas lo identifiquen.

Uso (dentro de un namespace de red):
    python3 servicios_simulados.py VM-FS01 10.10.10.20:445 10.10.10.20:22
"""
import asyncio
import sys

NOMBRES = {22: "SSH", 53: "DNS", 80: "HTTP", 88: "Kerberos", 389: "LDAP", 443: "HTTPS", 445: "SMB",
           464: "kpasswd", 636: "LDAPS", 1514: "Wazuh-agente", 1515: "Wazuh-registro",
           5432: "PostgreSQL", 8006: "Proxmox-VE", 8007: "Proxmox-Backup"}


async def main():
    equipo, destinos = sys.argv[1], sys.argv[2:]
    servidores = []
    for d in destinos:
        ip, puerto = d.rsplit(":", 1)
        puerto = int(puerto)
        banner = f"{equipo} {NOMBRES.get(puerto, 'servicio')} simulado\r\n".encode()

        async def atender(reader, writer, banner=banner):
            writer.write(banner)
            await writer.drain()
            writer.close()

        servidores.append(await asyncio.start_server(atender, ip, puerto))
    await asyncio.gather(*(s.serve_forever() for s in servidores))


if __name__ == "__main__":
    asyncio.run(main())
