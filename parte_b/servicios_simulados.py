"""
Levanta escuchas TCP y UDP que simulan los servicios de un servidor del campus.
Responde un banner con el nombre del servicio para que Nmap y las pruebas lo identifiquen.

Uso (dentro de un namespace de red; "udp/" indica un servicio UDP):
    python3 servicios_simulados.py VM-DC01 10.10.10.10:445 10.10.10.10:udp/53
"""
import asyncio
import sys

NOMBRES = {137: "NetBIOS", 22: "SSH", 53: "DNS", 80: "HTTP", 88: "Kerberos", 389: "LDAP", 443: "HTTPS", 445: "SMB",
           464: "kpasswd", 636: "LDAPS", 1514: "Wazuh-agente", 1515: "Wazuh-registro",
           5432: "PostgreSQL", 8006: "Proxmox-VE", 8007: "Proxmox-Backup"}


class EcoUDP(asyncio.DatagramProtocol):
    """Responde cada datagrama con el banner del servicio."""

    def __init__(self, banner):
        self.banner = banner

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(self.banner, addr)


async def main():
    equipo, destinos = sys.argv[1], sys.argv[2:]
    servidores = []
    loop = asyncio.get_running_loop()
    for d in destinos:
        ip, puerto = d.rsplit(":", 1)
        if puerto.startswith("udp/"):
            puerto = int(puerto[4:])
            banner = f"{equipo} {NOMBRES.get(puerto, 'servicio')} simulado (UDP)\r\n".encode()
            await loop.create_datagram_endpoint(lambda b=banner: EcoUDP(b), local_addr=(ip, puerto))
            continue
        puerto = int(puerto)
        banner = f"{equipo} {NOMBRES.get(puerto, 'servicio')} simulado\r\n".encode()

        async def atender(reader, writer, banner=banner):
            writer.write(banner)
            await writer.drain()
            writer.close()

        servidores.append(await asyncio.start_server(atender, ip, puerto))
    await asyncio.gather(*(s.serve_forever() for s in servidores), asyncio.Event().wait())


if __name__ == "__main__":
    asyncio.run(main())
