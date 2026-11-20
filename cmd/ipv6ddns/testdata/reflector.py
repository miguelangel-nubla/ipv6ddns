"""A machine of the link that answers for a device with what it announced before, for the live test
of several instances: as a reflector of mDNS between networks does, of the device's own name, MAC,
port and address, when the device starts again.

    reflector.py <address of the interface to answer on> <name> <mac> <port> <address of the device>

It prints "ready" once it answers, and ends when its input does. Its announcement is told from the
device's own by the friendly name, "reflected".
"""

import asyncio
import socket
import sys

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

SERVICE = "_esphomelib._tcp.local."


async def main(interface, name, mac, port, address):
    azc = AsyncZeroconf(interfaces=[interface], ip_version=IPVersion.V4Only)
    info = ServiceInfo(
        SERVICE,
        f"{name}.{SERVICE}",
        addresses=[socket.inet_aton(address)],
        port=int(port),
        properties={"mac": mac, "friendly_name": "reflected"},
        server=f"{name}.local.",
    )
    await azc.async_register_service(info)
    print("ready", flush=True)
    try:
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
    finally:
        await azc.async_close()


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:]))
