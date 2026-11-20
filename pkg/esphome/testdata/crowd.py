"""Clients that connect and say nothing, and Home Assistant among them, for the live tests.

    crowd.py <address> <port> <key> <clients> <seconds>

It opens the connections, which say nothing, and then has aioesphomeapi connect, as Home
Assistant: "among" is whether it got in while they were all open. Then it tries again until it
does, for the seconds given: "after" is whether it did, "dropped" how many of the silent
connections the device had closed by then, and "name" what the device said its name is.
"""

import asyncio
import json
import logging
import socket
import sys
import time

from aioesphomeapi import APIClient, APIConnectionError

# The library logs each connection that fails: the first here is meant to.
logging.getLogger("aioesphomeapi").setLevel(logging.CRITICAL)


def out(**event):
    print(json.dumps(event), flush=True)


async def connects(address, port, key):
    client = APIClient(address, port, None, noise_psk=key)
    try:
        await client.connect(login=True)
        info = await client.device_info()
        await client.disconnect()
        return info.name
    except APIConnectionError:
        return None


def closed(sock):
    """Whether the other end closed the connection: nothing was ever sent on it."""
    sock.setblocking(False)
    try:
        return sock.recv(1) == b""
    except BlockingIOError:
        return False
    except OSError:
        return True


async def main(address, port, key, clients, seconds):
    silent = [socket.create_connection((address, port), timeout=5) for _ in range(clients)]
    out(open=len(silent))
    out(among=await connects(address, port, key) is not None)

    name, end = None, time.monotonic() + seconds
    while name is None and time.monotonic() < end:
        await asyncio.sleep(0.5)
        name = await connects(address, port, key)
    await asyncio.sleep(1)
    out(after=name is not None, name=name, dropped=sum(closed(s) for s in silent))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])))
