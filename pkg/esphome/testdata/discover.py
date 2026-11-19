"""Home Assistant's side of discovery, with python-zeroconf, the library its zeroconf integration
uses, on the interface with the address given only.

    discover.py <name> <address> <seconds>

First it only listens, and sends no query: what it sees, the device announced by itself, as RFC
6762 has a new service do, and as Home Assistant needs of a device that starts after it, when it
queries an hour apart. It prints "ready" once listening, then a line for each record of the device
that changes: its port, TXT records, and addresses. Given "query" on stdin, it asks for the device
as Home Assistant does, with a cache of its own, and prints the addresses of the answer.
"""

import json
import socket
import sys
import threading
import time

import zeroconf._utils.net as zeroconf_net
from zeroconf import DNSAddress, DNSService, DNSText, RecordUpdateListener, ServiceInfo, Zeroconf

name, address, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
service = "_esphomelib._tcp.local."
instance = f"{name}.{service}"

# Linux gives a socket the multicast of every interface any socket of the machine joined the group
# on: that of the device's other networks too. Home Assistant, in its own network namespace, hears
# only its own; this, only the groups its sockets joined, on the interface given.
_new_socket = zeroconf_net.new_socket


def new_socket(*args, **kwargs):
    sock = _new_socket(*args, **kwargs)
    if sock is not None and sys.platform == "linux":
        sock.setsockopt(socket.IPPROTO_IP, 49, 0)  # IP_MULTICAST_ALL
    return sock


zeroconf_net.new_socket = new_socket


def ntop(packed):
    return socket.inet_ntop(socket.AF_INET6 if len(packed) == 16 else socket.AF_INET, packed)


class Listener(RecordUpdateListener):
    def async_update_records(self, zc, now, records):
        for update in records:
            r = update.new
            if isinstance(r, DNSAddress) and r.name.lower() == f"{name}.local.".lower():
                print(json.dumps({"address": ntop(r.address)}), flush=True)
            elif r.name.lower() != instance.lower():
                continue
            elif isinstance(r, DNSService):
                print(json.dumps({"port": r.port}), flush=True)
            elif isinstance(r, DNSText):
                txt, data = {}, r.text
                while data:
                    n, data = data[0], data[1:]
                    k, _, v = data[:n].decode().partition("=")
                    txt[k], data = v, data[n:]
                print(json.dumps({"txt": txt}), flush=True)

    def async_update_records_complete(self):
        pass


def query():
    zc = Zeroconf(interfaces=[address])
    info = ServiceInfo(service, instance)
    found = info.request(zc, 3000)
    print(json.dumps({"queried": info.parsed_addresses() if found else None}), flush=True)
    zc.close()


def commands():
    for line in sys.stdin:
        if line.strip() == "query":
            query()


zc = Zeroconf(interfaces=[address])
zc.loop.call_soon_threadsafe(zc.async_add_listener, Listener(), None)
time.sleep(0.5)
threading.Thread(target=commands, daemon=True).start()
print("ready", flush=True)
time.sleep(seconds)
zc.close()
