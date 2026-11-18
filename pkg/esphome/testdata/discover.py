"""Home Assistant's side of discovery, with python-zeroconf, the library its zeroconf integration
uses, on loopback only. It only listens, and sends no query: what it sees, the device announced
by itself, as RFC 6762 has a new service do, and as Home Assistant needs of a device that starts
after it, when it queries an hour apart.

    discover.py <name> <seconds>

It prints "ready" once listening, then a line for each record of the device that changes.
"""

import json
import sys
import time

from zeroconf import DNSService, DNSText, RecordUpdateListener, Zeroconf

name, seconds = sys.argv[1], float(sys.argv[2])
instance = f"{name}._esphomelib._tcp.local."
zc = Zeroconf(interfaces=["127.0.0.1"])


class Listener(RecordUpdateListener):
    def async_update_records(self, zc, now, records):
        for update in records:
            r = update.new
            if r.name.lower() != instance.lower():
                continue
            if isinstance(r, DNSService):
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


zc.loop.call_soon_threadsafe(zc.async_add_listener, Listener(), None)
time.sleep(0.5)
print("ready", flush=True)
time.sleep(seconds)
zc.close()
