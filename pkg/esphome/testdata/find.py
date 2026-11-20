"""Home Assistant finding the device and connecting to it, for the live tests: python-zeroconf
browses for ESPHome devices, as Home Assistant's zeroconf integration does, and aioesphomeapi
connects to what the device announced, as its ESPHome integration does then.

    find.py <name> <address of the interface to browse on> <key> <seconds>

It prints one JSON object per line: "found", the port and the addresses announced, and
"connected", what the device says of itself at the first of them, or "error".
"""

import asyncio
import json
import sys

from aioesphomeapi import APIClient, APIConnectionError
from zeroconf import IPVersion, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

SERVICE = "_esphomelib._tcp.local."


def out(**event):
    print(json.dumps(event), flush=True)


async def main(name, interface, key, seconds):
    instance = f"{name}.{SERVICE}"
    seen = asyncio.Event()

    def on_change(zeroconf, service_type, name, state_change):
        if name.lower() == instance.lower() and state_change is not ServiceStateChange.Removed:
            seen.set()

    azc = AsyncZeroconf(interfaces=[interface])
    browser = AsyncServiceBrowser(azc.zeroconf, SERVICE, handlers=[on_change])
    try:
        await asyncio.wait_for(seen.wait(), seconds)
        info = AsyncServiceInfo(SERVICE, instance)
        if not await info.async_request(azc.zeroconf, 3000):
            out(error="the service's records didn't come")
            return
        addresses = info.parsed_addresses(IPVersion.V4Only)
        out(found=dict(port=info.port, addresses=addresses, encryption=(info.decoded_properties or {}).get("api_encryption")))
    except TimeoutError:
        out(error="not announced")
        return
    finally:
        await browser.async_cancel()
        await azc.async_close()

    client = APIClient(addresses[0], info.port, None, noise_psk=key)
    try:
        await client.connect(login=True)
        device, entities, _ = await client.device_info_and_list_entities()
        out(connected=dict(name=device.name, mac=device.mac_address, entities=len(entities)))
        await client.disconnect()
    except (APIConnectionError, OSError) as err:
        out(error=f"{type(err).__name__}: {err}")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])))
