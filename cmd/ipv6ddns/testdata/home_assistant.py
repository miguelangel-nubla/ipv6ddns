"""Home Assistant on a machine of the link, for the live tests of several instances: python-zeroconf
browses for ESPHome devices for as long as it runs, as Home Assistant's zeroconf integration does,
and aioesphomeapi connects to those the test names, as its ESPHome integration does.

    home_assistant.py <address of the interface to browse on>

It prints one JSON object per line: "ready"; "service", a device as its announcement tells it, each
time that changes; "removed", a device that took its announcement back. And it takes one per line:

    {"connect": {"address": ..., "port": ..., "key": ...}}      "connected", or "failed"
    {"give_key": {"address": ..., "port": ..., "key": ...}}     "given"
    {"query": <name>}                                           "queried"

"connected" has what the device says of itself, its entities and their states. "queried" has the
device as a query answers now, to a Home Assistant that just started and remembers nothing.
"""

import asyncio
import json
import logging
import sys

from aioesphomeapi import APIClient, APIConnectionError
from aioesphomeapi.core import ZERO_NOISE_PSK
from zeroconf import IPVersion, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

SERVICE = "_esphomelib._tcp.local."

# A connection that fails is an event of this script's, when the test asks for one with a wrong key.
logging.getLogger("aioesphomeapi").setLevel(logging.CRITICAL)


def out(**event):
    print(json.dumps(event), flush=True)


async def resolve(zeroconf, name, timeout):
    info = AsyncServiceInfo(SERVICE, f"{name}.{SERVICE}")
    if not await info.async_request(zeroconf, timeout):
        return None
    txt = info.decoded_properties or {}
    return dict(
        name=name,
        port=info.port,
        host=info.server,
        addresses=info.parsed_addresses(IPVersion.V4Only),
        mac=txt.get("mac"),
        friendly_name=txt.get("friendly_name"),
        encryption=bool(txt.get("api_encryption")),
    )


async def connect(address, port, key):
    client = APIClient(address, port, None, noise_psk=key)
    try:
        await client.connect(login=True)
        device, entities, _ = await client.device_info_and_list_entities()
        ids = {e.key: e.object_id for e in entities}
        states = {}
        client.subscribe_states(lambda state: states.__setitem__(ids.get(state.key), getattr(state, "state", None)))
        await asyncio.sleep(1.5)
        await client.disconnect()
        out(connected=dict(address=address, port=port, name=device.name, friendly_name=device.friendly_name,
                           mac=device.mac_address, entities=sorted(ids.values()), states=states))
    except (APIConnectionError, OSError) as err:
        out(failed=dict(address=address, port=port, error=f"{type(err).__name__}: {err}"))


async def give_key(address, port, key):
    client = APIClient(address, port, None, noise_psk=ZERO_NOISE_PSK)
    try:
        await client.connect(login=True)
        ok = await client.noise_encryption_set_key(key.encode())
        await client.disconnect(force=True)
        out(given=dict(address=address, port=port, ok=bool(ok)))
    except (APIConnectionError, OSError) as err:
        out(given=dict(address=address, port=port, ok=False, error=f"{type(err).__name__}: {err}"))


async def query(interface, name):
    azc = AsyncZeroconf(interfaces=[interface])
    try:
        out(queried=dict(name=name, service=await resolve(azc.zeroconf, name, 3000)))
    finally:
        await azc.async_close()


async def main(interface):
    azc = AsyncZeroconf(interfaces=[interface])
    tasks = set()

    def run(coroutine):
        task = asyncio.ensure_future(coroutine)
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def changed(name):
        service = await resolve(azc.zeroconf, name, 3000)
        if service is not None:
            out(service=service)

    def on_change(zeroconf, service_type, name, state_change):
        name = name.removesuffix("." + SERVICE)
        if state_change is ServiceStateChange.Removed:
            out(removed=name)
        else:
            run(changed(name))

    browser = AsyncServiceBrowser(azc.zeroconf, SERVICE, handlers=[on_change])
    out(ready=True)
    loop = asyncio.get_running_loop()
    try:
        while line := await loop.run_in_executor(None, sys.stdin.readline):
            command = json.loads(line)
            if "connect" in command:
                run(connect(**command["connect"]))
            elif "give_key" in command:
                run(give_key(**command["give_key"]))
            elif "query" in command:
                run(query(interface, command["query"]))
    finally:
        await browser.async_cancel()
        await azc.async_close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
