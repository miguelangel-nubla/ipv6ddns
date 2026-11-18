"""Home Assistant's side of the worker's end-to-end test: aioesphomeapi, as its ESPHome integration,
connects to ipv6ddns, lists its entities, follows them, and sends the state of sensor.wan_ip, which a
homeassistant source reads; it ends when the name's addresses entity has that address.

    ha_client.py <port> <key>
"""

import asyncio
import json
import sys

from aioesphomeapi import APIClient


def out(**event):
    print(json.dumps(event), flush=True)


async def main(port, key):
    client = APIClient("127.0.0.1", port, None, noise_psk=key)
    await client.connect(login=True)
    # As Home Assistant's ESPHome manager does.
    info, entities, _ = await client.device_info_and_list_entities()
    await client.device_capabilities_compat(info)
    out(info=dict(name=info.name, project_name=info.project_name))
    names = {}
    for e in entities:
        names[e.key] = e.object_id
        out(entity=dict(object_id=e.object_id, name=e.name, type=type(e).__name__))

    done = asyncio.Event()

    def on_state(state):
        out(state=dict(entity=names.get(state.key), value=state.state))
        if names.get(state.key) == "dns_web_addresses" and "203.0.113.50" in str(state.state):
            done.set()

    client.subscribe_home_assistant_states_and_services(
        on_state,
        lambda call: None,
        lambda entity_id, attribute: client.send_home_assistant_state(entity_id, attribute, "203.0.113.50"),
    )
    try:
        await asyncio.wait_for(done.wait(), 15)
        out(done=True)
    except TimeoutError:
        out(done=False)
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2]))
