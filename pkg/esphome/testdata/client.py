"""Home Assistant's side of the compatibility test: aioesphomeapi, the library its ESPHome
integration connects to devices with, against the device the Go test serves.

    client.py <port> <key>

It prints one JSON object per line, for the Go test to check.
"""

import asyncio
import json
import sys

import aioesphomeapi
from aioesphomeapi import (
    APIClient,
    BinarySensorState,
    InvalidEncryptionKeyAPIError,
    RequiresEncryptionAPIError,
    SensorState,
    TextSensorState,
)


def out(**event):
    print(json.dumps(event), flush=True)


async def refused(port, key):
    client = APIClient("127.0.0.1", port, None, noise_psk=key)
    try:
        await client.connect(login=True)
        await client.disconnect()
        return None
    except (RequiresEncryptionAPIError, InvalidEncryptionKeyAPIError) as err:
        return type(err).__name__


async def main(port, key):
    out(no_key=await refused(port, None))
    out(wrong_key=await refused(port, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))

    client = APIClient("127.0.0.1", port, None, noise_psk=key)
    await client.connect(login=True)
    # As Home Assistant's ESPHome manager does, in homeassistant/components/esphome/manager.py.
    info, entities, _ = await client.device_info_and_list_entities()
    capabilities = await client.device_capabilities_compat(info)
    out(capabilities=str(capabilities))
    out(
        info=dict(
            name=info.name,
            friendly_name=info.friendly_name,
            mac=info.mac_address,
            esphome_version=info.esphome_version,
            project_name=info.project_name,
            project_version=info.project_version,
            manufacturer=info.manufacturer,
            model=info.model,
            api_version=str(client.api_version),
        )
    )

    keys = {}
    for e in entities:
        keys[e.object_id] = e.key
        out(entity=dict(type=type(e).__name__, object_id=e.object_id, name=e.name, icon=e.icon, category=int(e.entity_category)))

    states = {}
    done = asyncio.Event()

    def on_state(state):
        name = next((k for k, v in keys.items() if v == state.key), str(state.key))
        if isinstance(state, (TextSensorState, SensorState, BinarySensorState)):
            states[name] = state.state
            out(state=dict(entity=name, value=state.state, missing=state.missing_state))
        if states.get("echo") == "got:203.0.113.9" and states.get("pressed") is True:
            done.set()

    def on_state_sub(entity_id, attribute):
        out(asked=dict(entity_id=entity_id, attribute=attribute))
        client.send_home_assistant_state(entity_id, attribute, "203.0.113.9")

    client.subscribe_home_assistant_states_and_services(on_state, lambda call: None, on_state_sub)
    client.button_command(keys["update"])

    try:
        await asyncio.wait_for(done.wait(), 10)
        out(done=True)
    except TimeoutError:
        out(done=False, states=states)
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2]))
