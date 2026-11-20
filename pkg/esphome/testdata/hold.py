"""Home Assistant staying connected, for the live tests: aioesphomeapi connects with the key, as
its ESPHome manager does, follows the states, and stays until it is killed.

    hold.py <address> <port> <key> <keepalive seconds>

It prints one JSON object per line: "connected" once Home Assistant's states are asked for, each
state of a text sensor, and "disconnected" should the connection end.
"""

import asyncio
import json
import sys

from aioesphomeapi import APIClient, TextSensorState


def out(**event):
    print(json.dumps(event), flush=True)


async def main(address, port, key, keepalive):
    client = APIClient(address, port, None, noise_psk=key, keepalive=keepalive)
    gone = asyncio.Event()

    async def on_stop(expected):
        out(disconnected=True)
        gone.set()

    await client.connect(on_stop=on_stop, login=True)
    info, _, _ = await client.device_info_and_list_entities()

    def on_state(state):
        if isinstance(state, TextSensorState):
            out(state=state.state)

    client.subscribe_home_assistant_states_and_services(on_state, lambda call: None, lambda entity_id, attribute: None)
    out(connected=info.name)
    await gone.wait()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])))
