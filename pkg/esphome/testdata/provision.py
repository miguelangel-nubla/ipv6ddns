"""Home Assistant giving a device its key, as its ESPHome manager does: it connects without one,
sees the device takes one, and gives a key over Noise with the zero key.

    provision.py <port> <new key>
"""

import asyncio
import json
import sys

from aioesphomeapi import APIClient, InvalidEncryptionKeyAPIError, RequiresEncryptionAPIError
from aioesphomeapi.core import ZERO_NOISE_PSK


def out(**event):
    print(json.dumps(event), flush=True)


async def connects(port, key):
    client = APIClient("127.0.0.1", port, None, noise_psk=key)
    try:
        await client.connect(login=True)
        info = await client.device_info()
        await client.disconnect()
        return dict(ok=True, mac=info.mac_address, provisionable=info.api_encryption_provisionable)
    except (RequiresEncryptionAPIError, InvalidEncryptionKeyAPIError) as err:
        return dict(ok=False, error=type(err).__name__)


async def untrusted(port):
    """Without the key, the device asks no state, and takes no command."""
    client = APIClient("127.0.0.1", port, None)
    await client.connect(login=True)
    _, entities, _ = await client.device_info_and_list_entities()
    asked = []
    client.subscribe_home_assistant_states_and_services(
        lambda state: None, lambda call: None, lambda entity_id, attribute: asked.append(entity_id)
    )
    for e in entities:
        if type(e).__name__ == "ButtonInfo":
            client.button_command(e.key)
    client.send_home_assistant_state("sensor.wan_ip", None, "203.0.113.66")
    await asyncio.sleep(1)
    await client.disconnect()
    return dict(asked=asked)


async def main(port, new_key):
    out(before=await connects(port, None))
    out(untrusted=await untrusted(port))

    client = APIClient("127.0.0.1", port, None, noise_psk=ZERO_NOISE_PSK)
    await client.connect(login=True)
    out(set=await client.noise_encryption_set_key(new_key.encode()))
    await client.disconnect(force=True)

    out(with_key=await connects(port, new_key))
    out(without_key=await connects(port, None))
    out(with_zero=await connects(port, ZERO_NOISE_PSK))


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2]))
