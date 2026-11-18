# Home Assistant integration

With a `homeassistant` block, ipv6ddns is a device of Home Assistant's ESPHome integration, which every Home Assistant has: no custom integration to install. It works with ipv6ddns anywhere on the network, in the [add-on](../homeassistant/addon/DOCS.md), in Docker or as a binary.

- **To Home Assistant**, each name's addresses, last update, and an update problem; the hosts discovered; and a button to update every name now.
- **From Home Assistant**, the state of any entity, for a [`homeassistant` source](sources.md#types): a router's WAN address sensor can give a name its A record, as it changes.

## Setting it up

```yaml
homeassistant: {}
```

Home Assistant finds the device by mDNS, `ipv6ddns`, under *Settings → Devices & services → Discovered*. Add it: as to ESPHome's devices, Home Assistant makes an encryption key and gives it to ipv6ddns, which keeps it, and only takes connections with it from then on. Where mDNS doesn't reach, as across VLANs, or with `announce: false`, add the ESPHome integration by hand with ipv6ddns' address and port 6053.

The keys of the block are in the [reference](reference/configuration.md#top-level).

### The key

| | |
|---|---|
| **Given by Home Assistant** (no `key`) | Kept in `state_file`, `homeassistant.state` beside the configuration by default, which ipv6ddns must be able to write. Only a client with the key can change it, as Home Assistant does when the device is deleted. Delete the file, and the device is a new one, without a key |
| **Your own**, `key: ${file:homeassistant.key}` | Fixed: Home Assistant asks it when adding the device, and can't change it. For a configuration on a read-only file system. Make one with `openssl rand -base64 32` |

Until it has its key, the device takes connections without one, for Home Assistant to give it: those see its entities, but their button presses, and the states they send, are dropped, so nobody can give a `homeassistant` source an address. If someone else gives it a key first, Home Assistant asks for the key when adding it: delete the state file, and add it again.

## The entities

| Entity | |
|---|---|
| *name* addresses | The addresses the name has now, comma separated |
| *name* last update | When its records were last updated |
| *name* update | A problem when its last update failed |
| Discovered hosts | How many hosts discovery knows |
| Update now | Updates every name now, as after a change |

*name* is the name's domain, as `www.example.com`. The entity ids come from the credential and the host name, so they stay when a provider's zone does.

## An entity's addresses

```yaml
homeassistant:
  key: ${file:homeassistant.key}
sources:
  router-wan:
    type: homeassistant
    entity: sensor.router_wan_ip      # or its attribute: attribute: wan_ip
tasks:
  home:
    sources: [router-wan]
    endpoints:
      cloudflare: [home]
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 5m
      proxied: false
```

The state is one address or more, separated by commas or spaces. A change runs the source at once. `unknown` and `unavailable`, Home Assistant's states for none, give no address, nor does Home Assistant not being connected: the addresses then stay for the source's lifetime, and go.

## How it works

ipv6ddns speaks the ESPHome native API, as ESPHome 2026.11 does: the connection is encrypted with the key, Noise_NNpsk0_25519_ChaChaPoly_SHA256, and the device announces itself as `_esphomelib._tcp`. Its MAC, by which Home Assistant knows it, comes from the identity in the state file, or from a fixed key: keep them, and Home Assistant keeps the device. CI connects to it with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant has.
