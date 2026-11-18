# Home Assistant integration

With a `homeassistant` block, ipv6ddns is a device of Home Assistant's ESPHome integration, which every Home Assistant has: no custom integration to install. It works with ipv6ddns anywhere on the network, in the [add-on](../homeassistant/addon/DOCS.md), in Docker or as a binary.

- **To Home Assistant**, each name's addresses, last update, and an update problem; the hosts discovered; and a button to update every name now.
- **From Home Assistant**, the state of any entity, for a [`homeassistant` source](sources.md#types): a router's WAN address sensor can give a name its A record, as it changes.

## Setting it up

1. Make a key, and give it to the configuration: the add-on makes one the first time, in `homeassistant.key` beside its `config.yaml`, and logs it once.

   ```
   openssl rand -base64 32 > homeassistant.key
   ```

   ```yaml
   homeassistant:
     key: ${file:homeassistant.key}
   ```

2. Home Assistant finds the device by mDNS, `ipv6ddns`, under *Settings → Devices & services → Discovered*. Add it, and give it the key. Where mDNS doesn't reach, as across VLANs, add the ESPHome integration by hand with ipv6ddns' address and port 6053.

The keys of the block, its name and port among them, are in the [reference](reference/configuration.md#top-level).

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

ipv6ddns speaks the ESPHome native API, as ESPHome 2026.11 does: the connection is encrypted with the key, Noise_NNpsk0_25519_ChaChaPoly_SHA256, and the device announces itself as `_esphomelib._tcp`. Its MAC, by which Home Assistant knows it, comes from the key: keep the key, and Home Assistant keeps the device. CI connects to it with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant has.
