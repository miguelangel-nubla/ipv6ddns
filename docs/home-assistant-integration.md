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

### A machine on several networks

The device listens on every address, and announces itself on each interface discovery runs on, with that interface's addresses. Where Home Assistant can't reach some of them, as a container on several networks, beside Home Assistant's, `listen` says where: the device listens there only, and announces itself on the interfaces that hold those addresses, so Home Assistant connects to one it can reach.

```yaml
homeassistant:
  listen: 10.2.3.0/24
```

It takes the entries of [`webserver.listen`](installation.md#the-web-report): a port, an address, a network of the machine's addresses, or a host name, each with `:port` or not; without one, `port`, 6053. Two networks on one wire, as two macvlan networks on one bridge, both reach Home Assistant's mDNS: list the one Home Assistant can connect to.

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

The state is one address or more, separated by commas or spaces. A change runs the source at once. An empty state is none: the addresses go at once, as a [command](sources.md#runs-and-lifetimes) that prints nothing.

While Home Assistant restarts, the source waits: Home Assistant isn't connected, or the entity is `unknown` or `unavailable`, its states for none, until its integration is up. A wait isn't a failure: the addresses stay for the source's `lifetime`, and the log says when the wait starts and ends, at info, and warns if it outlasts the lifetime, when the addresses go. Give the lifetime longer than Home Assistant's restarts. Connected for 30 seconds without a state of the entity is an error: Home Assistant has no entity of that id.

## Recipes

The blocks headed `# Home Assistant` go in Home Assistant's configuration, as `configuration.yaml` or a package; the helpers can be made in its UI too, under *Settings → Devices & services → Helpers*. The others are ipv6ddns'. Each credential is the one of [An entity's addresses](#an-entitys-addresses), shortened.

### A record you set by hand

A text helper holds the address, and a name follows it: set it from a dashboard, an automation with `input_text.set_value`, or Assist. Cleared, the record goes at once; while Home Assistant restarts, it stays.

```yaml
# Home Assistant: a text helper
input_text:
  vpn_address:
    name: VPN address
    max: 100
```

```yaml
homeassistant:
  key: ${file:homeassistant.key}
sources:
  vpn:
    type: homeassistant
    entity: input_text.vpn_address
tasks:
  vpn:
    sources: [vpn]
    endpoints:
      cloudflare: [vpn]
credentials:
  cloudflare:
    provider: cloudflare
    settings: {api_token: "${CLOUDFLARE_TOKEN}", zone: example.com, ttl: 5m, proxied: false}
```

It takes one address or more, separated by commas or spaces: `203.0.113.7, 2001:db8::7`.

### Switching a name between servers

A select helper picks the server, and a template sensor gives its address: a name moves to the standby for maintenance, by hand, or by an automation when the primary stops answering.

```yaml
# Home Assistant: a select helper, and a template sensor of its address
input_select:
  web_server:
    name: Web server
    options: [primary, standby]

template:
  - sensor:
      - name: web_server_address
        unique_id: web_server_address
        state: >-
          {{ {'primary': '203.0.113.10, 2001:db8::10',
              'standby': '198.51.100.20, 2001:db8:1::20'}.get(states('input_select.web_server'), '') }}

automation:
  - alias: Web server to the standby when the primary is down
    triggers:
      - trigger: state
        entity_id: binary_sensor.web_primary_ping
        to: "off"
        for: "00:02:00"
    actions:
      - action: input_select.select_option
        target: {entity_id: input_select.web_server}
        data: {option: standby}
```

`binary_sensor.web_primary_ping` is one of the [Ping integration](https://www.home-assistant.io/integrations/ping/)'s.

```yaml
homeassistant:
  key: ${file:homeassistant.key}
sources:
  web:
    type: homeassistant
    entity: sensor.web_server_address
tasks:
  www:
    sources: [web]
    endpoints:
      cloudflare: [www]
credentials:
  cloudflare:
    provider: cloudflare
    settings: {api_token: "${CLOUDFLARE_TOKEN}", zone: example.com, ttl: 5m, proxied: false}
```

### Devices discovery doesn't reach

A device on a network ipv6ddns can't discover, as a VLAN it isn't on, may be known to Home Assistant: a router's integration gives each device tracker its address in the `ip` attribute.

```yaml
homeassistant:
  key: ${file:homeassistant.key}
sources:
  printer:
    type: homeassistant
    entity: device_tracker.printer
    attribute: ip
tasks:
  printer:
    sources: [printer]
    endpoints:
      cloudflare: [printer.lan]
credentials:
  cloudflare:
    provider: cloudflare
    settings: {api_token: "${CLOUDFLARE_TOKEN}", zone: example.com, ttl: 5m, proxied: false}
```

### Two WANs in one record

A template sensor joins the public addresses of two connections, dropping the one that is down, so the name has the addresses that answer.

```yaml
# Home Assistant: the addresses of both WANs, without one that has none
template:
  - sensor:
      - name: wan_addresses
        unique_id: wan_addresses
        state: >-
          {{ [states('sensor.wan1_ip'), states('sensor.wan2_ip')]
             | reject('in', ['unknown', 'unavailable', ''])
             | join(', ') }}
```

```yaml
homeassistant:
  key: ${file:homeassistant.key}
sources:
  wan:
    type: homeassistant
    entity: sensor.wan_addresses
tasks:
  home:
    sources: [wan]
    endpoints:
      cloudflare: [home]
credentials:
  cloudflare:
    provider: cloudflare
    settings: {api_token: "${CLOUDFLARE_TOKEN}", zone: example.com, ttl: 5m, proxied: false}
```

### Alerts, and updating now

The device's entities in automations: a notification when a name's update keeps failing, and an update of every name when the router comes back, rather than at the next change discovery sees. Entity ids are as Home Assistant made them: *Settings → Devices & services → ESPHome → ipv6ddns*.

```yaml
# Home Assistant: automations
automation:
  - alias: ipv6ddns update failing
    triggers:
      - trigger: state
        entity_id: binary_sensor.ipv6ddns_cloudflare_home_update
        to: "on"
        for: "00:10:00"
    actions:
      - action: notify.notify
        data:
          message: "{{ trigger.to_state.name }} has failed for 10 minutes"

  - alias: ipv6ddns update now, the router back
    triggers:
      - trigger: state
        entity_id: binary_sensor.router_wan_connected
        to: "on"
    actions:
      - action: button.press
        target: {entity_id: button.ipv6ddns_update_now}
```

## How it works

ipv6ddns speaks the ESPHome native API, as ESPHome 2026.11 does: the connection is encrypted with the key, Noise_NNpsk0_25519_ChaChaPoly_SHA256, and the device announces itself as `_esphomelib._tcp`. Its MAC, by which Home Assistant knows it, comes from the identity in the state file, or from a fixed key: keep them, and Home Assistant keeps the device. CI connects to it with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant has.
